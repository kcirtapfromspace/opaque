//! Trust-domain custody verification.
//!
//! The daemon's integrity guarantees (tamper-evident audit chain, config seal,
//! delegation signing key, device pairing store) are only as strong as the
//! filesystem custody of the files that back them. When the daemon shares a
//! uid with the agent it polices, every one of those guarantees degrades to
//! tamper-*evidence*: the agent can read the keys and rewrite the state.
//!
//! This module is the portable half of turning that into tamper-*prevention*:
//! it verifies, at startup, that every custody file is exclusively accessible
//! by the daemon's own principal — owned by the daemon uid, no group/other
//! permission bits, no symlinks substituted anywhere. Under an enforced trust
//! domain the daemon refuses to start otherwise (fail closed); it is this
//! refusal that makes the service-account split real rather than aspirational.
//!
//! Verification is pure logic over a [`FsInspect`] snapshot so every branch
//! (including foreign-uid ownership, which a same-uid unit test cannot set up)
//! is testable anywhere; the real filesystem impl and the multi-uid
//! integration suite exercise it for real on Linux.

use std::fmt;
use std::path::{Path, PathBuf};

/// What kind of node a custody path is expected to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    /// Regular file — mode must have no bits beyond 0o600.
    File,
    /// Directory — mode must have no bits beyond 0o700.
    Dir,
}

/// One path the daemon claims exclusive custody of.
#[derive(Debug, Clone)]
pub struct CustodyPath {
    pub path: PathBuf,
    pub kind: PathKind,
    /// Human label used in violation messages ("audit chain key", …).
    pub label: &'static str,
}

/// Filesystem facts about a single path, as observed via `lstat`.
#[derive(Debug, Clone, Copy)]
pub struct FileFacts {
    pub uid: u32,
    pub mode: u32,
    pub is_symlink: bool,
    pub is_dir: bool,
}

/// Source of filesystem metadata, injectable so ownership branches are
/// unit-testable without root.
pub trait FsInspect {
    /// `lstat` the path. `Ok(None)` means the path does not exist.
    fn facts(&self, path: &Path) -> std::io::Result<Option<FileFacts>>;
}

/// Real-filesystem [`FsInspect`].
pub struct SystemFs;

#[cfg(unix)]
impl FsInspect for SystemFs {
    fn facts(&self, path: &Path) -> std::io::Result<Option<FileFacts>> {
        use std::os::unix::fs::MetadataExt;
        match path.symlink_metadata() {
            Ok(meta) => Ok(Some(FileFacts {
                uid: meta.uid(),
                mode: meta.mode() & 0o7777,
                is_symlink: meta.file_type().is_symlink(),
                is_dir: meta.is_dir(),
            })),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// A single custody violation. `Display` includes the remediation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyViolation {
    /// Owned by a uid other than the daemon's.
    ForeignOwner {
        label: &'static str,
        path: PathBuf,
        owner: u32,
        expected: u32,
    },
    /// Permission bits grant access beyond the owner.
    TooPermissive {
        label: &'static str,
        path: PathBuf,
        mode: u32,
        allowed: u32,
    },
    /// The path is a symlink — custody of the link tells us nothing about
    /// custody of the target, so a substituted link always fails.
    Symlink { label: &'static str, path: PathBuf },
    /// Exists but is the wrong node type (file where a dir belongs or the
    /// reverse) — something replaced it.
    WrongKind { label: &'static str, path: PathBuf },
    /// Metadata could not be read at all.
    Unreadable {
        label: &'static str,
        path: PathBuf,
        error: String,
    },
}

impl fmt::Display for CustodyViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CustodyViolation::ForeignOwner {
                label,
                path,
                owner,
                expected,
            } => write!(
                f,
                "{label} {} is owned by uid {owner}, not the daemon uid {expected} — \
                 chown it to the daemon's service account",
                path.display()
            ),
            CustodyViolation::TooPermissive {
                label,
                path,
                mode,
                allowed,
            } => write!(
                f,
                "{label} {} has mode {mode:04o}, which grants access beyond the daemon \
                 (allowed bits {allowed:04o}) — chmod it to {allowed:o}",
                path.display()
            ),
            CustodyViolation::Symlink { label, path } => write!(
                f,
                "{label} {} is a symlink — custody files must be regular paths",
                path.display()
            ),
            CustodyViolation::WrongKind { label, path } => write!(
                f,
                "{label} {} is not the expected node type — remove whatever replaced it",
                path.display()
            ),
            CustodyViolation::Unreadable { label, path, error } => write!(
                f,
                "{label} {} could not be inspected: {error}",
                path.display()
            ),
        }
    }
}

fn allowed_bits(kind: PathKind) -> u32 {
    match kind {
        PathKind::File => 0o600,
        PathKind::Dir => 0o700,
    }
}

/// Verify exclusive custody of every path that exists.
///
/// Missing paths are not violations: the daemon creates its own state on
/// first use and then owns it. The invariant enforced here is that whatever
/// *does* exist under a custody path is exclusively the daemon's.
pub fn verify_custody(
    items: &[CustodyPath],
    daemon_uid: u32,
    fs: &dyn FsInspect,
) -> Vec<CustodyViolation> {
    let mut violations = Vec::new();

    for item in items {
        let facts = match fs.facts(&item.path) {
            Ok(Some(f)) => f,
            Ok(None) => continue,
            Err(e) => {
                violations.push(CustodyViolation::Unreadable {
                    label: item.label,
                    path: item.path.clone(),
                    error: e.to_string(),
                });
                continue;
            }
        };

        if facts.is_symlink {
            violations.push(CustodyViolation::Symlink {
                label: item.label,
                path: item.path.clone(),
            });
            // A symlink's uid/mode describe the link, not the target — the
            // remaining checks would be meaningless.
            continue;
        }

        if facts.is_dir != matches!(item.kind, PathKind::Dir) {
            violations.push(CustodyViolation::WrongKind {
                label: item.label,
                path: item.path.clone(),
            });
            continue;
        }

        if facts.uid != daemon_uid {
            violations.push(CustodyViolation::ForeignOwner {
                label: item.label,
                path: item.path.clone(),
                owner: facts.uid,
                expected: daemon_uid,
            });
        }

        let allowed = allowed_bits(item.kind);
        // Any bit outside the owner class (incl. setuid/setgid/sticky) is a
        // grant beyond the daemon.
        if facts.mode & !allowed != 0 {
            violations.push(CustodyViolation::TooPermissive {
                label: item.label,
                path: item.path.clone(),
                mode: facts.mode,
                allowed,
            });
        }
    }

    violations
}

/// The daemon's full custody set, derived from its HOME and config path.
///
/// `config_path` is passed separately because `$OPAQUE_CONFIG` may point it
/// outside the state dir; the seal always sits beside the config.
pub fn default_custody_set(home: &Path, config_path: &Path) -> Vec<CustodyPath> {
    let state = home.join(".opaque");
    let seal = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("config.seal");

    vec![
        CustodyPath {
            path: state.clone(),
            kind: PathKind::Dir,
            label: "state directory",
        },
        CustodyPath {
            path: config_path.to_path_buf(),
            kind: PathKind::File,
            label: "daemon config",
        },
        CustodyPath {
            path: crate::seal::seal_key_path(&seal),
            kind: PathKind::File,
            label: "config seal key",
        },
        CustodyPath {
            path: seal,
            kind: PathKind::File,
            label: "config seal",
        },
        CustodyPath {
            path: state.join("audit.db"),
            kind: PathKind::File,
            label: "audit database",
        },
        CustodyPath {
            path: state.join("audit.hmac"),
            kind: PathKind::File,
            label: "audit chain key",
        },
        CustodyPath {
            path: state.join("identity.db"),
            kind: PathKind::File,
            label: "identity store",
        },
        CustodyPath {
            path: state.join("identity.key"),
            kind: PathKind::File,
            label: "delegation signing key",
        },
        CustodyPath {
            path: state.join("profiles"),
            kind: PathKind::Dir,
            label: "profiles directory",
        },
        CustodyPath {
            path: state.join("bundle.state"),
            kind: PathKind::File,
            label: "federation bundle anti-rollback state",
        },
        CustodyPath {
            path: state.join("export.cursor"),
            kind: PathKind::File,
            label: "audit export cursors",
        },
        CustodyPath {
            path: state.join("pairing.key"),
            kind: PathKind::File,
            label: "device pairing signing key",
        },
        CustodyPath {
            path: state.join("approval_server.key"),
            kind: PathKind::File,
            label: "approval server TLS key",
        },
        CustodyPath {
            path: state.join("approval_server.cert"),
            kind: PathKind::File,
            label: "approval server TLS certificate",
        },
        CustodyPath {
            path: home.join(".config").join("opaque"),
            kind: PathKind::Dir,
            label: "pairing config directory",
        },
        CustodyPath {
            path: home
                .join(".config")
                .join("opaque")
                .join("paired_devices.json"),
            kind: PathKind::File,
            label: "paired device store",
        },
        CustodyPath {
            path: home
                .join(".config")
                .join("opaque")
                .join("paired_devices.hmac"),
            kind: PathKind::File,
            label: "paired device store integrity key",
        },
        CustodyPath {
            path: home
                .join(".config")
                .join("opaque")
                .join("fido2_credentials.json"),
            kind: PathKind::File,
            label: "FIDO2 credential store",
        },
        CustodyPath {
            path: home
                .join(".config")
                .join("opaque")
                .join("fido2_credentials.hmac"),
            kind: PathKind::File,
            label: "FIDO2 credential store integrity key",
        },
    ]
}

/// Tighten permission bits on custody paths the daemon already owns.
///
/// Self-heal for drift (a 0644 key created by an older build, an over-shared
/// state dir): anything owned by `daemon_uid` with bits beyond the allowance
/// is chmod'ed down. Foreign-owned paths are left alone — that is a violation
/// for [`verify_custody`] to report, not something to silently mutate.
///
/// Returns `(path, old_mode, new_mode)` for each change.
#[cfg(unix)]
pub fn tighten_modes(items: &[CustodyPath], daemon_uid: u32) -> Vec<(PathBuf, u32, u32)> {
    use std::os::unix::fs::PermissionsExt;

    let mut tightened = Vec::new();
    for item in items {
        let Ok(Some(facts)) = SystemFs.facts(&item.path) else {
            continue;
        };
        if facts.is_symlink || facts.uid != daemon_uid {
            continue;
        }
        let allowed = allowed_bits(item.kind);
        if facts.mode & !allowed != 0 {
            let new_mode = facts.mode & allowed;
            if std::fs::set_permissions(&item.path, std::fs::Permissions::from_mode(new_mode))
                .is_ok()
            {
                tightened.push((item.path.clone(), facts.mode, new_mode));
            }
        }
    }
    tightened
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Scripted [`FsInspect`] so foreign-uid and symlink branches are
    /// unit-testable without root.
    struct FakeFs(HashMap<PathBuf, FileFacts>);

    impl FakeFs {
        fn new(entries: &[(&str, FileFacts)]) -> Self {
            Self(
                entries
                    .iter()
                    .map(|(p, f)| (PathBuf::from(p), *f))
                    .collect(),
            )
        }
    }

    impl FsInspect for FakeFs {
        fn facts(&self, path: &Path) -> std::io::Result<Option<FileFacts>> {
            Ok(self.0.get(path).copied())
        }
    }

    const DAEMON_UID: u32 = 500;
    const AGENT_UID: u32 = 501;

    fn file(uid: u32, mode: u32) -> FileFacts {
        FileFacts {
            uid,
            mode,
            is_symlink: false,
            is_dir: false,
        }
    }

    fn dir(uid: u32, mode: u32) -> FileFacts {
        FileFacts {
            uid,
            mode,
            is_symlink: false,
            is_dir: true,
        }
    }

    fn item(path: &str, kind: PathKind) -> CustodyPath {
        CustodyPath {
            path: PathBuf::from(path),
            kind,
            label: "test path",
        }
    }

    #[test]
    fn exclusive_daemon_custody_passes() {
        let fs = FakeFs::new(&[
            ("/state", dir(DAEMON_UID, 0o700)),
            ("/state/audit.hmac", file(DAEMON_UID, 0o600)),
            ("/state/audit.db", file(DAEMON_UID, 0o600)),
        ]);
        let items = [
            item("/state", PathKind::Dir),
            item("/state/audit.hmac", PathKind::File),
            item("/state/audit.db", PathKind::File),
        ];
        assert!(verify_custody(&items, DAEMON_UID, &fs).is_empty());
    }

    #[test]
    fn missing_paths_are_not_violations() {
        let fs = FakeFs::new(&[]);
        let items = [item("/state/identity.key", PathKind::File)];
        assert!(verify_custody(&items, DAEMON_UID, &fs).is_empty());
    }

    #[test]
    fn agent_owned_key_is_a_violation() {
        let fs = FakeFs::new(&[("/state/audit.hmac", file(AGENT_UID, 0o600))]);
        let items = [item("/state/audit.hmac", PathKind::File)];
        let v = verify_custody(&items, DAEMON_UID, &fs);
        assert_eq!(
            v,
            vec![CustodyViolation::ForeignOwner {
                label: "test path",
                path: PathBuf::from("/state/audit.hmac"),
                owner: AGENT_UID,
                expected: DAEMON_UID,
            }]
        );
    }

    #[test]
    fn group_readable_key_is_a_violation() {
        let fs = FakeFs::new(&[("/state/audit.hmac", file(DAEMON_UID, 0o640))]);
        let items = [item("/state/audit.hmac", PathKind::File)];
        let v = verify_custody(&items, DAEMON_UID, &fs);
        assert!(matches!(v[0], CustodyViolation::TooPermissive { mode, .. } if mode == 0o640));
    }

    #[test]
    fn world_readable_state_dir_is_a_violation() {
        let fs = FakeFs::new(&[("/state", dir(DAEMON_UID, 0o755))]);
        let items = [item("/state", PathKind::Dir)];
        let v = verify_custody(&items, DAEMON_UID, &fs);
        assert!(matches!(v[0], CustodyViolation::TooPermissive { mode, .. } if mode == 0o755));
    }

    #[test]
    fn setuid_bit_is_a_violation_even_at_0600() {
        let fs = FakeFs::new(&[("/state/audit.hmac", file(DAEMON_UID, 0o4600))]);
        let items = [item("/state/audit.hmac", PathKind::File)];
        let v = verify_custody(&items, DAEMON_UID, &fs);
        assert!(matches!(v[0], CustodyViolation::TooPermissive { .. }));
    }

    #[test]
    fn owner_execute_on_file_is_a_violation_but_tighter_modes_pass() {
        // 0700 on a file exceeds the 0600 allowance…
        let fs = FakeFs::new(&[("/state/audit.hmac", file(DAEMON_UID, 0o700))]);
        let items = [item("/state/audit.hmac", PathKind::File)];
        assert_eq!(verify_custody(&items, DAEMON_UID, &fs).len(), 1);

        // …while 0400 (read-only key) is within it.
        let fs = FakeFs::new(&[("/state/audit.hmac", file(DAEMON_UID, 0o400))]);
        assert!(verify_custody(&items, DAEMON_UID, &fs).is_empty());
    }

    #[test]
    fn symlinked_custody_path_is_a_violation() {
        let fs = FakeFs::new(&[(
            "/state/audit.hmac",
            FileFacts {
                uid: DAEMON_UID,
                mode: 0o777,
                is_symlink: true,
                is_dir: false,
            },
        )]);
        let items = [item("/state/audit.hmac", PathKind::File)];
        let v = verify_custody(&items, DAEMON_UID, &fs);
        assert_eq!(v.len(), 1);
        assert!(matches!(v[0], CustodyViolation::Symlink { .. }));
    }

    #[test]
    fn dir_replaced_by_file_is_a_violation() {
        let fs = FakeFs::new(&[("/state/profiles", file(DAEMON_UID, 0o600))]);
        let items = [item("/state/profiles", PathKind::Dir)];
        let v = verify_custody(&items, DAEMON_UID, &fs);
        assert!(matches!(v[0], CustodyViolation::WrongKind { .. }));
    }

    #[test]
    fn multiple_violations_all_reported() {
        let fs = FakeFs::new(&[
            ("/state", dir(DAEMON_UID, 0o755)),
            ("/state/audit.hmac", file(AGENT_UID, 0o644)),
        ]);
        let items = [
            item("/state", PathKind::Dir),
            item("/state/audit.hmac", PathKind::File),
        ];
        let v = verify_custody(&items, DAEMON_UID, &fs);
        // dir too permissive + foreign owner + file too permissive
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn default_custody_set_covers_every_integrity_artifact() {
        let set = default_custody_set(Path::new("/var/lib/opaque"), Path::new("/etc/opaque.toml"));
        let paths: Vec<String> = set.iter().map(|c| c.path.display().to_string()).collect();
        for expected in [
            "/var/lib/opaque/.opaque",
            "/etc/opaque.toml",
            "/etc/config.seal",
            "/etc/config.seal.key",
            "/var/lib/opaque/.opaque/audit.db",
            "/var/lib/opaque/.opaque/audit.hmac",
            "/var/lib/opaque/.opaque/identity.db",
            "/var/lib/opaque/.opaque/identity.key",
            "/var/lib/opaque/.opaque/profiles",
            "/var/lib/opaque/.opaque/bundle.state",
            "/var/lib/opaque/.opaque/export.cursor",
            "/var/lib/opaque/.opaque/pairing.key",
            "/var/lib/opaque/.opaque/approval_server.key",
            "/var/lib/opaque/.opaque/approval_server.cert",
            "/var/lib/opaque/.config/opaque",
            "/var/lib/opaque/.config/opaque/paired_devices.json",
            "/var/lib/opaque/.config/opaque/paired_devices.hmac",
            "/var/lib/opaque/.config/opaque/fido2_credentials.json",
        ] {
            assert!(paths.contains(&expected.to_string()), "missing {expected}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn real_fs_roundtrip_and_tighten() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("audit.hmac");
        std::fs::write(&key, b"k").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();

        let me = unsafe { libc::geteuid() };
        let items = [CustodyPath {
            path: key.clone(),
            kind: PathKind::File,
            label: "audit chain key",
        }];

        // Real lstat sees the loose mode…
        let v = verify_custody(&items, me, &SystemFs);
        assert!(matches!(v[0], CustodyViolation::TooPermissive { mode, .. } if mode == 0o644));

        // …tighten repairs it (owner keeps rw, group/other stripped)…
        let fixed = tighten_modes(&items, me);
        assert_eq!(fixed.len(), 1);
        assert_eq!(fixed[0].2, 0o600);

        // …and the set now verifies clean.
        assert!(verify_custody(&items, me, &SystemFs).is_empty());
    }

    /// Real multi-uid custody matrix. Requires root (chown + seteuid are the
    /// point); run via `scripts/linux-harness.sh isolation`, which executes it
    /// as root in a Linux environment and fails if it did not actually run.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root — run via scripts/linux-harness.sh isolation"]
    fn root_multi_uid_custody_matrix() {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "isolation suite must run as root (harness bug if not)"
        );

        const DAEMON: u32 = 7381;
        const AGENT: u32 = 7382;

        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(".opaque");
        std::fs::create_dir_all(&state).unwrap();
        let key = state.join("audit.hmac");
        std::fs::write(&key, b"chain-key-material").unwrap();
        let db = state.join("audit.db");
        std::fs::write(&db, b"audit-rows").unwrap();

        for p in [&state, &key, &db] {
            let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
            assert_eq!(unsafe { libc::chown(c.as_ptr(), DAEMON, DAEMON) }, 0);
        }
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
        // The tempdir itself must let the daemon/agent uids traverse to it.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

        let items = [
            CustodyPath {
                path: state.clone(),
                kind: PathKind::Dir,
                label: "state directory",
            },
            CustodyPath {
                path: key.clone(),
                kind: PathKind::File,
                label: "audit chain key",
            },
            CustodyPath {
                path: db.clone(),
                kind: PathKind::File,
                label: "audit database",
            },
        ];

        // Real lstat as root: custody verifies clean for the daemon uid…
        assert!(verify_custody(&items, DAEMON, &SystemFs).is_empty());
        // …and reports every file as foreign for the agent uid.
        assert_eq!(verify_custody(&items, AGENT, &SystemFs).len(), 3);

        // THE guarantee: with the agent's effective uid, the chain key, the
        // database, and the state dir are unreadable and unwritable (EACCES),
        // not merely "detected after the fact".
        assert_eq!(unsafe { libc::seteuid(AGENT) }, 0);
        for path in [&key, &db] {
            let read = std::fs::read(path);
            assert_eq!(
                read.unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied,
                "{} must be unreadable at the agent uid",
                path.display()
            );
            let write = std::fs::OpenOptions::new().append(true).open(path);
            assert_eq!(
                write.unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied,
                "{} must be unwritable at the agent uid",
                path.display()
            );
        }
        assert!(
            std::fs::read_dir(&state).is_err(),
            "state dir must not even enumerate at the agent uid"
        );
        // A forged replacement key can't be dropped in either (dir is 0700).
        assert!(std::fs::write(state.join("audit.hmac.new"), b"forged").is_err());
        assert_eq!(unsafe { libc::seteuid(0) }, 0);

        // The daemon's own effective uid retains full access.
        assert_eq!(unsafe { libc::seteuid(DAEMON) }, 0);
        assert_eq!(std::fs::read(&key).unwrap(), b"chain-key-material");
        assert!(std::fs::OpenOptions::new().append(true).open(&db).is_ok());
        assert_eq!(unsafe { libc::seteuid(0) }, 0);
    }

    #[cfg(unix)]
    #[test]
    fn tighten_never_touches_foreign_files() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("audit.hmac");
        std::fs::write(&key, b"k").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();

        let me = unsafe { libc::geteuid() };
        let items = [CustodyPath {
            path: key.clone(),
            kind: PathKind::File,
            label: "audit chain key",
        }];

        // Claim a different daemon uid: the file reads as foreign, so tighten
        // must leave it untouched.
        let fixed = tighten_modes(&items, me.wrapping_add(1));
        assert!(fixed.is_empty());
        use std::os::unix::fs::MetadataExt;
        assert_eq!(key.metadata().unwrap().mode() & 0o777, 0o644);
    }
}
