//! Daemon-side trust-domain enforcement.
//!
//! The portable custody rules live in `opaque_core::trust_domain`; this module
//! is the process-level half: dropping privileges into the service account,
//! granting a client group access to the socket surface, orchestrating the
//! startup custody check, and deciding which peer uids a connection may come
//! from under each mode.
//!
//! Two modes exist:
//!
//! - **Shared-uid (default, developer mode):** daemon and clients run as the
//!   same user. Custody problems are *reported*, connections must come from
//!   the daemon's own uid (the pre-existing multi-user protection).
//! - **Enforced split (`[trust_domain] enforce = true`):** the daemon runs as
//!   a dedicated service account. Startup fails closed unless every custody
//!   file is exclusively the daemon's; connections from the daemon's own uid
//!   are refused (nothing legitimate runs as the service account except the
//!   daemon itself), and clients reach the socket only through membership in
//!   `socket_group`.

use std::ffi::CString;
use std::io;
use std::path::Path;

use opaque_core::trust_domain::{CustodyViolation, SystemFs, custody_paths};
use tracing::{info, warn};

/// Which peer uids may hold a connection, given the daemon's mode.
///
/// Pure so both directions of the rule are unit-testable. `enforce` inverts
/// the check: shared-uid mode admits only the daemon's own uid (multi-user
/// protection), the enforced split refuses exactly that uid (a peer running
/// as the service account inside its own trust domain is a breach, not a
/// client) and lets socket permissions + the daemon token gate everyone else.
pub fn peer_uid_allowed(peer_uid: u32, daemon_uid: u32, enforce: bool) -> bool {
    if enforce {
        peer_uid != daemon_uid
    } else {
        peer_uid == daemon_uid
    }
}

/// Run the startup custody check over the daemon's custody set.
///
/// Always tightens modes on daemon-owned files first (self-heal for drift),
/// then verifies. In enforce mode any surviving violation is fatal; otherwise
/// each is logged, making the daemon's actual security posture visible
/// without breaking shared-uid developer setups.
#[cfg(test)]
pub fn startup_custody_check(
    enforce: bool,
    home: &Path,
    config_path: &Path,
) -> io::Result<Vec<CustodyViolation>> {
    startup_custody_check_at(enforce, home, config_path, &home.join(".opaque"))
}

pub fn startup_custody_check_at(
    enforce: bool,
    home: &Path,
    config_path: &Path,
    state_dir: &Path,
) -> io::Result<Vec<CustodyViolation>> {
    let daemon_uid = unsafe { libc::geteuid() };
    let set = custody_paths(home, config_path, state_dir);

    for (path, old, new) in opaque_core::trust_domain::tighten_modes(&set, daemon_uid) {
        info!(
            "custody: tightened {} from {old:04o} to {new:04o}",
            path.display()
        );
    }
    check_custody(enforce, daemon_uid, &set)
}

fn check_custody(
    enforce: bool,
    daemon_uid: u32,
    set: &[opaque_core::trust_domain::CustodyPath],
) -> io::Result<Vec<CustodyViolation>> {
    let violations = opaque_core::trust_domain::verify_custody(set, daemon_uid, &SystemFs);

    if violations.is_empty() {
        info!(
            "custody verified: {} paths exclusively owned by uid {daemon_uid}",
            set.len()
        );
        return Ok(violations);
    }

    if enforce {
        let detail: Vec<String> = violations.iter().map(|v| format!("  - {v}")).collect();
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "trust_domain.enforce is on and {} custody violation(s) block startup \
                 (fail closed — these files ARE the integrity guarantees):\n{}",
                violations.len(),
                detail.join("\n")
            ),
        ));
    }

    for v in &violations {
        warn!("custody (not enforced): {v}");
    }
    warn!(
        "trust domain NOT enforced — the audit chain, config seal, and delegation keys \
         above are only tamper-EVIDENT while another principal can reach them. \
         See docs/deployment.md for the service-account split."
    );
    Ok(violations)
}

/// Resolve a group name (or numeric gid) to its gid.
///
/// The numeric form exists for containers, which typically have no named
/// groups at all — compose/k8s grant the agent the gid via `group_add` /
/// `supplementalGroups` without an /etc/group entry anywhere.
pub fn resolve_gid(group: &str) -> io::Result<libc::gid_t> {
    if let Ok(gid) = group.parse::<libc::gid_t>() {
        return Ok(gid);
    }
    let c_name = CString::new(group)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "group name contains NUL"))?;
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0u8; 4096];
    let mut result: *mut libc::group = std::ptr::null_mut();

    let rc = unsafe {
        libc::getgrnam_r(
            c_name.as_ptr(),
            &mut grp,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    if result.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("group '{group}' does not exist — create it (e.g. groupadd {group})"),
        ));
    }
    Ok(grp.gr_gid)
}

struct ResolvedUser {
    uid: libc::uid_t,
    gid: libc::gid_t,
    home: String,
}

fn resolve_user(user: &str) -> io::Result<ResolvedUser> {
    let c_name = CString::new(user)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "user name contains NUL"))?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0u8; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();

    let rc = unsafe {
        libc::getpwnam_r(
            c_name.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    if result.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("user '{user}' does not exist — create the service account first"),
        ));
    }
    let home = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) }
        .to_string_lossy()
        .into_owned();
    Ok(ResolvedUser {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        home,
    })
}

/// Drop privileges from root into `user` — the non-systemd path (container
/// entrypoints, manual launches). Under systemd, prefer `User=`/`Group=`.
///
/// Order matters and is verified: supplementary groups, then gid, then uid,
/// then proof that root cannot be regained. The environment is repointed at
/// the service account (`HOME`, `USER`, `LOGNAME`; `XDG_RUNTIME_DIR` is
/// cleared rather than inherited from root) because every custody path the
/// daemon derives afterwards must land in the service account's world.
pub fn drop_privileges(user: &str) -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("trust_domain.run_as = \"{user}\" requires starting as root"),
        ));
    }

    let target = resolve_user(user)?;
    if target.uid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("trust_domain.run_as user '{user}' is uid 0 — refusing a no-op drop"),
        ));
    }

    let c_name = CString::new(user).expect("validated above");

    // Supplementary groups first (requires root).
    #[cfg(target_os = "macos")]
    let rc = unsafe { libc::initgroups(c_name.as_ptr(), target.gid as libc::c_int) };
    #[cfg(not(target_os = "macos"))]
    let rc = unsafe { libc::initgroups(c_name.as_ptr(), target.gid) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    if unsafe { libc::setgid(target.gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::setuid(target.uid) } != 0 {
        return Err(io::Error::last_os_error());
    }

    // The drop must be irreversible: with saved-set-uid handled correctly,
    // regaining root now fails. If it doesn't, refuse to run at all.
    if unsafe { libc::setuid(0) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "privilege drop was reversible (setuid(0) succeeded) — refusing to run",
        ));
    }

    // SAFETY: single-threaded startup — called before the tokio runtime spawns
    // worker threads that could be reading the environment concurrently.
    unsafe {
        std::env::set_var("HOME", &target.home);
        std::env::set_var("USER", user);
        std::env::set_var("LOGNAME", user);
        std::env::remove_var("XDG_RUNTIME_DIR");
    }

    info!(
        "dropped privileges to {user} (uid {}, gid {}, home {})",
        target.uid, target.gid, target.home
    );
    Ok(())
}

/// Check that this process can actually assign `gid` to files it owns:
/// POSIX lets a non-root owner chgrp only to groups in its own supplementary
/// set. Enforce mode verifies this up front so the failure is a clear
/// startup message, not an EPERM crashloop at the post-bind chgrp.
pub fn require_socket_group_membership(gid: libc::gid_t, group_label: &str) -> io::Result<()> {
    if unsafe { libc::geteuid() } == 0 {
        return Ok(()); // root may chgrp to anything
    }
    if unsafe { libc::getegid() } == gid {
        return Ok(());
    }
    let mut groups = [0 as libc::gid_t; 64];
    let n = unsafe { libc::getgroups(groups.len() as libc::c_int, groups.as_mut_ptr()) };
    if n >= 0 && groups[..n as usize].contains(&gid) {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "the daemon is not a member of socket_group {group_label} (gid {gid}), so it              cannot hand the socket to that group. Add the membership where the daemon              runs: systemd `SupplementaryGroups=`, compose/k8s `group_add` /              `supplementalGroups`, or usermod -aG."
        ),
    ))
}

/// Grant `gid` access to the socket surface for the enforced split:
/// socket dir `0750`, socket `0660`, daemon token `0640`. Everything else the
/// daemon owns stays owner-only; this is the *entire* cross-domain surface.
pub fn apply_socket_group(
    socket_dir: &Path,
    socket: &Path,
    token_path: &Path,
    gid: libc::gid_t,
) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    for (path, mode) in [(socket_dir, 0o750u32), (socket, 0o660), (token_path, 0o640)] {
        let c_path = CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL byte"))?;
        // Skip the chown when the group is already right (idempotent restarts,
        // setgid-inherited directories).
        let already = std::fs::metadata(path)
            .map(|m| {
                use std::os::unix::fs::MetadataExt;
                m.gid() == gid
            })
            .unwrap_or(false);
        // chown(uid = -1) leaves the owner untouched; only the group changes.
        if !already && unsafe { libc::chown(c_path.as_ptr(), libc::uid_t::MAX, gid) } != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "cannot set group on {}: {} — a non-root owner can chgrp only to                      groups in its supplementary set (see trust_domain.socket_group docs)",
                    path.display(),
                    io::Error::last_os_error()
                ),
            ));
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_state_custody_preserves_the_actual_config_location() {
        let user_root = Path::new("/example/user");
        let config = user_root.join(".opaque/config.toml");
        let isolated = Path::new("/example/isolated");
        let paths = custody_paths(user_root, &config, isolated);
        assert!(
            paths
                .iter()
                .any(|item| item.label == "daemon config" && item.path == config)
        );
        assert!(
            paths
                .iter()
                .any(|item| item.path == isolated.join("attestation.key"))
        );
        assert!(
            paths
                .iter()
                .any(|item| item.path == isolated.join("tasks.db.writer.lock"))
        );
        for item in paths {
            if !matches!(
                item.label,
                "daemon config" | "config seal key" | "config seal"
            ) {
                assert!(item.path.starts_with(isolated), "{}", item.path.display());
            }
        }
    }

    const DAEMON_UID: u32 = 500;

    #[test]
    fn shared_mode_admits_only_daemon_uid() {
        assert!(peer_uid_allowed(DAEMON_UID, DAEMON_UID, false));
        assert!(!peer_uid_allowed(501, DAEMON_UID, false));
        assert!(!peer_uid_allowed(0, DAEMON_UID, false));
    }

    #[test]
    fn enforced_split_refuses_daemon_uid_and_admits_others() {
        assert!(!peer_uid_allowed(DAEMON_UID, DAEMON_UID, true));
        assert!(peer_uid_allowed(501, DAEMON_UID, true));
        assert!(peer_uid_allowed(1000, DAEMON_UID, true));
    }

    #[test]
    fn resolve_gid_roundtrips_own_group() {
        // Find a name for our own gid via getgrgid, then resolve it back.
        let my_gid = unsafe { libc::getgid() };
        let grp = unsafe { libc::getgrgid(my_gid) };
        if grp.is_null() {
            return; // nameless gid (some containers) — nothing to roundtrip
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*grp).gr_name) }
            .to_string_lossy()
            .into_owned();
        assert_eq!(resolve_gid(&name).unwrap(), my_gid);
    }

    #[test]
    fn resolve_gid_unknown_group_is_not_found() {
        let err = resolve_gid("opaque-no-such-group-c9d2").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn resolve_gid_accepts_numeric_gid() {
        // Containers have no named groups; a numeric gid resolves directly.
        assert_eq!(resolve_gid("7999").unwrap(), 7999);
        assert_eq!(resolve_gid("0").unwrap(), 0);
    }

    #[test]
    fn socket_group_membership_check() {
        // Own egid always passes.
        let my_gid = unsafe { libc::getegid() };
        require_socket_group_membership(my_gid, "own-gid").unwrap();

        if unsafe { libc::geteuid() } == 0 {
            // Root may chgrp to anything — any gid passes.
            require_socket_group_membership(54_321, "any").unwrap();
        } else {
            // A gid we can't possibly hold fails with the diagnostic that
            // names the deployment fixes.
            let err = require_socket_group_membership(u32::MAX - 7, "ghost-group").unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
            assert!(err.to_string().contains("SupplementaryGroups"), "{err}");
        }
    }

    #[test]
    fn drop_privileges_refuses_without_root() {
        if unsafe { libc::geteuid() } == 0 {
            return; // covered by the Linux isolation suite when root
        }
        let err = drop_privileges("nobody").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn apply_socket_group_sets_split_surface_modes() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("opaqued.sock");
        let token = dir.path().join("daemon.token");
        std::fs::write(&sock, b"").unwrap();
        std::fs::write(&token, b"t").unwrap();

        // chgrp to our own gid is always permitted.
        let my_gid = unsafe { libc::getgid() };
        apply_socket_group(dir.path(), &sock, &token, my_gid).unwrap();

        assert_eq!(
            std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
            0o750
        );
        assert_eq!(
            std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777,
            0o660
        );
        assert_eq!(
            std::fs::metadata(&token).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(std::fs::metadata(&token).unwrap().gid(), my_gid);
    }

    #[test]
    fn custody_check_reports_but_allows_in_shared_mode() {
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::tempdir().unwrap();
        let state = home.path().join(".opaque");
        std::fs::create_dir_all(&state).unwrap();
        let config = state.join("config.toml");
        std::fs::write(&config, b"").unwrap();

        // A world-readable chain key: reported, not fatal, in shared mode…
        let key = state.join("audit.hmac");
        std::fs::write(&key, b"k").unwrap();
        // …but startup_custody_check tightens what we own, so pre-set an
        // untightenable violation instead: a symlinked custody path.
        std::fs::remove_file(&key).unwrap();
        std::os::unix::fs::symlink(home.path().join("elsewhere"), &key).unwrap();

        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();

        let report = startup_custody_check(false, home.path(), &config).unwrap();
        assert_eq!(report.len(), 1, "symlink violation should be reported");
    }

    #[test]
    fn custody_check_fails_closed_in_enforce_mode() {
        let home = tempfile::tempdir().unwrap();
        let state = home.path().join(".opaque");
        std::fs::create_dir_all(&state).unwrap();
        let config = state.join("config.toml");
        std::fs::write(&config, b"").unwrap();

        let key = state.join("audit.hmac");
        std::os::unix::fs::symlink(home.path().join("elsewhere"), &key).unwrap();

        let err = startup_custody_check(true, home.path(), &config).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("fail closed"));
    }

    /// Root-only: the startup custody check fails closed against a real
    /// agent-owned file, and the privilege drop genuinely sheds root.
    /// Run via `scripts/linux-harness.sh isolation`. The drop is irreversible,
    /// so everything needing root happens before it, in this one test.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root — run via scripts/linux-harness.sh isolation"]
    fn root_enforce_blocks_foreign_custody_then_privileges_drop() {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "isolation suite must run as root (harness bug if not)"
        );

        const DAEMON: u32 = 7381;
        const AGENT: u32 = 7382;

        // Daemon-owned state with ONE agent-owned interloper file.
        let home = tempfile::tempdir().unwrap();
        let state = home.path().join(".opaque");
        std::fs::create_dir_all(&state).unwrap();
        let config = state.join("config.toml");
        std::fs::write(&config, b"").unwrap();
        let key = state.join("audit.hmac");
        std::fs::write(&key, b"k").unwrap();

        std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        for (p, mode) in [(&state, 0o700u32), (&config, 0o600), (&key, 0o600)] {
            let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
            assert_eq!(unsafe { libc::chown(c.as_ptr(), DAEMON, DAEMON) }, 0);
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        // The agent grabs the chain key.
        let c = std::ffi::CString::new(key.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(c.as_ptr(), AGENT, AGENT) }, 0);

        // As the daemon principal, enforce mode must refuse to start.
        assert_eq!(unsafe { libc::seteuid(DAEMON) }, 0);
        let err = startup_custody_check(true, home.path(), &config).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            err.to_string().contains("audit chain key"),
            "error must name the stolen artifact: {err}"
        );
        assert_eq!(unsafe { libc::seteuid(0) }, 0);

        // Repossess it and enforce mode starts.
        let c = std::ffi::CString::new(key.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(c.as_ptr(), DAEMON, DAEMON) }, 0);
        assert_eq!(unsafe { libc::seteuid(DAEMON) }, 0);
        assert!(startup_custody_check(true, home.path(), &config).is_ok());
        assert_eq!(unsafe { libc::seteuid(0) }, 0);

        // Finally: a real, irreversible privilege drop. Create a service
        // account (nologin, no home creation) and drop into it.
        let user = "opaque-iso-test";
        let have_user = resolve_user(user).is_ok();
        if !have_user {
            let status = std::process::Command::new("useradd")
                .args(["--system", "-M", "--shell", "/usr/sbin/nologin", user])
                .status()
                .expect("useradd must exist in the isolation environment");
            assert!(status.success(), "useradd {user} failed");
        }

        drop_privileges(user).unwrap();
        let dropped = resolve_user_uid_for_test(user);
        assert_eq!(unsafe { libc::geteuid() }, dropped);
        assert_eq!(unsafe { libc::getuid() }, dropped);
        // Root is gone for good (drop_privileges itself re-checks, but assert
        // from the outside too).
        assert_ne!(unsafe { libc::setuid(0) }, 0);
        // And the environment now belongs to the service account.
        assert_eq!(std::env::var("USER").unwrap(), user);
    }

    #[cfg(target_os = "linux")]
    fn resolve_user_uid_for_test(user: &str) -> u32 {
        resolve_user(user).unwrap().uid
    }

    #[test]
    fn custody_check_tightens_loose_daemon_owned_files() {
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::tempdir().unwrap();
        let state = home.path().join(".opaque");
        std::fs::create_dir_all(&state).unwrap();
        let config = state.join("config.toml");
        std::fs::write(&config, b"").unwrap();
        let key = state.join("audit.hmac");
        std::fs::write(&key, b"k").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();

        // Even in enforce mode a loose-but-owned key is self-healed, not fatal.
        startup_custody_check(true, home.path(), &config).unwrap();
        assert_eq!(
            std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
