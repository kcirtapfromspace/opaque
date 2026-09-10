//! End-to-end proof of the federation phase against the REAL `opaqued`
//! binary: signed policy bundles, SIEM export, and posture attestation
//! working together on one daemon.
//!
//! What this demonstrates that unit tests cannot:
//!   1. A signed bundle governs a real daemon's policy — an operation the
//!      LOCAL config never allowed succeeds because the bundle allows it.
//!   2. A rollback to an older signed bundle is refused across a restart,
//!      and the refusal is recorded in the audit chain.
//!   3. Exported records carry chain hashes that match the database — the
//!      SIEM stream is externally verifiable, not a parallel log.
//!   4. The daemon's attestation report verifies against a caller nonce and
//!      reports the applied bundle.
//!
//! Socket paths stay short (macOS `SUN_LEN`), so the runtime dir lives
//! directly under /tmp rather than a nested tempdir.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use opaque_core::bundle::{BundlePayload, Team, sign_bundle};
use serde_json::{Value, json};

/// These spawn real daemons; running several at once causes socket and
/// resource contention. Serialize them. `tokio::test` without a flavor is a
/// CURRENT-THREAD runtime, so the future never migrates between threads and
/// holding a std guard across awaits is sound (same pattern as identity_e2e).
static E2E_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
    E2E_SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn rand_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).unwrap();
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A bundle that allows `test.noop` with no approval — something the local
/// (empty) config would deny by default.
fn bundle_payload(version: u64) -> BundlePayload {
    let rule: opaque_core::policy::PolicyRule = toml_edit::de::from_str(
        r#"
        name = "bundle-allows-noop"
        operation_pattern = "test.noop"
        allow = true
        "#,
    )
    .unwrap();
    BundlePayload {
        org: "acme".into(),
        version,
        issued_at: now_unix() - 60,
        expires_at: None,
        key_id: String::new(),
        teams: vec![Team {
            name: "platform".into(),
            members: vec!["alice@acme.com".into()],
        }],
        rules: vec![rule],
        mcp_registry: None,
    }
}

struct Fixture {
    /// Signed bundle text per version. Re-signing would produce different
    /// bytes (fresh issued_at) under the same version, which the daemon
    /// correctly refuses as a substitution — so a restore must replay the
    /// EXACT bytes that were applied.
    signed: std::sync::Mutex<std::collections::HashMap<u64, String>>,
    home: tempfile::TempDir,
    runtime_dir: PathBuf,
    bundle_file: PathBuf,
    spool_file: PathBuf,
    org_key: SigningKey,
}

impl Fixture {
    fn new() -> Self {
        let home = tempfile::tempdir().expect("home tempdir");
        let tmp_base = Path::new("/tmp")
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from("/tmp"));
        let runtime_dir = tmp_base.join(format!("oqfed{}-{}", std::process::id(), rand_hex(4)));
        std::fs::create_dir_all(&runtime_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        let bundle_file = home.path().join("policy.bundle");
        let spool_file = home.path().join("audit.jsonl");
        Self {
            signed: std::sync::Mutex::new(std::collections::HashMap::new()),
            home,
            runtime_dir,
            bundle_file,
            spool_file,
            org_key: SigningKey::from_bytes(&[42u8; 32]),
        }
    }

    /// Write the bundle for `version`, signing it once and replaying the
    /// same bytes on any later restore.
    fn write_bundle(&self, version: u64) {
        let mut cache = self.signed.lock().unwrap();
        let text = cache
            .entry(version)
            .or_insert_with(|| sign_bundle(&bundle_payload(version), &self.org_key).unwrap())
            .clone();
        std::fs::write(&self.bundle_file, text).unwrap();
    }

    /// Write a DIFFERENT bundle carrying an already-applied version number —
    /// the substitution case.
    fn write_substituted_bundle(&self, version: u64) {
        let mut payload = bundle_payload(version);
        payload.teams.clear(); // same version, different content
        let text = sign_bundle(&payload, &self.org_key).unwrap();
        std::fs::write(&self.bundle_file, text).unwrap();
    }

    /// Write a daemon config wiring federation + export + attestation.
    fn write_config(&self, require_bundle: bool) -> PathBuf {
        let config_path = self.home.path().join("config.toml");
        let config = format!(
            r#"
# The enclave clamps approval to each operation's floor, and test.noop's
# floor is FirstUse — so an unattended e2e needs the test approval backend
# (which additionally demands OPAQUE_INSECURE_AUTO_APPROVE=1 in the env).
approval_backend = "insecure_auto_approve"

[federation]
trust_anchors = ["{anchor}"]
bundle_path = "{bundle}"
require_bundle = {require}
refresh_secs = 0

[export]
spool_path = "{spool}"
poll_secs = 1

[attestation]
interval_secs = 0
"#,
            anchor = hex(self.org_key.verifying_key().as_bytes()),
            bundle = self.bundle_file.display(),
            require = require_bundle,
            spool = self.spool_file.display(),
        );
        std::fs::write(&config_path, config).unwrap();
        config_path
    }

    fn audit_db(&self) -> PathBuf {
        self.home.path().join(".opaque").join("audit.db")
    }

    fn spawn(&self, config_path: &Path) -> Daemon {
        // Clear artifacts from a previous daemon in this fixture: otherwise
        // the readiness loop can latch a STALE socket+token pair before the
        // new daemon rebinds, and the handshake then fails with a token
        // mismatch that presents as a silently closed connection.
        let sock = self.runtime_dir.join("opaque").join("opaqued.sock");
        let token_path = self.runtime_dir.join("opaque").join("daemon.token");
        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_file(&token_path);

        let log = self.home.path().join(format!("daemon-{}.log", rand_hex(3)));
        let log_file = std::fs::File::create(&log).unwrap();
        // The daemon's tracing subscriber writes to STDOUT; capture both
        // streams or the log looks mysteriously empty.
        let log_stdout = log_file.try_clone().unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_opaqued"))
            .env("HOME", self.home.path())
            .env("XDG_RUNTIME_DIR", &self.runtime_dir)
            .env("OPAQUE_CONFIG", config_path)
            .env("RUST_LOG", "info")
            .env("OPAQUE_INSECURE_AUTO_APPROVE", "1")
            .env_remove("OPAQUE_SOCK")
            .stdout(Stdio::from(log_stdout))
            .stderr(log_file)
            .spawn()
            .expect("spawn opaqued");

        let mut daemon = Daemon {
            child_pid: child.id(),
            child,
            sock,
            token: String::new(),
            log,
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        while (!daemon.sock.exists() || !token_path.exists()) && Instant::now() < deadline {
            if let Ok(Some(status)) = daemon.child.try_wait() {
                panic!(
                    "daemon exited early ({status}):\n{}",
                    std::fs::read_to_string(&daemon.log).unwrap_or_default()
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            daemon.sock.exists() && token_path.exists(),
            "daemon did not come up:\n{}",
            std::fs::read_to_string(&daemon.log).unwrap_or_default()
        );
        daemon.token = std::fs::read_to_string(&token_path)
            .expect("daemon token")
            .trim()
            .to_owned();
        daemon
    }

    /// Spawn expecting failure; returns the daemon's stderr.
    fn spawn_expecting_exit(&self, config_path: &Path) -> String {
        let out = Command::new(env!("CARGO_BIN_EXE_opaqued"))
            .env("HOME", self.home.path())
            .env("XDG_RUNTIME_DIR", &self.runtime_dir)
            .env("OPAQUE_CONFIG", config_path)
            .env("RUST_LOG", "info")
            .env("OPAQUE_INSECURE_AUTO_APPROVE", "1")
            .env_remove("OPAQUE_SOCK")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("spawn opaqued");
        assert!(
            !out.status.success(),
            "daemon was expected to refuse startup but ran"
        );
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.runtime_dir);
    }
}

struct Daemon {
    child_pid: u32,
    child: Child,
    sock: PathBuf,
    token: String,
    log: PathBuf,
}

impl Daemon {
    async fn call(&self, method: &str, params: Value) -> Value {
        use futures_util::{SinkExt, StreamExt};
        use tokio_util::codec::{Framed, LengthDelimitedCodec};

        let stream = tokio::net::UnixStream::connect(&self.sock)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "connect: {e}\ndaemon log:\n{}",
                    std::fs::read_to_string(&self.log).unwrap_or_default()
                )
            });
        let codec = LengthDelimitedCodec::builder()
            .max_frame_length(opaque_core::MAX_FRAME_LENGTH)
            .new_codec();
        let mut framed = Framed::new(stream, codec);

        let handshake = json!({"handshake": "v1", "daemon_token": self.token});
        framed
            .send(serde_json::to_vec(&handshake).unwrap().into())
            .await
            .expect("send handshake");
        framed
            .send(
                serde_json::to_vec(&json!({"id": 1, "method": method, "params": params}))
                    .unwrap()
                    .into(),
            )
            .await
            .expect("send request");
        match tokio::time::timeout(Duration::from_secs(20), framed.next()).await {
            Ok(Some(Ok(frame))) => serde_json::from_slice(&frame).expect("response json"),
            other => {
                // Give the daemon a moment to finish writing before reading,
                // and report whether it is still alive.
                std::thread::sleep(Duration::from_millis(300));
                panic!(
                    "{method} failed: {other:?}\ndaemon alive: {}\ndaemon log:\n{}",
                    std::process::Command::new("kill")
                        .args(["-0", &self.child_pid.to_string()])
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false),
                    std::fs::read_to_string(&self.log).unwrap_or_default()
                )
            }
        }
    }

    async fn call_ok(&self, method: &str, params: Value) -> Value {
        let resp = self.call(method, params).await;
        assert!(
            resp.get("error").is_none_or(Value::is_null),
            "{method} returned error: {resp}"
        );
        resp.get("result").cloned().unwrap_or(Value::Null)
    }

    fn shutdown(mut self) {
        unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
            }
        }
    }
}

/// The whole phase on one daemon: a signed bundle governs policy, the
/// export stream is chain-verifiable, and attestation reports the truth.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // deliberate: serialize real daemons (current-thread runtime)
async fn signed_bundle_governs_policy_export_and_attestation() {
    let _serial = serial_guard();
    let fixture = Fixture::new();
    fixture.write_bundle(1);
    let config_path = fixture.write_config(true);
    let daemon = fixture.spawn(&config_path);

    // 1. The bundle is applied and visible.
    let version = daemon.call_ok("version", Value::Null).await;
    let federation = version
        .get("federation")
        .filter(|v| !v.is_null())
        .expect("federation status reported");
    assert_eq!(federation["org"], "acme");
    assert_eq!(federation["bundle_version"], 1);

    // 2. The BUNDLE's rule governs: test.noop is allowed by the bundle and
    //    by nothing in the local config (which has no [[rules]] at all).
    let exec = daemon
        .call(
            "execute",
            json!({"operation": "test.noop", "target": {}, "secret_ref_names": []}),
        )
        .await;
    assert!(
        exec.get("error").is_none_or(Value::is_null),
        "bundle rule must allow test.noop: {exec}"
    );

    // 3. Attestation reports the applied bundle and verifies against a
    //    caller-chosen nonce.
    let nonce = rand_hex(16);
    let attested = daemon
        .call_ok("attestation_report", json!({ "nonce": nonce }))
        .await;
    let report = attested["report"].as_str().expect("report");
    let key_hex = attested["attestation_key"].as_str().expect("key");
    let key = opaque_core::bundle::parse_anchor(key_hex).expect("attestation key parses");
    let verified = opaque_core::attest::verify_report(report, &key, &nonce, now_unix(), 120)
        .expect("attestation verifies");
    assert!(
        verified.payload.integrity_ok(),
        "posture: {:?}",
        verified.payload
    );
    let fed = verified.payload.federation.expect("bundle in attestation");
    assert_eq!(fed.org, "acme");
    assert_eq!(fed.version, 1);

    // A replay of that report against a different nonce must fail.
    assert!(
        opaque_core::attest::verify_report(report, &key, &rand_hex(16), now_unix(), 120).is_err(),
        "nonce binding must reject a replayed report"
    );

    daemon.shutdown();

    // 4. The exported stream is chain-verifiable: every spooled record's
    //    hash matches the database row it claims to be.
    let spool = std::fs::read_to_string(&fixture.spool_file).expect("spool written");
    let records: Vec<Value> = spool
        .lines()
        .map(|l| serde_json::from_str(l).expect("spool line is json"))
        .collect();
    assert!(!records.is_empty(), "export produced no records");

    let conn = rusqlite::Connection::open(fixture.audit_db()).unwrap();
    for record in &records {
        let seq = record["sequence_number"].as_i64().expect("sequence");
        let exported_hash = record["record_hash"].as_str().expect("record hash");
        let db_hash: String = conn
            .query_row(
                "SELECT record_hash FROM audit_events WHERE sequence_number = ?1",
                [seq],
                |r| r.get(0),
            )
            .unwrap_or_else(|e| panic!("seq {seq} missing from chain: {e}"));
        assert_eq!(
            exported_hash, db_hash,
            "exported record {seq} does not match the chain"
        );
    }

    // The federation application itself was audited and exported.
    assert!(
        records
            .iter()
            .any(|r| r["kind"] == "federation.bundle_applied"),
        "bundle application must appear in the export stream"
    );

    // And the chain still verifies end to end.
    let verification = opaque_core::audit::verify_audit_chain(&fixture.audit_db()).unwrap();
    assert!(verification.ok, "audit chain must verify: {verification:?}");
}

/// A rollback to an older signed bundle is refused across a restart, the
/// refusal is audited, and under require_bundle the daemon fails closed.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // deliberate: serialize real daemons (current-thread runtime)
async fn bundle_rollback_is_refused_across_restart() {
    let _serial = serial_guard();
    let fixture = Fixture::new();

    // Apply v3.
    fixture.write_bundle(3);
    let config_path = fixture.write_config(true);
    let daemon = fixture.spawn(&config_path);
    let version = daemon.call_ok("version", Value::Null).await;
    assert_eq!(version["federation"]["bundle_version"], 3);
    daemon.shutdown();

    // Restart with v2 in place: refused, fail closed.
    fixture.write_bundle(2);
    let stderr = fixture.spawn_expecting_exit(&config_path);
    assert!(
        stderr.contains("rollback refused"),
        "startup must name the rollback: {stderr}"
    );
    assert!(
        stderr.contains("fail closed"),
        "require_bundle must fail closed: {stderr}"
    );

    // The refusal is in the tamper-evident chain, and the applied state is
    // still v3 — a rejected bundle never moves the anti-rollback floor.
    let conn = rusqlite::Connection::open(fixture.audit_db()).unwrap();
    let outcome: String = conn
        .query_row(
            "SELECT outcome FROM audit_events WHERE kind = 'federation.bundle_rejected' \
             ORDER BY sequence_number DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .expect("a rejection event must exist");
    assert_eq!(outcome, "rollback_refused");
    drop(conn);

    let state: Value = serde_json::from_str(
        &std::fs::read_to_string(fixture.home.path().join(".opaque").join("bundle.state")).unwrap(),
    )
    .unwrap();
    assert_eq!(state["version"], 3, "anti-rollback floor must hold");

    // A DIFFERENT bundle minted under the already-applied version 3 is
    // refused too — signing authority does not permit silently swapping the
    // contents of a version a fleet has already applied.
    fixture.write_substituted_bundle(3);
    let stderr = fixture.spawn_expecting_exit(&config_path);
    assert!(
        stderr.contains("already applied with different content"),
        "substitution must be named as such: {stderr}"
    );

    // Putting the ORIGINAL v3 bytes back lets it start again — the refusals
    // were about rollback and substitution, not a wedged daemon.
    fixture.write_bundle(3);
    let daemon = fixture.spawn(&config_path);
    let version = daemon.call_ok("version", Value::Null).await;
    assert_eq!(version["federation"]["bundle_version"], 3);
    daemon.shutdown();

    let verification = opaque_core::audit::verify_audit_chain(&fixture.audit_db()).unwrap();
    assert!(
        verification.ok,
        "chain must verify across restarts: {verification:?}"
    );
}

/// A bundle signed by a key the daemon does not trust never applies, and
/// under require_bundle the daemon refuses to start at all.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // deliberate: serialize real daemons (current-thread runtime)
async fn untrusted_bundle_never_applies() {
    let _serial = serial_guard();
    let fixture = Fixture::new();

    // Sign with a key that is NOT the configured trust anchor.
    let impostor = SigningKey::from_bytes(&[77u8; 32]);
    let text = sign_bundle(&bundle_payload(1), &impostor).unwrap();
    std::fs::write(&fixture.bundle_file, text).unwrap();

    let config_path = fixture.write_config(true);
    let stderr = fixture.spawn_expecting_exit(&config_path);
    assert!(
        stderr.contains("signature") || stderr.contains("trust anchor"),
        "refusal must name the signature failure: {stderr}"
    );

    // Nothing was applied: no state file was written.
    assert!(
        !fixture
            .home
            .path()
            .join(".opaque")
            .join("bundle.state")
            .exists(),
        "an unverified bundle must not touch the anti-rollback state"
    );
}
