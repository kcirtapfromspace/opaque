//! Root-gated end-to-end proof of the trust-domain split, against the REAL
//! `opaqued` binary running as a dedicated uid.
//!
//! What this file demonstrates that unit tests cannot:
//!   1. The daemon comes up under `[trust_domain] enforce` as uid 7381 with
//!      custody verified, and the agent uid (7382) can read NONE of the
//!      custody files — EACCES at the kernel, not policy.
//!   2. Startup fails closed when the agent uid has stolen a custody file.
//!   3. An approval is settled by a PAIRED DEVICE'S Ed25519 signature over
//!      the daemon's challenge (through the real HTTPS approval server), and
//!      the audit chain records the approver as signature-bound
//!      (`paired_device`), not session-bound.
//!
//! Pairing bootstrap uses the insecure auto-approve backend (its one
//! legitimate purpose) in phase A; the daemon is then RESTARTED with the
//! native gate so the paired-device factor races alone in phase B.
//!
//! Runs only as root (`scripts/linux-harness.sh e2e-split`): it needs
//! setuid/setgroups to stage the two principals.

#![cfg(target_os = "linux")]

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const DAEMON_UID: u32 = 7381;
const AGENT_UID: u32 = 7382;
const SOCKET_GID: u32 = 7999;

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn rand_u32() -> u32 {
    let mut b = [0u8; 4];
    getrandom::fill(&mut b).unwrap();
    u32::from_le_bytes(b)
}

fn chown(path: &Path, uid: u32, gid: u32) {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(
        unsafe { libc::chown(c.as_ptr(), uid, gid) },
        0,
        "chown {} failed",
        path.display()
    );
}

fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Copy the daemon binary into the (world-traversable) test base and return
/// the copy's path. The cargo target dir may live under a 0750 home (GitHub
/// runners), where uid 7381 cannot even traverse to exec the original.
fn stage_daemon_binary(base: &Path) -> PathBuf {
    let dst = base.join("opaqued");
    std::fs::copy(env!("CARGO_BIN_EXE_opaqued"), &dst).expect("stage daemon binary");
    chmod(&dst, 0o755);
    dst
}

/// Run a probe command as the given principal, returning (success, output).
fn run_as(uid: u32, gid: u32, supplementary: &[u32], argv: &[&str]) -> (bool, String) {
    let mut cmd = Command::new(argv[0]);
    cmd.args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let sup: Vec<libc::gid_t> = supplementary.to_vec();
    unsafe {
        cmd.pre_exec(move || {
            if libc::setgroups(sup.len(), sup.as_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setgid(gid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setuid(uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = cmd.output().expect("probe spawn");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

struct SplitDaemon {
    child: Child,
    base: PathBuf,
    home: PathBuf,
    sock: PathBuf,
    daemon_token: String,
    log: PathBuf,
}

impl SplitDaemon {
    /// Stage a daemon home owned by the daemon uid and spawn the real binary
    /// AS that uid (setgroups → setgid → setuid pre-exec), with the socket at
    /// a short explicit path from the config.
    fn spawn(base: &Path, config_body: &str, extra_env: &[(&str, &str)]) -> Self {
        let home = base.join("home");
        let run = base.join("run");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&run).unwrap();
        chmod(base, 0o755);
        chown(&home, DAEMON_UID, DAEMON_UID);
        chmod(&home, 0o700);
        chown(&run, DAEMON_UID, SOCKET_GID);
        chmod(&run, 0o750);

        let sock = run.join("opaqued.sock");
        let config_path = home.join("config.toml");
        let config = format!(
            "{config_body}\n\n[trust_domain]\nenforce = true\nsocket_group = \"{SOCKET_GID}\"\nsocket_path = \"{}\"\n",
            sock.display()
        );
        std::fs::write(&config_path, config).unwrap();
        chown(&config_path, DAEMON_UID, DAEMON_UID);
        chmod(&config_path, 0o600);

        // Spawn via setpriv (util-linux) rather than a pre_exec setuid dance:
        // it is exactly what the container entrypoints do, and what the
        // manual reproduction validated.
        let daemon_bin = stage_daemon_binary(base);
        let log = base.join(format!("daemon-{:04x}.log", rand_u32() & 0xffff));
        let log_file = std::fs::File::create(&log).unwrap();
        let mut cmd = Command::new("setpriv");
        cmd.arg(format!("--reuid={DAEMON_UID}"))
            .arg(format!("--regid={DAEMON_UID}"))
            .arg(format!("--groups={SOCKET_GID}"))
            .arg(&daemon_bin)
            .env_clear()
            .env("HOME", &home)
            .env("OPAQUE_CONFIG", &config_path)
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(log_file);
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("spawn opaqued via setpriv");

        let token_path = run.join("daemon.token");
        let deadline = Instant::now() + Duration::from_secs(20);
        while (!sock.exists() || !token_path.exists()) && Instant::now() < deadline {
            if let Ok(Some(status)) = child.try_wait() {
                let err = std::fs::read_to_string(&log).unwrap_or_default();
                panic!("daemon exited early ({status}): {err}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if !sock.exists() || !token_path.exists() {
            let log_text = std::fs::read_to_string(&log).unwrap_or_default();
            panic!("split daemon did not come up; daemon log:\n{log_text}");
        }
        let daemon_token = std::fs::read_to_string(&token_path)
            .expect("read daemon token (root)")
            .trim()
            .to_owned();

        Self {
            child,
            base: base.to_path_buf(),
            home,
            sock,
            daemon_token,
            log,
        }
    }

    fn log_tail(&self) -> String {
        let text = std::fs::read_to_string(&self.log).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(30)..].join("\n")
    }

    async fn call_ok(&self, method: &str, params: Value) -> Value {
        let resp = raw_call(&self.sock, &self.daemon_token, method, params)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "{method} failed: {e}\ndaemon log tail:\n{}",
                    self.log_tail()
                )
            });
        assert!(
            resp.get("error").is_none_or(Value::is_null),
            "{method} returned error: {resp}"
        );
        resp.get("result").cloned().unwrap_or(Value::Null)
    }

    fn shutdown(mut self) -> PathBuf {
        let pid = self.child.id();
        unsafe { libc::kill(pid as i32, libc::SIGTERM) };
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
        self.base.clone()
    }
}

/// One request over a fresh connection, driving the real socket protocol.
/// The test runs as root (peer uid 0 ≠ daemon uid ⇒ admitted under the
/// enforce-mode inversion).
async fn raw_call(
    sock: &Path,
    daemon_token: &str,
    method: &str,
    params: Value,
) -> Result<Value, String> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_util::codec::{Framed, LengthDelimitedCodec};

    let stream = tokio::net::UnixStream::connect(sock)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let codec = LengthDelimitedCodec::builder()
        .max_frame_length(opaque_core::MAX_FRAME_LENGTH)
        .new_codec();
    let mut framed = Framed::new(stream, codec);

    let handshake = json!({"handshake": "v1", "daemon_token": daemon_token});
    framed
        .send(serde_json::to_vec(&handshake).unwrap().into())
        .await
        .map_err(|e| format!("send handshake: {e}"))?;
    framed
        .send(
            serde_json::to_vec(&json!({"id": 1, "method": method, "params": params}))
                .unwrap()
                .into(),
        )
        .await
        .map_err(|e| format!("send request: {e}"))?;
    match tokio::time::timeout(Duration::from_secs(45), framed.next()).await {
        Err(_) => Err("response timeout".into()),
        Ok(None) => Err("connection closed before response".into()),
        Ok(Some(Err(e))) => Err(format!("frame error: {e}")),
        Ok(Some(Ok(frame))) => {
            serde_json::from_slice(&frame).map_err(|e| format!("bad response json: {e}"))
        }
    }
}

/// Recompute the signable decision bytes exactly as
/// `opaqued::pairing::challenge::decision_bytes` defines them — this test
/// plays the phone, so it reimplements the device side of the protocol.
fn decision_bytes(challenge: &Value, approve: bool) -> Vec<u8> {
    use sha2::{Digest, Sha256};

    fn append_field(buf: &mut Vec<u8>, data: &[u8]) {
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(data);
    }

    let mut buf = Vec::new();
    append_field(
        &mut buf,
        challenge["server_id"].as_str().unwrap().as_bytes(),
    );
    append_field(
        &mut buf,
        challenge["request_id"].as_str().unwrap().as_bytes(),
    );
    append_field(
        &mut buf,
        challenge["operation_summary_hash"]
            .as_str()
            .unwrap()
            .as_bytes(),
    );
    append_field(
        &mut buf,
        &challenge["expires_at"].as_i64().unwrap().to_le_bytes(),
    );
    append_field(
        &mut buf,
        if approve {
            b"opaque-approve"
        } else {
            b"opaque-reject"
        },
    );
    Sha256::digest(&buf).to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn https_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

/// Custody at the agent uid + the full signature-bound approval loop.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root — run via scripts/linux-harness.sh e2e-split"]
async fn split_daemon_custody_and_signature_bound_approver() {
    assert!(is_root(), "e2e-split must run as root (harness bug if not)");

    let base = PathBuf::from(format!("/tmp/oqtd{:08x}", rand_u32()));
    std::fs::create_dir_all(&base).unwrap();

    let approval_port = 40000 + (std::process::id() % 20000) as u16;

    // ---- Phase A: pair + confirm a device under the auto-approve backend.
    let phase_a_config = format!(
        "approval_backend = \"insecure_auto_approve\"\n\n[approval]\nsecond_device = true\nserver_bind = \"127.0.0.1:{approval_port}\"\ntimeout_secs = 30\n"
    );
    let daemon = SplitDaemon::spawn(
        &base,
        &phase_a_config,
        &[("OPAQUE_INSECURE_AUTO_APPROVE", "1")],
    );

    daemon.call_ok("ping", Value::Null).await;

    let pair_start = daemon.call_ok("device_pair_start", Value::Null).await;
    let nonce = pair_start["qr_payload"]["nonce"]
        .as_str()
        .unwrap()
        .to_owned();
    let server_addr = pair_start["server_addr"].as_str().unwrap().to_owned();

    // The phone: fresh Ed25519 key, complete pairing over the real HTTPS server.
    let device_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let client = https_client();
    let pair: Value = client
        .post(format!("https://{server_addr}/pair"))
        .json(&json!({
            "nonce": nonce,
            "device_public_key": hex(device_key.verifying_key().as_bytes()),
            "device_name": "E2E Phone",
        }))
        .send()
        .await
        .expect("pair request")
        .json()
        .await
        .expect("pair response json");
    let device_id = pair["device_id"].as_str().unwrap().to_owned();
    let device_token = pair["token"].as_str().unwrap().to_owned();

    daemon
        .call_ok("device_pair_confirm", json!({ "device_id": device_id }))
        .await;

    // ---- Custody: the agent uid gets EACCES on every custody artifact.
    let state = daemon.home.join(".opaque");
    for artifact in [
        "audit.hmac",
        "audit.db",
        "pairing.key",
        "approval_server.key",
    ] {
        let path = state.join(artifact);
        assert!(path.exists(), "{artifact} should exist by now");
        let (ok, out) = run_as(
            AGENT_UID,
            AGENT_UID,
            &[SOCKET_GID],
            &["cat", path.to_str().unwrap()],
        );
        assert!(
            !ok && out.contains("Permission denied"),
            "{artifact} must be unreadable at the agent uid, got ok={ok}: {out}"
        );
    }
    // The daemon uid reads its own custody fine (control).
    let (ok, _) = run_as(
        DAEMON_UID,
        DAEMON_UID,
        &[],
        &["cat", state.join("audit.hmac").to_str().unwrap()],
    );
    assert!(ok, "daemon uid must read its own chain key");
    // And the device store under ~/.config is equally out of reach.
    let store = daemon
        .home
        .join(".config")
        .join("opaque")
        .join("paired_devices.json");
    let (ok, out) = run_as(
        AGENT_UID,
        AGENT_UID,
        &[SOCKET_GID],
        &["cat", store.to_str().unwrap()],
    );
    assert!(!ok && out.contains("Permission denied"), "{out}");

    let base = daemon.shutdown();

    // ---- Phase B: native gate; test.noop approvals pinned to the device factor.
    let phase_b_config = format!(
        "[approval]\nsecond_device = true\nserver_bind = \"127.0.0.1:{approval_port}\"\ntimeout_secs = 30\n\n[[rules]]\nname = \"noop-via-device\"\noperation_pattern = \"test.noop\"\nallow = true\n\n[rules.approval]\nrequire = \"always\"\nfactors = [\"ios_face_id\"]\n"
    );
    let daemon = SplitDaemon::spawn(&base, &phase_b_config, &[]);

    // Kick off the operation; it blocks until the device decides.
    let exec = tokio::spawn({
        let sock = daemon.sock.clone();
        let token = daemon.daemon_token.clone();
        async move {
            raw_call(
                &sock,
                &token,
                "execute",
                json!({"operation": "test.noop", "target": {}, "secret_ref_names": []}),
            )
            .await
        }
    });

    // The phone: poll pending, sign the approve decision, respond.
    let pending_url = format!("https://127.0.0.1:{approval_port}/approvals/pending");
    let mut challenge: Option<Value> = None;
    let deadline = Instant::now() + Duration::from_secs(20);
    while challenge.is_none() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let resp = client
            .get(&pending_url)
            .header("Authorization", format!("Bearer {device_token}"))
            .header("X-Opaque-Device", &device_id)
            .send()
            .await;
        if let Ok(resp) = resp
            && resp.status().is_success()
            && let Ok(body) = resp.json::<Value>().await
            && let Some(first) = body["approvals"].as_array().and_then(|a| a.first())
        {
            challenge = Some(first.clone());
        }
    }
    let wire = challenge.expect("an approval challenge must reach the device");
    let pairing_challenge: Value =
        serde_json::from_str(wire["challenge_data"].as_str().unwrap()).unwrap();

    use ed25519_dalek::Signer;
    let signature = device_key.sign(&decision_bytes(&pairing_challenge, true));
    let respond_url = format!(
        "https://127.0.0.1:{approval_port}/approvals/{}/respond",
        wire["request_id"].as_str().unwrap()
    );
    let resp = client
        .post(&respond_url)
        .header("Authorization", format!("Bearer {device_token}"))
        .header("X-Opaque-Device", &device_id)
        .json(&json!({
            "decision": "approve",
            "signature": hex(&signature.to_bytes()),
            "device_id": device_id,
        }))
        .send()
        .await
        .expect("respond request");
    assert!(
        resp.status().is_success(),
        "signed approve must verify: {}",
        resp.status()
    );

    // The blocked operation completes, approved by the device signature.
    let exec_resp = exec.await.unwrap().expect("execute call");
    assert!(
        exec_resp.get("error").is_none_or(Value::is_null),
        "test.noop must succeed after the signed approval: {exec_resp}"
    );

    let base = daemon.shutdown();

    // ---- The audit chain (readable as root) records a SIGNATURE-BOUND approver.
    let db = base.join("home").join(".opaque").join("audit.db");
    let conn = rusqlite::Connection::open(&db).unwrap();
    // Context dump for diagnostics: the last dozen events.
    {
        let mut stmt = conn
            .prepare(
                "SELECT sequence_number, kind, operation, outcome, approver_json \
                 FROM audit_events ORDER BY sequence_number DESC LIMIT 12",
            )
            .unwrap();
        let rows = stmt
            .query_map([], |r| {
                Ok(format!(
                    "seq={} kind={} op={:?} outcome={:?} approver={:?}",
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        eprintln!("audit tail:\n{}", rows.join("\n"));
    }
    let approver_json: String = conn
        .query_row(
            "SELECT approver_json FROM audit_events \
             WHERE kind = 'approval.granted' AND approver_json IS NOT NULL \
             ORDER BY sequence_number DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("an approval.granted row with an approver must exist");
    let approver: Value = serde_json::from_str(&approver_json).unwrap();
    assert_eq!(
        approver["source"].as_str().unwrap(),
        "paired_device",
        "approver must be signature-bound: {approver}"
    );
    assert_eq!(
        approver["principal_id"].as_str().unwrap(),
        format!("device:{device_id}"),
        "approver must be the verified device: {approver}"
    );

    // Chain still verifies end to end.
    let verification = opaque_core::audit::verify_audit_chain(&db).unwrap();
    assert!(verification.ok, "audit chain must verify: {verification:?}");

    let _ = std::fs::remove_dir_all(&base);
}

/// Startup fails closed when the agent uid holds a custody artifact.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root — run via scripts/linux-harness.sh e2e-split"]
async fn split_daemon_refuses_stolen_custody() {
    assert!(is_root(), "e2e-split must run as root (harness bug if not)");

    let base = PathBuf::from(format!("/tmp/oqtd{:08x}", rand_u32()));
    let home = base.join("home");
    let state = home.join(".opaque");
    std::fs::create_dir_all(&state).unwrap();
    chmod(&base, 0o755);

    // Stage state owned by the daemon… except the chain key, stolen by 7382.
    let key = state.join("audit.hmac");
    std::fs::write(&key, [7u8; 32]).unwrap();
    for p in [&home, &state] {
        chown(p, DAEMON_UID, DAEMON_UID);
        chmod(p, 0o700);
    }
    chown(&key, AGENT_UID, AGENT_UID);
    chmod(&key, 0o600);

    let run = base.join("run");
    std::fs::create_dir_all(&run).unwrap();
    chown(&run, DAEMON_UID, SOCKET_GID);
    chmod(&run, 0o750);

    let config_path = home.join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            "[trust_domain]\nenforce = true\nsocket_group = \"{SOCKET_GID}\"\nsocket_path = \"{}\"\n",
            run.join("opaqued.sock").display()
        ),
    )
    .unwrap();
    chown(&config_path, DAEMON_UID, DAEMON_UID);
    chmod(&config_path, 0o600);

    let daemon_bin = stage_daemon_binary(&base);
    let mut cmd = Command::new(&daemon_bin);
    cmd.env_clear()
        .env("HOME", &home)
        .env("OPAQUE_CONFIG", &config_path)
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    unsafe {
        cmd.pre_exec(|| {
            let sup = [SOCKET_GID as libc::gid_t];
            if libc::setgroups(1, sup.as_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setgid(DAEMON_UID) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setuid(DAEMON_UID) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = cmd.output().expect("spawn opaqued");
    assert!(
        !out.status.success(),
        "daemon MUST refuse to start with a stolen chain key"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("custody violation") && stderr.contains("audit chain key"),
        "refusal must name the stolen artifact: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&base);
}
