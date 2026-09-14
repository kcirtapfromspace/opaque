//! Actual daemon startup failures in disposable, sealed custody. All process
//! environments are private; macOS also denies access to the Keychain tool.
#![cfg(unix)]
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    state: PathBuf,
    config: PathBuf,
    socket: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = PathBuf::from("/tmp").canonicalize().unwrap();
        let dir = tempfile::Builder::new()
            .prefix("oqstart-")
            .tempdir_in(root)
            .unwrap();
        let home = dir.path().join("home");
        let state = home.join("state");
        fs::create_dir_all(&state).unwrap();
        for path in [&home, &state] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        #[cfg(target_os = "macos")]
        {
            let out = Command::new("/usr/bin/sandbox-exec")
                .args(["-p", Self::sandbox(), "/usr/bin/security", "help"])
                .output()
                .unwrap();
            assert_eq!(
                out.status.code(),
                Some(71),
                "Keychain isolation unavailable: {out:?}"
            );
            assert!(String::from_utf8_lossy(&out.stderr).contains("Operation not permitted"));
        }
        let config = home.join("config.toml");
        let socket = dir.path().join("run/opaqued.sock");
        Self {
            _dir: dir,
            home,
            state,
            config,
            socket,
        }
    }

    #[cfg(target_os = "macos")]
    fn sandbox() -> &'static str {
        "(version 1)(allow default)(deny process-exec (literal \"/usr/bin/security\"))"
    }

    fn document(&self) -> toml_edit::DocumentMut {
        format!(
            "data_dir = {:?}\nrequire_seal = true\n[trust_domain]\nenforce = true\nallow_root = true\nsocket_group = {:?}\nsocket_path = {:?}\n[attestation]\ninterval_secs = 0\n",
            self.state.to_str().unwrap(), unsafe { libc::getegid() }.to_string(), self.socket.to_str().unwrap()
        ).parse().unwrap()
    }

    fn reject(
        &self,
        document: &toml_edit::DocumentMut,
        env: &[(&str, &str)],
        expected: &str,
    ) -> String {
        let body = document.to_string();
        fs::write(&self.config, &body).unwrap();
        fs::set_permissions(&self.config, fs::Permissions::from_mode(0o600)).unwrap();
        let seal = self.home.join("config.seal");
        let key = opaque_core::seal::load_or_create_seal_key(&seal).unwrap();
        fs::write(
            &seal,
            opaque_core::seal::compute_seal_keyed(body.as_bytes(), &key),
        )
        .unwrap();
        fs::set_permissions(&seal, fs::Permissions::from_mode(0o600)).unwrap();
        #[cfg(target_os = "macos")]
        let mut command = {
            let mut c = Command::new("/usr/bin/sandbox-exec");
            c.args(["-p", Self::sandbox()])
                .arg(env!("CARGO_BIN_EXE_opaqued"));
            c
        };
        #[cfg(not(target_os = "macos"))]
        let mut command = Command::new(env!("CARGO_BIN_EXE_opaqued"));
        command
            .env_clear()
            .env("HOME", &self.home)
            .env("OPAQUE_CONFIG", &self.config)
            .env("PATH", "/usr/bin:/bin")
            .envs(env.iter().copied())
            .stdin(Stdio::null());
        #[cfg(coverage_nightly)]
        if let Some(dir) = std::env::var_os("OPAQUE_COVERAGE_PROFILE_DIR") {
            command.env(
                "LLVM_PROFILE_FILE",
                PathBuf::from(dir).join("daemon-%p-%m-%c.profraw"),
            );
        }
        let mut log = tempfile::tempfile().unwrap();
        command
            .stdout(log.try_clone().unwrap())
            .stderr(log.try_clone().unwrap());
        let mut child = command.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("daemon did not reject startup: {expected}");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        use std::io::{Read, Seek};
        log.rewind().unwrap();
        let mut output = String::new();
        log.read_to_string(&mut output).unwrap();
        assert_eq!(status.code(), Some(1), "expected {expected}: {output}");
        assert!(output.contains(expected), "expected {expected}: {output}");
        assert!(!output.contains("panicked"), "{output}");
        assert!(
            !self.socket.exists(),
            "failed startup left a socket: {output}"
        );
        assert!(
            !self.socket.with_file_name("opaqued.pid").exists(),
            "failed startup retained its PID lock: {output}"
        );
        assert_eq!(fs::read_to_string(&self.config).unwrap(), body);
        output
    }
}

#[test]
fn startup_rejects_invalid_custody_configuration_before_creating_ledgers() {
    for (field, value, expected) in [
        (
            "relative",
            "relative-state",
            "data_dir must be an absolute path",
        ),
        ("missing_group", "", "requires trust_domain.socket_group"),
        (
            "unknown_group",
            "opaque-synthetic-nonexistent-group-9e51",
            "does not exist",
        ),
        (
            "invalid_factor",
            "fido2",
            "approval.session_factor requires",
        ),
    ] {
        let f = Fixture::new();
        let mut doc = f.document();
        match field {
            "relative" => doc["data_dir"] = toml_edit::value(value),
            "missing_group" => {
                doc["trust_domain"]
                    .as_table_mut()
                    .unwrap()
                    .remove("socket_group");
            }
            "unknown_group" => doc["trust_domain"]["socket_group"] = toml_edit::value(value),
            _ => {
                doc["approval"] = toml_edit::Item::Table(toml_edit::Table::new());
                doc["approval"]["session_factor"] = toml_edit::value(value);
            }
        }
        f.reject(&doc, &[], expected);
        for file in ["audit.db", "identity.db", "tasks.db"] {
            assert!(!f.state.join(file).exists(), "{field}: {file}");
        }
    }
}

#[test]
fn startup_does_not_follow_a_symlinked_data_directory() {
    let f = Fixture::new();
    let destination = f.home.join("untouched");
    fs::create_dir(&destination).unwrap();
    let marker = destination.join("operator-record");
    fs::write(&marker, b"preserve").unwrap();
    let link = f.home.join("linked-state");
    std::os::unix::fs::symlink(&destination, &link).unwrap();
    let mut doc = f.document();
    doc["data_dir"] = toml_edit::value(link.to_str().unwrap());
    f.reject(&doc, &[], "symlink");
    assert_eq!(fs::read(&marker).unwrap(), b"preserve");
    assert_eq!(fs::read_dir(destination).unwrap().count(), 1);
}

#[test]
fn startup_preserves_unreadable_task_and_audit_ledgers_and_releases_socket() {
    for (file, expected) in [
        ("tasks.db", "task ledger unavailable"),
        ("audit.db", "failed to open audit database"),
    ] {
        let f = Fixture::new();
        let mut doc = f.document();
        doc["enable_task_grants"] = toml_edit::value(true);
        let path = f.state.join(file);
        let bytes = b"synthetic corrupt database retained as evidence";
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        f.reject(&doc, &[], expected);
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}

#[test]
fn startup_rejects_partial_insecure_approval_configuration() {
    for (backend, marker, expected) in [
        ("native", "1", "refusing to start"),
        ("insecure_auto_approve", "0", "additionally requires"),
        ("unknown-synthetic-backend", "0", "unknown approval_backend"),
    ] {
        let f = Fixture::new();
        let mut doc = f.document();
        doc["approval_backend"] = toml_edit::value(backend);
        f.reject(&doc, &[("OPAQUE_INSECURE_AUTO_APPROVE", marker)], expected);
        assert!(
            opaque_core::audit::verify_audit_chain(&f.state.join("audit.db"))
                .unwrap()
                .ok
        );
    }
}

#[test]
fn startup_tenant_ssh_requires_every_identity_and_task_precondition() {
    for missing in [
        "tenant",
        "task_grants",
        "identity",
        "required",
        "membership",
    ] {
        let f = Fixture::new();
        let mut doc = f.document();
        doc["enable_task_grants"] = toml_edit::value(missing != "task_grants");
        if missing != "tenant" {
            doc["tenant"] = "[tenant]\nid=\"startup-fixture\"\n"
                .parse::<toml_edit::DocumentMut>()
                .unwrap()["tenant"]
                .clone();
        }
        if missing != "identity" {
            let identity = format!(
                "[identity]\nissuer=\"https://idp.example.test\"\nclient_id=\"startup-fixture\"\nrequired={}\nallowed_subjects={}\n",
                missing != "required",
                if missing == "membership" {
                    "[]"
                } else {
                    "[\"operator\"]"
                }
            );
            doc["identity"] =
                identity.parse::<toml_edit::DocumentMut>().unwrap()["identity"].clone();
        }
        let profile = opaque_bounded_work::ssh::test_profile().config;
        let profile = toml_edit::ser::to_document(&profile).unwrap();
        doc["ssh"] = toml_edit::Item::Table(profile.as_table().clone());
        f.reject(
            &doc,
            &[],
            "tenant inference and SSH require task grants and identity.required=true",
        );
        assert!(!f.state.join("identity.db").exists());
        assert!(!f.state.join("tasks.db").exists());
        assert!(!f.state.join("audit.db").exists());
    }
}

#[test]
fn startup_approval_listener_address_failure_cleans_up_broker_listener() {
    let f = Fixture::new();
    let mut doc = f.document();
    doc["approval"] = "[approval]\nsecond_device=true\nserver_bind=\"invalid-address\"\n"
        .parse::<toml_edit::DocumentMut>()
        .unwrap()["approval"]
        .clone();
    f.reject(&doc, &[], "approval.server_bind invalid");
    assert!(
        opaque_core::audit::verify_audit_chain(&f.state.join("audit.db"))
            .unwrap()
            .ok
    );
}

fn required_identity() -> toml_edit::Item {
    "[identity]\nissuer=\"https://idp.example.test\"\nclient_id=\"startup-fixture\"\nrequired=true\nallowed_subjects=[\"operator\"]\n"
        .parse::<toml_edit::DocumentMut>().unwrap()["identity"].clone()
}

#[test]
fn startup_remote_approval_never_downgrades_missing_custody_requirements() {
    for missing in [
        "task_grants",
        "native",
        "seal",
        "enforcement",
        "identity",
        "required",
        "tenant",
    ] {
        let f = Fixture::new();
        let mut doc = f.document();
        doc["enable_task_grants"] = toml_edit::value(missing != "task_grants");
        doc["identity"] = required_identity();
        doc["approval"] = "[approval]\nserver_bind=\"127.0.0.1:0\"\n"
            .parse::<toml_edit::DocumentMut>()
            .unwrap()["approval"]
            .clone();
        // Structurally valid configuration; enrollment is deliberately later
        // than the daemon's custody requirements under test.
        let remote = format!(
            "[remote_approvals]\nreviewer_public_key_hex=\"{}\"\nrequired_role=\"approver\"\n",
            "11".repeat(32)
        );
        doc["remote_approvals"] =
            remote.parse::<toml_edit::DocumentMut>().unwrap()["remote_approvals"].clone();
        match missing {
            "native" => doc["approval_backend"] = toml_edit::value("insecure_auto_approve"),
            "seal" => doc["require_seal"] = toml_edit::value(false),
            "enforcement" => doc["trust_domain"]["enforce"] = toml_edit::value(false),
            "identity" => {
                doc.remove("identity");
            }
            "required" => doc["identity"]["required"] = toml_edit::value(false),
            _ => {}
        }
        let expected = match missing {
            "task_grants" | "native" => "remote approvals require native bounded-task approval",
            "tenant" => "remote approvals require an isolated tenant",
            _ => "remote approvals require sealed isolated custody and required identity",
        };
        let env = if missing == "native" {
            vec![("OPAQUE_INSECURE_AUTO_APPROVE", "1")]
        } else {
            vec![]
        };
        f.reject(&doc, &env, expected);
        assert!(!f.state.join("remote-approvals.db").exists());
        assert!(
            opaque_core::audit::verify_audit_chain(&f.state.join("audit.db"))
                .unwrap()
                .ok
        );
    }
}

#[test]
fn startup_accepts_complete_tenant_profiles_before_later_backend_rejection() {
    for kind in ["ssh", "inference"] {
        let f = Fixture::new();
        let mut doc = f.document();
        doc["enable_task_grants"] = toml_edit::value(true);
        doc["tenant"] = "[tenant]\nid=\"startup-fixture\"\n"
            .parse::<toml_edit::DocumentMut>()
            .unwrap()["tenant"]
            .clone();
        doc["identity"] = required_identity();
        doc["approval_backend"] = toml_edit::value("later-synthetic-rejection");
        if kind == "ssh" {
            let mut profile = opaque_bounded_work::ssh::test_profile().config;
            profile.grant_signing_key_path = f.home.join("task-grant.key");
            fs::write(&profile.grant_signing_key_path, [57u8; 32]).unwrap();
            fs::set_permissions(
                &profile.grant_signing_key_path,
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            doc["ssh"] = toml_edit::Item::Table(
                toml_edit::ser::to_document(&profile)
                    .unwrap()
                    .as_table()
                    .clone(),
            );
        } else {
            use opaque_bounded_work::inference::{
                DEMO_SOURCE_ID, InferenceProfileConfig, demo_source_snapshot_sha256,
            };
            let profile = InferenceProfileConfig {
                profile_id: "startup-fixture".into(),
                api_url: "https://model.example.test".into(),
                model_id: "fixture-model.gguf".into(),
                model_path: "/synthetic/model.gguf".into(),
                model_artifact_sha256: "ab".repeat(32),
                chat_template_sha256: "cd".repeat(32),
                server_build: "fixture-build".into(),
                service_uid: uuid::Uuid::new_v4(),
                source_id: DEMO_SOURCE_ID.into(),
                source_snapshot_sha256: demo_source_snapshot_sha256(),
                github_ci: None,
                credential_ref: None,
                allow_loopback_http: false,
            };
            doc["inference"] = toml_edit::Item::Table(
                toml_edit::ser::to_document(&profile)
                    .unwrap()
                    .as_table()
                    .clone(),
            );
        }
        // This proves startup binding/ledger construction, not observed model
        // completions, SSH execution or approval. No provider is called.
        f.reject(&doc, &[], "unknown approval_backend");
        assert!(f.state.join("identity.db").is_file());
        assert!(f.state.join("tasks.db").is_file());
        assert!(
            opaque_core::audit::verify_audit_chain(&f.state.join("audit.db"))
                .unwrap()
                .ok
        );
    }
}

#[test]
fn startup_fido_factor_registration_does_not_bypass_invalid_attestation_url() {
    let f = Fixture::new();
    let mut doc = f.document();
    doc["approval"] = "[approval]\nfido2=true\nfido2_rp_id=\"startup.example.test\"\n"
        .parse::<toml_edit::DocumentMut>()
        .unwrap()["approval"]
        .clone();
    doc["attestation"]["key_release_url"] = toml_edit::value("not-a-url");
    let output = f.reject(&doc, &[], "[attestation] key_release_url invalid");
    assert!(
        output.contains("FIDO2/passkey approval factor enabled (0 credential(s) registered)"),
        "{output}"
    );
    assert!(
        output.contains("approval factors registered") && output.contains("fido2"),
        "{output}"
    );
    assert!(f.state.join("approval/fido2_credentials.hmac").is_file());
    assert!(
        opaque_core::audit::verify_audit_chain(&f.state.join("audit.db"))
            .unwrap()
            .ok
    );
}

#[test]
fn startup_reporter_requires_seal_enforcement_and_tenant_before_network_work() {
    for missing in ["seal", "enforcement", "tenant"] {
        let f = Fixture::new();
        let mut doc = f.document();
        doc["require_seal"] = toml_edit::value(missing != "seal");
        doc["trust_domain"]["enforce"] = toml_edit::value(missing != "enforcement");
        // The credential intentionally does not exist: the startup custody
        // guards must reject before constructing a reporter or reading it.
        let fleet = format!(
            "[fleet]\ncollector_url=\"https://collector.example.test\"\ntoken_file={:?}\ninterval_secs=30\n",
            f.state.join("unread-reporter-token").to_str().unwrap()
        );
        doc["fleet"] = fleet.parse::<toml_edit::DocumentMut>().unwrap()["fleet"].clone();
        let expected = if missing == "tenant" {
            "fleet reporter requires a tenant binding"
        } else {
            "fleet reporter requires sealed isolated tenant custody"
        };
        f.reject(&doc, &[], expected);
        assert!(!f.state.join("unread-reporter-token").exists());
        assert!(
            opaque_core::audit::verify_audit_chain(&f.state.join("audit.db"))
                .unwrap()
                .ok
        );
    }
}

#[test]
fn startup_privilege_drop_rejects_invalid_user_without_changing_parent_identity() {
    let f = Fixture::new();
    let mut doc = f.document();
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    // NUL cannot name an OS account. A privileged child rejects before lookup;
    // a non-root child records that run_as is ignored, then fails path checks.
    doc["trust_domain"]["run_as"] = toml_edit::value("synthetic\0account");
    doc["data_dir"] = toml_edit::value("relative-state");
    let expected = if uid == 0 {
        "privilege drop failed"
    } else {
        "data_dir must be an absolute path"
    };
    let output = f.reject(&doc, &[], expected);
    if uid != 0 {
        assert!(output.contains("already dropped, ignoring"), "{output}");
    }
    assert_eq!(unsafe { libc::geteuid() }, uid);
    assert_eq!(unsafe { libc::getegid() }, gid);
    assert!(!f.state.join("audit.db").exists());
}
