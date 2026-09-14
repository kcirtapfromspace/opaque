//! Actual CLI subprocess and filesystem tests. Service controllers are explicitly
//! synthetic native-command boundaries; they do not claim launchd/systemd service
//! execution. macOS sealing runs under a mandatory sandbox denying Keychain tools.
#![cfg(unix)]
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    bin: PathBuf,
    config: PathBuf,
    service: PathBuf,
}

fn script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let bin = dir.path().join("bin");
        fs::create_dir_all(home.join(".opaque")).unwrap();
        fs::set_permissions(home.join(".opaque"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(&bin).unwrap();
        fs::copy(env!("CARGO_BIN_EXE_opaque"), bin.join("opaque")).unwrap();
        let config = dir.path().join("custom/config.toml");
        fs::create_dir(config.parent().unwrap()).unwrap();
        fs::set_permissions(config.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&config, "require_seal = true\n").unwrap();
        #[cfg(target_os = "macos")]
        let service = home.join("Library/LaunchAgents/com.opaque.daemon.plist");
        #[cfg(target_os = "linux")]
        let service = home.join("xdg/systemd/user/opaqued.service");
        script(
            &bin.join("which"),
            "if [ \"$1\" = opaqued ] && [ -f \"$HOME/../bin/opaqued\" ]; then echo \"$HOME/../bin/opaqued\"; else exit 1; fi",
        );
        script(
            &bin.join("opaqued"),
            "exit 99 # explicitly synthetic service payload; never invoked here",
        );
        let controller = r#"
echo "$*" >> "$HOME/controller.calls"
if [ "$1" = --user ]; then shift; fi
op="$1"
if [ -f "$HOME/fail" ] && [ "$(/bin/cat "$HOME/fail")" = "$op" ]; then
    echo "synthetic $op rejection" >&2; exit 23
fi
case "$op" in
  load|enable|start|restart|kickstart) echo running > "$HOME/service.state" ;;
  stop|disable|unload) echo stopped > "$HOME/service.state" ;;
  daemon-reload) if [ -e "$HOME/xdg/systemd/user/opaqued.service" ]; then echo present; else echo absent; fi >> "$HOME/reload.files" ;;
  show) if [ -f "$HOME/service.state" ] && [ "$(/bin/cat "$HOME/service.state")" = running ]; then echo 'ActiveState=active'; echo 'MainPID=1234'; else echo 'ActiveState=inactive'; echo 'MainPID=0'; fi ;;
  list) if [ -f "$HOME/service.state" ] && [ "$(/bin/cat "$HOME/service.state")" = running ]; then echo '"PID" = 1234;'; fi ;;
  *) echo "unexpected synthetic controller command: $*" >&2; exit 98 ;;
esac
"#;
        script(&bin.join("launchctl"), controller);
        script(&bin.join("systemctl"), controller);
        script(
            &bin.join("journalctl"),
            "echo synthetic-log-denial >&2; exit 24",
        );
        script(&bin.join("tail"), "echo synthetic-log-denial >&2; exit 24");
        #[cfg(target_os = "macos")]
        {
            // HOME cannot isolate the login Keychain: the seal backend clears its
            // environment and invokes /usr/bin/security. Prove execution denial
            // before any setup/doctor operation, without calling the real tool.
            let probe = Command::new("/usr/bin/sandbox-exec")
                .args(["-p", Self::sandbox(), "/usr/bin/security", "help"])
                .output()
                .unwrap();
            assert_eq!(
                probe.status.code(),
                Some(71),
                "Keychain isolation unavailable: {probe:?}"
            );
            assert!(String::from_utf8_lossy(&probe.stderr).contains("Operation not permitted"));
        }
        Self {
            _dir: dir,
            home,
            bin,
            config,
            service,
        }
    }

    #[cfg(target_os = "macos")]
    fn sandbox() -> &'static str {
        "(version 1)(allow default)(deny process-exec (literal \"/usr/bin/security\"))"
    }

    fn run(&self, args: &[&str]) -> Output {
        #[cfg(target_os = "macos")]
        let mut command = {
            let mut c = Command::new("/usr/bin/sandbox-exec");
            c.args(["-p", Self::sandbox()]).arg(self.bin.join("opaque"));
            c
        };
        #[cfg(not(target_os = "macos"))]
        let mut command = Command::new(self.bin.join("opaque"));
        command
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", &self.bin)
            .env("XDG_CONFIG_HOME", self.home.join("xdg"))
            .env("OPAQUE_CONFIG", &self.config)
            .env("OPAQUE_SOCK", self.home.join("broker.sock"))
            .env("NO_COLOR", "1")
            .args(["--yes"])
            .args(args)
            .stdin(Stdio::null());
        // Retain production CLI counters after clearing ambient state. No
        // collection setting is introduced into a release binary.
        #[cfg(coverage_nightly)]
        if let Some(directory) = std::env::var_os("OPAQUE_COVERAGE_PROFILE_DIR") {
            command.env(
                "LLVM_PROFILE_FILE",
                PathBuf::from(directory).join("adapter-%p-%m-%c.profraw"),
            );
        }
        let stdout = tempfile::tempfile().unwrap();
        let stderr = tempfile::tempfile().unwrap();
        command
            .stdout(stdout.try_clone().unwrap())
            .stderr(stderr.try_clone().unwrap());
        let mut child = command.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("CLI exceeded deadline: {args:?}");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        use std::io::{Read, Seek};
        fn bytes(mut f: fs::File) -> Vec<u8> {
            f.rewind().unwrap();
            let mut b = Vec::new();
            f.read_to_end(&mut b).unwrap();
            b
        }
        Output {
            status,
            stdout: bytes(stdout),
            stderr: bytes(stderr),
        }
    }
    fn ok(&self, args: &[&str]) -> String {
        let r = self.run(args);
        assert!(r.status.success(), "{args:?}: {r:?}");
        text(&r)
    }
    fn denied(&self, args: &[&str], expected: &str) {
        let r = self.run(args);
        assert_eq!(r.status.code(), Some(1), "{args:?}: {r:?}");
        assert!(text(&r).contains(expected), "{r:?}");
    }
    fn seal(&self) -> PathBuf {
        self.config.with_file_name("config.seal")
    }
    fn key(&self) -> PathBuf {
        self.config.with_file_name("config.seal.key")
    }
    fn fail(&self, operation: &str) {
        fs::write(self.home.join("fail"), operation).unwrap();
    }
    fn clear_failure(&self) {
        fs::remove_file(self.home.join("fail")).unwrap();
    }
}
fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn setup_custom_config_keyed_seal_verify_tamper_reset_and_reseal() {
    let f = Fixture::new();
    f.ok(&["setup", "--seal"]);
    assert!(f.seal().is_file() && f.key().is_file());
    assert!(!f.home.join(".opaque/config.seal").exists());
    assert_eq!(
        fs::metadata(f.key()).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(
        f.ok(&["setup", "--verify"])
            .contains("integrity OK (keyed)")
    );
    let old_key = fs::read(f.key()).unwrap();
    fs::write(&f.config, "require_seal = false\n").unwrap();
    f.denied(&["setup", "--verify"], "BROKEN");
    f.ok(&["setup", "--reset"]);
    assert!(!f.seal().exists() && !f.key().exists());
    f.ok(&["setup", "--reset"]); // idempotent file removal
    f.denied(&["setup", "--verify"], "unsealed");
    f.ok(&["setup", "--seal"]);
    assert_ne!(fs::read(f.key()).unwrap(), old_key);
    f.ok(&["setup", "--verify"]);
}

#[test]
fn setup_missing_key_corrupt_key_missing_config_and_legacy_are_distinct() {
    let f = Fixture::new();
    f.ok(&["setup", "--seal"]);
    fs::remove_file(f.key()).unwrap();
    f.denied(&["setup", "--verify"], "seal key missing");
    fs::write(f.key(), b"short").unwrap();
    f.denied(&["setup", "--verify"], "seal check failed");
    f.ok(&["setup", "--reset"]);
    let config = fs::read(&f.config).unwrap();
    fs::write(f.seal(), opaque_core::seal::compute_seal(&config)).unwrap();
    assert!(f.ok(&["setup", "--verify"]).contains("legacy UNKEYED"));
    f.ok(&["setup", "--seal"]);
    assert!(
        f.ok(&["setup", "--verify"])
            .contains("integrity OK (keyed)")
    );
    fs::remove_file(&f.config).unwrap();
    f.denied(&["setup", "--verify"], "config not found");
    f.denied(&["setup", "--seal"], "config not found");
}

#[test]
fn setup_real_filesystem_read_write_and_reset_failures_never_report_success() {
    let f = Fixture::new();
    fs::create_dir(f.seal()).unwrap();
    f.denied(&["setup", "--seal"], "failed to store seal");
    f.denied(&["setup", "--reset"], "failed to remove seal");
    fs::remove_dir(f.seal()).unwrap();
    fs::remove_file(&f.config).unwrap();
    fs::create_dir(&f.config).unwrap();
    f.denied(&["setup", "--verify"], "failed to read");
    f.denied(&["setup", "--seal"], "failed to read");
}

#[test]
fn doctor_custom_config_seal_failures_and_warning_exit_semantics() {
    let f = Fixture::new();
    // An invalid default config must not override the explicitly selected file.
    fs::write(f.home.join(".opaque/config.toml"), "invalid = [").unwrap();
    f.ok(&["setup", "--seal"]);
    let output = f.ok(&["doctor"]);
    assert!(
        output.contains("Config file valid") && output.contains("Config seal verified (keyed)")
    );
    assert!(output.contains("Socket not found") && output.contains("0 errors"));
    fs::write(&f.config, "require_seal = false\n").unwrap();
    f.denied(&["doctor"], "Config seal BROKEN");
    f.ok(&["setup", "--seal"]);
    fs::remove_file(f.key()).unwrap();
    f.denied(&["doctor"], "config.seal.key is missing");
    f.ok(&["setup", "--reset"]);
    fs::write(&f.config, "broken = [").unwrap();
    f.denied(&["doctor"], "Config file has parse errors");
    fs::remove_file(&f.config).unwrap();
    assert!(f.ok(&["doctor"]).contains("Config file not found"));
    fs::remove_dir_all(f.config.parent().unwrap()).unwrap();
    f.denied(&["doctor"], "Config directory not found");
}

#[test]
fn doctor_custody_modes_and_unreachable_socket_are_reported_without_false_pass() {
    let f = Fixture::new();
    fs::set_permissions(
        f.config.parent().unwrap(),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let socket = f.home.join("broker.sock");
    fs::write(&socket, []).unwrap();
    for mode in [0o404, 0o640, 0o700] {
        fs::set_permissions(&socket, fs::Permissions::from_mode(mode)).unwrap();
        let out = f.run(&["doctor"]);
        assert_eq!(out.status.code(), Some(1));
        let output = text(&out);
        assert!(output.contains("Config directory permissions are 0755"));
        assert!(
            output.contains(&format!("Socket permissions are {mode:04o}")),
            "{output}"
        );
        assert!(!output.contains("Socket exists with secure permissions"));
        assert!(output.contains("Daemon ping failed"));
    }
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let out = f.run(&["doctor"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out).contains("Socket exists with secure permissions (0600)"));
}

#[test]
fn service_synthetic_controller_lifecycle_and_persisted_state() {
    let f = Fixture::new();
    for op in ["start", "stop", "restart", "uninstall"] {
        f.denied(&["service", op], "not installed");
    }
    assert!(!f.home.join("controller.calls").exists());
    f.ok(&["service", "install"]);
    assert!(f.service.is_file());
    let original = fs::read(&f.service).unwrap();
    f.denied(&["service", "install"], "already installed");
    assert_eq!(fs::read(&f.service).unwrap(), original);
    let status = f.ok(&["service", "status"]);
    assert!(status.contains("1234"));
    for (op, state) in [
        ("stop", "stopped"),
        ("start", "running"),
        ("restart", "running"),
    ] {
        f.ok(&["service", op]);
        assert_eq!(
            fs::read_to_string(f.home.join("service.state"))
                .unwrap()
                .trim(),
            state
        );
    }
    f.ok(&["service", "uninstall"]);
    assert!(!f.service.exists());
    assert_eq!(
        fs::read_to_string(f.home.join("service.state"))
            .unwrap()
            .trim(),
        "stopped"
    );
    #[cfg(target_os = "linux")]
    assert_eq!(
        fs::read_to_string(f.home.join("reload.files")).unwrap(),
        "present\nabsent\n"
    );
}

#[test]
fn service_synthetic_controller_failure_never_claims_completed_mutation() {
    let f = Fixture::new();
    #[cfg(target_os = "macos")]
    let install = "load";
    #[cfg(target_os = "linux")]
    let install = "enable";
    f.fail(install);
    f.denied(&["service", "install"], "failed");
    assert!(f.service.is_file());
    assert!(!f.home.join("service.state").exists());
    f.clear_failure();
    f.ok(&["service", "start"]);
    for (op, boundary) in [
        ("start", "start"),
        ("stop", "stop"),
        (
            "restart",
            if cfg!(target_os = "macos") {
                "kickstart"
            } else {
                "restart"
            },
        ),
        (
            "uninstall",
            if cfg!(target_os = "macos") {
                "unload"
            } else {
                "disable"
            },
        ),
    ] {
        f.fail(boundary);
        f.denied(&["service", op], "failed");
        assert!(f.service.is_file());
        assert_eq!(
            fs::read_to_string(f.home.join("service.state"))
                .unwrap()
                .trim(),
            "running"
        );
        f.clear_failure();
    }
    f.ok(&["service", "uninstall"]);
}

#[test]
fn service_real_filesystem_and_missing_native_command_failures() {
    let f = Fixture::new();
    let parent = f.service.parent().unwrap();
    fs::create_dir_all(parent.parent().unwrap()).unwrap();
    fs::write(parent, b"not a directory").unwrap();
    f.denied(&["service", "install"], "failed to create");
    assert!(!f.service.exists());
    fs::remove_file(parent).unwrap();
    #[cfg(target_os = "macos")]
    let controller = "launchctl";
    #[cfg(target_os = "linux")]
    let controller = "systemctl";
    fs::remove_file(f.bin.join(controller)).unwrap();
    f.denied(&["service", "install"], "failed to run");
    assert!(f.service.is_file());
    for op in ["start", "stop", "restart", "uninstall"] {
        f.denied(&["service", op], "failed to run");
    }
    assert!(f.service.is_file());
}

#[test]
fn service_uninstall_file_removal_and_log_command_failures() {
    let f = Fixture::new();
    fs::create_dir_all(&f.service).unwrap();
    f.denied(&["service", "uninstall"], "failed to remove");
    assert!(f.service.is_dir());
    fs::create_dir_all(f.home.join(".opaque/logs")).unwrap();
    fs::write(
        f.home.join(".opaque/logs/opaqued.stderr.log"),
        "fixture log",
    )
    .unwrap();
    f.denied(&["service", "logs"], "synthetic-log-denial");
}

#[cfg(target_os = "linux")]
#[test]
fn service_systemd_reload_failures_preserve_truthful_final_file_state() {
    let f = Fixture::new();
    f.fail("daemon-reload");
    f.denied(&["service", "install"], "daemon-reload failed");
    assert!(f.service.is_file());
    assert!(!f.home.join("service.state").exists());
    f.clear_failure();
    f.ok(&["service", "start"]);
    f.fail("daemon-reload");
    f.denied(&["service", "uninstall"], "daemon-reload failed");
    assert!(!f.service.exists());
    assert_eq!(
        fs::read_to_string(f.home.join("service.state"))
            .unwrap()
            .trim(),
        "stopped"
    );
}

#[test]
fn doctor_actual_socket_transport_with_controlled_ping_and_version_responses() {
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    fn read_frame(stream: &mut UnixStream) -> serde_json::Value {
        fn exact(stream: &mut UnixStream, mut bytes: &mut [u8]) {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !bytes.is_empty() {
                match stream.read(bytes) {
                    Ok(0) => panic!("doctor closed before complete frame"),
                    Ok(n) => bytes = &mut bytes[n..],
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "doctor frame deadline");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("read doctor frame: {e}"),
                }
            }
        }
        let mut prefix = [0; 4];
        exact(stream, &mut prefix);
        let size = u32::from_be_bytes(prefix) as usize;
        assert!(size < 4096);
        let mut bytes = vec![0; size];
        exact(stream, &mut bytes);
        serde_json::from_slice(&bytes).unwrap()
    }
    let f = Fixture::new();
    f.ok(&["setup", "--seal"]);
    let socket = f.home.join("broker.sock");
    fs::write(f.home.join("daemon.token"), "synthetic-doctor-token").unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut methods = Vec::new();
        while methods.len() < 2 {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "doctor did not send both requests"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(e) => panic!("accept doctor request: {e}"),
            };
            stream.set_nonblocking(true).unwrap();
            let handshake = read_frame(&mut stream);
            assert_eq!(handshake["handshake"], "v1");
            assert_eq!(handshake["daemon_token"], "synthetic-doctor-token");
            let request = read_frame(&mut stream);
            let method = request["method"].as_str().unwrap().to_owned();
            assert_eq!(
                method,
                if methods.is_empty() {
                    "ping"
                } else {
                    "version"
                }
            );
            let result = if method == "ping" {
                serde_json::json!({"ok":true})
            } else {
                serde_json::json!({"version":"synthetic-doctor-version"})
            };
            let response =
                serde_json::to_vec(&serde_json::json!({"id":request["id"],"result":result}))
                    .unwrap();
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(&response).unwrap();
            methods.push(method);
        }
        methods
    });
    let result = f.run(&["doctor"]);
    let methods = server
        .join()
        .unwrap_or_else(|error| panic!("server {error:?}; CLI {result:?}"));
    assert_eq!(methods, ["ping", "version"]);
    assert!(result.status.success(), "{result:?}");
    let output = text(&result);
    assert!(output.contains("Daemon is reachable (ping OK)"));
    assert!(output.contains("synthetic-doctor-version") && output.contains("differs from CLI"));
    assert!(output.contains("0 errors"));
}

#[test]
fn service_missing_daemon_and_real_unit_write_failure_leave_no_installation() {
    let f = Fixture::new();
    fs::remove_file(f.bin.join("opaqued")).unwrap();
    f.denied(&["service", "install"], "could not find opaqued");
    assert!(!f.service.exists() && !f.home.join("controller.calls").exists());
    script(&f.bin.join("opaqued"), "exit 99");
    fs::create_dir_all(f.service.parent().unwrap()).unwrap();
    let missing_target = f.home.join("nonexistent-parent/unit");
    std::os::unix::fs::symlink(&missing_target, &f.service).unwrap();
    f.denied(&["service", "install"], "failed to write");
    assert!(!missing_target.exists() && !f.home.join("controller.calls").exists());
}

#[test]
fn service_synthetic_log_output_and_already_unloaded_uninstall() {
    let f = Fixture::new();
    f.ok(&["service", "install"]);
    fs::create_dir_all(f.home.join(".opaque/logs")).unwrap();
    fs::write(
        f.home.join(".opaque/logs/opaqued.stderr.log"),
        "fixture log",
    )
    .unwrap();
    for logger in ["journalctl", "tail"] {
        script(&f.bin.join(logger), "echo synthetic-owned-log");
    }
    assert!(f.ok(&["service", "logs"]).contains("synthetic-owned-log"));
    for logger in ["journalctl", "tail"] {
        script(&f.bin.join(logger), "exit 0");
    }
    let empty = f.ok(&["service", "logs"]);
    assert!(empty.contains("empty") || empty.contains("No log entries"));
    #[cfg(target_os = "macos")]
    script(
        &f.bin.join("launchctl"),
        "echo 'Could not find specified service' >&2; exit 3",
    );
    #[cfg(target_os = "linux")]
    script(
        &f.bin.join("systemctl"),
        "if [ \"$2\" = daemon-reload ]; then exit 0; fi; echo 'unit not loaded' >&2; exit 3",
    );
    f.ok(&["service", "uninstall"]);
    assert!(!f.service.exists());
}
