//! Linux-root, sealed split-UID fixture. No same-UID enforcement exception.
#[cfg(coverage)]
#[path = "coverage.rs"]
mod coverage;

use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;

pub const BROKER_UID: u32 = 7581;
pub const CLIENT_UID: u32 = 7582;
pub const SOCKET_GID: u32 = 7987;

fn command(args: &[&str]) {
    let status = Command::new(args[0])
        .args(&args[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(
        status.success(),
        "fixture setup command failed: {}",
        args[0]
    );
}
fn own(path: &Path, uid: u32, gid: u32, mode: u32) {
    let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::chown(name.as_ptr(), uid, gid) }, 0);
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

struct Accounts {
    users: Vec<String>,
    groups: Vec<String>,
}
impl Accounts {
    fn new() -> Self {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "synthesized review requires Linux root; run the mandatory contained profile"
        );
        let mut owned = Self {
            users: vec![],
            groups: vec![],
        };
        for (id, name) in [
            (BROKER_UID, "opaque-synth-broker"),
            (CLIENT_UID, "opaque-synth-client"),
            (SOCKET_GID, "opaque-synth-socket"),
        ] {
            if unsafe { libc::getgrgid(id) }.is_null() {
                command(&["groupadd", "--gid", &id.to_string(), name]);
                owned.groups.push(name.into());
            } else {
                let group = unsafe { &*libc::getgrgid(id) };
                assert_eq!(
                    unsafe { std::ffi::CStr::from_ptr(group.gr_name) }
                        .to_str()
                        .unwrap(),
                    name,
                    "fixture GID belongs to another workload"
                );
            }
            if id == SOCKET_GID {
                continue;
            }
            if unsafe { libc::getpwuid(id) }.is_null() {
                command(&[
                    "useradd",
                    "--uid",
                    &id.to_string(),
                    "--gid",
                    &id.to_string(),
                    "--no-create-home",
                    "--home-dir",
                    "/nonexistent",
                    "--shell",
                    "/usr/sbin/nologin",
                    "--password",
                    "!",
                    name,
                ]);
                owned.users.push(name.into());
            } else {
                let user = unsafe { &*libc::getpwuid(id) };
                assert_eq!(
                    unsafe { std::ffi::CStr::from_ptr(user.pw_name) }
                        .to_str()
                        .unwrap(),
                    name,
                    "fixture UID belongs to another workload"
                );
            }
        }
        owned
    }
}
impl Drop for Accounts {
    fn drop(&mut self) {
        for user in self.users.iter().rev() {
            command(&["userdel", user]);
        }
        for group in self.groups.iter().rev() {
            // Some Linux userdel configurations also delete an empty private
            // primary group. Only remove the fixture group if it still exists.
            let name = std::ffi::CString::new(group.as_bytes()).unwrap();
            if !unsafe { libc::getgrnam(name.as_ptr()) }.is_null() {
                command(&["groupdel", group]);
            }
        }
    }
}

pub struct Layout {
    pub base: tempfile::TempDir,
    pub home: PathBuf,
    pub state: PathBuf,
    pub socket: PathBuf,
    pub human_binary: PathBuf,
    agent_binary: PathBuf,
    daemon_binary: PathBuf,
    seal_key: [u8; 32],
    _accounts: Accounts,
}
impl Layout {
    pub fn new() -> Self {
        let accounts = Accounts::new();
        let base = tempfile::Builder::new()
            .prefix("oqsyn")
            .tempdir_in("/tmp")
            .unwrap();
        own(base.path(), 0, 0, 0o755);
        let home = base.path().join("home");
        let state = home.join("state");
        let run = base.path().join("run");
        for dir in [&home, &state, &run] {
            std::fs::create_dir(dir).unwrap();
            own(
                dir,
                BROKER_UID,
                if dir == &run { SOCKET_GID } else { BROKER_UID },
                if dir == &run { 0o750 } else { 0o700 },
            );
        }
        let source = base.path().join("peer.rs");
        std::fs::write(&source, include_str!("rpc_peer.rs")).unwrap();
        let human_binary = base.path().join("human-peer");
        let agent_binary = base.path().join("agent-peer");
        #[cfg(coverage)]
        coverage::compile_peer(&source, &human_binary);
        #[cfg(not(coverage))]
        {
            let compile = Command::new("rustc")
                .args(["--edition=2024"])
                .arg(&source)
                .arg("-o")
                .arg(&human_binary)
                .output()
                .unwrap();
            assert!(compile.status.success(), "std-only peer compilation failed");
        }
        std::fs::copy(&human_binary, &agent_binary).unwrap();
        let daemon_binary = base.path().join("opaqued");
        std::fs::copy(env!("CARGO_BIN_EXE_opaqued"), &daemon_binary).unwrap();
        for binary in [&human_binary, &agent_binary, &daemon_binary] {
            own(binary, 0, 0, 0o755);
        }
        let mut seal_key = [0; 32];
        getrandom::fill(&mut seal_key).unwrap();
        Self {
            base,
            home,
            state,
            socket: run.join("opaqued.sock"),
            human_binary,
            agent_binary,
            daemon_binary,
            seal_key,
            _accounts: accounts,
        }
    }
    pub fn seal(&self, config: &str) {
        for (name, bytes) in [
            ("config.toml", config.as_bytes().to_vec()),
            ("config.seal.key", self.seal_key.to_vec()),
            (
                "config.seal",
                opaque_core::seal::compute_seal_keyed(config.as_bytes(), &self.seal_key)
                    .into_bytes(),
            ),
        ] {
            let file = self.home.join(name);
            std::fs::write(&file, bytes).unwrap();
            own(&file, BROKER_UID, BROKER_UID, 0o600);
        }
    }
    pub fn start(&self, env: &[(&str, &str)]) -> Daemon {
        let token = self.socket.with_file_name("daemon.token");
        for path in [&self.socket, &token] {
            let _ = std::fs::remove_file(path);
        }
        let log = self
            .base
            .path()
            .join(format!("daemon-{}.log", uuid::Uuid::new_v4()));
        let file = std::fs::File::create(&log).unwrap();
        own(&log, 0, 0, 0o600);
        let mut cmd = Command::new("setpriv");
        cmd.args([
            format!("--reuid={BROKER_UID}"),
            format!("--regid={BROKER_UID}"),
            format!("--groups={SOCKET_GID}"),
            "--bounding-set=-all,+sys_ptrace".into(),
            "--inh-caps=+sys_ptrace".into(),
            "--ambient-caps=+sys_ptrace".into(),
        ])
        .arg(&self.daemon_binary)
        .env_clear()
        .env("HOME", &self.home)
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("OPAQUE_CONFIG", self.home.join("config.toml"))
        .env("RUST_LOG", "warn")
        .stdin(Stdio::null())
        .stdout(file.try_clone().unwrap())
        .stderr(file);
        for (key, value) in env {
            cmd.env(key, value);
        }
        #[cfg(coverage)]
        coverage::subprocess(&mut cmd, "daemon");
        let mut daemon = Daemon {
            child: cmd.spawn().unwrap(),
            log,
            socket: self.socket.clone(),
            token: String::new(),
            human_binary: self.human_binary.clone(),
            agent_binary: self.agent_binary.clone(),
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        while !self.socket.exists() || !token.exists() {
            if let Some(status) = daemon.child.try_wait().unwrap() {
                panic!(
                    "isolated daemon exited {status}: {}",
                    std::fs::read_to_string(&daemon.log).unwrap()
                );
            }
            assert!(Instant::now() < deadline, "daemon startup timed out");
            std::thread::sleep(Duration::from_millis(25));
        }
        daemon.token = std::fs::read_to_string(token).unwrap().trim().into();
        daemon
    }
}

pub struct Daemon {
    child: Child,
    pub log: PathBuf,
    socket: PathBuf,
    token: String,
    human_binary: PathBuf,
    agent_binary: PathBuf,
}
impl Daemon {
    pub fn human(&self) -> Peer {
        self.peer(true)
    }
    pub fn agent(&self) -> Peer {
        self.peer(false)
    }
    fn peer(&self, human: bool) -> Peer {
        Peer {
            binary: if human {
                self.human_binary.clone()
            } else {
                self.agent_binary.clone()
            },
            socket: self.socket.clone(),
            token: self.token.clone(),
        }
    }
    pub fn stop(&mut self) {
        if self.child.try_wait().unwrap().is_some() {
            return;
        }
        unsafe {
            libc::kill(self.child.id() as i32, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                self.child.kill().unwrap();
                self.child.wait().unwrap();
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Clone)]
pub struct Peer {
    binary: PathBuf,
    socket: PathBuf,
    token: String,
}
impl Peer {
    pub async fn call(
        &self,
        method: &str,
        params: Value,
        session: Option<&str>,
    ) -> Result<Value, String> {
        let mut handshake = json!({"handshake":"v1","daemon_token":self.token});
        if let Some(session) = session {
            handshake["session_token"] = json!(session);
        }
        let mut bytes = Vec::new();
        for value in [handshake, json!({"id":1,"method":method,"params":params})] {
            let frame = serde_json::to_vec(&value).unwrap();
            bytes.extend_from_slice(&(frame.len() as u32).to_be_bytes());
            bytes.extend(frame);
        }
        let mut command = tokio::process::Command::new("setpriv");
        command
            .args([
                format!("--reuid={CLIENT_UID}"),
                format!("--regid={CLIENT_UID}"),
                format!("--groups={SOCKET_GID}"),
                "--bounding-set=-all".into(),
            ])
            .arg(&self.binary)
            .arg(&self.socket)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(coverage)]
        coverage::subprocess(command.as_std_mut(), "peer");
        let mut child = command.spawn().map_err(|_| "peer spawn failed")?;
        let mut input = child.stdin.take().unwrap();
        input
            .write_all(&bytes)
            .await
            .map_err(|_| "peer input failed")?;
        drop(input);
        let output = tokio::time::timeout(Duration::from_secs(35), child.wait_with_output())
            .await
            .map_err(|_| "peer deadline")?
            .map_err(|_| "peer wait failed")?;
        if !output.status.success() {
            return Err("peer handshake or transport rejected".into());
        }
        serde_json::from_slice(&output.stdout).map_err(|_| "invalid peer response".into())
    }
    pub async fn ok(&self, method: &str, params: Value, session: Option<&str>) -> Value {
        let response = self
            .call(method, params, session)
            .await
            .expect("actual peer RPC");
        assert!(
            response.get("error").is_none_or(Value::is_null),
            "{method} rejected: {}",
            response["error"]["code"]
        );
        response["result"].clone()
    }
}
