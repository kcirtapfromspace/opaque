//! Execute the actual build scripts and Cargo's environment invalidation using
//! disposable, dependency-free crates. No product binaries or shared cache are rebuilt.
#![cfg(unix)]

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read, Seek};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().unwrap(),
        }
    }

    fn command(&self, program: impl AsRef<OsStr>) -> Command {
        let mut command = Command::new(program);
        command.env_clear().current_dir(self.root.path());
        for name in ["PATH", "RUSTUP_TOOLCHAIN", "TMPDIR"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let rustup = std::env::var_os("RUSTUP_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".rustup")));
        if let Some(rustup) = rustup {
            command.env("RUSTUP_HOME", rustup);
        }
        command
            .env("HOME", self.root.path())
            .env("CARGO_HOME", self.root.path().join("cargo-home"))
            .env("CARGO_INCREMENTAL", "0")
            .env("CARGO_PROFILE_DEV_DEBUG", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null");
        command
    }

    fn repository(&self) -> String {
        for args in [
            vec!["init"],
            vec!["add", "README"],
            vec![
                "-c",
                "user.name=Build metadata fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "-m",
                "fixture",
            ],
        ] {
            fs::write(self.root.path().join("README"), "Build metadata fixture.\n").unwrap();
            success(self.command("git").args(args));
        }
        String::from_utf8(success(self.command("git").args([
            "rev-parse",
            "--short",
            "HEAD",
        ])))
        .unwrap()
        .trim()
        .to_owned()
    }
}

fn run(command: &mut Command) -> Output {
    let mut stdout = tempfile::tempfile().unwrap();
    let mut stderr = tempfile::tempfile().unwrap();
    command
        .stdin(Stdio::null())
        .stdout(stdout.try_clone().unwrap())
        .stderr(stderr.try_clone().unwrap())
        .process_group(0);
    let mut child = command
        .spawn()
        .expect("required Rust/Git tool must be available");
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            // The unreaped child owns this process group; no user group is signalled.
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            child.wait().unwrap();
            panic!("owned build-metadata command exceeded its deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    stdout.rewind().unwrap();
    stderr.rewind().unwrap();
    let mut out = Vec::new();
    let mut err = Vec::new();
    stdout.read_to_end(&mut out).unwrap();
    stderr.read_to_end(&mut err).unwrap();
    Output {
        status,
        stdout: out,
        stderr: err,
    }
}

fn success(command: &mut Command) -> Vec<u8> {
    let result = run(command);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    result.stdout
}

fn source(package: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join(package)
        .join("build.rs")
}

fn revision_output(bytes: &[u8], expected: &str) {
    let output = std::str::from_utf8(bytes).unwrap();
    assert_eq!(
        output
            .lines()
            .filter(|line| line.starts_with("cargo:rustc-env=OPAQUE_GIT_SHA="))
            .collect::<Vec<_>>(),
        [format!("cargo:rustc-env=OPAQUE_GIT_SHA={expected}")]
    );
}

#[test]
fn actual_build_scripts_validate_supplied_revision_and_preserve_git_fallback() {
    let fixture = Fixture::new();
    let revision = "190cb16d9c9082f56beb11f4dcee5ace5ba85e34";
    let mut scripts = Vec::new();
    for package in ["opaque", "opaqued"] {
        let binary = fixture.root.path().join(format!("{package}-build"));
        success(
            fixture
                .command("rustc")
                .args(["--edition=2024", "-Cdebuginfo=0"])
                .arg(source(package))
                .arg("-o")
                .arg(&binary),
        );
        // No Git checkout exists here. Both scripts must still use verified metadata.
        revision_output(
            &success(
                fixture
                    .command(&binary)
                    .env("OPAQUE_BUILD_REVISION", revision),
            ),
            &revision[..7],
        );
        revision_output(&success(&mut fixture.command(&binary)), "unknown");
        for invalid in [
            OsString::from(""),
            OsString::from("HEAD"),
            OsString::from(&revision[..7]),
            OsString::from("A".repeat(40)),
            OsString::from("g".repeat(40)),
            OsString::from("1".repeat(41)),
            OsString::from("do-not-echo-this-invalid-build-revision"),
            OsStr::from_bytes(&[0xff; 40]).to_owned(),
        ] {
            let result = run(fixture
                .command(&binary)
                .env("OPAQUE_BUILD_REVISION", invalid));
            assert!(!result.status.success());
            assert!(
                !String::from_utf8_lossy(&result.stdout)
                    .contains("cargo:rustc-env=OPAQUE_GIT_SHA=")
            );
            let error = String::from_utf8_lossy(&result.stderr);
            assert!(error.contains("OPAQUE_BUILD_REVISION must be"));
            assert!(!error.contains("do-not-echo-this-invalid-build-revision"));
        }
        scripts.push(binary);
    }
    let expected = fixture.repository();
    for binary in scripts {
        revision_output(&success(&mut fixture.command(binary)), &expected);
    }
}

#[test]
fn cargo_rebuilds_daemon_version_when_verified_revision_changes_or_is_removed() {
    let fixture = Fixture::new();
    let fallback = fixture.repository();
    let crate_root = fixture.root.path().join("crates/metadata-fixture");
    fs::create_dir_all(crate_root.join("src")).unwrap();
    fs::write(crate_root.join("Cargo.toml"), "[package]\nname = \"metadata-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n[workspace]\n").unwrap();
    fs::copy(source("opaqued"), crate_root.join("build.rs")).unwrap();
    fs::write(
        crate_root.join("src/main.rs"),
        "fn main() { println!(\"{}\", env!(\"OPAQUE_GIT_SHA\")); }\n",
    )
    .unwrap();
    let target = fixture.root.path().join("target");
    for revision in [Some("1".repeat(40)), Some("2".repeat(40)), None] {
        let mut build = fixture.command("cargo");
        build
            .current_dir(&crate_root)
            .args(["build", "--offline", "--quiet", "--target-dir"])
            .arg(&target);
        if let Some(value) = &revision {
            build.env("OPAQUE_BUILD_REVISION", value);
        }
        success(&mut build);
        let actual = success(&mut fixture.command(target.join("debug/metadata-fixture")));
        let expected = revision
            .as_ref()
            .map(|value| &value[..7])
            .unwrap_or(&fallback);
        assert_eq!(String::from_utf8(actual).unwrap().trim(), expected);
    }
}
