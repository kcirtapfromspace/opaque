//! The daemon's command line, checked against the real binary.
//!
//! `opaqued --version` used to start a daemon: nothing parsed argv except a
//! scan for `--allow-unsealed`, so the flag fell through to full startup —
//! binding the socket, verifying custody, taking the PID lock. Installation
//! instructions (including the tutorial's) tell people to run exactly that, so
//! these run the binary rather than a function.

use std::process::Command;

fn run(args: &[&str]) -> (String, String, Option<i32>) {
    let out = Command::new(env!("CARGO_BIN_EXE_opaqued"))
        .args(args)
        // A stray config or runtime dir must not be able to turn a --version
        // into a daemon start.
        .env("OPAQUE_CONFIG", "/nonexistent/opaque/config.toml")
        .output()
        .expect("run opaqued");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
    )
}

#[test]
fn version_flag_prints_and_exits_without_starting() {
    for flag in ["--version", "-V"] {
        let (stdout, stderr, code) = run(&[flag]);
        assert_eq!(code, Some(0), "{flag} exited {code:?}: {stderr}");
        assert!(stdout.starts_with("opaqued "), "{flag} printed {stdout:?}");
        assert!(
            stdout.contains(env!("CARGO_PKG_VERSION")),
            "{flag} did not report the package version: {stdout:?}"
        );
        // The giveaway that it started: the daemon logs its startup steps.
        assert!(
            !stderr.contains("custody") && !stdout.contains("listening"),
            "{flag} started the daemon:\n{stdout}\n{stderr}"
        );
    }
}

#[test]
fn help_flag_documents_the_flags_that_exist() {
    for flag in ["--help", "-h"] {
        let (stdout, stderr, code) = run(&[flag]);
        assert_eq!(code, Some(0), "{flag} exited {code:?}: {stderr}");
        for expected in ["USAGE:", "--allow-unsealed", "OPAQUE_CONFIG"] {
            assert!(
                stdout.contains(expected),
                "{flag} output is missing {expected:?}:\n{stdout}"
            );
        }
    }
}
