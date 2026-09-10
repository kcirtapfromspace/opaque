//! Run the shipped CLI and prove a failing regression gate cannot sign/write.
//! All identities, targets and signing keys here are disposable test data.

use std::path::Path;
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

const BASELINE: &str = "rules = []\n";
const MANIFEST: &str = r#"
org = "synthetic"
version = 1
[[rules]]
name = "approved-read"
operation_pattern = "test.read"
allow = true
"#;

fn cli(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_opaque"))
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .args(args)
        .output()
        .expect("run CLI")
}

fn write_suite(path: &Path, expected: &str) {
    std::fs::write(
        path,
        serde_json::to_vec(&json!({
            "schema_version":1,"cases":[{
                "id":"read", "operation":"test.read", "safety":"SAFE", "client_type":"agent",
                "client_identity":{"uid":1000,"gid":1000},
                "target":{"repo":"synthetic-private-target"},
                "secret_ref_names":["synthetic-secret-reference"],
                "expect":{"decision":expected}
            }]
        }))
        .unwrap(),
    )
    .unwrap();
}

#[test]
fn cli_outputs_diff_and_failed_expectations_exit_nonzero() {
    let tmp = tempfile::tempdir().unwrap();
    let baseline = tmp.path().join("baseline.toml");
    let candidate = tmp.path().join("candidate.toml");
    let cases = tmp.path().join("cases.json");
    std::fs::write(&baseline, BASELINE).unwrap();
    std::fs::write(&candidate, MANIFEST).unwrap();
    write_suite(&cases, "deny");
    let result = cli(
        tmp.path(),
        &[
            "policy",
            "regress",
            "--baseline",
            baseline.to_str().unwrap(),
            "--candidate",
            candidate.to_str().unwrap(),
            "--cases",
            cases.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(result.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["scope"], "policy_engine_only");
    assert_eq!(report["passed"], false);
    assert_eq!(report["expectation_failures"], 1);
    assert_eq!(report["cases"][0]["changes"], json!(["newly_allowed"]));
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(!output.contains("synthetic-private-target"));
    assert!(!output.contains("synthetic-secret-reference"));

    write_suite(&cases, "allow");
    let args = [
        "policy",
        "regress",
        "--baseline",
        baseline.to_str().unwrap(),
        "--candidate",
        candidate.to_str().unwrap(),
        "--cases",
        cases.to_str().unwrap(),
        "--json",
    ];
    assert!(cli(tmp.path(), &args).status.success());
    let mut strict = args.to_vec();
    strict.push("--fail-on-change");
    assert_eq!(cli(tmp.path(), &strict).status.code(), Some(1));
}

#[test]
fn rejected_signing_gate_precedes_key_access_and_preserves_output() {
    let tmp = tempfile::tempdir().unwrap();
    let baseline = tmp.path().join("baseline.toml");
    let manifest = tmp.path().join("manifest.toml");
    let cases = tmp.path().join("cases.json");
    let key = tmp.path().join("nonexistent.key");
    let out = tmp.path().join("policy.bundle");
    std::fs::write(&baseline, BASELINE).unwrap();
    std::fs::write(&manifest, MANIFEST).unwrap();
    write_suite(&cases, "deny");
    let args = [
        "bundle",
        "sign",
        "--manifest",
        manifest.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--regression-cases",
        cases.to_str().unwrap(),
        "--baseline",
        baseline.to_str().unwrap(),
    ];
    let result = cli(tmp.path(), &args);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("policy regression gate failed"));
    assert!(!out.exists());
    assert!(!key.exists());

    std::fs::write(&out, "existing-signed-output").unwrap();
    assert!(!cli(tmp.path(), &args).status.success());
    assert_eq!(
        std::fs::read_to_string(out).unwrap(),
        "existing-signed-output"
    );
}

#[test]
fn passing_gate_signs_exact_candidate_and_signature_verifies() {
    let tmp = tempfile::tempdir().unwrap();
    let baseline = tmp.path().join("baseline.toml");
    let manifest = tmp.path().join("manifest.toml");
    let cases = tmp.path().join("cases.json");
    let key = tmp.path().join("disposable.key");
    let out = tmp.path().join("policy.bundle");
    std::fs::write(&baseline, BASELINE).unwrap();
    std::fs::write(&manifest, MANIFEST).unwrap();
    write_suite(&cases, "allow");
    let bytes = opaque_core::keyfile::load_or_create_key_file(&key).unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);
    let args = [
        "bundle",
        "sign",
        "--manifest",
        manifest.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--regression-cases",
        cases.to_str().unwrap(),
        "--baseline",
        baseline.to_str().unwrap(),
    ];
    let result = cli(tmp.path(), &args);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let text = std::fs::read_to_string(&out).unwrap();
    let verified =
        opaque_core::bundle::verify_bundle_allow_expired(&text, &[signing_key.verifying_key()])
            .unwrap();
    assert_eq!(verified.payload.org, "synthetic");
    assert_eq!(verified.payload.rules.len(), 1);
    assert_eq!(verified.payload.rules[0].operation_pattern, "test.read");

    let mut strict = args.to_vec();
    strict.push("--fail-on-policy-change");
    assert!(!cli(tmp.path(), &strict).status.success());
    assert_eq!(std::fs::read_to_string(&out).unwrap(), text);
}

#[test]
fn empty_unknown_and_malformed_suites_fail_without_echoing_input() {
    let tmp = tempfile::tempdir().unwrap();
    let baseline = tmp.path().join("baseline.toml");
    let cases = tmp.path().join("cases.json");
    std::fs::write(&baseline, BASELINE).unwrap();
    let args = [
        "policy",
        "regress",
        "--baseline",
        baseline.to_str().unwrap(),
        "--candidate",
        baseline.to_str().unwrap(),
        "--cases",
        cases.to_str().unwrap(),
        "--json",
    ];
    for input in [
        r#"{"schema_version":1,"cases":[]}"#,
        r#"{"schema_version":9,"cases":[]}"#,
        r#"{"schema_version":"sensitive-fixture-marker","cases":[]}"#,
        r#"{"schema_version":1,"cases":[],"params":"sensitive-fixture-marker"}"#,
    ] {
        std::fs::write(&cases, input).unwrap();
        let result = cli(tmp.path(), &args);
        assert_eq!(result.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&result.stderr).contains("sensitive-fixture-marker"));
    }
}

#[test]
fn signing_gate_arguments_must_be_complete() {
    let tmp = tempfile::tempdir().unwrap();
    for flag in ["--regression-cases", "--baseline"] {
        let result = cli(
            tmp.path(),
            &[
                "bundle",
                "sign",
                "--manifest",
                "manifest.toml",
                "--key",
                "key",
                "--out",
                "out",
                flag,
                "fixture",
            ],
        );
        assert_eq!(result.status.code(), Some(2));
    }
}

#[test]
fn checked_in_golden_suite_kills_target_broadening_and_approval_weakening() {
    let tmp = tempfile::tempdir().unwrap();
    let baseline = tmp.path().join("baseline.toml");
    let candidate = tmp.path().join("candidate.toml");
    let cases = tmp.path().join("golden.json");
    let original = include_str!("../../../examples/policy-regression/candidate.toml");
    std::fs::write(
        &baseline,
        include_str!("../../../examples/policy-regression/baseline.toml"),
    )
    .unwrap();
    std::fs::write(
        &cases,
        include_str!("../../../examples/policy-regression/golden.json"),
    )
    .unwrap();
    let args = [
        "policy",
        "regress",
        "--baseline",
        baseline.to_str().unwrap(),
        "--candidate",
        candidate.to_str().unwrap(),
        "--cases",
        cases.to_str().unwrap(),
        "--json",
    ];
    std::fs::write(&candidate, original).unwrap();
    let result = cli(tmp.path(), &args);
    assert!(result.status.success());
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["total_cases"], 6);
    assert_eq!(report["changed_cases"], 3);
    for mutation in [
        original.replace("environment = \"staging\"", "environment = \"*\""),
        original.replace("require = \"always\"", "require = \"never\""),
    ] {
        assert_ne!(original, mutation);
        std::fs::write(&candidate, mutation).unwrap();
        let result = cli(tmp.path(), &args);
        assert_eq!(result.status.code(), Some(1));
        let report: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert!(report["expectation_failures"].as_u64().unwrap() > 0);
    }
}

/// A FIFO regression must fail the test promptly, not hang the test runner.
fn cli_with_deadline(home: &Path, args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_opaque"))
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("regression input handling blocked past the deadline");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[test]
fn every_regression_input_rejects_fifos_and_oversized_files_before_signing() {
    let tmp = tempfile::tempdir().unwrap();
    let baseline = tmp.path().join("baseline.toml");
    let manifest = tmp.path().join("manifest.toml");
    let cases = tmp.path().join("cases.json");
    let key = tmp.path().join("nonexistent.key");
    let out = tmp.path().join("policy.bundle");
    let oversized = tmp.path().join("oversized");
    std::fs::File::create(&oversized)
        .unwrap()
        .set_len(8 * 1024 * 1024 + 1)
        .unwrap();
    let fifo = tmp.path().join("input.fifo");
    let fifo_name = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    // SAFETY: CString is NUL-terminated and valid for the duration of mkfifo.
    assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
    std::fs::write(&baseline, BASELINE).unwrap();
    std::fs::write(&manifest, MANIFEST).unwrap();
    write_suite(&cases, "allow");
    for (invalid, expected_error) in [
        (&oversized, "exceeds the 8 MiB regression input limit"),
        (&fifo, "must be a regular file"),
    ] {
        for field in ["--baseline", "--candidate", "--cases"] {
            let mut args = vec![
                "policy",
                "regress",
                "--baseline",
                baseline.to_str().unwrap(),
                "--candidate",
                manifest.to_str().unwrap(),
                "--cases",
                cases.to_str().unwrap(),
            ];
            let index = args.iter().position(|arg| *arg == field).unwrap() + 1;
            args[index] = invalid.to_str().unwrap();
            let result = cli_with_deadline(tmp.path(), &args);
            assert_eq!(result.status.code(), Some(2));
            assert!(String::from_utf8_lossy(&result.stderr).contains(expected_error));
        }
        let result = cli_with_deadline(
            tmp.path(),
            &[
                "bundle",
                "sign",
                "--manifest",
                invalid.to_str().unwrap(),
                "--key",
                key.to_str().unwrap(),
                "--out",
                out.to_str().unwrap(),
                "--regression-cases",
                cases.to_str().unwrap(),
                "--baseline",
                baseline.to_str().unwrap(),
            ],
        );
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains(expected_error));
        assert!(!key.exists());
        assert!(!out.exists());
    }
}

#[test]
fn gated_manifest_parse_errors_do_not_echo_config_contents() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = tmp.path().join("manifest.toml");
    let out = tmp.path().join("policy.bundle");
    std::fs::write(&manifest, "org = \"sensitive-fixture-marker\n").unwrap();
    let result = cli(
        tmp.path(),
        &[
            "bundle",
            "sign",
            "--manifest",
            manifest.to_str().unwrap(),
            "--key",
            "nonexistent.key",
            "--out",
            out.to_str().unwrap(),
            "--regression-cases",
            "nonexistent-cases.json",
            "--baseline",
            "nonexistent-baseline.toml",
        ],
    );
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("invalid bundle manifest TOML"));
    assert!(!String::from_utf8_lossy(&result.stderr).contains("sensitive-fixture-marker"));
    assert!(!out.exists());
}
