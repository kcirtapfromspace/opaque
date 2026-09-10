//! File/CLI boundary for the offline core regression harness.

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use opaque_core::bundle::Team;
use opaque_core::policy::PolicyRule;
use opaque_core::policy_regression::{PolicySnapshot, RegressionReport, RegressionSuite, compare};

const MAX_INPUT_BYTES: u64 = 8 * 1024 * 1024;

#[derive(serde::Deserialize)]
struct PolicyDocument {
    // Required: a wrong or empty file must not silently become deny-all.
    rules: Vec<PolicyRule>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    teams: Option<Vec<Team>>,
}

pub(crate) fn read_input(path: &Path) -> Result<String, String> {
    // O_NONBLOCK prevents a FIFO from hanging during open. Check the opened
    // descriptor, not the path, so a rename race cannot substitute a stream.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("cannot inspect {}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{} must be a regular file", path.display()));
    }
    if metadata.len() > MAX_INPUT_BYTES {
        return Err(format!(
            "{} exceeds the 8 MiB regression input limit",
            path.display()
        ));
    }
    let mut content = String::new();
    file.take(MAX_INPUT_BYTES + 1)
        .read_to_string(&mut content)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if content.len() as u64 > MAX_INPUT_BYTES {
        return Err(format!(
            "{} exceeds the 8 MiB regression input limit",
            path.display()
        ));
    }
    Ok(content)
}

fn load_policy(path: &Path) -> Result<PolicySnapshot, String> {
    let content = read_input(path)?;
    let parsed: PolicyDocument = toml_edit::de::from_str(&content)
        // Parser diagnostics may contain snippets of a config with credentials.
        .map_err(|_| {
            format!(
                "invalid policy TOML in {} (explicit rules required)",
                path.display()
            )
        })?;
    Ok(PolicySnapshot {
        rules: parsed.rules,
        teams: if parsed.org.is_some() {
            Some(parsed.teams.unwrap_or_default())
        } else {
            parsed.teams
        },
    })
}

fn load_suite(path: &Path) -> Result<RegressionSuite, String> {
    let content = read_input(path)?;
    serde_json::from_str(&content).map_err(|e| {
        format!(
            "invalid regression JSON at line {}, column {} (check required fields and schema)",
            e.line(),
            e.column()
        )
    })
}

pub fn print_report(report: &RegressionReport, json: bool) -> Result<(), String> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(report)
                .map_err(|_| "cannot serialize regression report")?
        );
    } else {
        println!(
            "Policy regression (policy engine only): {} cases, {} changed, {} expectation failures; {}",
            report.total_cases,
            report.changed_cases,
            report.expectation_failures,
            if report.passed { "PASS" } else { "FAIL" },
        );
        for case in &report.cases {
            if !case.changes.is_empty() || !case.passed {
                println!(
                    "  {}: {:?} -> {:?}; {:?}; expectation {}",
                    case.id,
                    case.baseline.decision,
                    case.candidate.decision,
                    case.changes,
                    if case.passed { "PASS" } else { "FAIL" }
                );
            }
        }
    }
    Ok(())
}

pub fn run(
    baseline: &Path,
    candidate: &Path,
    cases: &Path,
    fail_on_change: bool,
    json: bool,
) -> Result<bool, String> {
    let baseline = load_policy(baseline)?;
    let candidate = load_policy(candidate)?;
    let suite = load_suite(cases)?;
    let report =
        compare(&baseline, &candidate, &suite, fail_on_change).map_err(|e| e.to_string())?;
    print_report(&report, json)?;
    Ok(report.passed)
}

/// The caller must sign these exact in-memory rules and teams after success;
/// never reopen the candidate manifest between this gate and signing.
pub fn gate_bundle(
    baseline: &Path,
    cases: &Path,
    rules: &[PolicyRule],
    teams: &[Team],
    fail_on_change: bool,
) -> Result<(), String> {
    let baseline = load_policy(baseline)?;
    let suite = load_suite(cases)?;
    let candidate = PolicySnapshot {
        rules: rules.to_vec(),
        teams: Some(teams.to_vec()),
    };
    let report =
        compare(&baseline, &candidate, &suite, fail_on_change).map_err(|e| e.to_string())?;
    print_report(&report, false)?;
    if !report.passed {
        return Err("policy regression gate failed; bundle was not signed".into());
    }
    Ok(())
}
