//! Terminal UI helpers for modern, styled CLI output.
//!
//! Provides colored output, spinners, and structured formatting
//! that degrades gracefully on non-TTY terminals.

use std::time::Duration;

use console::{Emoji, style};
use indicatif::{ProgressBar, ProgressStyle};

// ---------------------------------------------------------------------------
// Emoji constants (fallback text for non-emoji terminals)
// ---------------------------------------------------------------------------

pub static CHECK: Emoji<'_, '_> = Emoji("✔ ", "ok ");
pub static CROSS: Emoji<'_, '_> = Emoji("✖ ", "!! ");
pub static WARN_ICON: Emoji<'_, '_> = Emoji("⚠ ", "!! ");
pub static INFO_ICON: Emoji<'_, '_> = Emoji("ℹ ", "-- ");
pub static KEY: Emoji<'_, '_> = Emoji("🔑 ", "** ");
pub static FOLDER: Emoji<'_, '_> = Emoji("📁 ", "[] ");
pub static PAPER: Emoji<'_, '_> = Emoji("📄 ", "   ");
pub static LINK: Emoji<'_, '_> = Emoji("🔗 ", "-> ");

// ---------------------------------------------------------------------------
// Message helpers
// ---------------------------------------------------------------------------

/// Print a green success message.
pub fn success(msg: &str) {
    println!("{} {}", style(CHECK).green(), style(msg).green().bold());
}

/// Print a red error message to stderr.
pub fn error(msg: &str) {
    eprintln!("{} {}", style(CROSS).red(), style(msg).red().bold());
}

/// Print a yellow warning message to stderr.
pub fn warn(msg: &str) {
    eprintln!("{} {}", style(WARN_ICON).yellow(), style(msg).yellow());
}

/// Print a cyan info message.
pub fn info(msg: &str) {
    println!("{} {}", style(INFO_ICON).cyan(), msg);
}

// ---------------------------------------------------------------------------
// Structured output
// ---------------------------------------------------------------------------

/// Print a section header.
pub fn header(title: &str) {
    println!("\n{}", style(title).bold().underlined());
}

/// Print a key-value pair with styled key.
pub fn kv(key: &str, value: &str) {
    println!("  {:<16} {}", style(format!("{key}:")).dim(), value);
}

// ---------------------------------------------------------------------------
// Spinner
// ---------------------------------------------------------------------------

/// Create and start a spinner with the given message.
pub fn spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ ")
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

/// Finish a spinner with an error message.
///
/// Falls back to direct stderr output when the progress bar is hidden
/// (e.g. when output is piped to a non-TTY).
pub fn spinner_error(pb: &ProgressBar, msg: &str) {
    if pb.is_hidden() {
        pb.finish_and_clear();
        error(msg);
    } else {
        pb.set_style(ProgressStyle::default_spinner().template("{msg}").unwrap());
        pb.finish_with_message(format!(
            "{} {}",
            style(CROSS).red(),
            style(msg).red().bold()
        ));
    }
}

// ---------------------------------------------------------------------------
// Response formatting
// ---------------------------------------------------------------------------

/// Format a daemon response in a human-friendly way.
///
/// Extracts known fields and presents them with appropriate styling.
/// Falls back to pretty-printed JSON for unknown shapes.
pub fn format_response(method: &str, result: &serde_json::Value) {
    match method {
        "ping" => {
            if let Some(status) = result.get("status").and_then(|v| v.as_str()) {
                if status == "ok" {
                    success("Daemon is alive");
                } else {
                    warn(&format!("Daemon responded with status: {status}"));
                }
            } else {
                success("Pong");
            }
        }
        "version" => {
            if let Some(ver) = result.get("version").and_then(|v| v.as_str()) {
                println!("  {} {}", style("opaqued").bold(), style(ver).cyan().bold());
            } else {
                print_json(result);
            }
        }
        "whoami" => {
            header("Client Identity");
            if let Some(obj) = result.as_object() {
                for (k, v) in obj {
                    let val = match v {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    kv(k, &val);
                }
            } else {
                print_json(result);
            }
        }
        "github" | "execute" | "exec" => {
            format_operation_result(result);
        }
        _ => {
            print_json(result);
        }
    }
}

/// Format an operation result (github, execute, exec).
fn format_operation_result(result: &serde_json::Value) {
    let obj = match result.as_object() {
        Some(o) => o,
        None => {
            print_json(result);
            return;
        }
    };

    // sandbox.exec returns a summary without a status field.
    if let Some(exit_code) = obj.get("exit_code").and_then(|v| v.as_i64()) {
        if exit_code == 0 {
            success("Sandbox exec succeeded");
        } else {
            warn(&format!("Sandbox exec failed (exit_code={exit_code})"));
        }
    } else {
        // Check status first
        let status = obj
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        match status {
            "ok" | "success" | "created" | "updated" => {
                // Build a descriptive success line.
                // For non-provider operations, fall back to a generic message.
                let desc = build_operation_description(obj);
                success(&desc);
            }
            _ => {
                warn(&format!("Operation returned status: {status}"));
            }
        }
    }

    // Print relevant fields (skip status since we already showed it)
    for (k, v) in obj {
        if k == "status" {
            continue;
        }
        let val = match v {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Null => continue,
            other => other.to_string(),
        };
        match k.as_str() {
            "secret_name" => {
                println!("  {} {}", style(KEY).dim(), style(&val).yellow().bold());
            }
            "repo" | "org" => {
                println!("  {} {}", style(LINK).dim(), style(&val).cyan());
            }
            "environment" => {
                println!(
                    "  {} {} {}",
                    style("env:").dim(),
                    style(FOLDER).dim(),
                    style(&val).magenta()
                );
            }
            "scope" => {
                println!("  {} {}", style("scope:").dim(), style(&val).dim());
            }
            _ => {
                kv(k, &val);
            }
        }
    }
}

/// Build a short description from operation result fields.
fn build_operation_description(obj: &serde_json::Map<String, serde_json::Value>) -> String {
    let Some(secret) = obj.get("secret_name").and_then(|v| v.as_str()) else {
        return "Operation succeeded".into();
    };

    if let Some(env) = obj.get("environment").and_then(|v| v.as_str())
        && let Some(repo) = obj.get("repo").and_then(|v| v.as_str())
    {
        return format!("Set {secret} on {repo} (env: {env})");
    }

    if let Some(repo) = obj.get("repo").and_then(|v| v.as_str()) {
        return format!("Set {secret} on {repo}");
    }

    if let Some(org) = obj.get("org").and_then(|v| v.as_str()) {
        return format!("Set {secret} on org {org}");
    }

    if let Some(scope) = obj.get("scope").and_then(|v| v.as_str())
        && scope == "user"
    {
        return format!("Set {secret} (user-level)");
    }

    format!("Operation completed: {secret}")
}

/// Format a daemon error response.
pub fn format_error(err: &opaque_core::proto::ErrorObj) {
    error(&err.message);
    if !err.code.is_empty() {
        println!("  {} {}", style("code:").dim(), style(&err.code).red());
    }
}

/// Pretty-print a JSON value as a fallback.
pub fn print_json(value: &serde_json::Value) {
    let formatted = serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_string());
    for line in formatted.lines() {
        println!("  {}", style(line).dim());
    }
}

// ---------------------------------------------------------------------------
// Audit formatting
// ---------------------------------------------------------------------------

/// Print an audit event row with colored columns.
pub fn audit_row(timestamp: &str, kind: &str, operation: &str, outcome: &str, request_id: &str) {
    let styled_outcome = match outcome {
        "allowed" | "ok" | "success" => style(format!("{outcome:<8}")).green(),
        "denied" | "error" | "failed" => style(format!("{outcome:<8}")).red(),
        _ => style(format!("{outcome:<8}")).yellow(),
    };

    let styled_kind = match kind {
        k if k.contains("denied") => style(format!("{kind:<24}")).red(),
        k if k.contains("error") => style(format!("{kind:<24}")).red(),
        k if k.contains("allowed") || k.contains("completed") => {
            style(format!("{kind:<24}")).green()
        }
        _ => style(format!("{kind:<24}")).white(),
    };

    println!(
        "  {} {} {} {} {}",
        style(timestamp).dim(),
        styled_kind,
        style(format!("{operation:<30}")).cyan(),
        styled_outcome,
        style(request_id).dim(),
    );
}

/// Print the audit log header row.
pub fn audit_header() {
    println!(
        "  {} {} {} {} {}",
        style(format!("{:<27}", "TIMESTAMP")).dim().bold(),
        style(format!("{:<24}", "EVENT")).dim().bold(),
        style(format!("{:<30}", "OPERATION")).dim().bold(),
        style(format!("{:<8}", "OUTCOME")).dim().bold(),
        style("REQUEST ID").dim().bold(),
    );
    println!("  {}", style("─".repeat(100)).dim());
}

// ---------------------------------------------------------------------------
// Init formatting
// ---------------------------------------------------------------------------

/// Print a step during init with a green check.
pub fn init_step(msg: &str) {
    println!("  {} {}", style(CHECK).green(), msg);
}
