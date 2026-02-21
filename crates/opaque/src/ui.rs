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
        "github" | "gitlab" | "execute" | "exec" => {
            format_operation_result(result);
        }
        "onepassword" => {
            format_onepassword_result(result);
        }
        "leases" => {
            format_leases_result(result);
        }
        "agent_session_list" => {
            format_agent_session_list_result(result);
        }
        "agent_session_end" => {
            format_agent_session_end_result(result);
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

    // github.list_secrets returns total_count + secrets array.
    if let Some(secrets) = obj.get("secrets").and_then(|v| v.as_array()) {
        let total = obj
            .get("total_count")
            .and_then(|v| v.as_i64())
            .unwrap_or(secrets.len() as i64);
        header(&format!("{total} secret(s)"));
        for secret in secrets {
            let name = secret
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("(unknown)");
            let updated = secret
                .get("updated_at")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if updated.is_empty() {
                println!("  {} {}", style(KEY).dim(), style(name).yellow().bold());
            } else {
                println!(
                    "  {} {}  {}",
                    style(KEY).dim(),
                    style(name).yellow().bold(),
                    style(format!("(updated {updated})")).dim()
                );
            }
        }
        return;
    }

    // sandbox.exec returns stdout/stderr + exit code.
    if let Some(exit_code) = obj.get("exit_code").and_then(|v| v.as_i64()) {
        // Print captured stdout directly (not styled — preserve command output).
        if let Some(stdout) = obj.get("stdout").and_then(|v| v.as_str())
            && !stdout.is_empty()
        {
            print!("{stdout}");
            if !stdout.ends_with('\n') {
                println!();
            }
        }
        // Print captured stderr to stderr.
        if let Some(stderr) = obj.get("stderr").and_then(|v| v.as_str())
            && !stderr.is_empty()
        {
            eprint!("{stderr}");
            if !stderr.ends_with('\n') {
                eprintln!();
            }
        }

        // Show truncation warning if output was capped.
        if obj
            .get("truncated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            let stdout_len = obj
                .get("stdout_length")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let stderr_len = obj
                .get("stderr_length")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            warn(&format!(
                "Output truncated (stdout: {} bytes, stderr: {} bytes)",
                stdout_len, stderr_len
            ));
        }

        // Summary line.
        let duration = obj.get("duration_ms").and_then(|v| v.as_u64()).unwrap_or(0);
        if exit_code == 0 {
            success(&format!("Sandbox exec succeeded ({duration}ms)"));
        } else {
            warn(&format!(
                "Sandbox exec failed (exit_code={exit_code}, {duration}ms)"
            ));
        }
        return;
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

/// Format a 1Password response (list_vaults or list_items).
fn format_onepassword_result(result: &serde_json::Value) {
    if let Some(vaults) = result.get("vaults").and_then(|v| v.as_array()) {
        header(&format!("{} vault(s)", vaults.len()));
        for vault in vaults {
            let name = vault
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("(unknown)");
            let desc = vault
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if desc.is_empty() {
                println!("  {} {}", style(FOLDER).dim(), style(name).cyan().bold());
            } else {
                println!(
                    "  {} {}  {}",
                    style(FOLDER).dim(),
                    style(name).cyan().bold(),
                    style(desc).dim()
                );
            }
        }
    } else if result.get("field").is_some() {
        // read_field response: vault, item, field, value.
        let vault = result.get("vault").and_then(|v| v.as_str()).unwrap_or("?");
        let item = result.get("item").and_then(|v| v.as_str()).unwrap_or("?");
        let field = result.get("field").and_then(|v| v.as_str()).unwrap_or("?");
        let value = result.get("value").and_then(|v| v.as_str()).unwrap_or("");
        header(&format!("{vault}/{item}/{field}"));
        println!("  {}", value);
    } else if let Some(items) = result.get("items").and_then(|v| v.as_array()) {
        let vault_name = result
            .get("vault")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)");
        header(&format!(
            "{} item(s) in vault '{}'",
            items.len(),
            vault_name
        ));
        for item in items {
            let title = item
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("(unknown)");
            let category = item.get("category").and_then(|v| v.as_str()).unwrap_or("");
            if category.is_empty() {
                println!("  {} {}", style(KEY).dim(), style(title).yellow().bold());
            } else {
                println!(
                    "  {} {}  {}",
                    style(KEY).dim(),
                    style(title).yellow().bold(),
                    style(format!("[{category}]")).dim()
                );
            }
        }
    } else {
        print_json(result);
    }
}

/// Format active leases response.
fn format_leases_result(result: &serde_json::Value) {
    let count = result.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
    let leases = result.get("leases").and_then(|v| v.as_array());

    if count == 0 {
        info("No active approval leases");
        return;
    }

    header(&format!("{count} active lease(s)"));

    if let Some(leases) = leases {
        for lease in leases {
            let operation = lease
                .get("operation")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let target = lease.get("target").and_then(|v| v.as_str()).unwrap_or("");
            let ttl = lease
                .get("ttl_remaining_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let fingerprint = lease
                .get("client_fingerprint")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let one_time = lease
                .get("one_time")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let ttl_str = if ttl >= 60 {
                format!("{}m {}s", ttl / 60, ttl % 60)
            } else {
                format!("{ttl}s")
            };

            println!(
                "  {} {}  {}",
                style(KEY).dim(),
                style(operation).yellow().bold(),
                style(format!("({ttl_str} remaining)")).dim()
            );
            if !target.is_empty() {
                println!(
                    "      {} {}",
                    style("target:").dim(),
                    target.replace('\0', ", ")
                );
            }
            let mut meta = vec![format!("client:{fingerprint}")];
            if one_time {
                meta.push("one-time".into());
            }
            println!(
                "      {} {}",
                style("meta:").dim(),
                style(meta.join(", ")).dim()
            );
        }
    } else {
        print_json(result);
    }
}

/// Format active wrapped-agent sessions response.
fn format_agent_session_list_result(result: &serde_json::Value) {
    let count = result.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
    let sessions = result.get("sessions").and_then(|v| v.as_array());

    if count == 0 {
        info("No active agent sessions");
        return;
    }

    header(&format!("{count} active agent session(s)"));

    if let Some(sessions) = sessions {
        for session in sessions {
            let session_id = session
                .get("session_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let label = session.get("label").and_then(|v| v.as_str()).unwrap_or("");
            let ttl = session
                .get("ttl_remaining_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            let ttl_str = if ttl >= 60 {
                format!("{}m {}s", ttl / 60, ttl % 60)
            } else {
                format!("{ttl}s")
            };

            if label.is_empty() {
                println!(
                    "  {} {}  {}",
                    style(KEY).dim(),
                    style(session_id).yellow().bold(),
                    style(format!("({ttl_str} remaining)")).dim()
                );
            } else {
                println!(
                    "  {} {}  {}  {}",
                    style(KEY).dim(),
                    style(session_id).yellow().bold(),
                    style(format!("({ttl_str} remaining)")).dim(),
                    style(format!("[{label}]")).dim()
                );
            }
        }
    } else {
        print_json(result);
    }
}

/// Format agent session end/revoke response.
fn format_agent_session_end_result(result: &serde_json::Value) {
    let status = result
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let session_id = result
        .get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or("?");

    match status {
        "ended" => success(&format!("Ended agent session {session_id}")),
        "not_found" => warn(&format!("Agent session not found: {session_id}")),
        _ => print_json(result),
    }
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
