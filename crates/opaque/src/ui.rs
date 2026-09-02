//! Terminal UI helpers for modern, styled CLI output.
//!
//! Provides colored output, spinners, and structured formatting
//! that degrades gracefully on non-TTY terminals.
//!
//! ## Design System
//!
//! **Color palette:**
//! - Success: green (bold for headline, normal for details)
//! - Error: red (bold for message, dim for code/details)
//! - Warning: yellow
//! - Info/accent: cyan
//! - Metadata/secondary: dim/grey
//! - Key names/identifiers: yellow bold
//! - Paths/URLs: cyan underlined
//!
//! **Typography hierarchy:**
//! - Bold: headers, key messages, identifiers
//! - Normal: body text, values
//! - Dim: metadata, timestamps, secondary info
//!
//! **Layout:**
//! - 2-space indent for nested content
//! - 6-space indent for sub-details
//! - Box-drawing characters for bordered sections
//! - Consistent column alignment in tables

use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use console::{Emoji, Term, style};
use indicatif::{ProgressBar, ProgressStyle};

// ---------------------------------------------------------------------------
// Verbosity control
// ---------------------------------------------------------------------------

/// Global verbosity level (0 = normal, 1 = quiet, 2 = verbose).
static VERBOSITY: AtomicU8 = AtomicU8::new(0);

const VERBOSITY_NORMAL: u8 = 0;
const VERBOSITY_QUIET: u8 = 1;
const VERBOSITY_VERBOSE: u8 = 2;

/// Set the global verbosity level. Call once at startup from main().
pub fn set_verbosity(quiet: bool, verbose: bool) {
    if quiet {
        VERBOSITY.store(VERBOSITY_QUIET, Ordering::Relaxed);
    } else if verbose {
        VERBOSITY.store(VERBOSITY_VERBOSE, Ordering::Relaxed);
    } else {
        VERBOSITY.store(VERBOSITY_NORMAL, Ordering::Relaxed);
    }
}

/// Returns true if quiet mode is active (--quiet or --json).
pub fn is_quiet() -> bool {
    VERBOSITY.load(Ordering::Relaxed) == VERBOSITY_QUIET
}

/// Returns true if verbose mode is active (--verbose).
pub fn is_verbose() -> bool {
    VERBOSITY.load(Ordering::Relaxed) == VERBOSITY_VERBOSE
}

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
// Box-drawing characters (with ASCII fallback for non-TTY)
// ---------------------------------------------------------------------------

/// Returns whether the terminal likely supports unicode box-drawing characters.
fn supports_unicode() -> bool {
    // console crate's Term handles TTY detection; if we can get a terminal
    // that is not dumb, assume unicode works.
    Term::stdout().is_term() && std::env::var("TERM").map(|t| t != "dumb").unwrap_or(true)
}

pub struct BoxChars {
    pub tl: &'static str, // top-left
    pub tr: &'static str, // top-right
    pub bl: &'static str, // bottom-left
    pub br: &'static str, // bottom-right
    pub h: &'static str,  // horizontal
    pub v: &'static str,  // vertical
}

pub fn box_chars() -> BoxChars {
    if supports_unicode() {
        BoxChars {
            tl: "┌",
            tr: "┐",
            bl: "└",
            br: "┘",
            h: "─",
            v: "│",
        }
    } else {
        BoxChars {
            tl: "+",
            tr: "+",
            bl: "+",
            br: "+",
            h: "-",
            v: "|",
        }
    }
}

/// Terminal width, clamped to a sensible range.
fn term_width() -> usize {
    Term::stdout().size().1 as usize
}

// ---------------------------------------------------------------------------
// Message helpers
// ---------------------------------------------------------------------------

/// Print a green success message. Suppressed in quiet mode.
pub fn success(msg: &str) {
    if is_quiet() {
        return;
    }
    println!("{} {}", style(CHECK).green(), style(msg).green().bold());
}

/// Print a red error message to stderr. Always prints (even in quiet mode).
pub fn error(msg: &str) {
    eprintln!("{} {}", style(CROSS).red(), style(msg).red().bold());
}

/// Print a yellow warning message to stderr. Suppressed in quiet mode.
pub fn warn(msg: &str) {
    if is_quiet() {
        return;
    }
    eprintln!("{} {}", style(WARN_ICON).yellow(), style(msg).yellow());
}

/// Print a cyan info message. Suppressed in quiet mode.
pub fn info(msg: &str) {
    if is_quiet() {
        return;
    }
    println!("{} {}", style(INFO_ICON).cyan(), msg);
}

/// Print a debug message (only in verbose mode) to stderr.
pub fn debug(msg: &str) {
    if !is_verbose() {
        return;
    }
    eprintln!("  {} {}", style("debug:").dim(), style(msg).dim());
}

// ---------------------------------------------------------------------------
// Structured output
// ---------------------------------------------------------------------------

/// Print a section header. Suppressed in quiet mode.
pub fn header(title: &str) {
    if is_quiet() {
        return;
    }
    println!("\n{}", style(title).bold().underlined());
}

/// Print a key-value pair with styled key. Suppressed in quiet mode.
pub fn kv(key: &str, value: &str) {
    if is_quiet() {
        return;
    }
    println!("  {:<16} {}", style(format!("{key}:")).dim(), value);
}

// ---------------------------------------------------------------------------
// New design system components
// ---------------------------------------------------------------------------

/// Print a bordered section box with a title and content lines.
///
/// ```text
///   ┌─ Title ──────────────────────┐
///   │  line 1                      │
///   │  line 2                      │
///   └──────────────────────────────┘
/// ```
pub fn section_box(title: &str, content: &[&str]) {
    if is_quiet() {
        return;
    }
    let b = box_chars();
    // Determine box width: fit content or terminal, whichever is smaller.
    let min_content_width = content
        .iter()
        .map(|l| console::measure_text_width(l))
        .max()
        .unwrap_or(0);
    let title_width = console::measure_text_width(title) + 4; // "─ Title ─"
    let inner_width = min_content_width.max(title_width).max(20);
    let tw = term_width();
    // Leave room for "  │  " prefix (5) + " │" suffix (2) + 2 for outer indent
    let max_inner = if tw > 9 { tw - 9 } else { 40 };
    let inner_width = inner_width.min(max_inner);
    let box_width = inner_width + 4; // 2 padding each side inside the box

    // Top border: ┌─ Title ─────┐
    let title_bar_remaining = if box_width > title_width + 2 {
        box_width - title_width - 2
    } else {
        1
    };
    println!(
        "  {}{} {} {}{}",
        style(b.tl).dim(),
        style(b.h).dim(),
        style(title).bold(),
        style(b.h.repeat(title_bar_remaining)).dim(),
        style(b.tr).dim(),
    );

    // Content lines
    for line in content {
        let visible_len = console::measure_text_width(line);
        let pad = if box_width > visible_len + 4 {
            box_width - visible_len - 4
        } else {
            0
        };
        println!(
            "  {}  {}{}  {}",
            style(b.v).dim(),
            line,
            " ".repeat(pad),
            style(b.v).dim(),
        );
    }

    // Bottom border
    println!(
        "  {}{}{}",
        style(b.bl).dim(),
        style(b.h.repeat(box_width)).dim(),
        style(b.br).dim(),
    );
}

/// Status badge states.
pub enum BadgeState {
    Ok,
    Fail,
    Warn,
    Info,
}

/// Print a colored inline status badge like `[OK]`, `[FAIL]`, `[WARN]`.
///
/// Returns the formatted string (does not print).
pub fn status_badge(label: &str, state: BadgeState) -> String {
    match state {
        BadgeState::Ok => style(format!("[{label}]")).green().bold().to_string(),
        BadgeState::Fail => style(format!("[{label}]")).red().bold().to_string(),
        BadgeState::Warn => style(format!("[{label}]")).yellow().bold().to_string(),
        BadgeState::Info => style(format!("[{label}]")).cyan().bold().to_string(),
    }
}

/// Print a properly aligned table with header separator.
///
/// `headers` and each row in `rows` must have the same length.
///
/// ```text
///   NAME             STATUS     UPDATED
///   ───────────────  ─────────  ─────────────
///   MY_SECRET        active     2024-03-15
///   DB_PASSWORD      active     2024-03-14
/// ```
pub fn table(headers: &[&str], rows: &[Vec<String>]) {
    if is_quiet() || headers.is_empty() {
        return;
    }

    // Calculate column widths.
    let col_count = headers.len();
    let mut widths: Vec<usize> = headers
        .iter()
        .map(|h| console::measure_text_width(h))
        .collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < col_count {
                widths[i] = widths[i].max(console::measure_text_width(cell));
            }
        }
    }

    // Print header.
    let header_line: String = headers
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let w = widths[i];
            format!("{:<width$}", h, width = w)
        })
        .collect::<Vec<_>>()
        .join("  ");
    println!("  {}", style(header_line).dim().bold());

    // Separator.
    let sep: String = widths
        .iter()
        .map(|w| {
            if supports_unicode() {
                "─".repeat(*w)
            } else {
                "-".repeat(*w)
            }
        })
        .collect::<Vec<_>>()
        .join("  ");
    println!("  {}", style(sep).dim());

    // Rows.
    for row in rows {
        let line: String = row
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                let w = if i < col_count { widths[i] } else { 0 };
                let visible = console::measure_text_width(cell);
                let pad = w.saturating_sub(visible);
                format!("{cell}{}", " ".repeat(pad))
            })
            .collect::<Vec<_>>()
            .join("  ");
        println!("  {line}");
    }
}

/// Print a numbered step indicator.
///
/// ```text
///   [2/5] Configuring providers...
/// ```
pub fn step(n: usize, total: usize, msg: &str) {
    if is_quiet() {
        return;
    }
    println!(
        "  {} {}",
        style(format!("[{n}/{total}]")).cyan().bold(),
        msg,
    );
}

/// Print a horizontal divider line.
pub fn divider() {
    if is_quiet() {
        return;
    }
    let w = term_width().min(72);
    let line = if supports_unicode() {
        "─".repeat(w)
    } else {
        "-".repeat(w)
    };
    println!("  {}", style(line).dim());
}

/// Print an app banner with title and subtitle.
///
/// ```text
///
///   ┌──────────────────────────────────┐
///   │  Opaque                    v0.1  │
///   │  Approval-gated secrets broker   │
///   └──────────────────────────────────┘
///
/// ```
pub fn banner(title: &str, subtitle: &str) {
    if is_quiet() {
        return;
    }
    let b = box_chars();
    let content_width = console::measure_text_width(title)
        .max(console::measure_text_width(subtitle))
        .max(30);
    let box_width = content_width + 4; // 2 padding each side

    println!();
    println!(
        "  {}{}{}",
        style(b.tl).dim(),
        style(b.h.repeat(box_width)).dim(),
        style(b.tr).dim(),
    );

    // Title line, padded.
    let title_pad = if box_width > console::measure_text_width(title) + 4 {
        box_width - console::measure_text_width(title) - 4
    } else {
        0
    };
    println!(
        "  {}  {}{}  {}",
        style(b.v).dim(),
        style(title).bold(),
        " ".repeat(title_pad),
        style(b.v).dim(),
    );

    // Subtitle line.
    let sub_pad = if box_width > console::measure_text_width(subtitle) + 4 {
        box_width - console::measure_text_width(subtitle) - 4
    } else {
        0
    };
    println!(
        "  {}  {}{}  {}",
        style(b.v).dim(),
        style(subtitle).dim(),
        " ".repeat(sub_pad),
        style(b.v).dim(),
    );

    println!(
        "  {}{}{}",
        style(b.bl).dim(),
        style(b.h.repeat(box_width)).dim(),
        style(b.br).dim(),
    );
    println!();
}

/// Format a path for display (cyan, underlined).
#[allow(dead_code)]
pub fn path(p: &str) -> String {
    style(p).cyan().underlined().to_string()
}

/// Format an identifier/key name (yellow, bold).
#[allow(dead_code)]
pub fn ident(name: &str) -> String {
    style(name).yellow().bold().to_string()
}

/// Format secondary/metadata text (dim).
pub fn dim(text: &str) -> String {
    style(text).dim().to_string()
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
                    // The logged-in principal is rendered as its own
                    // section below, not as a raw JSON blob.
                    if k == "identity" || k == "identity_required" {
                        continue;
                    }
                    let val = match v {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    kv(k, &val);
                }
                format_whoami_identity(obj);
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
        "identity.logout" => {
            format_identity_logout_result(result);
        }
        "identity.principal_list" => {
            format_identity_principal_list_result(result);
        }
        "identity.role_set" => {
            format_identity_role_set_result(result);
        }
        "identity.delegation_list" => {
            format_identity_delegation_list_result(result);
        }
        "device_pair_start" => {
            format_device_pair_start_result(result);
        }
        "device_list" => {
            format_device_list_result(result);
        }
        "device_pair_confirm" => {
            let name = result.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            success(&format!(
                "Device \"{name}\" confirmed — it now holds approval authority."
            ));
        }
        "device_revoke" => {
            let id = result
                .get("device_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            success(&format!(
                "Device {id} revoked — approval authority removed."
            ));
        }
        _ => {
            print_json(result);
        }
    }
}

/// Render the pairing payload + next steps.
fn format_device_pair_start_result(result: &serde_json::Value) {
    header("Device pairing started");
    if let Some(addr) = result.get("server_addr").and_then(|v| v.as_str()) {
        kv("approval server", addr);
    }
    if let Some(payload) = result.get("qr_payload") {
        if let Some(expires) = payload.get("expires_at").and_then(|v| v.as_i64()) {
            kv("pairing window ends", &format_epoch_seconds(expires));
        }
        println!();
        info("Scan this payload with the companion app (JSON, single line):");
        if let Ok(compact) = serde_json::to_string(payload) {
            println!("{compact}");
        }
    }
    println!();
    info("After the app completes pairing, run `opaque device ls` to see the new");
    info("device, then `opaque device confirm <device-id>` and MATCH the key");
    info("fingerprint against what the device displays. Until confirmed, the");
    info("device has no approval authority.");
}

/// Render the device table.
fn format_device_list_result(result: &serde_json::Value) {
    let empty = vec![];
    let devices = result
        .get("devices")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);
    if devices.is_empty() {
        info("No paired devices.");
        return;
    }
    header(&format!("{} paired device(s)", devices.len()));
    for d in devices {
        let name = d.get("name").and_then(|v| v.as_str()).unwrap_or("?");
        let id = d.get("device_id").and_then(|v| v.as_str()).unwrap_or("?");
        let fp = d.get("fingerprint").and_then(|v| v.as_str()).unwrap_or("?");
        let revoked = d.get("revoked").and_then(|v| v.as_bool()).unwrap_or(false);
        let confirmed = d
            .get("confirmed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let badge = if revoked {
            status_badge("REVOKED", BadgeState::Fail)
        } else if !confirmed {
            status_badge("UNCONFIRMED", BadgeState::Warn)
        } else {
            status_badge("ACTIVE", BadgeState::Ok)
        };
        println!(
            "  {badge} {}  {}",
            style(name).yellow().bold(),
            style(format!("fingerprint {fp}")).dim()
        );
        println!("      {}", style(format!("id {id}")).dim());
        if let Some(paired_by) = d.get("paired_by").and_then(|v| v.as_str()) {
            println!("      {}", style(format!("paired by {paired_by}")).dim());
        }
        if !confirmed && !revoked {
            println!(
                "      {}",
                style(format!("confirm with: opaque device confirm {id}")).cyan()
            );
        }
    }
}

/// Format a unix-seconds timestamp relative to now (no date dependency).
fn format_epoch_seconds(secs: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let delta = secs - now;
    if delta > 0 {
        format!("in {delta}s")
    } else {
        format!("{}s ago", -delta)
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

    // sandbox.exec returns exit code + output lengths (never content).
    if let Some(exit_code) = obj.get("exit_code").and_then(|v| v.as_i64()) {
        // SECURITY (C2): the daemon does not return stdout/stderr content — a
        // command's output may contain secrets. Only lengths are surfaced here; a
        // human-only live-output view is tracked as separate follow-up work.
        let stdout_len = obj
            .get("stdout_length")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let stderr_len = obj
            .get("stderr_length")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if stdout_len > 0 || stderr_len > 0 {
            println!(
                "  {}",
                style(format!(
                    "output withheld (stdout: {stdout_len} bytes, stderr: {stderr_len} bytes)"
                ))
                .dim()
            );
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
    let end_all = result.get("all").and_then(|v| v.as_bool()).unwrap_or(false);

    if end_all {
        let ended_count = result
            .get("ended_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        success(&format!(
            "Ended {ended_count} wrapped-agent session(s) for current user"
        ));
        return;
    }

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

// ---------------------------------------------------------------------------
// Identity substrate rendering (Phase 1)
// ---------------------------------------------------------------------------

/// Format a future epoch-ms timestamp as "in Xh Ym" (or "expired").
fn format_expires_in(expires_at_ms: i64) -> String {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let remaining_secs = (expires_at_ms - now_ms) / 1000;
    if remaining_secs <= 0 {
        return "expired".into();
    }
    if remaining_secs < 60 {
        format!("in {remaining_secs}s")
    } else if remaining_secs < 3600 {
        format!("in {}m", remaining_secs / 60)
    } else if remaining_secs < 86400 {
        format!(
            "in {}h {}m",
            remaining_secs / 3600,
            (remaining_secs % 3600) / 60
        )
    } else {
        format!(
            "in {}d {}h",
            remaining_secs / 86400,
            (remaining_secs % 86400) / 3600
        )
    }
}

/// Shorten a principal/session id for table display: `hum_0a1b2c3d…`.
fn short_id(id: &str) -> String {
    if id.chars().count() > 12 {
        format!("{}…", id.chars().take(12).collect::<String>())
    } else {
        id.to_string()
    }
}

fn roles_cell(roles: Option<&serde_json::Value>) -> String {
    roles
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| r.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "-".into())
}

/// Render the logged-in principal summary (used by `opaque login` success
/// and the whoami identity section).
pub fn format_identity_summary(identity: &serde_json::Value) {
    if is_quiet() || identity.is_null() {
        return;
    }
    if let Some(label) = identity.get("label").and_then(|v| v.as_str()) {
        kv("principal", label);
    }
    if let Some(id) = identity.get("principal_id").and_then(|v| v.as_str()) {
        kv("id", &ident(id));
    }
    if let Some(email) = identity.get("email").and_then(|v| v.as_str()) {
        kv("email", email);
    }
    let roles = roles_cell(identity.get("roles"));
    if roles != "-" {
        kv("roles", &style(roles).cyan().to_string());
    }
    if let Some(iss) = identity.get("issuer").and_then(|v| v.as_str()) {
        kv("issuer", &dim(iss));
    }
    if let Some(exp) = identity
        .get("session_expires_at_utc_ms")
        .and_then(|v| v.as_i64())
    {
        kv("session", &format!("expires {}", format_expires_in(exp)));
    }
}

/// Render the identity portion of a whoami response.
fn format_whoami_identity(obj: &serde_json::Map<String, serde_json::Value>) {
    let identity = obj.get("identity");
    let required = obj
        .get("identity_required")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Older daemons don't send identity fields at all — print nothing.
    if identity.is_none() && !required {
        return;
    }

    header("Identity");
    match identity {
        Some(id_obj) if !id_obj.is_null() => {
            format_identity_summary(id_obj);
        }
        _ => {
            println!("  {}", dim("not signed in"));
            if required {
                println!(
                    "  {} {}",
                    style("hint:").cyan().bold(),
                    style("this daemon requires identity — run `opaque login`").cyan()
                );
            }
        }
    }
}

fn format_identity_logout_result(result: &serde_json::Value) {
    let revoked = result.get("revoked").and_then(|v| v.as_u64()).unwrap_or(0);
    if revoked == 0 {
        info("No active login sessions");
    } else {
        success(&format!("Revoked {revoked} login session(s)"));
    }
}

fn format_identity_principal_list_result(result: &serde_json::Value) {
    let principals = match result.get("principals").and_then(|v| v.as_array()) {
        Some(p) => p,
        None => {
            print_json(result);
            return;
        }
    };
    if principals.is_empty() {
        info("No principals registered — run `opaque login` to create the first one");
        return;
    }

    header(&format!("{} principal(s)", principals.len()));
    let rows: Vec<Vec<String>> = principals
        .iter()
        .map(|p| {
            let id = p.get("id").and_then(|v| v.as_str()).unwrap_or("?");
            let kind = p.get("kind").and_then(|v| v.as_str()).unwrap_or("?");
            let label = p.get("label").and_then(|v| v.as_str()).unwrap_or("-");
            let disabled = p.get("disabled").and_then(|v| v.as_bool()).unwrap_or(false);
            let last_seen = p
                .get("last_seen")
                .and_then(|v| v.as_i64())
                .map(|secs| crate::format_relative_time(secs * 1000))
                .unwrap_or_else(|| "-".into());
            let status = if disabled {
                status_badge("DISABLED", BadgeState::Fail)
            } else {
                status_badge("OK", BadgeState::Ok)
            };
            vec![
                short_id(id),
                kind.to_string(),
                label.to_string(),
                roles_cell(p.get("roles")),
                last_seen,
                status,
            ]
        })
        .collect();
    table(
        &["ID", "KIND", "LABEL", "ROLES", "LAST SEEN", "STATUS"],
        &rows,
    );
}

fn format_identity_role_set_result(result: &serde_json::Value) {
    let label = result
        .get("label")
        .and_then(|v| v.as_str())
        .or_else(|| result.get("id").and_then(|v| v.as_str()))
        .unwrap_or("principal");
    success(&format!(
        "Updated roles for {}: {}",
        style(label).bold(),
        style(roles_cell(result.get("roles"))).cyan()
    ));
}

fn format_identity_delegation_list_result(result: &serde_json::Value) {
    let delegations = match result.get("delegations").and_then(|v| v.as_array()) {
        Some(d) => d,
        None => {
            print_json(result);
            return;
        }
    };
    if delegations.is_empty() {
        info("No delegations recorded");
        return;
    }

    header(&format!("{} delegation(s)", delegations.len()));
    let rows: Vec<Vec<String>> = delegations
        .iter()
        .map(|d| {
            let jti = d.get("jti").and_then(|v| v.as_str()).unwrap_or("?");
            let mode = d.get("mode").and_then(|v| v.as_str()).unwrap_or("?");
            let sub = d
                .get("sub_label")
                .or_else(|| d.get("sub"))
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let act = d
                .get("act_label")
                .or_else(|| d.get("act"))
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let approved_by = d
                .get("approved_by")
                .and_then(|v| v.as_str())
                .map(short_id)
                .unwrap_or_else(|| "-".into());
            let state = if d.get("revoked_at").is_some_and(|v| !v.is_null()) {
                status_badge("REVOKED", BadgeState::Warn)
            } else {
                match d.get("expires_at").and_then(|v| v.as_i64()) {
                    // expires_at is unix seconds in delegation records.
                    Some(exp) => {
                        let human = format_expires_in(exp * 1000);
                        if human == "expired" {
                            status_badge("EXPIRED", BadgeState::Warn)
                        } else {
                            format!("expires {human}")
                        }
                    }
                    None => "-".into(),
                }
            };
            vec![
                short_id(jti),
                mode.to_string(),
                sub.to_string(),
                act.to_string(),
                approved_by,
                state,
            ]
        })
        .collect();
    table(
        &[
            "SESSION",
            "MODE",
            "ON BEHALF OF",
            "AGENT",
            "APPROVED BY",
            "STATE",
        ],
        &rows,
    );
}

/// Format a daemon error response.
pub fn format_error(err: &opaque_core::proto::ErrorObj) {
    error(&err.message);
    if !err.code.is_empty() {
        println!(
            "  {} {}",
            style("code:").dim(),
            style(&err.code).red().dim()
        );
    }

    // Provide actionable hints based on error code
    if !err.code.is_empty() {
        println!();
        match err.code.as_str() {
            code if code.contains("denied") || code.contains("DENIED") => {
                println!(
                    "  {} This operation was denied by the security policy.",
                    style("hint:").cyan().bold()
                );
                println!(
                    "    • Check policy: {}",
                    style("opaque policy show").yellow()
                );
                println!(
                    "    • Request approval or check pending leases: {}",
                    style("opaque leases").yellow()
                );
            }
            code if code.contains("not_found") || code.contains("NOT_FOUND") => {
                println!(
                    "  {} Resource not found. Check that names and IDs are correct.",
                    style("hint:").cyan().bold()
                );
                println!("    • List available resources before trying again");
            }
            code if code.contains("invalid") || code.contains("INVALID") => {
                println!(
                    "  {} Check your input parameters for validity.",
                    style("hint:").cyan().bold()
                );
                println!(
                    "    • Run with {}  for more details",
                    style("--json").yellow()
                );
            }
            code if code.contains("config") || code.contains("CONFIG") => {
                println!(
                    "  {} Daemon configuration issue.",
                    style("hint:").cyan().bold()
                );
                println!(
                    "    • Verify config: {}",
                    style("opaque policy check").yellow()
                );
                println!("    • Run diagnostics: {}", style("opaque doctor").yellow());
            }
            _ => {
                println!(
                    "  {} Run '{}' for diagnostics",
                    style("hint:").cyan().bold(),
                    style("opaque doctor").yellow()
                );
            }
        }
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
// Init formatting
// ---------------------------------------------------------------------------

/// Print a step during init with a green check.
pub fn init_step(msg: &str) {
    if is_quiet() {
        return;
    }
    println!("  {} {}", style(CHECK).green(), msg);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }

    #[test]
    fn format_expires_in_past_is_expired() {
        assert_eq!(format_expires_in(now_ms() - 5_000), "expired");
        assert_eq!(format_expires_in(0), "expired");
    }

    #[test]
    fn format_expires_in_future_buckets() {
        let now = now_ms();
        assert!(format_expires_in(now + 30_000).starts_with("in "));
        let hours = format_expires_in(now + 2 * 3600 * 1000 + 90_000);
        assert!(hours.starts_with("in 2h"), "got {hours}");
        let days = format_expires_in(now + 3 * 86400 * 1000 + 3_600_000);
        assert!(days.starts_with("in 3d"), "got {days}");
    }

    #[test]
    fn short_id_truncates_long_ids_safely() {
        let id = "hum_0123456789abcdef0123456789abcdef";
        let short = short_id(id);
        assert!(short.starts_with("hum_01234567"));
        assert!(short.ends_with('…'));
        assert_eq!(short_id("hum_short"), "hum_short");
        // Multi-byte chars must not panic.
        let _ = short_id("ééééééééééééééééé");
    }

    #[test]
    fn roles_cell_renders_lists_and_dashes() {
        let v = serde_json::json!(["admin", "operator"]);
        assert_eq!(roles_cell(Some(&v)), "admin, operator");
        let empty = serde_json::json!([]);
        assert_eq!(roles_cell(Some(&empty)), "-");
        assert_eq!(roles_cell(None), "-");
    }
}
