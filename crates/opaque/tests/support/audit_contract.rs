//! Actual CLI queries over the production SQLite audit sink. These cases check
//! filtering, presentation, rejection and read-only state; no ambient broker.
use super::*;
use opaque_core::audit::{AuditEvent, AuditEventKind, AuditSink, SqliteAuditSink};
use serde_json::{Value, json};

fn database(f: &Fixture, events: &[AuditEvent]) -> PathBuf {
    let path = f.home.join(".opaque/audit.db");
    let sink = SqliteAuditSink::new(path.clone(), 90).unwrap();
    for event in events {
        sink.emit(event.clone());
    }
    drop(sink);
    let verified = opaque_core::audit::verify_audit_chain(&path).unwrap();
    assert!(verified.ok, "{verified:?}");
    assert_eq!(verified.records_checked, events.len() as u64);
    path
}

fn projected(event: &AuditEvent) -> Value {
    json!({"event_id":event.event_id,"ts_utc_ms":event.ts_utc_ms,
        "kind":event.kind.to_string(),"operation":event.operation,
        "outcome":event.outcome,"request_id":event.request_id})
}

fn rows(f: &Fixture, options: &[&str]) -> Vec<Value> {
    let mut args = vec!["audit", "tail", "--json"];
    args.extend(options);
    let out = f.run(&args);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(out.stderr.is_empty(), "{out:?}");
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn audit_tail_filters_exact_records_without_changing_the_chain() {
    let f = Fixture::new();
    let request = uuid::Uuid::new_v4();
    let mut newest = AuditEvent::new(AuditEventKind::PolicyDenied)
        .with_request_id(request)
        .with_operation("synthetic.release")
        .with_outcome("denied")
        .with_detail("quartz policy refusal");
    newest.ts_utc_ms -= 10_000;
    let mut older = AuditEvent::new(AuditEventKind::OperationSucceeded)
        .with_operation("synthetic.observe")
        .with_outcome("ok");
    older.ts_utc_ms = newest.ts_utc_ms - 120_000;
    let path = database(&f, &[older.clone(), newest.clone()]);
    let before = fs::read(&path).unwrap();
    assert_eq!(rows(&f, &[]), vec![projected(&newest), projected(&older)]);
    assert_eq!(rows(&f, &["--limit", "1"]), vec![projected(&newest)]);
    assert_eq!(rows(&f, &["--limit", "0"]), Vec::<Value>::new());
    for options in [
        vec!["--kind", "policy.denied"],
        vec!["--operation", "synthetic.release"],
        vec!["--outcome", "denied"],
        vec!["--query", "quartz"],
        vec!["--since", "1m"],
    ] {
        assert_eq!(rows(&f, &options), vec![projected(&newest)], "{options:?}");
    }
    let request = request.to_string();
    assert_eq!(
        rows(&f, &["--request-id", &request, "--outcome", "denied"]),
        vec![projected(&newest)]
    );
    assert!(rows(&f, &["--request-id", &request, "--outcome", "ok"]).is_empty());
    assert!(rows(&f, &["--operation", "' OR 1=1 --"]).is_empty());
    for duration in ["180s", "3m", "1h", "1d", " 1d "] {
        assert_eq!(rows(&f, &["--since", duration]).len(), 2, "{duration}");
    }
    assert_eq!(rows(&f, &["--since", "9223372036854775s"]).len(), 2);
    assert!(rows(&f, &["--since", "0s"]).is_empty());
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(opaque_core::audit::verify_audit_chain(&path).unwrap().ok);
}

#[test]
fn audit_tail_human_rows_preserve_order_outcomes_and_limit_summary() {
    let f = Fixture::new();
    let mut events = Vec::new();
    let now = AuditEvent::new(AuditEventKind::RequestReceived).ts_utc_ms;
    for (age, outcome) in [
        (5_000, Some("ok")),
        (180_000, Some("denied")),
        (7_200_000, Some("pending")),
        (100_000_000, None),
        (200_000_000, Some("error")),
    ] {
        let mut event = AuditEvent::new(AuditEventKind::RequestReceived);
        event.ts_utc_ms = now - age;
        event.outcome = outcome.map(str::to_owned);
        events.push(event);
    }
    database(&f, &events);
    let all = f.ok(&["audit", "tail"]);
    for expected in [
        "5 event(s)",
        "3m ago",
        "2h ago",
        "yesterday",
        "2d ago",
        "unknown",
        "denied",
        "pending",
        "error",
        "Showing all 5",
    ] {
        assert!(all.contains(expected), "missing {expected}: {all}");
    }
    assert!(all.find("3m ago").unwrap() < all.find("2h ago").unwrap());
    let limited = f.ok(&["audit", "tail", "--limit", "2"]);
    assert!(
        limited.contains("Showing 2 of many events. Use --limit 12"),
        "{limited}"
    );
    assert!(!limited.contains("2h ago"), "{limited}");
}

#[test]
fn audit_tail_missing_empty_corrupt_and_invalid_filters_fail_explicitly() {
    let f = Fixture::new();
    for operation in ["tail", "verify"] {
        f.denied(&["audit", operation], "audit database not found");
    }
    assert!(!f.home.join(".opaque/audit.db").exists());
    let path = database(&f, &[]);
    assert!(rows(&f, &[]).is_empty());
    assert!(f.ok(&["audit", "tail"]).contains("No audit events found"));
    for (option, value, error) in [
        ("--kind", "not.an.event", "invalid --kind"),
        ("--request-id", "not-a-uuid", "invalid --request-id"),
        ("--query", "\"", "query failed"),
    ] {
        f.denied(&["audit", "tail", option, value], error);
    }
    let corrupt = b"synthetic corrupt SQLite audit database";
    fs::write(&path, corrupt).unwrap();
    f.denied(&["audit", "tail"], "query failed");
    f.denied(&["audit", "verify"], "failed to verify audit chain");
    assert_eq!(fs::read(path).unwrap(), corrupt);
}

#[test]
fn audit_since_rejects_malformed_unicode_negative_and_overflow_without_panicking() {
    let f = Fixture::new();
    let path = database(&f, &[]);
    let before = fs::read(&path).unwrap();
    for duration in [
        "",
        " ",
        "x",
        "1w",
        "é",
        "1💥",
        "-1s",
        "9223372036854776s",
        "9223372036854775807d",
        "999999999999999999999s",
    ] {
        let out = f.run(&["audit", "tail", &format!("--since={duration}")]);
        assert_eq!(out.status.code(), Some(1), "duration {duration:?}: {out:?}");
        let message = text(&out);
        assert!(message.contains("duration"), "{duration:?}: {message}");
        assert!(!message.contains("panicked"), "{message}");
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}

#[test]
fn audit_verify_human_failure_cannot_be_mistaken_for_an_intact_chain() {
    let f = Fixture::new();
    let event = AuditEvent::new(AuditEventKind::PolicyDenied).with_outcome("denied");
    let path = database(&f, &[event]);
    let valid = f.ok(&["audit", "verify"]);
    assert!(
        valid.contains("Audit chain intact") && valid.contains("1 records verified"),
        "{valid}"
    );
    let connection = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        connection
            .execute("UPDATE audit_events SET outcome = 'ok'", [])
            .unwrap(),
        1
    );
    drop(connection);
    let altered = fs::read(&path).unwrap();
    let out = f.run(&["audit", "verify"]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(text(&out).contains("Audit chain BROKEN"), "{out:?}");
    assert!(!text(&out).contains("chain intact"), "{out:?}");
    assert_eq!(fs::read(path).unwrap(), altered);
}
