#!/usr/bin/env python3
"""Deterministic observations over one strict audit export; never authorization."""
from __future__ import annotations

import argparse
from collections import Counter, OrderedDict
import hashlib
import json
import re
from pathlib import Path
import sys

from approval_metrics import attribution
from verify_audit_evidence import EvidenceError, HEX_SHA256, Snapshot, inspect_export, strict_json, valid_int

SCHEMA = "opaque.audit.anomalies.v1"
CAP = 8192
FINDING_ID = re.compile(r"[0-9a-f]{16}(?:-[0-9a-f]{16}){3}\Z")
RULES = {"approval_missing", "approval_lineage_mismatch", "action_lineage_mismatch", "audit_loss_recorded",
         "evidence_gap", "state_evicted", "restart_coverage_gap", "export_spool_failed",
         "export_webhook_failed", "export_syslog_failed"}


def recorded_finding(record):
    try:
        value = strict_json((record.get("detail") or "").encode())
        if (not isinstance(value, dict) or set(value) != {"schema", "id", "rule", "sequence", "related_sequence"}
                or value["schema"] != "opaque.anomaly.finding.v1" or value["rule"] not in RULES
                or not isinstance(value["id"], str) or not FINDING_ID.fullmatch(value["id"])
                or not valid_int(value["sequence"], 0)
                or value["related_sequence"] is not None and not valid_int(value["related_sequence"], 0)):
            return None
        return value
    except (EvidenceError, TypeError):
        return None


def finding(rule, record, related=None):
    identity = (f"opaque:anomaly:v1\0{rule}\0{record['sequence_number']}\0"
                f"{record['event_id']}\0{record.get('record_hash') or ''}\0"
                f"{related if related is not None else ''}")
    digest = hashlib.sha256(identity.encode()).hexdigest()
    return {"schema": "opaque.anomaly.finding.v1", "id": "-".join(digest[i:i+16] for i in range(0, 64, 16)),
            "rule": rule, "sequence": record["sequence_number"], "related_sequence": related}


def identifier(value):
    return value if isinstance(value, str) and 0 < len(value.encode()) <= 128 and not any(
        ord(c) < 32 or 127 <= ord(c) <= 159 for c in value) else None


def action(value):
    return value if isinstance(value, str) and HEX_SHA256.fullmatch(value) else None


def review_signals(records, clock_regressions):
    """Predefined descriptive signals, not fitted behavioral anomaly claims."""
    timestamps = [r["ts_utc_ms"] for r in records]
    duration = max(timestamps) - min(timestamps) if timestamps else 0
    valid_window = not clock_regressions and 60_000 <= duration <= 86_400_000
    grants = [r for r in records if r["kind"] == "approval.granted" and attribution(r) == "recorded_human"
              and type(r.get("latency_ms")) is int and r["latency_ms"] >= 0]
    denies = sum(r["kind"] == "policy.denied" for r in records)
    outcomes = denies + sum(r["kind"] == "operation.started" for r in records)
    signals = []
    for name, numerator, denominator, threshold in [
        ("fast_recorded_human_grants", sum(r["latency_ms"] < 2000 for r in grants), len(grants), 0.8),
        ("policy_denial_event_share", denies, outcomes, 0.5),
    ]:
        eligible = valid_window and denominator >= 30
        signals.append({"name": name, "numerator": numerator, "denominator": denominator,
                        "minimum_population": 30, "threshold": threshold,
                        "status": "descriptive_review_signal" if eligible and numerator / denominator >= threshold
                        else "below_configured_threshold" if eligible else "insufficient_observation",
                        "value": numerator / denominator if denominator else None})
    return {"clock": "recorded_timestamps_only", "clock_regressions": clock_regressions,
            "observed_span_ms": duration, "window_eligible": valid_window,
            "window_limits_ms": [60_000, 86_400_000], "signals": signals,
            "interpretation": "Fixed descriptive thresholds evaluated on labeled synthetic fixtures; not calibrated on customer populations, proof of malicious behavior, or fatigue detection. Events are not independent people or unique operations."}


def build_report(snapshot: Snapshot):
    pending = OrderedDict()
    health = Counter()
    findings = {}
    recorded = {}
    previous = None
    for record in snapshot.records:
        def add(rule, related=None):
            item = finding(rule, record, related)
            findings[item["id"]] = item
        if previous is None and (record["sequence_number"] > 0 or record["rowid"] > 1):
            health["prefix_unobserved"] += 1
        if previous and record["ts_utc_ms"] < previous["ts_utc_ms"]:
            health["clock_regressions"] += 1
        previous = record
        health["observed_records"] += 1
        kind = record["kind"]
        if kind == "audit.dropped":
            add("audit_loss_recorded")
        if kind == "audit.alert":
            health["recorded_alert_events"] += 1
            observed = recorded_finding(record)
            if observed:
                if observed["id"] in recorded and observed != recorded[observed["id"]]:
                    health["conflicting_recorded_finding_ids"] += 1
                else:
                    recorded[observed["id"]] = observed
            else:
                health["unparsed_alert_events"] += 1
        request = identifier(record.get("request_id"))
        if request is None:
            if kind in ("approval.required", "approval.granted", "operation.succeeded"):
                health["missing_request_identity"] += 1
            continue
        current_action = action(record.get("request_hash"))
        current_approval = identifier(record.get("approval_id"))
        if kind == "approval.required":
            pending.pop(request, None)
            if len(pending) == CAP:
                pending.popitem(last=False)
                health["capacity_evictions"] += 1
                add("state_evicted")
            if current_action is None or current_approval is None:
                health["missing_lineage"] += 1
            pending[request] = {"action": current_action, "approval": current_approval,
                                "sequence": record["sequence_number"], "granted": False, "indeterminate": False}
        elif kind in ("approval.granted", "lease.hit") and request in pending:
            state = pending[request]
            mismatch = any(a is not None and b is not None and a != b for a, b in
                           ((state["action"], current_action), (state["approval"], current_approval)))
            if mismatch:
                add("approval_lineage_mismatch", state["sequence"])
            elif current_action is not None and current_action == state["action"] and current_approval is not None and current_approval == state["approval"] and kind == "approval.granted":
                state["granted"] = True
            else:
                state["indeterminate"] = True
                health["missing_lineage"] += 1
        elif kind in ("operation.succeeded", "operation.failed"):
            state = pending.pop(request, None)
            if kind == "operation.succeeded":
                if state is None:
                    health["terminal_without_observed_requirement"] += 1
                elif state["action"] is None or current_action is None:
                    health["missing_lineage"] += 1
                elif state["action"] != current_action:
                    add("action_lineage_mismatch", state["sequence"])
                elif not state["granted"] and not state["indeterminate"] and state["approval"] is not None:
                    add("approval_missing", state["sequence"])
    for finding_id in recorded.keys() & findings.keys():
        if recorded[finding_id] == findings[finding_id]:
            health["corroborated_recorded_findings"] += 1
        else:
            health["conflicting_recorded_finding_ids"] += 1
    return {"schema": SCHEMA, "rules_version": 1, "input_evidence": snapshot.summary(),
            "scope": "observed_single_export_only", "findings": sorted(findings.values(), key=lambda f: (f["sequence"], f["rule"], f["id"])),
            "health": dict(sorted(health.items())), "pending_requirements": len(pending),
            "recorded_findings_not_recomputed": sorted((value for key, value in recorded.items() if key not in findings), key=lambda f: (f["sequence"], f["rule"], f["id"])),
            "recorded_findings_trust": "Producer assertions only; source lifecycle may fall outside this export. No producer signature is verified.",
            "coverage": {"prefix_and_tail": "unknown", "producer_identity": "unverified",
                         "approval_signatures": "not_verified", "outside_broker_activity": "unobserved",
                         "global_completeness": False,
                         "lifecycle": "Only fully observed, matching lineage can establish a contradiction; missing lineage and unmatched terminal events are unknown."},
            "review_signals": review_signals(snapshot.records, health["clock_regressions"])}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path)
    args = parser.parse_args(argv)
    try:
        report = build_report(inspect_export(args.export))
    except (EvidenceError, OSError, ValueError, RecursionError):
        print(json.dumps({"ok": False, "error": "invalid_anomaly_evidence"}))
        return 2
    print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
