#!/usr/bin/env python3
"""Offline, descriptive approval metrics over a single broker's SIEM export.

Never authorizes work. Attribution is reported as recorded, not independently
authenticated. No request payloads, targets, approver names or IDs are emitted.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
import math
from pathlib import Path
import re
import statistics
import sys

from verify_audit_evidence import EvidenceError, inspect_export, strict_json

HUMAN_SOURCES = frozenset({
    "local_bio_session", "paired_device", "paired_workstation", "fido2", "polkit_account",
})
FAMILIES = frozenset({
    "github", "gitlab", "aws", "onepassword", "bitwarden", "vault", "ssh",
    "inference", "sandbox", "mcp", "test", "task",
})


def proportion(numerator: int, denominator: int) -> dict:
    """Wilson score interval, z=1.959963984540054 (two-sided nominal 95%)."""
    if denominator == 0:
        return {"numerator": numerator, "denominator": 0, "value": None,
                "wilson_95": None}
    p = numerator / denominator
    z = 1.959963984540054
    scale = 1 + z * z / denominator
    center = (p + z * z / (2 * denominator)) / scale
    half = z * math.sqrt(p * (1 - p) / denominator + z * z / (4 * denominator**2)) / scale
    return {"numerator": numerator, "denominator": denominator, "value": p,
            "wilson_95": [max(0.0, center - half), min(1.0, center + half)]}


def attribution(record: dict) -> str:
    raw = record.get("approver_json")
    if not isinstance(raw, str):
        return "unknown"
    try:
        value = strict_json(raw.encode("utf-8"))
    except (ValueError, UnicodeError, RecursionError):
        return "unknown"
    if not isinstance(value, dict):
        return "unknown"
    principal = value.get("principal_id")
    if not isinstance(principal, str) or not principal.strip():
        return "unknown"
    source = value.get("source")
    if isinstance(source, str) and source in HUMAN_SOURCES:
        return "recorded_human"
    if source == "insecure_auto_approve":
        return "test_automation"
    return "unknown"


def family(record: dict) -> str:
    # Only known family labels leave this process. A malicious operation name
    # must not turn a report intended for forwarding into a metadata leak.
    operation = record.get("operation")
    if not isinstance(operation, str) or not re.fullmatch(r"[a-z][a-z0-9_]*\.[a-z0-9_.]+", operation):
        return "other"
    prefix = operation.split(".", 1)[0]
    return prefix if prefix in FAMILIES else "other"


def summarize(records: list[dict], fast_threshold_ms: int) -> dict:
    counts = Counter(record["kind"] for record in records)
    grants = [record for record in records if record["kind"] == "approval.granted"]
    identities = Counter(attribution(record) for record in grants)
    human = [record for record in grants if attribution(record) == "recorded_human"]
    latencies = sorted(record["latency_ms"] for record in human
                       if type(record.get("latency_ms")) is int and record["latency_ms"] >= 0)
    fast = sum(latency < fast_threshold_ms for latency in latencies)
    return {
        "events": len(records),
        "operation_success_events": counts["operation.succeeded"],
        "operation_failure_events": counts["operation.failed"],
        "policy_denial_events": counts["policy.denied"],
        "approval_grant_events": len(grants),
        "approval_denial_events": counts["approval.denied"],
        "lease_reuse_events": counts["lease.hit"],
        "grants_recorded_human": identities["recorded_human"],
        "grants_test_automation": identities["test_automation"],
        "grants_unknown_attribution": identities["unknown"],
        "recorded_human_share_of_grants": proportion(identities["recorded_human"], len(grants)),
        "human_approval_latency_ms": {
            "observed": len(latencies),
            "missing_or_invalid": len(human) - len(latencies),
            "median": statistics.median(latencies) if latencies else None,
            "p95_nearest_rank": latencies[math.ceil(0.95 * len(latencies)) - 1] if latencies else None,
        },
        "fast_human_approval_share": {
            **proportion(fast, len(latencies)),
            "threshold_ms_exclusive": fast_threshold_ms,
        },
    }


def build_report(records: list[dict], fast_threshold_ms: int = 2000) -> dict:
    if type(fast_threshold_ms) is not int or not 1 <= fast_threshold_ms <= 3_600_000:
        raise ValueError("fast threshold must be 1..3600000 milliseconds")
    grouped: dict[str, list[dict]] = {}
    for record in records:
        grouped.setdefault(family(record), []).append(record)
    counts = Counter(record["kind"] for record in records)
    return {
        "schema": "opaque.approval-metrics.v1",
        "scope": "observed_export_events_only",
        "total": summarize(records, fast_threshold_ms),
        "by_operation_family": {key: summarize(value, fast_threshold_ms)
                                for key, value in sorted(grouped.items())},
        "evidence_health": {
            "audit_dropped_events": counts["audit.dropped"],
            "audit_alert_events": counts["audit.alert"],
            "producer_hmac_verified": False,
            "global_completeness_verified": False,
        },
        "unavailable_metrics": {
            "out_of_policy_execution_rate": "requires canonical action, effective policy and dispatch lineage",
            "sensitive_operations_human_approved_share": "requires authoritative sensitivity and grant-to-effect lineage",
            "retrospective_validation_share": "no retrospective review records in opaque.audit.v1",
            "inter_approver_agreement": "requires independently reassigned reviews of the same operation",
        },
        "interpretation": [
            "Counts are unique exported events, not unique operations or people; denial events can repeat per request.",
            "Recorded human attribution trusts the producer record; this report verifies no approval signature.",
            "Fast approvals are a review signal, not proof of fatigue or inadequate review; queue and human time differ.",
            "Wilson intervals assume independent Bernoulli observations; correlated approvals are descriptive only.",
            "Missing data is unknown. No alerts or denials does not establish compliant or complete execution.",
            "Snapshots from multiple brokers must be reported separately; v1 exports contain no broker identity.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path, help="single-broker opaque.audit.v1 JSONL export")
    parser.add_argument("--fast-threshold-ms", type=int, default=2000)
    args = parser.parse_args(argv)
    try:
        snapshot = inspect_export(args.export)
        report = build_report(list(snapshot.records), args.fast_threshold_ms)
        report["input_evidence"] = snapshot.summary()
    except (EvidenceError, OSError, ValueError, RecursionError):
        # Raw exception messages may include sensitive input or filesystem paths.
        print(json.dumps({"ok": False, "error": "invalid_export_or_metrics_options"}), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
