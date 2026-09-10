"""Shared lifecycle corpus plus labeled descriptive-signal evaluation."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import audit_anomalies as anomalies
from verify_audit_evidence import Snapshot, inspect_export


def records(events):
    return [{"schema": "opaque.audit.v1", "event_id": f"event-{index}", "rowid": index + 1,
             "sequence_number": index, "ts_utc_ms": index * 3000, "kind": "request.received", "level": "info",
             "record_hash": "c" * 64, "request_hash": "a" * 64, "request_id": "private-request",
             "approval_id": "round", **event} for index, event in enumerate(events)]


def snapshot(events):
    rows = records(events)
    return Snapshot(tuple(rows), hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest(), len(rows))


class AnomalyTests(unittest.TestCase):
    def test_shared_lifecycle_corpus(self):
        path = Path(__file__).parent.parent / "crates/opaque-federation-runtime/tests/fixtures/anomaly_lifecycle_v1.json"
        for case in json.loads(path.read_text()):
            with self.subTest(case=case["name"]):
                report = anomalies.build_report(snapshot(case["events"]))
                self.assertEqual([f["rule"] for f in report["findings"]], case["rules"])
                self.assertEqual(report["pending_requirements"], case["pending"])
                for name, count in case.get("health", {}).items():
                    self.assertEqual(report["health"][name], count)

    def test_capacity_is_visible_and_terminal_cleanup_prevents_eviction(self):
        with patch.object(anomalies, "CAP", 2):
            report = anomalies.build_report(snapshot([{"kind": "approval.required", "request_id": f"req-{n}"} for n in range(3)]))
            self.assertEqual(report["health"]["capacity_evictions"], 1)
            self.assertEqual([f["rule"] for f in report["findings"]], ["state_evicted"])
            events = [event for n in range(3) for event in
                      ({"kind": "approval.required", "request_id": f"req-{n}"},
                       {"kind": "operation.failed", "request_id": f"req-{n}"})]
            self.assertEqual(anomalies.build_report(snapshot(events))["findings"], [])

    def test_retries_deduplicate_and_ids_are_deterministic_private(self):
        rows = records([{"kind": "approval.required"}, {"kind": "operation.succeeded"}])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "audit.jsonl"
            path.write_text("".join(json.dumps(row) + "\n" for row in rows + rows[:1]))
            report = anomalies.build_report(inspect_export(path))
            self.assertEqual(len(report["findings"]), 1)
            self.assertEqual(report, anomalies.build_report(inspect_export(path)))
            self.assertNotIn("private-request", json.dumps(report))
            self.assertEqual(report["input_evidence"]["duplicate_count"], 1)

    def test_labeled_review_signal_scenarios(self):
        # Labels describe expected review triage, not maliciousness. Fast routine
        # approvals deliberately trigger the same descriptive signal as hasty ones.
        for label, latency, count, clock_regression, expected in [
            ("routine_fast_work", 500, 30, False, "descriptive_review_signal"),
            ("deliberate_review", 5000, 30, False, "below_configured_threshold"),
            ("small_population", 500, 10, False, "insufficient_observation"),
            ("unreliable_clock", 500, 30, True, "insufficient_observation"),
        ]:
            events = [{"kind": "approval.granted", "latency_ms": latency,
                       "approver_json": '{"source":"paired_workstation","principal_id":"fixture-human"}'} for _ in range(count)]
            if clock_regression:
                events[-1]["ts_utc_ms"] = 0
            report = anomalies.build_report(snapshot(events))
            with self.subTest(label=label):
                self.assertEqual(report["review_signals"]["signals"][0]["status"], expected)
                self.assertEqual(report["findings"], [])
        for denies, expected in [(20, "descriptive_review_signal"), (5, "below_configured_threshold")]:
            report = anomalies.build_report(snapshot([{"kind": "policy.denied" if n < denies else "operation.started"} for n in range(30)]))
            self.assertEqual(report["review_signals"]["signals"][1]["status"], expected)

    def test_partial_retained_range_never_claims_global_completeness(self):
        report = anomalies.build_report(snapshot([{"kind": "operation.succeeded", "sequence_number": 99, "rowid": 100}]))
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["health"]["prefix_unobserved"], 1)
        self.assertFalse(report["coverage"]["global_completeness"])

    def test_recorded_alerts_are_deduplicated_and_separate_from_recomputed_evidence(self):
        source = snapshot([{"kind":"approval.required"},{"kind":"operation.succeeded"}])
        found = anomalies.build_report(source)["findings"][0]
        events = [{"kind":"approval.required"},{"kind":"operation.succeeded"},
                  {"kind":"audit.alert","detail":json.dumps(found)},
                  {"kind":"audit.alert","detail":json.dumps(found)}]
        report = anomalies.build_report(snapshot(events))
        self.assertEqual(len(report["findings"]),1)
        self.assertEqual(report["recorded_findings_not_recomputed"],[])
        self.assertEqual(report["health"]["corroborated_recorded_findings"],1)
        partial = anomalies.build_report(snapshot(events[2:]))
        self.assertEqual(partial["findings"],[])
        self.assertEqual(len(partial["recorded_findings_not_recomputed"]),1)
        malformed = {**found,"rule":"private-unknown-rule"}
        report = anomalies.build_report(snapshot([{"kind":"audit.alert","detail":json.dumps(malformed)}]))
        self.assertEqual(report["recorded_findings_not_recomputed"],[])
        self.assertNotIn("private-unknown-rule",json.dumps(report))


if __name__ == "__main__":
    unittest.main()
