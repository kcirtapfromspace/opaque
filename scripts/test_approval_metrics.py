"""Descriptive metrics regressions: never convert missing evidence into assurance."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import approval_metrics as metrics


def event(kind="approval.granted", source="paired_workstation", latency=1000, operation="ssh.service_health"):
    return {"kind": kind, "operation": operation, "latency_ms": latency,
            "approver_json": json.dumps({"source": source, "principal_id": "hum_private-person",
                                         "label": "private-person@example.test"})}


class ApprovalMetricsTests(unittest.TestCase):
    def test_empty_denominators_are_unknown_and_not_zero_compliance(self):
        report = metrics.build_report([])
        self.assertIsNone(report["total"]["recorded_human_share_of_grants"]["value"])
        self.assertIsNone(report["total"]["fast_human_approval_share"]["wilson_95"])
        self.assertFalse(report["evidence_health"]["global_completeness_verified"])
        self.assertIn("out_of_policy_execution_rate", report["unavailable_metrics"])

    def test_test_automation_missing_identity_and_unknown_sources_never_count_as_humans(self):
        malformed = event()
        malformed["approver_json"] = "[]"
        absent_principal = event()
        absent_principal["approver_json"] = '{"source":"paired_workstation"}'
        report = metrics.build_report([event(), event(source="insecure_auto_approve"),
                                       event(source="future_source"), malformed, absent_principal])
        self.assertEqual(report["total"]["grants_recorded_human"], 1)
        self.assertEqual(report["total"]["grants_test_automation"], 1)
        self.assertEqual(report["total"]["grants_unknown_attribution"], 3)
        self.assertEqual(report["total"]["recorded_human_share_of_grants"]["value"], 0.2)

    def test_latency_threshold_is_exclusive_and_excludes_unknown_and_machine_latencies(self):
        records = [event(latency=value) for value in (0, 1999, 2000, 10000, None, -1, True)]
        records += [event(source="insecure_auto_approve", latency=1)]
        report = metrics.build_report(records)
        latency = report["total"]["human_approval_latency_ms"]
        self.assertEqual(latency, {"observed": 4, "missing_or_invalid": 3,
                                   "median": 1999.5, "p95_nearest_rank": 10000})
        self.assertEqual(report["total"]["fast_human_approval_share"]["value"], 0.5)

    def test_no_names_targets_raw_operation_or_unknown_kind_in_report(self):
        record = event(operation="private_customer.secret")
        record["target_json"] = '{"host":"private-host"}'
        report = metrics.build_report([record, event(kind="private-kind")])
        serialized = json.dumps(report)
        for private in ("private-person", "private_customer", "private-host", "private-kind"):
            self.assertNotIn(private, serialized)
        self.assertEqual(set(report["by_operation_family"]), {"other", "ssh"})

    def test_events_are_not_promoted_to_operations_or_compliance(self):
        report = metrics.build_report([event(kind="operation.succeeded"), event(kind="audit.dropped"),
                                       event(kind="audit.alert"), event(kind="lease.hit")])
        self.assertEqual(report["total"]["operation_success_events"], 1)
        self.assertEqual(report["total"]["grants_recorded_human"], 0)
        self.assertEqual(report["total"]["lease_reuse_events"], 1)
        self.assertEqual(report["evidence_health"]["audit_dropped_events"], 1)
        self.assertEqual(report["evidence_health"]["audit_alert_events"], 1)

    def test_wilson_reference_bounds_and_small_samples(self):
        interval = metrics.proportion(0, 10)["wilson_95"]
        self.assertAlmostEqual(interval[0], 0)
        self.assertAlmostEqual(interval[1], 0.2775328, places=6)
        interval = metrics.proportion(10, 10)["wilson_95"]
        self.assertAlmostEqual(interval[0], 0.7224672, places=6)
        self.assertAlmostEqual(interval[1], 1)

    def test_cli_invalid_input_emits_no_private_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input.jsonl"
            path.write_text('private-session-content\n')
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(metrics.main([str(path)]), 1)
            self.assertEqual(out.getvalue(), "")
            self.assertNotIn("private-session-content", err.getvalue())

    def test_duplicate_attribution_keys_remain_unknown(self):
        record = event()
        record["approver_json"] = ('{"principal_id":"hum_x", "source":"insecure_auto_approve",'
                                    '"source":"paired_workstation"}')
        self.assertEqual(metrics.build_report([record])["total"]["grants_unknown_attribution"], 1)

    def test_cli_deduplicates_production_format_and_binds_the_input_digest(self):
        record = {**event(), "schema": "opaque.audit.v1", "event_id": "00000000-0000-4000-8000-000000000001",
                  "rowid": 5, "sequence_number": 4, "ts_utc_ms": 100, "level": "info", "record_hash": "a" * 64}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "export.jsonl"
            path.write_text((json.dumps(record) + "\n") * 2)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(metrics.main([str(path)]), 0)
            report = json.loads(out.getvalue())
            self.assertEqual(report["total"]["approval_grant_events"], 1)
            self.assertEqual(report["input_evidence"]["duplicate_count"], 1)
            self.assertEqual(report["input_evidence"]["first_sequence"], 4)
            self.assertEqual(len(report["input_evidence"]["export_sha256"]), 64)
            self.assertNotIn("private-person", out.getvalue())

    def test_invalid_thresholds_fail(self):
        for threshold in (0, -1, True, 3_600_001):
            with self.assertRaises(ValueError):
                metrics.build_report([], threshold)


if __name__ == "__main__":
    unittest.main()
