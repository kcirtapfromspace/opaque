"""Adversarial offline export checks using only synthetic metadata."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from verify_audit_evidence import (
    EvidenceError, checkpoint_document, inspect_export, iter_export_records,
    verify_export,
)


SCRIPT = Path(__file__).with_name("verify_audit_evidence.py")


def records():
    return [{"schema": "opaque.audit.v1", "rowid": index + 1,
             "event_id": f"synthetic-event-{index}", "sequence_number": index,
             "ts_utc_ms": 1000 + index, "level": "info",
             "kind": kind, "request_id": "synthetic-request",
             "operation": "test.noop", "record_hash": hashlib.sha256(f"synthetic-{index}".encode()).hexdigest()}
            for index, kind in enumerate(("request.received", "approval.required", "approval.granted", "operation.succeeded"))]


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.export = self.directory / "export.jsonl"
        self.checkpoint = self.directory / "checkpoint.json"
        self.write(records())

    def write(self, rows, path=None):
        target = path or self.export
        target.write_bytes(b"".join((json.dumps(row) + "\n").encode() for row in rows))

    def anchor(self):
        document = checkpoint_document(inspect_export(self.export), "synthetic/source")
        raw = json.dumps(document).encode()
        self.checkpoint.write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def assertRejected(self, error, **kwargs):
        with self.assertRaisesRegex(EvidenceError, error):
            verify_export(self.export, **kwargs)

    def test_unanchored_success_explicitly_denies_stronger_claims(self):
        result = verify_export(self.export)
        self.assertEqual(result["record_count"], 4)
        self.assertEqual(result["structure"], "verified")
        self.assertEqual(result["export_integrity"], "unverified")
        self.assertEqual(result["audit_hmac"], "not_verified")
        self.assertEqual(result["cryptographic_chain_linkage"], "not_verified")
        self.assertEqual(result["global_completeness"], "not_proven")

    def test_anchor_binds_exact_range_but_never_authenticates_producer(self):
        pin = self.anchor()
        result = verify_export(self.export, self.checkpoint, pin)
        self.assertEqual(result["completeness"], "externally_pinned_export_range_verified")
        self.assertEqual(result["export_integrity"], "matches_externally_pinned_checkpoint")
        self.assertEqual(result["producer_identity"], "unverified")
        self.assertEqual(result["audit_hmac"], "not_verified")

    def test_untrusted_matching_manifest_is_not_an_anchor(self):
        self.anchor()
        result = verify_export(self.export, self.checkpoint)
        self.assertEqual(result["checkpoint"], "matched")
        self.assertEqual(result["export_integrity"], "unverified")
        self.assertEqual(result["completeness"], "unanchored_observed_range_only")

    def test_edited_payload_with_unchanged_hmac_is_detected_by_anchor(self):
        pin = self.anchor()
        rows = records()
        rows[3]["outcome"] = "forged-success"
        self.write(rows)
        self.assertRejected("checkpoint_export_mismatch", checkpoint=self.checkpoint,
                            trusted_checkpoint_sha256=pin)
        # V1 public HMAC values cannot alone authenticate changed event fields.
        self.assertEqual(verify_export(self.export)["audit_hmac"], "not_verified")

    def test_prefix_tail_and_empty_truncations_are_detected_by_anchor(self):
        pin = self.anchor()
        for rows in (records()[1:], records()[:-1], []):
            with self.subTest(count=len(rows)):
                self.write(rows)
                self.assertRejected("checkpoint_export_mismatch", checkpoint=self.checkpoint,
                                    trusted_checkpoint_sha256=pin)
                self.assertEqual(verify_export(self.export)["global_completeness"], "not_proven")

    def test_regenerated_checkpoint_cannot_replace_external_pin(self):
        pin = self.anchor()
        self.write(records()[:-1])
        self.anchor()
        self.assertRejected("checkpoint_pin_mismatch", checkpoint=self.checkpoint,
                            trusted_checkpoint_sha256=pin)

    def test_interior_sequence_or_rowid_gap_is_rejected_without_anchor(self):
        self.write(records()[:1] + records()[2:])
        self.assertRejected("interior_record_gap")
        rows = records()
        rows[-1]["rowid"] += 1
        self.write(rows)
        self.assertRejected("interior_record_gap")

    def test_reordering_is_rejected_but_exact_old_retries_are_deduplicated(self):
        rows = records()
        self.write(rows[:3] + [rows[0], rows[1]] + rows[3:] + rows)
        result = verify_export(self.export)
        self.assertEqual((result["record_count"], result["delivery_count"], result["duplicate_count"]), (4, 10, 6))
        self.write([rows[1], rows[0]])
        self.assertRejected("record_order_regression")

    def test_duplicate_sequence_payload_hash_or_event_id_conflict_is_rejected(self):
        for field, value in (("record_hash", "f" * 64), ("detail", "forged"), ("event_id", "other")):
            with self.subTest(field=field):
                rows = records()
                retry = copy.deepcopy(rows[0])
                retry[field] = value
                self.write(rows + [retry])
                self.assertRejected("conflicting_duplicate_sequence")
        rows = records()
        rows[-1]["event_id"] = rows[0]["event_id"]
        self.write(rows)
        self.assertRejected("conflicting_duplicate_event_id")

    def test_same_range_reference_compares_full_normalized_fields_and_hashes(self):
        reference = self.directory / "reference.jsonl"
        rows = records()
        rows[0]["detail"] = None  # absent and null are the same optional SQL column
        self.write(rows + rows[:2], reference)
        result = verify_export(self.export, reference=reference)
        self.assertEqual(result["cross_check"]["status"], "matched")
        rows[2]["outcome"] = "different"
        self.write(rows, reference)
        self.assertRejected("reference_record_mismatch", reference=reference)
        self.write(records()[:-1], reference)
        self.assertRejected("reference_range_mismatch", reference=reference)

    def test_cross_check_does_not_upgrade_two_untrusted_exports(self):
        reference = self.directory / "reference.jsonl"
        self.write(records(), reference)
        result = verify_export(self.export, reference=reference)
        self.assertEqual(result["export_integrity"], "unverified")

    def test_partial_lifecycle_and_retained_prefix_are_valid_structural_ranges(self):
        self.write(records()[3:])
        result = verify_export(self.export)
        self.assertEqual(result["first_sequence"], 3)
        self.assertTrue(result["ok"])

    def test_clock_regression_is_valid(self):
        rows = records()
        rows[2]["ts_utc_ms"] = -500
        self.write(rows)
        self.assertTrue(verify_export(self.export)["ok"])

    def test_strict_json_rejects_duplicates_nonfinite_surrogates_and_incomplete_framing(self):
        for raw in (b'{"schema":1,"schema":2}\n', b'{"schema":NaN}\n', b'{"schema":1e999}\n', b'\xff\n', b'{}', b'\n'):
            with self.subTest(raw=raw), self.assertRaises(EvidenceError):
                self.export.write_bytes(raw)
                inspect_export(self.export)
        rows = records()
        rows[0]["detail"] = "\ud800"
        self.write(rows)
        self.assertRejected("invalid_record_unicode")

    def test_schema_types_unknown_fields_and_hash_shape_fail_closed(self):
        for field, value in (("rowid", True), ("sequence_number", -1), ("ts_utc_ms", 1.1),
                             ("record_hash", None), ("record_hash", "X" * 64),
                             ("operation", []), ("latency_ms", False),
                             ("schema", "opaque.audit.v2"), ("new_field", "unknown")):
            with self.subTest(field=field, value=value), self.assertRaises(EvidenceError):
                rows = records()
                rows[0][field] = value
                self.write(rows)
                inspect_export(self.export)

    def test_resource_bounds_are_enforced(self):
        for setting, value in (("MAX_EXPORT_BYTES", 10), ("MAX_LINE_BYTES", 10), ("MAX_LINES", 2)):
            with self.subTest(setting=setting), patch("verify_audit_evidence." + setting, value):
                self.assertRejected("export_resource_limit")

    def test_checkpoint_metadata_is_checked_even_if_its_digest_is_trusted(self):
        self.anchor()
        document = json.loads(self.checkpoint.read_bytes())
        document["record_count"] = 9
        raw = json.dumps(document).encode()
        self.checkpoint.write_bytes(raw)
        self.assertRejected("checkpoint_export_mismatch", checkpoint=self.checkpoint,
                            trusted_checkpoint_sha256=hashlib.sha256(raw).hexdigest())

    def test_public_parser_normalizes_optional_fields_without_deduplication(self):
        self.write(records() + records())
        self.assertEqual(len(list(iter_export_records(self.export))), 8)
        snapshot = inspect_export(self.export)
        self.assertEqual(len(snapshot.records), 4)
        self.assertIsNone(snapshot.records[0]["approver_json"])

    def run_cli(self, *args):
        output = subprocess.run([sys.executable, "-B", str(SCRIPT), *map(str, args)],
                                capture_output=True, timeout=10, check=False)
        self.assertEqual(output.stderr, b"")
        return output.returncode, json.loads(output.stdout)

    def test_real_cli_roundtrip_private_exclusive_checkpoint_and_tamper_failure(self):
        code, created = self.run_cli("checkpoint", self.export, "--source-id", "fixture", "--output", self.checkpoint)
        self.assertEqual(code, 0)
        self.assertEqual(created["checkpoint"], "created_unsigned")
        self.assertEqual(self.checkpoint.stat().st_mode & 0o777, 0o600)
        pin = created["checkpoint_sha256"]
        code, verified = self.run_cli("verify", self.export, "--checkpoint", self.checkpoint,
                                      "--trusted-checkpoint-sha256", pin)
        self.assertEqual(code, 0)
        self.assertTrue(verified["ok"])
        code, error = self.run_cli("checkpoint", self.export, "--source-id", "fixture", "--output", self.checkpoint)
        self.assertEqual((code, error["error"]), (2, "evidence_io_error"))
        self.write(records()[:-1])
        code, error = self.run_cli("verify", self.export, "--checkpoint", self.checkpoint,
                                   "--trusted-checkpoint-sha256", pin)
        self.assertEqual((code, error["error"]), (2, "checkpoint_export_mismatch"))

    def test_cli_errors_never_echo_sensitive_input_or_paths(self):
        secret_path = self.directory / "PRIVATE-PATH-SENTINEL.jsonl"
        secret_path.write_bytes(b'{"PRIVATE-ROW-SENTINEL":NaN}\n')
        code, result = self.run_cli("verify", secret_path)
        self.assertEqual(code, 2)
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_nonregular_inputs_fail_without_waiting(self):
        fifo = self.directory / "input.fifo"
        os.mkfifo(fifo)
        for args in (("verify", fifo), ("verify", self.directory),
                     ("verify", self.export, "--checkpoint", fifo)):
            with self.subTest(args=args):
                code, result = self.run_cli(*args)
                self.assertEqual((code, result["error"]), (2, "not_regular_evidence_file"))


if __name__ == "__main__":
    unittest.main()
