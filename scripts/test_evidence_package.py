"""Artifact identity, semantic reproduction, privacy boundaries and bounded IO."""
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import evidence_package as package
from test_audit_anomalies import records
from verify_audit_evidence import EvidenceError


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.export = self.root / "export.jsonl"
        self.export.write_text("".join(json.dumps(r) + "\n" for r in records([
            {"kind": "approval.required"}, {"kind": "operation.succeeded"}])))

    def tearDown(self):
        self.temporary.cleanup()

    def create(self, name="package"):
        path = self.root / name
        result = package.create_package(self.export, path, "fixture-broker")
        return path, result

    def refresh_entry(self, directory, name):
        manifest = json.loads((directory / "manifest.json").read_text())
        raw = (directory / name).read_bytes()
        manifest["artifacts"][name] = {"sha256": package.digest(raw), "bytes": len(raw)}
        (directory / "manifest.json").write_bytes(package.encoded(manifest))

    def test_reproducible_regular_restricted_allowlist_and_external_pin(self):
        first, created = self.create()
        second, again = self.create("second")
        self.assertEqual(created, again)
        self.assertEqual({p.name for p in first.iterdir()}, set(package.ARTIFACTS) | {"manifest.json"})
        self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o700)
        for path in first.iterdir():
            self.assertEqual(path.read_bytes(), (second / path.name).read_bytes())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        report = package.verify_package(first, created["manifest_sha256"])
        self.assertEqual(report["reports"], "reproduced_exactly")
        self.assertEqual(report["producer_authenticity"], "unverified")
        self.assertEqual(report["global_completeness"], "unknown")
        with self.assertRaises(EvidenceError):
            package.verify_package(first, "0" * 64)

    def test_every_artifact_change_is_rejected(self):
        directory, _ = self.create()
        for name in package.ARTIFACTS:
            path = directory / name
            original = path.read_bytes()
            path.write_bytes(original + b" ")
            with self.subTest(name=name), self.assertRaises(EvidenceError):
                package.verify_package(directory)
            path.write_bytes(original)

    def test_mixed_report_rejected_even_after_manifest_hash_updated(self):
        directory, _ = self.create()
        report = json.loads((directory / "metrics.json").read_text())
        report["input_evidence"]["export_sha256"] = "d" * 64
        (directory / "metrics.json").write_bytes(package.encoded(report))
        self.refresh_entry(directory, "metrics.json")
        with self.assertRaisesRegex(EvidenceError, "reproduction"):
            package.verify_package(directory)

    def test_fabricated_control_or_coverage_claim_rejected_with_updated_hash(self):
        for name in ("controls.json", "coverage.json", "anomalies.json"):
            directory, _ = self.create(name)
            report = json.loads((directory / name).read_text())
            report["certified"] = True
            (directory / name).write_bytes(package.encoded(report))
            self.refresh_entry(directory, name)
            with self.assertRaises(EvidenceError):
                package.verify_package(directory)

    def test_substituted_checkpoint_fails_without_supplying_any_key(self):
        directory, _ = self.create()
        value = json.loads((directory / "checkpoint.json").read_text())
        value["source_id"] = "other-broker"
        (directory / "checkpoint.json").write_bytes(package.encoded(value))
        self.refresh_entry(directory, "checkpoint.json")
        with self.assertRaises(EvidenceError):
            package.verify_package(directory)

    def test_extra_key_session_config_and_directory_are_not_packaged(self):
        directory, _ = self.create()
        for name in ("audit.key", "private.pem", ".env", "session.json", "extra"):
            path = directory / name
            path.write_text("fixture-not-a-real-secret")
            with self.assertRaises(EvidenceError):
                package.verify_package(directory)
            path.unlink()
        (directory / "extra").mkdir()
        with self.assertRaises(EvidenceError):
            package.verify_package(directory)

    def test_retained_range_empty_and_duplicate_delivery_remain_honest(self):
        for index, rows in enumerate(([], records([{"kind": "operation.succeeded", "rowid": 51, "sequence_number": 50}]))):
            self.export.write_text("".join(json.dumps(r) + "\n" for r in rows * 2))
            directory, _ = self.create(str(index))
            package.verify_package(directory)
            metrics = json.loads((directory / "metrics.json").read_text())
            self.assertIsNone(metrics["total"]["recorded_human_share_of_grants"]["value"])
            self.assertEqual(metrics["input_evidence"]["duplicate_count"], len(rows))
            self.assertEqual(json.loads((directory / "anomalies.json").read_text())["findings"], [])

    def test_nonregular_symlink_size_and_malformed_inputs_fail_before_output(self):
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        link = self.root / "link"
        link.symlink_to(self.export)
        for source in (fifo, link, self.root):
            with self.assertRaises((OSError, EvidenceError)):
                package.create_package(source, self.root / "bad", "fixture")
            self.assertFalse((self.root / "bad").exists())
        with patch.object(package, "MAX_EXPORT_BYTES", 1), self.assertRaises(EvidenceError):
            package.create_package(self.export, self.root / "bad", "fixture")
        self.export.write_text("bad-input-with-sensitive-text")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(package.main(["create", str(self.export), "--source-id", "fixture", "--output", str(self.root / "bad")]), 2)
        self.assertNotIn("sensitive", output.getvalue())
        self.assertFalse((self.root / "bad").exists())

    def test_package_member_symlink_or_fifo_rejected(self):
        directory, _ = self.create()
        path = directory / "metrics.json"
        backup = self.root / "backup"
        path.rename(backup)
        path.symlink_to(backup)
        with self.assertRaises((EvidenceError, OSError)):
            package.verify_package(directory)
        path.unlink()
        os.mkfifo(path)
        with self.assertRaises(EvidenceError):
            package.verify_package(directory)

    def test_no_overwrite_and_source_snapshot_is_read_once(self):
        directory, _ = self.create()
        before = (directory / "manifest.json").read_bytes()
        with self.assertRaises(FileExistsError):
            package.create_package(self.export, directory, "fixture")
        self.assertEqual(before, (directory / "manifest.json").read_bytes())
        real = package.read_bounded
        def capture(path, limit):
            raw = real(path, limit)
            if path == self.export:
                self.export.write_text("changed-after-snapshot")
            return raw
        with patch.object(package, "read_bounded", capture):
            new, _ = self.create("snapshot")
            package.verify_package(new)


if __name__ == "__main__":
    unittest.main()
