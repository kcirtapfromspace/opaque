"""cargo-auditable embedding gate regressions, with `cargo audit` replaced by
a fake subprocess so no real toolchain is required for the core tests."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import release_artifacts as release
import verify_auditable_binary as verify


class VerifyAuditableBinaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="opaque-auditable-test-")
        self.addCleanup(temporary.cleanup)
        self.binary_dir = Path(temporary.name)
        for name in release.BINS:
            (self.binary_dir / name).write_bytes(b"not a real binary, just a fixture")

    def completed(self, returncode, stdout="", stderr=""):
        return subprocess.CompletedProcess(["cargo", "audit", "bin"], returncode, stdout=stdout, stderr=stderr)

    def test_every_release_binary_carries_embedded_data(self):
        report = '{"lockfile": {}, "vulnerabilities": {"found": false}}'
        with patch.object(verify.subprocess, "run", return_value=self.completed(0, stdout=report)) as run:
            results = [verify.check_binary(self.binary_dir / name) for name in release.BINS]
        self.assertTrue(all(ok for ok, _ in results), results)
        self.assertEqual(run.call_count, len(release.BINS))

    def test_missing_embedded_data_fails_even_with_nonzero_exit_and_no_json(self):
        # cargo-audit's exit code encodes "vulnerabilities found", not
        # "extraction succeeded" -- the gate must inspect the report, not trust returncode alone.
        with patch.object(verify.subprocess, "run",
                           return_value=self.completed(1, stdout="", stderr="No dependency information found in binary")):
            ok, message = verify.check_binary(self.binary_dir / "opaque")
        self.assertFalse(ok)
        self.assertIn("no embedded dependency manifest", message)
        self.assertIn("No dependency information found in binary", message)

    def test_reported_vulnerability_does_not_fail_the_provenance_gate(self):
        report = '{"lockfile": {}, "vulnerabilities": {"found": true, "count": 1}}'
        with patch.object(verify.subprocess, "run", return_value=self.completed(1, stdout=report)):
            ok, message = verify.check_binary(self.binary_dir / "opaque")
        self.assertTrue(ok)
        self.assertIn("1 known advisory", message)

    def test_missing_cargo_audit_tool_fails_with_install_hint(self):
        with patch.object(verify.subprocess, "run", side_effect=FileNotFoundError()):
            ok, message = verify.check_binary(self.binary_dir / "opaque")
        self.assertFalse(ok)
        self.assertIn("cargo install cargo-audit", message)

    def test_timeout_is_reported_not_raised(self):
        with patch.object(verify.subprocess, "run",
                           side_effect=subprocess.TimeoutExpired(cmd="cargo audit bin", timeout=120)):
            ok, message = verify.check_binary(self.binary_dir / "opaque")
        self.assertFalse(ok)
        self.assertIn("timed out", message)

    def test_missing_binary_file_fails_before_any_subprocess_call(self):
        with patch.object(verify.subprocess, "run") as run:
            ok, message = verify.check_binary(self.binary_dir / "does-not-exist")
        run.assert_not_called()
        self.assertFalse(ok)
        self.assertIn("no such file", message)

    def test_main_exits_nonzero_and_names_every_failing_binary(self):
        # main() reads argv directly; drive it the same way the release workflow does.
        argv = ["verify_auditable_binary.py", "--binary-dir", str(self.binary_dir),
                "--bin", "opaque", "--bin", "opaqued"]
        with patch.object(verify.sys, "argv", argv), \
             patch.object(verify.subprocess, "run", side_effect=FileNotFoundError()), \
             self.assertRaises(SystemExit) as raised:
            verify.main()
        self.assertEqual(raised.exception.code, 1)

    def test_main_succeeds_when_every_checked_binary_passes(self):
        report = '{"lockfile": {}, "vulnerabilities": {"found": false}}'
        argv = ["verify_auditable_binary.py", "--binary-dir", str(self.binary_dir),
                "--bin", "opaque"]
        with patch.object(verify.sys, "argv", argv), \
             patch.object(verify.subprocess, "run", return_value=self.completed(0, stdout=report)):
            verify.main()  # must not raise

    # Defined only when the real tools are present, instead of unittest.skipUnless,
    # so environments without them (e.g. the scripts/ suite in ci.yml, which treats
    # any unittest-reported skip as a failure) simply don't collect this test rather
    # than reporting a skip. It still exercises the real round trip once the release
    # workflow installs both cargo-auditable and cargo-audit.
    if shutil.which("cargo-auditable") and shutil.which("cargo-audit"):
        def test_real_cargo_auditable_binary_round_trips_through_cargo_audit(self):
            crate = self.binary_dir / "fixture-crate"
            subprocess.run(["cargo", "new", "--quiet", "--bin", str(crate)], check=True, capture_output=True)
            subprocess.run(["cargo", "auditable", "build", "--quiet", "--release"],
                            check=True, capture_output=True, cwd=crate)
            binary = crate / "target" / "release" / crate.name
            ok, message = verify.check_binary(binary)
            self.assertTrue(ok, message)


if __name__ == "__main__":
    unittest.main()
