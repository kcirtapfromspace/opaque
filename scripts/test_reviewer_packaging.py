"""Portable packaging contract tests. No native UI, registration or Keychain."""
import importlib.util
import os
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("reviewer_packaging", Path(__file__).with_name("package-reviewer-macos.py"))
PACKAGING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGING)
ROOT = Path(__file__).resolve().parent.parent


class ReviewerPackageTests(unittest.TestCase):
    def test_bundle_layout_and_sign_order_use_fixed_executables(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            binaries = base / "binaries"
            binaries.mkdir()
            for name in ("opaque-approver", "opaque-approve-helper"):
                path = binaries / name
                path.write_bytes(b"synthetic executable fixture")
                path.chmod(0o700)
            calls = []
            def run(command, **kwargs):
                calls.append(command)
                if command[0] == "xcrun":
                    Path(command[-1]).write_bytes(b"synthetic launcher fixture")
            with patch.object(PACKAGING.subprocess, "run", side_effect=run):
                output = PACKAGING.build(binaries, base / "Opaque Reviewer.app", "arm64", identity="Synthetic test identity")
            info = plistlib.loads((output / "Contents/Info.plist").read_bytes())
            self.assertEqual(info["CFBundleExecutable"], "OpaqueReviewer")
            self.assertTrue(info["LSMultipleInstancesProhibited"])
            self.assertEqual(info["CFBundleURLTypes"][0]["CFBundleURLSchemes"], ["opaque-approval"])
            self.assertEqual(sorted(p.name for p in (output / "Contents/MacOS").iterdir()), ["OpaqueReviewer", "opaque-approve-helper", "opaque-approver"])
            signs = [c for c in calls if c[0] == "codesign" and "--sign" in c]
            self.assertEqual([Path(c[-1]).name for c in signs], ["opaque-approver", "opaque-approve-helper", "OpaqueReviewer", "Opaque Reviewer.app"])
            self.assertTrue(all("--timestamp" in c for c in signs))
            self.assertFalse(any(c[0] in ("security", "open", "launchctl") for c in calls))
            with self.assertRaises(ValueError):
                PACKAGING.build(binaries, output, "arm64")

    def test_missing_or_linked_binary_fails_before_compilation(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            with patch.object(PACKAGING.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    PACKAGING.build(base, base / "Missing.app", "arm64")
                source = base / "fixture"
                source.write_bytes(b"x")
                source.chmod(0o700)
                os.symlink(source, base / "opaque-approver")
                with self.assertRaises(ValueError):
                    PACKAGING.build(base, base / "Linked.app", "arm64")
                run.assert_not_called()

    def test_release_contains_reviewer_and_staples_app(self):
        release = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("opaque-approve-helper opaque-approver opaque-evidence opaque-web", release)
        self.assertIn("scripts/package-reviewer-macos.py", release)
        self.assertIn("stapler validate", release)
        self.assertIn('"${EXTRAS[@]}"', release)


if __name__ == "__main__":
    unittest.main()
