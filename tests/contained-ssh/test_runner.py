"""Safety regressions for owned-resource cleanup, separate from service proof."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("contained_runner", Path(__file__).with_name("run.py"))
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def result(code=0, stdout=b""):
    return subprocess.CompletedProcess([], code, stdout, b"")


class CleanupTests(unittest.TestCase):
    def test_coverage_acceptance_is_explicit_and_rejects_invalid_combinations_before_docker(self):
        invalid = (["--acceptance", "model"], ["--coverage-allow-dirty"],
                   ["--coverage", "--coverage-acceptance-only"],
                   ["--coverage", "--acceptance", "model", "--acceptance", "model"],
                   ["--coverage", "--model-file", "/unused/model.gguf"])
        for arguments in invalid:
            with self.subTest(arguments=arguments), patch.object(RUNNER.sys, "argv", ["run.py", "--output", "/unused/output", *arguments]), \
                 patch.object(RUNNER, "command") as command:
                with self.assertRaises(SystemExit):
                    RUNNER.main()
                command.assert_not_called()

    def test_restrictive_umask_keeps_outer_private_and_mount_traversable(self):
        previous_umask = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "new"
                with patch.object(RUNNER.sys, "argv", ["run.py", "--output", str(output)]), \
                     patch.object(RUNNER, "command", side_effect=RuntimeError("stop before Docker")):
                    with self.assertRaisesRegex(RuntimeError, "stop before Docker"):
                        RUNNER.main()
                self.assertEqual(output.stat().st_mode & 0o777, 0o700)
                self.assertEqual((output / "container").stat().st_mode & 0o777, 0o711)
        finally:
            os.umask(previous_umask)

    def test_artifact_handoff_has_fixed_mount_and_does_not_follow_symlinks(self):
        with patch.object(RUNNER.os, "getuid", return_value=1001), \
             patch.object(RUNNER.os, "getgid", return_value=1002), \
             patch.object(RUNNER, "command") as command:
            RUNNER.handoff_artifacts("exact-id")
        command.assert_called_once_with([
            "docker", "exec", "exact-id", "chown", "--recursive", "--no-dereference",
            "1001:1002", "/evidence"])

    def test_matching_label_removes_exact_container_only(self):
        metadata = json.dumps([{"Config": {"Labels": {RUNNER.LABEL: "owned"}}}]).encode()
        with patch.object(RUNNER, "command", side_effect=[result(stdout=metadata), result(), result()]) as command:
            self.assertEqual(RUNNER.cleanup_container("exact-id", "owned", Path("/tmp/evidence")), "removed_owned_container")
        self.assertEqual(command.call_args_list[-1].args[0], ["docker", "rm", "--force", "exact-id"])
        self.assertEqual(command.call_count, 3)

    def test_wrong_or_missing_ownership_never_deletes_container(self):
        for labels in ({RUNNER.LABEL: "someone-else"}, {}, None):
            with self.subTest(labels=labels):
                metadata = json.dumps([{"Config": {"Labels": labels}}]).encode()
                with patch.object(RUNNER, "command", return_value=result(stdout=metadata)) as command:
                    self.assertEqual(RUNNER.cleanup_container("exact-id", "owned", Path("/tmp/evidence")), "ownership_mismatch")
                self.assertEqual(command.call_count, 1)

    def test_unavailable_daemon_never_reports_successful_cleanup(self):
        with patch.object(RUNNER, "command", side_effect=[result(1), result(1)]):
            self.assertEqual(RUNNER.cleanup_container("exact-id", "owned", Path("/tmp/evidence")), "failed")

    def test_absence_needs_successful_inventory(self):
        with patch.object(RUNNER, "command", side_effect=[result(1), result(stdout=b"other-id other-name\n")]):
            self.assertEqual(RUNNER.cleanup_container("exact-id", "owned", Path("/tmp/evidence")), "already_absent")
        with patch.object(RUNNER, "command", side_effect=[result(1), result(stdout=b"exact-id still-running\n")]):
            self.assertEqual(RUNNER.cleanup_container("exact-id", "owned", Path("/tmp/evidence")), "failed")

    def test_failed_removal_is_not_a_completed_cleanup(self):
        metadata = json.dumps([{"Config": {"Labels": {RUNNER.LABEL: "owned"}}}]).encode()
        with patch.object(RUNNER, "command", side_effect=[result(stdout=metadata), result(), result(1)]):
            self.assertEqual(RUNNER.cleanup_container("exact-id", "owned", Path("/tmp/evidence")), "failed")

    def test_source_or_existing_output_is_refused(self):
        with self.assertRaises(ValueError):
            RUNNER.output_path(RUNNER.ROOT / "must-not-create-evidence")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                RUNNER.output_path(Path(directory))
            created = RUNNER.output_path(Path(directory) / "new")
            self.assertEqual(created.stat().st_mode & 0o777, 0o700)

    def test_mount_syntax_cannot_add_options_through_a_path(self):
        with self.assertRaises(ValueError):
            RUNNER.mount(Path("/tmp/synthetic,readonly=false"))


if __name__ == "__main__":
    unittest.main()
