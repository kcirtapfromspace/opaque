"""Human milestone evidence must reject test, incomplete and duplicate effects."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from release_dogfood import ReleaseDogfood, host_environment, main, native_readiness, validate_native_completion


class NativeReadinessTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name).resolve()
        for name in ("opaque-approver", "opaque-approve-helper"):
            executable = self.path / name
            executable.write_text("fixture executable identity\n")
            executable.chmod(0o700)
        self.report = {"check": "native_review", "ready": True,
                       "visibility_verified": False, "authentication_available": True}

    def test_explicit_binaries_are_probed_without_custody_or_approval(self):
        response = subprocess.CompletedProcess([], 0, json.dumps(self.report), "")
        with patch("release_dogfood.execute", return_value=response) as run:
            evidence = native_readiness(self.path, {})
        self.assertEqual(run.call_args.args[0], [str(self.path / "opaque-approver"), "check-native"])
        self.assertFalse(evidence["visibility_verified"])
        self.assertFalse(evidence["human_approval"])
        self.assertEqual(set(evidence["binary_sha256"]), {"opaque-approver", "opaque-approve-helper"})
        self.assertTrue(all(len(value) == 64 for value in evidence["binary_sha256"].values()))
        self.assertEqual(len(list(self.path.iterdir())), 2)

    def test_unavailable_authentication_or_unsupported_report_cannot_pass(self):
        for report in ({}, [], {**self.report, "ready": 1},
                       {**self.report, "authentication_available": False},
                       {**self.report, "visibility_verified": True}):
            response = subprocess.CompletedProcess([], 0, json.dumps(report), "")
            with self.subTest(report=report), patch("release_dogfood.execute", return_value=response), \
                 self.assertRaisesRegex(RuntimeError, "unsupported or incomplete"):
                native_readiness(self.path, {})

    def test_missing_or_nonexecutable_helper_stops_before_probe(self):
        helper = self.path / "opaque-approve-helper"
        helper.chmod(0o600)
        with patch("release_dogfood.execute") as run, self.assertRaisesRegex(RuntimeError, "not executable"):
            native_readiness(self.path, {})
        run.assert_not_called()
        helper.unlink()
        with self.assertRaisesRegex(RuntimeError, "missing"):
            native_readiness(self.path, {})

    def test_failed_probe_stops_before_docker_build_or_task_creation(self):
        fixture = ReleaseDogfood.__new__(ReleaseDogfood)
        fixture.args = SimpleNamespace(native=True)
        fixture.native_bin_dir = self.path
        fixture.clean_env = {}
        fixture.docker = Mock()
        failure = subprocess.CompletedProcess([], 2, "", "native review UI unavailable")
        with patch("release_dogfood.execute", return_value=failure), \
             self.assertRaisesRegex(RuntimeError, "before task creation"):
            fixture.build()
        fixture.docker.assert_not_called()

    def test_native_desktop_metadata_survives_without_provider_credentials(self):
        environment = {"PATH": "/usr/bin", "DISPLAY": ":0", "XDG_RUNTIME_DIR": "/run/user/1000",
                       "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
                       "GITHUB_TOKEN": "must-not-propagate", "LD_PRELOAD": "must-not-load"}
        with patch.dict("release_dogfood.os.environ", environment, clear=True):
            native = host_environment(native=True)
            automated = host_environment()
        self.assertEqual(native["DISPLAY"], ":0")
        self.assertEqual(native["DBUS_SESSION_BUS_ADDRESS"], environment["DBUS_SESSION_BUS_ADDRESS"])
        self.assertNotIn("GITHUB_TOKEN", native)
        self.assertNotIn("LD_PRELOAD", native)
        self.assertEqual(automated, {"PATH": "/usr/bin"})


class NativeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.receipt = {
            "approval_mode": "paired_workstation", "approved_at": 1,
            "state": "completed", "slots": [{"state": "api_accepted"}],
        }

    def test_completed_workstation_receipt_with_one_effect(self):
        validate_native_completion(self.receipt, 1)

    def test_test_or_unattributed_approval_never_closes_human_gate(self):
        for mode in ("insecure_test", "native", None):
            with self.subTest(mode=mode), self.assertRaises(RuntimeError):
                validate_native_completion(dict(self.receipt, approval_mode=mode), 1)

    def test_pending_approval_never_closes_human_gate(self):
        with self.assertRaises(RuntimeError):
            validate_native_completion(dict(self.receipt, approved_at=None), 1)

    def test_unknown_or_failed_effect_never_counts_as_success(self):
        for state in ("unknown", "rejected", "reserved", "unattempted"):
            receipt = copy.deepcopy(self.receipt)
            receipt["slots"][0]["state"] = state
            with self.subTest(state=state), self.assertRaises(RuntimeError):
                validate_native_completion(receipt, 1)

    def test_missing_or_additional_slot_is_not_the_reviewed_contract(self):
        for slots in ([], self.receipt["slots"] * 2):
            with self.subTest(slots=slots), self.assertRaises(RuntimeError):
                validate_native_completion(dict(self.receipt, slots=slots), 1)

    def test_provider_counter_must_agree_with_receipt(self):
        for dispatches in (0, 2):
            with self.subTest(dispatches=dispatches), self.assertRaises(RuntimeError):
                validate_native_completion(self.receipt, dispatches)

    def test_incomplete_task_rejected_even_with_accepted_slot(self):
        with self.assertRaises(RuntimeError):
            validate_native_completion(dict(self.receipt, state="running"), 1)

    def test_review_failure_records_failure_and_stops_own_waiter(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = ReleaseDogfood.__new__(ReleaseDogfood)
            fixture.args = SimpleNamespace(native=True)
            fixture.directory = fixture.signer_dir = Path(directory)
            fixture.native_bin_dir = Path(directory)
            fixture.task_id = None
            fixture.agent_name = "isolated-native-test-agent"
            fixture.clean_env = {}
            fixture.assert_custody = Mock()
            fixture.control = Mock()
            fixture.count_dispatches = Mock(return_value=0)
            fixture.task = Mock(return_value=({"id": "fixture-task"}, 0))
            pending = [{"operation": "github.release_manifest", "approval_id": "fixture-round"}]
            replies = [subprocess.CompletedProcess([], 0, json.dumps(pending), ""),
                       subprocess.CompletedProcess([], 1, "", "task review timed out")]
            process = Mock()
            process.poll.return_value = None
            with patch("release_dogfood.execute", side_effect=replies), \
                 patch("release_dogfood.subprocess.Popen", return_value=process), \
                 self.assertRaisesRegex(RuntimeError, "Native review did not complete"):
                fixture.native_check()
            evidence = json.loads((Path(directory) / "native-review-evidence.json").read_text())
            self.assertFalse(evidence["passed"])
            self.assertEqual(evidence["stage"], "native_review")
            self.assertEqual(evidence["observed_dispatches"], 0)
            self.assertFalse((Path(directory) / "native-approved-receipt.json").exists())
            process.terminate.assert_called_once()
            process.wait.assert_called_once_with(timeout=5)
            fixture.task.assert_called_once_with("plan", "--manifest", "/input/manifest.json")

    def test_failure_after_human_review_still_records_failed_milestone(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = ReleaseDogfood.__new__(ReleaseDogfood)
            fixture.args = SimpleNamespace(native=True)
            fixture.directory = Path(directory)
            fixture.task_id = "fixture-task"
            fixture.count_dispatches = Mock(side_effect=[0, 1])

            def failed_reconciliation(_baseline):
                fixture.native_progress("reconciliation")
                raise RuntimeError("The observed run is ambiguous")

            fixture._native_check = failed_reconciliation
            with self.assertRaisesRegex(RuntimeError, "ambiguous"):
                fixture.native_check()
            evidence = json.loads((fixture.directory / "native-review-evidence.json").read_text())
            self.assertFalse(evidence["passed"])
            self.assertEqual(evidence["stage"], "reconciliation")
            self.assertEqual(evidence["observed_dispatches"], 1)
            self.assertFalse((fixture.directory / "native-approved-receipt.json").exists())

    def test_new_attempt_cannot_overwrite_previous_native_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = ReleaseDogfood.__new__(ReleaseDogfood)
            fixture.args = SimpleNamespace(native=True)
            fixture.directory = Path(directory)
            path = fixture.directory / "native-review-evidence.json"
            path.write_text('{"passed":false,"task_id":"previous"}\n')
            original = path.read_bytes()
            fixture._native_check = Mock()
            with self.assertRaisesRegex(RuntimeError, "fresh --data-dir"):
                fixture.native_check()
            self.assertEqual(path.read_bytes(), original)
            fixture._native_check.assert_not_called()

    def test_constructor_refuses_old_native_attempt_before_any_mutation(self):
        for evidence_name in ("native-review-evidence.json", "native-progress.json", "native-approved-receipt.json"):
            with self.subTest(evidence=evidence_name), tempfile.TemporaryDirectory() as directory:
                path = Path(directory)
                marker = path / ".opaque-release-dogfood.json"
                marker.write_text('{"native":true,"prefix":"retained"}\n')
                evidence = path / evidence_name
                evidence.write_text('{"task_id":"previous"}\n')
                before = {item.name: item.read_bytes() for item in path.iterdir()}
                args = SimpleNamespace(data_dir=path, native=True, native_check=True)
                with self.assertRaisesRegex(RuntimeError, "before starting any fixture resources"):
                    ReleaseDogfood(args)
                self.assertEqual({item.name: item.read_bytes() for item in path.iterdir()}, before)

    def test_interrupt_retains_failed_native_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = ReleaseDogfood.__new__(ReleaseDogfood)
            fixture.args = SimpleNamespace(native=True)
            fixture.directory = Path(directory)
            fixture.task_id = "fixture-task"
            fixture.count_dispatches = Mock(return_value=0)
            fixture._native_check = Mock(side_effect=KeyboardInterrupt())
            with self.assertRaises(KeyboardInterrupt):
                fixture.native_check()
            evidence = json.loads((fixture.directory / "native-review-evidence.json").read_text())
            self.assertFalse(evidence["passed"])
            self.assertEqual(evidence["reason"], "native_walkthrough_interrupted")
            self.assertEqual(evidence["observed_dispatches"], 0)

    def test_interrupted_command_returns_nonzero_and_closes_only_its_fixture(self):
        fixture = Mock()
        fixture.directory = Path("/private/tmp/fixture-interrupted")
        fixture.native_check.side_effect = KeyboardInterrupt()
        with patch("release_dogfood.sys.argv", ["release_dogfood.py", "--native-check"]), \
             patch("release_dogfood.ReleaseDogfood", return_value=fixture):
            self.assertEqual(main(), 130)
        fixture.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
