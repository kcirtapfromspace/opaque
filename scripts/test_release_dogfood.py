"""Human milestone evidence must reject test, incomplete and duplicate effects."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from release_dogfood import ReleaseDogfood, validate_native_completion


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
            self.assertEqual(evidence["observed_dispatches"], 0)
            self.assertFalse((Path(directory) / "native-approved-receipt.json").exists())
            process.terminate.assert_called_once()
            process.wait.assert_called_once_with(timeout=5)
            fixture.task.assert_called_once_with("plan", "--manifest", "/input/manifest.json")


if __name__ == "__main__":
    unittest.main()
