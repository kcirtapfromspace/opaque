"""Prerequisite regressions; all provider calls are local fixtures."""
import base64
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import staging_release_preflight as preflight


class FakeGitHub:
    def __init__(self, replies):
        self.replies = replies
        self.calls = []

    def get(self, path):
        self.calls.append(path)
        return copy.deepcopy(self.replies.get(path, (404, {})))


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.action, self.workflow = preflight.load_contract(
            preflight.ROOT / "examples/staging-release/opaque.json",
            preflight.ROOT / "examples/staging-release/opaque-staging-release.workflow.yml",
        )
        self.action["image_digest"] = "sha256:" + "b" * 64
        self.commit = "a" * 40
        self.prefix = f"repos/{preflight.REPO}"
        self.package = "users/kcirtapfromspace/packages/container/opaque-dogfood"
        content = {"type": "file", "path": preflight.WORKFLOW_PATH,
                   "encoding": "base64", "content": base64.b64encode(self.workflow).decode()}
        self.replies = {
            self.prefix: (200, {"private": True, "visibility": "private", "id": preflight.REPOSITORY_ID,
                               "full_name": preflight.REPO, "default_branch": "main"}),
            self.prefix + "/branches/main": (200, {"name": "main", "protected": True, "commit": {"sha": self.commit}}),
            self.prefix + "/actions/permissions": (200, {"enabled": True}),
            self.prefix + "/branches/main/protection": (200, {
                "required_pull_request_reviews": {"required_approving_review_count": 1, "require_code_owner_reviews": True, "dismiss_stale_reviews": True},
                "required_status_checks": {"contexts": ["test"]}, "enforce_admins": {"enabled": True},
                "allow_force_pushes": {"enabled": False}, "allow_deletions": {"enabled": False},
            }),
            self.prefix + "/actions/workflows/opaque-staging-release.yml": (200, {"id": 17001, "state": "active", "path": preflight.WORKFLOW_PATH}),
            self.prefix + f"/contents/{preflight.WORKFLOW_PATH}?ref={self.commit}": (200, content),
            self.prefix + "/environments/staging": (200, {
                "name": "staging", "can_admins_bypass": False,
                "deployment_branch_policy": {"protected_branches": True},
                "protection_rules": [{"type": "required_reviewers", "prevent_self_review": True, "reviewers": [{"type": "User"}]}],
            }),
            self.package: (200, {"name": "opaque-dogfood", "visibility": "private", "repository": {"id": preflight.REPOSITORY_ID}}),
            self.package + "/versions?per_page=100&page=1": (200, [{"name": self.action["image_digest"]}]),
        }

    def inspect(self):
        api = FakeGitHub(self.replies)
        report = preflight.inspect_contract(self.action, self.workflow, api)
        return report, {item["name"]: item for item in report["checks"]}, api

    def test_api_success_does_not_forge_artifact_or_authority_evidence(self):
        report, checks, _ = self.inspect()
        self.assertTrue(report["api_prerequisites_met"])
        self.assertFalse(report["ready_for_live_demo"])
        self.assertEqual(checks["artifact_runtime_evidence"]["status"], "operator_required")
        self.assertEqual(checks["effective_authority_review"]["status"], "operator_required")

    def test_public_or_substituted_repository_stops_all_further_queries(self):
        for field, value in [("private", False), ("visibility", "public"), ("id", 1156844526), ("full_name", "kcirtapfromspace/opaque")]:
            with self.subTest(field=field):
                original = self.replies[self.prefix]
                self.replies[self.prefix] = (200, {**original[1], field: value})
                report, _, api = self.inspect()
                self.assertFalse(report["api_prerequisites_met"])
                self.assertEqual(api.calls, [self.prefix])
                self.replies[self.prefix] = original

    def test_tag_lookup_auth_failure_is_not_treated_as_tag_absence(self):
        for status in [0, 200, 401, 403, 500]:
            self.replies[self.prefix + "/git/ref/tags/main"] = (status, {})
            _, checks, _ = self.inspect()
            self.assertEqual(checks["dispatch_ref_unambiguous"]["status"], "blocked")

    def test_workflow_requires_exact_bytes_and_valid_encoding(self):
        key = self.prefix + f"/contents/{preflight.WORKFLOW_PATH}?ref={self.commit}"
        for encoded in [base64.b64encode(self.workflow + b"\n").decode(), "%%%", "x" * (preflight.MAX_WORKFLOW_BYTES * 2 + 1)]:
            self.replies[key][1]["content"] = encoded
            _, checks, _ = self.inspect()
            self.assertEqual(checks["workflow_bytes_at_commit"]["status"], "blocked")
            self.assertEqual(checks["workflow_on_default_branch"]["status"], "blocked")

    def test_explicit_commit_must_match_branch(self):
        self.action["approved_commit_sha"] = "c" * 40
        _, checks, _ = self.inspect()
        self.assertEqual(checks["approved_commit"]["status"], "blocked")

    def test_disabled_actions_unprotected_branch_missing_environment_remain_blocked(self):
        self.replies[self.prefix + "/actions/permissions"] = (200, {"enabled": False})
        self.replies[self.prefix + "/branches/main"][1]["protected"] = False
        self.replies[self.prefix + "/environments/staging"] = (404, {"message": "sensitive provider text"})
        report, checks, _ = self.inspect()
        for name in ["actions_enabled", "branch_protected", "staging_environment"]:
            self.assertEqual(checks[name]["status"], "blocked")
        self.assertNotIn("sensitive provider text", json.dumps(report))

    def test_private_repository_does_not_make_public_package_safe(self):
        self.replies[self.package][1]["visibility"] = "public"
        _, checks, api = self.inspect()
        self.assertEqual(checks["private_image_package"]["status"], "blocked")
        self.assertFalse(any("/versions?" in call for call in api.calls))

    def test_digest_search_is_bounded_and_does_not_invent_match(self):
        for page in range(1, 5):
            self.replies[self.package + f"/versions?per_page=100&page={page}"] = (200, [{"name": "sha256:" + "c" * 64}] * 100)
        _, checks, api = self.inspect()
        self.assertEqual(checks["image_digest_published"]["status"], "blocked")
        self.assertFalse(checks["image_digest_published"]["bounded_search_complete"])
        self.assertEqual(len([call for call in api.calls if "/versions?" in call]), 3)

    def test_zero_digest_remains_a_blocker(self):
        self.action["image_digest"] = "sha256:" + "0" * 64
        _, checks, api = self.inspect()
        self.assertEqual(checks["image_digest"]["status"], "blocked")
        self.assertFalse(any("/versions?" in call for call in api.calls))

    def test_manifest_cannot_redirect_to_public_repo(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            action = {**self.action, "repo": "kcirtapfromspace/opaque"}
            path.write_text(json.dumps({"schema_version": 2, "actions": [action]}))
            with self.assertRaisesRegex(ValueError, "private dogfood contract"):
                preflight.load_contract(path, preflight.ROOT / "examples/staging-release/opaque-staging-release.workflow.yml")

    def test_transport_is_get_only_and_never_returns_subprocess_error_text(self):
        with patch.object(preflight.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "ghp_SUPER_SECRET")) as run:
            status, body = preflight.GitHub().get(self.prefix)
            self.assertEqual((status, body), (0, {}))
            command = run.call_args.args[0]
            self.assertEqual(command[command.index("--method") + 1], "GET")
            self.assertIn("--hostname", command)
            self.assertNotIn("GH_DEBUG", run.call_args.kwargs["env"])

    def test_transport_parses_status_without_exposing_headers(self):
        response = 'HTTP/2.0 200 OK\r\nAuthorization: secret\r\n\r\n{"enabled": false}'
        with patch.object(preflight.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, response, "")):
            self.assertEqual(preflight.GitHub().get(self.prefix), (200, {"enabled": False}))


if __name__ == "__main__":
    unittest.main()
