"""Offline tests for narrow rollout rendering; no cluster or Secret access."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).parent
spec = importlib.util.spec_from_file_location("approval_rollout", ROOT / "approval/render-rollout.py")
rollout = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rollout)
IMAGE = "registry.example/opaque-demo@sha256:" + "1" * 64


def deployment():
    return {"metadata": {"generation": 8}, "spec": {"replicas": 1, "strategy": {"type": "Recreate"},
            "template": {"spec": {"containers": [{"name": "controller", "image": "previous-image",
                "env": [{"name": "OPAQUE_DEMO_WORKER_URL", "value": "https://demo.opaque.info"},
                        {"name": "OPAQUE_DEMO_SLOT_NAMESPACES", "value": "opaque-demo-slot-0"},
                        {"name": "OPAQUE_DEMO_CONTROLLER_SECRET", "valueFrom": {"secretKeyRef": {"name": "existing-auth", "key": "controller-secret"}}},
                        {"name": "UNRELATED_SETTING", "value": "preserve-me"}]}]}}}}


def policy():
    return {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
            "metadata": {"name": "opaque-hosted-demo-runtime", "resourceVersion": "96975157",
                         "generation": 8, "uid": "existing-policy-uid",
                         "labels": {"existing-label": "preserve-me"},
                         "annotations": {"kubectl.kubernetes.io/last-applied-configuration":
                                         '{"metadata":{"resourceVersion":"96853509"}}'}},
            "spec": {"failurePolicy": "Fail", "validations": [{"expression": "false"}]}}


class ApprovalRolloutTests(unittest.TestCase):
    def test_only_image_and_environment_are_changed_with_concurrent_edit_guards(self):
        live = deployment()
        original = copy.deepcopy(live)
        patch, policy, summary = rollout.render(live, IMAGE, (ROOT / "k8s-admission.yaml").read_text())
        self.assertEqual(live, original)
        changes = [item for item in patch if item["op"] != "test"]
        self.assertEqual([item["path"] for item in changes], ["/spec/template/spec/containers/0/image", "/spec/template/spec/containers/0/env"])
        self.assertEqual(patch[0], {"op": "test", "path": "/metadata/generation", "value": 8})
        env = {item["name"]: item for item in changes[1]["value"]}
        self.assertEqual(env["UNRELATED_SETTING"]["value"], "preserve-me")
        self.assertEqual(env["OPAQUE_DEMO_SLOT_NAMESPACES"]["value"], "opaque-demo-slot-0")
        self.assertEqual(env["OPAQUE_DEMO_CONTROLLER_SECRET"], original["spec"]["template"]["spec"]["containers"][0]["env"][2])
        self.assertEqual(env["OPAQUE_DEMO_OAUTH_CLIENT_SECRET"]["valueFrom"]["secretKeyRef"], {"name": "opaque-demo-github-oauth", "key": "client-secret"})
        self.assertEqual(summary["runtime_image"], IMAGE)
        self.assertIn("kind: ValidatingAdmissionPolicy\n", policy)
        self.assertNotIn("ValidatingAdmissionPolicyBinding", policy)
        self.assertNotIn("${", policy)

    def test_unreviewed_origin_and_strategy_changes_fail_before_rendering(self):
        for change in ("origin", "strategy", "replicas"):
            live = deployment()
            if change == "origin":
                live["spec"]["template"]["spec"]["containers"][0]["env"][0]["value"] = "https://foreign.example"
            elif change == "strategy":
                live["spec"]["strategy"]["type"] = "RollingUpdate"
            else:
                live["spec"]["replicas"] = 2
            with self.assertRaises(ValueError):
                rollout.render(live, IMAGE, "")

    def test_inline_sensitive_environment_and_unpinned_image_are_not_rendered(self):
        live = deployment()
        live["spec"]["template"]["spec"]["containers"][0]["env"].append({"name": "UNRELATED_TOKEN", "value": "must-never-be-rendered"})
        with self.assertRaises(ValueError):
            rollout.render(live, IMAGE, "")
        with self.assertRaises(ValueError):
            rollout.render(deployment(), "registry.example/opaque-demo:latest", "")

    def test_policy_patch_guards_live_version_and_spec_and_never_mutates_metadata(self):
        live = policy()
        original = copy.deepcopy(live)
        desired = policy()
        desired["spec"]["validations"] = [{"expression": "true", "message": "reviewed policy"}]
        desired["metadata"] = {"name": "opaque-hosted-demo-runtime", "resourceVersion": "0"}
        patch = rollout.admission_patch(live, desired)
        self.assertEqual(live, original)
        self.assertEqual(patch[:2], [
            {"op": "test", "path": "/metadata/resourceVersion", "value": "96975157"},
            {"op": "test", "path": "/spec", "value": original["spec"]}])
        mutations = [item for item in patch if item["op"] != "test"]
        self.assertEqual(mutations, [{"op": "replace", "path": "/spec", "value": desired["spec"]}])
        # A stale last-applied version must never reach a mutation payload.
        self.assertNotIn("96853509", json.dumps(patch))
        self.assertNotIn("resourceVersion", json.dumps(mutations))
        self.assertNotIn("last-applied", json.dumps(patch))

    def test_policy_guards_are_taken_from_fresh_live_state_and_invalid_objects_fail_closed(self):
        desired = policy()
        for version in ("96975157", "96975158"):
            live = policy()
            live["metadata"]["resourceVersion"] = version
            self.assertEqual(rollout.admission_patch(live, desired)[0]["value"], version)
        for change in ("missing_version", "zero_version", "numeric_version", "wrong_name", "wrong_kind", "missing_spec"):
            live = policy()
            if change == "missing_version":
                del live["metadata"]["resourceVersion"]
            elif change == "zero_version":
                live["metadata"]["resourceVersion"] = "0"
            elif change == "numeric_version":
                live["metadata"]["resourceVersion"] = 96975157
            elif change == "wrong_name":
                live["metadata"]["name"] = "another-policy"
            elif change == "wrong_kind":
                live["kind"] = "ValidatingAdmissionPolicyBinding"
            else:
                del live["spec"]
            with self.subTest(change=change), self.assertRaises(ValueError):
                rollout.admission_patch(live, desired)
        desired["metadata"]["name"] = "unexpected-policy"
        with self.assertRaises(ValueError):
            rollout.admission_patch(policy(), desired)

    def test_cli_only_reads_live_metadata_and_decodes_yaml_before_writing_four_review_files(self):
        desired = policy()
        desired["metadata"] = {"name": "opaque-hosted-demo-runtime"}
        desired["spec"]["validations"] = [{"expression": "true"}]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "review"
            responses = [json.dumps(value).encode() for value in (deployment(), policy(), desired)]
            with mock.patch("sys.argv", ["render-rollout.py", "--runtime-image", IMAGE, "--output", str(output)]), \
                    mock.patch.object(rollout.subprocess, "check_output", side_effect=responses) as command, \
                    mock.patch.object(rollout.os, "umask"), mock.patch("builtins.print"):
                rollout.main()
            self.assertEqual(command.call_count, 3)
            self.assertIn("get", command.call_args_list[0].args[0])
            self.assertIn("validatingadmissionpolicy", command.call_args_list[1].args[0])
            decode = command.call_args_list[2]
            self.assertEqual(decode.args[0], ["kubectl", "--context", "admin@turingpi", "create",
                             "--dry-run=client", "--validate=false", "-f", "-", "-o", "json"])
            self.assertIn(IMAGE.encode(), decode.kwargs["input"])
            self.assertEqual({path.name for path in output.iterdir()}, {
                "controller-rollout.patch.json", "admission-policy.patch.json", "admission-policy.yaml", "rollout-summary.json"})
            patch = json.loads((output / "admission-policy.patch.json").read_text())
            self.assertEqual(patch, rollout.admission_patch(policy(), desired))
            summary = json.loads((output / "rollout-summary.json").read_text())
            self.assertEqual(summary["admission_policy_resource_version"], "96975157")
            self.assertEqual(summary["admission_policy_generation"], 8)
            for path in output.iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
