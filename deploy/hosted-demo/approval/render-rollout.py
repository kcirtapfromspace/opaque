#!/usr/bin/env python3
"""Read live deployment metadata and render narrow approval rollout inputs.

Never applies Kubernetes mutations, reads Secret contents, or renders slot state.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import subprocess


def render(deployment, runtime_image, policy_template):
    if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", runtime_image):
        raise ValueError("runtime image must be digest pinned")
    spec = deployment["spec"]
    if spec["replicas"] != 1 or spec["strategy"]["type"] != "Recreate":
        raise ValueError("review the changed controller replica or rollout strategy")
    containers = spec["template"]["spec"]["containers"]
    matches = [index for index, item in enumerate(containers) if item["name"] == "controller"]
    if len(matches) != 1:
        raise ValueError("expected exactly one controller container")
    index = matches[0]
    container = containers[index]
    before = container["env"]
    if len({item["name"] for item in before}) != len(before):
        raise ValueError("duplicate controller environment variable")
    if any(re.search(r"SECRET|TOKEN|PASSWORD", item["name"], re.I) and item.get("value") for item in before):
        raise ValueError("inline sensitive environment requires secure migration before rendering")
    env_by_name = {item["name"]: item for item in before}
    origin = env_by_name["OPAQUE_DEMO_WORKER_URL"].get("value")
    if origin != "https://demo.opaque.info":
        raise ValueError("review the changed public demo origin")
    after = [copy.deepcopy(item) for item in before if not item["name"].startswith("OPAQUE_DEMO_OAUTH_")
             and item["name"] != "OPAQUE_DEMO_RUNTIME_IMAGE"]
    after += [{"name": "OPAQUE_DEMO_RUNTIME_IMAGE", "value": runtime_image},
              {"name": "OPAQUE_DEMO_OAUTH_PROVIDER", "value": "github"}]
    for name, key in (("OPAQUE_DEMO_OAUTH_CLIENT_ID", "client-id"),
                      ("OPAQUE_DEMO_OAUTH_CLIENT_SECRET", "client-secret")):
        after.append({"name": name, "valueFrom": {"secretKeyRef": {
            "name": "opaque-demo-github-oauth", "key": key}}})
    prefix = f"/spec/template/spec/containers/{index}"
    patch = [{"op": "test", "path": "/metadata/generation", "value": deployment["metadata"]["generation"]},
             {"op": "test", "path": "/spec/replicas", "value": 1},
             {"op": "test", "path": "/spec/strategy/type", "value": "Recreate"},
             {"op": "test", "path": prefix + "/name", "value": "controller"},
             {"op": "test", "path": prefix + "/image", "value": container["image"]},
             {"op": "test", "path": prefix + "/env", "value": before},
             {"op": "replace", "path": prefix + "/image", "value": runtime_image},
             {"op": "replace", "path": prefix + "/env", "value": after}]
    # The admission binding already exists. Render only the reviewed Policy;
    # never bootstrap state ConfigMaps, quotas, RBAC, or namespaces at rollout.
    policy = policy_template.split("\n---\n", 1)[0]
    policy = policy.replace("${RUNTIME_IMAGE}", runtime_image).replace("${WORKER_ORIGIN}", origin)
    if re.search(r"\$\{[A-Z_]+\}", policy):
        raise ValueError("unresolved admission policy input")
    summary = {"controller_generation": deployment["metadata"]["generation"],
               "previous_image": container["image"], "runtime_image": runtime_image,
               "worker_origin": origin, "github_secret": "opaque-demo-github-oauth",
               "github_secret_keys": ["client-id", "client-secret"]}
    return patch, policy, summary


def admission_patch(live_policy, desired_policy):
    """Replace only the reviewed policy spec after testing its live version."""
    for policy in (live_policy, desired_policy):
        if (policy.get("apiVersion") != "admissionregistration.k8s.io/v1"
                or policy.get("kind") != "ValidatingAdmissionPolicy"
                or policy.get("metadata", {}).get("name") != "opaque-hosted-demo-runtime"
                or not isinstance(policy.get("spec"), dict) or not policy["spec"]):
            raise ValueError("expected the existing named admission policy and a nonempty spec")
    version = live_policy["metadata"].get("resourceVersion")
    if not isinstance(version, str) or not version or version == "0":
        raise ValueError("live admission policy resourceVersion is required")
    return [
        {"op": "test", "path": "/metadata/resourceVersion", "value": version},
        {"op": "test", "path": "/spec", "value": copy.deepcopy(live_policy["spec"])},
        {"op": "replace", "path": "/spec", "value": copy.deepcopy(desired_policy["spec"])},
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-image", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    raw = subprocess.check_output(["kubectl", "--context", "admin@turingpi", "-n", "opaque-demo-system",
                                   "get", "deployment", "opaque-demo-controller", "-o", "json"])
    live_policy = json.loads(subprocess.check_output([
        "kubectl", "--context", "admin@turingpi", "get", "validatingadmissionpolicy",
        "opaque-hosted-demo-runtime", "-o", "json"]))
    template = Path(__file__).resolve().parents[1] / "k8s-admission.yaml"
    patch, policy, summary = render(json.loads(raw), args.runtime_image, template.read_text())
    # kubectl supplies its YAML decoder without another Python dependency.
    # Client dry-run only converts the local template; it never creates a Policy.
    desired_policy = json.loads(subprocess.check_output([
        "kubectl", "--context", "admin@turingpi", "create", "--dry-run=client",
        "--validate=false", "-f", "-", "-o", "json"], input=policy.encode()))
    policy_patch = admission_patch(live_policy, desired_policy)
    summary.update({"admission_policy": live_policy["metadata"]["name"],
                    "admission_policy_resource_version": live_policy["metadata"]["resourceVersion"],
                    "admission_policy_generation": live_policy["metadata"].get("generation")})
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, data in (("controller-rollout.patch.json", json.dumps(patch, indent=2) + "\n"),
                       ("admission-policy.patch.json", json.dumps(policy_patch, indent=2) + "\n"),
                       ("admission-policy.yaml", policy + "\n"),
                       ("rollout-summary.json", json.dumps(summary, indent=2) + "\n")):
        target = args.output / name
        target.write_text(data)
        target.chmod(0o600)
    print("Rendered guarded controller/policy patches, policy review YAML, and safe summary; no changes applied.")


if __name__ == "__main__":
    main()
