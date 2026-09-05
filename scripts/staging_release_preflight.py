#!/usr/bin/env python3
"""GET-only inventory of the private staging contract; never dispatches a task.

Uses the existing gh login. Prints selected non-secret facts, never subprocess
output, HTTP bodies, credentials, or headers. Exit 1 means a prerequisite is
blocked or needs operator evidence; exit 2 means invalid local input. No files,
repository settings, containers, packages, or workflows are changed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from datetime import datetime, timezone
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
REPO = "kcirtapfromspace/opaque-dogfood"
REPOSITORY_ID = 1357845081
WORKFLOW_PATH = ".github/workflows/opaque-staging-release.yml"
IMAGE = "ghcr.io/kcirtapfromspace/opaque-dogfood"
BRANCH = "main"
MAX_WORKFLOW_BYTES = 128 * 1024
API_VERSION = "2026-03-10"


class GitHub:
    def get(self, path):
        """Return (HTTP status, parsed body); fail closed without echoing errors."""
        if not path.startswith((f"repos/{REPO}", "users/kcirtapfromspace/packages/")):
            raise ValueError("preflight endpoint is outside the private contract")
        env = os.environ.copy()
        env.pop("GH_DEBUG", None)
        env.update(GH_PROMPT_DISABLED="1", GH_PAGER="cat")
        try:
            result = subprocess.run(
                ["gh", "api", "--hostname", "github.com", "--method", "GET", "--include",
                 "-H", "Accept: application/vnd.github+json",
                 "-H", f"X-GitHub-Api-Version: {API_VERSION}", path],
                capture_output=True, text=True, timeout=30, env=env,
            )
            headers, _, body = result.stdout.replace("\r\n", "\n").partition("\n\n")
            status_match = re.match(r"HTTP/\S+ (\d{3})(?: |$)", headers)
            status = int(status_match[1]) if status_match else 0
            if status == 200 and result.returncode:
                return 0, {}
            value = json.loads(body)
            return status, value if isinstance(value, (dict, list)) else {}
        except (OSError, subprocess.TimeoutExpired, ValueError):
            return 0, {}


def load_contract(manifest_path, workflow_path):
    try:
        document = json.loads(Path(manifest_path).read_text())
        actions = document["actions"]
        if document["schema_version"] != 2 or len(actions) != 1:
            raise ValueError
        action = actions[0]
        expected = {
            "operation": "github.dispatch_staging_workflow", "repo": REPO,
            "repository_id": REPOSITORY_ID, "workflow_path": WORKFLOW_PATH,
            "workflow_ref": BRANCH, "image_repository": IMAGE, "environment": "staging",
        }
        if any(action.get(key) != value for key, value in expected.items()):
            raise ValueError
        digest = action.get("image_digest", "")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError
        commit = action.get("approved_commit_sha", "")
        if commit and not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise ValueError
        workflow = Path(workflow_path).read_bytes()
        if not 0 < len(workflow) <= MAX_WORKFLOW_BYTES:
            raise ValueError
        pinned = action.get("workflow_sha256", "")
        if pinned and pinned != hashlib.sha256(workflow).hexdigest():
            raise ValueError
        return action, workflow
    except (OSError, ValueError, KeyError, TypeError):
        raise ValueError("local manifest/workflow must match the private dogfood contract") from None


def inspect_contract(action, workflow, api):
    checks = []

    def record(name, status, detail, **facts):
        checks.append({"name": name, "status": status, "detail": detail, **facts})

    def check(name, passed, detail, **facts):
        record(name, "pass" if passed else "blocked", detail, **facts)

    def unavailable(name, status):
        record(name, "blocked", "Evidence absent or inaccessible; HTTP status alone does not prove absence.", http_status=status)

    digest = hashlib.sha256(workflow).hexdigest()
    result = {
        "schema_version": 1, "observed_at": datetime.now(timezone.utc).isoformat(),
        "repository": REPO, "repository_id": REPOSITORY_ID,
        "reviewed_workflow_sha256": digest, "checks": checks,
        "scope": "Read-only prerequisite snapshot; does not approve or dispatch a task.",
    }
    prefix = f"repos/{REPO}"
    status, repo = api.get(prefix)
    private = status == 200 and isinstance(repo, dict) and (
        repo.get("private") is True and repo.get("visibility") == "private"
        and repo.get("id") == REPOSITORY_ID and repo.get("full_name") == REPO
        and not repo.get("archived") and not repo.get("disabled")
    )
    check("private_destination", private, "The live target must be the active private dogfood repository.", http_status=status)
    if not private:
        result.update(api_prerequisites_met=False, ready_for_live_demo=False)
        return result  # Do not inspect a public or substituted destination.

    status, branch = api.get(f"{prefix}/branches/{BRANCH}")
    commit = branch.get("commit", {}).get("sha", "") if isinstance(branch, dict) else ""
    branch_valid = status == 200 and branch.get("name") == BRANCH and bool(re.fullmatch(r"[0-9a-f]{40}", commit))
    check("branch_identity", branch_valid, "Observe the dispatch branch and exact commit.", http_status=status)
    if branch_valid:
        result["observed_commit_sha"] = commit
        check("branch_protected", branch.get("protected") is True, "Provider planning requires GitHub's protected branch flag.")
        check("approved_commit", not action.get("approved_commit_sha") or action["approved_commit_sha"] == commit,
              "An explicit approved commit must equal the current branch; otherwise planning fills this observed commit.")

    status, _ = api.get(f"{prefix}/git/ref/tags/{BRANCH}")
    check("dispatch_ref_unambiguous", status == 404, "The same-name tag lookup must return 404, as required by the provider.", http_status=status)
    status, permissions = api.get(f"{prefix}/actions/permissions")
    check("actions_enabled", status == 200 and permissions.get("enabled") is True,
          "Repository Actions must be enabled; this check does not change them.", http_status=status)

    status, protection = api.get(f"{prefix}/branches/{BRANCH}/protection")
    if status == 200:
        review = protection.get("required_pull_request_reviews") or {}
        required_checks = protection.get("required_status_checks") or {}
        controls = {
            "required_review": review.get("required_approving_review_count", 0) >= 1,
            "code_owner_review": review.get("require_code_owner_reviews") is True,
            "dismiss_stale_reviews": review.get("dismiss_stale_reviews") is True,
            "enforce_admins": (protection.get("enforce_admins") or {}).get("enabled") is True,
            "required_checks": bool(required_checks.get("checks") or required_checks.get("contexts")),
            "force_push_disabled": (protection.get("allow_force_pushes") or {}).get("enabled") is False,
            "deletion_disabled": (protection.get("allow_deletions") or {}).get("enabled") is False,
        }
        check("branch_controls", all(controls.values()), "Conservative classic branch-protection baseline; review effective rulesets, bypass actors and CODEOWNERS separately.", controls=controls)
    else:
        unavailable("branch_controls", status)

    status, metadata = api.get(f"{prefix}/actions/workflows/{WORKFLOW_PATH.rsplit('/', 1)[1]}")
    workflow_valid = status == 200 and metadata.get("path") == WORKFLOW_PATH and metadata.get("state") == "active" and type(metadata.get("id")) is int and metadata["id"] > 0
    check("installed_workflow", workflow_valid, "The exact workflow path must have an active numeric workflow identity.", http_status=status)
    if workflow_valid:
        result["workflow_id"] = metadata["id"]

    def content_matches(ref, name):
        status, content = api.get(f"{prefix}/contents/{WORKFLOW_PATH}?ref={quote(ref, safe='')}")
        matched = False
        observed_hash = None
        if status == 200 and content.get("type") == "file" and content.get("path") == WORKFLOW_PATH and content.get("encoding") == "base64":
            encoded = content.get("content", "")
            try:
                if isinstance(encoded, str) and len(encoded) <= MAX_WORKFLOW_BYTES * 2:
                    decoded = base64.b64decode("".join(encoded.split()), validate=True)
                    if len(decoded) <= MAX_WORKFLOW_BYTES:
                        observed_hash = hashlib.sha256(decoded).hexdigest()
                        matched = decoded == workflow
            except ValueError:
                pass
        check(name, matched, "Installed bytes must exactly equal the local reviewed workflow; pin its SHA-256 in the trusted broker.", http_status=status, observed_sha256=observed_hash)
        return matched

    installed_matches = content_matches(commit, "workflow_bytes_at_commit") if branch_valid else False
    if repo.get("default_branch") == BRANCH:
        check("workflow_on_default_branch", installed_matches, "workflow_dispatch requires the reviewed workflow on the default branch.")
    else:
        default = repo.get("default_branch", "")
        if isinstance(default, str) and default:
            content_matches(default, "workflow_on_default_branch")
        else:
            record("workflow_on_default_branch", "blocked", "Default branch identity is unavailable.")

    status, environment = api.get(f"{prefix}/environments/staging")
    if status == 200 and environment.get("name") == "staging":
        policy = environment.get("deployment_branch_policy") or {}
        branch_restricted = policy.get("protected_branches") is True and branch_valid and branch.get("protected") is True
        if policy.get("custom_branch_policies") is True:
            policy_status, policies = api.get(f"{prefix}/environments/staging/deployment-branch-policies?per_page=100")
            rules = policies.get("branch_policies", [])
            branch_restricted = policy_status == 200 and policies.get("total_count") == 1 and len(rules) == 1 and rules[0].get("name") == BRANCH and rules[0].get("type") == "branch"
        check("environment_branch_controls", branch_restricted, "Staging must restrict eligible branches; a custom policy must name only main as a branch.")
        reviewers = [rule for rule in environment.get("protection_rules", []) if rule.get("type") == "required_reviewers"]
        reviewed = any(rule.get("prevent_self_review") is True and bool(rule.get("reviewers")) for rule in reviewers)
        check("environment_review", reviewed and environment.get("can_admins_bypass") is False,
              "Require independent environment review and no administrator bypass; plan availability must be checked for this private repository.")
    else:
        unavailable("staging_environment", status)

    image_digest = action["image_digest"]
    real_digest = image_digest != "sha256:" + "0" * 64
    check("image_digest", real_digest, "Replace the sentinel with the reviewed immutable private artifact digest.")
    package_path = "users/kcirtapfromspace/packages/container/opaque-dogfood"
    status, package = api.get(package_path)
    private_package = status == 200 and package.get("visibility") == "private" and package.get("name") == "opaque-dogfood" and (package.get("repository") or {}).get("id") == REPOSITORY_ID
    check("private_image_package", private_package, "The fixed GHCR package must be private and linked to the private dogfood repository.", http_status=status)
    if private_package and real_digest:
        found = False
        complete = False
        for page in range(1, 4):
            status, versions = api.get(f"{package_path}/versions?per_page=100&page={page}")
            if status != 200 or not isinstance(versions, list):
                break
            if any(version.get("name") == image_digest for version in versions):
                found = True
                break
            if len(versions) < 100:
                complete = True
                break
        check("image_digest_published", found, "Find the exact digest in at most 300 package versions; an incomplete search cannot establish absence.", bounded_search_complete=complete or found)
    record("artifact_runtime_evidence", "operator_required",
           "GitHub metadata cannot prove linux/amd64, /usr/local/bin/opaque execution as UID 65532, revision-label equality, or this workflow's GITHUB_TOKEN pull access. Validate the exact digest in an isolated smoke run; retain sanitized evidence before calling the live milestone complete.")
    record("effective_authority_review", "operator_required",
           "Review effective rulesets, workflow CODEOWNERS, independent dispatch/rerun authority, conflicting-tag creation and package access. API flags alone do not establish these controls.")
    result["api_prerequisites_met"] = all(item["status"] != "blocked" for item in checks)
    result["ready_for_live_demo"] = all(item["status"] == "pass" for item in checks)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "examples/staging-release/opaque.json")
    parser.add_argument("--workflow", type=Path, default=ROOT / "examples/staging-release/opaque-staging-release.workflow.yml")
    parser.add_argument("--json", action="store_true", help="Emit a sanitized prerequisite report")
    args = parser.parse_args(argv)
    try:
        action, workflow = load_contract(args.manifest, args.workflow)
    except ValueError as error:
        parser.exit(2, f"preflight: {error}\n")
    report = inspect_contract(action, workflow, GitHub())
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Private staging preflight: {REPO}")
        print(f"Reviewed workflow SHA-256: {report['reviewed_workflow_sha256']}")
        for item in report["checks"]:
            print(f"{item['status'].upper()}: {item['name']}: {item['detail']}")
        print("GET-only snapshot complete. No task dispatched or external state changed.")
    return 0 if report["ready_for_live_demo"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
