# One reviewed staging workflow

This is an **uninstalled contract template**, not a tested live deployment. The
provider fixture tests use disposable local responses. No GitHub workflow was
installed or dispatched, and no image, repository protection, environment, or
staging service was provisioned by creating these files.

The narrow flow approves one repository/workflow identity, branch and observed
commit, exact workflow bytes, immutable image, and `staging` destination. It
dispatches at most once through the broker's durable final gate. A timeout or
uncertain provider response consumes that slot permanently. Reconciliation only
reads GitHub run evidence; it cannot retry the dispatch.

## Contract and trusted configuration

The supplied workflow targets `kcirtapfromspace/opaque` (repository ID
`1156844526`) on `main`. It checks the approved SHA, a fixed image repository,
staging destination, task correlation, and first run attempt before pulling an
image by digest. It then runs the fixed `/usr/local/bin/opaque --version` smoke
check in a restricted disposable container. It receives no deployment or broker
credentials, checks out no repository scripts, accepts no shell command or
arbitrary extra inputs, and performs no rollout.

The proposed `ghcr.io/kcirtapfromspace/opaque` image has **not** been verified or
published for this flow. Replace the zero digest in `opaque.json` with a real
reviewed artifact digest only after the image contract is met: public registry
read access, `/usr/local/bin/opaque`, and the
`org.opencontainers.image.revision` label equal to the approved commit. That
label is a consistency check, not cryptographic build provenance. Workflow
success means that smoke check succeeded; it does not establish application
health or a completed staging deployment.

Before live use, an operator must review the entire workflow, install it as
`.github/workflows/opaque-staging-release.yml` through the repository's reviewed
change process, and configure the `staging` environment. Protect the dispatch
branch and workflow changes with appropriate required review and environment
protection. The provider checks GitHub's `protected` branch flag; that flag does
not prove specific review rules, CODEOWNERS coverage, bypass restrictions, or
environment protections. Those remain an operator prerequisite.

Pin the reviewed workflow's exact file bytes in the **trusted broker's**
environment. The agent must not control these settings or the broker filesystem.
For example, after review, with `reviewed_workflow` pointing at the installed
workflow's exact local bytes:

```sh
export OPAQUE_GITHUB_API_URL=https://api.github.com
export OPAQUE_GITHUB_TOKEN_REF=keychain:opaque/github-pat
export OPAQUE_STAGING_REPO=kcirtapfromspace/opaque
export OPAQUE_STAGING_WORKFLOW_PATH=.github/workflows/opaque-staging-release.yml
export OPAQUE_STAGING_REF=main
export OPAQUE_STAGING_IMAGE_REPOSITORY=ghcr.io/kcirtapfromspace/opaque
export OPAQUE_STAGING_WORKFLOW_SHA256="$(shasum -a 256 "$reviewed_workflow" | cut -d ' ' -f 1)"
```

These are authority and credential **references**, never token values. A
fine-grained credential needs repository metadata/contents read and Actions
read/write for the selected repository. Configure broker policy for both
`github.release_manifest` and the exact child
`github.dispatch_staging_workflow` scope, and require trusted human approval.
Use the separate broker deployment instructions for process and custody
isolation. The loopback fixture flag is not a live deployment setting.

Planning replaces repository/workflow IDs with observed numeric IDs and fills
an omitted commit with the observed protected branch SHA. An explicitly supplied
commit must match. It fetches workflow content at that SHA and requires an exact
match to the operator's configured SHA-256. A manifest-supplied hash alone
cannot establish an approved contract. Before dispatch it rechecks repository,
workflow, branch SHA/protection, and content, then calls the final broker gate.
Both planning and dispatch require a same-name tag lookup to return `404`,
because the dispatch API accepts either a branch or tag name.
The callback is the in-flight boundary; revoke cannot cancel a POST already
authorized there.

## Dispatch and evidence

The provider sends only these six inputs: `opaque_task_id`,
`opaque_manifest_digest`, `approved_commit_sha`, `image_repository`,
`image_digest`, and `environment` (`staging`). The exact required run name is
`opaque-staging:<task UUID>:<manifest SHA-256>`. Current GitHub REST API
`2026-03-10` documents a successful dispatch response with the workflow run ID;
the provider retains that run ID and also accepts the older empty `204`
response. A successful API response records `api_accepted`, independently of
workflow completion. Invalid or partial `200` response evidence is unknown.
[GitHub workflow dispatch API](https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event)

With a recorded dispatch response ID, reconciliation fetches only that exact
run and reports `dispatch_response` correlation. With a legacy or uncertain
response, it searches by workflow, event, branch, and commit and reports the
weaker `task_title` correlation. Both verify the exact task/digest run name,
numeric workflow/repository identities, and head SHA. A direct-ID mismatch does
not fall back to title search.
It constructs the run link from trusted API authority rather than returning a
provider-supplied URL. It reads at most 300 candidate runs. Multiple matches,
incomplete bounded searches, inconsistent evidence, and external reruns are
ambiguous. Missing evidence is `pending`, never proof that dispatch did not
happen. Attempt 2 or later is external activity outside the approved one-shot
dispatch. These observations are workflow evidence, not independent deployment
attestation. [GitHub workflow run API](https://docs.github.com/en/rest/actions/workflow-runs#list-workflow-runs-for-a-workflow)

## Remaining trust and race boundary

GitHub dispatch accepts a branch or tag name; it does not offer an atomic
compare-and-dispatch against the observed SHA. This provider accepts branches
only. A branch can move after the final recheck but before GitHub handles the
request, or a conflicting tag can be created after its absence is checked. The
reviewed workflow must require the exact `GITHUB_REF` branch and fail if its
actual `GITHUB_SHA` differs from the approved input; repository protections
must prevent replacing those guards or creating conflicting dispatch refs. The
workflow must also exist on the default branch for dispatch. Neither a local
recheck nor a content hash removes that provider race.
[GitHub workflow dispatch event semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch)

Other GitHub users with Actions write permissions can dispatch or rerun workflows
outside Opaque. The correlation title is public metadata, not a signature or
authorization token; someone with that independent authority can copy it. The
broker's durable one-shot guarantee covers its own dispatch slot. Restrict other
dispatchers and require environment protection where provenance matters. A
stronger rollout contract would require provider-side authorization validation,
immutable workflow dependencies, signed artifact provenance, and independent
staging health evidence. Those are outside this smoke-check template.
