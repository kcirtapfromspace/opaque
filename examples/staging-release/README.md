# One reviewed staging workflow

This is a **prepared local workflow**, not an installed or tested live deployment. The
provider fixture tests use disposable local responses. No GitHub workflow was
installed or dispatched, and no image, repository protection, environment, or
staging service was provisioned by creating these files.

The copy at `.github/workflows/opaque-staging-release.yml` is byte-identical to
the template here and refuses any other repository or public visibility. The
[live runbook](LIVE-RUNBOOK.md) and `broker.live.example.toml` make the separate
production path reviewable; remote installation, independent review and the
private artifact prerequisites still need completion.

The narrow flow approves one repository/workflow identity, branch and observed
commit, exact workflow bytes, immutable image, and `staging` destination. It
dispatches at most once through the broker's durable final gate. A timeout or
uncertain provider response consumes that slot permanently. Reconciliation only
reads GitHub run evidence; it cannot retry the dispatch.

## Contract and trusted configuration

The supplied workflow targets the **private** `kcirtapfromspace/opaque-dogfood`
(repository ID `1357845081`) on `main`. It checks the approved SHA, a fixed image repository,
staging destination, task correlation, and first run attempt before pulling an
image by digest. It then runs the fixed `/usr/local/bin/opaque --version` smoke
check in a restricted disposable container. The fetch step uses the workflow's
short-lived `GITHUB_TOKEN` with only `packages: read`, through password-stdin and
a temporary Docker configuration removed on exit. That token is not passed to
the artifact container. The job receives no deployment or broker credentials,
checks out no repository scripts, accepts no shell command or
arbitrary extra inputs, and performs no rollout.

The proposed `ghcr.io/kcirtapfromspace/opaque-dogfood` image has **not** been verified or
published for this flow. Replace the zero digest in `opaque.json` with a real
reviewed artifact digest only after the image contract is met: **private** package
visibility, a link and Actions read access for the private dogfood repository,
`linux/amd64`, executable `/usr/local/bin/opaque` as UID/GID `65532`, and the
`org.opencontainers.image.revision` label equal to the approved commit. That
label is a consistency check, not cryptographic build provenance. Workflow
success means that smoke check succeeded; it does not establish application
health or a completed staging deployment.

Repository privacy does not establish package privacy. Verify both separately;
do not publish dogfood artifacts in the public product package. GitHub documents
the required private package access for a workflow's `GITHUB_TOKEN` in
[Working with the Container registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry).
The provider sends image coordinates only; the workflow owns package
authentication, so this private registry contract requires no new provider input.

Before live use, an operator must review the entire workflow, install it as
`.github/workflows/opaque-staging-release.yml` through the repository's reviewed
change process, and configure the `staging` environment. Protect the dispatch
branch and workflow changes with appropriate required review and environment
protection. The provider checks GitHub's `protected` branch flag; that flag does
not prove specific review rules, CODEOWNERS coverage, bypass restrictions, or
environment protections. Those remain an operator prerequisite.
Some environment protection features depend on the GitHub plan for a private
repository. Verify that they are enforced before proceeding; converting the
repository or artifact to public visibility is not an acceptable workaround.
[GitHub environment requirements](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)

## Read-only preflight and next operator steps

Run from this checkout using an existing `gh` login:

```sh
python3 scripts/staging_release_preflight.py
python3 scripts/staging_release_preflight.py --json
python3 -m unittest discover -s scripts -p 'test_staging_release_preflight.py'
```

The preflight performs GitHub API GETs only, pins the destination to the private
dogfood repository, and stops before further queries if privacy or numeric
identity does not match. It checks Actions, the branch and its protection,
same-name tag absence, workflow identity and exact bytes at the observed SHA and
default branch, staging environment controls, and private package identity. With
a real digest it searches at most 300 package versions for that exact digest.
The JSON report contains selected facts only, never authentication headers,
credential values, API bodies, or subprocess error output. A `404` on a protected
resource is reported as absent **or inaccessible**.

Exit `1` means a prerequisite is blocked or requires operator evidence; exit `2`
means invalid local contract input. `api_prerequisites_met` describes the machine
checks only. This first version intentionally leaves `ready_for_live_demo` false
until runtime artifact and effective authority evidence have been collected; it
does not accept a flag that turns those unchecked assertions into a pass.

The executable sequence to close this milestone is:

1. Review effective branch rules, workflow ownership, bypass permissions and
   dispatch/rerun access for the private repository. Provision the required
   protections and staging environment through the reviewed administration flow.
2. Review this complete workflow and install its exact bytes at
   `.github/workflows/opaque-staging-release.yml` on the default branch. Enable
   Actions deliberately; existing workflows may become eligible when enabled.
3. Build and verify a private immutable artifact from that final approved commit.
   Record its digest, architecture, revision label, isolated version check, package
   visibility and Actions read access. Do not invent or reuse a fixture digest.
4. Copy `opaque.json` into ignored or temporary storage, replace only the sentinel
   digest with the observed digest, and optionally pin `approved_commit_sha`.
   Re-run `--manifest /absolute/path/to/private-manifest.json --json` and resolve
   every blocker. Keep sanitized evidence in internal milestone records.
5. Pin the reviewed workflow hash in the trusted broker, complete native human
   approval, dispatch once, reconcile that exact task, and demonstrate denied
   replay. Retain the run identity, terminal conclusion, and durable slot evidence.

None of these commands install a workflow, enable Actions, publish an artifact,
change protections, or dispatch a task. The disposable `release_dogfood.py`
harness serves synthetic GitHub metadata on loopback and hashes these bytes; it
does not execute GitHub workflow guards, pull this package, or validate live
repository settings. Fixture success cannot close the live milestone.

## Trusted broker configuration

### Prepare and validate the artifact locally

The local builder exports committed source into a fresh private directory, builds
only the CLI for **linux/amd64**, and verifies its exact local image ID before the
fixed isolated `--version` smoke check. Its official Rust and Debian base images
are pinned to their reviewed amd64 manifest digests in `Dockerfile.artifact`.
It does not reuse the native arm64 fixture binaries.

```sh
# No Docker invocation: prepare a reviewable archive, recipe and build command.
python3 scripts/build_staging_artifact.py --prepare-only

# Requires a clean worktree; builds and validates locally without publication.
python3 scripts/build_staging_artifact.py

# When unrelated work is in progress, supply the full immutable committed SHA.
python3 scripts/build_staging_artifact.py --revision FULL_40_CHARACTER_COMMIT_SHA
python3 -m unittest discover -s scripts -p 'test_build_staging_artifact.py'
```

An explicit revision uses only that commit, excluding uncommitted changes and
untracked files. Default HEAD refuses a dirty worktree. The selected commit must
include the CLI's `OPAQUE_BUILD_REVISION` build support; older commits fail the
version check rather than claiming matching provenance. Build labels retain the
full source SHA and exact private repository URL; the CLI embeds its first seven
characters. These are build consistency checks, not signed build attestation.

The tool uses a unique local image tag and a new private temporary directory, or
the new directory named by `--output-dir`. `evidence.json` contains sanitized
metadata and a strictly validated version string. `build.log` stays local. The
smoke container runs as UID/GID `65532`, with no network, read-only filesystem,
no capabilities and bounded memory, CPU and processes. The tool removes only its
own smoke container and disposable source context; existing workloads and caches
remain. `--prepare-only` retains the context for review. Allow local disk space
for an amd64 Rust build before proceeding.

Neither a successful local image ID nor a matching version is a registry digest.
The report therefore keeps `registry_digest` null, `published` false and
`ready_for_live_dispatch` false. Publication is a separate operator action after
private destination and package-access review. Only the digest observed from the
actual private registry can replace the manifest sentinel. The final workflow's
`GITHUB_TOKEN` pull access and live smoke result still require M2 evidence. No
login, credential extraction, push, Actions change or provider dispatch is
performed by this builder.

### Configure the separate live broker

Pin the reviewed workflow's exact file bytes in the **trusted broker's**
environment. The agent must not control these settings or the broker filesystem.
For example, after review, with `reviewed_workflow` pointing at the installed
workflow's exact local bytes:

```sh
export OPAQUE_GITHUB_API_URL=https://api.github.com
export OPAQUE_GITHUB_TOKEN_REF=keychain:opaque/github-pat
export OPAQUE_STAGING_REPO=kcirtapfromspace/opaque-dogfood
export OPAQUE_STAGING_WORKFLOW_PATH=.github/workflows/opaque-staging-release.yml
export OPAQUE_STAGING_REF=main
export OPAQUE_STAGING_IMAGE_REPOSITORY=ghcr.io/kcirtapfromspace/opaque-dogfood
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
