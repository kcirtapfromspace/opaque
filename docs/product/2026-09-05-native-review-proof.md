# Native review and staging preparation

**Private validation record · September 5, 2026**

The M1 human approval ceremony completed during implementation on
`codex/native-staging-proof`, based on `190cb16`. This record distinguishes the
observed disposable-provider operation from the still-unprovisioned real staging
contract. Keep it out of public documentation, search and assets.

## Native review changes

The earlier 90-second timeout did not establish a root cause. The helper now
finishes AppKit launch, lays out and explicitly orders its review window, and
emits fixed progress markers. Readiness probes check the current desktop session
and native authentication capability before a task or approval timer starts.
They create no custody, request no decision and do not establish human visibility.

The daemon retains only known stage markers. The full review still goes through
stdin, and the existing 90-second deadline now includes document delivery as well
as interaction. Review confirmation still requires separate native authentication;
a diagnostic marker cannot supply either decision. Timeout and cancellation reap
the helper. Linux dialog children are bound to their helper's lifetime.

The fixture accepts an explicit host binary directory and records both executable
hashes. It preserves Linux desktop connection metadata without passing provider
credentials. It retains the failed stage even when reconciliation, replay or
restart validation fails after approval. Prior native evidence is refused before
fixture mutation, and interrupted runs return a nonzero status.

## Observed human ceremony

Commands:

```sh
python3 scripts/release_dogfood.py --check
python3 scripts/release_dogfood.py --native-preflight \
  --native-bin-dir /Users/thinkstudio/opaque/target/debug
python3 scripts/release_dogfood.py --native-check --no-build \
  --native-bin-dir /Users/thinkstudio/opaque/target/debug
```

The first command rebuilt the Linux broker/client/MCP/dashboard from the working
source and passed the complete four-task test-signer fixture. The native command
then used those binaries with a fresh broker and the actual host reviewer. No
automated signer or UI automation supplied the human decision.

| Observation | Result |
| --- | --- |
| Task | `d418833c-41bd-47b9-b9cc-6f3ceba24fbc` |
| Approval round | `4c4eb9e5-f138-4d87-a0ef-81ff3a1aa88a` |
| Manifest SHA-256 | `8f5955efe1ee7c47e2f062b05804f4e032dded121934867a57cba3aa17ad404f` |
| Approval provenance | `paired_workstation`, completed human review and native authentication |
| Native stages | `ui-ready`, `window-ordered`, `review-confirmed`, `authenticating` |
| Walkthrough elapsed time | 10.14 seconds, including verification; not a usability benchmark |
| Provider dispatch count | Exactly one disposable-loopback POST |
| Receipt | Completed, one `api_accepted` slot |
| Reconciliation | Fixture run `80001`, `dispatch_response` correlation, `succeeded` |
| Replay and restart | Replay denied before and after restart; persisted slots/observation unchanged |
| Other clients | MCP reconciliation and authenticated dashboard evidence passed |

The actual host binaries used for that ceremony were:

- `opaque-approver`: `77f3af5122c25daf91f3f8e136c11440dd6704796a79e43a44cf2b2af9272145`
- `opaque-approve-helper`: `29fa348dd295245b298d8457c527db0b8c151471721aa0a23993efa66a108063`

Temporary custody and raw logs remain in `/private/tmp/orf-tao8l82b`; the automated
fixture is `/private/tmp/orf-y49m8kb6`. Only those runners' containers were removed;
their state volumes remain available for inspection. The proof belongs to the
recorded binary hashes; later Linux cleanup/test changes do not rewrite it.

The signature proves the enrolled application decision. It is not remote hardware
biometric attestation. Subjective comprehension was not surveyed. The screenshot
attempt occurred after the review closed, so no screenshot corroboration is
claimed. No real GitHub workflow, image pull, rollout or cluster change occurred.

## Real staging status

The fresh GET-only audit still reports **5 passed, 9 blocked, 2 operator-required**.
The destination is the active private repository with ID `1357845081`. Its owner
has administration access, but Actions are disabled, `main` is unprotected, and
there is no configured staging environment, observed staging workflow, or observed
private artifact package. Protected-resource absence/inaccessibility remains
distinct. Only the owner is a collaborator; plan information was unavailable.

The current contract requires independent review and effective protection against
other dispatch/ref-changing authority. The owner alone cannot supply independent
environment review. Required reviewers on private repositories also depend on the
GitHub plan. Reviewer and plan details were requested; no settings were weakened
or repository made public to bypass these prerequisites.

Local artifact tooling prepares committed source, builds a pinned `linux/amd64`
image, verifies its revision/user/entrypoint and performs the fixed version check
without a network or credentials. A local image ID is not a registry digest, and
local success does not establish publication or the workflow's private pull access.
See [artifact preparation](../../examples/staging-release/README.md).

The actual local artifact build and isolated smoke check passed against commit
`9681a7bbf16d216bbd06614439edd7bbb1636f60`:

```sh
python3 scripts/build_staging_artifact.py \
  --output-dir /private/tmp/opaque-staging-proof-20260905
```

The build took approximately three minutes. Inspection verified `linux/amd64`,
the exact source/revision labels, `/usr/local/bin/opaque` entrypoint and
`65532:65532` user. The fixed smoke command ran with no network, a read-only
filesystem, no capabilities and bounded CPU/memory/PIDs; it returned
`opaque 0.2.0+9681a7b`. Its local image identity is
`sha256:6d0c47833e8ae8f808569def78f351793aec7cdd728c6c8b0ee34d10fdbf92ff`,
tagged `opaque-staging-artifact:9681a7bbf16d-8c0a886b`. This is local image
evidence, not an observed registry publication/digest. The recipe SHA-256 was
`47cb5ef094873286d262e631b5e252ab95d963849fcc490dc1eef2af80c86906`.
Temporary source context/archive cleanup completed; build logs and the local
image remain available. Cleanup commands targeted only this task's uniquely named
fixture/smoke containers. Final inventory retained the original BuildKit and Talos
registry containers. Two unrelated `admachina-p1` containers seen at the initial
inventory were absent at the final check; this task did not stop or remove them,
and their lifecycle was not investigated.

The sanitized report is `/private/tmp/opaque-staging-proof-20260905/evidence.json`.
It explicitly records `published: false`, `registry_digest: null` and
`ready_for_live_dispatch: false`. A future approved `main` commit needs its own
matching artifact; do not substitute this development artifact for a different
approved commit. No repository setting, remote workflow, package or workload was
changed during this validation.

M1 is demonstrated. M2 requires the real private workflow, protection/reviewer
configuration, published immutable artifact, separately custodied live broker,
and one native-approved GitHub dispatch with correlated terminal evidence. The
fixture runner remains explicitly unsuitable for production credentials.

## Change validation

| Check | Result |
| --- | --- |
| macOS helper and approver | 16 tests passed |
| Shared daemon approval logic | 10 tests passed |
| Linux helper, including dialog child cleanup | 4 tests passed |
| Python native runner and staging preflight | 31 tests passed |
| Local artifact builder | 14 tests passed |
| Archived-source build metadata | Standalone Rust build-script regression passed |
| Clippy | Host helper/approver/daemon and Linux helper/approver, all targets, warnings denied |
| Final automated protocol repeat | Fresh Linux build and four test-signed tasks passed using the revised workflow; `/private/tmp/orf-im94dqf1` |
| Documentation | Strict build passed; 74 generated files checked for excluded routes and five new private-evidence markers, no matches |
| Source hygiene | Formatting, whitespace and redacted changed-source Gitleaks checks passed |

The prepared manual workflow's SHA-256 is
`469c6c9183550da43ad5d4c076f9b488738197fce4104fd03a2e43e009a1ba5b`.
The installed-path source and example are byte-identical. Their job guard requires
the exact private repository name, numeric ID and private visibility. This local
file does not establish remote installation or enablement. The earlier native
proof retains its actual historical workflow and binary identities.
