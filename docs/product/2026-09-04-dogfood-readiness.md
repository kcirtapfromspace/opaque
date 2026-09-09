# Bounded work: implementation and dogfood handoff

> **Historical evidence — September 4, 2026.** Current priorities and completion
> gates are in the [private milestone roadmap](roadmap.md). This note preserves
> its original implementation, test counts and temporary runtime references;
> those references are not a current session inventory. Later work adds separate
> broker/workstation review. Unchecked historical PRDs are not today's checklist,
> and public repository examples below are not current dogfood destinations.

This records the first, secret-publication increment. The subsequent
[remote approval and staging-release increment](2026-09-04-remote-release-readiness.md)
adds a separate broker trust boundary, paired workstation review, and read-only
workflow reconciliation. The limits and test counts below describe this earlier
snapshot.

The first working slice is a fixed GitHub Actions secret-publishing task. An
agent can plan exact writes, an owner can review the complete manifest and
approve it once, and the broker can publish pinned Vault values while retaining
a receipt for every attempted slot. This implements the proving workflow from
the [product strategy](2026-09-04-product-strategy.md); customer demand remains a
hypothesis to test.

## What is implemented

- Immutable manifests bind provider URLs, repository numeric IDs, exact secret
  names, pinned Vault KV v2 versions, credential references, and expiry.
- A private SQLite ledger admits one run per task and permanently charges each
  slot before preparation. Concurrent callers, changed agent sessions, failures,
  cancellation, and restarts cannot refill the task's allowance.
- Every child operation passes policy checks. Native review shows the complete
  manifest in a scrollable window, followed by fingerprint-bound biometric
  authentication. Task grants currently require the native `local_bio` factor;
  alternate review surfaces are not enabled for this workflow.
- A final authority check immediately before publishing observes task expiry,
  revocation, policy changes, and expired or disabled agent identities. A request
  already authorized for dispatch cannot be recalled.
- Outcomes distinguish API acceptance, rejection, and unknown effects. Partial
  runs return their receipts and signal failure to CLI/MCP automation. Unknown
  slots remain consumed; they cannot be retried under the old task.
- Receipts retain whether approval was native, insecure test approval, or an
  older record whose approval mode was not recorded. Changing daemon settings
  does not relabel historical test approvals as human consent.
- CLI and MCP expose plan, run, show/get, list, and revoke. Lists paginate within
  the IPC size limit. The dashboard displays owner-scoped receipts, authenticated
  live audit updates, and explicit disconnected/test/demo states.
- The unsigned AWS transport is restricted to explicitly configured loopback
  mocks. It is not production AWS support.

## The three targets

| App | Repository | Verified local checkout |
| --- | --- | --- |
| Opaque | `kcirtapfromspace/opaque` | `/Users/thinkstudio/opaque` |
| No Drake in the House | `kcirtapfromspace/no_drake_in_the_house` | `/Users/thinkstudio/repos/no_drake_in_the_house` |
| Adanima | `Nereus-Data/admachina` | `/Users/thinkstudio/ai_ad_agency` |

Repository identities were checked through local Git remotes and GitHub's read
API. The live templates in `examples/dogfood/README.md` propose six disposable
marker writes and a manual-only consumption-check workflow. Those Vault fields
have not been provisioned, and no live secrets or workflows were changed.

## Start testing

From the Opaque checkout:

```bash
python3 scripts/dogfood.py --check
python3 scripts/dogfood.py --serve
```

The first command exercises the real daemon, CLI, MCP server, dashboard, and
durable state against local provider fixtures. The second leaves a dashboard
and a fresh task available for exploration. It prints the precise socket,
manifest, CLI, and MCP commands. Default fixture approval is explicitly insecure
and uses disposable values. Use `--serve --native` to test actual review and
biometric prompts against the same disposable providers.

See the [dogfood guide](../dogfood.md) for expected behavior, retained evidence,
restarts, and isolated state directories.

## Verification on this checkout

On September 4, 2026, the complete workspace test run passed: 1,564 tests
passed, none failed, and three were ignored. This includes the existing
federation, identity, and provider end-to-end tests alongside the new task,
approval, provider, CLI/MCP, and dashboard coverage. `cargo clippy --workspace
-- -D warnings` and `cargo fmt --check` also passed.

The task tests cover concurrent run attempts, permanent slot consumption,
cancellation, restart recovery, revoked or expired authority, policy changes,
workspace verification, source version and repository identity binding, and
approval provenance. These results establish the exercised implementation
contract; they do not establish production deployment or product demand.

The final `python3 scripts/dogfood.py --check` passed against the built binaries.
It observed six encrypted fixture writes, blocked replay, one charged unknown
outcome, persisted receipts after daemon restart, authenticated dashboard reads,
and discovery/read/list/replay checks through the actual stdio MCP process.
The MCP process received the isolated socket without provider credentials.
Public manifest digests, source references, and test-approval provenance remained
intact, and no fixture plaintext appeared in receipts or MCP responses.

This run's retained local evidence is in `/private/tmp/odf-pmjmfywh`: daemon and
MCP logs, `mcp-responses.json`, `fixture-writes.jsonl`, manifests, and durable
receipt databases. These temporary paths are local to this machine; the runner
recreates an equivalent environment when needed.

The handoff session is serving at `http://127.0.0.1:19392` using that directory.
It contains completed and unknown-outcome receipts plus a fresh six-slot plan.
An agent can connect using this command, without provider credentials:

```bash
env -u OPAQUE_SESSION_TOKEN \
  OPAQUE_SOCK=/private/tmp/odf-pmjmfywh/run/opaqued.sock \
  /Users/thinkstudio/opaque/target/debug/opaque-mcp
```

The current session uses explicitly labeled insecure test approval. Its planned
tasks expire after one hour; create a fresh plan from the retained
`manifest.json` when needed. Restart this same session with:

```bash
python3 scripts/dogfood.py --serve --no-build \
  --data-dir /private/tmp/odf-pmjmfywh --port 19392
```

## What this does not establish

This is a shared-UID developer installation. Other processes with the same OS
account can alter local state; it is not a demonstration of a dedicated broker
trust domain. Task access is scoped to the authenticated owner, with fresh
workspace checks at execution. It is not isolation between sibling agents.

The provider fixture proves protocol behavior and accounting. It does not prove
real GitHub/Vault credential permissions, external availability, or application
deployment. GitHub repository identity checks precede the name-based write;
the provider does not offer this workflow an atomic compare-and-set across a
repository rename or transfer. GitHub acceptance also cannot prove a stored
secret's plaintext, safe downstream workflows, or ongoing confidentiality.

The native macOS review window was rendered and visually inspected. Scrolling
through the final action and completing biometric approval still need a human
dogfood session. Linux native review code is included but was not built or
exercised on this macOS host. The mobile approval product remains
outside this increment.

## Product experiment

Use this session to observe whether an owner can identify the targets, source
versions, budget, expiry, and meaning of an unknown outcome without explanation.
Record time to first successful task, approval-reading time, interventions,
incorrect interpretations, and whether they want to repeat the workflow.

After the local walkthrough, provision disposable live marker sources, review
the constrained policy, and run one native-approved task. Install the optional
manual marker-consumption workflow only through each repository's normal review
process. Then repeat with agents from the three applications and compare setup
and recovery effort with the existing manual process.

The next build decision should follow those observations: improve onboarding
and receipt clarity first; add stronger broker deployment and protected
destination controls where needed; expand operations only after repeated useful
work. Attestation and more general delegation remain possible extensions, not
evidence that the product already fits the market.
