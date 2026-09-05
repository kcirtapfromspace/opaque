# Staging release dogfood with separate custody

This fixture runs the real broker, CLI, MCP server, and dashboard in separate Docker containers. A workstation outside those containers enrolls over pinned TLS and signs the complete, bounded release review. GitHub is a disposable loopback fixture: no workflow is installed, no image is pulled by a workflow, and no service or cluster is changed.

The release contract approves one dispatch of a specific workflow in `kcirtapfromspace/opaque-dogfood`, at an exact commit, with one immutable image digest and the `staging` environment. The reviewed workflow template at `examples/staging-release/opaque-staging-release.workflow.yml` performs an artifact smoke check. This runner simulates the repository and workflow responses locally; it never executes that GitHub workflow or establishes its live prerequisites. It is not a service rollout. Current milestone status is maintained in the private [roadmap](product/roadmap.md).

## Run the automated protocol check

Requirements: Docker with its Linux engine running, OpenSSL with Ed25519 support, Python 3, and the images referenced in the script. The runner uses `rust:1.95.0-slim-bookworm`, `debian:bookworm-slim`, and a pinned Python runtime image already distributed through Docker MCP. It starts Python directly; no MCP connector runs in that container. `--python-image` can select another operator-reviewed image with `python3`.

```bash
python3 scripts/release_dogfood.py --check
```

The script builds Linux binaries using the existing `opaque-linux-target` and Cargo cache volumes. It creates a short, isolated directory under `/private/tmp` on macOS, prints its path, and retains logs and public receipts after stopping its containers. `--no-build` reuses the Linux artifacts after a successful build.

The automated check uses a **TEST SIGNER**. There is no human approval ceremony. The trusted, sealed broker config sets `workstation_test_mode = true`, which permanently records `insecure_test` provenance on approved tasks. The challenge, enrollment, signature, expiry, allowlist, and broker authorization checks still run. The dashboard displays **TEST APPROVAL** even though its transport and broker are live.

Checks include:

- Broker UID 7381 and client UID 7382, custody absent from the client mount namespace, socket group 7999, and refusal of a broker-UID client.
- A separate private signing key, public-key enrollment allowlisted by trusted config, exact broker TLS pin, and signature over the full review hash and current challenge.
- A single charged dispatch per approved task. Repeating execution does not produce another provider POST.
- Separate workflow observations: pending, running, succeeded, failed, ambiguous, and external rerun.
- Direct provider run-ID evidence and the legacy exact-task-title correlation path.
- An uncertain dispatch followed by observed workflow success. The original dispatch remains unknown and its allowance remains consumed.
- Broker restart, durable receipts, and read-only MCP reconciliation without another dispatch.

## Keep a fixture running

```bash
python3 scripts/release_dogfood.py --serve --no-build
```

The default dashboard is `http://127.0.0.1:19393`; approval TLS is published only at `127.0.0.1:19443`. These ports do not replace the earlier secret-publication fixture on 19392. The runner prints exact container names, a fresh planned task ID, its CLI execution command, and its MCP command.

The automated signer stays available in this mode and is conspicuously labeled. To keep completed check receipts visible, reuse the check directory:

```bash
python3 scripts/release_dogfood.py --serve --no-build --data-dir /private/tmp/orf-REPLACE
```

Use **Check workflow** in the dashboard to refresh evidence. That endpoint can only perform daemon-scoped reconciliation. It does not approve, dispatch, retry, or create authority. Audit and policy files are deliberately not mounted into the client container; their dashboard tabs report that those local data sources are unavailable.

## Use the native workstation reviewer

For one complete human walkthrough, build the host reviewers and run:

```bash
cargo build --locked -p opaque-approver -p opaque-approve-helper
python3 scripts/release_dogfood.py --native-preflight
python3 scripts/release_dogfood.py --native-check
```

The preflight runs `opaque-approver check-native` without creating keys, enrolling,
opening an approval window, authenticating, or creating a task or container. It
checks the current desktop session and native authentication availability. A
successful probe does **not** prove that a human saw or approved a review. The
walkthrough repeats this check before building or starting its broker.

When Cargo uses a different target directory, pass the actual host binary
directory to both commands with `--native-bin-dir /absolute/path/to/debug`.
Both reviewer executables must be built from the current source. The retained
`native-readiness.json` records their SHA-256 hashes. Native Linux execution
preserves the current desktop connection metadata while excluding provider
credentials and unrelated environment overrides.

This starts a fresh isolated broker, enrolls the workstation public key, opens
the complete native review, and waits for the human decision and authentication.
It never supplies a decision or substitutes the automated signer. On acceptance,
it verifies exactly one fixture dispatch, workflow reconciliation, denied replay,
receipt persistence and replay denial after broker restart, plus MCP and dashboard
checks. It then stops only its own containers and retains the private fixture
directory. `--no-build` may be used only after a current Linux build has passed.

`native-approved-receipt.json` and `native-review-evidence.json` record a completed
`paired_workstation` outcome. Rejection, expiry, missing native UI, test provenance,
an unknown effect or an unexpected dispatch count cannot produce a passing human
milestone. Logs and key material stay in temporary private custody, never Git.
This proves the exercised workstation application/protocol path against a
disposable provider, not hardware biometric attestation or real GitHub execution.

`native-progress.json` identifies the current stage: challenge, review, task
completion, receipt validation, reconciliation, replay, restart, or MCP/dashboard
verification. A failure at any of those stages records a failed milestone,
including failures after a valid human approval. `native-review.log` retains
fixed native stage diagnostics. The review deadline remains 90 seconds; the
separate native authentication deadline remains unchanged. A timeout reports the
last observed helper stage; an ordered window is not proof of human visibility.
Use a fresh fixture directory for each native check so an earlier result cannot
be overwritten by a later attempt.

For manual exploration instead of the automatic post-review checks:

Build the host binaries, then create a fresh fixture directory:

```bash
cargo build -p opaque-approver -p opaque-approve-helper
python3 scripts/release_dogfood.py --serve --native --no-build
```

The runner initializes host approver state, inserts only its public key into the sealed broker configuration, and enrolls it against the exact TLS fingerprint obtained through the trusted Docker operator channel. It never mounts workstation private state into the broker or agent. It prints a task execution command and the following review commands with the actual state path:

```bash
opaque-approver list --state-dir /private/tmp/orf-REPLACE/approver
opaque-approver review --state-dir /private/tmp/orf-REPLACE/approver --approval-id APPROVAL_ID
```

Start the task command, list its pending approval, then review the complete document in the native approver. The broker verifies the signed decision. Native approval requires a supported interactive workstation session and fails closed when its review ceremony cannot run. The receipt records `paired_workstation`; the broker trusts the enrolled workstation's review application and key custody. A remote Ed25519 signature alone does not attest that a biometric sensor was used.

Use a fresh directory when changing native/test signing modes. Historical approval provenance belongs to each task and is never inferred from the current broker configuration.

## What the evidence means

| Evidence | Meaning |
|---|---|
| Dispatch API accepted | GitHub accepted the one approved request; it is not a deployment result. |
| Run ID from dispatch response | The receipt retained the provider's direct run identity. Reconciliation reads that exact run. |
| Matched task correlation title | A legacy response supplied no run ID. The broker matched the exact task ID and manifest digest plus repository, workflow, branch, commit, and event. |
| Workflow succeeded | The correlated reviewed workflow reported success. This does not establish service health beyond that workflow's own checks. |
| Workflow evidence ambiguous | Multiple matches, mismatched evidence, or an external rerun prevent a clean execution claim. |
| Unknown dispatch | The request may have reached GitHub. Its authority stays consumed even if later workflow evidence is available. |

## Isolation and cleanup

The agent sees the Unix socket volume, public manifest, and executable binaries. It does not receive provider credentials, broker custody, workstation private keys, or the Docker socket. The broker receives only the workstation public key. The fixture provider holds only a fake token and public test inputs. A local relay publishes the dashboard while preserving its loopback Host/Origin checks and bearer authentication.

The Docker host operator remains trusted and can inspect container volumes. This is a real container and UID boundary against the workload client, not protection from the host administrator. No macOS account, launch service, home directory, production credential store, or cluster configuration is modified.

Ctrl-C stops this runner's signer and removes this runner's containers. Its uniquely named broker/socket volumes remain for inspection and restart; the exact removal command is saved in `cleanup.txt` under the printed state directory. Existing unrelated containers and the earlier dogfood session are left running.
