# Remote approval and staging-release readiness

Opaque now has a second bounded task: approve one reviewed staging workflow
dispatch, then inspect the resulting workflow without granting another attempt.
The shared task ledger also supports a trusted workstation signing the full
review for a broker running under a separate container and OS identity.

The product hypothesis remains: an owner can grant an agent enough authority to
finish useful work, understand exactly what that grant permits, and recover from
uncertain results without handing over reusable provider credentials.

## Implemented contract

- A trusted broker configuration allowlists a workstation public key. Enrollment
  proves possession over TLS pinned through an operator-trusted channel.
- Approval binds the broker, request, operation, complete review-text hash,
  nonce, decision, and expiry. Altered, unsigned, replayed, expired, cancelled,
  removed, and revoked approvals fail closed. The broker trusts the enrolled
  workstation application and key; its signature does not remotely attest a
  biometric sensor.
- Production workstation review displays the full document, then invokes the
  native approval ceremony. The automated fixture uses a separate test signer
  with permanent `insecure_test` receipt provenance. It does not claim human
  approval.
- A version-two task contains exactly one staging workflow action. It binds the
  numeric repository and workflow IDs, protected branch, exact observed commit,
  trusted workflow SHA-256, immutable image digest, environment, and credential
  reference. Version-one secret tasks retain their wire format and approval
  digests.
- The broker rechecks the workflow contract and live task authority before one
  dispatch POST. Redirects and transport retries are disabled. Unknown effects
  consume the same durable allowance as accepted effects.
- Read-only reconciliation has its own scoped policy. A direct provider run ID
  is preferred; legacy/unknown responses use explicitly weaker title correlation.
  Mismatches, duplicate matches, and externally rerun workflows become ambiguous.
  Observation cannot replenish authority or erase the original dispatch result.
- The CLI, MCP, and dashboard show dispatch acceptance separately from workflow
  state. Workflow success means the reviewed workflow succeeded, not that every
  downstream service is healthy.

The staging workflow template described in `examples/staging-release/README.md` is an
artifact smoke check. No actual application rollout, workflow installation, or
live dispatch is represented by that fixture. Branch protection and the exact
reviewed workflow are part of the trusted execution boundary: GitHub's dispatch
API does not atomically pin its branch to the broker's observed commit.

Workspace verification now isolates Git status metadata from agent-controlled
configuration. Active external filters, including Git LFS filters, and unsupported
index/checkout forms fail closed when a task supplies workspace context. See the
[security review](2026-09-04-release-security-review.md) for the reproduced issue,
fix, exercised boundaries, and remaining process-isolation work.

## Run and inspect

```bash
python3 scripts/release_dogfood.py --check
python3 scripts/release_dogfood.py --serve --no-build
```

The default release dashboard is `http://127.0.0.1:19393`. The previous
secret-publication fixture uses 19392. Each runner prints isolated state paths,
task commands, and cleanup instructions. See the
[release dogfood guide](../release-dogfood.md) for native workstation setup,
container custody, exact evidence semantics, and restart instructions.

## Local evidence

Final native validation on September 4, 2026: **1,609 workspace tests passed,
zero failed, three ignored**. `cargo clippy --workspace -- -D warnings`,
`cargo fmt --all --check`, and `git diff --check` passed. The ten focused workspace
regressions include late filter changes, concealed dirtiness, FIFO metadata,
subprocess deadlines, output overflow, stdin preservation, and child cleanup.
The dashboard's five JavaScript behavior tests passed; browser inspection found
zero console errors or warnings and no overflow at a 390-pixel viewport.

The complete Docker release fixture passed with four separate tasks and one
dispatch per task. It exercised broker UID 7381 versus workload UID 7382,
unavailable custody from the workload container, pinned TLS, signed test review,
direct run identity, legacy correlation, success/failure/ambiguity, an externally
rerun workflow, an unknown dispatch followed by observed success, durable
receipts after restart, replay denial, and authenticated MCP/dashboard
reconciliation without additional dispatches.

Retained public receipts and logs are in `/private/tmp/orf-f7vvy6n0`. The running
19393 fixture uses this directory. Its approvals are explicitly test approvals;
historical receipts retain that provenance. A fresh plan expires after one hour.
The final Docker check passed in `/private/tmp/orf-piqr8srl`. The refreshed live
daemon's binary hash matches that checked build; `final-refresh-evidence.json`
in the retained directory records that match and preservation of the original
four dispatches. The latest planned task is
`bc004b9c-488f-4e44-989f-ac2f0c823068`.

Run that disposable, test-signed task or connect an agent through MCP:

```bash
docker exec opaque-release-2149bc22202e-agent /opt/opaque/opaque \
  --socket /run/opaque/opaqued.sock task run bc004b9c-488f-4e44-989f-ac2f0c823068
docker exec -i opaque-release-2149bc22202e-agent /opt/opaque/opaque-mcp
```

The earlier secret-publication regression also passed with six encrypted fixture
writes, replay denial, a consumed unknown slot, and restart/MCP checks; its latest
check evidence is in `/private/tmp/odf-3gkyudcj`.

The actual host workstation CLI was separately built and exercised against fresh
Docker brokers: key initialization, trusted public-key enrollment, pinned TLS,
private custody, and pending approval listing passed. Evidence is retained in
`/private/tmp/orf-zi5if3xx/native-setup-evidence.json` and
`/private/tmp/orf-c7ykozfc/native-setup-evidence.json`. Those temporary containers
were removed. No native review was opened, decision signed, or provider request
dispatched during those setup checks.

These paths are temporary local evidence, not portable dependencies. The runners
recreate the environment. No fixture establishes real GitHub permissions,
application rollout, model accuracy, GPU capacity, or market fit.

## Validation priorities

1. **Complete a human review across the broker boundary.** Can the owner identify
   the repository, artifact, destination, allowance, expiry, and consequence of
   an uncertain request without coaching? Record review time, mistakes, and
   interventions. Automated signatures alone cannot answer this.
2. **Perform one useful staging operation.** Install and protect the exact
   reviewed workflow through the application's normal process, provide narrowly
   scoped broker credentials, then observe the native-approved task end to end.
   Use fresh authority for retries and rollback. Begin with Opaque; reuse the
   contract for No Drake in the House and Adanima after their destinations and
   workflow contracts are specified.
3. **Demonstrate bounded inference on the existing cluster.** The read-only
   inspection found three reserved Jetson GPUs and an existing ready Gemma
   endpoint. Start with three serial requests through a fixed model/service
   contract once its owner allocates access and load. The
   [GPU assessment](2026-09-04-gpu-showcase.md) records the exact observations,
   proposed limits, remaining inputs, and suspended future Job template.
4. **Test repeat use and recovery.** Measure time from a new checkout to a useful
   receipt, denied scope changes, interpretation of unknown outcomes, and whether
   owners willingly use the same flow again. Add operations in response to those
   observations.

The GPU inference provider and Kubernetes operator are not implemented by this
increment. A narrow inference or fixed Job operation should prove demand and
authority semantics before introducing controller reconciliation. Signed SSH
certificates remain a candidate for a concrete deployment or host-access task;
general shell access would require a separate scope and validation exercise.

No live workflow, model request, model download, GPU reservation, or cluster
mutation was performed during this implementation. The existing GPU workloads
remain in place. Native human approval and live provider effectiveness remain
explicit next dogfood checks.
