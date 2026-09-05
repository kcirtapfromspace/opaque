# Hosted demo validation

Validation date: **2026-09-04 (America/Denver)**. This record distinguishes live
production observations from local tests. It does not establish production
customer data isolation or attest the shared model service.

This historical record covers the operational-metrics pilot. Credit-portfolio
checks and rollout status are recorded separately in
[CREDIT-VALIDATION.md](CREDIT-VALIDATION.md).

## Deployment identity

| Item | Recorded value |
| --- | --- |
| Public entry point | `https://demo.opaque.info/` |
| Worker version | `00d6976b-ba84-4a7a-a2fe-3c4164c3acf8` |
| Main-site Pages deployment | `https://c9d71290.opaque-3pv.pages.dev` (production branch `main`) |
| Runtime image | `192.168.25.201:5050/opaque-hosted-demo@sha256:0906c9987c03682084190ed237788aedf969b8623e61f56ac80d738ebf6ca117` |
| Tunnel image | `cloudflare/cloudflared@sha256:51c9cefcb4569df44e1ad403ab1d3d8065aa8e84339bcfc6aee75502e1140339` |
| Tunnel | `19b53ba6-3242-4456-a1ac-11d2dcaa5f7e` |
| Workers VPC service | `01a06f35-01e7-7f30-b3ca-bd99e3a7a673` |
| First live lease | `7273b41ac1ec4e6690a4fc6895ef9b8d` |
| First tenant | `demo-7273b41ac1ec4e6690a4fc6895ef9b8d` |

Image metadata is retained at
`/private/tmp/opaque-hosted-demo-rendered/images.json`. Temporary evidence paths
are local working records; copy required evidence to durable operator storage.

## Live observations

Final release check: `opaque.info/` and `opaque.info/hosted-demo/` returned 200
with the public demo link. Demo admissions remain enabled at capacity one. Both
test workspaces were ended and removed; the slot is empty with its retained
generation-4 cleanup tombstone. Controller and tunnel Deployments are each 1/1
available. Temporary local test servers were stopped.

The coordinating operator used the normal production browser flow, with real
Turnstile and no fixture proof, copied visitor credential or bot bypass.

| Check | Result |
| --- | --- |
| Public configuration | `available:true`, `capacity:1`, `session_seconds:600`; independently fetched from the public endpoint |
| Bot verification and admission | First browser admitted through real Turnstile |
| Provisioning | First lease reached Kubernetes and browser readiness with the tenant binding above |
| Scoped live metrics | Gemma-assisted error-rate watch issued five scoped source queries and displayed five snapshots, followed by an answer reporting 7.69% |
| Denied metric | Request for p95 latency was denied; `source.aggregate_queries` stayed at five, so the denied request added no source query |
| Cancellation and cleanup | **Passed at 19:59:06 MDT**: End session entered cleaning; the slot namespace contained no lease Pods, Services or Secrets; retained state advanced to generation 2 with the first lease's cleaned tombstone |
| Access after cancellation | Old browser's `/workspace` request returned HTTP 410 |
| Reprovisioning after cleanup | **Passed** through a new normal Turnstile flow: lease `21edda65c59a454b8f6a2ab71291663b` reached Running/ready with tenant `demo-21edda65c59a454b8f6a2ab71291663b`; retained state and provision generation were both 3 |
| Independent two-visitor queue handoff | **Not demonstrated live**: the second isolated browser required an interactive Turnstile check and did not submit a request |

The 7.69% value records that particular synthetic snapshot; it is not a constant
or promised result. The first lease's displayed expiry was 20:05:34 MDT. This
record does not imply that the same lease remains usable after its deadline.

The second-browser bot check screenshot is retained at
`/private/tmp/opaque-hosted-public-visitor-b/bot-check.png`. That browser was
closed after recording the block. No CAPTCHA was solved or bypassed by the
automation. Its console included a blocked Cloudflare analytics beacon under
the restrictive page CSP and warnings originating inside the challenge frame;
these are not a clean-console claim for the production visit.

## Tests and admission checks

- **57 JavaScript tests passed**, including UI, HTTP authorization and durable
  queue behavior. SQLite/concurrency checks cover queue coordination locally;
  they are not evidence of a live second visitor taking over a slot.
- **22 Python controller tests passed** with fixture Kubernetes and loopback
  proxy behavior, including generation, cleanup and uncertainty fences.
- An actual local Wrangler/SQLite smoke passed **13 checks**: admission,
  provisioning state, foreign visitor rejection, duplicate-cookie rejection,
  exact Origin, rejected client priority, protected internal routes, CSP hashes,
  cancellation entering cleanup and denied workspace access. Evidence:
  `/private/tmp/opaque-hosted-worker-review/evidence.json`. This local run used
  explicit loopback test bot mode and the installed runtime's 2026-04-27
  compatibility date; it did not validate production Turnstile or VPC routing.
- Target-cluster server dry-runs accepted the positive runtime Pod and rejected
  **six negative resource-quantity admission cases**. Dry-run acceptance does
  not establish scheduling, networking or cleanup behavior.

## Remaining boundaries

The runtime uses synthetic source events and a disposable identity. It does not
admit arbitrary visitor code or production credentials. Runtime images are
digest pinned, but the existing shared Gemma executable/model have not been
verified as immutable. The model is a trusted processor shared with other
cluster clients, outside the demo's own concurrency budget.

Flannel has no verified NetworkPolicy enforcement in this cluster. Namespace,
RBAC, restricted Pod Security, admission rules and authenticated proxies do not
establish a network boundary against a compromised process. Internal registry,
model and origin hops include HTTP. This deployment is not a microVM, TEE,
confidential inference service or hardware-attested enclave.

Follow [OPERATIONS.md](OPERATIONS.md) for deployment and pause/drain rollback.
Never reset the retained slot ConfigMaps or Durable Object state to clear an
uncertain lease. Cleanup and reuse require evidence of resource deletion and
stopped execution, including potentially outstanding remote model work.
