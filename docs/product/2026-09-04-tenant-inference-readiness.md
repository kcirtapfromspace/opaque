# Tenant-scoped data and model access: readiness

> **Historical evidence — September 4, 2026.** The
> [private milestone roadmap](roadmap.md) is the current checklist. Later work
> built and demonstrated a scoped HTTP OAuth/MCP gateway, GPU-backed synthetic
> analytics and a demo lifecycle controller. The evidence limits and iteration
> order below describe this earlier inference snapshot. Real-source/production
> IdP integration, general attestors and bounded SSH retain separate gates.

Opaque now binds a fixed inference task to an authenticated principal, an immutable tenant/broker lineage, a trusted source snapshot, a model destination, and three permanently consumed attempts. This is the first executable slice of the data-governance direction described in [tenant boundaries](../tenant-boundaries.md). The model requests work; the broker grants or denies it.

## Implemented

- A tenant installation requires enforced broker/agent custody separation. An immutable private marker and lifetime lock prevent silent adoption, tenant reassignment, missing-marker recovery, and reuse of another broker’s ledger.
- OIDC login validates code/PKCE, issuer, audience, signature, nonce and expiry. Tenant inference additionally requires an explicit issuer-local subject allowlist. Membership, service declarations, human-session state and delegation validity are checked again during use.
- Agent delegation can receive full signed review on an enrolled workstation using the trusted `approval.session_factor` setting. Native approval remains the default. Role changes require fresh native review and atomically protect the last admitted human administrator.
- Schema 3 fixes three compiled public prompts, their source snapshot and hashes, the exact model/profile/destination, 512 input tokens, 96 requested output tokens per attempt, and a 30-second client deadline. Expiry is at most 600 seconds. Unknown outcomes consume allowance and stop later slots.
- Trusted review shows the actual destination URL, service identity, model path, build and template hash, operator-attested model digest, complete prompts and disclosure purpose. A changed route or profile requires a new manifest and approval.
- CLI `opaque task plan-inference` and MCP `opaque_task_plan_inference` create the server-selected plan. CLI/MCP run the existing durable task protocol; the dashboard renders tenant-bound results as text with separate reserved and observed usage.

## Validation

The full native workspace suite passed **1,654 tests**, with **0 failures and 3 pre-existing ignored tests**. Clippy passed with warnings denied; formatting and whitespace checks passed. Eight dashboard tests passed, including safe output rendering and no retry authority after uncertainty. Focused tests exercise scope tampering, provider limits, policy change during approval, membership removal, cross-broker ledger reuse, signed review changes and atomic role management.

The executable two-tenant Docker harness, `scripts/tenant_dogfood.py`, also passed end to end. Each tenant produced exactly four provider completion requests: three successful fixed requests and one unknown outcome in a separate task. Replay, cross-tenant authority, direct provider access from the agent, MCP replay, and broker restart produced no additional generation requests. The fixture exercised real OIDC and signed delegation/task protocols with a disposable issuer, model stub and automatic test signer. It is not evidence of human consent or private warehouse isolation.

The retained run is `/private/tmp/otf-x1fwo4vx`, with `live-summary.json` and per-tenant custody, MCP, restart, dashboard and receipt evidence. Its dashboards are [tenant A](http://127.0.0.1:19394/) and [tenant B](http://127.0.0.1:19396/). The existing secret and release dashboards on ports 19392/19393 remain separate. Reproduction and lifecycle details are in the fixture runbook at `examples/tenant-inference/README.md`.

An independent review strengthened the network evidence: disposable canaries bound to each fixture's network interface were reachable from the corresponding broker-shared network namespace, while both agents failed connections to both canaries. Each tenant's `network-canary-evidence.json` records the positive control, negative probes and unchanged provider request counts. This validates those container network paths; it does not attest a microVM or a real data store's authorization.

Browser inspection verified tenant A at 1280 pixels and tenant B at 390 pixels, including expanded completion receipts, clear test-approval labels and tenant-specific contents. Both body and document widths matched the viewport, and neither page logged console warnings or errors. Mobile receipts use stacked labeled fields. `browser-evidence.json` records the check; `web-update-evidence.json` records the dashboard-only binary refresh. The brokers and receipt ledgers were preserved, with four completion requests per tenant. The final MCP description changes also passed its 37 focused tests.

## Evidence limits and next work

This revision’s data source is a compiled synthetic snapshot and its model endpoint in the fixture is a protocol stub. It does not query the application databases, integrate Oleander, implement a remote HTTP OAuth resource server, run GPU inference, launch ArcBox, or establish hardware attestation. Model/file/service hashes are trusted operator assertions, not independent measurements. A client timeout cannot prove backend cancellation or GPU billing.

The next useful increment is a named, read-only DuckDB query over two disposable tenant snapshots: separate worker mounts and source credentials; typed parameters; reviewed columns/predicates; row and byte limits; then a separate grant to disclose the result to a named model. Prove cross-tenant reads and unapproved disclosure fail before adding routing flexibility, Kubernetes reconciliation, or SSH authority. The live cluster’s current constraints are recorded in [tenant discovery](2026-09-04-tenant-data-discovery.md).

For HTTP/MCP consumers, add a distinct OAuth resource-server boundary with recipient-bound access tokens and explicit data scopes. Existing OIDC login and the internal delegation protocol do not constitute that transport. [The design note](../tenant-boundaries.md) maps the proposed grant to resource indicators, protected resource metadata and optional Rich Authorization Requests.

## Iteration order

| Priority | Product behavior | Required dogfood evidence |
|---|---|---|
| 1 | A tenant member authorizes a named data read and separately authorizes model disclosure. The connected agent can finish that useful task within the approved limits. | Two disposable tenant snapshots; a successful allowed query; denied foreign-source, excess-column/row/byte and unapproved-model requests; revocation and expiry prevent subsequent access. |
| 2 | A remote client enters the same flow through a proper OAuth resource-server boundary. | A configured authorization server; exact audience and tenant checks; required scopes; wrong-resource access tokens and ID-token substitution denied; provider credentials remain broker-local. |
| 3 | An isolated worker executes the granted job, with a verified lifecycle and restricted destination access. | Separate mounts and identities; positive and negative network controls; no broker credentials in the worker; enforced limits; observed teardown and result cleanup. A live GPU trial starts with public synthetic data. |
| 4 | A Kubernetes controller installs and maintains the already-proven tenant deployment. | Reconciliation preserves tenant/broker lineage, cannot expand grants, detects policy drift, and reports failed isolation or unavailable GPU capacity. |
| Later | Signed SSH certificates authorize a specific operational workflow. | A demonstrated customer task that needs SSH, with restricted principals/destinations and expiry. General shell access is not required for the current data-read product. |

Treat routing engines and runtime providers as adapters behind these boundaries. Validate one source and one model destination first; adding connectors is useful only after the approved work and denial behavior can be demonstrated together.

## Local runtime recovery

Fixture iteration encountered host disk pressure, which caused Docker I/O errors. Only generated failed-run binaries and Opaque’s regenerable Rust incremental cache were removed; roughly 27 GiB was recovered from the latter. Docker startup then encountered the documented helper/CLI startup issue; a minimal-environment Desktop restart recovered the API. No Docker disk, image, volume or container metadata reset was performed. The existing release containers, dashboard and retained test signer were restored, as was an unrelated container whose command was verified to be an idle keepalive. Prior task records remained readable.
