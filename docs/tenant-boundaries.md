# Tenant boundaries, data routing, and scoped execution

Opaque should let a user authorize useful work across data sources and models while keeping the authority understandable: **these sources, these columns and rows, this purpose, these permitted processors, this output destination, and this budget until this deadline**. A model may request work within that envelope. The broker resolves the request and enforces the limits deterministically.

Oleander's router selects an engine and machine size from query structure and source metadata, exposes its decision, and supports an explain step. Opaque's proposed integration places an authorization envelope around that routing: an engine change, additional source, larger disclosure, or more expensive machine must remain inside the approved choices or require a new grant. Routing and lineage are useful evidence; neither grants access. [Oleander query routing](https://docs.oleander.dev/platform/query-routing/overview).

## What this revision implements

The first tenant mode uses one independently deployed broker per tenant. It requires `trust_domain.enforce = true`; there is no tenant mode that silently treats two directories under one shared agent/broker UID as isolation. The operator must provide separate broker custody using OS accounts or isolated container/VM mounts, tenant-specific socket access, keys, credentials, workspace access, and state volumes. A host administrator or shared container runtime administrator remains trusted.

The sealed daemon configuration chooses a canonical tenant ID. Startup creates an immutable `TenantBinding { schema_version, tenant_id, broker_id }` in a private, fsynced `tenant.binding.json`. The accompanying exclusive lock permits one active broker per state directory and acts as an initialization witness. Changing the tenant, removing its marker, starting in legacy mode over tenant state, or adopting an existing unbound ledger fails closed. Backups must preserve the binding and ledger together; tenant renaming or migration requires an explicit offline procedure, which is not implemented here.

Task ownership includes the complete tenant and broker binding plus authenticated UID/principal. Schema 3 allows exactly three inference slots, each requesting at most 512 input tokens, 96 output tokens, and a 30-second client deadline; task expiry is at most 600 seconds. The immutable manifest includes the bound profile, model artifact assertion, source snapshot, prompt hashes, credential reference, and fixed options. A slot is reserved durably before dispatch. Rejection, interruption, or unknown delivery never restores its allowance. Completion evidence must match the action and tenant, and cannot claim fewer reserved units based on observed usage. Existing schema 1/2 manifest encodings and approval digests remain stable.

This implemented inference slice uses fixed synthetic public source records. It does not execute live warehouse queries, connect to Oleander, launch ArcBox, attest model weights, or prove GPU billing/cancellation behavior. An operator-attested artifact hash is labeled as such. Provider output in these synthetic receipts is bounded and checked; private data workflows will need a separate retention and disclosure policy.

## Three different kinds of authority

| Authority | Establishes | Does not establish |
|---|---|---|
| Human login / delegated identity | Verified subject, actor, login state, current role and delegation validity | Dataset membership, a provider credential, or permission to disclose data to a model |
| Tenant data-source credential | The broker/query worker's permitted access to one configured upstream resource | Permission for every logged-in user to read that resource |
| Approved task grant | Exact permitted action, data scope, destination, attempts, deadline, and evidence requirements | General ownership of the provider credential or a reusable unrestricted API token |

Tenant inference requires `identity.required = true` and an explicit `identity.allowed_subjects` allowlist under the configured issuer. Admission is checked before the first-human admin bootstrap and on live delegation use. Removed subjects, changed issuers, and removed service principals cannot keep using persisted authority. Role changes require fresh native review, and the last admitted human administrator is protected by an atomic ledger update.

For remote use, `[approval] session_factor = "paired_workstation"` routes agent-session creation through the enrolled workstation. The full review names tenant, broker, UID, stable subject, mode and lifetime. Its default remains native approval. This grants a delegation; each inference task still requires its own exact-scope approval.

The existing OIDC code is a login relying party: discovery, authorization code with PKCE, signature/issuer/audience/expiry verification, and nonce checking. Reuse that login and the current principal/delegation revocation checks. Existing federation bundles and teams can supply policy membership **inside** a tenant. They do not create tenant custody. Tenant membership must be configured against a stable issuer/subject identity or another verified immutable identity; matching an issuer, email domain, display label, or team name alone is insufficient.

A future HTTP/MCP resource server should verify access tokens for its exact resource audience and configured trusted issuer, then check tenant membership and scopes against broker policy. It must reject ID tokens as resource grants, unsupported algorithms, wrong audiences, expired/revoked authorization, and caller-supplied tenant overrides. Resource indicators bind the intended recipient, while protected resource metadata advertises the resource and supported authorization servers. These are future transport capabilities, not present tenant-mode endpoints. [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html), [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html).

Use a distinct verified access-grant type after token validation; a deserialized claims object must never be sufficient authority. For JWT access tokens, apply the access-token profile and distinguish their token type from ID tokens. Keep provider credentials tenant-local and obtain provider-specific authorization separately; do not pass an Opaque bearer token through to an unrelated upstream. [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html).

Scopes can name broad capabilities such as `datasource.read` and `inference.invoke`. Resource-specific details should also bind the full tenant/broker identity, subject/actor, dataset snapshot, named query, allowed columns and predicates, row/byte ceiling, purpose, model destination, approved manifest digest, expiry, and grant ID. Where the authorization server supports Rich Authorization Requests, this envelope can map to a registered `authorization_details` type. Otherwise keep it as a broker-local grant referenced by an opaque identifier. Either way, the durable ledger enforces attempts and revocation; a signed scope string does not implement a budget. [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html).

## The next data slice

Build a read-only named DuckDB query over two disposable synthetic tenant snapshots before adding a generic cluster controller or remote command capability. Each tenant gets a separate query worker and source mount. A server-selected source handle resolves to an immutable snapshot and a reviewed query template with typed parameters. The agent supplies neither a connection string nor SQL.

The broker evaluates permitted source, columns, row predicate, purpose, result size and retention before opening the source. The worker has no write capability, arbitrary `ATTACH`, extension installation, external URL reader, or unrestricted filesystem access. Result metadata records the selected snapshot, query/template hash and output hash. Disclosing that bounded result to a model requires a separate destination-bound approval. A data-read permission alone must not authorize inference.

An eventual Oleander adapter may offer several approved engines or cost tiers. Its explain response informs review; dispatch must verify the chosen route still fits the grant and record what actually ran. Broad arbitrary SQL, scripts, cross-source joins, or automatic budget expansion should be separate capabilities with their own review and execution boundary.

## Execution and warehouse boundaries

ArcBox documents separate Firecracker microVM kernels for sandboxes; ordinary containers share its System VM kernel. Its local sandbox mode requires supported nested virtualization hardware. A future execution adapter should create one disposable sandbox per tenant job, pin its root filesystem, bound CPU/memory/time, restrict egress to the authorized gateway, and keep broker/provider credentials outside the guest. Cleanup must be observed after expiry or revocation. Container fixture evidence must be labeled container evidence; no ArcBox or hardware attestation claim follows from it. [ArcBox security](https://arcbox.dev/docs/core/security), [ArcBox sandbox requirements](https://arcbox.dev/docs/core/sandbox).

Keep operational authority in each broker's durable ledger. A lake or warehouse is an analytical destination for explicitly exported evidence, not a second authority database. Start with a tenant-local append-only spool; no new SQL service is required. A future minimal export should contain full tenant/broker binding, event ID and sequence, task ID, timestamps, manifest/policy hashes, operation, outcome, approval provenance, and reserved/observed usage. Exclude raw prompts, model outputs, secrets, bearer tokens and free-form provider errors by default. Source and target identifiers may themselves need restricted access.

Central ingestion must derive tenant authority from the authenticated broker credential and verify it matches the record. Use tenant-specific storage credentials/datasets and enforced query authorization, not a caller-supplied SQL filter or object prefix alone. Deduplicate using tenant, broker and event identity. The existing audit hash chain uses a broker-held HMAC key; it is not independently verifiable with a public key. Keep that key inside custody and add signed export segments if independently verifiable warehouse evidence becomes a requirement.

## Acceptance evidence

Current focused tests cover strict IDs, immutable marker lifecycle, exclusive custody, foreign owner/action/approval rejection, tenant/legacy ledger refusal, receipt tampering, durable unknown outcomes, and no resume after restart. Those tests verify application enforcement; they do not prove deployment isolation.

The next fixture must demonstrate that tenant A cannot read B's source, receipt, credentials, approval capability, output volume or socket; forged membership and wrong resource audiences fail before data access; read-only permission cannot disclose to a model; denied/unknown work receives no retry; and expiry cleans temporary results. Run it with disposable canaries before admitting private data. The live environment's observed capabilities and remaining hardware gates are documented separately in [tenant and data discovery](product/2026-09-04-tenant-data-discovery.md).
