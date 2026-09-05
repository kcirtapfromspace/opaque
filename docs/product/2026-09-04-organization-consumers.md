# Organizations, customer tenants and agent consumers

**Status, 4 September 2026:** the organization extension passed local boundary
tests and a packaged Docker run using the real Gemma service. It is deployed in
the hosted credit demo. Public sessions verified analyst and support reads,
engineer metadata access without metric entitlement, default question
concealment, future sharing and withdrawal. A support request for Cedar was
denied without another source query. Slot resources were removed after both
sessions, and the final controller generation was retained after cleanup.

The product should let a platform company operate customer-facing agents while
keeping each customer's data authority explicit. An engineer can investigate a
failed tool call. A support specialist can help one customer with a temporary,
limited grant. Neither becomes every customer merely by belonging to the parent
organization. The organization view groups customers and consumers; the gateway
still authorizes the particular actor, tenant, operation and disclosure.

The scenario names **Northstar Financial Systems** as the fictional
platform organization, **Harborlight Credit Union** as this workspace's customer,
and **Cedar Community Bank** as a directory-only customer. Cedar has no source
connection or query capability in this demo. Organization context is scoped to
the disposable lease; it is not a shared directory of real demo visitors.

## Current posture

- The metrics gateway admits one configured tenant and explicit verified
  subjects. It checks the access-token signature, issuer, exact resource
  audience, tenant, scopes, lifetime and revocation before granting access.
- The source URL and source credential come from trusted tenant configuration.
  A chat message or tool argument cannot select a different customer or source.
- Current local audit records contain tenant, subject, operation, outcome and an
  evidence hash. They do not contain raw questions, model answers or credentials.
- The role selector is a **synthetic role simulator** backed by three
  distinct disposable OAuth subjects and fixed clients. Real PKCE exchanges and
  subject-specific tokens can test the protocol and grants; one visitor choosing
  all three roles still does not prove real employee/customer identity or
  production role-assignment controls.

The relevant starting points are `AuthVerifier::new` and `VerifiedAccess` in
`crates/opaque-metrics/src/auth.rs`, tenant/source validation and `App::audit` in
`crates/opaque-metrics/src/server.rs`, and the hosted runtime's disposable issuer
in `deploy/hosted-demo/runtime.py`. The existing broker's stronger custody model
is described separately in [tenant boundaries](../tenant-boundaries.md); adding
an organization label must not weaken that model or turn a tenant ID into an
unverified query parameter.

## Relationship and authority

| Object | Meaning | Authority it does not confer by itself |
| --- | --- | --- |
| Organization | The platform operator and its administrative grouping of customers. | Reading every child customer's data, questions or outputs. |
| Customer tenant | The data owner and the gateway/source boundary for that customer. | Access by any employee of the operator. |
| Principal | A verified issuer/subject identity for a person or service. | Membership inferred from an email domain, display name or request header. |
| Consumer | A registered application, chat session or agent that uses a particular customer's grants. | Arbitrary source access merely because it has a known application name. |
| Activity grant | Permission to see specified operational metadata for named customers and consumers. | Raw question content, metric values or source credentials. |
| Content-sharing grant | Permission to disclose specified conversation content to named recipients. | Tool execution or access to other conversations. |
| Support grant | Temporary authority for an identified support actor to perform named operations for one customer. | Impersonation without attribution, writes, all-customer access or indefinite renewal. |

The organization-to-customer relationship comes from operator-controlled
registration. It is not a wildcard tenant grant and is not inferred from a
caller-provided organization ID. An internal consumer that needs its own data
also gets its own tenant or explicit source grant; it does not use a parent
label to bypass a customer's boundary.

For production support, preserve both **the staff actor** and **the represented
customer/subject** in authorization and activity records. OAuth token exchange
defines delegation that retains separate actor and subject identities; it does
not establish an application's membership or support policy. That protocol is
an optional future integration, not implemented by the demo role selector.
[RFC 8693, delegation and actor claims](https://www.rfc-editor.org/rfc/rfc8693.html#section-1.1).
Resource servers must continue to validate the intended access-token type and
recipient rather than accept an ID token or forward one resource's token to
another. [JWT access-token profile](https://www.rfc-editor.org/rfc/rfc9068.html).

## The bounded demo

The optional `organization_demo` configuration is restricted to the
synthetic credit experience. It retains the current single customer and source;
it does not introduce a shared production data plane or another tenant selector.
The engineer token has only `organization:activity:read`. Analyst and support
tokens have their separately admitted metric and activity scopes. The hosted
runtime holds the three private session cookies and activates the selected
subject only after the gateway accepts the transition. Browser role labels and
capabilities are presentation, not authorization.

| Demo persona | Useful action | Required denial |
| --- | --- | --- |
| Customer analyst | Ask the three permitted aggregate questions and inspect evidence. | Another customer's data, borrower records, credit score and mutations. |
| Internal engineer | Inspect bounded activity: consumer, model, tool phase, outcome, timing and permission decision. | Customer metric queries through chat or direct MCP merely because the actor is an engineer. |
| Support specialist | Use a short-lived, customer-specific read grant, with a reason shown in the activity trail. | Reads before the grant, after expiry/revocation, for another customer or outside the grant's metrics. |

The implemented routes include `GET /api/organization/activity`,
`POST /api/demo/persona` and `POST /api/organization/sharing`. They must authenticate
the selected verified session and derive
customer and organization from trusted configuration. The mutation accepts only
the fixed persona choice and bounded support context. An entered reason explains
the request; it does not authorize it. The demo's server policy determines which
synthetic grants can be exercised. A future production service must replace this
self-selected simulation with separately authenticated staff and explicit
customer/policy-authorized grants.

The support token permits bounded snapshots and explanations, without the
`metrics:stream` scope. A support case does not add that missing permission.
The reason is displayed with the case and recorded in the local audit, so the
form tells visitors not to enter borrower information or secrets.

Every role change needs a monotonically increasing session authorization
generation. A started chat retains its original generation and must fail a later
check if the role changed, even if the user switches back. Support authority must
be bounded by a grant deadline of at most 300 seconds, access-token expiry and
workspace expiry. An explicit rejection preserves the prior actor. An ambiguous
response disables runtime readiness because the gateway may already have
accepted the transition; it does not assume the gateway rolled back. Runtime
cookie selection must not get ahead of confirmed server authority.
Switching personas cannot replenish the lease's question or model-call budgets.
Revocation blocks new dispatch and further evidence release; it cannot retract
data already delivered to a browser or an already-authorized model request.
The hosted runtime currently rejects role and sharing changes while chat/model
work is active or execution is uncertain. Gateway generation/expiry tests are
therefore not a live demonstration of immediately changing roles during an
active hosted model request. Ending the lease and verifying cleanup is a
separate lifecycle operation.

## Questions and tool activity are different data

Tool runs can be useful without storing their input or output. Start with a
bounded activity envelope: server-assigned event/request IDs, authenticated
producer, organization/customer binding, actor and represented subject,
consumer/session, model alias, tool name, phase, decision, grant ID/generation,
timestamps and outcome. Distinguish a proposed tool call, an authorized attempt,
a received response and validated evidence. A failure is not proof that no
source access occurred.

An engineer seeing a question is a separate disclosure. Synthetic source events
do **not** make visitor-entered text synthetic: a visitor can paste a real name,
account number or secret. Metadata-only visibility should be the default.
Question text needs an explicit, visible sharing decision for that conversation
and recipient scope, bounded storage and retention, and a way to stop future
disclosure. A configuration flag labeled “synthetic consent” is not evidence
that a visitor agreed to share arbitrary text. Redaction can reduce exposure but
does not prove all personal data was removed. Never collect bearer tokens,
source credentials, authorization headers or free-form provider errors in this
feed. A prompt hash is still potentially sensitive and is not anonymization.

The agreed demo behavior makes sharing an **analyst-only** action, initially off.
Enabling it permits future capture rather than retroactively collecting earlier
questions. Disabling it purges captured text from the activity store and denies
later reads of that content. The implementation must recheck sharing when
projecting activity, including reads delayed by a role change. Withdrawal cannot
erase a copy that a recipient already saw or saved.

The initial activity store is an in-memory, per-workspace feed with at most 100
records and a 900-second retention ceiling; the hosted lease expires sooner.
The feed does not contain numeric metric results or model answer text. Existing
append-only audit metadata is separate, and the activity feed is not a signed
ledger or a warehouse. A future organization warehouse can ingest minimized
events from authenticated tenant producers, stamp the tenant from that producer
identity, and authorize each reader's customer and content scope. It must not
hold source credentials or become a second authority store. A browser-selected
tenant filter or object prefix alone is insufficient. Cross-customer operational
aggregation and diagnostic-content storage remain separate roadmap work.

## Focused review findings and acceptance gates

These hazards guided the bounded review. The working-tree implementation now
contains the controls below; they are retained as regression and release gates,
not presented as unresolved bypasses in the deployed extension. Local
test evidence is recorded after the table; public organization validation remains
a separate step.

| Priority and hazard | Evidence or affected integration | Required fix and verification |
| --- | --- | --- |
| P1: parent membership becomes customer authority | Current `AuthVerifier::new` admits exactly one tenant; widening it to parent membership or trusting a tenant selector would change the boundary. | Keep tenant/data grants explicit. Engineer chat and direct MCP queries must fail before any source/model call. Foreign organization/customer fields and unknown arguments must fail without disclosing foreign activity. |
| P1: an old stream survives a role change | Current SSE delivery in `server.rs::chat` rechecks token authority; a new mutable role overlay needs its own check there and before source/model dispatch. | Capture a generation in each operation. Test a paused source/model response and unpolled SSE through customer→engineer→customer; the old operation must release no later content or dispatch another read. |
| P1: support reason becomes a confused-deputy grant | `/api/demo/persona` creates a temporary support context. | Resolve a trusted grant for the exact actor, customer, operations and deadline. Test an empty/forged reason, caller-selected tenant, expired grant, removed grant and replay after a generation change. The reason alone must never add scopes. |
| P1: raw questions enter engineer telemetry by default | Existing `App::audit` deliberately excludes question content; the activity endpoint adds a new disclosure path. | Separate metadata from shared content. Test an unshared secret/PII canary is absent from activity responses, audit records and error bodies; test withdrawal blocks future reads. Do not promise universal PII detection. |
| P2: the simulator is presented as production staff authorization | Hosted runtime uses a disposable issuer, three fixed clients/subjects and private sessions selectable by one visitor. | Restrict configuration and routes to fixture mode; reject production enablement at startup. Label the selector and support grant as demonstrations. Test that a normal production configuration cannot expose the role-switch route. |
| P2: activity misstates execution or resets budgets | Real tool execution spans model planning, MCP requests and streamed release. | Record events from the executed path, enforce bounded rows/bytes and lifetime, retain actor attribution, and test that polling/switching/replay makes no source/model calls or refunds consumed allowance. |

Use source and model request counters as the negative-test oracle; a hidden UI
button or a 403 response alone is insufficient. Test activity access after
logout, expiry and support revocation, including buffered responses. Verify that
support activity remains attributed to support instead of silently becoming a
customer action. Keep the existing global single-model concurrency fence across
all personas.

Two specific integration cases need attention. An internal HTTP MCP call from
an older chat must retain the chat's expected generation; it must not silently
adopt a newer generation after a role round trip. For activity accuracy, one
successful source read makes `source_accessed: true` persist for that question
even if a later watch iteration fails or is denied. Starting the next tool call
must not erase the earlier observation.

The Python boundary suite passed **49 tests** after adding role activation,
private-cookie selection, scoped identity, lease-clamped token and controller
fence cases. A subsequent targeted rerun passed the updated control-response
cases: complete 3xx/5xx responses disable readiness because a role change may
already have happened, while explicit 4xx rejection preserves the prior actor.
A deterministic concurrent test also verifies that a request waiting behind an
ambiguous activation rechecks readiness after taking the identity lock and makes
no second outbound request. These use local fixtures, not real employee login,
GPU calls, a live organization rollout or cross-customer data access.

A real stdlib HTTP/1.1 regression also covers Content-Length completion. The
packaged Python 3.11 run exposed a `read1` behavior where a fully consumed JSON
response still reported an open response object, causing a safe but incorrect
503 after the gateway had accepted the role. The corrected path performs a final
empty `read(1)` before checking framing completion. The regression uses a real
loopback HTTP server and connection: a complete response activates the target
identity, while truncation disables readiness and preserves the prior selected
cookie. The full 49-test Python suite passed after this correction.

The provider's completed Rust run reported **53 passing tests**, including nine
organization cases. Those cover engineer bearer and spoofed-header denial with
zero source/model calls, subject/client-pinned login, assigned-customer support
and no stream scope, Cedar denial, sharing and deferred-body purge, retained
source evidence, role-change interruption and delayed internal MCP requests.
The review confirmed the final pre-dispatch checks, including one after the
awaited explanation-status event. A shared 120-change control ceiling prevents
persona switching from resetting the limit; reaching it clears stored shared
question text. The current bounded review found no remaining material issue in
this extension. This is not a whole-repository security assessment.

## Packaged local integration

The operator's corrected Docker/Python 3.11 run completed three distinct PKCE
logins and used the real Gemma service. The analyst received an application-rate
answer with sharing off. The engineer's same question was denied without result
events. After the analyst enabled sharing, a later identity-mismatch question was
visible to the engineer; the earlier unshared question was not. A support case
named the exact assigned customer, lasted no more than 300 seconds and had no
stream scope. Support could request a manual-review snapshot, could not change
sharing, and received a denial for named directory customer Cedar.

Returning to the analyst and disabling sharing purged all stored question text
from the engineer's view. The source recorded exactly three aggregate queries
after the three allowed and two denied questions; eight activity records remained. Final health reported
ready, zero active requests, zero model requests and no execution uncertainty;
the local container was stopped. Source evidence and audit records were captured
under `/private/tmp/opaque-organization-deployment/evidence`. These temporary
paths are operator records, not a durable archive. The focused automated tests
separately prove zero source/model calls for engineer denial. This local run does
not establish production staff identity, customer consent outside the simulator
or public deployment of the organization feature.
The operator's complete evidence and deployment status are recorded separately
in `deploy/hosted-demo/ORGANIZATION-VALIDATION.md`.

## Public integration and remaining work

The first public Gemma session returned an analyst application rate of
704 apps/min and a support manual-review rate of 19.1964%, with 672 samples in a
60-second window. The engineer saw activity with no metric entitlement: the
earlier unshared question remained concealed, while a later opted-in
identity-mismatch question was visible. The support case named Harborlight and
was capped to the workspace deadline. The lease expired naturally and its Pods,
Services and Secrets were removed.

A second public session verified the remaining controls. After an analyst shared
an application question, the engineer saw its text and tool metadata. Support
then requested Cedar's application rate and received `customer_scope_denied`
with zero tool calls. Actual source aggregate queries stayed at one before and
after that denial. The analyst stopped sharing, and the engineer's expanded
activity records concealed all question text, including the previously shared
question. Ending the session removed its Pods, Services and Secrets. Durable
controller state retained generation 16 and its cleaned lease ID with no current
lease. The final audit preserved distinct subjects, role generations, the
support limit and the denial instead of attributing support work to the analyst.

The fixture role selector, metadata view and bounded future-sharing path are
implemented and exercised publicly. Support case limits, stale-generation
interruptions and direct bearer denials also have focused automated coverage.
Revoking support during an active public model request remains unproven live.
The next production work is to connect separately authenticated staff and
customer identities to durable, revocable support grants, preserving actor
attribution and customer visibility. Organization-wide ingestion and querying
should follow only after two real tenant bindings pass cross-tenant denial and
content-disclosure tests.

No new OAuth authorization server, production organization directory, warehouse,
source integration, microVM or network-isolation claim follows from this
increment. The model remains a trusted recipient of authorized question and
aggregate content under the existing demo limits.
