# Broker-owned resource authorization

Internal implementation and operator notes. Keep this document excluded from public site routes, search, sitemaps and assets.

The gateway delegates production OAuth authorization to the same `IdentityRuntime` that authorizes broker delegation. It sends the original access token over a separate, authenticated Unix socket. The broker re-verifies the token and intersects its exact tenant/subject/client admission and scopes with the stored principal's current roles and current issuer/subject/email membership. Unknown principals do not bootstrap through resource access; establish the human through broker OIDC login and approved role administration first.

Every source dispatch, returned evidence disclosure, model planning/answer disclosure and delivered chat stream event uses this authority. A disabled principal, removed role, removed membership, revoked token, expiry or unavailable broker denies further access. An in-flight provider request cannot be undone; evidence returned after authority changes is discarded. The gateway stores the original token only in private server memory and does not forward it to source/model providers.

`opaque-core::resource_auth` contains the shared pinned RS256 access-token validator and narrow wire protocol. The JWT profile still requires `typ=at+jwt`, a single exact resource audience, `client_id`, a tenant claim, concrete scopes, a unique JTI, and at most 900 seconds of lifetime. Trusted public-key rotation replaces broker configuration and restarts its verifier; JWT headers cannot select remote keys. The gateway's OAuth endpoint metadata must match the broker issuer and resource exactly.

## Production custody and configuration

Start from a broker with `identity.required=true`, sealed configuration and enforced tenant custody. Use the immutable `tenant.binding.json` value for both resource-authority and gateway bindings. A different broker UUID must fail closed, even for the same tenant name. Gateway state also pins this complete binding.

Run the gateway as a separate unprivileged UID. It receives no broad `daemon.token`, signing key, identity database path, writable broker state, or ordinary broker-socket access. Provision a fresh CSPRNG 32-byte credential solely for this endpoint; store it broker-owned with mode `0640` and a dedicated gateway-reader group. Use a broker-owned endpoint directory with no group/other write access; set its group and setgid bit so the resource socket inherits the dedicated gateway group. The resource listener creates a `0660` socket; it independently checks the configured gateway UID allowlist. The gateway checks the socket owner and actual connected peer UID before sending the original token and HMAC proof. The resource credential can only check or revoke that presented access token, and cannot issue delegations, perform host operations, or call arbitrary broker methods.

The broker adds this configuration (operator-specific paths, UIDs, bindings and public PEM must be supplied):

```toml
[resource_authority]
socket_path = "/run/opaque-resource/authorize.sock"
credential_file = "/run/opaque-resource/resource.key"
allowed_gateway_uids = [1002]

[resource_authority.binding]
schema_version = 1
tenant_id = "customer-a"
broker_id = "00000000-0000-4000-8000-000000000001"

[resource_authority.role_scopes]
operator = ["metrics:read", "metrics:explain", "metrics:stream", "metrics:metric:requests_per_second"]

[resource_authority.auth]
issuer = "https://identity.example.com"
resource_audience = "https://metrics.example.com/mcp"
# Set public_key_pem to the operator-verified RSA public PEM from the IdP.

[[resource_authority.auth.admissions]]
tenant_id = "customer-a"
subject = "exact-issuer-local-subject"
client_id = "registered-gateway-client"
scopes = ["metrics:read", "metrics:explain", "metrics:stream", "metrics:metric:requests_per_second"]
```

The gateway adds `broker_authority` with `socket_path`, `credential_file`, `broker_uid` and the same `binding` object. Its `auth` object contains `issuer` and `resource_audience`; omit `public_key_pem`, `admissions`, and `revoked_jtis`. Those are broker policy and production gateway startup rejects duplicate configuration. Its existing `oauth`, source credential reference, source allowlist, model and public-origin settings still apply. A gateway starts without a live broker but denies every authenticated request until the configured authority responds; connect, read and write waits are bounded, and no cached allow decision is used.

Logout persists revocation in the broker's `identity.db` before clearing an active browser session. Self-revocation authenticates the original pinned JWT, exact issuer, audience and tenant, then withdraws only that token's signed JTI without requiring its former admission, membership or roles. This operation returns token metadata, never an access grant. Restoring a disabled account or removed role cannot revive a token after logout. Missing or expired cookie sessions clear locally with `signed_out=true, revoked=false`; an unavailable broker returns 503 for active sessions and retains the cookie for retry instead of claiming durable revocation. Resource revocations are monotonic and keyed by issuer, resource audience and JTI. Broker and gateway restarts do not restore a revoked token. Operator fixture revocations in the broker's trusted `auth.revoked_jtis` also deny access. Broker resource checks/revocations emit audit events with the trusted tenant/broker binding and no bearer material.

An existing socket path is never removed on startup, to avoid replacing a running broker. Normal shutdown removes the resource socket. After an unclean exit, the service manager/operator must retire the stale socket within its dedicated runtime directory before restarting.

## Explicit compatibility fixtures

Standalone static gateway authorization is accepted only when `fixture_mode=true`. Broker resource fixtures also require `resource_authority.fixture_mode=true` and the explicit `OPAQUE_RESOURCE_AUTHORITY_FIXTURE=1` process environment switch. This fixture path permits same-UID loopback tests without presenting them as isolated production custody.

`crates/opaqued/tests/resource_authority_e2e.rs` launches the actual daemon and an HTTP gateway with disposable keys/state and loopback IdP/source/model fixtures. Only the test harness mutates its private broker identity database. It exercises missing-principal rejection, current disabled/roles/membership checks, exact issuer/client/tenant binding, expiration, broker UUID mismatch, evidence withheld after a source-time role removal, browser logout, durable restart revocation and outage denial without additional provider calls. Shared validator and identity-store tests cover malformed/signed claims, HMAC tampering, exact issuer+subject lookup and issuer/resource-scoped revocation persistence.
