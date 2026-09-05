# Application source and production identity prerequisites

Private read-only evidence, September 5, 2026. No application database or data
endpoint was opened, no Secret or production token was read, and no workload,
identity provider, source permission or repository outside this checkout changed.

The production OIDC metadata preflight is implemented and passes against
`https://argocd.tail16ecc2.ts.net/api/dex`. It validates the exact issuer, same
origin endpoints, authorization code flow, PKCE S256, broker login scopes and
bounded public RS256 JWKS. Ten tests pass, including a real local HTTP server
proving no redirect following, oversized-response rejection and credential-free
requests. Production connection remains unverified: discovery is not a client
registration, login or tenant membership check.

## Identity findings

The live issuer advertises `openid`, `email`, `groups`, `profile` and
`offline_access`; `code`; PKCE `S256` and `plain`; RS256; and token endpoint
authentication methods `client_secret_basic` and `client_secret_post`. Five
compatible public signing-key thumbprints were observed. Public-client support
and the proposed Opaque callback still require actual registration/login; the
advertised authentication methods alone do not prove that registration.

The inspected local Argo ConfigMap fragment contains a GitHub connector with
credential references and `orgs: []`, without an Opaque static client. This
describes the checked configuration, not every live Dex client. Do not infer
tenant membership from login, email text, GitHub organization membership or an
agent-supplied `tenant_id`.

Prepared [client/configuration fragments](../../examples/production-connections/README.md)
bind proposed client `opaque-broker` and callback
`http://127.0.0.1:8721/callback`, matching the daemon's existing fixed-port
PKCE callback path. Infrastructure deployment and real issuer/subject enrollment
remain external prerequisites.

Dex documents its primary signed identity output as an ID token. Its documented
scopes do not include the Opaque metric resource scopes. Its cross-client
audience feature still concerns ID tokens. The current Opaque resource profile
requires RS256 `at+jwt`, exact issuer/audience/client, `tenant_id`, `sub`, scope,
`jti`, `iat` and `exp`; source and disclosure scope admission and current
revocation must be checked through the broker. Do not weaken that verifier to
accept Dex ID tokens. Provision a compatible OAuth resource provider or an
explicitly designed broker access-token issuance flow after login.
[Dex tokens](https://dexidp.io/docs/configuration/tokens/),
[Dex scopes and public clients](https://dexidp.io/docs/configuration/custom-scopes-claims-clients/).

## Quant source findings

Read-only source inspection found:

- `quant-api/src/lib.rs::build_router` mounts `/api/v1/*` without applying
  `auth::require_api_key`. The middleware exists but is not attached in the
  inspected router. A configured `QUANT_API_KEY` reference therefore does not
  prove authentication at these routes. Live route behavior was not probed.
- `AppState` contains one DuckDB path and one OMS path, with no tenant authority.
  `/portfolio` returns position records. `/portfolio/history` is an empty stub.
  `/risk` computes scalar values but carries no verified tenant or event watermark.
  `/observability` may create current timestamps from missing textfile values,
  so those timestamps cannot serve as proof of fresh source events.
- `quant-data/src/store.rs` defines `ohlcv(symbol,date,open,high,low,close,volume,adj_close)`
  with `(symbol,date)` primary key and ISO calendar date strings. Daily OHLCV
  cannot honestly become requests per second or a one-hour operational stream.
- Deployment config mounts `market-data` read-only and references one shared
  API credential. Read-only filesystem access is not a tenant data boundary.

Source references:
[router](/Users/thinkstudio/quant-platform/quant-rs/quant-api/src/lib.rs),
[authentication middleware](/Users/thinkstudio/quant-platform/quant-rs/quant-api/src/auth.rs),
[observability](/Users/thinkstudio/quant-platform/quant-rs/quant-api/src/routes/observability.rs),
[OHLCV schema](/Users/thinkstudio/quant-platform/quant-rs/quant-data/src/store.rs).

The smallest honest Quant integration for the current gateway is a new
application instrumentation export, `POST /v1/metrics/query`, behind a dedicated
server-owned per-tenant service credential. Its body must be exactly
`{"window_secs":300,"metrics":["requests_per_second","error_rate_percent"]}`,
with no caller-selected tenant, database, URL, SQL or symbols. The server binds
the credential to the authorized tenant and an independently protected event
store. It computes named aggregates from actual timestamped request/status
events over the requested bounded window and returns exactly
`tenant_id`, `window_secs`, `as_of`, `watermark`, and numeric
`metrics[{name,value,count}]`. `watermark` is the latest included event time;
an empty or stalled source must remain unavailable under the existing gateway's
freshness policy. Merely assigning two labels to the same global source fails
the tenant requirement. An OHLCV integration needs a distinct market-data
query/window contract and is separate work.

## Umami alternative

Selected live workload names/images show `umami` using
`ghcr.io/umami-software/umami:postgresql-latest` and `umami-postgres` using
`postgres:15-alpine`. This does not pin an application version or establish
website ownership. No local Umami source/schema checkout or authorized website
IDs were found in the bounded repository inspection.

Umami's official aggregate API provides pageview statistics and a fixed
five-minute active-visitor count. Pageviews are not server requests, visitors
are not arbitrary-window active sessions, and those responses do not establish
the existing gateway's latest included event watermark. A naive adapter would
misrepresent the evidence. A sound integration needs named website analytics
metrics, exact window semantics, an aggregate export with a genuine watermark,
and two actual website/tenant credentials whose authorization is enforced by
the source. No Umami login or statistics request was performed.
[Umami website statistics](https://docs.umami.is/docs/api/website-stats),
[Umami v2 statistics](https://v2.umami.is/docs/api/website-stats-api).

## Completion gates

1. Select the actual application surface and two tenant owners, with approved
   per-tenant source custody and read scope.
2. Deploy and validate the bounded aggregate export, with missing credentials,
   opposite-tenant credentials, extra query fields and stalled source denial.
3. Register the exact broker OIDC client and perform real PKCE login/enrollment.
4. Provision and verify the resource access-token contract without substituting
   identity tokens, then test both tenants through the broker's current authority.
5. Prove source-read and model-disclosure denial during revocation/expiry, and
   record only sanitized authorization/result evidence.

No speculative adapter was added because neither inspected source currently
provides this authorized, semantically compatible contract.
