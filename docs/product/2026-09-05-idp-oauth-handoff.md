# IdP connections and OAuth linkage handoff

Private continuation record, September 5, 2026. The user requested merging the
current work to private `main`, then clearing context before this next track.
Start by reading this file, the [roadmap](roadmap.md), and the
[production connection preflight](2026-09-05-production-connection-preflight.md).
Recheck live configuration before acting; the observations below are dated.

## Product direction and completed foundation

Opaque authorizes specific bounded work. The broker owns current resource
authority, durable consumption and production task receipts; specialist
providers retain credential custody. Vault is the selected SSH signer/CA.
**Do not introduce AWX.** See the
[strategy](2026-09-05-unified-product-strategy.md) and
[implementation PRD](prd-unified-bounded-work.md).

Gateway and broker now share strict access-token validation, with a separate
authenticated broker authority socket enforcing current enrollment, tenant,
membership, role and durable revocation. Real-daemon/gateway fixtures exercise
this path. See [resource authority](2026-09-05-broker-resource-authority.md).
The public demo at `https://demo.opaque.info/` uses synthetic application data
and an explicitly unsigned demo task coordinator. Its observed one-read,
replay-denial, role-change and cleanup results do not establish production
source or identity connectivity. See the
[deployment record](../../deploy/hosted-demo/BOUNDED-WORK-VALIDATION.md).

## Identity and OAuth work to resume

- The metadata preflight passed against
  `https://argocd.tail16ecc2.ts.net/api/dex`. Discovery advertised authorization
  code flow, PKCE S256 and RS256 public signing keys. The inspected configuration
  had a GitHub connector; an Opaque client was not provisioned by this work.
- The prepared client is `opaque-broker` with exact loopback callback
  `http://127.0.0.1:8721/callback`. Review the
  [configuration fragments](../../examples/production-connections/README.md)
  against current infrastructure, register the client and complete actual PKCE
  login/enrollment for the selected issuer/subject identities.
- Dex identity tokens are not Opaque resource access tokens. Preserve the
  RS256 `at+jwt` verifier, exact issuer/audience/client and required `tenant_id`,
  `sub`, scopes, `jti`, `iat` and `exp`. Choose a compatible resource provider
  or explicitly design broker access-token issuance following login. Do not
  substitute ID tokens or infer tenant membership from email or caller input.
- Define key custody, key rotation and revocation before integration. The
  current resource verifier uses one pinned RS256 key; automatic JWKS rotation
  is not implemented. Keep current broker admission at source and disclosure
  boundaries, including membership removal and logout/revocation failures.

Use `scripts/production_connection_preflight.py` and its tests for the existing
metadata checks. Do not log tokens, client secrets or raw browser/session state.

## Real application source gate

No real source is connected. Quant's inspected router did not attach its API-key
middleware and its single database did not establish tenant separation. Its
position records and daily OHLCV do not match the gateway's operational metric
contract. Umami lacked selected authorized website IDs and a compatible event
watermark contract. The preflight record explains both findings in detail.

Select an owning application and two actual test tenants before data access.
Implement a truthful bounded aggregate export with source-enforced tenant
credentials and real event freshness; do not relabel one global source as two
tenants. Keep arbitrary SQL, URLs, databases and caller-selected tenant values
outside the authorized query contract.

Completion evidence must include real login and enrollment, correctly scoped
access tokens, permitted aggregate reads, foreign-tenant/source denials,
membership removal, expiry, credential/key rotation and disclosure suppression
when authority changes. Record source effects separately from model disclosure.

## Workspace and deployment boundaries

Work only in `kcirtapfromspace/opaque-dogfood`; verify it remains private before
pushing. `upstream` is the public product repository with a disabled push URL.
Keep this handoff, product docs, dogfood records and operator evidence excluded
from all generated public site files, search, sitemaps and assets. Preserve the
running demo and unrelated cluster workloads. Runtime credentials, private
keys, local environment files, binaries and raw session artifacts stay outside
Git. Actions were disabled at the merge preflight; local tests are not CI.

Fresh merge checks passed: locked workspace tests (1,769 passed, four explicitly
ignored live-provider checks), locked workspace/all-target Clippy with warnings
denied, Rust formatting, 123 JavaScript tests, 56 hosted Python tests and 43
Python contract tests (41 passed, two Linux-only checks skipped on macOS).
The artifact/credential audit and relative documentation link check passed.
The authored PRD was moved out of ignored `tasks/` into private `docs/product/`.
The final visitor-guide wording is published and verified; its deployment
identity and generated-output checks are in the deployment record above.

Native human approval, the real staging dispatch and the selected real-host SSH
operation remain separate roadmap gates. Certificate issuance and fixture
signatures do not complete them.
