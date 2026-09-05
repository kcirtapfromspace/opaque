# Demo human approval: GitHub OAuth and optional Dex configuration

Internal configuration and validation notes. Keep this file out of public site
routes, search, sitemaps, preview deployments, and assets.

The public demo uses GitHub directly. Register a dedicated GitHub OAuth app
under the selected owner, with homepage `https://demo.opaque.info` and the exact
callback `https://demo.opaque.info/approval/callback`. Keep callback wildcard
matching disabled. Configure the demo API through runtime secret injection:

```sh
OPAQUE_DEMO_OAUTH_PROVIDER=github
OPAQUE_DEMO_OAUTH_CLIENT_ID=<registered-client-id>
OPAQUE_DEMO_OAUTH_CLIENT_SECRET=<runtime-secret-reference>
OPAQUE_DEMO_OAUTH_REDIRECT_URI=https://demo.opaque.info/approval/callback
```

The placeholders are configuration descriptions, not working credentials.
GitHub mode requires a client secret and rejects `OPAQUE_DEMO_OAUTH_ISSUER`;
the authorization/token endpoints on `github.com` and identity endpoint
`https://api.github.com/user` are fixed in code. This public flow does not need
the Dex tailnet path. It leaves the existing Dex/GitHub connector intact.

The authorization request explicitly requests an empty scope and PKCE S256,
with a fresh one-use state and an account picker. The backend exchanges the code
using its client secret and PKCE verifier, rejects non-bearer tokens and any
returned scope, then revalidates identity against `/user`. It also rejects a
nonempty `X-OAuth-Scopes` response header. Existing broad authorizations for the
same OAuth app therefore fail closed: use a dedicated approval app or have the
user remove that app's old authorization before retrying. No email, repository,
organization, offline-access, or private-profile scope is requested. The proof
records `kind: github_oauth`, issuer `https://github.com`, and the stable positive
numeric GitHub account ID as its subject. It does not infer tenant membership or
authentication-factor strength. Provider tokens remain temporary server-side
values and never enter the browser, receipts, or resource authorization.

Optional `OPAQUE_DEMO_OAUTH_PROVIDER=oidc` mode uses the existing Dex issuer and its GitHub
connector. It needs a **separate browser-demo client** registered in Dex. The
existing `opaque-broker` client and its loopback redirect must be preserved.
The application does not register clients automatically.

Register a dedicated client with the exact callback
`https://demo.opaque.info/approval/callback`. A public Dex static client with
PKCE is supported; a confidential client can instead use a secret stored only in
the service's runtime secret store. The sample below contains no credentials:

```yaml
# Append under Dex staticClients; preserve all existing entries.
- id: opaque-demo-approval
  name: Opaque demo human approval
  public: true
  redirectURIs:
    - https://demo.opaque.info/approval/callback
```

Configure the demo API process:

```sh
OPAQUE_DEMO_OAUTH_PROVIDER=oidc
OPAQUE_DEMO_OAUTH_ISSUER=https://argocd.tail16ecc2.ts.net/api/dex
OPAQUE_DEMO_OAUTH_CLIENT_ID=opaque-demo-approval
OPAQUE_DEMO_OAUTH_REDIRECT_URI=https://demo.opaque.info/approval/callback
```

Set `OPAQUE_DEMO_OAUTH_CLIENT_SECRET` only for a confidential client, through
runtime secret injection. Do not commit a populated environment file. Omitting
all OAuth variables disables this approval method. Partial configuration fails
closed. Restart the demo API after changing configuration.

Both the browser and API process must reach this issuer. The `tail16ecc2.ts.net`
address may require the existing Tailscale access path: a public visitor without
that access cannot complete this provider flow. The frontend callback route must
be served at the registered public origin, and the same browser session must
remain active through approval. A passkey remains a separate browser method.

Clicking the task's explicit OAuth approval button starts a fresh authorization
code request with PKCE S256, a nonce, and a one-use state. The API stores the
challenge with the browser/session/task/digest/persona/expiry binding and consumes
it before exchange; after provider verification it rechecks that task binding.
Provider consent identifies the approver of the already reviewed task. Ordinary
OAuth login is not an unrestricted task grant.

The verifier discovers metadata from the exact configured HTTPS issuer, accepts
only endpoints beneath that issuer's path on the same origin, disallows HTTP
redirects, and bounds response bodies and network time. It requires advertised
PKCE S256 and RS256, verifies the ID token against the pinned issuer's JWKS, and
checks signature, issuer, audience, authorized party, nonce, expiry, issued-at,
and subject. It retains issuer and subject only as approval metadata. ID tokens,
access tokens, refresh tokens, authorization codes, client secrets, and PKCE
verifiers are never receipt fields or resource authorization.

Approval remains scoped to the fixed synthetic demo task. This feature does not
claim a production broker signature, a hardware-backed identity, GitHub factor
strength, or completion of a real host operation. A completed live OAuth
ceremony requires the dedicated client, deployed configuration, issuer
reachability, and a human's provider interaction; unit tests do not establish
those deployment facts.

Validation performed locally: `cargo test -p opaque-metrics approval_oauth::tests
--lib` covers both provider modes. The signed-token tests generate an ephemeral RSA
key in memory and exercise code exchange, signature tampering, issuer/audience/
authorized-party/nonce/time/subject rejection, unsupported JOSE headers,
algorithm confusion, duplicate key IDs, endpoint pinning, body bounds, and the
exact PKCE/state/nonce authorization request. No private signing-key fixture,
provider token, or live OAuth authorization was created by those tests.

A bounded review of the frontend dialog and server integration found no further
approval bypass after fixing the expiry check around the awaited token exchange
and matching the callback origin to the configured approval origin. The dialog
rejects stale task/identity state, checks its displayed manifest bytes and
digest, validates the OAuth message's origin/window/state, and records a
submitted-but-unconfirmed outcome when closed during verification. The API
independently enforces proof, task/session binding and one-use approval; browser
WASM is a review aid. This source review is not a live identity ceremony.

References: [GitHub authorization and PKCE](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps),
[GitHub authenticated public identity](https://docs.github.com/en/rest/users/users#get-the-authenticated-user),
[Dex clients and scopes](https://dexidp.io/docs/configuration/custom-scopes-claims-clients/),
[OIDC ID token validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation),
[PKCE](https://www.rfc-editor.org/rfc/rfc7636).
