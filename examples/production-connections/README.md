# Production connection preparation

These files are private preparation, not applied production configuration. The
existing Argo Dex issuer is reachable, but its Opaque client, tenant enrollment
and metrics resource credentials have not been provisioned or verified.

Run the credential-free metadata preflight:

```sh
python3 -B scripts/production_connection_preflight.py \
  --issuer https://argocd.tail16ecc2.ts.net/api/dex \
  --client-id opaque-broker
python3 -B -m unittest discover -s scripts -p 'test_production_connection_preflight.py' -v
```

The tool makes two public GETs: OIDC discovery and the same-origin JWKS. It
rejects redirects, foreign endpoint origins, duplicate JSON fields, private
JWK material, oversized responses and incompatible keys. It prints public-key
thumbprints without key material, tokens or HTTP bodies. Optional repeated
`--expected-jwk-thumbprint` arguments require the full compatible key set to
match operator pins; rotation then requires an intentional pin update.

Exit 0 means metadata is compatible with the broker's RS256/code/PKCE profile.
The output always includes `production_connection_verified: false` because
public discovery cannot prove client registration, real login, tenant admission,
access-token profile or source authorization. Exit 1 is a metadata failure;
exit 2 is invalid local input.

The adjacent TOML is a broker identity configuration fragment. The Dex YAML
contains the matching proposed public client with an exact fixed callback.
Merge that entry into the existing `dex.config` only through the infrastructure
owner's deployment flow; replacing the ConfigMap would lose existing connector
configuration. `opaque-broker` and loopback port 8721 are proposed values, not
observed registrations. No client secret is required for this proposed public
client, and no registration or login was performed.

This login authenticates the broker principal. A Dex ID token must not be
submitted as an `at+jwt` metrics access token. The gateway resource profile
requires its own registered issuer, exact resource audience and client, signed
tenant/subject/scope claims, token lifetime and current broker admission and
revocation. Register and verify those independently.

See the [private source and identity findings](../../docs/product/2026-09-05-production-connection-preflight.md)
for the concrete source changes and remaining external provisioning.
