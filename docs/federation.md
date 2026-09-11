# Federation

For operators managing multiple Opaque daemons: distribute signed policy,
export audit records, and inspect signed daemon posture reports.

Federation requires the [trust-domain split](deployment.md) to protect bundle
anti-rollback state, export cursors, and the attestation key from the agent's
OS user. Set `[trust_domain] enforce = true` under a separate broker identity.

---

## Signed policy bundles

A bundle is an org's policy as one signed document:
`opqb1.<payload>.<signature>`. The Ed25519 signature covers the literal payload
bytes under a domain separator; verification requires no canonicalization.

### What a daemon guarantees about a bundle

1. **Signature first.** A configured trust anchor verifies the signature
   before the payload is parsed. Multiple anchors support signing-key rotation.
2. **No rollback.** The daemon persists `(org, version, digest)` in its custody
   set. A lower version is refused; an equal version is accepted only if it is
   byte-identical (idempotent re-apply); a *different* bundle carrying an
   already-applied version is refused as a substitution. Refusals are recorded
   in the audit chain as `federation.bundle_rejected`.
3. **Fail closed on demand.** With `require_bundle = true` the daemon refuses
   to start until a valid, unexpired bundle applies.
4. **Applied bundles are authoritative.** Bundle rules replace local
   `[[rules]]`; the swap is live, with no restart.

### Org tooling

```sh
opaque bundle keygen --out org-signing.key     # prints the trust anchor
opaque bundle sign --manifest policy.toml --key org-signing.key --out policy.bundle
opaque bundle verify policy.bundle --anchor <hex>   # exits nonzero on failure
opaque bundle inspect policy.bundle                 # contents, loudly UNVERIFIED
```

A manifest is TOML, the same rule shape as the daemon config:

```toml
org = "acme"
version = 7            # monotonic; the anti-rollback counter
expires_days = 30      # optional

[[teams]]
name = "platform"
members = ["alice@acme.com", "service:ci-bot"]

[[rules]]
name = "platform-github-sync"
operation_pattern = "github.*"
allow = true

[rules.approval]
require = "always"
factors = ["local_bio"]

[rules.identity]
teams = ["platform"]   # only platform members match this rule
```

Protect the signing key; configure its public key as a daemon trust anchor.

### Daemon configuration

```toml
[federation]
trust_anchors = ["<hex org public key>", "<previous key during rotation>"]
bundle_url = "https://policy.acme.com/opaque/policy.bundle"
bundle_path = "/etc/opaque/policy.bundle"   # offline fallback
require_bundle = true
refresh_secs = 300
```

The URL is fetched first, with the path as fallback. With `require_bundle`,
an expired bundle prevents startup. Refresh can apply an expired but otherwise
valid bundle with a warning. Failed refresh leaves the applied policy in place.

Distribute bundles through a static host, object store, or git raw URL.
The configured trust anchors authenticate the bundle signature.

---

## Org and team namespaces

Bundles carry team rosters. Membership is resolved **daemon-side per request**
from the applied bundle (never supplied by a client), and a bundle refresh
takes effect immediately.

Rules constrain on teams through the identity block:

```toml
[rules.identity]
teams = ["platform", "ml-infra"]   # ANY-of
```

Matching requires a verified principal in at least one listed team. Without an
applied bundle, no principal has team membership. An empty list matches nobody.

Audit records include the principal and resolved team membership.

---

## Audit export to SIEM

The export pump reads the audit chain. Each exported record carries its
`sequence_number` and `record_hash` for comparison with the source database.
See [evidence verification](evidence-checkpoints.md) for authentication,
continuity, and completeness limits.

```toml
[export]
spool_path = "/var/log/opaque/audit.jsonl"        # append-only JSONL (0600)
webhook_url = "https://siem.acme.com/ingest"      # batched JSON POST
webhook_authorization = "Bearer …"
syslog_addr = "tls://siem.acme.com:6514"          # RFC 5424, RFC 6587 framing
syslog_ca_file = "/etc/opaque/siem-ca.pem"        # required for tls://
poll_secs = 2
batch_size = 256
```

Each transport keeps its own persisted cursor and resumes from it after restart.
Delivery is at-least-once; dedupe on `(sequence_number, record_hash)`.

TLS syslog requires a CA file and has no insecure-skip option.

### The independent detector

The pump also runs a detector with its own cursor: any request that recorded
`approval.required` must record `approval.granted` (or a `lease.hit`) before
`operation.succeeded`. A violation raises an Error-level `audit.alert` event
into the chain for export. The detector checks the daemon's recorded events;
it cannot establish that omitted events or provider effects occurred.

---

## Continuous attestation

The daemon periodically checks its custody set and audit chain and records
the results. These are the daemon's observations at each check, not continuous
proof of host integrity. Request a signed report on demand:

```sh
opaque attest --key <expected attestation key hex>
```

The CLI generates a fresh nonce, the daemon answers with a signed report
covering custody, chain, trust-domain enforcement, applied bundle, and
registered approval factors, and the CLI verifies signature, nonce, and
freshness **before** printing the report. Without `--key`, it uses the key
supplied with the response: nonce and freshness checks do not authenticate
a particular enrolled daemon.

```toml
[attestation]
interval_secs = 900
key_release_url = "https://kms.acme.com/opaque"
key_release_authorization = "Bearer …"
```

The verdicts summarize the signed report's fields:

| Verdict | Means | Requires |
|---|---|---|
| **Healthy** | Reported custody and audit checks passed | custody verified + chain verifies |
| **Release-eligible** | Meets the built-in posture predicate; the verifier decides release | healthy **and** trust-domain enforced |

A session-mode daemon can report healthy checks while sharing a uid with the
agent. It does not meet the release-eligible predicate.

### Verify before trust (key release)

With `key_release_url` set, the daemon submits a signed posture report to an
external verifier to request key material:

1. Daemon asks the verifier for a challenge; the verifier returns a nonce.
2. Daemon returns a freshly signed report answering that nonce.
3. The verifier checks the signature against the key it **enrolled**, checks
   the nonce it issued, and applies its own posture policy.
4. Only then does it release the material.

The verifier owns the release policy. A refusal is logged but does not stop the
daemon or revoke material it already holds.

Hardware-backed attestation or a KMS/SPIFFE/SPIRE integration would require
separate implementation and qualification. This exchange alone provides no
hardware measurement of the running binary.

> **Trust requirement.** Software attestation establishes that a holder of the
> enrolled key signed these claims in response to the verifier's nonce. The
> daemon and key holder remain trusted to report honestly. A compromised daemon
> or signing key can produce false posture claims that pass signature checks.

Inspect the [report format and verification tests](https://github.com/kcirtapfromspace/opaque/blob/83e7924960f809e87379a54996317dbe1422fe70/crates/opaque-core/src/attest.rs)
and [posture observation and key-release client](https://github.com/kcirtapfromspace/opaque/blob/83e7924960f809e87379a54996317dbe1422fe70/crates/opaque-federation-runtime/src/attest.rs).
These source references describe implementation, not an independent security audit.
