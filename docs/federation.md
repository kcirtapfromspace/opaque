# Federation

Central, signed control for a fleet of daemons: an org signs its policy once,
every daemon verifies before applying it, the audit chain streams to your SIEM,
and each daemon can prove its integrity posture on demand.

Federation builds on the [trust-domain split](deployment.md): under
`[trust_domain] enforce = true` the files these features depend on (the bundle
anti-rollback state, export cursors, attestation key) are custody material the
agent's uid cannot touch.

---

## Signed policy bundles

A bundle is an org's policy as one signed document:
`opqb1.<payload>.<signature>`. The Ed25519 signature covers the literal payload
bytes under a domain separator, so there is no canonicalization step to
disagree about: what was signed is exactly what is verified.

### What a daemon guarantees about a bundle

1. **Signature first.** The payload is not even parsed until a configured
   trust anchor verifies it. Multiple anchors are allowed, which is how you
   rotate a signing key without a flag day.
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

Guard the signing key like a CA key. The trust anchor (public half) is what
goes into each daemon's config.

### Daemon configuration

```toml
[federation]
trust_anchors = ["<hex org public key>", "<previous key during rotation>"]
bundle_url = "https://policy.acme.com/opaque/policy.bundle"
bundle_path = "/etc/opaque/policy.bundle"   # offline fallback
require_bundle = true
refresh_secs = 300
```

The URL is fetched first and the path serves as a fallback, so a network blip
cannot strip policy from a running fleet. A bundle that has *expired* is fatal
as the initial `require_bundle` load but only a warning on refresh: an org
outage must not disarm a running daemon.

Distribution is deliberately dumb: any static host, object store, or git raw
URL works, because trust comes from the signature rather than the channel.

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

This fails closed in every direction that matters: requests without a verified
principal never match, principals in none of the listed teams never match, and
neither does anyone when no bundle is applied (nobody has teams then). An empty
list matches nobody rather than everybody.

Team membership rides into the audit chain alongside the principal, so
"who could have done this, under which namespace" is answerable after the fact.

---

## Audit export to SIEM

The export pump tails the audit **chain**, not the live event stream, so every
exported record carries its `sequence_number` and `record_hash`. A SIEM holding
those records can verify them against the database: the stream is evidence,
not a parallel log that could drift.

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

Each transport keeps its own persisted cursor, so a dead SIEM never stalls the
others and delivery resumes exactly where it stopped after a restart. Delivery
is at-least-once; dedupe on `(sequence_number, record_hash)`.

TLS syslog requires a CA file. There is no insecure-skip option, because
shipping an audit trail to an unauthenticated endpoint is not a supported
posture.

### The independent detector

The pump also runs a detector with its own cursor. Its rule comes from the
chain rather than from policy: any request that recorded `approval.required`
must record `approval.granted` (or a `lease.hit`) before
`operation.succeeded`. A violation raises an Error-level `audit.alert` event
into the chain, which then exports like everything else. It is a second
opinion on the enclave, derived from evidence the enclave itself wrote.

---

## Continuous attestation

The daemon re-verifies its own custody set and audit chain on an interval and
records the result in the chain, so *"was this daemon healthy at time T?"* is
answerable from the log. On demand it produces a signed report:

```sh
opaque attest --key <expected attestation key hex>
```

The CLI generates a fresh nonce, the daemon answers with a signed report
covering custody, chain, trust-domain enforcement, applied bundle, and
registered approval factors, and the CLI verifies signature, nonce, and
freshness **before** printing anything. Without `--key` it says plainly that
the report is proven fresh but not proven to come from a particular daemon.

```toml
[attestation]
interval_secs = 900
key_release_url = "https://kms.acme.com/opaque"
key_release_authorization = "Bearer …"
```

Two verdicts are kept separate on purpose:

| Verdict | Means | Requires |
|---|---|---|
| **Healthy** | nothing is broken | custody verified + chain verifies |
| **Release-eligible** | may receive custody keys | healthy **and** trust-domain enforced |

A developer's session-mode daemon is healthy; it simply must never be handed
custody material, because it shares a uid with the agent.

### Verify before trust (key release)

With `key_release_url` set, the daemon proves posture before it receives key
material:

1. Daemon asks the verifier for a challenge; the verifier returns a nonce.
2. Daemon returns a freshly signed report answering that nonce.
3. The verifier checks the signature against the key it **enrolled**, checks
   the nonce it issued, and applies its own posture policy.
4. Only then does it release the material.

The daemon never sees the release policy: it proves posture and either
receives material or does not. A refusal is loud but not fatal: the daemon
keeps running on what it already holds.

This is the seam where hardware-rooted attestation belongs. A KMS release
policy or a SPIFFE/SPIRE SVID exchange plugs in at exactly this point with the
same protocol shape; what changes is the strength of the identity, not the
flow.

> **Honesty about strength.** This is *software* attestation: it proves a
> holder of the enrolled key claims this posture, freshly. It is not a
> hardware measurement of the running binary. What it buys is real but bounded:
> a daemon whose custody was tampered with cannot silently collect fresh
> keys, because the report it must produce carries the violations.
