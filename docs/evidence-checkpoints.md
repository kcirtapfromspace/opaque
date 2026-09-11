# Signed evidence checkpoints

`opaque-evidence` creates a portable Ed25519 checkpoint from an authenticated audit
snapshot and verifies it using a separately enrolled producer key. The snapshot
contains the existing `opaque.audit.v1` JSONL records. It never contains the audit
HMAC key, producer private key, broker configuration or session files.

The checkpoint authenticates the producer's declared instrumented range. It does
not establish global completeness, independently observed provider effects,
hardware attestation, certification or safe restoration of authorization state.
Audit metadata remains sensitive even when it contains no secret values.

## Trust and custody

An administrator assigns tenant, broker, stream and generation labels when enrolling
the producer key. These are trusted administrative assertions for this audit source;
the audit database does not independently derive tenant identity. Enroll the public
key and its fingerprint through an authenticated channel. Receiving a key together
with a package is insufficient evidence of who owns that source.

Keep the dedicated Ed25519 evidence private key under broker custody. It is separate
from the audit HMAC key and any custodian key. The CLI requires owner-only regular
private-key files and explicit paths, and refuses to overwrite outputs. It does not
use Keychain, trigger native review or send anything over a network.

The receiver owns the persistent enrolled-key history and last accepted checkpoint
for each exact scope/generation. A new checkpoint must increment sequence by one,
link the previous checkpoint digest and not regress its observed head. A first
checkpoint has sequence 1 and no predecessor. Snapshots may overlap; they represent
the currently retained audit range. A valid old snapshot remains cryptographically
valid, so a retained high-water reference is necessary to detect its replay.

V1 key replacement requires explicit enrollment of a new stream generation. The
new generation is visibly discontinuous; it must not erase the previous generation's
records, revocation or missing coverage. No implicit same-generation key rotation
or recovery is performed. A compromised enrolled key can sign false claims; a
signature does not make a compromised producer truthful.

## Commands

Build with `cargo build --locked -p opaque --bin opaque-evidence`. The examples use
explicit generic paths in directories already controlled by the administrator.

```sh
opaque-evidence keygen \
  --private-key /custody/evidence.key \
  --public-key /custody/evidence-public.json

opaque-evidence enroll \
  --public-key PUBLIC_KEY_HEX --key-id INDEPENDENTLY_CHECKED_SHA256_FINGERPRINT \
  --tenant tenant-a --broker broker-a --stream audit --generation generation-1 \
  --output /verifier/producer-enrollment.json

opaque-evidence create \
  --database /custody/audit.db --private-key /custody/evidence.key \
  --enrollment /custody/producer-enrollment.json --build-identity REVIEWED_BUILD_ID \
  --output /custody/checkpoint-1

opaque-evidence verify \
  --enrollment /verifier/producer-enrollment.json \
  --checkpoint /received/checkpoint.json --export /received/audit.jsonl \
  --expected-checkpoint-sha256 PREVIOUSLY_RETAINED_CHECKPOINT_DIGEST

opaque-evidence prepare-retention \
  --enrollment /verifier/producer-enrollment.json \
  --checkpoint /received/checkpoint.json --export /received/audit.jsonl \
  --output /received/request.json
```

Replace uppercase values with the actual public key, independently checked
fingerprint, build identity and retained digest. The optional checkpoint pin compares
canonical checkpoint identity to that supplied reference; the CLI cannot establish
where the caller obtained it. For a later snapshot, pass `create --previous` with the
previous signed checkpoint. A receiver must separately require the exact checkpoint
it retained, rather than accepting a sender-selected predecessor as its own history.
`verify` reports whether a checkpoint pin matched. Without a pin, freshness is not
checked; even a matching pin proves only identity to that reference, not that it is
the source's latest checkpoint. The CLI reports history as unchecked because this
command verifies one checkpoint rather than a retained sequence of checkpoints.

`create` verifies the local HMAC chain, authenticated tail and retention boundary
inside the same read transaction used to export bytes. It signs only that verified
snapshot, not an arbitrary export file. The output directory contains `audit.jsonl`,
`checkpoint.json` and `retention-request.json`. A partial failed output is retained
for explicit inspection and is never silently reused or overwritten.

Snapshots are bounded to 64 MiB, 100,000 records, 1 MiB per record and 128 declared
interior sequence gaps. Larger histories require a separately controlled archival
procedure; this command does not delete records to fit them. Retained-prefix absence
is visible through the first sequence/coverage start. An unknown missing tail cannot
be inferred from one producer-selected snapshot.

## Wire contract and verification

`opaque_core::evidence_checkpoint` exposes typed, versioned documents with unknown
and duplicate fields rejected on decode. Canonical V1 bytes are compact UTF-8 JSON
in the declared struct field order, with no maps or floating-point fields. Transport
JSON may be pretty printed; implementations reconstruct the canonical typed form.
Signatures use Ed25519 strict verification with distinct domain prefixes:

- `opaque.evidence.checkpoint.v1` followed by NUL and canonical checkpoint payload.
- `opaque.evidence.retention.v1` followed by NUL and canonical retention payload.

Public keys, signatures and digests use lowercase hexadecimal. A key ID is the
SHA-256 digest of the raw 32-byte public key. The checkpoint digest is SHA-256 over
the canonical signed envelope, including its signature. The export digest is
SHA-256 over the exact JSONL bytes, including record terminators.

A checkpoint binds exact scope/generation, producer key ID, checkpoint sequence,
first/last event sequence, record count, export digest, previous checkpoint digest,
declared build identity, coverage start and interior gaps. Verification checks the
enrolled key/scope, strict signature, exact export digest, framing, event identities,
ordered sequences and correspondence between actual range/count/gaps and signed
metadata. It does not verify HMACs using a public key; the producer verified its
local HMAC chain before signing the snapshot.

## Independent retention receipts

`RetentionRequest` binds a checkpoint envelope and its checkpoint/export digests.
It is a prepared artifact, not proof of delivery. A custodian must verify the
producer enrollment and exact bytes, enforce per-generation high-water history,
durably retain/read back the objects, and only then sign its receipt.

`SignedRetentionReceipt` binds the custodian key, exact scope, checkpoint and export
digests, range/count, object/version identity, previous receipt digest, receipt time
and retention deadline. The public verifier checks that binding, signature and
retention interval against an independently enrolled `CustodianTrust` document:

```sh
opaque-evidence verify-receipt \
  --enrollment /verifier/producer-enrollment.json \
  --custodian-enrollment /verifier/custodian-enrollment.json \
  --checkpoint /received/checkpoint.json --export /received/audit.jsonl \
  --receipt /received/receipt.json --now-unix-ms CURRENT_UNIX_MILLISECONDS \
  --expected-receipt-sha256 INDEPENDENTLY_RETAINED_RECEIPT_DIGEST
```

The custodian enrollment has `schema_version: 1`, `key_id` and `public_key`; it must
come from the independently selected custodian. A signed receipt is an authenticated
retention commitment. The verifier rejects use of the producer's signing key as
the custodian key. Distinct keys still do not establish separate administrators or
physical custody. A signed receipt alone cannot prove physical independence, WORM configuration,
read-back, key availability or future object retention. Deployments must validate
those properties and preserve their own object/version references separately.

## Authenticated local head and older databases

The local `chain_head` now includes format version 1 and a domain-separated HMAC
over its tail hash and sequence, updated atomically with audit rows. Removing a
suffix and replacing the head with a surviving row's public hash cannot forge this
authenticator. The empty genesis head is authenticated too. Missing, altered or
unsupported authenticated heads stop verification and startup.

An existing unversioned head is not automatically trusted or upgraded. Stop every
old writer and preserve the complete custody state. Use an exact export digest
already established independently before applying the explicit offline upgrade:

```sh
opaque-evidence legacy-inspect --database /custody/audit.db \
  --output /review/current-legacy-export.jsonl

opaque-evidence upgrade-legacy --database /custody/audit.db \
  --trusted-export-sha256 INDEPENDENTLY_RETAINED_ORIGINAL_EXPORT_DIGEST
```

Today's `legacy-inspect` output is not a historical trust anchor. An attacker who
already shortened an old log and updated its unkeyed head can produce a consistent
current export. If the original independent reference is unavailable, this tool
cannot prove its completeness: retain the legacy evidence and establish a new,
explicitly discontinuous source rather than manufacturing an upgrade pin.

The upgrade verifies the old HMAC chain and exact trusted export bytes before any
head/schema change in one writer transaction. It preserves every existing record
authenticator and refuses to re-anchor an already versioned database. An unchained
database is never automatically backfilled into authenticated history.

A local head MAC does not prevent restoration of an older intact database and
authentic head, nor a reset of the trusted custody environment. Compare with
independently retained checkpoints and fence generations. The audit contract is
separate from authority recovery: a recovery manifest must bind exact identity,
task, MCP, approval and policy snapshots to a fenced authority generation. Missing
consumption or revocation history requires quarantine or fresh authority; an audit
export cannot reconstruct permission or refund an unknown external effect.
