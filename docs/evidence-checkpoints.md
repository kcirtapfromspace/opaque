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
valid, so a retained high-water reference is necessary to detect a rollback. An
exact already-retained checkpoint may be returned idempotently without advancing
that reference; a duplicate acknowledgment is not evidence that it is the latest
checkpoint. Receivers must also reject changes to already-retained event records
inside overlapping ranges, even when the new checkpoint has a valid signature.

V1 key replacement requires explicit enrollment of a new stream generation. The
new generation is visibly discontinuous; it must not erase the previous generation's
records, revocation or missing coverage. No implicit same-generation key rotation
or recovery is performed. A compromised enrolled key can sign false claims; a
signature does not make a compromised producer truthful.

## Commands

These examples use a source-built binary from a reviewed checkout. Do not assume
an installed release already contains these commands. From the core repository:

```sh
cargo build --locked -p opaque --bin opaque-evidence
EVIDENCE="${CARGO_TARGET_DIR:-target}/debug/opaque-evidence"
"$EVIDENCE" --help
umask 077
```

The remaining examples use explicit paths. Provision the parent directories under
the appropriate broker or verifier account first. The audit database must already
exist and its matching sibling `.hmac` file must be available to the producer.
For `/custody/audit.db`, that file is `/custody/audit.hmac`. Verification on the
receiving side needs neither file. Keep all generated outputs at fresh paths.

Generate a dedicated producer key under broker custody. Its public JSON file
contains `schema_version`, `public_key` and `key_id`; the command's stdout is a
separate status object. After authenticating that public key and fingerprint,
create the scoped enrollment on the verifier side:

```sh
"$EVIDENCE" keygen \
  --private-key /custody/evidence.key \
  --public-key /custody/evidence-public.json

"$EVIDENCE" enroll \
  --public-key PUBLIC_KEY_HEX --key-id INDEPENDENTLY_CHECKED_SHA256_FINGERPRINT \
  --tenant tenant-a --broker broker-a --stream audit --generation generation-1 \
  --output /verifier/producer-enrollment.json
```

Transfer an authenticated copy of that enrollment to
`/custody/producer-enrollment.json`. The producer uses its own private key and the
same enrollment to create the first snapshot:

```sh
"$EVIDENCE" create \
  --database /custody/audit.db --private-key /custody/evidence.key \
  --enrollment /custody/producer-enrollment.json --build-identity REVIEWED_BUILD_ID \
  --output /custody/checkpoint-1
```

The command prints `checkpoint_sha256` and `export_sha256`. Preserve the expected
checkpoint digest through the verifier's trusted reference channel. Transfer only
`checkpoint.json` and `audit.jsonl` from that snapshot directory to `/received`;
leave the database, audit HMAC and producer private key in broker custody.

```sh
"$EVIDENCE" verify \
  --enrollment /verifier/producer-enrollment.json \
  --checkpoint /received/checkpoint.json --export /received/audit.jsonl \
  --expected-checkpoint-sha256 EXPECTED_CHECKPOINT_DIGEST

"$EVIDENCE" prepare-retention \
  --enrollment /verifier/producer-enrollment.json \
  --checkpoint /received/checkpoint.json --export /received/audit.jsonl \
  --expected-checkpoint-sha256 EXPECTED_CHECKPOINT_DIGEST \
  --output /received/request.json
```

Replace uppercase values with the actual public key, independently checked
fingerprint, build identity and expected digest. The checkpoint pin identifies the
checkpoint being verified, not its predecessor. It compares canonical checkpoint
identity to that supplied reference; the CLI cannot establish where the caller
obtained it. A sender-supplied digest alongside the same package does not provide
independent history.

For a later snapshot, use a fresh output directory and pass `create --previous`
with the previous signed checkpoint. A receiver must require the exact predecessor
it retained. Accepting a sender-selected predecessor cannot replace the receiver's
own history. `verify` reports whether a checkpoint pin matched. Without a pin,
freshness is not checked; even a matching pin proves only identity to that reference,
not that it is the source's latest checkpoint. The CLI reports history as unchecked
because this command verifies one checkpoint rather than a retained sequence.

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
retention interval against an independently enrolled `CustodianTrust` document.
`--now-unix-ms` is the verifier's current Unix time in milliseconds, supplied by a
trusted clock; copying the receipt's own timestamp bypasses a current-expiry check.
For example, obtain it with `python3 -c 'import time; print(time.time_ns() // 1000000)'`.
The tool does not query a time service:

```sh
"$EVIDENCE" verify-receipt \
  --enrollment /verifier/producer-enrollment.json \
  --custodian-enrollment /verifier/custodian-enrollment.json \
  --checkpoint /received/checkpoint.json --export /received/audit.jsonl \
  --receipt /received/receipt.json --now-unix-ms CURRENT_UNIX_MILLISECONDS \
  --expected-receipt-sha256 INDEPENDENTLY_RETAINED_RECEIPT_DIGEST
```

Both checkpoint and receipt pins hash the canonical typed signed envelope. Do not
use a checksum of pretty-printed JSON or a status response as either pin. On first
receipt verification, omitting `--expected-receipt-sha256` still verifies the enrolled
custodian signature and exact checkpoint/export binding; it does not establish
previous receipt history. Record the successful result's `receipt_sha256` in the
verifier's independently controlled reference store, then require that reference
when checking that same receipt later. A successful receipt verification says
nothing about newer receipts the verifier has not observed.

The custodian enrollment has `schema_version: 1`, `key_id` and `public_key`; it must
come from the independently selected custodian. A signed receipt is an authenticated
retention commitment. The verifier rejects use of the producer's signing key as
the custodian key. Distinct keys still do not establish separate administrators or
physical custody. A signed receipt alone cannot prove physical independence, WORM
configuration, read-back, key availability or future object retention. Deployments
must validate those properties and preserve their own object/version references
separately.

## Authenticated local head and older databases

The local `chain_head` now includes format version 1 and a domain-separated HMAC
over its tail hash and sequence, updated atomically with audit rows. Removing a
suffix and replacing the head with a surviving row's public hash cannot forge this
authenticator. The empty genesis head is authenticated too. Missing, altered or
unsupported authenticated heads stop verification and startup. The head and
retention-boundary tables must each contain at most their single `id=0` row and
must have no attached triggers; unexpected metadata structure is rejected before
maintenance or upgrade. The normal audit-event full-text-search triggers remain
supported. Preserve malformed custody for investigation rather than deleting its
unexpected metadata to force startup.

An existing unversioned head is not automatically trusted or upgraded. This is an
offline format upgrade of audit evidence, not a restore procedure:

1. Stop every old writer, including the broker and background export/retention jobs.
   Keep them stopped until the upgraded writer is ready. Do not start the old binary
   again against the upgraded custody state.
2. Preserve a consistent custody backup using the stopped writer or a supported
   SQLite backup procedure. Preserve the matching sibling `.hmac`, database and any
   remaining WAL/SHM files together; copying only a live database file can omit
   committed events. Keep authority stores and their generations intact too.
3. Obtain the previously independently archived export for the **exact retained
   rows** being upgraded and its authenticated provenance. The required digest is
   SHA-256 of those exact compact `opaque.audit.v1` JSONL bytes in insertion order,
   with one LF after every record, original `rowid`/hash values and no wrapper.
   It is not a database-file checksum, checkpoint digest, webhook JSON array,
   syslog frame or a reserialized/deduplicated SIEM result. A spool containing
   retries, an older snapshot before legitimate appends, or already-pruned rows
   does not automatically match this range. Stop and reconcile against independent
   evidence rather than substituting a newly calculated local pin.
4. Inspect to a fresh file, compare it with the independently archived exact bytes,
   and then provide that archive's authenticated digest to the upgrade:

```sh
"$EVIDENCE" legacy-inspect --database /custody/audit.db \
  --output /review/current-legacy-export.jsonl

cmp /independent/archive/exact-retained-export.jsonl /review/current-legacy-export.jsonl

"$EVIDENCE" upgrade-legacy --database /custody/audit.db \
  --trusted-export-sha256 INDEPENDENTLY_RETAINED_EXACT_EXPORT_DIGEST
```

`legacy-inspect` prints its current `export_sha256` and writes the compared bytes;
it does not enroll that digest as trusted. Inspection and upgrade have the same
64 MiB/100,000-record export bounds. A size failure requires an archival plan; do
not delete audit rows or regenerate the HMAC key to fit the tool.

An empty legacy export is always refused by `upgrade-legacy`, even when its digest
matches an independently archived empty export. Empty bytes cannot bind a historical
sequence frontier: genesis, a fully pruned history and erased legacy boundaries
share that digest. This version has no in-place upgrade for that case. Preserve
the existing custody and independent historical evidence for a reviewed migration;
do not delete/recreate the database, remove boundaries or append an invented event
to make the upgrade pass. A new source, if separately authorized, must preserve the
old custody and visibly start a distinct generation; it does not recover authority.

Today's `legacy-inspect` output is not a historical trust anchor. An attacker who
already shortened an old log and updated its unkeyed head can produce a consistent
current export. If the original independent reference is unavailable, this tool
cannot prove its completeness: retain the legacy evidence and establish a new,
explicitly discontinuous source rather than manufacturing an upgrade pin.

The upgrade verifies the old HMAC chain and exact trusted export bytes before any
head/schema change in one writer transaction. A mismatched pin leaves row content
and head schema unchanged. After writing the authenticated head, the transaction
verifies the chain and rechecks the exact export digest before committing. Success
adds only the authenticated head format and preserves every existing record
authenticator. Confirm the new writer starts and
create/verify a first signed checkpoint before resuming normal work. A second
upgrade attempt is an error: an already versioned database is never re-anchored.
An unchained database is never automatically backfilled into authenticated history.

A local head MAC does not prevent restoration of an older intact database and
authentic head, nor a reset of the trusted custody environment. Compare with
independently retained checkpoints and fence generations. The audit contract is
separate from authority recovery: a recovery manifest must bind exact identity,
task, MCP, approval and policy snapshots to a fenced authority generation. Missing
consumption or revocation history requires quarantine or fresh authority; an audit
export cannot reconstruct permission or refund an unknown external effect.

## Focused validation

From the source checkout, these isolated suites cover the actual CLI and audit
checkpoint API without using a live audit store or native credential prompt:

```sh
cargo test --locked -p opaque --test evidence_cli
cargo test --locked -p opaque-core --test evidence_checkpoint
```

The checkpoint suite covers suffix/head rewrites, independent scope/key pins,
explicit legacy upgrade, preserved authenticators, rejected legacy truncation and
empty-frontier ambiguity, malformed metadata and unexpected-trigger refusal,
retained-reference rollback detection and receipt key/deadline checks. Synthetic
fixtures establish software behavior; they do not establish production key custody,
independent storage, human-reviewed migration provenance or authority recovery.
