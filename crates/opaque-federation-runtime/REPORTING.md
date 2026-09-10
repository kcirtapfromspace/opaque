# Embedding signed broker reporting

The public `fleet` module contains a versioned software-report contract and a
bounded broker reporter. It has no dependency on an enterprise collector,
management API, license server, or enrollment database. Consumers can implement
collectors or integrate reports into their own applications.

`Heartbeat` v1 carries a challenge, compact audit metadata and an existing
Ed25519 `opqa1` software attestation. `Heartbeat::nonce_for` hashes the exact
serialized `(Challenge, Evidence)` tuple with the `opaque.fleet.heartbeat.v1`
domain prefix. Existing v1 wire bytes are preserved. The report says what a
holder of the pinned key observed; it is not hardware attestation or proof of
complete fleet discovery.

`verify_heartbeat` checks the expected tenant/broker binding, signature, schema,
batch limit and report freshness. A caller pins the verifying key independently.
See [the independent verifier example](examples/verify_broker_report.rs).

A production consumer must also authenticate the reporting connection, enroll
keys, maintain epochs and revocations, compare the exact outstanding challenge,
and atomically consume accepted challenges. Verification alone is stateless and
will verify an identical report twice while it is fresh. Evidence frontiers,
contiguous coverage, persistent receipts and enrollment rotation are consumer
responsibilities. Signing a heartbeat never authorizes task execution.

`reporter::Reporter` sends at most 128 audit event IDs, sequence numbers and record
hashes per heartbeat; it does not export full event payloads. The collector root
must use HTTPS, except an explicit loopback HTTP address for local integrations.
Redirects and environment proxies are disabled. Credentials must be private
files directly within broker custody. Requests and responses have size/time
bounds, and acknowledgments are checked against the challenge and sent batch.
The reporter uses these stable routes:

- `POST /v1/tenants/{tenant}/brokers/{broker}/challenge`
- `POST /v1/tenants/{tenant}/brokers/{broker}/heartbeat`

A public-only consumer can build and exercise the protocol with:

```sh
cargo test -p opaque-federation-runtime --test broker_reporting_contract
cargo run -p opaque-federation-runtime --example verify_broker_report -- \
  heartbeat.json binding.json PINNED_PUBLIC_KEY_HEX
```
