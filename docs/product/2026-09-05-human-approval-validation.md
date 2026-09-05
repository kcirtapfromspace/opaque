# Human approval implementation and local validation

Private operator record. Exclude this file from public site routes and assets.

The hosted bounded-task UI now opens an accessible review dialog. The displayed
manifest is compared with the exact serialized bytes hashed by the service.
Web Crypto computes SHA-256 and a build-generated WebAssembly module checks
the digest, one-use allowance, 60-second source window, and bounded expiry.
This is a local review aid; server verification and the durable ledger enforce
the authority independently.

Opaque verifies passkey registration and a separate, fresh WebAuthn assertion
using `webauthn-rs`. User verification is required. A pending ceremony binds the
browser session, resource JTI, task ID, manifest digest, persona generation and
deadline. Legacy unsigned approvals cannot execute new source reads. Credentials
are temporary server-side enrollments and do not establish production tenant
membership. The authenticator can retain its demo credential after the session.

## Browser qualification

September 5, 2026, local native gateway with a synthetic source and Chromium CDP
virtual authenticator. No personal authenticator or GitHub credential was used.

- Desktop and 390 × 844 mobile review layouts inspected.
- Actual WASM executes under the generated script-hash CSP, with
  `wasm-unsafe-eval` and without JavaScript `unsafe-eval`.
- Escape closes review, restores focus to the review button, and leaves the
  task planned.
- Browser `navigator.credentials.create()` and `.get()` completed; the service
  recorded `webauthn`, user verification, and the credential identifier digest.
- Approval left the task unconsumed and showed no execution receipt.
- Explicit **Run once** completed one source read and displayed 17.25% from
  the fixture. **Test replay denial** returned HTTP 409 and retained that receipt.
- The deliberate HTTP 409 was the only browser console error observed.

Screenshots and raw browser state were kept in ignored or OS temporary storage.
The temporary fixture and cookie file were removed after qualification.

## Automated qualification

The final direct-GitHub revision passed 53 Rust unit tests and 43 gateway tests,
with one explicitly ignored interactive browser fixture. Clippy with warnings
denied and Rust formatting passed. The browser/edge suites passed 138 tests
including the actual compiled WASM cases; hosted Python tests passed 64 tests.
The Linux/ARM64 optimized test suite also passed before image packaging.

To include the actual build-generated module in the UI tests:

```sh
cargo build --locked -p opaque-metrics
# Select the approval-wasm.json emitted by that build under target/debug/build.
OPAQUE_APPROVAL_WASM_JSON=/absolute/path/to/approval-wasm.json \
  node --test crates/opaque-metrics/tests/ui.test.cjs
```

## GitHub and deployment status

The user selected direct GitHub OAuth for the public demo after live inspection
showed that the Argo Dex issuer was tailnet-only and the hosted controller could
not resolve it. Argo/Dex must remain unchanged. The intended OAuth application
owner is `opaque-dev`, with callback `https://demo.opaque.info/approval/callback`.
Direct GitHub login requests only public account identity, never repository or
private-email scope. The Opaque Demo Approval application was registered under `opaque-dev` with an
exact callback and no wildcard or device-flow setting. Runtime secret injection
and a live human login must be verified separately from fixture tests.

No live rollout has been performed by this record. Preserve active leases and
existing slot generation state during rollout; never apply bootstrap slot state
over an existing deployment.
