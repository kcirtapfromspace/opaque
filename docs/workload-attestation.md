# Constrain access to observed workloads

Use `[rules.client]` to require observations made by the broker's Unix listener.
For example, require a client running as UID 1001 with at least medium evidence:

```toml
[[rules]]
name = "inventory-from-service-user"
operation_pattern = "github.list_secrets"
allow = true

[rules.client]
attestor = "peercred"
min_attestation = "medium"
selectors = ["peercred:uid:1001"]

[rules.approval]
require = "always"
factors = ["local_bio"]
```

The selected UID must differ from the broker's effective UID to achieve
`medium` with this listener. Same-UID connections achieve `weak`. A missing
observation never satisfies a constrained rule, including a `none` minimum.
The listener rejects connections when peer credentials are unavailable.

Every configured selector must match exactly; selectors do not interpret globs.
The `peercred` source emits `uid`, `gid`, and available `exe_path`/`exe_sha256`
observations. On macOS it also emits `codesign_team_id` when native code-signing
validation establishes an Apple-anchored signing team. A policy can require
the same value with the existing `codesign_team_id` field or an exact selector
such as `peercred:codesign_team_id:TEAMID1234`.

The macOS lookup uses the kernel's connection audit token and Security.framework
dynamic code validation. It does not substitute a PID-only lookup or parse
`codesign` command output. Missing tokens, invalid signatures, ad-hoc signatures,
and absent Team IDs supply no team observation. A valid software signing team
does not increase the connection's strength.

Trusted workload source, achieved strength, and canonical selector set bind
the operation approval hash and first-use allowance. Deserialized client claims
cannot supply this context. A changed observation cannot reuse the old approval
or allowance. Unknown client-policy fields are rejected to catch misspelled or
unsupported constraints.

These observations identify the connection's executable and operating-system
principal. A signed interpreter identifies its runtime publisher; it does not
authenticate the script, prompt, or individual agent executing inside it.
Possession or transfer of a connected socket remains part of the process trust
boundary. Hardware measurements and a configurable multi-attestor registry are
not implemented by this listener.

This contract is implemented in source and requires a release containing it.
The opt-in macOS regression uses installed signed and ad-hoc Node runtimes as
isolated socket clients. Set `OPAQUE_TEST_SIGNED_NODE`, `OPAQUE_TEST_ADHOC_NODE`,
and independently verified `OPAQUE_TEST_SIGNED_TEAM_ID`, then run:

```sh
cargo test --locked -p opaque-federation-runtime --lib \
  workload_attest::tests::live_signed_and_adhoc_child_socket_attestation \
  -- --exact --ignored
```

The check verifies observed team identity, policy matching, unchanged weak
strength, and rejection of a mismatched process incarnation. It never signs a
binary or uses a signing certificate.

Native API contract: [Apple guest attributes](https://developer.apple.com/documentation/security/guest-attribute-dictionary-keys)
and [dynamic code validation](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:)).
