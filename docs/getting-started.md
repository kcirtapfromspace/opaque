# Getting Started (Local)

Opaque is a local secrets broker made of:

- `opaqued`: trusted local daemon (enclave, policy, approvals, audit)
- `opaque`: untrusted CLI client

Everything flows through `Enclave::execute()` and results are sanitized so plaintext secrets never enter LLM-visible output.

## Build

```bash
cargo build --release
```

Binaries:

- `./target/release/opaqued`
- `./target/release/opaque`

## Initialize Local State

`opaque init` creates:

- `~/.opaque/config.toml` (policy + daemon config)
- `~/.opaque/profiles/` (exec profiles)
- `~/.opaque/run/` (socket fallback; prefer `XDG_RUNTIME_DIR` on Linux)

```bash
./target/release/opaque init
```

## Minimal Policy (Example)

Policy is deny-by-default. Start by allowing only low-risk test operations.

```toml
[[rules]]
name = "allow-test-noop"
operation_pattern = "test.*"
allow = true
client_types = ["human", "agent"]

[rules.client]

[rules.approval]
require = "never"
factors = []
```

Validate:

```bash
./target/release/opaque policy check
```

For the full config format, see `docs/policy.md` and `examples/policy.toml`.

## Run The Daemon

In one terminal:

```bash
./target/release/opaqued
```

In another terminal:

```bash
./target/release/opaque ping
./target/release/opaque version
./target/release/opaque whoami
```

## Execute Operations

### `test.noop`

```bash
./target/release/opaque execute test.noop
```

### `sandbox.exec` (Profile-Based)

1. Create a profile at `~/.opaque/profiles/dev.toml` (example: `examples/profiles/dev.toml`)
2. Run:

```bash
./target/release/opaque exec --profile dev -- echo "hello from sandbox"
```

`sandbox.exec` intentionally does **not** return stdout/stderr contents (only lengths + exit code) to avoid leaking secrets via command output.

### `github.set_actions_secret`

```bash
./target/release/opaque github set-secret \
  --repo owner/repo \
  --secret-name MY_TOKEN \
  --value-ref keychain:opaque/my-token
```

This operation is `SAFE`: it never returns the secret value or ciphertext.

## Audit

The daemon writes a local SQLite audit DB at `~/.opaque/audit.db`.

```bash
./target/release/opaque audit tail --limit 50
```

## Environment Variables

- `OPAQUE_CONFIG`: override daemon/CLI config path (default: `~/.opaque/config.toml`)
- `OPAQUE_SOCK`: override socket path for the CLI only (daemon ignores it)
- `OPAQUE_GITHUB_TOKEN_REF`: override default GitHub PAT secret ref used by `github.set_actions_secret`

## Next

- Demo recordings: `docs/demos.md`
- Deployment & OS approval backends: `docs/deployment.md`

