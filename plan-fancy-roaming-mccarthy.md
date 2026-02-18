# Plan: Opaque Public Launch (OSS + MCP + Bitwarden)

## Context

The PRD (`tasks/prd-opaque-public-launch.md`) requires shipping Opaque as a credible open-source alpha with MCP integration, Bitwarden support, and low-friction onboarding. Decisions: Alpha launch, Claude+Codex in parallel, Bitwarden Secrets Manager, macOS+Linux.

The codebase is functionally complete for v1 (policy engine, approval system, audit logging, GitHub/1Password providers, sandboxed exec, Linux polkit) and the P0/P1 security fixes are already merged. What's missing: OSS scaffolding, CI/CD, MCP server, Bitwarden provider, policy presets, and version stamping.

---

## Phase 0: OSS Scaffolding (Blocks repo going public)

Create standard OSS files at repo root. Zero code changes.

| File | Content |
|------|---------|
| `LICENSE` | Apache-2.0 |
| `SECURITY.md` | Disclosure process, supported versions, contact |
| `CONTRIBUTING.md` | Dev setup, `cargo test/clippy/fmt`, PR expectations |
| `CODE_OF_CONDUCT.md` | Contributor Covenant v2.1 |
| `.github/ISSUE_TEMPLATE/bug_report.md` | Bug template |
| `.github/ISSUE_TEMPLATE/feature_request.md` | Feature template |
| `.github/PULL_REQUEST_TEMPLATE.md` | PR checklist |

Also update `README.md`: add license badge, install instructions (macOS + Linux), link quickstart.

---

## Phase 1: CI/CD + Version Stamping

### 1.1 Test CI (`.github/workflows/ci.yml`)
- Trigger: push to main, PRs
- Matrix: `{os: [ubuntu-latest, macos-latest]}`
- Steps: `cargo build --workspace`, `cargo test --workspace`, `cargo clippy -- -D warnings`, `cargo fmt --check`

### 1.2 Release CI (`.github/workflows/release.yml`)
- Trigger: git tag `v*`
- Build matrix: `{x86_64-linux, aarch64-linux, x86_64-macos, aarch64-macos}`
- Steps: cross-compile binaries, strip, tar.gz, SHA-256 checksums, GitHub Release with artifacts

### 1.3 Version + git SHA
- Add `vergen` build dependency to embed git SHA at compile time
- `opaque version` prints `0.1.0+abc1234` instead of just `0.1.0`
- Files: `crates/opaque/build.rs`, `crates/opaqued/build.rs`, both `main.rs`

---

## Phase 2: Bitwarden Secrets Manager Integration

Follow the 1Password provider pattern exactly. New module at `crates/opaqued/src/bitwarden/`.

### 2.1 API Client (`bitwarden/client.rs`)
- Pattern: `crates/opaqued/src/onepassword/client.rs`
- Bitwarden Secrets Manager REST API with service account bearer token
- Default base URL: `https://api.bitwarden.com` (override via `OPAQUE_BITWARDEN_URL`)
- URL scheme validation (reuse `validate_url_scheme` pattern)
- Endpoints: list projects, list secrets, get secret by ID
- Types: `BitwardenProject`, `BitwardenSecret`, `BitwardenApiError`

### 2.2 Secret Resolver (`bitwarden/resolve.rs`)
- Pattern: `crates/opaqued/src/onepassword/resolve.rs`
- Ref format: `bitwarden:<secret-id>` (UUID) or `bitwarden:<project>/<secret-key>`
- Resolver fetches secret value inside daemon, returns `SecretValue` (mlock'd, zeroed on drop)
- Token sourced via env/keychain only (no cycles)

### 2.3 Operation Handler (`bitwarden/mod.rs`)
- Pattern: `crates/opaqued/src/onepassword/mod.rs`
- Operations to register:
  - `bitwarden.list_projects` — Safety: `Safe`, Approval: `FirstUse`
  - `bitwarden.list_secrets` — Safety: `Safe`, Approval: `FirstUse`, params: `{ project?: string }`
  - `bitwarden.read_secret` — Safety: `Reveal` (hard-blocked in v1, like `onepassword.read_field`)

### 2.4 Wiring
- `crates/opaqued/src/main.rs`: Add `mod bitwarden;`, register operations, wire handler
- `crates/opaque-core/src/profile.rs`: Add `"bitwarden:"` to `ALLOWED_REF_SCHEMES`
- `crates/opaqued/src/sandbox/resolve.rs`: Add `bitwarden:` dispatch to `CompositeResolver`
- `crates/opaqued/src/main.rs` (convenience wrapper): Add `"bitwarden"` method handler like the existing `"onepassword"` wrapper, populate `secret_ref_names`

### 2.5 Tests
- Wiremock-based API client tests (list projects, list secrets, get secret, auth errors)
- Resolver ref parsing tests (valid, invalid, edge cases)
- Handler dispatch tests (unknown action, missing params)
- Safety test: `bitwarden.read_secret` is Reveal-blocked

---

## Phase 3: MCP Server (Biggest feature)

### Architecture: New `opaque-mcp` crate

The MCP server is a thin protocol adapter, NOT part of the daemon. It connects to `opaqued` over the Unix socket as an Agent client, translating MCP JSON-RPC to Opaque IPC. All safety enforcement stays in the daemon.

```
Claude Code  --MCP/stdio-->  opaque-mcp  --Unix socket-->  opaqued (enclave)
```

### 3.1 Crate setup (`crates/opaque-mcp/`)
- Add to workspace `Cargo.toml`
- Dependencies: `opaque-core`, `serde`, `serde_json`, `tokio`, `tracing`, `rmcp` (Rust MCP SDK)
- Binary: `opaque-mcp`
- Use `rmcp` crate to handle MCP protocol plumbing (JSON-RPC, tool schema, transport)

### 3.2 Daemon client (`daemon_client.rs`)
- Connect to daemon Unix socket (reuse `opaque_core::socket::socket_path()`)
- Handshake with daemon token
- Send/receive `Request`/`Response` frames via `LengthDelimitedCodec`
- This is the same IPC pattern as the CLI — consider extracting shared client logic into `opaque-core`

### 3.3 MCP protocol (`main.rs`)
- Transport: stdio (JSON-RPC 2.0 over stdin/stdout) via `rmcp` SDK
- Tracing to stderr only (stdout is MCP transport)
- Implement `rmcp::ServerHandler` trait (or equivalent) for tool dispatch
- `rmcp` handles initialize/capabilities/tools_list plumbing; we provide tool definitions and call handler

### 3.4 Tool definitions (`tools.rs`)
- Hard-coded Safe operation list (defense-in-depth, not dynamic discovery):
  - `opaque_github_set_actions_secret`
  - `opaque_github_set_codespaces_secret`
  - `opaque_github_set_dependabot_secret`
  - `opaque_github_set_org_secret`
  - `opaque_github_list_secrets`
  - `opaque_github_delete_secret`
  - `opaque_onepassword_list_vaults`
  - `opaque_onepassword_list_items`
  - `opaque_bitwarden_list_projects`
  - `opaque_bitwarden_list_secrets`
- NOT exposed: `sandbox.exec` (SensitiveOutput), `*.read_field`/`*.read_secret` (Reveal), `test.noop`
- Each tool has name, description, and JSON Schema `inputSchema`

### 3.5 Tool execution flow
1. MCP `tools/call` arrives with tool name + arguments
2. Map tool name to Opaque operation (e.g., `opaque_github_set_actions_secret` -> method `"github"`, params with scope/action)
3. Build IPC `Request`, send to daemon
4. Receive sanitized `Response` from daemon
5. Return as MCP tool result (content array with text type)

### 3.6 Tests
- MCP JSON-RPC parsing (initialize, tools/list, tools/call)
- Tool schema completeness (all Safe ops present, no Reveal/SensitiveOutput)
- End-to-end: mock daemon socket, MCP tool call, verify sanitized response
- Safety: verify tool list excludes dangerous operations

---

## Phase 4: Policy Presets

### 4.1 Preset files (embedded in binary via `include_str!`)
- `safe-demo`: test.noop only, deny-all else
- `github-secrets`: Allow Claude/Codex to sync GitHub Actions/Codespaces/Dependabot secrets
- `sandbox-human`: Allow human-only sandbox.exec, deny agent sandbox access
- Each preset is a complete `config.toml` with `[[rules]]` and `[[known_human_clients]]`

### 4.2 CLI commands
- `opaque policy presets` — list available presets with descriptions
- `opaque init --preset <name>` — initialize with a preset config (or `opaque policy preset apply <name>`)
- Files: `crates/opaque/src/main.rs`, `crates/opaque/src/setup.rs`

---

## Phase 5: Documentation

### New docs
- `docs/mcp-integration.md`: Claude Code MCP config, available tools, safety model, troubleshooting
- `docs/bitwarden.md`: Service account setup, ref format, profile examples, end-to-end workflow

### Updates
- `docs/operations.md`: Add Bitwarden operations
- `docs/getting-started.md`: Add Bitwarden setup, MCP quickstart
- `docs/llm-harness.md`: Mention MCP as the preferred path, CLI harness as fallback
- `docs/roadmap-deferred.md`: Mark MCP + Bitwarden as shipped
- `README.md`: Install for all 4 binaries, MCP quickstart for Claude Code, CLI quickstart for Codex

---

## Implementation Order & Parallelism

```
Week 1 (Foundation + Bitwarden):
  Phase 0: OSS files                    ████  (Day 1-2, all parallel)
  Phase 1.1: Test CI                    ██    (Day 2-3)
  Phase 1.3: Version+SHA               ██    (Day 2-3, parallel with CI)
  Phase 2: Bitwarden provider           ██████████  (Day 2-7, parallel with CI)

Week 2 (MCP + Polish):
  Phase 1.2: Release CI                 ████  (Day 8-9)
  Phase 3: MCP server                   ████████████████  (Day 5-12, critical path)
  Phase 4: Policy presets               ████  (Day 8-10, parallel with MCP)
  Phase 5: Documentation                ██████  (Day 10-12, as features land)

Alpha release tag: end of Week 2
```

### Alpha must-haves
- OSS files (LICENSE, SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md)
- Test CI workflow
- MCP server exposing Safe operations
- Bitwarden `bitwarden:` ref scheme in resolver
- Basic MCP + Bitwarden docs

### Alpha nice-to-haves (can follow immediately after)
- Release CI with cross-compiled artifacts + checksums
- Policy presets
- Version+git SHA stamping
- Bitwarden browsing operations (list_projects, list_secrets)

---

## Key Files to Modify/Create

| File | Change |
|------|--------|
| `LICENSE` | **New** — Apache-2.0 |
| `SECURITY.md` | **New** |
| `CONTRIBUTING.md` | **New** |
| `CODE_OF_CONDUCT.md` | **New** |
| `.github/workflows/ci.yml` | **New** — test matrix |
| `.github/workflows/release.yml` | **New** — release pipeline |
| `crates/opaque-mcp/` | **New crate** — MCP server |
| `crates/opaqued/src/bitwarden/` | **New module** — Bitwarden provider |
| `crates/opaque-core/src/profile.rs` | Add `"bitwarden:"` to `ALLOWED_REF_SCHEMES` |
| `crates/opaqued/src/sandbox/resolve.rs` | Add Bitwarden dispatch to `CompositeResolver` |
| `crates/opaqued/src/main.rs` | Register Bitwarden operations + handler wiring |
| `Cargo.toml` | Add `opaque-mcp` to workspace members |
| `README.md` | Update install/quickstart |

---

## Verification

1. `cargo build --workspace` compiles (including new `opaque-mcp` and Bitwarden modules)
2. `cargo test --workspace` — all tests pass
3. `cargo clippy --workspace` — zero warnings
4. MCP smoke test: `echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | opaque-mcp` returns Safe tools only
5. MCP safety: tool list contains zero SensitiveOutput/Reveal operations
6. Bitwarden: profile with `bitwarden:` ref passes validation
7. Bitwarden: wiremock tests verify API client + resolver
8. CI: GitHub Actions workflow runs on push/PR
9. OSS: LICENSE, SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md present at root
