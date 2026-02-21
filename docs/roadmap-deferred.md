# Deprioritized Features Roadmap

Features cut from v1 PRD, organized by when they should be revisited.

## Gate criteria

Do not start a phase until the prior phase is shipped, tested with real users, and stable. "Stable" means: no critical bugs open, audit log shows clean event chains for 2+ weeks of daily use, zero secret leaks in production.

---

## v2: Multi-Provider + MCP Integration

**Prerequisites:** v1 shipped. At least one real user has completed the GitHub Actions secret workflow end-to-end. Audit log has real data. Policy engine has been exercised by multiple client identities.

| Feature | Description | Status | Effort |
|---------|-------------|--------|--------|
| **MCP server** | Expose Opaque operations as MCP tools for Claude Code | **Shipped** — see `docs/mcp-integration.md` | Large |
| **Bitwarden Secrets Manager** | `bitwarden:` ref scheme, browsing operations, service account auth | **Shipped** — see `docs/bitwarden.md` | Medium |
| **GitLab CI variable sync** | `gitlab.set_ci_variable` operation | **Shipped** — daemon/CLI/MCP wiring with write-only provider flow and policy-bound secret refs. | Medium |
| **GitHub Codespaces secrets (shipped)** | `github.set_codespaces_secret` operation (user + repo scope) | **Shipped** in v1. | Small |
| **1Password provider connector (hardening)** | Fetch secrets from 1Password vaults via Connect API or service accounts | **Shipped** — `onepassword.read_field` is `REVEAL`, agent-visible channels remain blocked, and canonical secret ref derivation is enforced server-side for policy binding. | Medium |
| **HashiCorp Vault provider connector** | Fetch secrets from Vault KV, dynamic secrets (DB, AWS) | Deferred — Vault adds lease management complexity. | Large |
| **SQLite FTS5 audit search** | Full-text search over sanitized audit event text | **Shipped** — local SQLite FTS5 index with `opaque audit tail --query`. | Small |

---

## v3: iOS Mobile Approvals + FIDO2

**Prerequisites:** v2 shipped. Local-bio approval flow has been battle-tested. Multiple provider connectors are stable. Users are asking for second-factor or remote approval capabilities.

| Feature | Description | Justification for Deferral | Effort |
|---------|-------------|---------------------------|--------|
| **iOS companion app** | QR pairing, Secure Enclave key, Face ID approval | This is a standalone mobile project (Swift/SwiftUI, App Store submission, push notifications). Cannot be built incrementally alongside the broker. Requires the pairing crypto protocol, local-network HTTPS server in the daemon, and mDNS discovery. | XL |
| **iOS approval factor (`ios_faceid`)** | Second-device approval via paired iPhone | Depends on the iOS app. The challenge construction (`H(server_id \|\| request_id \|\| sha256(request_summary_json) \|\| expires_at)`) needs structured encoding (canonical JSON or length-prefixed) and key confirmation during pairing. | Large |
| **FIDO2 / WebAuthn** | Hardware security key approval factor | Requires a WebAuthn relying party identifier (domain) and either a browser/webview ceremony or a CLI-based CTAP2 flow. Adding this before the local-bio path is proven adds complexity without user demand. | Large |
| **Step-up authentication** | Policy requiring multiple factors (e.g., `local_bio + ios_faceid` for production targets) | Requires at least two working approval factors. Step-up logic is simple once the factors exist. | Medium |
| **Push notifications for mobile approvals** | APNs integration for real-time approval delivery when the phone is not on the same LAN | Requires Apple Developer provisioning, a relay component, and the iOS app. v3 minimum. | Large |
| **Device management** | `opaque devices list`, `opaque devices remove <id>`, paired device revocation | Requires mobile pairing infrastructure. | Small |

---

## v4: Analytics + Enterprise Features

**Prerequisites:** v3 shipped. Audit log has months of data. Users are requesting export, visualization, or compliance features.

| Feature | Description | Justification for Deferral | Effort |
|---------|-------------|---------------------------|--------|
| **Arrow/Parquet audit export** | Periodically export audit events to Parquet files for long-term analytics | No users have enough data to justify columnar storage. SQLite handles months of single-user audit data trivially. Revisit when multi-user or enterprise deployment creates data volume. | Medium |
| **DuckDB analytics queries** | Query Parquet-exported audit data with DuckDB | Depends on Parquet export. | Small |
| **LanceDB semantic search** | Embed sanitized audit event text and support natural language search over history | Requires: choosing an embedding model (local ONNX or cloud API), async indexing pipeline, redaction-safe text generation, and a query interface with role-gated access. Massive dependency surface area (ONNX runtime or cloud API) for a feature nobody has asked for. Revisit if users demonstrate they can't find events with structured SQL + FTS5. | Large |
| **SSE live feed** | HTTP `localhost` endpoint with Server-Sent Events for web/desktop UI | Adds an HTTP server dependency to a local daemon. `opaque audit tail --follow` over UDS is sufficient until a web UI exists. | Medium |
| **Arrow Flight feed** | Arrow-native streaming for BI/analytics tools | Enterprise feature. No justification until there are enterprise users. | Large |
| **Audit retention policies** | Configurable retention with automatic purge and Parquet rolloff | v1 has basic 90-day retention with row deletion. Parquet rolloff is only needed when data volume justifies it. | Medium |
| **Compliance reporting** | Pre-built audit reports for SOX, HIPAA, SOC2 | Enterprise feature with significant regulatory research. | XL |

---

## v5: Broader Cloud + Advanced Sandbox

**Prerequisites:** GitHub + GitLab + 1Password + Vault integrations are stable. Sandbox is proven on Linux.

| Feature | Description | Justification for Deferral | Effort |
|---------|-------------|---------------------------|--------|
| **Kubernetes secret writes** | `k8s.set_secret`, `k8s.patch_secret`, `k8s.apply_manifest` (with `kind: Secret` rejection) | Requires cluster access management (kubeconfig, service accounts), write-only RBAC setup, and per-cluster policy. Significant operational complexity. | Large |
| **AWS SDK proxy** | `aws.call` operation — broker executes AWS SDK calls, returns sanitized output | Requires modeling/allowlisting AWS APIs, sanitizing responses (especially `sts:AssumeRole`, `ecr:GetAuthorizationToken` which return credentials), and supporting multiple auth sources (Vault dynamic, AWS SSO, static keys). | XL |
| **HTTP proxy operation** | `http.request_with_auth` — authenticated HTTP requests with domain/method allowlists | Generic authenticated HTTP proxy is an enormous attack surface. Every endpoint's response format must be understood for sanitization. Defer until specific use cases are identified. | Large |
| **GCP/Azure provider support** | Cloud provider access for GCP and Azure workloads | Follow-on after AWS. Same pattern. | Large per provider |
| **macOS VM-based sandbox** | Replace `sandbox-exec` (deprecated) with a VM-based runner (Virtualization.framework) for strong per-command egress isolation | `sandbox-exec` is best-effort. A VM provides true isolation but adds significant complexity (image management, shared filesystem, startup latency). Revisit if macOS sandbox bypasses become a real problem. | XL |
| **Linux seccomp-bpf fine-tuning** | Granular syscall filtering per-command (not just the default block list) | v1 sandbox blocks the obvious dangerous syscalls. Fine-tuned profiles per-tool (npm, docker, terraform) require testing each tool's syscall surface. | Large |

---

## Not Planned

Features explicitly decided against. Reopen only with strong user demand.

| Feature | Reason |
|---------|--------|
| **Windows support** | Unix domain sockets, peer creds, polkit, LocalAuthentication — the entire architecture is Unix-first. Windows would require a parallel implementation (named pipes, Windows Hello, etc). Not enough demand to justify. |
| **Multi-user daemon** | Opaque is a single-user local tool. Multi-user adds access control complexity (which user's keychain? which policy?). Use separate daemon instances per user. |
| **GUI / menubar app** | CLI + LaunchAgent/systemd is the v1 model. A GUI adds a frontend project. Revisit if user research shows the CLI is a barrier to adoption. |
| **Cloud-hosted relay for mobile approvals** | Adds a cloud dependency and a hosted service to operate. Local-network-only pairing (v3) is simpler and has a tighter threat model. Push notifications via APNs are acceptable if needed. |
| **Generic "reveal secret" API** | Fundamentally contradicts the design. Opaque never returns plaintext secrets to clients. |
