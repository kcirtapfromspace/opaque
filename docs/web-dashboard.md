# Web Dashboard (`opaque-web`)

A localhost web UI for monitoring and demonstrating the Opaque enclave.

## Quick Start

```bash
# Start the dashboard (opens browser automatically)
opaque-web --open

# Custom port
opaque-web --port 8080
```

The dashboard is available at `http://127.0.0.1:7380` (default). It binds to `127.0.0.1` only — never exposed to the network.

## Modes

### Live Mode

When `opaqued` is running, the dashboard connects via:
- **Unix socket IPC** for session listing and daemon health checks
- **SQLite read-only** for audit event queries and SSE streaming

The header shows a green **LIVE** indicator with the daemon version.

### Demo Mode

When `opaqued` is not running, the dashboard automatically switches to demo mode with synthetic data. This is useful for onboarding and showcasing the security model without a running daemon.

The header shows an amber **DEMO** indicator.

Mode switching is automatic — the dashboard polls `/api/status` every 10 seconds and transitions seamlessly when the daemon starts or stops.

## Tabs

### Audit (default)

Real-time scrolling event list via Server-Sent Events. Supports filters:
- **Kind**: request.received, policy.denied, approval.granted, operation.succeeded, etc.
- **Operation**: filter by operation name
- **Outcome**: ok, denied, error
- **Full-text search**: FTS5 query across all event fields

Click any event to expand and see the full JSON detail with syntax highlighting.

### Policy

Read-only display of policy rules from `~/.opaque/config.toml`. Shows:
- Config file path and seal status
- Agent session enforcement settings
- Each rule as a card with operation pattern, allow/deny status, client types, and approval configuration

### Sessions

Active agent sessions table showing session ID, label, TTL remaining (live countdown), and expiration time. Data is fetched via the `agent_session_list` IPC method.

### Operations

All registered operations grouped by provider (GitHub, GitLab, 1Password, Bitwarden, Sandbox). Each operation shows its safety classification, MCP exposure status, and default approval requirement.

## API Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Serve embedded SPA |
| `/api/status` | GET | Daemon health + mode detection |
| `/api/audit` | GET | Query audit events (with filters) |
| `/api/audit/stream` | GET | SSE stream of new audit events |
| `/api/policy` | GET | Parsed config.toml policy rules |
| `/api/sessions` | GET | Agent session list via IPC |
| `/api/operations` | GET | Hardcoded operation registry |

## Architecture

```
Browser ──HTTP──▸ opaque-web (127.0.0.1:7380)
                    ├── Unix socket IPC ──▸ opaqued (sessions, health)
                    └── SQLite read-only ──▸ ~/.opaque/audit.db (audit queries + SSE)
```

The SPA is embedded in the binary via `include_str!()` — no external files or build tooling required.
