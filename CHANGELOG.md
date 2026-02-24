# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **Web dashboard (`opaque-web`)**: Localhost Axum server (port 7380) with embedded SPA for real-time monitoring and onboarding
  - Live mode: audit event streaming (SSE), policy viewer, agent session monitor, operations registry
  - Demo mode: graceful degradation with synthetic data when daemon is not running
  - Auto-detection and switching between live/demo modes
  - `--open` flag to launch browser on startup, `--port` flag for custom port
  - Dark terminal theme matching the opaque-explorer playground

## [0.1.0] - 2026-02-23

### Added

- **Core architecture**: Policy-driven enclave with Approve-then-Execute pipeline
- **Daemon (`opaqued`)**: Unix-domain-socket daemon with rate limiting, audit logging, and config seal verification
- **CLI (`opaque`)**: Full-featured client with `init`, `setup`, `doctor`, `exec`, `audit`, policy management, and agent wrapper commands
- **MCP server (`opaque-mcp`)**: Model Context Protocol integration for Claude Code and MCP-aware tools
- **GitHub provider**: Actions, Codespaces, Dependabot, and org-level secret management with NaCl sealed-box encryption
- **GitLab provider**: CI/CD variable sync (project-level, environment-scoped, protected, masked)
- **1Password provider**: Connect Server integration and `op://` ref resolution
- **Bitwarden provider**: Secrets Manager integration with `bitwarden:` ref scheme
- **HashiCorp Vault provider**: KV v2 client with lease-aware caching and automatic lease revocation
- **Secret resolution**: `keychain:`, `env:`, `vault:`, `bitwarden:`, and `op://` ref schemes
- **Policy engine**: Deny-by-default rules with glob patterns, client type filtering, and approval factors
- **Policy presets**: `safe-demo`, `github-secrets`, `gitlab-variables`, `sandbox-human`, `agent-wrapper-github`
- **Approval backends**: macOS LocalAuthentication (Touch ID / password), Linux polkit helper
- **Agent wrapper mode**: Session-scoped tokens with TTL enforcement, list, and bulk revoke
- **Sandbox execution**: Profile-based sandboxed command execution with output capture and sanitization
- **Env manifest workflow**: `build-manifest` / `publish-manifest` for `.env.example`-driven secret sync
- **Audit system**: SQLite-backed audit log with FTS5 full-text search and `audit tail` command
- **Security hardening**: `mlock()` for secret memory, `Zeroizing<Vec<u8>>` wrappers, stdout/stderr scrubbing, `[REDACTED]` in Debug/Display
- **Service management**: `opaque service install/start/stop/uninstall` for launchd (macOS) and systemd (Linux)
- **Diagnostics**: `opaque doctor` command with pass/warn/fail checks for config, daemon, service, and provider health
- **Documentation**: Architecture guide, policy reference, provider setup guides, MCP integration, deployment guide, security assessment

### Security

- Server-side `secret_ref_names` derivation to prevent policy bypass
- Sandbox stdout/stderr stripping to prevent secret leakage through `SensitiveOutput`
- Audit database sanitization to prevent plaintext secret persistence
- Config seal integrity verification at daemon startup
- HTTPS-only enforcement for all provider API URLs (with localhost exception)
