# Enterprise Architecture Plan

This document describes the technical architecture for Opaque's enterprise features: centralized policy management, SSO/OIDC integration, compliance reporting, team governance, pricing tier boundaries, and the implementation roadmap to deliver them. It is intended for engineering planning and investor communication.

Opaque today is a single-user, local-first secrets broker. Every daemon instance (`opaqued`) runs on a developer's machine, enforces policy from a local TOML file, stores audit events in a local SQLite database, and never sends data to an external service. The enterprise plan preserves this privacy-first architecture while adding the coordination layer that teams and compliance organizations require.

The core design principle is: **local daemons remain the enforcement boundary; the central service is an advisory policy distributor, never a secret handler.**

---

## 1. Centralized Policy Management

### 1.1 Problem

Today, each developer maintains their own `~/.opaque/config.toml`. There is no mechanism for a security team to express organization-wide rules ("all agents must require biometric approval for production targets") and have those rules propagate to every developer workstation. Manual TOML distribution via dotfiles repos is fragile and unauditable.

### 1.2 Policy Server

Introduce `opaque-policy-server`, a lightweight REST API that stores and distributes team policy overlays.

**Responsibilities:**

- Store versioned team policy documents (TOML-compatible schema, signed by the publishing admin).
- Serve policy documents to authenticated daemons via `GET /v1/policy/{team_id}/latest`.
- Maintain a policy changelog with diffs between versions.
- Expose a write API (`PUT /v1/policy/{team_id}`) gated by admin role, used by the governance dashboard and CI pipelines.

**Non-responsibilities:**

- The policy server never receives, stores, or proxies secrets.
- The policy server never receives audit events (see Section 3).
- The policy server never communicates with provider backends (Vault, 1Password, etc.).

**Technology choice:** A stateless HTTP service backed by PostgreSQL. Deployable as a single container or managed service. The server is intentionally simple so that self-hosted enterprise customers can run it inside their own infrastructure.

### 1.3 Policy Sync Daemon

`opaqued` gains a new subsystem: `PolicySync`. When a `[team_policy]` section is present in the local config, the daemon periodically fetches the team overlay.

```toml
[team_policy]
server_url = "https://policy.opaque.dev"
team_id = "acme-corp"
sync_interval_secs = 300       # 5 minutes
auth = "oidc"                  # see Section 2
```

**Sync protocol:**

1. Daemon sends `GET /v1/policy/{team_id}/latest` with an `If-None-Match` header containing the SHA-256 of the last-applied policy version.
2. Server responds `304 Not Modified` (common path) or `200` with the new policy document and an `ETag`.
3. Daemon verifies the Ed25519 signature on the policy document against a pinned team public key stored in local config.
4. Daemon merges team policy with local policy (see conflict resolution below).
5. On merge success, the daemon hot-reloads the policy engine without restart. Existing approval leases remain valid.
6. If the server is unreachable, the daemon continues operating with the last-known-good team policy. After a configurable staleness window (`max_staleness_secs`, default 86400), the daemon can optionally degrade to local-only policy or refuse agent requests, per team configuration.

**Auth:** The sync request is authenticated using the daemon's OIDC-derived token (see Section 2). The policy server validates the token, extracts the team membership claim, and returns only the policy for teams the developer belongs to.

### 1.4 Local Override and Conflict Resolution

The merge model is asymmetric by design:

- **Team policy sets the floor.** If the team policy requires `approval.require = "always"` for `github.set_actions_secret` on production repos, no local config can weaken this to `"first_use"` or `"never"`.
- **Local policy can only add restrictions.** A developer can add rules that deny operations the team policy allows, require additional approval factors, or reduce lease TTLs. They cannot add `allow` rules for operations the team policy does not permit.

Implementation: the merged policy is the union of team and local rules, with team rules evaluated first. When a team rule and local rule both match a request, the more restrictive outcome wins (shorter TTL, stricter approval requirement, deny over allow).

### 1.5 Policy Versioning and Signing

Every team policy document carries:

- `version`: monotonically increasing integer.
- `published_at`: ISO 8601 timestamp.
- `publisher`: identity of the admin who published (from OIDC `sub` claim).
- `signature`: Ed25519 detached signature over the canonical TOML bytes.
- `parent_version`: previous version, forming a hash chain.

The daemon rejects any policy with a version number lower than or equal to its current version (prevents rollback attacks). The team public key is distributed out-of-band during initial enrollment (see Section 7).

---

## 2. SSO/OIDC Integration

### 2.1 Challenge: Local Daemon + Corporate Identity

Opaque daemons run locally, not behind a corporate reverse proxy. Traditional SSO flows assume a browser redirect to an IdP and a callback to a server-side application. A local daemon has no publicly routable callback URL.

### 2.2 Proposed Flow

Opaque uses the **OAuth 2.0 Device Authorization Grant (RFC 8628)** combined with OIDC, which is designed for devices without browsers or with limited input capability.

**Initial SSO login:**

1. Developer runs `opaque auth login` (or the daemon triggers it on first policy sync attempt).
2. The daemon requests a device code from the OIDC provider's device authorization endpoint.
3. The CLI displays a URL and a user code (e.g., "Visit https://login.acme-corp.com/device and enter code ABCD-1234").
4. Developer authenticates in their browser using the corporate SSO flow (Okta, Azure AD, Google Workspace, etc.). SAML federations are supported transparently because the OIDC provider handles SAML-to-OIDC bridging.
5. The daemon polls the token endpoint until the device code is authorized.
6. The daemon receives an OIDC `id_token` (containing `sub`, `email`, `groups`/`teams` claims) and a `refresh_token`.
7. Both tokens are stored in the OS credential store (Keychain on macOS, Secret Service on Linux).

**Ongoing usage:**

- The daemon uses the `access_token` (refreshed automatically via `refresh_token`) when communicating with the policy server and compliance endpoints.
- Token refresh is handled transparently. If the refresh token is revoked (employee offboarding), the daemon detects the `401` and prompts re-authentication.
- The `id_token` claims (`teams`, `roles`) determine which team policies the daemon receives and which compliance buckets it reports into.

### 2.3 Identity Binding

The daemon's local identity (Unix socket peer creds, executable hash) is **not** replaced by SSO. Instead, SSO identity is layered on top:

- **Local identity** continues to gate which processes can talk to the daemon (policy enforcement).
- **SSO identity** gates which team policies the daemon receives and which compliance org the daemon reports to.

This means a developer's daemon is simultaneously identified locally (by process credentials) and organizationally (by OIDC claims).

### 2.4 Offline and Disconnected Scenarios

The daemon must function without network access to the IdP or policy server:

- **Cached tokens:** The daemon caches the last valid `access_token` and `id_token`. If the token is not expired, it is used without network calls.
- **Cached policy:** The last-synced team policy is persisted to `~/.opaque/team-policy.toml.signed` and loaded on startup even if the server is unreachable.
- **Grace period:** A configurable `offline_grace_secs` (default: 86400 / 24 hours) allows the daemon to continue enforcing the last-known team policy after token expiry. After the grace period, the daemon can either continue in local-only mode or lock agent operations, per team configuration.
- **Air-gapped environments:** For environments with no internet access, the team policy can be distributed as a signed file via internal package management (RPM, Homebrew tap, artifact registry). The daemon loads it from a local path instead of polling a server.

### 2.5 SAML Support

Opaque does not implement a SAML SP directly. Instead, it relies on the OIDC provider to bridge SAML. This is standard practice: Okta, Azure AD, and Google Workspace all support SAML-to-OIDC federation. The daemon only speaks OIDC.

---

## 3. Compliance Reporting

### 3.1 Privacy Architecture

Opaque's compliance model respects the local-first privacy guarantee:

- **Local audit events stay local.** The full audit log (`~/.opaque/audit.db`) with request details, client identities, approval factors, target metadata, and operation outcomes is never sent to a central service.
- **Aggregated metrics are sent.** The daemon computes aggregate statistics locally and pushes them to the compliance endpoint. These metrics contain counts and latencies, never individual event details.

This design allows a compliance team to answer "are all developers using biometric approval for production operations?" without learning which specific repos or secrets any individual developer is accessing.

### 3.2 Metrics Pipeline

The daemon runs a `ComplianceReporter` subsystem that:

1. Periodically (every 15 minutes, configurable) queries the local SQLite audit database.
2. Computes aggregate metrics for the reporting window:
   - Total operations by type and outcome (allowed/denied/error).
   - Approval factor usage distribution (percentage of operations using `local_bio`, `fido2`, `ios_faceid`).
   - Policy sync freshness (seconds since last successful sync).
   - Mean and p95 approval latency.
   - Daemon uptime and version.
   - Count of distinct agent client identities observed.
3. Submits the metrics payload to `POST /v1/compliance/{team_id}/metrics`, authenticated with the OIDC token.
4. The compliance server stores metrics in a time-series database (e.g., TimescaleDB or InfluxDB) for dashboard rendering and alerting.

**What is never sent:** individual audit event IDs, request IDs, secret reference names, repository names, target details, client executable paths, or any data that could identify a specific secret or operation.

### 3.3 SOC 2 Evidence Generation

SOC 2 Type II audits require evidence that controls are operating effectively over time. Opaque generates evidence artifacts locally:

- **Policy enforcement evidence:** The daemon logs every policy evaluation (match, deny, or allow) with the rule name and version. A local CLI command (`opaque compliance export --period 2025-Q4`) generates a summary report showing policy enforcement statistics, policy versions active during the period, and any policy sync failures.
- **Access control evidence:** Approval logs demonstrate that biometric authentication was required and completed for each secret-consuming operation.
- **Change management evidence:** The policy version chain (see Section 1.5) provides a tamper-evident history of policy changes with publisher identity and timestamps.

These reports can be generated locally by each developer and submitted to the compliance team, or (for Team/Enterprise tiers) aggregated from the metrics pipeline.

### 3.4 SIEM Integration

For enterprises that require centralized security event monitoring:

- **Splunk:** The compliance server exposes a Splunk HEC-compatible endpoint. Aggregated metrics are formatted as Splunk events with `sourcetype=opaque:metrics`. Alternatively, the daemon can be configured to push metrics directly to a customer-hosted Splunk HEC endpoint, bypassing the Opaque compliance server entirely.
- **Elastic:** Metrics are available via an Elasticsearch-compatible bulk API or via Filebeat-compatible JSON log files.
- **Generic webhook:** For other SIEMs, the compliance server supports a configurable webhook that forwards metrics payloads to an arbitrary HTTPS endpoint with HMAC-signed bodies.

The SIEM integration sends the same aggregated metrics described above. It does not forward raw audit events. If a customer requires raw event forwarding for their SIEM, they can configure a local export pipeline (`opaque audit export --format json --dest /var/log/opaque/`) on each developer machine, keeping the decision to centralize raw events within the customer's control.

---

## 4. Team Governance Dashboard

### 4.1 Architecture

The governance dashboard is a web application served by the policy server (or a co-deployed frontend service). It is the admin interface for team and enterprise features.

The local `opaque-web` dashboard (currently at `127.0.0.1:7380`) remains the developer-facing interface for inspecting their own audit events, sessions, and policy. The governance dashboard is complementary: it is the team-wide view.

### 4.2 Capabilities

**Policy Editor:**
- Visual editor for team policy rules (operation patterns, target constraints, approval requirements).
- Diff view between policy versions.
- Publish workflow: draft, review, publish (with Ed25519 signing via the admin's key).
- Policy simulation: test a proposed policy against historical aggregate data to estimate impact ("this rule would have denied 12% of sandbox.exec operations last week").

**Developer Enrollment:**
- Invite flow: admin generates an enrollment token (short-lived, single-use).
- Developer runs `opaque auth enroll <token>`, which configures the `[team_policy]` section, pins the team public key, and performs the initial OIDC login.
- Dashboard shows enrolled developers (by OIDC identity), their daemon versions, last policy sync time, and policy staleness.
- Offboarding: admin revokes a developer's enrollment. On next policy sync, the daemon receives a `410 Gone` response and clears team policy, reverting to local-only mode.

**Audit Analytics:**
- Aggregated views from the compliance metrics pipeline (not raw events).
- Dashboards: operations per day by type, approval factor adoption over time, policy denial trends, daemon version distribution.
- Alerting: configurable alerts for anomalies (e.g., policy sync failures exceeding threshold, spike in denials, daemon version drift).

**Integration with `opaque-web`:**
- The local `opaque-web` dashboard gains a "Team" tab (visible only when team policy is configured) showing the developer's own compliance status: policy sync freshness, whether their local overrides are in effect, and a link to the governance dashboard.

---

## 5. Pricing Tier Boundaries

### 5.1 Open Source (Free)

Everything that exists today and everything on the current roadmap through v5 remains open source under a permissive license.

Includes:
- `opaqued` daemon with full policy engine, approval factors, and audit log.
- All provider connectors (1Password, Vault, Bitwarden).
- All delivery targets (GitHub, GitLab, Kubernetes, AWS).
- `opaque` CLI, `opaque-mcp` server, `opaque-web` local dashboard.
- Local biometric approval (`local_bio`), FIDO2, and iOS mobile approvals (when shipped).
- Full local audit with FTS5 search and SSE streaming.
- Sandbox execution with egress control.

The open source tier has no artificial feature gates, no telemetry, and no "phone home" requirements. A solo developer or a team that manages policy via dotfiles repos can use Opaque indefinitely at no cost.

### 5.2 Team ($8-12/developer/month)

For teams that need coordinated policy and visibility without per-developer manual configuration.

Includes everything in Open Source, plus:
- **Centralized policy server** (hosted by Opaque or self-hosted).
- **Policy sync** in the daemon (the `[team_policy]` config section and sync subsystem).
- **Team governance dashboard** (policy editor, developer enrollment, aggregated audit analytics).
- **Compliance metrics pipeline** (aggregated metrics to the dashboard).
- Up to 100 developers per team.
- Email support with 48-hour SLA.

**Enforcement mechanism:** The policy sync client and compliance reporter in the daemon check a license key (included in the team enrollment token). Without a valid license, these subsystems log a warning and disable themselves. The rest of the daemon continues to function as the open source tier.

### 5.3 Enterprise (Custom Pricing)

For organizations with regulatory requirements, large teams, and existing security infrastructure.

Includes everything in Team, plus:
- **SSO/OIDC integration** (device authorization grant flow, IdP configuration support).
- **SAML federation** (via OIDC provider bridging).
- **SOC 2 evidence generation** (local report export and aggregated compliance reports).
- **SIEM integration** (Splunk HEC, Elastic, generic webhook).
- **Advanced policy features:** policy simulation, staged rollouts (canary policy to a subset of developers before full deployment), policy approval workflows (require two admins to publish).
- **Air-gapped deployment support** (signed policy file distribution, no outbound network requirement).
- **Unlimited developers.**
- **Dedicated support** with 4-hour SLA for critical issues.
- **Custom onboarding** and integration assistance.

---

## 6. Implementation Roadmap

### Phase 1: Policy Server and Sync (Weeks 1-6)

**Goal:** A team admin can publish a policy document and have it propagate to all enrolled developer daemons within 5 minutes.

| Week | Deliverable |
|------|------------|
| 1-2 | Policy server: REST API (`GET/PUT /v1/policy/{team_id}`), PostgreSQL schema, Ed25519 signature verification, ETag-based conditional fetch. |
| 2-3 | `PolicySync` subsystem in `opaqued`: periodic fetch, signature verification, team public key pinning, last-known-good caching. |
| 3-4 | Policy merge engine: team-floor / local-ceiling conflict resolution, hot-reload without daemon restart. |
| 4-5 | Enrollment flow: `opaque auth enroll <token>`, team public key distribution, initial sync. |
| 5-6 | Integration tests, dog-fooding on the Opaque team itself, documentation. |

**Dependencies:** None. This phase uses a simple API key for auth (replaced by OIDC in Phase 2).

### Phase 2: SSO and Team Dashboard (Weeks 7-12)

**Goal:** Developers authenticate via corporate SSO. Admins manage policy and view team status in a web dashboard.

| Week | Deliverable |
|------|------------|
| 7-8 | OIDC Device Authorization Grant in the daemon: device code flow, token storage in OS credential store, automatic refresh. |
| 8-9 | Policy server OIDC token validation, team membership extraction from claims, replace API key auth. |
| 9-10 | Governance dashboard frontend: policy editor, developer enrollment list, policy version history. |
| 10-11 | Compliance metrics pipeline: `ComplianceReporter` in daemon, metrics ingestion endpoint on server, time-series storage. |
| 11-12 | Dashboard analytics views: operations/day, approval factor adoption, policy sync health. Integration tests, security review. |

**Dependencies:** Phase 1 (policy server and sync must be stable).

### Phase 3: Compliance and SIEM (Weeks 13-18)

**Goal:** Enterprise customers can generate SOC 2 evidence and forward metrics to their SIEM.

| Week | Deliverable |
|------|------------|
| 13-14 | SOC 2 evidence export: `opaque compliance export` CLI command generating policy enforcement, access control, and change management reports. |
| 14-15 | SIEM integration: Splunk HEC endpoint on compliance server, daemon-direct Splunk HEC mode, Elastic bulk API. |
| 15-16 | Generic webhook forwarder with HMAC signing. Dashboard alerting (policy sync failures, denial spikes). |
| 16-17 | Advanced policy features: policy simulation against historical metrics, staged rollout (canary percentage). |
| 17-18 | Air-gapped deployment documentation and tooling (signed policy file packaging). End-to-end integration testing with Okta, Azure AD, and Google Workspace. |

**Dependencies:** Phase 2 (SSO and dashboard must be stable).

---

## 7. Migration Path: Zero-Downtime Upgrade

### 7.1 OSS to Team

A developer currently running Opaque open source upgrades to the Team tier with zero disruption:

1. **Admin creates team** on the governance dashboard (or self-hosted policy server). Receives a team enrollment token.
2. **Developer runs** `opaque auth enroll <token>`. This:
   - Adds a `[team_policy]` section to `~/.opaque/config.toml`.
   - Pins the team Ed25519 public key.
   - Performs an initial policy sync.
3. **Daemon hot-reloads** the merged policy. No restart required. Existing approval leases remain valid. Local rules that are more restrictive than team policy remain in effect. Local rules that are less restrictive than team policy are overridden by the team floor.
4. **No data migration.** The local SQLite audit database, provider configurations, paired devices, and profiles are untouched. The compliance metrics reporter begins collecting aggregates from the existing audit history.

### 7.2 Team to Enterprise

1. **Admin configures OIDC** in the governance dashboard (IdP discovery URL, client ID, required claims).
2. **Developers re-authenticate** with `opaque auth login`, which now uses the Device Authorization Grant against the corporate IdP instead of the simple enrollment token.
3. **SIEM integration** is configured in the governance dashboard. Metrics begin flowing to the customer's SIEM endpoint immediately.
4. **SOC 2 evidence** commands become available in the CLI. No daemon changes required; the evidence is generated from data already present in the local audit database.

### 7.3 Rollback

At any point, a developer (or admin) can remove the `[team_policy]` section from the local config. The daemon reverts to local-only policy enforcement on the next config reload. No data is lost. The developer simply stops receiving team policy updates and stops reporting compliance metrics.

---

## Appendix A: Security Considerations

**Policy server compromise:** If the policy server is compromised, an attacker could push a permissive policy. Mitigations: (1) all team policies are Ed25519 signed; the daemon rejects policies not signed by the pinned team key, (2) the daemon rejects policy version rollbacks, (3) local policy can only add restrictions, so even a maximally permissive team policy cannot disable local rules.

**OIDC token theft:** If a daemon's OIDC tokens are stolen, the attacker can fetch team policy and submit compliance metrics. They cannot access secrets (tokens are not used for provider auth) or modify policy (requires admin role). Mitigation: tokens are stored in the OS credential store with the same protections as provider credentials.

**Compliance metrics tampering:** A compromised daemon could submit false metrics. Mitigation: (1) metrics are signed with the daemon's OIDC token (attributable to a specific developer), (2) statistical anomaly detection on the compliance server flags outliers, (3) SOC 2 evidence can be cross-referenced against metrics for consistency.

**Network dependency:** The enterprise features introduce network dependencies (policy server, OIDC provider, compliance endpoint). The offline/disconnected design (Section 2.4) ensures the daemon never fails-open due to a network outage. The daemon either continues with cached policy or fails-closed, depending on team configuration.

## Appendix B: Data Flow Summary

```
Developer Machine                          Opaque Cloud / Self-Hosted
========================                   ========================

opaqued                                    Policy Server
  |-- PolicySync ----GET /policy-------->    |-- PostgreSQL (policy docs)
  |      (ETag, OIDC token)                  |
  |                                          |
  |-- ComplianceReporter --POST /metrics->  Compliance Server
  |      (aggregated counts, no events)      |-- TimescaleDB (metrics)
  |                                          |
  |-- local audit.db (full events)           Governance Dashboard
  |-- local config.toml                        |-- Policy editor
  |-- OS credential store (tokens)             |-- Enrollment mgmt
                                               |-- Aggregated analytics

                    Secrets NEVER leave the developer machine.
              Full audit events NEVER leave the developer machine.
```
