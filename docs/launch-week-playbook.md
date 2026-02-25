# Launch Week Playbook (Alpha)

This runbook closes launch-week blockers for public alpha readiness. It defines messaging guardrails, the required quickstart validation gate, incident triage rotation, and post-launch issue SLA expectations.

Related launch artifacts:
- [Alpha competitive battlecard](alpha-competitive-battlecard.md)
- [Design-partner scorecard template](design-partner-scorecard-template.md)
- [Alpha go/no-go status (2026-02-25)](alpha-go-no-go-status-2026-02-25.md)

## 1. Messaging Guardrails

Only make launch claims that are true for the shipped alpha build.

Allowed claims:
- Opaque is a local approval-gated secrets broker for AI coding tools.
- Opaque returns operation results, not plaintext secret values.
- Alpha platform scope is macOS and Linux desktop sessions.
- Shipped providers include GitHub, GitLab, 1Password, Bitwarden, Vault, and AWS Secrets Manager.

Required qualifiers:
- This is an alpha release and behavior can change before beta.
- Headless, SSH, CI-only, and container-only deployments are out of scope for approvals.
- iOS approvals, APNs push, and FIDO2/WebAuthn approvals are deferred.

No-go messaging violations:
- Any claim of support for deferred features.
- Any claim of "production-ready" reliability or uptime guarantees not backed by SLO evidence.
- Any workflow claim that cannot be reproduced with the current quickstart and docs.

## 2. Quickstart Validation Gate

Run this gate for every release candidate and once again on launch day.

### 2.1 Preconditions

- Use a clean temp `HOME` and `XDG_RUNTIME_DIR`.
- Keep both paths on the same non-symlinked filesystem root (avoid `/var` symlink aliasing on macOS).
- Use built binaries from `target/release/` (or `target/debug/` for local smoke checks).

### 2.2 Validation Procedure

```bash
WORKDIR="$(pwd)/.tmp_qs.$(date +%s)"
mkdir -p "$WORKDIR/home" "$WORKDIR/run"

export HOME="$WORKDIR/home"
export XDG_RUNTIME_DIR="$WORKDIR/run"

target/release/opaque init --preset safe-demo
target/release/opaqued >"$WORKDIR/opaqued.log" 2>&1 &
DAEMON_PID=$!

target/release/opaque ping
target/release/opaque execute test.noop
target/release/opaque audit tail --limit 5

kill "$DAEMON_PID"
wait "$DAEMON_PID" 2>/dev/null || true
```

### 2.3 Pass Criteria

- `opaque init --preset safe-demo` completes successfully.
- `opaque ping` returns success.
- `opaque execute test.noop` returns success.
- `opaque audit tail --limit 5` includes `approval.required`, `approval.granted`, `operation.started`, and `operation.succeeded`.
- No unexpected daemon crash or panic in `opaqued.log`.

### 2.4 Current Validation Record

- Date: 2026-02-25
- Environment: clean temp `HOME` + `XDG_RUNTIME_DIR` under repository working directory
- Result: PASS
- Evidence path: `.tmp_qs.mBradp/` (`init.out`, `ping.out`, `execute.out`, `audit.out`, `opaqued.log`)
- Notes: `config is unsealed` warning is expected for this smoke path and is not a launch blocker.

Observed output snapshot:
- `ping`: `✔  Pong`
- `execute`: `✔  Operation succeeded`
- `audit`: includes `approval.required`, `approval.granted`, and `operation.succeeded` for `test.noop`

## 3. Incident Triage Rotation Setup

This rotation applies for launch day and the first seven days after launch.

### 3.1 Roles

- Incident commander: `REL` (backup: `PO`)
- Investigating engineer: `ENG` (backup: `REL`)
- Security lead: `SEC` (backup: `ENG`)
- Customer/status comms owner: `GTM` (backup: `PO`)

### 3.2 Coverage and Cadence

- Launch day (2026-02-25): active triage coverage from 08:00 to 20:00 PT.
- Week 1 (2026-02-26 to 2026-03-04): business-hours coverage with 10:00 PT daily triage review.
- Escalation bridge opens immediately for any `sev/P0` or `sev/P1` issue.

### 3.3 Escalation Triggers

- `sev/P0`: data exposure, approval bypass, or remote execution class risk.
- `sev/P1`: broken core workflow (init, ping, execute, or major provider operation) with no documented workaround.
- `sev/P2`: degraded behavior with workaround.
- `sev/P3`: low-impact defects, docs polish, and non-blocking UX issues.

### 3.4 First-Response Targets

- `sev/P0`: acknowledge within 15 minutes.
- `sev/P1`: acknowledge within 60 minutes.
- `sev/P2`: acknowledge within 1 business day.
- `sev/P3`: acknowledge within 2 business days.

## 4. Post-Launch Issue Classification and SLA

### 4.1 Required Labels

Apply one label from each group on triage:

- Severity: `sev/P0`, `sev/P1`, `sev/P2`, `sev/P3`
- Type: `type/bug`, `type/security`, `type/docs`, `type/feature`, `type/support`
- Area: `area/enclave`, `area/policy`, `area/providers`, `area/mcp`, `area/docs`, `area/release`
- Lifecycle: `status/needs-triage`, `status/accepted`, `status/in-progress`, `status/blocked`, `status/released`

### 4.2 SLA Targets

| Severity | Assign owner | Mitigation start | Target resolution |
|----------|--------------|------------------|-------------------|
| `sev/P0` | 15 minutes | 30 minutes | 24 hours or explicit no-go |
| `sev/P1` | 4 hours | 1 business day | 3 business days |
| `sev/P2` | 1 business day | 2 business days | 10 business days |
| `sev/P3` | 2 business days | Scheduled in backlog | Next planned milestone |

Rules:
- Any unresolved `sev/P0` is an automatic no-go for launch.
- Any unresolved `sev/P1` requires explicit sign-off from `ENG` and `REL` before launch.
- `type/security` issues require `SEC` acknowledgment before closure.

## 5. Launch-Week Review Checklist

Complete during daily launch standup:

- Review all open `status/needs-triage` issues and apply full label set.
- Confirm SLA clock status for all open `sev/P0` and `sev/P1`.
- Confirm quickstart gate still passes on current release candidate.
- Record go/no-go recommendation with owners (`PO`, `ENG`, `SEC`, `GTM`, `REL`).
