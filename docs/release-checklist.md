# Release Go/No-Go Checklist (Alpha)

Use this checklist for release candidates and public alpha tags. Launch is a **no-go** if any required item is unchecked.

Current snapshot: [Alpha go/no-go status (2026-02-25)](alpha-go-no-go-status-2026-02-25.md)

## Owner Assignments

- Quality gates owner: `ENG` (backup: `REL`)
- Release integrity owner: `REL` (backup: `ENG`)
- Security/docs consistency owner: `SEC` (backup: `ENG`)
- PMF and launch readiness owner: `PO` (backup: `GTM`)
- Final decision record owner: `REL` (collect approvals from `PO`, `ENG`, `SEC`, `GTM`)

## 1. Quality Gates

- [ ] `cargo fmt --all -- --check` passes.
- [ ] `cargo clippy --all-targets -- -D warnings` passes.
- [ ] `cargo test --workspace` passes.
- [ ] Two consecutive clean CI runs on the release-candidate branch.

## 2. Release Integrity

- [ ] Dry-run owner assigned for this candidate (`REL` default).
- [ ] Dry-run release workflow completed successfully.
- [ ] Release artifacts match launch scope (`opaqued`, `opaque`, `opaque-mcp`, `opaque-approve-helper`, `opaque-web`).
- [ ] SHA256 files generated for every release archive.
- [ ] Install instructions in `README.md` match the produced artifacts.
- [ ] Dry-run evidence captured (workflow URL + artifact list + checksum verification notes).

Dry-run execution command:

```sh
gh workflow run release.yml -f tag=v0.0.0-dryrun -f dry_run=true
```

If this command returns `Workflow does not have 'workflow_dispatch' trigger`, merge the latest `release.yml` first.

## 3. Security and Docs Consistency

- [ ] `docs/operations.md` matches current daemon behavior for all exposed operations.
- [ ] `sandbox.exec` contract is consistent across `docs/operations.md`, `docs/getting-started.md`, `docs/llm-harness.md`, and `docs/mcp-integration.md`.
- [ ] Deferred features (iOS approvals, APNs push, FIDO2/WebAuthn) are clearly marked as out of alpha scope.
- [ ] Security-critical docs review completed and signed off by the security owner.

## 4. PMF and Launch Readiness

- [ ] At least 3 design partners are active weekly.
- [ ] Launch messaging reviewed against `docs/launch-week-playbook.md` guardrails (no unsupported claims).
- [ ] Quickstart validation gate has a recorded PASS on the current candidate (with evidence path and timestamp).
- [ ] Support and incident response owner assignment is complete.
- [ ] Incident triage rotation and post-launch SLA labels are active per `docs/launch-week-playbook.md`.
- [ ] Go/no-go approval recorded from PO, ENG, SEC, GTM, and REL owners.

## Release Record (Fill Per Candidate)

- Candidate version/tag:
- Release branch:
- Dry-run workflow URL:
- Release owner (`REL`):
- Engineering sign-off (`ENG`):
- Security/docs sign-off (`SEC`):
- PMF/GTM sign-off (`PO`/`GTM`):
- Quickstart validation evidence path:
- Launch-week triage confirmation (`REL`/`ENG`/`SEC`):

## Automatic No-Go Triggers

- Any unresolved P0 quality, security, or docs mismatch.
- Any reproducible flaky test in core provider flows.
- Any launch claim not supported by shipped behavior.
