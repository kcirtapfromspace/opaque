# Alpha Go/No-Go Status (2026-02-25)

This is the current readiness snapshot for the public alpha launch gate.

## Candidate Metadata

- Date: 2026-02-25
- Candidate tag: not tagged yet
- Branch: `main`
- Release owner (`REL`): pending assignment

## Validation Evidence

Local evidence directory:
- `.tmp_release_validation_2026-02-25/`

Contained outputs:
- `fmt.out`
- `clippy.out`
- `test.out`
- `test-second-pass.out`
- `build-release-bins.out`
- `release-binaries-present.txt`
- `summary.txt`
- `release-dry-run-dispatch-attempt.out`
- `run-22386006368-failed.log`
- `run-22386149718-summary.json`
- `release-dry-run-report.txt`

Quickstart smoke evidence:
- `.tmp_qs.mBradp/` (`init.out`, `ping.out`, `execute.out`, `audit.out`, `opaqued.log`)

Recent CI evidence:
- `https://github.com/kcirtapfromspace/opaque/actions/runs/22383428049` (success, 2026-02-25)
- `https://github.com/kcirtapfromspace/opaque/actions/runs/22382821476` (success, 2026-02-25)

Release dry-run evidence:
- First dry-run attempt (failed): `https://github.com/kcirtapfromspace/opaque/actions/runs/22386006368`
  - Failure reason: macOS signing secrets missing (`APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD`, `APPLE_TEAM_ID`)
- Second dry-run attempt (success): `https://github.com/kcirtapfromspace/opaque/actions/runs/22386149718`
  - Branch/ref: `codex/release-dry-run-blocker-20260225`
  - PR for merge to `main`: `https://github.com/kcirtapfromspace/opaque/pull/11`
  - Artifacts downloaded: `.tmp_release_validation_2026-02-25/run-22386149718/`
  - Checksum verification: `.tmp_release_validation_2026-02-25/run-22386149718/checksum-verify.txt` (all PASS)
  - Consolidated report: `.tmp_release_validation_2026-02-25/release-dry-run-report.txt`

## Checklist Status

- [x] Clippy gate clean with `-D warnings` (local run on 2026-02-25).
- [x] Workspace tests stable across repeated runs (two local full-workspace passes on 2026-02-25).
- [x] Two consecutive CI runs completed successfully on `main` (2026-02-25).
- [x] Release artifacts fully match documented launch scope (workflow + docs + local release bins verified).
- [x] Security-critical docs match implementation behavior (sandbox contract and launch scope alignment in docs set).
- [x] Dry-run release completed successfully (`run 22386149718`, workflow_dispatch, dry_run=true).
- [ ] Apple signing/notarization secrets configured for real tag releases (currently missing in CI environment).
- [ ] At least 3 design partners active with weekly usage (pending external PMF execution evidence).
- [x] Support and incident response playbook assigned (roles, escalation, and SLAs in `docs/launch-week-playbook.md`).
- [ ] Launch owner approvals from PO, ENG, SEC, GTM, REL (pending formal sign-offs).

## Open Blockers

1. Configure Apple signing/notarization secrets for tag releases, or approve a documented unsigned-macOS waiver.
2. Confirm design-partner usage threshold (>= 3 weekly active partners).
3. Collect and record approvals from PO, ENG, SEC, GTM, and REL.

Execution artifacts for remaining blockers:
- PMF usage capture: [Alpha design-partner usage log (2026-02-25)](alpha-design-partner-usage-log-2026-02-25.md)
- Approval capture: [Alpha sign-off ledger (2026-02-25)](alpha-signoff-ledger-2026-02-25.md)

## Decision

Current recommendation: **No-Go** until all open blockers above are closed.
