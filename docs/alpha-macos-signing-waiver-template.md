# Alpha macOS Signing Waiver Template (2026-02-25)

Use this only if signed/notarized macOS artifacts are intentionally out of scope for this alpha release.

## Waiver Request

- Request date (UTC):
- Requested by:
- Release version/tag:
- Scope:
  - [ ] `x86_64-apple-darwin`
  - [ ] `aarch64-apple-darwin`

## Reason for Waiver

- Why Apple signing/notarization is unavailable for this release:
- Why launch still proceeds safely:

## Risk Assessment

- Primary risk:
- Affected users:
- Severity:
- Likelihood:

## Compensating Controls

- [ ] Publish SHA256 checksums for all macOS artifacts.
- [ ] Provide verification instructions in release notes.
- [ ] Mark macOS binaries as unsigned in release notes and docs.
- [ ] Time-box waiver with explicit expiration date.

Additional controls:

## Expiration and Exit Plan

- Waiver expiration date (UTC):
- Secret provisioning owner:
- Target date for full signing/notarization:
- Verification run URL once resolved:

## Approvals

| Role | Owner | Decision (`approve` / `reject`) | Date (UTC) | Notes |
|------|-------|----------------------------------|------------|-------|
| `SEC` |  |  |  |  |
| `REL` |  |  |  |  |

## Linked Evidence

- [Alpha go/no-go status (2026-02-25)](alpha-go-no-go-status-2026-02-25.md)
- [Release go/no-go checklist](release-checklist.md)
