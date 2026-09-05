# Private worktree consolidation — September 5, 2026

This record reconciles the private milestone preparation commit `daa3624` with
the unified bounded-work/Vault SSH commit `f8a2858`. The
[roadmap](roadmap.md) remains the execution checklist. The earlier
[milestone validation](2026-09-05-milestone-validation.md) and
[unified-work handoff](2026-09-05-idp-oauth-handoff.md) retain their own historical
test results and limitations.

## Consolidation and preservation

- `/Users/thinkstudio/opaque` is the sole registered Git worktree. Both private
  lines of work are integrated here; no product source from the newer main was
  discarded. The final native failure handling, strict staging preflight,
  regression tests, historical PRDs and public-publication guards are retained.
- The private dependency worktree at `/private/tmp/opaque-main-integration/private`
  was clean and already included in main. Its registration and directory were
  removed normally.
- The public integration worktree at `/private/tmp/opaque-main-integration/public`
  was clean and exactly matched fetched public `upstream/main` (`d02eb8a`) in
  content. Its directory and registration were removed. The original `8511a3a`
  commit remains reachable through `codex/public-main-integration`; its history
  differs because the upstream change was squash-merged. No public push occurred.
- The former Codex worktree at
  `/Users/thinkstudio/.codex/worktrees/f11f/opaque` had clean source and attached
  tool processes. Its directory inode, source snapshot and ignored runtime files
  are preserved at
  `/Users/thinkstudio/.codex/worktree-archives/2026-09-05/f11f-opaque` without Git
  worktree registration. The original path is a compatibility symlink to the
  primary checkout. Only its regenerable Rust `target/` cache was removed,
  reclaiming about 17 GB. The primary checkout's ignored state was preserved.
- The two running Docker containers were inventoried. Neither mounts the removed
  cache or secondary source trees; neither was changed or stopped. No cluster
  configuration or workload mutation was performed.

The archive and raw local validation logs are deliberately outside Git. No
private key, credential, generated binary or raw session artifact is included
in this consolidation record.

## Fresh consolidation checks

| Check | Result and scope |
| --- | --- |
| Rust workspace | 1,769 passed, zero failed, four ignored live-provider checks across 21 reported suites; `CARGO_INCREMENTAL=0 cargo test --locked --workspace` on macOS |
| Rust formatting | Passed, `cargo fmt --all -- --check` |
| Rust Clippy | Passed, locked workspace/all-target checks with warnings denied and incremental compilation disabled |
| Hosted Python | 56 passed |
| Python contracts | 56 run: 54 passed, two Linux-only checks skipped on macOS |
| JavaScript | 134 passed across Worker/privacy, metrics UI and broker dashboard suites |
| Publication guards | Six public-only job guards across five workflows match `daa3624`; no new publication path |
| Generated documentation | Strict MkDocs build passed; 74 files scanned against 69 markers from 30 private documents, with no private route/content/search/sitemap/asset matches |
| Documentation links | 104 local links across 25 changed Markdown documents resolved |
| Artifact/credential audit | No new credential findings in the added-line scan; no generated binaries or runtime-sensitive paths in the changed tracked files. Full-file fixture/dependency-name matches were already present in `f8182a2` |
| Private destination | GET confirmed active private `kcirtapfromspace/opaque-dogfood`, repository ID `1357845081` |
| Staging prerequisites | 5 passed, 9 blocked, 2 operator-required; no dispatch |

The read-only staging snapshot again found disabled Actions and unprotected
`main`. Installed workflow bytes, environment controls and private package access
remain unavailable or blocked; the artifact digest is still a sentinel. The
prepared workflow is not evidence that it is installed or that its artifact can
run. Effective authority review and exact artifact smoke evidence remain open.
Local tests do not establish fresh GitHub CI.

## Milestone consequences

The deployed synthetic one-read demo remains complete within its recorded scope.
Vault-signed SSH and broker resource authority are implemented and fixture
validated. This consolidation did not repeat or widen the recorded 47 real
Vault/OpenSSH checks or 26 Linux host/control tests. Native human approval still
has only the recorded 90-second timeout with zero dispatches; real staging,
source/IdP provisioning and a selected real-host SSH operation remain open.
