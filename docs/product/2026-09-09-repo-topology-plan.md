# Repo topology plan

Private product/operator decision. Exclude from public routes, assets, search, sitemaps and previews.

The user decided this repository (`kcirtapfromspace/opaque-dogfood`) should
split into three, and that both non-dogfood repos will later move to a
GitHub org. This document records the intended split so the actual
extraction and code-migration work has a concrete map. It commits to no
timeline and executes no move itself — no repo has been created, no code
ported, no ownership transferred.

## Why three repos, not two

The demo (`opaque-showcase` + hosted-demo infra) is customer-facing sales
collateral, not core product — it already gets excluded from the workspace's
`default-members` and from the public docs build for the same reason.
Splitting it into its own private repo removes it from the core repo's
blast radius entirely, rather than just excluding it from a default build.

The core product's public repo (`kcirtapfromspace/opaque`) is real but
badly behind: it has 6 crates (`opaque`, `opaque-approve-helper`,
`opaque-core`, `opaque-mcp`, `opaque-web`, `opaqued`, the last still an
unsplit ~55-file monolith) against this repo's 15, missing the entire
bounded-work pivot (`opaque-bounded-work`, `opaque-tenant`,
`opaque-approver`, `opaque-federation-runtime`, `opaque-sandbox`,
`opaque-providers`, `opaque-approval`, `opaque-native-approval`, plus
`opaque-showcase`). It already independently has Phase 0/1, trust-domain
and federation (`docs/identity.md`, `docs/federation.md`,
`docs/enterprise-architecture.md` all exist there), so this is a partial
sync gap to close, not a from-scratch push.

`opaque-dogfood` (this repo) keeps existing rather than being emptied out:
it's the place `docs/product/`'s 40+ dated strategy/evidence memos, the
PRDs under `tasks/`, and the private dogfooding fixtures under `examples/`
already live and are written to expect to live, per this repo's own
`AGENTS.md`.

## The split

| Destination | Contents |
|---|---|
| **`opaque-dogfood` (here, unchanged)** | `docs/product/` (all dated memos), `tasks/` (PRDs), `examples/{bounded-ssh,dogfood,production-connections,staging-release,tenant-inference}` and their paired `scripts/*_dogfood.py` / `scripts/test_*.py` — every one of these already marks itself "private fixture" / "private preparation" in its own README |
| **New private demo repo** | `crates/opaque-showcase`, `deploy/hosted-demo/`, `deploy/cloudflare-demo/`, `examples/{gpu-showcase,metrics-chat}`, demo-specific scripts (`demo_leads.py`, `demo_quickstart.sh`, `demo_sandbox_exec.sh`, `demo_security_*.sh`, `metrics_chat_dogfood.py`, `portfolio_exploration_dogfood.py`, `check_site_privacy.py`, `record_demos.sh`) |
| **Public `kcirtapfromspace/opaque` (core)** | Every crate except `opaque-showcase` (14 total), public `docs/*.md` (excluding `product/`, `dogfood.md`, `release-dogfood.md`), `deploy/{docker,k8s,systemd,launchd,config.trust-domain.example.toml,cloudflare-docs-privacy}`, root `wrangler.toml` (the docs-site Pages pipeline, not the demo), release/CI scripts (`release-prep.sh`, `update-tap.sh`, `rewrite_formula.py`, `linux-harness.sh`, `linux-probe.c`, `compose-smoke.sh`), root project-meta files, `homebrew/`, `assets/`, `ios/` (dormant stub) |

## Flagged for a decision at actual migration time, not here

- `docs/tenant-boundaries.md` — private-only today (`mkdocs.yml` excludes
  it), but it documents real core architecture; reconsider making it public
  once the core repo catches up to having a tenant model at all.
- `deploy/hosted-demo/*-VALIDATION.md` evidence ledgers — proposed to move
  with the demo repo since they document that infra specifically, but could
  instead stay here alongside the rest of the validation record.
- `tasks/prd-attestor-seam.md` / `prd-bounded-agent-work.md` — proposed to
  stay here as internal planning history even though the features they
  describe move to the core repo.
- `.github/workflows/*` — needs a file-by-file split at extraction time;
  not enumerated here.

## Explicitly out of scope for now

- Creating the new demo repo.
- Porting the 9 missing crates (or their tests/CI) into the public repo —
  reconciling two independently-diverged git histories, a monolithic vs.
  split `opaqued`, and provider feature-gating differences is large enough
  to need its own planning pass, scoped separately from this decision.
- Any GitHub org/ownership change. The user performs the actual transfers;
  code-side follow-up (remote URLs, README/Cargo.toml/CI org references)
  happens once each repo actually exists in its new home.

## Related cleanup done alongside this decision (2026-09-09)

Resolved the stray branches/worktrees accumulated from prior multi-agent
sessions while establishing this plan: 13 already-merged branches deleted
(the 2026-09-06 crate-split worktree branches, `codex/quality-remediation`,
`codex/native-staging-proof`, `codex/dogfood-bounded-work`), two duplicate/
superseded branches identified for deletion (`codex/cloudflare-usage-safeguards`
— its one unique commit is byte-identical to what's already on `main`;
`brand-landing` and `worktree-agent-a561bb900dcac56a3` — both superseded by
main's later, larger `docs/overrides/home.html`), and a real unmerged
security review recovered from an abandoned worktree rather than discarded
— see [security review](2026-09-09-security-review.md),
[threat model](opaque-threat-model.md), and
[remediation plan](2026-09-09-security-remediation-plan.md). `codex/public-main-integration`
(the branch behind the last real public sync, PR #64) and
`refactor/linux-principles` (the crate-split execution record) were kept.
