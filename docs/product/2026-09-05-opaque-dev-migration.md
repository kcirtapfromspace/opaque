# Opaque GitHub ownership migration inventory

Private operator evidence. Exclude from public routes, search, sitemaps, preview
deployments, and assets. Collected through read-only GitHub API, Git, and scoped
source inspection on 2026-09-05. Repository transfer scope remains unanswered.
No transfer, remote change, namespace edit, push, or commit was performed for
this inventory. Recheck destination identity and visibility before any push.

## Verified repositories and destination

| Repository | Visibility | Repository ID | Main SHA | Access |
| --- | --- | --- | --- | --- |
| `kcirtapfromspace/opaque-dogfood` | Private | `1357845081` | `605ea2661820319c7d08ef8ef118720c8174a39a` | ADMIN |
| `kcirtapfromspace/opaque` | Public | `1156844526` | `d02eb8a1ad150b04a12668d1f114525cf05b949a` | ADMIN |

Both repositories are active, independent non-forks with no forks. Their
default branch is `main`. `opaque-dev` had no repositories, so both destination
names were available. `kcirtapfromspace` was its sole member and active owner;
creating private and public repositories was permitted. The organization uses
GitHub Free and defaults member repository access to read.

The private repository had no protected main branch, GitHub Pages, or
environments. No loss of those existing features was observed. The public
repository had protected main with required checks `test`, `clippy`, `fmt`, and
`supply-chain`, enforced for non-admins. Its environments were `github-pages`,
`preview`, and `production`.

Public GitHub Pages was configured through a workflow at
`https://kcirtapfromspace.github.io/opaque/`, with HTTPS enforced and no custom
domain. GitHub redirects transferred repository URLs but does not redirect
their Pages URLs. The expected Pages address after a public transfer is
`https://opaque-dev.github.io/opaque/`; verify its actual configuration and
content after transfer. [GitHub transfer documentation](https://docs.github.com/en/repositories/creating-and-managing-repositories/transferring-a-repository)

## Local work and namespace dependencies

All four linked worktrees share `/Users/thinkstudio/opaque/.git/config`:

- `/Users/thinkstudio/opaque`: `main`.
- `/Users/thinkstudio/.codex/worktrees/6efe/opaque`: `codex/idp-delegated-provisioning`.
- `/Users/thinkstudio/.codex/worktrees/e4b6/opaque`: detached.
- `/Users/thinkstudio/.codex/worktrees/ecfe/opaque`: `codex/demo-human-approval`;
  demo approval implementation checkpoint `1da0ab0`.

The latter three contained uncommitted work during the initial inspection. Preserve their
branches, files, and running workloads; transferring a remote repository does
not require resetting, stashing, or committing these checkouts. A shared remote
URL change affects all four worktrees. Current remotes are:

```text
origin fetch/push: git@github.com:kcirtapfromspace/opaque-dogfood.git
upstream fetch:    git@github.com:kcirtapfromspace/opaque.git
upstream push:     disabled://public-upstream
```

Keep public upstream pushing disabled. Public namespace updates require an
independent clean checkout of the public repository's own main branch. Never
push the private checkout, its history, or its internal documentation to public
upstream.

Scoped inspection found 47 files referencing the existing repository names.
Update active configuration only for repositories included in the selected
scope; retain historical evidence as historical evidence.

| Dependency | Required treatment after the applicable transfer |
| --- | --- |
| Public release, release-PR, Pages, site deployment, and scorecard workflows | Update exact `github.repository` owner guards while preserving public-visibility conditions. Old guards would skip jobs. |
| Private staging workflow and its example copy | Update repository-name guards and assertions while preserving repository ID `1357845081` and mandatory private visibility. |
| Staging manifests, runbooks, Docker source labels, artifact-builder origin allowlist | Update private source identity and proposed registry namespace consistently. Keep immutable commit/image checks. |
| `scripts/staging_release_preflight.py` | Change both the package API request and its request allowlist from `users/kcirtapfromspace/packages/...` to `orgs/opaque-dev/packages/...` if dogfood moves. A repository-string replacement alone misses this. Update corresponding tests. |
| Public package metadata, install scripts, Homebrew URLs, README, security links, MkDocs and service documentation | Update public repository links in the independent public checkout; separately update matching references in private source as needed. |
| `deploy/k8s/opaque.yaml` and staging image references | Review explicit `ghcr.io/kcirtapfromspace/...` references; repository transfer is not evidence that a new registry image exists. |

The container-package inventory returned no `opaque*` packages under
`kcirtapfromspace`. No package migration was established or performed. The
proposed private staging image was already documented as unverified. Do not
invent an image or change running workloads to an unverified namespace.

## Execution by selected scope

**Private repository only:** transfer `opaque-dogfood` to
`opaque-dev/opaque-dogfood`, preserving private visibility. Verify repository
ID `1357845081`, permissions, and main SHA. Update shared `origin` and private
staging/configuration dependencies. Leave public `upstream` and public-owner
workflow guards pointing to `kcirtapfromspace/opaque`.

**Public repository only:** transfer `opaque` to `opaque-dev/opaque`, preserving
public visibility. Verify repository ID `1156844526`, permissions, main SHA,
branch protection, environments, and Pages. Update shared `upstream` fetch URL
while retaining its disabled push URL. Apply public namespace changes in an
independent clean public checkout. Leave private `origin` and dogfood-specific
guards at `kcirtapfromspace/opaque-dogfood`.

**Both repositories:** perform and verify the private transfer first, then the
public transfer. Update each shared remote to its matching destination, keeping
the public push restriction. Apply the two dependency sets in their respective
private and public contexts. Never merge private work into the public migration.

For any selected scope, confirm the transferred repository retains its exact ID,
visibility, and source commits before editing remotes or pushing changes.
Transfers are asynchronous; an accepted transfer request alone does not confirm
completion. [GitHub transfer API](https://docs.github.com/en/rest/repos/repos#transfer-a-repository)

After namespace changes, run the affected workflow/configuration and staging
contract tests. Check generated site content for internal-file exclusion before
any public publishing. Do not recreate repositories at the old owner/name
locations: doing so removes GitHub's repository redirects.
