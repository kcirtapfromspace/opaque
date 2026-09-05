# Milestone restart validation

**Private execution record · September 5, 2026 · America/Denver**

The [roadmap](roadmap.md) is the current completion checklist. This record
captures work on `codex/milestone-readiness`, based on
`f8182a2c30b74951b71a26cc7364aebc102f9f44`. The changes at this checkpoint are
uncommitted roadmap, runbook, fixture-runner, preflight, publication guards and
private workflow preparation changes. Rust product source and the lockfile were
not changed.

## Fresh local checks

| Check | Result | Scope |
| --- | --- | --- |
| Host reviewer/helper build | Passed | `CARGO_INCREMENTAL=0 cargo build --locked -p opaque-approver -p opaque-approve-helper` |
| Rust workspace | **1,726 passed, 0 failed, 3 ignored**, across 20 reported suites | `CARGO_INCREMENTAL=0 cargo test --locked --workspace`; host platform, not fresh Linux kernel enforcement evidence |
| Rust formatting | Passed | `cargo fmt --all -- --check` |
| Rust Clippy | Passed, warnings denied | `CARGO_INCREMENTAL=0 cargo clippy --locked --workspace --all-targets -- -D warnings` |
| Hosted Python | **54 passed** | `python3 -m unittest discover -s deploy/hosted-demo -p 'test_*.py' -v` |
| Worker/demo JavaScript | **86 passed** | `node --test deploy/cloudflare-demo/tests/*.test.mjs deploy/cloudflare-docs-privacy/tests/*.test.mjs` |
| Milestone/preflight Python | **20 passed** | `python3 -m unittest discover -s scripts -p 'test_*release*.py' -v`; includes refusal of test/unknown/duplicate native evidence and failed-review cleanup |
| Separate broker release fixture | Passed after a locked Linux build | `python3 scripts/release_dogfood.py --check`; four test-signed tasks, custody, pinned TLS, replay, uncertainty, restart, MCP and dashboard reconciliation |
| Generated documentation | Strict build passed; **74 files checked**, zero matching private routes/content | Product notes and roadmap absent from generated routes, search, sitemap and assets |
| Publication guards | YAML parsed; **six job guards checked** | Five inherited workflows require the exact public repository and public visibility |
| Changed-source credential scan | No findings | Bounded Gitleaks scan of changed source, including newly admitted PRDs; not a repository-history guarantee |
| Whitespace | Passed | `git diff --check` |

The first host workspace build failed with imports reported absent from
`opaque-core`, although those modules were present in its source. Removing only
that package's generated artifacts with `cargo clean -p opaque-core` and rerunning
the identical workspace command passed. No Rust source workaround was introduced.
The failed log is retained alongside the successful rebuild, rather than omitted.

Check logs are in `/private/tmp/opaque-milestones-KeIovx`. The automated release
fixture's records are in `/private/tmp/orf-hh7n0_86`. These temporary paths are
local evidence, not portable dependencies. No full model/GPU demo or cluster
network-enforcement test was rerun by this checkpoint.

## M1: native human review remains open

The runner now provides `--native-check`: it prepares a fresh isolated broker,
enrolls the actual host reviewer, opens the production native review, and checks
the receipt, one provider dispatch, reconciliation, denied replay, restart
persistence, MCP and dashboard access after a human decision. The runner never
supplies the approval decision. It rejects `insecure_test` provenance as evidence
for this milestone. Native-review errors now retain an explicit failed evidence
record and stop the runner's own waiting client immediately.

The operator authorized opening the review during this session. The first live
attempt used `/private/tmp/orf-xqv5euc7` and task
`76c4ad5c-cfb1-4c3b-b945-03f735d8fafb`. Broker/workload custody and host enrollment
completed, and the native helper ran. It returned `task review timed out` after
the existing 90-second review deadline. After cleanup, the fixture recorded
**zero dispatches**. No completed human decision, biometric authentication or
successful native receipt is claimed. The original attempt also exposed a runner
wait that continued after review failure; the new failed-review regression covers
the corrected immediate failure path. The operator's observation of whether the
window appeared is still needed before completing the next attempt.

Only this run's containers were removed. Its private state volumes and logs were
retained. The existing BuildKit container and Talos registry were present before
and after the checks and remained running; no cluster workload was changed.

## M2: exact private contract prepared; live prerequisites unmet

The example now targets private `kcirtapfromspace/opaque-dogfood`, repository ID
`1357845081`, and the fixed private GHCR package of the same name. Its proposed
workflow uses a temporary registry credential with `packages: read`, checks the
approved commit, digest and Linux/amd64 artifact, then executes only
`/usr/local/bin/opaque --version` under the restricted container contract. It does
not roll out a service. The all-zero digest remains an explicit unresolved input.

The local workflow's SHA-256 at this checkpoint is
`e2f84267e288de82b2f4ec270ebf0c6f98c67de842290ba3e684a8cdf7c9b5d4`.
YAML parsing and all three shell steps' syntax checks passed. The contract guard
passed one positive and seven negative cases without fetching or executing an
image. These are template checks, not evidence that GitHub ran the workflow.

The GET-only preflight observed the following at `2026-09-05T08:03:07Z`:

| Prerequisite | Observation |
| --- | --- |
| Destination identity | Private, active, exact repository name and numeric ID |
| Branch | `main` at the baseline revision above, `protected: false` |
| Actions | Disabled |
| Same-name tag | Lookup returned 404, satisfying the provider's branch-only check |
| Branch-protection details | HTTP 404: absent or inaccessible |
| Workflow metadata and installed content | HTTP 404: absent or inaccessible |
| Staging environment | HTTP 404: absent or inaccessible |
| Private image package | HTTP 404: absent or inaccessible |
| Artifact digest | Sentinel; no real artifact selected |

The preflight returns an unmet-prerequisite result. It deliberately does not
equate API flags with effective authority, artifact runtime behavior or workflow
token pull access. No repository settings, workflow installation, publication,
dispatch or protection changes were made. Actions remain disabled, so the local
passes do not establish fresh GitHub CI. Enabling Actions requires reviewing the
existing publication workflows as well as this manual smoke workflow; do not
enable public release/site paths for internal dogfood material.

Local job guards now limit the inherited Cloudflare/GitHub Pages deployments,
release build/signing/publication, release-PR automation and public Scorecard
reporting to the exact public product repository with public visibility. The
private checkout therefore cannot activate those paths simply by enabling
Actions after these changes land. The ordinary Rust validation workflow remains
available. These are prepared source controls, not claims that settings or
workflows on GitHub have already changed.

## Documentation containment and tracking

The two historical PRDs were covered by the old blanket `tasks/` ignore rule.
The ignore now admits only those two reviewed Markdown files and continues to
exclude other task scratch material. Both PRDs carry reconciliation notices;
four dated readiness notes retain their original bodies with added status
banners. Product notes, this validation record and the roadmap remain under the
existing private-site exclusion. Validation performed no pushes or public
deployment. Packaging the verified changes into a private branch/PR follows this
checkpoint; its commit and PR provide the resulting review revision.
