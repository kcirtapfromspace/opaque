# Unified bounded-work demo validation

**September 5, 2026 · private operator record**

The unified strategy and one-read demonstration are implemented and deployed.
This record covers a real read of synthetic application data and a public
Gemma session. It does not establish a production IdP/source connection, native
signed human approval, a public SSH operation, or confidential inference.

## Deployment identity

| Component | Identity |
| --- | --- |
| Public demo | `https://demo.opaque.info/` |
| Runtime image | `192.168.25.201:5050/opaque-hosted-demo@sha256:4d2b1844472bb63f7bdfd18bcafb009ee5dcdb80477e3215f9cdeb0dc3623e54` |
| Enabled Worker version | `9b887b25-b993-422d-a1c4-eff3ddd8c143` |
| Paused cutover Worker | `5445cf28-ebf0-4b9c-8046-a8d1a0e6b7cd` |
| Visitor guide / Pages | `https://ca3fe4da.opaque-3pv.pages.dev`, production branch `main` |
| Admission policy | Generation 8 observed with no type-check warnings |
| Source base revision | `f8182a2c30b74951b71a26cc7364aebc102f9f44`, with uncommitted local changes |

The main visitor guide update first deployed at
`https://6a59e867.opaque-3pv.pages.dev`. The later clarification about receipt
expiry and non-retractable results deployed successfully at the Pages URL above
after connectivity recovered. Both the deployment and production domain return
that wording. Eighteen HTTP checks passed, including private-route 404s and
clean search/sitemap responses. A strict rebuild and privacy scan covered all
74 generated files, assets, search and compressed sitemap. This wording-only
follow-up changed no Worker, runtime or cluster workload.

Source hashes, logs, rendered manifests and raw synthetic evidence are in
`/private/tmp/opaque-unified-deployment/`. This temporary directory is not a
durable evidence archive. The deployment preceded the source integration to
private `main`. GitHub confirmed the destination repository is private and
Actions remain disabled; the checks below are local, not CI.

## Enforced contract

The explicit fixture-only coordinator issues one server-owned manifest for
`manual_review_rate_percent`, a 60-second aggregate window, the current analyst,
and this workspace's configured tenant/source. Approval submits only the exact
task ID and manifest digest. SQLite reserves one use before source I/O with
FULL synchronous commits. Restart converts reserved uncertainty to `unknown`;
timeout or an ambiguous response never restores authority. A source request has
a five-second timeout; the task expires within five minutes and before its
authorizing token. Engineer/support identities cannot use the task endpoints.

Current identity, role, scope, task state and expiry are checked before execution
and disclosure. A persona change durably revokes the task, including its receipt;
returning to the analyst cannot create another allowance. Completed receipts
are withheld after the task deadline. The edge buffers bounded JSON and checks
visitor lease and receipt expiry before returning it. No layer retries execution.

The visitor's confirmation and service receipt are explicitly unsigned demo
evidence. The broker's production ledger and signed approvals remain separate.
Portfolio chat keeps its own 12-question/10-minute session limits. The one-read
task limit does not restrict the separate chat tool.

## Automated and packaged checks

| Check | Result |
| --- | --- |
| `cargo test --locked -p opaque-metrics` | 32 unit + 42 HTTP tests passed, including 9 new task regressions |
| `cargo clippy -p opaque-metrics --all-targets -- -D warnings` | Passed |
| `node --test deploy/cloudflare-demo/tests/*.test.mjs` | 87 passed |
| `python3 -B -m unittest discover -s deploy/hosted-demo -p 'test_*.py'` | 56 passed |
| Linux/ARM64 locked Cargo build and runtime image | Passed; stripped executable used in the recorded image |
| Worker dry run, `mkdocs build --strict`, and `cargo check --locked --workspace` | Passed |
| Packaged browser flow | Confirmation, completed read, actual replay denial, role evidence clearing; final build had no captured browser warning/error entries |
| Responsive/keyboard checks | 390px viewport had 390px document width and a 354px task panel; keyboard confirmation also exercised publicly |

Regressions cover extra authority fields, exact manifest/source binding,
concurrent execution, unknown source outcomes, revocation races, expiry,
foreign token identity, valid support-case denial, restart, held response bodies,
and fixture-only availability. Review found and corrected receipt disclosure
after task expiry and persona changes while a task response drained through the
runtime proxy. These are tested trust-boundary contracts, not a whole-system
security certification. The trusted runtime administrator can modify its state.

## Public flow and source effects

A normal browser admission completed through production Turnstile. The operator
did not solve a challenge, use test bot mode, manufacture admission state or
copy a visitor credential. Lease `789495a9aac04312842868bc18c8ee23` used Gemma on
the new runtime.

1. The manifest showed one permitted manual-review-rate read over 60 seconds.
   Keyboard confirmation made it approved; **Run once** returned **17.8197%**
   from **477 samples**, observed at **09:07:43 MDT**.
2. **Test replay denial** returned the service's `task_state_conflict` decision.
   The source counter was exactly **1** after the read and replay.
3. The existing portfolio chat answered which channel had the highest manual
   review rate over 15 minutes: **Mobile, 31.48%**, versus Web 16.37% and Partner
   18.00%, with the exact source values/sample counts displayed.
4. A request for borrower names and SSNs was denied with `raw_records_denied`.
   The source counter was exactly **2** after the task, permitted portfolio
   query, replay and raw-record denial.
5. Switching to the engineer removed the task receipt and customer metrics.
   Returning to the analyst showed **Revoked** and **Consumed**, with no receipt
   and no fresh approval/run allowance.
6. **End this demo** entered cleanup. The slot ended with no Pods, Services or
   Secrets, retained generation **24**, no active lease, and this lease's cleaned
   tombstone. The controller and tunnel remained available.

The numbers describe that synthetic session; they are not fixed expected values.
This release did not repeat every historical sharing, live-watch or Qwen flow
publicly. Their regression suites passed; both configured model profiles passed
positive Pod admission dry runs and rejected the old image digest.

## Publication and workload preservation

Admissions were paused before cutover; the queue had no pending controller
actions and the slot had no active resources. Retained slot generation 22 was
unchanged by rollout. Only the demo controller's image/runtime-image environment
and the matching admission image condition changed. Existing Gemma/Qwen and
other workloads were not restarted, scaled or reconfigured.

All 74 generated site files, search and sitemap were inspected for private
routes, internal paths, private repository markers and key material. The Worker
asset directory contained only its reviewed landing page. Public home/visitor
guide/search/sitemap returned 200; tested strategy, SSH evidence, dogfood,
release-dogfood and tenant-boundary routes returned 404. Private strategy,
deployment records, configuration and raw session files were not published.

Production provisioning remains gated as described in the
[strategy](../../docs/product/2026-09-05-unified-product-strategy.md) and
[roadmap](../../docs/product/roadmap.md): select a real tenant-safe source,
register the IdP client and compatible resource-token authority, complete native
human review, and validate the bounded operation on the selected real host.
