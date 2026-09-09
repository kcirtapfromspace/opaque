# Cloudflare usage safeguards rollout

Private operator evidence. Exclude from public routes, assets, search and sitemap.

Implemented and deployed on 2026-09-09 following the
[usage investigation](2026-09-09-cloudflare-worker-usage.md). The user requested
the preventative measures. This record describes the final deployment and
preserves the distinction between local tests and live qualification.

## Final deployment

| Component | Verified state |
| --- | --- |
| Worker | `30352897-c991-479d-8a39-256ee6f5e86e`, 100%, deployed 11:30:26 UTC |
| Admissions / default | `DEMO_ENABLED=true`, `DEMO_DEFAULT_MODEL=qwen35-4b` |
| Controller | Deployment generation 11, one ready replica, zero container restarts |
| Controller image | `192.168.25.201:5050/opaque-demo-controller@sha256:de8384b9f9093e944e02ec2f87fcba5c9890f22fda9012b4e94b804e6fb749b5` |
| Runtime image retained | `192.168.25.201:5050/opaque-hosted-demo@sha256:6f0af6495b7c043532d3d5a41afa525beeed406a2679181517aa249806f5e428` |
| Durable namespace | `2717f51d97914ae7822b7d692962d1ba`, existing `DemoScheduler` class and queue identity |
| Slot | Retained generation 28, no lease, no lease Pod/Service/Secret |
| Controller source SHA-256 | `9f4ebaf265791bb44af8aa66138c8ace5e2c08529622de3d0fa2f047a1eece4a` |
| Landing HTML SHA-256 | `85983735fe91e1601bab923dfb0a7d60dfe3e9f137e02b8394bb883d7f70fe1d` |
| Approval callback SHA-256 | `be92294e9f5ccd526c35757d1b26a37fa51b80e6ce93b7d690a6ddc400c5c354`, unchanged |

The controller Deployment spec was compared with its preflight snapshot after
rollout. Only the container image changed. All environment entries, including
the runtime digest and GitHub OAuth secret references, were preserved. Slot
ConfigMap data was byte-identical before and after. No slot bootstrap, model,
tunnel, admission policy, Pages, secret, or billing change was made by this fix.

## Safeguards

- Controller idle polling is 30 seconds; returned work keeps 2-second polling.
  Consecutive queue failures back off from 30 seconds to 300 seconds. Future
  known deadlines shorten waits; repeated failures after a deadline has passed
  still back off. Detection of recovery can consequently take five minutes.
- `next_poll_at` is a backward-compatible optional queue response hint that
  includes quarantined cleanup retries. The controller also understands legacy
  `next_alarm_at` and chooses the earliest valid deadline. Cleanup does not need
  a recurring storage alarm to remain responsive.
- Hidden landing tabs stop status timers and abort in-flight checks. Visible
  idle/terminal sessions refresh every 60 seconds; active/queued/cleanup states
  refresh every 5 seconds. Config is cached for 60 seconds during normal polls.
  Returning, retrying, and completing actions force fresh checks. Errors back
  off to five minutes; stale aborted responses cannot replace confirmed state.
- A controller work request performs one queue sweep/state transaction. The
  scheduler reuses its resulting alarm deadline instead of sweeping again.
  Fetch/alarm operations serialize queue mutations and alarm comparisons;
  unchanged alarms are not rewritten. Exact duplicate state writes are skipped,
  preserving every change to the monotonic `last_now` watermark.
- Lease expiry, authorization, generations, uncertain execution fences, and
  cleanup evidence requirements retain their previous semantics. Queue schema
  and Durable Object identity are unchanged.

At negligible latency, an idle controller falls from 43,200 to 2,880 Worker
requests/day, a 93.3% reduction. Queue-state writes fall from at least 86,400 to
2,880/day, a 96.7% reduction, excluding admission/alarm/visitor operations. Each
continuously visible idle landing tab falls from 34,560 to 2,880 requests/day;
hidden tabs make no scheduled requests. Already-open pages must refresh to load
the updated polling code. These are configuration estimates, not whole-account
quota guarantees.

## Artifact and test evidence

The repository changes passed 111 JavaScript tests including nine scheduler
tests using real SQLite, plus all 82 hosted-demo Python tests. The scheduler's
simulated idle day committed exactly 2,880 state writes and zero alarm writes.
Regression coverage includes expiry, clock rollback, failed storage recovery,
concurrent cancellation/alarm updates, quarantine retries, browser visibility
races, error backoff, sticky errors, and immutable model selection.

The controller artifact was derived from the exact deployed `6f0af649…` image.
The baseline controller source matched the repository before the polling edits
(`62c16cdd3b7370216233c39684c5c226f8dee5cea3cad006189692d9ea835707`).
Independent byte and AST comparisons proved the candidate adds only polling
fields, validation, remembered deadlines, polling methods and environment
configuration. All OAuth and other runtime behavior remained intact.

A deterministic tar layer contained only
`opt/opaque/deploy/hosted-demo/controller.py`, ownership `0:0`, mode `0644`.
`crane append --output` combined it with the digest-pinned base. Archive
inspection verified Linux/ARM64, every original base layer, unchanged image
configuration, and exactly that one added file. Twelve isolated polling tests
passed inside the built image as its non-root user, with no network, a read-only
filesystem, dropped capabilities and no new privileges. The private-registry
readback digest matched the local archive digest before deployment.

Worker dry-run build and inspection covered the actual generated bundle and
exact public asset allowlist: landing HTML and approval callback only. No
private record or fixture appeared in the upload. Live HTTP bodies matched the
final HTML and callback hashes above exactly.

## Deployment coordination and verification

A concurrent quality deployment from worktree `a65c` published the new design
as `e0a23462…` at 11:16:55 UTC. An initial expected-version assertion failed,
but the containing shell did not stop, so safeguards version `34ae0fce…` at
11:17:52 temporarily restored the older live layout. The concurrent task
restored its release as `853ecf00…` at 11:22:39, upgraded the runtime/controller
to `6f0af649…`, and opened admissions with Qwen.

Both tasks then explicitly coordinated release ownership. No old-controller
patch was applied. The final safeguard release preserves the new design and
the upgraded runtime/OAuth environment. Subsequent publication checks and
deployment commands ran under a single checked Python control flow, so a failed
version assertion prevented the deployment command from running. The earlier
`d179…`-based candidate image was obsolete and never deployed.

Worker `66f3c404…` first combined the safeguards with the new design. Admissions
were then temporarily paused by `6da6d130…` at 11:28:21. Fresh authenticated
queue inspection showed zero actions and no alarm; slot generation 28 had no
lease or uncertainty fence and no runtime resources. Server dry-run accepted a
JSON Patch testing resource version, generation 10, and the entire existing
Deployment spec before replacing only its controller image. After rollout,
readiness, actual pod image ID, source hash, all retained environment entries,
and unchanged slot data were verified. The final Worker restored admissions
and Qwen at 11:30:26.

A 75-second live tail observed three successful controller work requests,
30.00 and 30.08 seconds apart, plus their three Durable Object calls. All 14
observed invocations completed normally; expected public probes returned 401,
403 or 404 as appropriate. The reader retained only path/method/status counts
and polling intervals, discarding headers, cookies, payloads and query strings.

Final public checks confirmed `available:true` and Qwen default, workspace
access without a session returned 401, foreign-origin and invalid-bot joins
returned 403, and both private investigation/report routes returned 404.
No demo lease was created during this safeguards validation. Real human
OAuth/passkey and full live lease qualification remain separate from these
checks, as acknowledged by the quality deployment task.

Source changes are provided as a clean `codex/` commit for that task to integrate
with its newer private main history. No push to a public repository is involved.
