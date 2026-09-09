# Cloudflare usage and paused demo investigation

Private operator evidence. Exclude from public routes, assets, search and sitemap.

Read-only production investigation on 2026-09-09, approximately 10:53–10:59 UTC.
Repository checkpoint: `2adcff30bdb8ce6137e9f1071682e1b82a4b6d78`.
No code, deployment, admission, billing, or cluster configuration was changed.

The current pause is an explicit application setting left by the September 5
human-approval rollout. Separately, continuous polling creates substantial
Worker traffic and redundant Durable Object writes. Cloudflare recorded more
than the free SQLite write allowance on September 5 and 6; the September 6
write stoppage and HTTP 503s strongly support storage-quota exhaustion.
The email's exact Worker-request threshold is not reconciled by available
invocation analytics and must not be conflated with the separate storage limit.

## Current deployment and pause

- Public `GET https://demo.opaque.info/demo/api/config` returned HTTP 200 with
  `available:false`; the service is executing its own application response.
- Cloudflare Worker settings confirm `DEMO_ENABLED=false`, both required secret
  bindings present, and default model `gemma4-e2b`.
- Deployment history shows version `d1d8bed8-075a-4d60-b830-0b44cbe992c4` at
  100%, deployed 2026-09-05 21:19:21 UTC, with no subsequent deployment.
- The [human-approval rollout record](2026-09-05-human-approval-live-rollout.md)
  documents that same paused version and has no completed combined rollout.
  This pause predates the email's September 7 00:00 UTC reset boundary.
- The controller and dedicated tunnel each have one ready replica and zero
  container restarts. The slot has no runtime Pod and retains generation 28,
  `lease_id:null`, model `qwen35-4b`. No retained state was rewritten.
- The running controller image is the qualified exploration digest
  `sha256:d179e9b52ac3ccbccad7d5478bf91756f388c8008d7d67bd2c97573ee9dcedb0`.
  Live default-model configuration differs from this checkout's Qwen default;
  reopening must account for the pending combined approval rollout.

The [availability check](../../deploy/cloudflare-demo/src/http.mjs) reads
application configuration; it does not inspect Cloudflare quotas. Cloudflare
documents Error 1027 for exhausted free Worker requests and a reset at midnight
UTC. That reset does not change `DEMO_ENABLED`.
[Workers limits](https://developers.cloudflare.com/workers/platform/limits/#daily-requests)

## Measured usage

Authenticated Cloudflare GraphQL results for complete UTC days:

| UTC day | `opaque-demo` Worker requests | Other Worker requests | Demo SQLite rows written |
| --- | ---: | ---: | ---: |
| September 5 | 78,451 | 70 | 105,182 |
| September 6 | 83,696 | 46 | 102,414 |
| September 7 | 41,503 | 5 | 79,232 |
| September 8 | 41,183 | 8 | 82,398 |

The other measured traffic was `fnshd-ai-proxy`, plus 34 requests to
`opaque-docs-privacy` on September 5. Inventory also contains `admachina` and
four Pages projects; the account-wide Worker datasets returned no additional
script rows for these dates. This is a statement about returned analytics,
not proof that every billing or rejected-request counter is represented.

September 6 zone analytics for the demo hostname identify the dominant traffic:

| Path / outcome | Reported requests |
| --- | ---: |
| `/internal/work`, controller user agent, HTTP 200 | 30,908 |
| `/internal/work`, controller user agent, HTTP 503 | 10,675 |
| `/demo/api/config`, dominant Chrome user agent, HTTP 200 | 20,831 |
| `/demo/api/session`, same Chrome user agent, HTTP 200 | 20,263 |
| `/demo/api/session`, same Chrome user agent, HTTP 503 | 578 |

This is a polling-shaped workload. A shared browser user agent does not identify
a person or establish the exact number of open tabs. The much smaller crawler
and scanner traffic does not explain the volume in these results.

A bounded 45-second live tail on September 9 observed 21 successful
`GET /internal/work` events and 21 corresponding internal Durable Object
`POST /` events, plus two config and two session requests. Those internal DO
events are not another 21 public Worker requests. Headers, cookies, query
strings, payloads, IPs, and exception contents were discarded by the reader.

## Storage exhaustion evidence

Cloudflare's free Durable Objects allowance includes 100,000 SQLite rows
written per day; each `setAlarm()` also counts as a write. DO requests have a
separate 100,000/day allowance. Exceeding an operation allowance causes that
operation to fail until reset.
[Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/)

On September 6, reported SQLite writes accumulated to 102,414, with the last
1,206 in the 18:00 UTC hour and zero in every hour from 19:00 through 23:59.
During those final five hours, `/internal/work` returned about 1,740 HTTP 503s
per hour. There were also seven Durable Object alarm exceptions that day.
These observations strongly support write-quota exhaustion; historical raw
exception messages were unavailable, so the precise exception text is unverified.

Worker invocation analytics reported zero execution errors. That does not mean
all HTTP requests succeeded: the scheduler catches storage exceptions and
returns `{error:'scheduler_unavailable'}` with HTTP 503, which is still a handled
Worker invocation. See [worker.mjs](../../deploy/cloudflare-demo/src/worker.mjs),
lines 49–51.

## Request and write multipliers

| Source | Configured rate / effect | Code |
| --- | --- | --- |
| Controller | `/internal/work` every 2 seconds, including idle, paused admissions, and errors; up to 43,200 requests/day before network latency | [controller.py](../../deploy/hosted-demo/controller.py), lines 158, 477–495 |
| Landing tab | Config and session every 5 seconds; up to 34,560 requests/day per continuously polling tab; paused, terminal, and hidden tabs continue polling | [index.html](../../deploy/cloudflare-demo/public/index.html), lines 197–206 |
| Scheduler | `queue.work()` for the response, then again inside `arm()`; both persist the state row | [worker.mjs](../../deploy/cloudflare-demo/src/worker.mjs), lines 40–59 |
| SQLite store | Unconditional state-row upsert on every transaction, including idle work/status | [queue.mjs](../../deploy/cloudflare-demo/src/queue.mjs), lines 67–81 |
| Alarm | Repeated scheduling while a deadline exists adds storage writes | [worker.mjs](../../deploy/cloudflare-demo/src/worker.mjs), lines 57–59 |
| Static demo files | `run_worker_first=true` invokes the Worker before serving assets | [wrangler.toml](../../deploy/cloudflare-demo/wrangler.toml), line 10 |

The deployed bundle was checked in memory and retains the duplicate work calls
and unconditional writes. At negligible latency, the controller alone produces
86,400 queue-state writes/day before alarm writes and visitor traffic. Controller
plus two continuously polling landing tabs can produce 112,320 public requests
per day. These are configuration estimates; browser throttling and latency
reduce actual rates. Repository tests are local/mocked; no recurring public-demo
test job or Cloudflare Cron Trigger was found in this checkout.

## Recommended remediation

1. Slow idle controller polling to 10–30 seconds and back off repeated errors.
   Retain prompt polling for provisioning and cleanup. Admissions being paused
   must not prevent draining existing work. Bound polling and backoff by pending
   lease/cleanup deadlines such as `next_alarm_at`; an empty action list can
   still accompany a ready lease approaching expiry. A 30-second idle interval is about
   2,880 requests/day, with a pickup-latency tradeoff unless a wakeup path is added.
2. Suspend hidden landing-page polling; slow paused/no-session refresh to about
   60 seconds; fetch stable config less often. Restore timely refresh when a
   visitor returns or requests work.
3. Reuse the work response's `next_alarm_at` instead of running `queue.work()`
   again. Only set/delete alarms when necessary, with serialized comparison and
   mutation and correct rearming after an alarm fires.
4. Avoid truly identical state writes without discarding `last_now`, the
   persisted monotonic-time watermark. A simple equality check alone will not
   eliminate ordinary idle writes because that watermark advances.
5. Verify quota savings and preserved expiry/cleanup behavior, complete the
   combined human-approval rollout, then reopen admissions with the intended
   model configuration. A quota reset or plan upgrade alone cannot reopen it.

Workers Paid is an optional operational margin: currently a $5/month base with
10 million included Worker requests and larger DO allowances. DO requests and
other products retain separate usage charges. Fix the unnecessary traffic and
writes regardless of plan. No purchase or upgrade was performed.
[Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/)

## Evidence limits and reproduction

Queries used `workersInvocationsAdaptive` grouped by date/script and hour/status,
`workersOverviewRequestsAdaptiveGroups`, `durableObjectsPeriodicGroups` grouped
by date/hour, `durableObjectsInvocationsAdaptiveGroups`, and zone
`httpRequestsAdaptiveGroups` filtered to `demo.opaque.info` and grouped by
path/status/user agent. Complete-day filters were inclusive at 00:00 UTC and
exclusive at the following 00:00 UTC. Results came from the account identified
in the supplied email and the existing authenticated Wrangler account.

Adaptive analytics can return estimated counts; datasets need not agree exactly.
[Cloudflare sampling](https://developers.cloudflare.com/analytics/graphql-api/sampling/)
The September 6 Worker request datasets report 83,742 account-wide invocations,
not 100,000. The 62,717 demo subrequests cannot be added to reconcile the email:
Cloudflare explicitly excludes outbound subrequests from Worker request billing.
The exact alert/billing counter requires account billing/notification evidence
or Cloudflare clarification. Existing OAuth access could read operational
analytics but the subscription endpoint rejected it, and the dashboard browser
was not signed in. No new permissions were requested.

Only this summarized private record was added to the repository. Temporary API
helpers contained no embedded credentials, and raw sessions were not committed.
