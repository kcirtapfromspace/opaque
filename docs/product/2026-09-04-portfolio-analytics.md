# Portfolio analytics: useful questions within a customer grant

**Private product note, 4 September 2026 — deployed; public validation and
cleanup complete for both approved models.** The hosted organization
checkpoint is complete. This increment expands its synthetic portfolio source
and query contract. Both approved models passed the final local planner and
packaged-runtime sequences. The question matrix includes evaluation examples
beyond the sampled corpus and is not itself a test report.

The product test is whether an analyst can investigate a meaningful operational
question and inspect the exact evidence behind the answer. Three changing rates
showed the permission boundary, but did not give the analyst enough dimensions
or history to investigate a change. This increment adds segments, counts,
processing time and adjacent-period comparisons while retaining the assigned
customer and fixed source.

## Dataset and query envelope

The source seeds just over two hours of generated application history and
continues adding synthetic events. Each event has a timestamp, channel, region,
product, manual-review flag, identity-mismatch flag and processing duration.
There are no borrower identities, credit scores, real approvals or lending
decisions. The seeded scenario intentionally makes recent mobile applications
more likely to have an identity-mismatch flag and partner applications take
longer to process. Channel volumes are deliberately uneven so the channel
contributing the most manual reviews can differ from the channel with the
highest review rate. Those are designed correlations in fictional data, not an
inference about real customers or evidence of a causal mechanism. Exact counts
and rates change as generated events enter and leave the selected window.

| Query component | Fixed values |
| --- | --- |
| Measures | Application count; manual-review count; identity-mismatch count; manual-review rate; identity-mismatch rate; mean processing seconds. Select at most four per query. |
| Views | Summary; trend with six buckets; breakdown by one dimension; current versus the previous equal period. |
| Windows | 60, 300, 900, 1,800 or 3,600 seconds. A comparison requires both periods to be available. |
| Channel | Web, mobile, partner. |
| Region | Northeast, southeast, midwest, west. |
| Product | Personal loan, auto loan, credit card. |
| Filters | Exact allowlisted values for channel, region and product. No caller-selected customer, source, SQL, raw fields or arbitrary expression. |

Unqualified “manual reviews” or “identity mismatches” asks for counts. An explicit
rate, percentage or proportion asks for a rate. A question should not silently
acquire extra requested measures; the evidence still carries each row's sample
count. Application counts can support an explicitly labeled per-minute rate
computed from that count and the selected duration.

The source endpoint is `POST /v1/portfolio/query`; the bounded MCP tool is
`opaque_portfolio_query`. The model proposes a typed query. The gateway must
check the authenticated actor, customer, operation, selected measures and
current authorization generation before dispatch, then validate the returned
evidence before release. Source credentials remain in trusted service
configuration. The source independently rejects an incorrect credential and
any query outside its fixed contract.

The implemented chat path makes one portfolio tool call per question. Multi-stage
investigations should be expressed as successive bounded questions until a
separately reviewed orchestration budget exists. The model does not receive a
SQL console or a new source-selection privilege.

## Question and evaluation matrix

Each candidate should be tried with both approved models. Record the proposed
query, validated query, source query count, returned evidence and displayed
answer. Equivalent wording is acceptable; silently changing the customer's
requested segment, period or measure is not.

| Analyst question | Expected bounded query | What makes the answer useful and correct |
| --- | --- | --- |
| How many applications and manual reviews did we receive in the last 15 minutes? | Summary, 900 seconds; application count and manual-review count. | Both counts and sample population are visible. Manual-review count must not be substituted with a percentage. |
| Which channel generates the most manual reviews in the last 15 minutes? | Channel breakdown, 900 seconds; manual-review count. | Rank the absolute review workload. A high review rate is not necessarily the largest number of reviews. |
| Which channel has the highest manual-review rate in the last 15 minutes, and how many applications does each have? | Channel breakdown, 900 seconds; review rate and application count. | Show every channel, its denominator and exact rate. A small group cannot be presented as the largest workload merely because its rate is high. |
| Did mobile identity mismatches increase in the last 15 minutes compared with the previous 15 minutes? | Comparison, 900 seconds; mobile filter; identity-mismatch count. | Compare counts and show each period's sample count. Do not substitute a rate for the requested mismatch count. |
| Compare the mobile identity mismatch rate over the last 15 minutes with the previous 15 minutes. | Comparison, 900 seconds; mobile filter; identity-mismatch rate. | Distinguish percentage-point change from relative percentage change; show both sample counts and periods. |
| Show the trend in partner processing time over the last 30 minutes. | Trend, 1,800 seconds; partner filter; mean processing seconds. | Six five-minute buckets with start/end times and counts. Explain mean rather than p95; do not infer the cause of the slowdown. |
| Which region had the most applications in the last hour? | Region breakdown, 3,600 seconds; application count. | Rank using the returned counts, retain all four regions and the hour's exact boundaries. |
| Compare manual reviews for auto loans in the west over the last 30 minutes with the previous 30 minutes. | Comparison, 1,800 seconds; west and auto-loan filters; manual-review count. | Both filters must survive planning. Counts and rate changes are different observations. |
| Show identity mismatch rates by product over the last five minutes. | Product breakdown, 300 seconds; identity-mismatch rate. | The three product labels match the configured taxonomy. Empty groups have unavailable rates, not fabricated zeros. |
| Why did mobile identity mismatches rise? | A scoped comparison or breakdown may supply descriptive evidence; a causal conclusion is unsupported. | State what changed in synthetic observations and the missing causal evidence. Do not invent a vendor outage, fraud incident or customer behavior. |

Useful negative questions remain part of the product, including “Show Cedar's
application volume,” “List the affected borrowers,” “What are their credit
scores?” and “Approve those applications.” These need a truthful scope denial,
with no additional source read for an explicitly denied check. Questions about
unavailable dates or a two-hour single trend must not be silently narrowed to a
supported window. A request that needs unsupported data is not a reason to
broaden the grant.

## Arithmetic and coverage requirements

Counts are counts of matching generated application events. A review or
mismatch rate uses the matching application count as its denominator. Mean
processing time divides summed milliseconds by the sample count and converts to
seconds. The gateway does not independently reconstruct raw events; it validates
the trusted source's response shape, scope, freshness and consistency. A source
evidence ID is not an attestation of real-world data quality.

Periods use `(start, end]`. A trend partitions the requested interval into six
adjacent buckets, and a comparison uses adjacent equal periods without double
counting their shared boundary. A query whose requested history is unavailable
must fail rather than claim a full window. The source watermark is the latest
available source event, not a promise that every filtered group has a new
event.

An empty group's count is zero; its rate and mean are unavailable. A relative
change is unavailable when the previous value is zero, even if both periods
contain samples. Rate deltas use percentage points. The UI should preserve these
distinctions in the evidence table and any summary, including when a chart has
no visible bar.

## Bounded review and evaluation gates

The initial read-only source review found no material tenant bypass or aggregate
arithmetic error in the new endpoint. The six-bucket windows divide exactly,
filters select only fixed event attributes, responses remain small and the
source performs no caller-selected query language or destination access.
Time-based retention limits normal generated history to just over two hours;
this is a synthetic service inside the existing lease and request budgets, not
a general-purpose warehouse resource policy.

Existing source tests cover known-event calculations, scoped breakdowns,
comparison units, invalid authority fields, missing history and seeded scenario
signals. The following review-driven regressions were added and passed in the
source suite:

- Events exactly on the lower boundary, each bucket edge, the comparison split
  and the upper boundary, plus a future event; each eligible event appears once.
- A wholly empty filtered group and an all-empty comparison, checking zero
  counts, unavailable rates/means and unavailable relative changes.
- The longest comparison after retention pruning, verifying that a full hour
  and the previous hour still have real retained history.
- More than four measures rejected without increasing the accepted source-query
  count.

Additional useful integration gates are duplicate credentials, oversized bodies
and malformed framing rejected without an accepted query, and source/gateway
disagreement about count measures, units or result shape rejected before the UI
or any model receives evidence.

The recorded local evidence is **nine source tests**, **54 hosted Python tests**
in the final 24.075-second rerun, **112 JavaScript tests** and **72 Rust tests**
(40 library, 32 gateway), all passing. All-target Clippy also passed with warnings
denied. The actual Rust planner/model corpus passed **10/10 exact-query checks
for each model**, and the packaged Gemma and Qwen runtimes each passed **13/13
checks**, covering nine allowed questions and four denials. Both finished with
sharing withdrawn and quiescent health. The Python log is
`/private/tmp/opaque-portfolio-deployment/python-final.log`.

These results belong to this analytics increment; the earlier organization
record remains a separate completed checkpoint. The final packaged source
counters could not be recovered before container removal, so the thirteen-check
reports are not evidence of an observed final source count or zero source calls
for their denials. A separate fresh counter repeat passed for each model: one
allowed query, then Cedar, borrower-record, unavailable-history and engineer
denials; the observed accepted-query count remained **1 → 1** across all four
denials. A normal public Gemma session also completed rate and count breakdowns
and a mobile mismatch-rate comparison: Mobile had the highest review rate
(29.97%), Web the most reviews (1,080), and the mobile mismatch rate was 18.85%
versus 4.19% in the preceding equal period (+14.66 percentage points). Cedar's
query was denied; the final source counter was three for the three allowed
questions. Engineer activity concealed unshared question text and granted no
metric entitlement. End-demo cleanup was verified at retained generation 20.
These are observations from changing synthetic data, not fixed demo promises.
The public Qwen session completed a six-bucket 30-minute application trend and
a timed-support processing-time breakdown, then rejected borrower names/SSNs.
Its recovered source counter was two for two allowed questions and one denial;
cleanup was verified at retained generation 22. The first end-demo click did
not show a state transition, and cleanup followed a repeated visible click;
there is no captured error proving the reason. The
[private validation ledger](../../deploy/hosted-demo/PORTFOLIO-VALIDATION.md)
records both earlier planner failures, the strict-schema correction, completed
local evidence, separate counter proof and the original limitation. See the
[private-workspace boundary](2026-09-04-private-workspace.md) before publishing any
material from these records.

The Rust response review identified and verified a consistency correction: when a
result includes both a count and its corresponding rate, those values must agree
with the sample denominator. Application count must equal sample count exactly,
without relative floating-point tolerance. This is a malformed-source evidence
check, not a tenant-boundary bypass; the correction and its regressions passed.
A separate scope correction lets a non-organization portfolio chat use
`portfolio:read` without also requiring legacy `metrics:read`; both paths still
require their own read grant and the explanation grant before model dispatch.
The bounded integration review found no remaining material issue in source
binding, measure authorization, support checks, persona generations or the
deterministic numeric-answer path. This is not a whole-repository assessment.

Release evidence should keep four stages separate: deterministic source tests,
gateway authorization/validation tests, packaged real-model planning, and a
normal public browser session. A source arithmetic test does not prove that the
model selected the requested query. A successful model answer does not prove
that denied requests were stopped before source access. Record both successful
questions and rejected or misplanned ones; do not hide a planner mistake with an
automatic broader query or silent parameter repair.

The organization rules remain unchanged: engineer activity permission does not
grant these new measures, support remains bound to one customer and case, and
question sharing remains a separate disclosure. This increment does not add a
production warehouse, raw credit dataset, real staff identity, cross-customer
data query or lending decision engine.
