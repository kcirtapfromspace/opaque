# Pilot contact capture deployment

Private deployment and validation record. Exclude from public HTML, assets,
search, sitemaps and previews. No real lead data, credentials or raw session
artifacts belong in this repository.

The user approved the proposed optional demo contact flow. This release adds
that flow, private custody and operator access, the invitation after a useful
workspace result, visitor guidance, and the
[initial recruitment plan](2026-09-09-demo-pilot-recruitment.md). No outreach
messages or automatic emails were sent.

## Published state

| Component | Verified identity |
| --- | --- |
| Feature source | Private `kcirtapfromspace/opaque-dogfood`, `main`, commit `ad59106` |
| Enabled Worker | `54556df6-ced0-48d2-9e1a-c0228c583c27`, 100%, admissions and contact available, Qwen default |
| Temporary paused Worker | `894d5df9-276a-43d9-879b-9dffb551c8f8` |
| Added custody | `LeadInbox` SQLite Durable Object, additive migration `v2`; existing scheduler class and identity retained |
| Controller and runtime image | `192.168.25.201:5050/opaque-hosted-demo@sha256:bfca6b377fa5759c127411ab18499ee691261c74db0d4e9c89b9e0c7bd7e3504` |
| Runtime executable | Linux/ARM64 `opaque-showcase`, 12,090,400 bytes, SHA-256 `1bf405b3e93b28fe94913e21ece8e9fd1914a29bc25add6ed05d57a43a35eebc` |
| Controller | Generation 12, one ready replica, zero restarts |
| Runtime admission policy | Generation 11, observed generation matched, no type-check warnings |
| Pages | Production `d9ef0b7c-aa53-4315-86a3-ed2792f52b81`, source `ad59106` |
| Public destinations | `https://demo.opaque.info/`, `https://opaque.info/`; direct Pages artifact `https://d9ef0b7c.opaque-3pv.pages.dev` |

The repository destination was verified private before pushing. Public remotes
were not used. GitHub Actions remain disabled; validation and publication were
performed locally. No GitHub repository settings, billing plan, model, tunnel
or documentation privacy-routing configuration was changed by this feature.

## Data and behavior

Email remains optional for demo access. The contact form requires a workflow
description and explicit follow-up consent. Separate action-bound Turnstile
verification protects contact submission; it does not reuse admission proof or
GitHub approval identity. Successful `202` responses follow durable storage.

Only the consented email/workflow, server consent version and timestamps,
allowlisted referral metadata and browser-reported entry point are retained as
a lead. Exact normalized submissions deduplicate without extending retention;
a different workflow from the same email creates a separate record rather than
overwriting or discarding earlier intent. Addresses are explicitly unverified.
HMAC IP buckets and a fixed inbox bound limit abuse. Live records expire after
90 days through storage alarms. The private recruitment plan distinguishes live
inbox expiry from Cloudflare recovery history and operator-downloaded exports.

The admin secret is separate from the controller credential and was installed
through Wrangler's additive secrets-file option. Its owner-only local copy is
outside the repository. Private export/deletion uses `scripts/demo_leads.py`;
the CLI refuses redirects, writes new exports with mode `0600`, bounds responses
and avoids printing token/contact contents. No additional mail service or CRM
account was created.

## Validation and rollout

- All **217 JavaScript regressions** passed across queue, scheduler, HTTP,
  contact custody, admission UI, showcase UI, dashboard and privacy routing.
  All **7 operator CLI tests** passed.
- Real local workerd and SQLite storage passed **29 integration assertions**:
  durable receipt, restart persistence, exact deduplication, distinct workflow
  preservation, private pagination/deletion, CLI protected exports, rejected
  unauthorized access and unchanged scheduler storage bytes.
- Local browser checks verified empty-field and unchecked-consent errors,
  multiline submission and confirmed success, plus desktop and 390-pixel mobile
  layout. Local bot verification was an explicitly labeled disposable fixture;
  it was not claimed as a production Turnstile test. Its server, contact data,
  credential files and exports were removed afterward.
- The Linux/ARM64 release suite passed **89 unit tests and 53 gateway tests**;
  one existing long browser fixture remained intentionally ignored. The actual
  packaged executable started as UID 7383 with no network, a read-only root,
  temporary memory-backed state, dropped capabilities and no new privileges.
  Its running binary hash and authenticated health/session responses matched.
- The new image adds only the rebuilt showcase executable to the exact deployed
  controller image `de8384b9…`, preserving the previous polling safeguards.
  Archive inspection verified the platform, base-layer count, single appended
  file and executable bytes. Local archive and private-registry digests matched.
- Admissions were paused, slot generation 30 had no lease/resources, and the
  controller's actual HTTP client confirmed zero pending actions. Guarded
  controller and policy patches passed server dry-run before application.
  Post-rollout comparison confirmed only image/runtime-image values changed;
  existing OAuth references, other environment values and slot data remained
  intact. The final Worker reopened admissions with the configured Qwen default.

The actual Worker build and exact public asset allowlist were inspected before
upload. Only landing HTML and the unchanged approval callback are public assets.
The callback retained its exact bytes, no-store/no-transform policy and
noindex/noarchive headers. Marked-source site generation excluded **48 private
fixtures** before release; the exact Pages upload directory separately passed
HTML, asset, search and sitemap inspection. Adding this private record was
followed by another marked-source privacy build.

## Live qualification

The production browser's separate contact Turnstile check completed naturally,
without agent interaction with the challenge. A synthetic multiline contact
submission visibly confirmed a save. Private export verified consent, source
tags, entry point, unverified-address state and the exact 90-day expiry interval.
The test record was then deleted through the supported CLI, a fresh list
confirmed removal, and all exported files were removed. This checks actual
production save/export/delete, not a 90-day elapsed-time expiration.

A normal demo request succeeded with the email fields empty. The rebuilt
runtime returned a Qwen answer to “Which channel is giving our review team the
most work?” with a complete 15-minute, three-channel synthetic source breakdown
and seven evidence events. The pilot invitation appeared after completion and
its link returned to `/#pilot-result` with the contact form visible. The normal
**End this demo** action reached **Request cancelled**. Kubernetes confirmed
slot generation **32**, no active lease, and no lease Pods, Services or Secrets.
No real GitHub/passkey approval or task execution was attempted in this check.

Independent public checks passed all **13 expected responses**: landing,
configuration and callback were available; private/unknown paths returned 404;
anonymous and wrong-secret contact administration returned 401; foreign-origin
submission and production use of the local fixture proof returned 403; missing
consent returned 400. No sampled fixture/contact data appeared publicly.

All **20 Pages requests** passed across the production and direct domains.
Both visitor guides contained the new contact guidance. Direct Pages HTML was
byte-identical to the inspected artifact; production-domain copy was verified
without claiming byte identity. Private routes remained 404, search/sitemap
locations stayed on the public allowlist, and compressed sitemap contents
matched the inspected XML.

Only sanitized summaries are retained here. Protected temporary build and
verification evidence was stored under
`/private/tmp/opaque-pilot-release-_1ykwjbr/`; local workerd assertions and cleanup
summaries remain under `/private/tmp/opaque-lead-workerd-qb1h3666/`. These paths
are temporary operator evidence, not a durable contact archive.
