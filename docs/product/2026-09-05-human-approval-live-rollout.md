# Human approval live rollout

Private operator evidence. Exclude from public routes, assets, search and sitemap.

## Identity boundary

The user authorized direct GitHub login for the public demo and explicitly
required that it provide no organization access. The `opaque-dev` OAuth app
`Opaque Demo Approval` uses the exact callback
`https://demo.opaque.info/approval/callback`, with wildcard matching and device
flow disabled. Its description explicitly excludes organization, repository,
and private-email permissions.

The runtime sends `scope=""` and rejects nonempty returned scopes. Its only
GitHub calls exchange the authorization code and retrieve `/user`; it retains
only a positive numeric user ID and the GitHub issuer as approval evidence.
It makes no organization, repository, membership or installation requests and
creates no production tenant membership. Approval remains bound to one reviewed
synthetic demo task; execution is a separate action.

## Credential storage

The approved client credential is stored in
`opaque-demo-system/opaque-demo-github-oauth`, keys `client-id` and
`client-secret`. The copied credential was checked against the registered app
without printing it. An unused credential created during setup was removed;
the app retained exactly one credential. Temporary credential files and the
local intake service were removed or stopped. No credential entered Git, chat,
command arguments, shell history, or operator evidence.

## Rollout preparation

Runtime image:
`192.168.25.201:5050/opaque-hosted-demo@sha256:7e33c82086eff061b4360be76b63576be5eddf70651924d1214ff491e3da724f`.
Core implementation checkpoint: `1da0ab0`; guarded rollout preparation: `44d751e`.

New admissions were paused with Worker version
`0215b1c8-2052-48a8-b061-ceec10bacd3d`. Public config reported
`available:false`. A Qwen visitor had already started on slot generation 27;
the existing runtime remained running while that session finished. The queue
poll returned zero pending provision/cleanup actions. Both narrow Kubernetes
patches passed server dry-run; no bootstrap slot state was applied.

Live callback inspection found Cloudflare injected an analytics script. The
existing CSP blocked it. The callback route alone now additionally emits
`Cache-Control: no-store, no-transform`, preserving its hashed script CSP and
`no-referrer`. The change passed all 33 HTTP tests. Cloudflare documents
`no-transform` as the opt-out for Web Analytics injection:
[Web Analytics setup](https://developers.cloudflare.com/web-analytics/get-started/).

The header fix was deployed while paused as Worker
`d1d8bed8-075a-4d60-b830-0b44cbe992c4`. The live callback then matched the
reviewed 1,256-byte asset exactly, with one script and no analytics injection.

## Concurrent release coordination

The active visitor was the portfolio exploration task's qualification session.
That task had independently deployed a newer runtime while approval setup was
in progress, then ended its session and handed release ownership to this task.
At 21:21:59 UTC the slot was empty at retained generation 28, with no lease
resources. Controller generation 9 selected the portfolio runtime
`sha256:d179e9b52ac3ccbccad7d5478bf91756f388c8008d7d67bd2c97573ee9dcedb0`.
No old approval runtime or policy patch was applied. The combined release must
include private PR #21, preserve the Qwen default and `--cache-ram 0`, rebuild
the runtime, and regenerate guarded rollout inputs from fresh live state.

Final combined rollout and live lifecycle results will be recorded below.
