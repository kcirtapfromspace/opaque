# Customer metrics chat fixture

This demo connects an authenticated customer chat to a bearer-protected HTTP MCP server and a separate rolling aggregate source. It runs as native processes on one host and UID. It does not establish a microVM, production OAuth deployment, private warehouse boundary, or real customer data.

## Run

From the Opaque repository, after the current gateway tests pass:

```sh
cargo build --locked -p opaque-metrics
python3 -B scripts/metrics_chat_dogfood.py --check --no-build
python3 -B scripts/metrics_chat_dogfood.py --serve --no-build
```

`--check` uses the explicitly labeled deterministic test parser. `--serve` first runs those checks, then starts fresh gateway sessions using the configured Gemma endpoint at `http://127.0.0.1:19680/`, model `gemma-4-E2B-it-Q3_K_M.gguf`. The endpoint must already be available through the separately authorized loopback forward. The runner does not create a Kubernetes forward, change a deployment, allocate a GPU, download a model, or silently fall back if the live model fails. Use `--fixture-model` with `--serve` to request the deterministic parser explicitly.

Every invocation uses fresh disposable state. `--data-dir` may select an empty directory; otherwise the runner prints a short `/private/tmp/omf-*` path. `--no-build` uses the existing native binary, so omit it or build explicitly after source changes. Ctrl-C stops only the runner's own child processes and retains evidence. No `HOME` override, Docker mutation, or change to the existing Opaque dogfood dashboards occurs.

| Customer | Chat | Allowed metrics |
| --- | --- | --- |
| synthetic-a / Customer A | http://127.0.0.1:19400 | Request rate, error rate, p95 latency, active sessions |
| synthetic-b / Customer B | http://127.0.0.1:19401 | Request rate and error rate |

The disposable issuer listens on 19402 and the two source processes on 19403/19404. Custom ports are available through `--port`, `--issuer-port`, and `--source-port`.

Open a chat and select **Sign in to this customer**. The issuer clearly labels the test ceremony and asks you to continue as the registered test customer. No password or real account is involved. The browser receives a uniquely named host-only HttpOnly session cookie; the gateway retains the access token. Access expires after 15 minutes. Each gateway uses its own customer admission, resource audience, source key, and state directory. The chat has no editable customer field.

Try:

- “Watch my request rate and error rate live.”
- “What is my p95 latency?” in Customer A.
- The same latency question in Customer B, where policy must reject it.

The deterministic test parser recognizes those metric names and synonyms. The live model must produce the same bounded tool schema; unfamiliar or unauthorized tool arguments fail closed. Watching performs repeated authorized MCP reads about every two seconds for up to 30 seconds, then asks the model for a final explanation. **Stop** closes the UI stream; it does not claim that already accepted work was rolled back.

## What is real in this fixture

The metric source is a real rolling deque receiving synthetic events every 250 milliseconds. It computes named numeric aggregates over the requested window. Sources start empty, so the first rolling window is partial; the UI shows sample counts and a warm-up notice. Empty windows use an unavailable event watermark rather than inventing a new event time. Each source process contains only one customer's events and receives only its own bearer credential. Each gateway child receives only the credential for its configured source; credentials are not accumulated in the parent's environment or sent to the browser/model. The shared host UID still permits host-level access; this is process/protocol evidence, not an OS-user isolation claim.

OAuth uses a public repository test RSA key, `at+jwt` access-token typing, exact audience/customer/subject/client admission, PKCE S256, fixed redirect/resource/client bindings, and signed scope claims. The issuer is deliberately disposable. Native gateway code validates the tokens and rechecks authorization during repeated reads. Explicit `metrics:explain` scope permits the configured model destination to receive the bounded question and numeric aggregate evidence.

Each `auth.admissions` entry requires an exact `client_id` alongside `tenant_id`, `subject`, and `scopes`. Existing configuration without that field fails to load; regenerate fixture configuration or add the registered client explicitly. This binding applies to direct MCP bearer requests as well as browser login. Gateway admission and revocation still use local state; this change does not connect a production IdP or the broker's identity store.

The UI distinguishes the source snapshot time, latest included event watermark, gateway receipt time, and freshness threshold. It preserves each tool call's evidence ID and snapshot sequence. Answers and source/model strings remain plain text. The model provides an explanation, not independent verification that an aggregate is correct.

## Checks and retained evidence

`check-evidence.json` records customer admissions, scope checks, source query counts and stream observations. Each customer's directory includes `chat-evidence.json`, `revoked-stream-evidence.json`, source counters and an aggregate-query journal. `binary-digest.json` identifies the gateway binary. `live-summary.json` describes the running model, source, customer URLs and process IDs. Logs omit tokens, authorization URLs and source credentials.

The runner asserts that wrong-customer/audience/client, expired/revoked tokens, ID-token substitution, payload tampering, missing scope, forbidden metric names and extra tenant/SQL/source fields cannot reach the source. Direct source requests with no key, the opposite customer’s key, or a customer OAuth token receive 401 without computing an aggregate. It verifies changing streamed watermarks, revocation after the first snapshot, and rejection of a reachable source whose event watermark has stopped moving, including an empty one-second window. The two dashboards require independent customer sign-in and scope permissions. Gateway/provider unit tests provide additional protocol and adversarial coverage.

The live Gemma service remains a trusted processor. Its current deployment does not prove hardware isolation or confidential inference. Only synthetic questions and aggregates belong in this demo; no application database, private dataset, raw event row, or production credential is connected.

## Verified local run: 2026-09-04

The final run used `python3 -B scripts/metrics_chat_dogfood.py --serve --no-build` after building the current native gateway. Current evidence is retained at `/private/tmp/omf-p7ciwxzj`; prior independent runs remain at `/private/tmp/omf-65nyj79c`, `/private/tmp/omf-y5k95ud4` and `/private/tmp/omf-2km3s_ut`. The current run also verifies the sign-in form CSP permits only the issuer and its registered customer callback origin, including the cross-port redirect.

The final deterministic check passed for both customers with five changing streamed snapshots each, 24 recorded negative authorization/source/staleness cases, strict-schema rejection, and revocation during a stream without another source read. Each source recorded nine aggregate queries during the check, including rejected stale-evidence probes. No raw rows were returned. The UI's nine Node tests pass for event framing, interrupted streams, freshness, plaintext rendering, scope boundaries, repeated observations, revocation, cookie-only requests, and clearing prior-customer evidence.

The running gateways then switched to the configured Gemma endpoint and require fresh browser sign-in. Customer A is at `http://127.0.0.1:19400` (gateway PID 2316), Customer B at `http://127.0.0.1:19401` (PID 2318). `live-summary.json` records these processes and their source mappings; `check-evidence.json` distinguishes the deterministic protocol checks from subsequent live-model interaction. Existing dashboards on ports 19392, 19393, 19394 and 19396 were preserved.

Final live-model browser verification is recorded separately in `browser-evidence.json` in that state directory. Customer A received five changing error-rate snapshots and a model explanation. Customer B's p95 request was denied with its source query count unchanged, then an allowed request-rate question returned its own data and a model explanation. Both customers completed the actual browser OAuth redirect flow. Desktop and mobile screenshots and a copy of the proof are in `output/playwright/metrics-chat/`. The final gateway tests passed (34 Rust tests), all 17 new/existing UI tests passed, and Clippy with warnings denied passed. The live model's brief prose omitted time context; inspect the validated window, source time and watermark shown beside it.
