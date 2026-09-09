# Hosted demo operations

This runbook describes the implementation and deployment procedure. It is not a
record of a successful public deployment. Record the deployed image digest,
Worker version, admission checks, browser evidence and cleanup result separately.
Run commands from the repository root using the intended `admin@turingpi` context.

## Fixed deployment boundary

| Component | Configuration |
| --- | --- |
| Public Worker | `opaque-demo`, `https://demo.opaque.info` |
| Durable queue | `DEMO_SCHEDULER`, `DemoScheduler`, `global-capacity-v1` |
| Workers VPC service | `01a06f35-01e7-7f30-b3ca-bd99e3a7a673` |
| Dedicated tunnel | `19b53ba6-3242-4456-a1ac-11d2dcaa5f7e` |
| Controller | `opaque-demo-system/opaque-demo-controller`, one replica, `Recreate` |
| Default slot | `opaque-demo-slot-0` |
| Origin destination | `opaque-demo-controller.opaque-demo-system.svc.cluster.local:8080` |

Use the dedicated VPC/tunnel route. Do not add a public controller ingress, reuse
another application's tunnel, or change the existing Pages deployment. The
Turnstile widget must allow only `demo.opaque.info`, use managed mode, and match
the Worker's site key. Server verification requires `action=demo_join` and the
expected hostname. Production must not set `LOCAL_TEST_MODE` or use test keys.

## Build and render immutable inputs

Prerequisites: a tested **Linux/ARM64** `opaque-showcase` binary at
`deploy/hosted-demo/bin/opaque-showcase`, Docker, crane, kubectl, Python with PyYAML,
and an authenticated Wrangler version supporting the checked-in configuration.
A macOS binary cannot be used in the runtime image. Use the existing configured
Docker builder; these instructions do not switch contexts or install runtimes.

The registry currently requires plain HTTP. The explicit `--insecure` below
applies only to that internal registry; it is not a general TLS exception.

```sh
umask 077
export OPAQUE_RENDER_DIR="$(mktemp -d /private/tmp/opaque-hosted-render.XXXXXX)"
export RUNTIME_REPOSITORY=192.168.25.201:5050/opaque-hosted-demo
export RUNTIME_TAG="$RUNTIME_REPOSITORY:20260904"
export WORKER_ORIGIN=https://demo.opaque.info
export CLOUDFLARED_IMAGE=cloudflare/cloudflared@sha256:51c9cefcb4569df44e1ad403ab1d3d8065aa8e84339bcfc6aee75502e1140339

docker build --platform linux/arm64 -f deploy/hosted-demo/Dockerfile -t "$RUNTIME_TAG" .
docker save -o "$OPAQUE_RENDER_DIR/runtime.tar" "$RUNTIME_TAG"
crane push --insecure --image-refs "$OPAQUE_RENDER_DIR/published-images.txt" "$OPAQUE_RENDER_DIR/runtime.tar" "$RUNTIME_TAG"
export RUNTIME_IMAGE="$RUNTIME_REPOSITORY@$(crane digest --tarball "$OPAQUE_RENDER_DIR/runtime.tar")"
test "$(crane digest --insecure "$RUNTIME_IMAGE")" = "${RUNTIME_IMAGE##*@}"
printf '%s\n' "$RUNTIME_IMAGE" > "$OPAQUE_RENDER_DIR/runtime-image.txt"
```

The pinned cloudflared image was identified as version 2026.8.3. Re-review an
updated digest before replacing it. Preserve the runtime digest and source/test
revision with the deployment record; the tag alone is not a deployment identity.

Render and separate the initial state from repeatable configuration:

```sh
python3 - <<'PY'
import os, pathlib, re, yaml
out = pathlib.Path(os.environ['OPAQUE_RENDER_DIR'])
values = {name: os.environ[name] for name in ('RUNTIME_IMAGE', 'WORKER_ORIGIN', 'CLOUDFLARED_IMAGE')}
for name in ('RUNTIME_IMAGE', 'CLOUDFLARED_IMAGE'):
    assert re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}', values[name]), name
assert values['WORKER_ORIGIN'] == 'https://demo.opaque.info'
def read(name):
    text = pathlib.Path('deploy/hosted-demo', name).read_text()
    for key, value in values.items():
        text = text.replace('${' + key + '}', value)
    assert not re.search(r'\$\{[A-Z_]+\}', text)
    return [doc for doc in yaml.safe_load_all(text) if doc]
def write(name, docs):
    (out / name).write_text(yaml.safe_dump_all(docs, sort_keys=False))
base = read('k8s.yaml')
write('namespaces.yaml', [d for d in base if d['kind'] == 'Namespace'])
write('initial-state.yaml', [d for d in base if d['kind'] == 'ConfigMap'])
write('deployment.yaml', [d for d in base if d['kind'] not in ('Namespace', 'ConfigMap')])
write('admission.yaml', read('k8s-admission.yaml'))
write('tunnel.yaml', read('k8s-tunnel.yaml'))
PY
```

**The slot ConfigMap is initial bootstrap only. Never apply the original
`k8s.yaml` wholesale to an existing deployment.** Its generation-zero state would
overwrite retained creation/execution uncertainty and lease fences. Repeat
updates use `deployment.yaml`, which excludes that ConfigMap. An absent state
record on a previously used slot requires reconciliation, not fresh bootstrap.

## Install while admissions are paused

Review the rendered files first. Namespace labels enforce restricted Pod Security;
check compatibility with the target cluster before applying. Create state only
for a slot that has never been used:

```sh
kubectl --context admin@turingpi apply -f "$OPAQUE_RENDER_DIR/namespaces.yaml"
# INITIAL INSTALL ONLY. AlreadyExists means preserve and inspect existing state.
kubectl --context admin@turingpi create -f "$OPAQUE_RENDER_DIR/initial-state.yaml"
```

Keep three distinct credentials in protected files: the controller secret shared
between Worker and controller, the dedicated tunnel token, and Turnstile's secret
key. Set `CONTROLLER_SECRET_FILE`, `TUNNEL_TOKEN_FILE`, and `TURNSTILE_SECRET_FILE`
to those files; do not paste their values into shell arguments, checked-in YAML,
logs or chat. Use mode 0600 in a mode 0700 directory and retain recoverable copies
in the operator's secure storage. Temporary files under `/private/tmp` are not a
backup. A controller credential must be 43–128 URL-safe characters without a
trailing newline. Do not rotate it during active leases without coordinated drain.

```sh
: "${CONTROLLER_SECRET_FILE:?Set protected file path}"
: "${TUNNEL_TOKEN_FILE:?Set protected file path}"
: "${TURNSTILE_SECRET_FILE:?Set protected file path}"
chmod 600 "$CONTROLLER_SECRET_FILE" "$TUNNEL_TOKEN_FILE" "$TURNSTILE_SECRET_FILE"

wrangler deploy --config deploy/cloudflare-demo/wrangler.toml --var DEMO_ENABLED:false
wrangler secret put CONTROLLER_SECRET --config deploy/cloudflare-demo/wrangler.toml < "$CONTROLLER_SECRET_FILE"
wrangler secret put TURNSTILE_SECRET --config deploy/cloudflare-demo/wrangler.toml < "$TURNSTILE_SECRET_FILE"

kubectl --context admin@turingpi -n opaque-demo-system create secret generic opaque-demo-controller-auth --from-file=controller-secret="$CONTROLLER_SECRET_FILE" --dry-run=client -o yaml | kubectl --context admin@turingpi apply -f -
kubectl --context admin@turingpi -n opaque-demo-system create secret generic opaque-demo-tunnel --from-file=TUNNEL_TOKEN="$TUNNEL_TOKEN_FILE" --dry-run=client -o yaml | kubectl --context admin@turingpi apply -f -

kubectl --context admin@turingpi apply --dry-run=server -f "$OPAQUE_RENDER_DIR/admission.yaml"
kubectl --context admin@turingpi apply -f "$OPAQUE_RENDER_DIR/admission.yaml"
kubectl --context admin@turingpi get validatingadmissionpolicy opaque-hosted-demo-runtime -o jsonpath='{.status.typeChecking.expressionWarnings}'
kubectl --context admin@turingpi apply --dry-run=server -f "$OPAQUE_RENDER_DIR/deployment.yaml"
kubectl --context admin@turingpi apply -f "$OPAQUE_RENDER_DIR/deployment.yaml"
kubectl --context admin@turingpi apply -f "$OPAQUE_RENDER_DIR/tunnel.yaml"
kubectl --context admin@turingpi -n opaque-demo-system rollout status deployment/opaque-demo-controller --timeout=120s
kubectl --context admin@turingpi -n opaque-demo-system rollout status deployment/opaque-demo-tunnel --timeout=120s
```

Resolve every admission type-check warning before enabling requests; an empty
status before reconciliation is not evidence that checking finished. Rollout
success alone does not establish tunnel connectivity or runtime readiness.

For two slots, bootstrap `k8s-slot-1.yaml` with the same initial-state separation,
configure both namespaces in `OPAQUE_DEMO_SLOT_NAMESPACES`, and only then raise
`DEMO_CAPACITY` to 2. Do not change the existing queue binding or Durable Object
identity to increase capacity. Model concurrency remains one.

## Fixed model selection and rollout

The model-choice release accepts only a catalog alias at admission.
`DEMO_MODEL_IDS` enables a comma-separated subset of that catalog for new joins;
`DEMO_DEFAULT_MODEL` must be in the enabled subset. The legacy default is
`gemma4-e2b`; the checked-in public configuration now defaults new joins to
`qwen35-4b` after the September 5 exploration qualification. Existing leases
retain their selected model. A catalog entry does not mean its backend is
running or qualified for every kind of question.
The browser never supplies the backend URL, model file, credentials or Pod
configuration. A lease's `model_id` cannot change once queued or admitted.

| Lease alias | Fixed backend | Actual model name |
| --- | --- | --- |
| `gemma4-e2b` | `http://llama-server.gemma4.svc.cluster.local:8080/` | `gemma-4-E2B-it-Q3_K_M.gguf` |
| `qwen35-4b` | `http://llama-server-qwen35.opaque-models.svc.cluster.local:8080/` | `Qwen3.5-4B-Q4_K_M.gguf` |
| `qwen3-14b` | `http://llamacpp-head.nvidia-system.svc.cluster.local:8080/` | `Qwen3-14B-Q4_K_M.gguf` |

`model_profiles.py` owns the controller/runtime mapping. Every provision and
cleanup action carries the alias, and the controller retains it in slot state
and the cleanup tombstone. The runtime checks
`OPAQUE_DEMO_MODEL_PROFILE`, `OPAQUE_DEMO_MODEL_URL` and `OPAQUE_DEMO_MODEL_ID`
against that exact mapping. Authenticated health must report the same alias,
name and URL before readiness or uncertain-execution clearance. The local model
bridge refuses a different request-body model before sending any model request.
This proves configured routing, not attestation of remote weights or hardware.

Packaged tests may explicitly set `OPAQUE_DEMO_MODEL_TEST_ORIGIN` equal to the
model URL, restricted to canonical HTTP `127.0.0.1` or `host.docker.internal`
with an explicit port from 1024–65535. The model name must still match its fixed
profile. **Never include this test variable in production runtime environments
or permit it in the admission policy.**

For a model-choice cutover, pause admissions and drain before replacing the
controller/runtime and admission policy. Old runtime health does not carry the
new model binding, so mixed old/new active leases cannot be assumed compatible.
Validate the generated Pod for every newly enabled profile with server dry-run,
including negative alias/URL/name combinations, and qualify actual allowed and
denied requests before enabling that alias. Keep an existing lease's selected
backend reachable through cleanup even if its alias is removed from new joins.
The shared global model-request fence remains one across all profiles.

The dedicated Qwen service uses the reviewed `qwen35-model.yaml`, a bounded
8 GiB model PVC and verified GGUF bytes. Its GPU allocation is separate from
disposable lease Pods. The checked-in replica count is now one for the qualified
deployment. For an initial install, stage the Deployment at zero until the
artifact download and explicit GPU allocation are complete. The operator backed
up the stalled old Qwen3-14B
head at `/private/tmp/opaque-credit-deployment/llamacpp-head-before-model-update.yaml`
and scaled only that head down to release Jetson 1. RPC workers 2/3 and Gemma
were unchanged. That temporary file is not a durable backup; retain a protected
copy. Do not restart the old head while Qwen3.5 holds the same GPU, and do not
infer that the previously stalled service becomes healthy just by restoring
its replica count. Actual qualification and current rollout status belong in
[CREDIT-VALIDATION.md](CREDIT-VALIDATION.md).

Keep `--cache-ram 0` on the Qwen service. The pinned server otherwise defaults
to an 8192 MiB cross-request prompt cache, exceeding the container's entire
5500 MiB allowance. Repeated exploration qualification observed an OOM kill
under that default. The active context remains 2048 tokens and one inference
slot; disabling the optional RAM cache does not require another GPU or a larger
memory limit. Apply model configuration changes only after confirming no active
demo workspaces or inference requests, and verify readiness and memory behavior
before qualification resumes. The September 5 exploration record tracks this
change separately from the web application rollout.

## Validate, then open requests

### Request and storage budgets

The controller polls every 30 seconds while idle and every 2 seconds when work
is returned. `next_poll_at` and the legacy `next_alarm_at` cap that wait at lease
expiry or a quarantined cleanup retry. Paused admissions do not stop draining.
Consecutive queue failures back off from 30 seconds to a maximum of 300 seconds;
future known deadlines preempt the wait, while an already-passed deadline does
not force repeated fast retries during an outage. Once capped, recovery may
take up to five minutes to be detected. Existing proxy/runtime expiry fences
continue to apply during that wait.

Optional controller environment settings are `OPAQUE_DEMO_POLL_SECONDS` (2),
`OPAQUE_DEMO_IDLE_POLL_SECONDS` (30), and
`OPAQUE_DEMO_ERROR_BACKOFF_MAX_SECONDS` (300). All must be finite, with
`1 <= active <= 30` and `active <= idle <= error maximum <= 300` seconds.

Visible landing pages check idle/terminal sessions every 60 seconds, and
queued, provisioning, ready, cleaning, and quarantined sessions every 5 seconds.
Configuration is refreshed at most once a minute during ordinary polling.
Hidden tabs stop scheduled checks; returning, retrying, or completing an action
forces a fresh check. Connection failures back off to five minutes. Local
countdowns still close expired workspace links independently of polling.

The scheduler commits at most one queue-state change per `/internal/work`
request and changes a storage alarm only when its deadline changes. Identical
state writes are skipped without dropping the persisted monotonic clock. The
Durable Object class, queue schema, generations, and cleanup evidence remain
compatible with the previous release. With no visitors or pending work,
30-second polling is approximately 2,880 Worker requests and 2,880 queue-state
writes per day, excluding other account usage and network latency. Measure both
Worker requests and Durable Object rows written; successful Worker execution
metrics can still contain handled HTTP 503 responses.

### Validation

Run local tests before deployment:

```sh
node --test deploy/cloudflare-demo/tests/*.test.mjs
python3 -B -m unittest discover -s deploy/hosted-demo -p 'test_*.py' -v
```

These use fixtures; they do not prove live cluster isolation or real bot checks.
For public probes, do not add visitor cookies or controller credentials:

```sh
curl --fail --silent --show-error "$WORKER_ORIGIN/demo/api/config"
curl --silent --show-error -o /dev/null -w '%{http_code}\n' "$WORKER_ORIGIN/workspace"
curl --silent --show-error -o /dev/null -w '%{http_code}\n' "$WORKER_ORIGIN/internal/work"
curl --silent --show-error -o /dev/null -w '%{http_code}\n' -X POST "$WORKER_ORIGIN/demo/api/join" -H 'Origin: https://foreign.invalid' -H 'Content-Type: application/json' --data '{"turnstile_token":"invalid","model_id":"qwen35-4b"}'
curl --silent --show-error -o /dev/null -w '%{http_code}\n' -X POST "$WORKER_ORIGIN/demo/api/join" -H "Origin: $WORKER_ORIGIN" -H 'Content-Type: application/json' --data '{"turnstile_token":"invalid","model_id":"qwen35-4b"}'
```

While paused, config must report `available:false`; workspace and internal routes
must return 401, foreign Origin 403, and same-origin join 503. Confirm the
controller can poll the queue through the dedicated route, the admission policy
accepts only the reviewed runtime, and there are no unexplained slot resources.
When checking drain, retain terminal session records: their 24-hour history
expiry can leave `next_alarm_at` set after all work has ended. Under the current
queue limits, queued, provisioning and ready deadlines are within 30 minutes.
Check the alarm together with work actions, the retained slot lease and slot
Pod/Service/Secret resources; a retention alarm alone does not mean a workspace
is active. Preserve any cleanup fences. Do not clear the queue or reset the
slot ConfigMap to remove that timer.

Enable only after these checks and real Turnstile configuration are complete:

```sh
wrangler deploy --config deploy/cloudflare-demo/wrangler.toml --var DEMO_ENABLED:true
```

Re-run the probes: config must report `available:true` with capacity 1 and 600
seconds; invalid same-origin bot proof must now return 403 with no lease created.
Complete one real browser bot check, observe queued/provisioning/ready states,
open chat, and verify actual metric timestamps and permission denials. End the
session and confirm workspace access is denied, cleanup removes the exact lease
Pod/Service/Secret, and the state ConfigMap retains its advanced generation.
Also verify expiry, subsequent slot reuse and mobile layout. Do not announce the
public demo as operational until this evidence is retained. Browser cookies and
secret-bearing responses must be excluded from screenshots and diagnostic logs.

## Pause, drain and roll back

1. Deploy with `--var DEMO_ENABLED:false` and verify public config reports false.
   This stops new admission; it does not cancel existing or queued leases.
2. Keep Worker, controller, tunnel and model connectivity running while admitted
   sessions finish or expire and queued tickets drain. Queue lifetime is 30
   minutes; allow bounded provisioning/session time after the last admission.
   Watch controller work and slot state without displaying credentials.
3. Confirm no active/provisioning/cleaning work, no lease Pod/Service/Secret,
   and no `create_inflight` or unresolved execution fence. Inspect the state
   ConfigMaps and retained controller/Worker evidence. Resource absence alone
   does not prove that a remote model request stopped.
4. Only after confirmed drain, stop the controller/tunnel or apply a reviewed
   previous runtime digest. Keep the Worker paused during rollback, render the
   admission policy for that same digest, and preserve queue storage and both
   slot state records. Do not blindly reapply bootstrap YAML or delete a
   namespace/Durable Object as a cleanup shortcut.
5. Repeat admission, connectivity and lifecycle validation before re-enabling.

**Model-catalog migrations constrain rollback.** The new Worker migrates queue
state version 2 to version 3, assigning every historical ticket explicitly to
Gemma. New controller writes use state schema 2 with a required model alias;
schema-1 state with no alias is interpreted as historical Gemma and migrated on
the next normal write. Neither migration follows the current default model.
Missing model binding in a new-format record fails closed.

After these migrations, a previous Worker/controller that only reads the old
schema is not a valid binary rollback. Choose a rollback build that can read
queue version 3 and controller schema 2, or roll forward with a reviewed fix.
Preserve every generation, ticket and uncertainty fence; restoring an old
pre-migration state snapshot can resurrect expired authority or lose outstanding
work. Merely changing the default model does not retarget queued or active
leases. If no compatible rollback exists, keep admission paused while preparing
a reviewed recovery; do not reset state or silently rewrite model bindings.

A quarantined slot is deliberately unavailable. Do not clear its fence to make
capacity appear free. Unknown Kubernetes CREATE or possible remote model work
needs manual reconciliation as described in [CONTROLLER.md](CONTROLLER.md).
Stopping the pod/controller alone is not proof of quiescence.

## Limits and known gaps

- Default capacity 1; maximum 2; at most 100 queued visitors. Admission is limited
  to five requests per IP per hour; public priority is server-controlled.
- Sessions last 10 minutes after readiness, with a two-minute provisioning
  deadline. Each session allows 12 questions, at most two model calls per
  question, 192 output tokens per model call, and 30-second metric watches.
- Lease runtimes have one bounded, non-root pod, their own source/proxy
  credentials, no mounted Kubernetes token, no host mounts, and no new GPU
  allocation. Sources and visitor identities are synthetic, not customer OAuth.
- Flannel currently has no verified NetworkPolicy enforcement. Namespaces, RBAC,
  admission and authenticated proxies do **not** provide network isolation.
  Compromised processes can reach routable cluster services.
- Shared model services are trusted processors outside the lease sandbox.
  Gemma retains mutable host-mounted model/executable identity; Qwen uses a
  pinned server image and verified artifact on its model PVC. Other cluster
  clients remain outside the demo's model budget. Internal registry/model/origin hops include
  plaintext HTTP. This is not confidential inference, a microVM, a TEE, or
  hardware-attested execution. Use only synthetic/public information.
