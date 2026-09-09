# Hosted human approval deployment

Private operator preparation, September 5, 2026. The public demo uses a separate
GitHub OAuth application owned by `opaque-dev`. Its homepage is
`https://demo.opaque.info/` and its exact authorization callback is
`https://demo.opaque.info/approval/callback`.

The callback only returns a short-lived code and state to the originating
approval popup. The runtime exchanges that code using its private client secret,
verifies the GitHub identity, and asks Opaque to approve the already-reviewed
task. The browser never receives the GitHub access token. Executing the task is
a separate user action. This establishes human identity for the synthetic demo;
it does not infer tenant membership, repository permissions, or organization
membership from app ownership.

## Configuration

Store the application's ID and secret in the existing secure credential store.
The optional [controller patch](controller-oauth.patch.yaml) references a
Kubernetes Secret named `opaque-demo-github-oauth` in namespace
`opaque-demo-system`, with keys `client-id` and `client-secret`. Neither value
belongs in Git or operator evidence. When provisioning from protected local
files, use `kubectl create secret ... --from-file` rather than placing values in
command arguments. Do not print the rendered Secret.

The controller reads `OPAQUE_DEMO_OAUTH_PROVIDER=github`,
`OPAQUE_DEMO_OAUTH_CLIENT_ID`, and `OPAQUE_DEMO_OAUTH_CLIENT_SECRET`. It derives
the approval origin and exact callback from `OPAQUE_DEMO_WORKER_URL`, copies the
client secret into each disposable lease's Secret, and supplies only the fixed
approval environment variables to the gateway subprocess. No issuer or custom
provider endpoint is accepted for direct GitHub mode.

The runtime admission template now accepts the approval variables, requires the
configured Worker origin and exact callback, and permits the OAuth client
secret only through the pod's own lease Secret. Render both `${RUNTIME_IMAGE}`
and `${WORKER_ORIGIN}` before updating the policy. Review the rendered policy,
then use the drain and rollout process in [OPERATIONS.md](../OPERATIONS.md).
Apply the optional controller patch as part of that same reviewed rollout.
Do not restore an old controller image without checking the persisted queue and
controller state schema compatibility.

## Narrow rollout inputs

After the immutable image is built and published and the GitHub Secret is ready,
pause new admission and let existing/queued sessions finish using the existing
Worker, controller, tunnel, and model services. Confirm both queue reconciliation
and empty lease resources; an empty namespace alone does not prove a drained
queue or stopped model work. Never reset the slot ConfigMap generation.

Render the current controller's narrow patch using the verified image digest:

```sh
export OPAQUE_APPROVAL_ROLLOUT_DIR="$(mktemp -d /private/tmp/opaque-approval-rollout.XXXXXX)"
python3 deploy/hosted-demo/approval/render-rollout.py \
  --runtime-image "$RUNTIME_IMAGE" \
  --output "$OPAQUE_APPROVAL_ROLLOUT_DIR"
```

The renderer reads the current Deployment, current admission Policy, and local
admission template. It uses `kubectl create --dry-run=client --validate=false`
to decode the rendered YAML as JSON. It does not apply changes or read any
Secret. It preserves the controller's other environment values and rollout
settings and writes four review files: the controller JSON Patch, the admission
Policy JSON Patch, the desired Policy YAML, and a safe summary. It rejects inline
sensitive environment values, unpinned images, or changed public-origin/rollout
settings. Review all four output files before rollout.

The Policy patch tests the exact live `metadata.resourceVersion` and current
`spec`, then replaces only `spec`. Kubernetes retains the live metadata,
including its annotations, labels, UID and managed fields. The YAML is for
review; use the guarded patch for rollout. This avoids interpreting a stale
resource version embedded in an earlier `last-applied-configuration` annotation.

With admissions paused, queue/slots drained, and the image and Secret verified,
the narrow rollout commands are:

```sh
kubectl --context admin@turingpi patch validatingadmissionpolicy opaque-hosted-demo-runtime \
  --type=json --dry-run=server \
  --patch-file "$OPAQUE_APPROVAL_ROLLOUT_DIR/admission-policy.patch.json"
kubectl --context admin@turingpi -n opaque-demo-system patch deployment opaque-demo-controller \
  --type=json --dry-run=server \
  --patch-file "$OPAQUE_APPROVAL_ROLLOUT_DIR/controller-rollout.patch.json"
kubectl --context admin@turingpi patch validatingadmissionpolicy opaque-hosted-demo-runtime \
  --type=json --patch-file "$OPAQUE_APPROVAL_ROLLOUT_DIR/admission-policy.patch.json"
kubectl --context admin@turingpi -n opaque-demo-system patch deployment opaque-demo-controller \
  --type=json --patch-file "$OPAQUE_APPROVAL_ROLLOUT_DIR/controller-rollout.patch.json"
kubectl --context admin@turingpi -n opaque-demo-system rollout status \
  deployment/opaque-demo-controller --timeout=120s
```

The generation and previous-image/environment checks reject concurrent
Deployment changes; the resource-version and spec checks reject concurrent
Policy changes. If either patch fails its guards, read the new state and
re-render; do not remove the guards. These commands do not change namespace, quota, RBAC, slot
ConfigMap, tunnel, or model objects. Keep the Worker paused through startup,
admission-policy positive/negative checks, and callback-asset checks. Record a
fresh safe state observation and image digest before reopening admission. Then
verify one controlled real-login/passkey lifecycle immediately; pause admission
again if any lifecycle check fails.

The September 5 read-only observation was controller generation 8, one ready
replica with `Recreate`, and tunnel generation 1 with one ready replica. The
controller and seven-validation admission policy both selected runtime digest
`sha256:4d2b1844472bb63f7bdfd18bcafb009ee5dcdb80477e3215f9cdeb0dc3623e54`.
Slot 0 retained state schema 2 and generation 26, with no current lease or
execution/create fences and no lease Pod/Service/Secret. Public admissions were
enabled. These observations are not authorization to skip the fresh drain
checks before a rollout.

## Build and validation

The Linux/ARM64 `rust:1.95.0-slim-bookworm` builder needs `libssl-dev` and
`pkg-config` for `webauthn-rs`; the inspected base image contains only
`libssl3`. Install the development packages inside the disposable builder,
then build `cargo build --locked --release -p opaque-showcase`. Keep the Cargo
target/cache in the existing Docker cache volumes. Copy and strip the resulting
Linux executable into the ignored `deploy/hosted-demo/bin/` directory before
building the runtime image. The runtime Dockerfile installs `openssl`, which
provides the required `libssl3` shared library on Debian Bookworm.

Before enabling public OAuth, verify the registered application's callback,
positive and denied login, expiry, replay rejection, cancelled-popup behavior,
session binding, and a real human passkey prompt. Verify the callback page is
served only at its exact path with hashed scripts, `no-store`, `no-referrer`,
and no network capability. Include the new callback HTML in the Worker assets.

Read-only connectivity checks from the existing controller pod returned HTTP
200 from `https://github.com` and `https://api.github.com/meta` on September 5.
No slot pod was running at the time, so these observations are not a completed
OAuth exchange or a direct slot-network validation.

## Existing Argo identity

The private Argo Dex/GitHub login remains unchanged. Its tailnet issuer failed
DNS resolution from the controller pod during read-only preflight, which is why
the public demo uses direct GitHub. No Argo ConfigMap, connector, OAuth app,
GitOps repository, network configuration, or cluster workload was changed by
this preparation. Transferring or replacing the existing Argo OAuth app is not
needed for the separate `opaque-dev` demo application.
