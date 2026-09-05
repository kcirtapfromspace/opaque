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
and `${WORKER_ORIGIN}` before applying the policy. Review the rendered policy,
then use the drain and rollout process in [OPERATIONS.md](../OPERATIONS.md).
Apply the optional controller patch as part of that same reviewed rollout.
Do not restore an old controller image without checking the persisted queue and
controller state schema compatibility.

## Build and validation

The Linux/ARM64 `rust:1.95.0-slim-bookworm` builder needs `libssl-dev` and
`pkg-config` for `webauthn-rs`; the inspected base image contains only
`libssl3`. Install the development packages inside the disposable builder,
then build `cargo build --locked --release -p opaque-metrics`. Keep the Cargo
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
