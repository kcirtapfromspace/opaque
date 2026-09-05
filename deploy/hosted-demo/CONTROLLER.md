# Hosted demo controller

This controller provisions only the reviewed synthetic metrics runtime. Visitors
cannot supply images, commands, URLs, Kubernetes specs, source credentials, SQL,
or tenant identifiers. The Worker admits a lease into one of one or two slots;
each slot is a precreated namespace with one Pod, one Service and one Secret.
The controller keeps a fourth, persistent ConfigMap containing its generation
and uncertainty fences. That control record is intentionally not deleted with
the lease.

The demo uses a disposable synthetic identity. Its loopback issuer, source and
gateway share a pod; the only listening pod entry point requires a separate
random lease credential. This demonstrates governed synthetic data access, not
production customer OAuth or sandboxing arbitrary visitor code.

The model-profile extension binds a fixed alias to each lease. The runtime
checks the exact backend URL and model name from `model_profiles.py`, and the
controller verifies that binding in authenticated health before readiness or
execution clearance. It cannot be changed by a chat message. Queue version 3
and controller schema 2 preserve that alias; legacy records resolve explicitly
to Gemma. See [OPERATIONS.md](OPERATIONS.md#fixed-model-selection-and-rollout)
for rollout status requirements, local test exceptions and rollback compatibility.

## Initial cluster evidence, 2026-09-04

Read-only discovery used the existing `admin@turingpi` context. All six nodes are
ARM64. `talos-ek0-5dx` has approximately 30Gi allocatable memory but a control-plane
NoSchedule taint; this deployment does not tolerate it. `talos-lwn-dba` is
unreachable. Scheduled ordinary-container requests on `talos-ssm-o4m` total
2564m CPU and 2442Mi memory against 3950m/~3297Mi allocatable. This is request
accounting, not measured usage; `kubectl top nodes` reported that the Metrics API
is unavailable. The Jetson nodes have CPU/memory request headroom, but all three
advertised GPUs are already requested by existing workloads.

These initial observations predate the separately recorded Qwen3.5 deployment.
Current model changes are recorded in [CREDIT-VALIDATION.md](CREDIT-VALIDATION.md);
the older placement and request accounting below are not a current free-capacity
claim.

The existing Gemma service is
`llama-server.gemma4.svc.cluster.local:8080`, model
`gemma-4-E2B-it-Q3_K_M.gguf`, one parallel slot and 2048-token configured context.
Its host-mounted executable and model do not have verified immutable identities.
The initial demo reused this service without deploying another model, reserving
another GPU or preempting existing work. The later Qwen model deployment is
recorded separately above. Worker and controller both serialize demo model requests; unrelated
existing cluster clients are outside that demo budget.

The existing registry's `http://192.168.25.201:5050/v2/` returned 200. This verifies
read reachability only, not push permission. Build the runtime image for
`linux/arm64`, then configure its exact `@sha256:` digest. The plain HTTP registry
and existing mutable Gemma deployment are internal infrastructure limitations;
an image digest protects content selection, not registry transport privacy.

Only the Tailscale ingress class was found. Existing Cloudflare tunnels in
`kcirtap` and `ukodus` remain untouched. `k8s-tunnel.yaml` is for a new dedicated
tunnel connected to a fixed Workers VPC service, without a public origin route.

Flannel v0.27.4 was observed without a network-policy controller. No RuntimeClass,
ResourceQuota, LimitRange or ValidatingAdmissionPolicy existed before this work.
The existing seven NetworkPolicies were all in ArgoCD. Flannel documents a
[separate policy controller](https://github.com/flannel-io/flannel/blob/master/Documentation/netpol.md),
and Kubernetes requires a
[policy-enforcing network implementation](https://kubernetes.io/docs/concepts/services-networking/network-policies/).
These templates do not install one. Namespace/RBAC separation and bearer-authenticated
proxies do not establish network or microVM isolation; compromised demo processes
could reach other routable cluster services. Use synthetic data only within this
boundary. No live cluster deployment or adversarial network probe is claimed by
the local controller tests.

## Local checks and deployment inputs

Run `python3 -m unittest discover -s deploy/hosted-demo -p test_controller.py -v`.
The tests use a fake Kubernetes API and real loopback HTTP for proxy behavior.
They cover create ambiguity across restart, concurrent cleanup, retained
finalizers, exact generation/expiry, slot reuse, credentials, uncertain model
work and completion trailers. They do not test Kubernetes admission or the
Cloudflare tunnel.

An operator renders `k8s.yaml` and `k8s-admission.yaml` with `RUNTIME_IMAGE` and
`WORKER_ORIGIN`; `RUNTIME_IMAGE` must be digest pinned. The system namespace is
`opaque-demo-system`. Provision `opaque-demo-controller-auth` there with key
`controller-secret`; use the same secret at the Worker's controller boundary.
Do not put secret values in checked-in YAML or command output.

The new tunnel uses a separate `opaque-demo-tunnel` Secret with key
`TUNNEL_TOKEN`. Render `CLOUDFLARED_IMAGE` as a reviewed digest for version 2025.7
or newer. Its service destination is fixed:
`opaque-demo-controller.opaque-demo-system.svc.cluster.local:8080`.

Server dry-run and type-check the admission policy before activation. Its
namespace selector limits it to the newly labelled demo slot namespaces.
Pod Security Admission additionally enforces the Kubernetes 1.35 restricted
profile. The controller service account has only get/create/delete on lease
pods, services and secrets inside those namespaces, plus get/update on the
single state ConfigMap. It cannot create namespaces, RBAC, workloads elsewhere,
or read other application secrets. Runtime pods do not mount API credentials.

Keep the controller at one replica using `Recreate`. For capacity two, first
provision `k8s-slot-1.yaml`, configure both slot namespaces in the controller and
raise Worker capacity to two. Model concurrency remains one. Never recreate or
reset the state ConfigMaps when redeploying: they contain durable high-water
marks, not disposable example configuration. Back them up and reconcile them
with Worker state before replacing a cluster or Worker database.

## Lifecycle and uncertainty

The Worker generates monotonically increasing generations per slot. Provision
requests bind lease, tenant, generation and hard expiry. All resource names are
`demo-<32 hexadecimal lease ID>`. The pod receives only its own proxy secret,
fixed model configuration and lease bounds. It has no host mounts, host ports,
GPU allocation, privilege escalation, service account token or writable root
filesystem. It has bounded temporary memory, CPU/memory limits, `Never` restart
policy and a hard pod deadline. The runtime separately enforces absolute expiry.

Before each Kubernetes CREATE, the controller persists `create_inflight:true`.
A known response clears it. A transport error, server 5xx or restart between those
steps leaves the slot quarantined. An API timeout does not prove a create failed;
a later absence check alone cannot safely refund capacity. Do not clear this
fence through a visitor endpoint or an automatic retry. An operator must first
stop the old controller, establish that outstanding API requests are over,
inspect/delete the exact old lease resources, and reconcile the Worker before
editing the durable state. No automated recovery is provided for this case.

Proxy requests require the controller credential, exact generation, and actual
visitor expiry. Seeing a shorter expiry permanently narrows that lease's proxy
bound; later requests cannot extend it. Only GET `workspace`, GET `api/session`
and POST `api/chat` are forwarded. Browser cookies, upstream cookies and arbitrary
headers are not forwarded. The controller persists an execution fence before
chat, drains the runtime response even if the browser disconnects, and emits
`opaque_execution_complete` only after authenticated runtime health establishes
zero active and model requests. Model uncertainty blocks new demo model work
across both slots.

Cleanup advances the generation under the same per-slot lock as creation and
proxy dispatch. It requires evidence that possible model work stopped; killing
the pod does not prove a remote GPU request stopped. It deletes resources with
UID preconditions, checks all three are absent, persists the cleaned tombstone,
then reports all cleanup proofs. Finalizers, unknown creation, unreachable
runtime with possible work, or failed state writes retain capacity rather than
allowing another visitor into an uncertain slot.
