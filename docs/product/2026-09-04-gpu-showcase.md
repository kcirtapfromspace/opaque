# GPU showcase: bounded use of an existing model

Start with a few approved inference requests to the existing Gemma service,
after its owner confirms acceptable load and access. This demonstrates Opaque's
core value: an agent can use a scarce capability within an approved budget,
without receiving cluster administration or unrestricted inference credentials.
Do not allocate a new GPU job while the existing reservations and direct-device
workloads are unresolved.

This assessment used read-only Kubernetes workload, image, service, endpoint,
and status metadata through `admin@turingpi` on 2026-09-04. It did not read
Secrets, execute inside pods, generate tokens, pull models, change workloads,
install templates, or dispatch GitHub workflows.

## Observed state

| Surface | Observation | Implication |
| --- | --- | --- |
| Nodes | Six ARM64 nodes; three Jetsons each advertise one `nvidia.com/gpu`; kubelet `v1.35.0` | A generic x86 CUDA image is unsuitable. |
| `nvidia-system/llamacpp-head` | One desired pod, running but not ready; its service endpoint is not ready | Do not use this endpoint for the first inference test. |
| `nvidia-system/llamacpp-rpc-jetson2` and `jetson3` | Both ready; head and RPC deployments each reserve one GPU | All three advertised GPUs are reserved; no spare allocation was observed. |
| `gemma4/llama-server` | One ready pod and ready service endpoint on `talos-jetson-3`; model argument `/models/gemma-4-E2B-it-Q3_K_M.gguf`; context 2048, parallel 1, reasoning budget 0 | Best existing endpoint candidate, subject to owner approval and readiness recheck. |
| Gemma resource isolation | CPU/memory limits, no `nvidia.com/gpu` request, direct `/dev/nvgpu` and related device mounts | Actual GPU sharing is not fully represented by scheduler reservations. Do not infer idle capacity from Kubernetes GPU accounting. |
| `ollama` | Argo Application reports Healthy/Synced, but namespace contains a service with no ready endpoint and no pod | Argo health is not sufficient evidence of an available inference backend. |
| RuntimeClasses | No RuntimeClass resources | Do not assume an `nvidia` runtime class exists. Validate Jetson CDI/device-plugin compatibility before any new job. |

The ready Gemma pod's observed image was
`192.168.25.201:5050/llama-server@sha256:ae30dbf9e8cd03535f2e5c9c44a2b2a59a49cb5c77204841eecfa9d701db8c9d`.
Its deployment still references a mutable `latest` tag. The service UID was
`b4d88789-84c4-4f74-ac90-4c75be218c59`, with port 8080 and NodePort 30083.
These are observation identifiers, not a verified model hash or authorization
to use the endpoint. A broker should use a fixed trusted internal service
authority and verify identity/readiness, rather than accept an arbitrary agent
URL or expose the NodePort as its authorization boundary.

## First bounded experience

Propose one human-approved task for **three serial requests**, each with at most
512 input tokens and 96 generated tokens, for a total generation allowance of
288 tokens. The task expires after ten minutes. Each request has a 30-second
broker deadline, with no concurrent requests, tools, image uploads, model
selection, endpoint selection, or extra generation options. Use small public
dogfood prompts, such as summarizing a fixed synthetic deployment receipt.

The future broker operation should bind the cluster/provider authority, service
UID, model identity or verified model-file hash, prompt digest, exact generation
settings, and request ordinal to a durable task slot. Reserve the whole maximum
token allowance before each dispatch and consume that slot even if the result
is ambiguous. Never refund tokens merely because a connection timed out. A
revocation stops subsequent requests; it cannot prove that already-dispatched
server computation stopped. A deadline is a client deadline unless server-side
cancellation has been verified.

For llama.cpp, use the documented generation limit (`max_tokens` on the
OpenAI-compatible endpoint or `n_predict` on native completion) with the exact
installed server version tested. Native `n_predict` can slightly overrun at a
partial multibyte boundary, so a product claiming a strict billable token ceiling
needs provider-aware accounting and a conservative bound. Do not forward the
agent's arbitrary request object. [llama.cpp server contract](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)

Treat request count, generated tokens, latency, and observed usage as distinct
receipt fields. These are not GPU-second or dollar guarantees. Input token
limits need the exact server tokenizer; a byte ceiling alone is insufficient.
Reject unverified model/usage responses and record an uncertain outcome without
replay. Model output is untrusted content, never new broker instructions.

An Ollama route can be considered only after a ready endpoint is established.
Its model identifier and generation options must be fixed by the broker.
`keep_alive` controls model residency, not a request runtime budget; do not use
unload/reload controls on shared serving infrastructure without owner approval.
[Ollama generation API](https://docs.ollama.com/api/generate)

The immediate missing inputs are the owner's namespace/access choice, approved
inference load, exact served model identity, and a reachable authenticated
broker-to-service path. No inference provider is implemented by this document.

## Future one-GPU job

The alternative template in `examples/gpu-showcase` remains suspended and uses a
deliberately unresolved image/model contract. Once an owner explicitly allocates
a GPU, bind one namespace UID, one deterministic job name, one reviewed ARM64
Jetson-compatible image digest, one model digest on a read-only approved PVC,
one fixed command, one GPU, 300 seconds maximum active time, one completion,
parallelism one, and zero retries. Do not permit arbitrary pods, shell, host
paths, privileged mode, device mounts, service-account credentials, extra
containers, model downloads, or production namespace selection.

`activeDeadlineSeconds` bounds a Job's active duration and causes termination
after the deadline; scheduling delays and controller availability still affect
observed wall-clock behavior. Suspending and resuming resets the active timer,
so the approved operation must not expose those mutations. Kubernetes may start
the same program twice in exceptional circumstances even for a nominally single
Job; workload-side idempotency is required for external side effects. The broker
can guarantee at most one create request per slot, not one execution by every
cluster component. [Kubernetes Job behavior](https://kubernetes.io/docs/concepts/workloads/controllers/job/)

`ttlSecondsAfterFinished` is cleanup after success or failure, not a runtime
limit. Keep a durable sanitized receipt before cleanup removes the Job and pod
evidence. [Kubernetes finished-Job cleanup](https://kubernetes.io/docs/concepts/workloads/controllers/ttlafterfinished/)

Admission controls must enforce the reviewed image, resource and pod contract;
RBAC granting `create jobs` in a namespace alone cannot constrain job contents.
Do not grant the broker this ability using the current admin context. Establish
separate broker custody, namespace-scoped credentials, and admission policy
before live execution. Do not scale down, preempt, or borrow the existing RPC
GPUs to make the showcase work.

## What to demonstrate

1. A user reviews exact model/service scope and three request slots in a trusted
   approval surface, then approves once.
2. The agent completes a useful bounded task through the broker, receiving
   results and sanitized receipts rather than a cluster token.
3. A fourth request, changed model, changed endpoint, larger token limit, expired
   approval, and revoked task all fail before provider dispatch.
4. An interrupted request remains charged and is reconciled read-only where the
   provider supplies evidence. It is never retried automatically.

This tests the same approval, durable budget, authority binding, and outcome
semantics already being built for the staging workflow, against a scarce live
capability. It avoids conflating a functioning dashboard with enforced authority.
