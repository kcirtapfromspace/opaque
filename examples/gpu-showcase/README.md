# GPU showcase proposals — not installed

These files describe a possible next provider. They are not supported Opaque
task manifests and were not applied to the cluster. No inference was run and no
GPU was allocated. See the [read-only assessment](../../docs/product/2026-09-04-gpu-showcase.md).

`existing-inference.contract.json` proposes three serial calls to the ready
Gemma service after owner approval and identity verification. It records bounds
that a future typed provider must enforce; it does not grant access.

`future-job.template.yml` deliberately has `suspend: true`, an unresolved image
digest, and a proposed namespace/PVC. It is a deployment sketch, not a runnable
workload. Before activation, the owner must allocate a GPU, provide a reviewed
ARM64 Jetson-compatible smoke-test image with the fixed entrypoint, provision a
read-only model PVC, verify model digest, and approve the namespace and admission
policy. None of those resources is provisioned here. Do not use the admin
context for a broker runtime, mutate the template into a generic command runner,
or borrow GPUs from existing workloads.

The Job's 300-second active deadline is separate from its 300-second cleanup
TTL. Zero retries and one parallel pod reduce repeat work, but do not establish
exactly-once execution. The broker must durably consume a deterministic create
slot before dispatch and never re-create an ambiguous job. External side
effects require workload-side idempotency.
