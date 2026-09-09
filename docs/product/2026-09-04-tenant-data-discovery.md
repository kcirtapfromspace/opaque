# Tenant, data, and GPU discovery — 2026-09-04

The cluster can support a synthetic integration experiment. It does not yet provide a verified tenant isolation boundary for private inference. The useful next test is two synthetic tenants, separate data/query authority, and an explicit grant to disclose a bounded result to a model. Keep execution isolation, data authorization, and model processing as separate claims.

## Scope and evidence

Read-only inspection used Kubernetes context `admin@turingpi`, selected local repository configuration, and temporary loopback port-forwarded HTTP GETs. No Secret resource was read, no data table or model file was opened, no pod command or inference POST was executed, and no cluster object was changed. Configuration references are evidence of intended wiring, not proof of stored data or authorization behavior.

| Area | Verified observation | Product implication |
|---|---|---|
| Cluster | Kubernetes server v1.35.0; three Talos v1.12.1 nodes and three Jetson Talos v1.12.6-tegra nodes. | Existing cluster is the integration target; do not change it to prove a product prototype. |
| GPUs | Each Jetson advertises one `nvidia.com/gpu`. `llamacpp-head`, `llamacpp-rpc-jetson2`, and `llamacpp-rpc-jetson3` each reserve one. | No unallocated advertised GPU was observed. A new reserved workload needs an explicit allocation decision. |
| Live Gemma | One ready `gemma4/llama-server` pod on `talos-jetson-3`, Service NodePort `30083` → `8080`. Other Gemma demo deployments are scaled to zero. | Existing server is reachable; it is a shared processor, not a new isolated GPU lease. |
| Gemma isolation | UID 0, privileged, raw GPU device hostPath mounts, host-mounted executable, writable model hostPath, default ServiceAccount token projection, no `nvidia.com/gpu` request/limit. | Do not claim private tenant isolation, immutable model identity, or exclusive GPU accounting. Use only public/synthetic inputs until an allocated service is hardened. |
| Network | `kube-flannel` v0.27.4; no separate policy controller was observed among workloads. Seven NetworkPolicies exist, all in `argocd`. Gemma has no Linkerd proxy or policy. | Policy YAML alone is insufficient evidence of blocked traffic. Require an enforcement test before tenant claims. |
| Tenant resource controls | No ResourceQuota, LimitRange, or RuntimeClass objects. Linkerd Server/AuthorizationPolicy resources occur only in `linkerd-viz`. | Tenant quotas and sandbox/runtime placement are new work. |
| Storage | Longhorn default and static StorageClasses, provisioner `driver.longhorn.io`, reclaim `Delete`; ten Bound PVCs. | Storage plumbing exists. Separate tenant volumes and lifecycle still need design and validation. |
| Data services | `umami/umami-postgres` (Postgres 15, 5 GiB PVC), `ukodus/neo4j` (Neo4j 5 Community, 5 GiB PVC), Redis. | These are application stores; no authority to repurpose their contents or credentials. |
| Analytical data | `hypothesis-validation/quant-api` mounts `market-data` (50 GiB RWO) read-only at `/data`, `QUANT_DB_PATH=/data/quant.duckdb`. Backtest results use separate 20 GiB PVCs. | DuckDB is a concrete local integration path. Presence and schema of the database were not inspected. |
| Warehouse/lakehouse | No MinIO, Iceberg, ClickHouse, Trino, Redpanda, or Kafka workload/service/operator CRD was observed in cluster inventory, nor a matching running local Docker container. | Do not promise an existing shared warehouse. External/unmanaged services remain unknown. |
| Identity | Argo Dex v2.43.0 is running. Selected live `argocd-cm` metadata shows a GitHub connector and no `oidc.config`; Argo URL is `https://argocd.tail16ecc2.ts.net`. No Keycloak or Authentik workload was observed. | Argo login is not proof of an Opaque OAuth audience, tenant claims, delegated data scopes, or revocation. Register and validate those explicitly. |

Flannel's own documentation says the `flanneld` binary does not enforce NetworkPolicy; a policy controller can be added. No traffic-denial probe was run, so the cluster's effective enforcement is unverified. [Flannel network policy documentation](https://github.com/flannel-io/flannel#network-policy).

The local kubectl client is v1.37.0 and reports unsupported version skew against server v1.35.0. Discovery reads succeeded; use a supported client version for subsequent operational validation.

## Live model identity and API compatibility

GETs used `kubectl --context admin@turingpi port-forward -n gemma4 service/llama-server 19680:8080 --address 127.0.0.1`. No inference or tokenizer POST was sent.

| Evidence | Result |
|---|---|
| `/health` | HTTP 200, `{"status":"ok"}` |
| `/v1/models` | HTTP 200; OpenAI-shaped `data` list plus a `models` list |
| Model ID / alias | `gemma-4-E2B-it-Q3_K_M.gguf`; owner `llamacpp`; completion capability |
| Advertised metadata | GGUF, 4,647,450,147 parameters, 2,520,965,260 bytes; vocabulary 262,144; training context 131,072 |
| `/props` | HTTP 200; build `b1-268d61e`, one slot; vision/audio false; model path `/models/gemma-4-E2B-it-Q3_K_M.gguf` |
| Deployment settings | Context 2048, parallel 1, reasoning budget 0, GPU layers 99; CPU limit 4, memory limit 7 GiB |
| `/version`, `/openapi.json`, `/tokenize` GET | HTTP 404; this does not establish whether POST tokenizer/inference routes exist |
| Model weight digest | Empty in `/v1/models`; unverified |
| Runtime container digest | `sha256:ae30dbf9e8cd03535f2e5c9c44a2b2a59a49cb5c77204841eecfa9d701db8c9d` |
| Executable custody | `/cuda-build` mounted from `/var/lib/cliniq/llama-build` read-only inside the pod |
| Weight custody | `/models` mounted writable from `/var/lib/ollama/models` |

The container digest does **not** pin the host-mounted executable or weights. `b1-268d61e` is reported build metadata, not verified artifact provenance. Do not promote the basename to a model revision. The provider must report missing model hash honestly and keep this endpoint synthetic-only. Chat-completion compatibility, exact tokenizer accounting, cancellation behavior, cache separation, retention, and idempotency remain untested.

## Existing configuration and reconciliation

Argo Applications predominantly reference `kcirtapfromspace/think_talos_k8s`, with separate Ukodus/blog repositories. No Gemma or hypothesis-validation Application appeared in the inventory, and their inspected Deployments had no Argo tracking ID. This is evidence of missing visible ownership, not proof that no external reconciler exists. At inspection, `linkerd-control-plane` was OutOfSync/Healthy, `monitoring` Synced/Progressing, and `umami` Unknown/Healthy.

Relevant local evidence:

- [Gemma deployment](/Users/thinkstudio/gemma4/apps/llama-server/deployment.yaml) and [Gemma deployment variant](/Users/thinkstudio/gemma4/apps/llama-server/deployment-spec.yaml): model-serving configuration; live metadata takes precedence.
- [Quant platform README](/Users/thinkstudio/quant-platform/README.md): describes MinIO for parquet/artifacts and DuckDB for OLAP; this is repository intent, not a verified deployed MinIO.
- [Quant API deployment](/Users/thinkstudio/quant-platform/k8s/hypothesis-validation/deployment-quant-api.yaml): read-only DuckDB mount and a credential reference; credential values were not inspected.
- [Argo public login wiring](/Users/thinkstudio/think_talos_k8s/infra/argocd/expose/argocd-cm-patch.yaml): GitHub OAuth connector references.
- [Flannel IPAM maintenance](/Users/thinkstudio/think_talos_k8s/infra/cni-ipam-gc/README.md): explains the installed Flannel maintenance workload.

Expired Opaque work must not remain as a desired running Job in an Argo Application. Reconciliation should own static broker/service infrastructure; a lease controller must enforce deadline, revoke execution, record cleanup, and prevent recreation from stale desired state. Kubernetes Job cleanup alone is not a lease or revocation authority.

## ArcBox feasibility on this host

The host reports Apple M1 Ultra and macOS 26.5.2. `arcbox` and `abctl` were not on PATH; standard ArcBox app and `~/.arcbox` paths were absent. This is a bounded installation check, not an exhaustive filesystem scan. Docker remains on `desktop-linux` (server 29.2.0); `podman` is installed. No runtime was installed, started, or switched.

ArcBox documents separate Firecracker microVM kernels for sandboxes, whereas ordinary containers share its System VM kernel. Its local sandbox requires Apple M3 or newer, macOS 15+, and the Virtualization.framework backend. This M1 host cannot run that documented local sandbox mode. [ArcBox security](https://arcbox.dev/docs/core/security), [ArcBox sandbox requirements](https://arcbox.dev/docs/core/sandbox).

A Docker fixture here can test separate processes, mounts, identities, and network reachability. Label that evidence **container isolation**, not ArcBox microVM isolation or TEE attestation. A later supported sandbox host is a distinct acceptance gate. Even a microVM does not authorize a data read or prevent an approved remote model from seeing disclosed input.

## Proposed two-tenant synthetic test

Use neutral tenants `synthetic-a` and `synthetic-b` until the user defines the real tenant unit. Give each distinct input records, a separate source volume or database, separate output storage, a distinct authenticated subject and policy, and a private canary. No real repository, customer, clinical, or market dataset is required.

| Boundary | Proposed responsibility | Required negative test |
|---|---|---|
| Execution | Separate sandbox per tenant/task, immutable rootfs, bounded CPU/memory/time, no host home or broker/data credential mounts; network only to the authorized gateway. | Tenant A cannot read B's filesystem, broker state, provider credentials, container socket, or unrestricted network. |
| Identity and policy | Verify OAuth issuer, audience, signature, expiry and server-controlled tenant membership. Resolve opaque dataset handles through broker policy; agent-supplied `tenant_id` is not authority. | Wrong audience/tenant, expired or revoked delegation, and a forged tenant parameter fail before opening a data connection. |
| Data/query worker | Separate trusted worker and source credential for each tenant; approved dataset snapshot, template/query identity, bounded rows/bytes and result destination. For the first fixture, separate read-only synthetic files/DuckDB databases are sufficient. | A cannot request B's handle, path, object prefix, SQL connection, external URL, `ATTACH`, extension, arbitrary file reader, or unbounded export. |
| Model processor | Explicit disclosure grant binds the allowed result/input hash, model identity/evidence level, endpoint, output ceiling, deadline and tenant output location. The provider is a trusted recipient of that input. | Data-read approval alone cannot send data to a model. Endpoint changes, extra input, excess output, replay and a second attempt consume no new unauthorized capability. |
| Receipt and lifecycle | Persist reserved attempts before dispatch; record accepted/unknown provider outcomes separately from result evidence; hash/tenant scope metadata rather than data contents. Expiry cancels remaining work and cleans ephemeral storage. | Restart/replay creates no second inference; unknown result does not auto-retry; TTL cleanup is observed and a reconciler does not recreate expired work. |

For lakehouse expansion, add an S3-compatible object store with separate tenant credentials and object namespaces plus a trusted query worker. A bucket prefix or SQL `WHERE tenant_id = ...` alone is not an isolation boundary. Keep the source abstraction small: a server-side dataset handle resolves to a pinned snapshot, permitted read, and result destination. OAuth should govern that mapping, rather than pass broad source credentials into an agent runtime.

The first cluster test remains a separately authorized **public/synthetic** request to the existing Gemma service. Private tenant prompts require a hardened, allocated processor and verified network controls. The fixture can validate authorization and cross-tenant denial locally before that cluster gate.

## Open decisions and completion gates

1. Define a tenant: customer organization, internal team, repository, or workspace; define whether source owners and model recipients are the same party.
2. Select the first data surface: synthetic files/DuckDB, a new disposable S3 service, or an explicitly approved existing source. Existing application databases are outside scope.
3. Select a trusted OAuth issuer/audience and enrollment flow. Existing Argo GitHub login does not establish these contracts.
4. Allocate a GPU/time window and identify a processor that can meet the intended privacy claim. Current metadata does not show spare reserved GPU capacity.
5. Verify source credential separation, cross-tenant data and network denial, budget/replay/expiry handling, no plaintext in receipts, and cleanup. Run these with disposable canaries before admitting private data.
6. Demonstrate microVM isolation on supported hardware separately from local Docker evidence; obtain model weight/executable provenance separately from HTTP aliases.

Design-only fixture inputs are in [examples/tenant-inference](/Users/thinkstudio/opaque/examples/tenant-inference/README.md). They are not Kubernetes manifests and have not been applied.
