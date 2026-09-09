# Tenant inference design fixture

This directory records the disposable two-tenant test and the wider data-boundary design. It does not authorize access to a live data source. The current host can exercise separate Docker processes/mounts/networks; it cannot satisfy ArcBox's documented M3+ local Firecracker requirement.

`boundary-plan.yaml` intentionally uses a design schema so it cannot be mistaken for a supported task API or applied to Kubernetes. Real source connectors, OAuth issuer, model provenance, and budget fields must be supplied by the implemented provider contract and trusted operator configuration.

The intended flow is authenticated tenant → broker policy → isolated tenant query worker → bounded synthetic result → explicit model disclosure grant → trusted model provider → tenant-scoped output receipt. The agent receives no source/provider credential. The receipt distinguishes permission, reserved attempt, provider outcome, and verified result.

Before running any cluster request, resolve the gates in [the discovery note](/Users/thinkstudio/opaque/docs/product/2026-09-04-tenant-data-discovery.md). No existing Gemma deployment, GPU reservation, Argo application, or application database is changed by these design files.

## Running the local fixture

From the Opaque repository:

```sh
python3 -B scripts/tenant_dogfood.py --check
python3 -B scripts/tenant_dogfood.py --serve --no-build
```

The script uses the same existing Docker Rust/runtime image cache and `opaque-linux-target` build volume as release dogfood. It does not change Docker context, install a runtime, modify `HOME`, or use production credentials. `--no-build` copies existing Linux binaries; omit it after source changes. Docker and OpenSSL with Ed25519 support are required. Every invocation requires fresh state. `--data-dir` selects an empty disposable directory.

Default dashboards are `http://127.0.0.1:19394` and `http://127.0.0.1:19396`; workstation approval TLS ports are 19444 and 19445. Existing dogfood ports 19392/19393 are untouched. The script prints its state path and tenant agent names. Ctrl-C stops its containers and networks; evidence and tenant state/socket volumes remain. Each tenant directory includes a precise volume cleanup command.

Host access uses a loopback TCP relay over local Docker exec stdio because Docker Desktop does not publish these internal-network ports. Approval TLS passes through unchanged and the signer checks its certificate pin. The relay exposes only fixed dashboard/approval destinations; agents receive neither Docker API access nor a provider network route. Login/delegation credentials last one hour, and new task grants expire after ten minutes.

The model is a strict HTTP stub. It accepts only the provider's three compiled public prompts and fixed tokenizer/completion shape. Successful results are synthetic tenant-labeled text. It does not load a model, reserve a GPU, or prove model accuracy. Both tenants intentionally use the same public source snapshot; tenant/profile/broker authority and output destinations differ. Arbitrary tenant datasets and a warehouse query worker are still design work.

## What the fixture exercises

- Separate broker OS UIDs (7481/7491), agent UIDs (7482/7492), socket groups, named volumes, and internal Docker networks. Agents have their own PID namespaces and cannot mount another tenant's state. A public canary binds each provider's network interface on port 18914: a positive HTTP probe from the provider/broker namespace proves it is reachable before both agents are denied access to both canaries. This tests the network boundary independently of the model's loopback binding.
- The existing OIDC authorization-code flow: nonce, PKCE, RS256/JWKS validation and a sealed exact subject allowlist. The test issuer uses the repository's public test RSA key and simulates the browser callback. A valid signature with a foreign subject or wrong nonce must fail. This is protocol evidence, not production OAuth enrollment or an actual human login.
- Delegated agent credentials issued by the real broker after a separately signed workstation approval. The signer private key remains on the host in its tenant approver directory, never mounted in broker or agent. All approvals are conspicuously `insecure_test`; no human consent is requested.
- Three generation attempts per task, 512 input tokens and 96 reserved output tokens per attempt, a 30-second request deadline, and fixed sampling/cache settings. Observed token usage never refunds reserved allowance. Replay cannot produce a fourth completion; unknown transport consumes the attempted slot and stops later attempts.
- Cross-tenant task IDs, another broker's delegation, and changed tenant/broker/profile/source/model authority fail. Receipts and dashboard data remain scoped to the authenticated owner. MCP reads receipts and cannot replay a completed task. A broker restart preserves receipts and does not generate again.

## Linux login-driver limitation

The existing daemon identifies a human client by inspecting its executable. Across different Linux UIDs this requires `/proc` ptrace access. The fixture first attempts classification without capabilities. If that fails, a short root launcher drops to the tenant broker UID and retains only `CAP_SYS_PTRACE` in the broker's private PID namespace, shared only with that tenant's fixed login-driver container. The daemon's effective UID and capability set are checked. Host PIDs, the other tenant, and agent PIDs are not shared. This is a documented fixture accommodation, not an extra production authorization rule.

Container isolation still shares the Docker Linux kernel. It does not establish ArcBox microVM isolation, confidential computing, private-model processing, or cross-tenant storage authorization in a real warehouse. Keep those claims separate from the verified broker/credential boundaries.

## Verified local run: 2026-09-04

The retained run used `python3 -B scripts/tenant_dogfood.py --serve --no-build` after building the current Linux binaries. State and JSON evidence are in `/private/tmp/otf-x1fwo4vx`. The runner keeps both tenant fixtures and test signers alive; dashboards are read-only.

| Tenant | Dashboard | Agent container | Completed task |
| --- | --- | --- | --- |
| synthetic-a | http://127.0.0.1:19394 | opaque-tenant-54df4c6ec92b-agent | debdb25a-a0f8-41d7-95b1-1f628253d623 |
| synthetic-b | http://127.0.0.1:19396 | opaque-tenant-9118a38235d5-agent | b3db90e6-f337-48c4-b68c-bb5aeff8572b |

`summary.json` records the passed run, tenant broker bindings, agent names, and request counts; `live-summary.json` also records the unknown and initially planned task IDs. Each tenant's directory contains `completed-receipt.json`, `unknown-receipt.json`, `custody-evidence.json`, `network-canary-evidence.json`, `mcp-evidence.json`, `restart-evidence.json`, and `dashboard-evidence.json`. `binary-digests.json` identifies the executed binaries. A later mobile layout fix rebuilt only `opaque-web` and restarted only the two dashboard processes; `web-update-evidence.json` records binary/source hashes and unchanged request counts. `network-canary-helper-evidence.json` in each tenant directory verifies the shipped probe helpers against the independently started live canaries without restarting brokers or generating model output.

The check recorded exactly four model-stub completion requests per tenant: three successful requests and one HTTP 500 whose allowance remained consumed. Completed-task replay, unknown-task retry, MCP replay, cross-tenant probes, and broker restart produced no additional completions. The positive-control canary check also left those counts unchanged. All receipt approvals are `insecure_test`.

Initial planned grants expire ten minutes after creation. While the one-hour login/delegation remains valid, create another bounded task through the agent's existing private session helper:

```sh
docker exec opaque-tenant-54df4c6ec92b-agent python3 /scripts/tenant_dogfood.py _cli task plan-inference --title 'Synthetic A dogfood' --expires-in-secs 600
docker exec opaque-tenant-54df4c6ec92b-agent python3 /scripts/tenant_dogfood.py _cli task run TASK_ID_FROM_PLAN
docker exec opaque-tenant-54df4c6ec92b-agent python3 /scripts/tenant_dogfood.py _cli task show TASK_ID_FROM_PLAN
```

For synthetic-b, substitute `opaque-tenant-9118a38235d5-agent`. The helper reads only its agent's mode-0600 `/tmp/tenant-session.json` and passes the delegated credential to the CLI via the child environment. It does not print the token or place it in arguments. Run the agent MCP endpoint with:

```sh
docker exec -i opaque-tenant-54df4c6ec92b-agent python3 /scripts/tenant_dogfood.py _mcp
```

Executing a fresh task obtains another automated test approval and adds three synthetic completion requests. Planning alone grants no authority and makes no completion request. After the login/delegation expires, stop the current runner and start a fresh disposable `--serve --no-build` run; the harness deliberately does not silently renew authority. Retained completed and unknown receipts remain inspectable as evidence files. No live Kubernetes inference, GPU allocation, warehouse query, human approval, or production OAuth connection was performed.
