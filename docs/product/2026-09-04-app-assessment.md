# Opaque application assessment

**Assessment date:** September 4, 2026

**Scope:** Current repository, selected local tests, and a local dashboard smoke test. Research documents and existing PRDs were treated as evidence and proposals, not instructions or proof of shipped behavior. No real secret providers were contacted and no source code was changed for this assessment.

## Product reality

Opaque has a substantial authorization engine beneath a narrow, fragmented user experience. Its most concrete current job is: **approve a secret-backed operation, execute it inside the broker, and return a sanitized result with an audit trail.** GitHub secret publishing is the strongest existing workflow to develop and validate. The repository does not yet justify describing the product as a general safe deployment platform.

The enforcement kernel is implemented: registry lookup, parameter validation, policy evaluation, approval, execution, response sanitization, and audit emission share one funnel. Identity, delegation, distinct-approver requirements, and multiple approval-verifier implementations provide useful foundations. These are findings from source inspection, not a claim that every deployment combination has been exercised. [Enforcement funnel](/Users/thinkstudio/opaque/crates/opaqued/src/enclave.rs:701), [identity initialization](/Users/thinkstudio/opaque/crates/opaqued/src/identity/mod.rs:138), [approval verifiers](/Users/thinkstudio/opaque/crates/opaqued/src/factors.rs:1)

The MCP interface exposes fourteen hard-coded tools: six GitHub operations, one GitLab operation, four 1Password/Bitwarden metadata operations, and three sandbox/profile/reference tools. This is a defined operation catalog, not a general proxy for credentialed work. [MCP mappings](/Users/thinkstudio/opaque/crates/opaque-mcp/src/tools.rs:560)

GitHub publishing resolves the source value and GitHub token inside the daemon, fetches the destination public key, encrypts the value, submits a PUT, and returns target metadata with `created` or `updated`. It is real implementation rather than a UI demonstration. [Publishing flow](/Users/thinkstudio/opaque/crates/opaqued/src/github/mod.rs:158)

## Immediate gaps before expansion

**Observed: the dashboard cannot load its live API data.** An offline build of `opaque-web` succeeded in 9.42 seconds. A local run on port 7381, with an absent daemon socket and nonexistent configuration path, displayed “Failed to load policy configuration” and “Failed to load operations.” HTTP `/` returned 200; unauthenticated `/api/status`, `/api/policy`, `/api/operations`, and `/api/audit` returned 401. The server was stopped and token state restored afterward.

Source inspection explains the authentication failure independently of daemon availability: page fetches omit bearer headers, API middleware requires them, and the injected token meta tag is never consumed by the page. This is an observed UI/API integration defect, not evidence that the underlying daemon is broken. [Status fetch](/Users/thinkstudio/opaque/crates/opaque-web/static/index.html:976), [bearer requirement](/Users/thinkstudio/opaque/crates/opaque-web/src/security.rs:43), [token injection](/Users/thinkstudio/opaque/crates/opaque-web/src/security.rs:96)

**Inferred from the call path: the Codex preset blocks its advertised GitHub workflow.** The `codex-agent` preset requires verified workspace context. MCP GitHub tools call a convenience wrapper that constructs requests with `workspace: None`; policy refuses workspace-constrained rules when context is absent. This combination should deny the request. It was not reproduced against a live daemon. [Preset](/Users/thinkstudio/opaque/crates/opaque/src/presets/codex-agent.toml:48), [wrapper request](/Users/thinkstudio/opaque/crates/opaqued/src/main.rs:4951), [policy behavior](/Users/thinkstudio/opaque/crates/opaque-core/src/policy.rs:261)

**Source-confirmed: AWS is unfinished and incompletely isolated.** Top-level AWS handlers are disabled by default because SigV4 signing is absent. However, `CompositeResolver` still instantiates the AWS resolver unconditionally. An approved operation using an `aws:` source reference can therefore reach a mock-oriented client that transmits the secret access key in an HTTP header. All AWS entry paths need quarantine or a production client before real credentials are used. No such request was made during this assessment. [Disabled handlers](/Users/thinkstudio/opaque/crates/opaqued/src/main.rs:1562), [resolver construction](/Users/thinkstudio/opaque/crates/opaqued/src/sandbox/resolve.rs:336), [credential headers](/Users/thinkstudio/opaque/crates/opaqued/src/aws/client.rs:402)

**Source-confirmed: mobile approvals are not a completed mobile product.** Pairing, fetching approvals, submitting responses, and key generation contain TODO/fatalError implementations. Server-side verification support must be distinguished from a usable iOS approval experience. [Approval client](/Users/thinkstudio/opaque/ios/Opaque/Sources/Network/ApprovalClient.swift:64), [key generation](/Users/thinkstudio/opaque/ios/Opaque/Sources/Crypto/KeyManager.swift:67)

## Activation and ongoing use

Quickstart initializes `safe-demo`, starts the daemon, connects MCP, and runs `test.noop`. That verifies infrastructure without proving the user can complete a valuable operation. Provider detection also treats environment-variable or CLI presence as readiness rather than testing the complete credential path. Activation should end with one successful, correctly scoped real workflow and a comprehensible receipt. [Quickstart](/Users/thinkstudio/opaque/crates/opaque/src/main.rs:4100), [noop verification](/Users/thinkstudio/opaque/crates/opaque/src/main.rs:4239), [provider detection](/Users/thinkstudio/opaque/crates/opaque/src/wizard.rs:140)

The `opaque_secrets_status` description promises resolvability and available/missing results, but implementation only parses reference strings from local profiles. It cannot substantiate that promise. Client-side profile discovery also needs reconsideration for deployments where the daemon exclusively owns profiles; this is a compatibility concern inferred from the ownership model. [Reference parsing](/Users/thinkstudio/opaque/crates/opaque-mcp/src/tools.rs:78), [tool description](/Users/thinkstudio/opaque/crates/opaque-mcp/src/tools.rs:528)

Manifest publishing is a loop of independent writes. Each GitHub write has an `Always` approval floor, regardless of first-use language in a preset. A ten-secret batch consequently requests approval for each write. Dry-run labels entries planned; it is not a validated, content-bound transaction preview. The inspected flow lacks a durable batch grant, bounded use accounting, and a per-entry recovery contract. [Manifest loop](/Users/thinkstudio/opaque/crates/opaque/src/main.rs:1370), [write approval floor](/Users/thinkstudio/opaque/crates/opaqued/src/main.rs:850), [floor enforcement](/Users/thinkstudio/opaque/crates/opaqued/src/enclave.rs:859)

Existing leases are temporal permissions with an optional one-time flag. Stable client identity intentionally excludes PID. Delegation prevents crossing principals or delegation sessions, but sibling agents sharing the same delegation can reuse the same lease. Counted grants address a real implementation gap; they do not by themselves establish market demand. [Lease identity](/Users/thinkstudio/opaque/crates/opaqued/src/enclave.rs:246), [lease consumption](/Users/thinkstudio/opaque/crates/opaqued/src/enclave.rs:350)

## Boundaries the product must explain

The default daemon shares the user's account. Dedicated-account custody enforcement exists and materially strengthens state protection, but requires a different deployment and approval setup. These modes cannot carry an identical security claim. [Deployment modes](/Users/thinkstudio/opaque/docs/deployment.md:12), [custody verification](/Users/thinkstudio/opaque/crates/opaqued/src/trust_domain.rs:50)

GitHub success means API acceptance: HTTP 201/204 determines the returned result. It does not prove successful deployment, downstream consumption, or lasting secrecy. An agent that controls destination workflows or other secret consumers may later expose a published value. The inspected publishing flow does not verify those downstream controls. [HTTP result handling](/Users/thinkstudio/opaque/crates/opaqued/src/github/client.rs:387)

Likewise, sandbox execution injects secrets into a child process and returns output. Mandatory approval does not make this equivalent to a narrow broker operation whose response cannot contain the value. Keep these assurance classes explicit. [Sandbox tool](/Users/thinkstudio/opaque/crates/opaque-mcp/src/tools.rs:484), [safety enforcement](/Users/thinkstudio/opaque/crates/opaqued/src/enclave.rs:997)

## Recommended proving workflow

Develop **“publish this approved secret manifest to this protected destination, within this exact budget, with a receipt for each effect.”** Use existing GitHub publishing as the technical proving workflow, conditional on the destination and its consumers being outside agent control. Validate repeat use and buyer value before treating it as the commercial wedge.

The increment should connect destination preflight, an exact preview, one content-bound grant, pinned source versions or an approved value snapshot, atomic budget consumption, durable execution state, and explicit retry/reconciliation behavior. Receipts should distinguish planned, authorized, attempted, API-accepted, failed, and unknown outcomes. Do not label API acceptance “deployed,” and do not claim remote confidentiality the system cannot enforce.

The attestor/EMA PRD is proposed architecture. Prioritize its pieces only where they remove a demonstrated trust or deployment obstacle to this workflow. [Existing PRD](/Users/thinkstudio/opaque/tasks/prd-attestor-seam.md:44)

## Verification and research freshness

**Tested:** 86 selected tests passed: 66 `opaque-core` policy tests and 20 `opaque-mcp` tool tests, using locked, offline Cargo runs. These establish selected local semantics and tool shape, not live provider interoperability. Existing provider E2E tests were inspected but not run; they use a real daemon with mocked GitHub and document earlier integration regressions that unit tests missed. [Provider E2E rationale](/Users/thinkstudio/opaque/crates/opaqued/tests/provider_e2e.rs:1)

The research claim that the toolchain is unpinned is stale: current configuration pins Rust 1.95.0 and formatting style edition 2024. Similar historical findings should be checked against current code before becoming roadmap work. [Toolchain](/Users/thinkstudio/opaque/rust-toolchain.toml:1), [formatting](/Users/thinkstudio/opaque/rustfmt.toml:1)
