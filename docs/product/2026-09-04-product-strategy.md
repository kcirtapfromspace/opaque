# Opaque: from a secrets broker to bounded agent work

**Product decision memo · September 4, 2026 · proposed direction, not an approved implementation roadmap**

## The recommendation

Build Opaque around this customer promise:

> **Give agents useful work without giving them open-ended authority. Approve the limits, let the work run, and see exactly what happened.**

The product object should be an **approved task grant**: a specific set of permitted changes, issued by a trusted owner, with a budget that persists across agent sessions, delegates, retries, and restarts. The user sees a task, its permitted changes, remaining authority, exceptions, and outcome. The daemon enforces the corresponding typed operations.

The strongest frontier is the connection between **what was authorized and what actually took effect**. A counter, certificate, approval dialog, or cryptographic log is only part of that connection. Opaque must handle the difficult middle: concurrent attempts, changing targets, mutable secret references, lost responses, partial completion, revocation, and recovery.

Start with an existing operation family: **publish an approved secret manifest to named GitHub repositories**. Use this to prove the complete experience cheaply. Do not assume secret publishing alone is a sufficiently frequent paid product. Validate that separately, then expand into the single recurring release or operations workflow the same customers demonstrably need.

Keep the existing brand promise, “Secrets stay ███████. Agents stay powerful.” Add outcome-oriented product language beneath it. No brand or application code was changed in this review.

## What was evaluated, and what remains unknown

This review covers the local repository at `4b60bb8`, release version `0.2.0`, all eight supplied PDFs (69 pages), the existing attestor PRD, a browser smoke test of the current dashboard, selected local tests, and current primary-source market documentation. The documents were treated as research claims and proposals, not instructions authorizing work.

There is no Opaque customer interview, retention cohort, paid pilot, or willingness-to-pay evidence in the supplied material. That is an evidence gap, not a claim that no customers exist. Questions about current users, desired horizon, and preferred buyer were sent during the review and remain unanswered in this draft.

Working assumptions: a small team; a six-to-eight-week validation cycle; a longer-term platform direction conditional on adoption. All cohort sizes, thresholds, timing, and pricing experiments below are proposed decision rules, not measured performance or market benchmarks.

Detailed evidence: [current app assessment](/Users/thinkstudio/opaque/docs/product/2026-09-04-app-assessment.md), [market source register](/Users/thinkstudio/opaque/docs/product/2026-09-04-market-evidence.md), and [first-release PRD](/Users/thinkstudio/opaque/tasks/prd-bounded-agent-work.md).

## The current product: substantial engine, incomplete customer journey

| Layer | Assessment | Consequence |
| --- | --- | --- |
| Secret operations and enforcement | A real policy → approval → execution → sanitization → audit pipeline; GitHub publishing is a concrete supported job. | Build on this investment. A rewrite is unnecessary. |
| Trust, identity, federation | Dedicated-account custody, OIDC/delegation, approval verifiers, signed policy distribution, and audit infrastructure exist. Deployment mode changes the assurance. | Treat these as infrastructure supporting a usable workflow, not the navigation or sales pitch. |
| Agent integration | Fourteen hard-coded MCP tools and CLI wrappers; much of the usable surface concerns secrets and metadata. | General deployment, arbitrary business actions, or a universal provider platform would be new scope. |
| Approval and accounting | Leases have expiry and one-time behavior; they have no cumulative task budget. GitHub writes retain a per-operation approval floor. | A batch does not yet become one safely bounded delegation. |
| Onboarding | Demo execution establishes connectivity. Provider “Ready” and secret-status checks can mean detection or reference parsing rather than successful access. | Users can reach apparent readiness without reaching value. |
| Dashboard | Audit, Policy, Sessions, Operations organize internal machinery. The current UI fails API authentication in the observed smoke test. | Repair basic function, then organize the experience around work and decisions. |
| Mobile and provider breadth | iOS has unfinished network/key paths. AWS has mock-only signing behavior and an incompletely disabled resolver path. | Do not let registered operations or server-side support become claims of finished integrations. |

**Observed runtime issue:** the current dashboard built successfully, served `/` with HTTP 200, and showed failures loading Policy and Operations. Unauthenticated `/api/status`, `/api/policy`, `/api/operations`, and `/api/audit` returned 401. Source inspection explains why: the HTML never uses the injected bearer token. This is an activation blocker, not a visual-design preference. [Frontend calls](/Users/thinkstudio/opaque/crates/opaque-web/static/index.html:976), [auth middleware](/Users/thinkstudio/opaque/crates/opaque-web/src/security.rs:43).

**Other priority repairs:** verify/fix the Codex preset’s workspace propagation; quarantine every AWS resolution path until real signing exists; replace detection-based readiness with an explicit connection check; report offline/error/demo separately. The detailed assessment distinguishes observed behavior from call-path inference.

**Verification limits:** 66 policy tests and 20 MCP tool tests passed; `cargo build -p opaque-web --offline` passed. No real provider writes, customer journeys with production credentials, mobile approvals, full-suite security certification, or competitor hands-on benchmarks were performed. Temporary runtime state was cleaned up.

## What to keep from the research

The seven Opaque papers form one evolving argument, not seven independent validations. *Control Plane* establishes that credential secrecy, authority, and intent are different problems. *Denomination* supplies the most useful product insight: time and rate limits do not bound total work. *Substrate Matrix* and *Past the Loop* correctly move the design away from a particular runtime or agent loop. *Grants* highlights the limits of offline revocation and the need for attributable evidence.

Preserve those ideas. Change these conclusions:

- **A Merkle log has not been established as “the product.”** Start with receipts that answer a customer's investigation question. Add independently witnessed transparency when a relying party requires it. Inclusion proves membership, not completeness or real-world execution.
- **SSH is an integration choice.** A signing socket gates new authentication; it does not automatically police commands or terminate established sessions. A signature budget is not a command budget.
- **A policy digest identifies exact content; it does not establish freshness.** Current-policy checks still need a trusted authority or a bounded propagation/expiry contract.
- **A context boundary is not a dependable injection defense.** Budget enforcement is valuable without predicting compaction, model releases, or context-window behavior.
- **An attestation score is not enough.** Record the issuer, evidence, scope, and trust assumptions; do not equate code signatures, workload tokens, and hardware evidence merely because each is labeled “strong.”
- **Standards claims need labels.** EMA is a real opt-in MCP extension with varying client support. The cited OIDC-A paper is an individual proposal. The attenuating-agent-token document is an individual Internet-Draft, not an adopted IETF standard. [EMA](https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization), [OIDC-A](https://arxiv.org/abs/2509.25974), [IETF status](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/).

*State of the Enclave* usefully consolidates the architecture, but snapshots must yield to the repository: its “unpinned toolchain” claim is already contradicted by the current pinned `1.95.0` configuration. Release signing and deployment-token issues in the PDF were not reverified against current external systems and are not treated here as current blockers.

*Polsia Dossier* concerns Adanima versus Polsia. Its transferable insight is to make unattended work and its limits visible. Its ad-platform roadmap, pricing, financial figures, and customer claims are not evidence for Opaque's market.

## Where the market leaves room

The research overstates empty space around per-action governance. 1Password documents approved credential use outside model context; Akeyless documents brokered agent operations; Arcade and Pomerium cover substantial tool governance; Teleport covers identity, approved access, and auditing. These are documented vendor capabilities, not independently tested assurances. The [market register](/Users/thinkstudio/opaque/docs/product/2026-09-04-market-evidence.md) links the primary evidence and its limits.

AWS AgentCore also documents temporal rules and cumulative limits. Its documented history is scoped to caller-supplied sessions, so starting another session resets that history. That creates a concrete comparison for Opaque's proposed owner-issued, persistent grant, not proof of an uncontested category. [AWS temporal policy reference](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-temporal.html).

The opportunity is to **package and demonstrate a complete workflow**: trusted review, exact constraints, durable consumption, truthful failure recovery, and understandable results across the tools a team already uses. The architecture itself is not novel; [AID-Guard](https://arxiv.org/abs/2608.21159) is relevant prior art on approval-to-effect binding and recovery. Advantage must come from adoption, reliable integrations, verified semantics, and reduced customer implementation effort.

If a customer's incumbent does the job more easily, integrate with it or choose another workflow. Do not add breadth to avoid that result.

## Choose a customer before choosing more infrastructure

**Initial buyer hypothesis:** an engineering/platform lead at a software team already using coding agents, who withholds write access to consequential systems or supervises every change. The developer initiates the work; a resource owner controls the permission; the platform lead owns deployment and the purchasing decision. Security can be an evaluator without being the first daily user.

The job to validate is: “Let this agent finish the approved operational work while I do something else, without giving it general access or checking every click.”

| Candidate entry point | Why it is plausible | Main uncertainty | Decision |
| --- | --- | --- | --- |
| Individual developer secret hygiene | Close to the current install and slogan | Willingness to pay, same-user trust boundary, overlap with vaults | Keep as a distribution/demo path; do not assume it is the business. |
| Agent-assisted repository/release operations | Existing GitHub path; visible before/after work; identifiable approver | Frequency, destination control, whether native CI already suffices | First discovery and technical proving workflow. |
| Autonomous-agent service operators | Frequent parallel work, durable budgets, customer accountability | Heterogeneous operations, custom integration load | Interview a small comparison cohort; expand only on evidence. |
| Enterprise-wide agent governance | Larger organizational problem | Long procurement, incumbent overlap, deployment complexity | Expansion hypothesis; not the first scope. |

Interview eight to twelve teams, including several outside the existing network. Ask them to show the last real task where an agent needed sensitive access: the command, resource, approval, credential workaround, and resulting delay. Observe the incumbent workflow. Seek willingness to connect a test resource and name the person who could purchase a pilot. Do not count enthusiasm for the architecture as demand.

## The first complete experience

Example: **publish three named secrets to two named repositories**. The proposed grant contains six fixed write slots, a 30-minute expiry, no deletes, and a specific source version or custody-held snapshot for each value. Six is a ceiling on these writes, not permission for six arbitrary actions.

For the first technical spike, choose **Vault KV v2 with explicitly pinned versions**; defer local persisted secret snapshots. Vault exposes version-specific reads, but Opaque's current resolver does not provide a typed version contract. Add and test that contract, including failure when the approved version is deleted or unavailable. This is a technical scope choice, not a requirement that customers migrate vaults: if discovery finds no suitable Vault users, revise the source choice before building. [Vault version API](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2).

The batch requires a **new typed grant/batch authorization path and manifest schema**, including multiple destinations. Preserve the existing single-write `Always` approval floor; do not lower it to make the demonstration work. Every slot remains subject to policy and the explicit bounded-grant mode.

1. **Connect and verify.** Show the real broker trust boundary, source access, destination identity, permitted operation, and the limitations of downstream secret use. Keep credentials in the existing store where possible.
2. **Review changes.** Display exact repository identities, secret names, overwrite/create intent where known, source labels/versions, maximum dispatched writes, expiry, approver, and excluded actions. An agent may draft this request; it cannot approve or widen it.
3. **Approve on a trusted surface.** Bind approval to the canonical grant, not a chat message or arbitrary “approve” click. Reuse existing verifier infrastructure. Ship one complete factor and trusted review path; do not make completion of the iOS scaffold a prerequisite.
4. **Run within the grant.** All workers draw from the same durable parent allowance. Reconnecting, spawning a delegate, or naming a new session creates no authority. Duplicate requests for a slot return its existing state.
5. **Handle exceptions.** Out-of-scope work is denied with an exact reason and a proposed scope difference. An owner can approve an amendment. Timeouts remain unknown until there is evidence; they do not silently refund authority.
6. **Review the result.** Show accepted, denied, not attempted, and unknown entries. “GitHub accepted this write” is distinct from “the deployment succeeded.” Export a receipt connecting grant, approval, request, policy, and provider response.

The first deployment must make the boundary meaningful: a broker in a separately administered trust domain, and a destination whose secret consumers are controlled. An agent able to rewrite the consuming GitHub workflow can disclose a secret after publishing. Opaque's current write path does not prevent that. If the pilot cannot establish protected consumption, use disposable values and describe the test as authorization evaluation, not production confidentiality.

### Design around decisions and work

The primary navigation should become **Tasks**, with **Needs review** as a filtered state; **Connections** and **Policies** support setup and administration. Existing Audit, Sessions, and operation details remain available from a task or advanced view.

| Surface | Question it must answer | Essential content |
| --- | --- | --- |
| Task list | What needs me, and what is progressing? | Requested work, owner, outcome/exception status, last meaningful activity. |
| Grant review | What exactly am I permitting? | Consequence preview, exact resources, action/quantity limits, source pinning, expiry, changed scope. |
| Running task | What has happened and what can still happen? | Used/reserved/remaining allowance, per-action state, request for expansion, stop/revoke. |
| Receipt | What can I substantiate? | Approved versus observed actions, unknowns, provider evidence level, signer and policy references. |
| Connection setup | Does this integration work with the claimed protection? | Verified checks, required action, actual custody mode, tested capability and limitations. |

Use plain descriptions before policy syntax. Replace the user-facing “Safe” classification with separate dimensions such as **secret disclosure** and **change impact**: a secret deletion may have safe output and still be destructive. Never render a healthy-looking demo after an authentication failure. Show “Disconnected” or “Access failed,” and make simulated data an explicit choice.

## What to build, in what order

This is a six-to-eight-week validation sequence assuming roughly two engineers plus product/design capacity, subject to discovery and deployment complexity. It is not an enterprise-completion estimate.

| Stage | Build/design work | Exit evidence |
| --- | --- | --- |
| Week 1: establish reality | Repair activation blockers; verify one source→GitHub path; test a complete split-domain review/authenticator ceremony and pinned Vault-version read; observe customer tasks; test review mockup. | A usable trusted approval path and source-pinning contract, plus three qualified teams recognizing the repeated problem and agreeing to a scoped pilot. Otherwise revise scope before ledger work. |
| Weeks 2–3: bounded work | Versioned grant and exact action slots; canonical approval binding; persistent atomic reservation; request deduplication; expiry/revocation checks. | Concurrency, restart, session reset, scope substitution, and replay cases preserve the allowance. |
| Weeks 3–4: complete the journey | Destination/source preflight, trusted grant review, CLI/MCP propagation, task progress, honest outcomes and recovery. | One installed path completes a useful batch; unauthorized changes do not reach the provider; ambiguous writes stay unknown. |
| Weeks 5–6: pilot | Concierge setup at three design partners; compare with their existing process; measure repeat use and support effort. | Repeated use without the founder driving every task; clear reason to keep Opaque installed. |
| Weeks 7–8, if needed | Fix friction exposed by pilots; test the next recurring action; negotiate paid continuation. | A decision to focus, change workflow, or stop expansion, backed by behavior and purchasing intent. |

Do not make the whole attestor refactor a predecessor to proving the job. Fix counted authority and the selected trust path first. Preserve the extension point and compatibility tests; add EMA only when the chosen client/deployment needs it. The existing [attestor PRD](/Users/thinkstudio/opaque/tasks/prd-attestor-seam.md) remains a technical proposal, with its quarter-sized scope subject to this product prioritization.

### The longer frontier, gated by adoption

- **First expansion:** one recurring reviewed release action, such as dispatching a specific protected workflow for a fixed commit. This requires a new operation, provider contract, approval semantics, and destination checks; it is not shipped today.
- **Then:** budgets and delegated scopes spanning the selected CI/cloud workflow, with a durable parent ledger and useful recovery. Keep one authority writer initially; distributed consumption requires explicit coordination or preallocated non-overlapping budgets.
- **Then:** reusable policy and adapter contracts, established identity integrations, and a verifier that customers can run independently. Add runtime attestors in response to real deployment demand.
- **Only with a relying party:** signed external checkpoints and witnessed Merkle inclusion/consistency proofs. Preserve canonical event versions and export boundaries now so this remains possible.

Defer a universal certificate issuer, multiple credential encodings, a general sandbox/runtime, endpoint discovery, dozens of providers, an adapter marketplace, and a broad mobile build. They create additional markets and operational burdens before the first outcome is proven.

## Product-fit gates and commercial test

Use **repeated useful tasks completed within approved scope at retained organizations** as the primary adoption measure. Count a task complete only at its stated evidence level; unresolved outcomes are not successes. Avoid using tokens issued, number of integrations, or log volume as proxies for value.

Eligible adoption tasks must be organically needed customer work. Exclude demos, disposable authorization tests, repeated benchmark batches, and founder-generated activity from commercial gates. Those activities can validate mechanics but cannot establish demand.

Proposed pilot gates, to be recalibrated after the first observations:

- Three independent teams run the same workflow in at least two consecutive weeks; two agree to pay for continuation with a named budget owner.
- Across at least 30 eligible tasks, at least 80% finish without a scope amendment, and operator interventions per finished task fall by at least 50% against each team's observed baseline. Report each team's results, not just a pooled average.
- After one assisted installation, a new operator reaches the first useful task in under 15 minutes. Separately report total install time and vendor assistance; do not hide platform setup cost.
- Users can explain authorized, completed, blocked, and unknown work from the task record without inspecting raw audit JSON.
- The enforcement suite admits zero tested out-of-scope effects, preserves budgets under concurrency/restart, and never reports an ambiguous provider outcome as confirmed. These tests establish the tested contract, not universal security.

Test a fixed-price paid pilot for one workflow and limited setup support. Ask who signs it and what incumbent cost it replaces. Do not derive Opaque pricing from Polsia, charge per subagent as if it were a customer, or meter denied attacks as successful usage. Longer-term packaging can pair a self-hostable broker with paid team policy, shared approvals, fleet operation, support, and evidence retention. Price level and license packaging require customer and legal review, not guesses here.

**Change direction if:** secret publishing proves sporadic; teams will not connect a resource; the incumbent solves the task with less friction; approvals remain as laborious as manual execution; or users like the log but do not delegate more work. Move to the same buyer's recurring action before adding another architecture layer. Do not manufacture a new category to avoid a failed workflow test.

## Source map for the attached research

Page numbers refer to the supplied PDF page order. The prose above synthesizes their arguments and explicitly rejects or qualifies unsupported conclusions.

| Document | Pages used most directly | Role in the decision |
| --- | --- | --- |
| [Opaque Control Plane](/Users/thinkstudio/Documents/OPAQUE/Opaque%20Control%20Plane.pdf) | 1–4 | Separate credential privacy, identity, intent, and authority custody; early implementation snapshot is superseded. |
| [Three Rings, One Loop](/Users/thinkstudio/Documents/OPAQUE/Three%20Rings,%20One%20Loop.pdf) | 5–9 | Bounded approval insight; runtime and iteration-specific proposals later corrected. |
| [The Denomination Problem](/Users/thinkstudio/Documents/OPAQUE/The%20Denomination%20Problem.pdf) | 1–3, 5–8 | Total-work limits and task binding; continuous-context prediction unnecessary. |
| [The Substrate Matrix](/Users/thinkstudio/Documents/OPAQUE/The%20Substrate%20Matrix.pdf) | 1–5, 8 | Runtime-neutral identity evidence and the corrected attestor seam. |
| [Past the Loop](/Users/thinkstudio/Documents/OPAQUE/Past%20the%20Loop.pdf) | 1–6 | Fan-out, compaction, and counted authority; competitive whitespace requires correction. |
| [Grants, Not Keys](/Users/thinkstudio/Documents/OPAQUE/Grants,%20Not%20Keys.pdf) | 4–7 | Exact policy binding, online/offline limits, evidence; digest/SSH/Merkle claims qualified. |
| [State of the Enclave](/Users/thinkstudio/Documents/OPAQUE/State%20of%20the%20Enclave.pdf) | 1–7 | Architecture consolidation and sequencing; current code overrides stale operational assertions. |
| [Polsia Dossier](/Users/thinkstudio/Documents/OPAQUE/Polsia%20Dossier.pdf) | 1–3, 9–12 | Legibility of autonomous work; Adanima-specific competitive and financial claims excluded. |

The next decision is commercial before it is architectural: **which real task will a team let an agent finish once Opaque can enforce and explain its limits?** The proposed release makes that decision testable.
