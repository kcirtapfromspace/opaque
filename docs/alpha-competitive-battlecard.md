# Opaque Alpha Competitive Battlecard

Date: 2026-02-25
Owner: GTM (with PO + ENG + SEC review)

## 1. Target Buyer and Trigger

- Primary ICP: AI-native startup engineering teams using coding agents and CI/CD automation.
- Buying trigger: "We need agents to perform secret-using operations without pasting secrets into prompts/logs."
- Disqualifier: teams requiring centralized multi-tenant governance as a launch-day requirement.

## 2. Why Opaque (Use in Every Pitch)

- Local-first trust boundary: secret resolution and execution stay on the developer machine.
- Operation-bound approvals and policy controls: approve intent, not plaintext value access.
- Agent-safe output model: no plaintext secret values returned in normal operation responses.

## 3. Non-Goals (State Explicitly)

- Not a hosted multi-tenant secret platform.
- Not a plaintext "give my agent the secret value" system.
- Not a full enterprise compliance suite in alpha.

## 4. Direct Competitor Matrix

| Competitor | Strength | Risk Against Opaque | Opaque Counter-Position | When to Concede |
|------------|----------|---------------------|-------------------------|-----------------|
| Infisical Agent Sentinel | Agent-focused controls + managed platform | Faster enterprise adoption with centralized controls | Opaque is simpler for local developer workflows and strict local-first operation gating | Buyer mandates managed control plane immediately |
| Akeyless AI + MCP | Enterprise access controls and platform depth | Strong compliance trust and centralized admin model | Opaque optimizes for developer speed + local approvals without platform overhead | Buyer requires enterprise procurement/compliance before pilot |
| 1Password AI + Secrets Automation | Brand trust, strong UX, existing footprint | "Already have 1Password, why add Opaque?" | Opaque complements existing stores by enforcing operation-bound policy/approval around agent actions | Team only needs secret storage UX, not operation mediation |
| Doppler Enclave / Dynamic Secrets | Mature developer workflow tooling | Convenience-first buyers may prefer integrated workflow suite | Opaque prioritizes safety boundaries for agent actions over broad workflow features | Team optimizes purely for workflow breadth over trust boundaries |

## 5. Adjacent Alternatives and Positioning

| Alternative | Typical Buyer Reason | Counter-Message |
|-------------|----------------------|-----------------|
| HashiCorp Vault | "We already have a secret backend." | Keep Vault; use Opaque as the agent-facing enforcement layer for operation + approval policy. |
| GitHub native secrets | "We only need CI secrets." | Opaque gives unified approval + audit + policy for agent-driven writes across providers. |
| GitLab CI variables | "Pipeline vars already exist." | Opaque standardizes safety controls across GitLab, GitHub, and provider refs. |

## 6. Objection Handling

### Security Objection

- Objection: "Local tools are less secure than centralized systems."
- Response: Opaque uses local trust boundaries with deny-by-default policy, operation-bound approvals, and audit trails; it avoids plaintext secret exposure in agent-visible result channels.
- Proof to show: policy rules, approval flow, audit log chain for one operation.

### Usability Objection

- Objection: "This will slow developers down."
- Response: Start with low-friction presets for safe operations, first-use leases for repeated workflows, and one-command install paths.
- Proof to show: quickstart demo + first successful secret sync in minutes.

### Migration Objection

- Objection: "We already use 1Password/Bitwarden/Vault."
- Response: Opaque does not replace secret backends; it mediates how agents use them for operations safely.
- Proof to show: provider ref (`bitwarden:`/`onepassword:`/`vault:`) driving GitHub/GitLab secret write without secret value disclosure.

## 7. Competitive Discovery Questions

- Are you trying to solve secret storage, or safe agent execution using secrets?
- Do you require a hosted control plane before validating agent workflows?
- Is your primary risk accidental secret leakage through agent/tool output?
- Which workflow matters first: GitHub secrets, GitLab variables, or sandboxed command execution?

## 8. "Why Opaque Now" Talk Track (30s)

"Teams are adopting coding agents faster than they can safely adapt secret workflows. Opaque gives a local, operation-bound control layer so agents can do real work with secrets without being handed plaintext values. It plugs into your existing secret providers and adds policy, approvals, and audit evidence where the agent acts."
