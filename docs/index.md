---
template: home.html
hide:
  - toc
---

# Opaque

**Approve the work. Keep secrets secret.**

Opaque runs sensitive operations for Claude Code, Codex, and MCP clients.
It checks policy, requests required approval, and uses broker-held credentials.

[Try one operation](tutorial.md) · [Architecture](architecture.md) ·
[Installation and release status](getting-started.md)

## Publish a GitHub Actions secret

The agent names a repository, secret, and stored reference. With a policy
requiring approval for every write, you review the request before Opaque calls
GitHub. The response omits the secret value. Inspect the observed result with
`opaque audit tail` and `opaque audit verify`.

## Approve a whole task

For supported workflows, [review a pinned manifest](bounded-work.md). Each action
consumes a durable attempt before dispatch; retries do not replenish it.

## Know the boundary

A separate broker identity isolates custody from the agent's OS user. The default
same-user setup does not. Other agent access remains outside Opaque. Audit records
describe observations, not proof of every external effect. An interrupted call can
leave the outcome unknown. Read the [architecture and evidence](architecture.md).

## Start with one task

Run the tutorial on a test repository, or bring a recurring CI task to a pilot
conversation. [Demo and pilot invitation](https://demo.opaque.info/). The hosted
demo uses fictional portfolio data and a separate workflow; see the [guide](hosted-demo.md).
