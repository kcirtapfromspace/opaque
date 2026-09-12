---
template: home.html
hide:
  - toc
---

# Opaque

**Approve the work. Keep secrets secret.**

Give coding agents a reviewed task with a fixed scope and expiry.
Opaque checks authority before dispatch and keeps credentials with the broker.

[Try it out](https://demo.opaque.info/) · [Architecture](architecture.md) ·
[Installation and release status](getting-started.md)

## Approve one staging release. Keep the scope fixed. { #approve-one-staging-release }

Your agent requests a release of a specific build. Review the image, destination,
and workflow. Opaque binds approval to that task, with an expiry and at most one
dispatch attempt.

- **Review:** the planned task pins the repository, workflow, commit, and image digest.
- **Enforce:** a different build requires a new task and review. Production is outside
  this staging operation. Current policy, identity, expiry, and revocation still apply.
- **Inspect:** a timeout can leave the result unknown. The attempt stays consumed;
  `opaque task show <task-id>` and `opaque task reconcile <task-id>` inspect evidence
  without dispatching again.

## You set the permitted scope { #set-the-permitted-scope }

Operators configure the allowed repository, workflow, branch, and image source.
Agent requests must fit that scope before approval can authorize an attempt.
Read [task setup, limits, and evidence](bounded-work.md).

## Know the boundary

A separate broker identity isolates custody from the agent's OS user. The default
same-user setup does not. Other agent access remains outside Opaque. Workflow dispatch
is not deployment success. The workflow and its credentials also need review; these
controls apply to work routed through Opaque. Read the [architecture and evidence](architecture.md).

## Start with one task

Set up Opaque with the secret-write tutorial, or bring a staging workflow to a pilot
conversation. [Try it out](https://demo.opaque.info/) or [set up locally](tutorial.md). The hosted
demo uses fictional portfolio data and a separate workflow; see the [guide](hosted-demo.md).
