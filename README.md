# Opaque

![CI](https://github.com/kcirtapfromspace/opaque/actions/workflows/ci.yml/badge.svg)
[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-orange.svg)](LICENSE)
![Release](https://img.shields.io/github/v/release/kcirtapfromspace/opaque)

**Approve the work. Keep secrets secret.**

Opaque is a local broker for Claude Code, Codex, and MCP clients. It checks
policy, requests required human approval, and performs supported operations
using credentials held by the broker. The agent receives the permitted result.

Start with one task: publish a GitHub Actions secret using a stored reference,
without returning the secret value to the agent. The [tutorial](docs/tutorial.md)
walks through setup, approval, and inspection of the broker's observed outcome.

## Start here

| Your question | Read |
| --- | --- |
| Can I use it for a real task? | [First operation](docs/tutorial.md) |
| Where does the security boundary hold? | [Architecture and evidence](docs/architecture.md) |
| How do I install or upgrade? | [Install and command reference](docs/getting-started.md) |
| How do we evaluate it as a team? | [Scope one workflow](https://opaque.info/#op-pilot) |

For a quick hosted exploration, [try the demo](https://demo.opaque.info/).
It uses fictional portfolio data and a separate demo workflow; it does not
connect to your repository. See the [demo guide](docs/hosted-demo.md).

## One operation

After completing the tutorial's credential and policy setup:

```sh
opaque github set-secret \
  --repo myorg/myrepo \
  --secret-name API_KEY \
  --value-ref keychain:opaque/api-key
```

The broker checks the request, obtains the required approval, calls GitHub,
and records the observed result. [Bounded tasks](docs/bounded-work.md) add
reviewed manifests and durable action limits. [Qualified MCP calls](docs/mcp-qualified-tools.md)
have a separate signed contract and review path.

## What the boundary covers

Opaque governs operations routed through its broker. An agent's other credentials,
readable files, and direct access remain outside that boundary. Use a
[dedicated broker identity](docs/deployment.md) to isolate custody from the
agent's OS user; the default same-user setup does not provide that isolation.
The broker, its administrators, and configured approval factors remain trusted.

Audit verification checks recorded evidence under specified trust assumptions.
It does not independently prove every provider effect or that every action was
logged. See [evidence verification](docs/evidence-checkpoints.md).

## Install and release status

macOS and Linux are supported. For the published Homebrew package:

```sh
brew install kcirtapfromspace/tap/opaque
```

The workstation reviewer app, signed MCP v2 contracts, and portable evidence
checkpoints are **unreleased source capabilities**. Tagged packages may omit
them. Follow [source build instructions](docs/getting-started.md) to evaluate the
checkout, and the [explicit audit migration](docs/evidence-checkpoints.md#authenticated-local-head-and-older-databases)
before upgrading an existing audit store.

[Documentation](docs/README.md) · [Build on the public core](docs/reusable-core.md) ·
[BUSL-1.1 license](LICENSE)
