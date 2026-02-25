# Why We Built Opaque

*February 2026*

AI coding tools are writing production code, deploying services, and managing infrastructure. They are also, increasingly, touching secrets -- and they are doing it with no guardrails.

This is the story of why we built Opaque, a local secrets broker that ensures LLMs never see plaintext secret values.

## The Problem

Modern AI coding assistants need access to secrets to be useful. Setting a GitHub Actions secret, rotating an API key, deploying a service with database credentials -- these are the workflows that developers want to automate. The natural approach is to give the AI tool access to the secrets it needs.

The problem is that "access" in the current model means the secret value flows through the LLM's context window. Once a secret is in context, it can be:

- **Echoed back** in the model's response, ending up in terminal scrollback, log files, or screen recordings
- **Exfiltrated** through prompt injection attacks that trick the model into including the secret in a web request, code comment, or MCP tool call
- **Persisted** in conversation logs, training data pipelines, or third-party analytics

This is not theoretical. It is happening today.

## The Incidents

**CVE-2025-32711 (EchoLeak).** A prompt injection technique demonstrated that AI coding tools could be tricked into reflecting secrets from their context into outputs that leave the local machine. The attack works because the model has the plaintext value and can be socially engineered into using it.

**Claude Code .env loading.** Early versions of Claude Code would read `.env` files into context to understand a project's configuration. Well-intentioned, but it meant every secret in that file was now part of the conversation -- available to be echoed, logged, or influenced by injected instructions in other files the model reads.

**GitGuardian's 2025 State of Secrets Sprawl.** GitGuardian reported a 40% increase in the rate of secret leaks in public repositories, correlating directly with the rise of AI-assisted coding. AI tools generate more code, faster, and the secret hygiene of that generated code is worse than human-written code on average.

These are not edge cases. They are the predictable consequence of a model where AI tools are given raw secret values and trusted not to mishandle them.

## Why Existing Tools Do Not Solve It

The security ecosystem has strong tools for managing and detecting secrets. None of them address this specific threat:

**Secret managers** (Vault, 1Password, AWS Secrets Manager) store and distribute secrets securely. But they authenticate the *client*, and once authenticated, they hand over the plaintext value. If the client is an AI coding tool, the value ends up in LLM context. The secret manager did its job; the problem is downstream.

**Secret scanners** (GitGuardian, Gitleaks, TruffleHog) detect secrets after they have leaked -- in commits, logs, or artifacts. They are essential, but they are a detection layer, not a prevention layer. By the time a scanner finds a leaked key, the damage window has already opened.

**Environment variable managers** (direnv, dotenvx) make it convenient to load secrets into the shell environment. They do nothing to prevent those environment variables from being read by any process in that shell, including an AI coding tool.

The gap is clear: no existing tool prevents the secret value from entering the LLM's context in the first place.

## The Insight: Operations, Not Values

The key insight behind Opaque is that AI coding tools almost never need the *value* of a secret. They need to *perform an operation* that involves a secret.

Consider the workflow "set the GitHub Actions secret `API_KEY` to the value stored in 1Password." The AI tool needs to:

1. Know that the operation is "set a GitHub secret"
2. Know the target: `myorg/myrepo`, secret name `API_KEY`
3. Know the source: 1Password item `production/api-key`
4. Know whether it succeeded or failed

At no point does the AI tool need to see the actual API key value. It needs to *reference* it and *invoke an operation* that uses it. The secret value is needed only by the system that executes the operation -- and that system does not need to be the LLM.

This is the core design principle of Opaque: **the LLM sees operations and references; a trusted local daemon handles the secret values.**

## How Opaque Works

Opaque interposes a five-stage pipeline between the AI coding tool and your secrets:

```
AI Tool  -->  Policy  -->  Approval  -->  Execute  -->  Sanitize  -->  Audit  -->  AI Tool
             (deny by      (Touch ID      (provider     (strip         (structured
              default)      / polkit)       action)       values)        log)
```

**Policy.** Every operation is checked against a deny-by-default policy. The policy specifies which operations are allowed, for which clients, and under what conditions. An AI coding tool can only invoke operations that have been explicitly permitted.

**Approval.** Allowed operations require explicit human approval through native OS mechanisms -- Touch ID on macOS, polkit on Linux. This is not a browser pop-up or a terminal prompt that the AI tool could auto-dismiss. It is a biometric or system-level confirmation that requires physical human presence.

**Execute.** The trusted daemon (`opaqued`) executes the operation against the provider. It reads the secret value from the source, performs the action (e.g., sets a GitHub secret via the API), and captures the result. The secret value exists only in the daemon's memory, briefly, for the duration of the operation.

**Sanitize.** Before the result is returned to the AI tool, it passes through typestate-enforced sanitization. The response is scrubbed for anything that looks like a secret value -- not just the specific secret involved in the operation, but any pattern that matches known secret formats (API keys, tokens, connection strings). The type system ensures that unsanitized responses cannot be sent to the client.

**Audit.** Every operation -- allowed or denied, approved or rejected, successful or failed -- is logged to a structured SQLite audit trail with correlation IDs, client identity, timestamps, and session information. You can query the audit log to understand exactly what your AI tools have been doing with your secrets.

The AI tool gets back a confirmation: "GitHub secret `API_KEY` was set successfully for `myorg/myrepo`." That is all it needs. That is all it gets.

## What Is Available Today

Opaque is open source under the Apache-2.0 license. It ships with:

- **`opaqued`** -- the trusted daemon that manages the enclave, policy evaluation, approval prompts, provider execution, sanitization, and audit logging
- **`opaque`** -- the CLI client for direct human use and agent wrapper mode
- **`opaque-mcp`** -- an MCP server that integrates directly with Claude Code
- **Providers** for GitHub Actions secrets, GitLab CI/CD variables, 1Password, Bitwarden Secrets Manager, HashiCorp Vault (KV and dynamic secrets), and AWS Secrets Manager
- **Policy presets** for common workflows so you can go from install to working setup in under a minute
- **Agent wrapper mode** that scopes sessions to an agent's lifetime with automatic cleanup

The project is written in Rust, runs entirely on your local machine, and makes no network calls except to the secret providers you configure. There is no hosted service, no account to create, no telemetry.

## Try It

Install Opaque:

```sh
brew install anthropics/tap/opaque
```

Or from source:

```sh
cargo install --git https://github.com/anthropics/opaque.git opaque opaqued opaque-mcp
```

Initialize a preset and start the daemon:

```sh
opaque init --preset github-secrets
opaqued
```

Add the MCP server to Claude Code and ask it to set a secret. You will see the Touch ID prompt. You will see the audit log entry. You will not see the secret value anywhere in the conversation.

We think this is how AI tools should interact with secrets: through operations, with approval, under audit. If you agree, we would welcome your contributions -- whether that is trying it out, filing issues, or submitting pull requests.

Repository: [github.com/anthropics/opaque](https://github.com/anthropics/opaque)

License: Apache-2.0
