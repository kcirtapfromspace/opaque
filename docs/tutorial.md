# Tutorial: your first gated operation

**Time: about 15 minutes.** By the end you will have an agent that can push a
secret to GitHub without ever being able to read it — and an audit trail that
proves what happened.

You need macOS or Linux and a terminal. Steps 1–4 need nothing else; from step 5
you also want a GitHub repo you can write to and a token with `repo` scope. No
prior Opaque knowledge assumed.

---

## What you are about to build

```
   your agent  ──►  opaque CLI  ──►  opaqued  ──►  GitHub
  (Claude Code)      (asks for       (holds the      (receives the
                    an operation)     secret)          secret)
                                          │
                                    you approve
                                     (Touch ID)
```

The agent asks for an **operation** — "set this secret" — never for the secret
itself. The daemon holds the value, you approve the act, and the response the
agent sees carries no secret material.

---

## 1. Install

=== "macOS (Homebrew)"

    ```sh
    brew install kcirtapfromspace/tap/opaque
    ```

=== "Linux / macOS (script)"

    ```sh
    curl -sSfL https://raw.githubusercontent.com/kcirtapfromspace/opaque/main/install.sh | sh
    ```

=== "From source"

    ```sh
    cargo install --git https://github.com/kcirtapfromspace/opaque.git opaque opaqued opaque-mcp
    ```

Check all three binaries are on your PATH:

```sh
opaque --version && opaqued --version
```

---

## 2. Start from a policy you can read

Opaque denies by default. A preset gives you a starting point you can read:

```sh
opaque init --preset github-secrets
```

This writes `~/.opaque/config.toml`. Open it — the whole security model is
visible in one file. Here is the rule that matters most:

```toml
[[rules]]
name = "allow-github-actions-secret"
operation_pattern = "github.set_actions_secret"
allow = true
client_types = ["agent", "human"]

[rules.approval]
require = "always"          # every single time, no lease
factors = ["local_bio"]     # Touch ID / polkit
```

Read that as: *setting a GitHub Actions secret is permitted, and only with a
human approving each one.* The preset adds a few sibling rules (Codespaces,
Dependabot, org secrets, list/delete) and one `test.noop` rule for onboarding.

Everything not named in this file is denied. There is no implicit allowance to
forget about — which you will see for yourself in step 6.

---

## 3. Run the daemon

In a second terminal, leave this running so you can watch it work:

```sh
opaqued
```

You will see it verify custody of its own state, load your policy, and listen:

```
INFO opaqued::trust_domain: custody verified: 20 paths exclusively owned by uid 501
INFO opaqued: listening on ~/.opaque/run/opaqued.sock
INFO opaqued: policy engine loaded with 7 rules
INFO opaqued: audit chain verified (0 records)
```

Back in your first terminal, confirm the two can talk:

```sh
opaque ping
```

```
✔  Pong
```

!!! tip "Prefer it always-on?"
    `opaque service install` registers a LaunchAgent (macOS) or systemd user
    service (Linux). For this tutorial the foreground daemon is better — you get
    to watch every decision.

---

## 4. Run your first gated operation

Nothing external needed yet — the preset includes a no-op operation exactly for
this moment:

```sh
opaque execute test.noop
```

Your machine prompts for Touch ID (macOS) or your password (polkit on Linux).
**Read the prompt before you approve** — it names the operation and carries a
hash binding the approval to this specific request. That prompt is the security
boundary: an agent can ask, but it cannot answer.

```
✔  Operation succeeded
```

Run it a second time and it goes through without prompting. That is the rule's
`require = "first_use"` with a 5-minute `lease_ttl`: approve once, and repeats of
the *same* request ride the lease until it expires. The write rules you are about
to use are `require = "always"` instead — no lease, every time.

---

## 5. Give the daemon your secrets

The daemon reads secrets from a **ref** — a pointer, not a value. Two entries: a
GitHub token for API access (the daemon looks for it at
`keychain:opaque/github-pat`), and the value you want to publish.

=== "macOS"

    ```sh
    security add-generic-password -s opaque -a github-pat -w
    # paste a GitHub token with `repo` scope, press Enter

    security add-generic-password -s opaque -a tutorial-value -w
    # type any throwaway value, press Enter
    ```

=== "Linux (secret-tool)"

    ```sh
    secret-tool store --label="opaque github pat" service opaque account github-pat
    secret-tool store --label="opaque tutorial value" service opaque account tutorial-value
    ```

Both values now live in the keychain. Nothing you type from here on contains
either one — you refer to them as `keychain:opaque/github-pat` and
`keychain:opaque/tutorial-value`.

---

## 6. Push a secret you never see

This is the moment the whole design exists for:

```sh
opaque github set-secret \
  --repo YOUR_ORG/YOUR_REPO \
  --secret-name TUTORIAL_KEY \
  --value-ref keychain:opaque/tutorial-value
```

Approve at the prompt — this rule is `require = "always"`, so there is no lease
to ride and you will be asked every single time. Note what the prompt shows: the
repo, the secret name, and the request hash. Then:

```
✔  Set TUTORIAL_KEY on YOUR_ORG/YOUR_REPO
  🔗  YOUR_ORG/YOUR_REPO
  🔑  TUTORIAL_KEY
```

Notice what is *not* there: the value. The daemon encrypted it with GitHub's
public key and sent it directly. It never passed through the CLI's output, so it
could never land in an agent's context.

Now try the same shape of request against a provider this preset never
mentioned — GitLab instead of GitHub:

```sh
opaque gitlab set-ci-variable \
  --project YOUR_GROUP/YOUR_PROJECT \
  --key TUTORIAL_KEY \
  --value-ref keychain:opaque/tutorial-value
```

```
✖  policy denied: operation 'gitlab.set_ci_variable' denied by policy —
   debug with: opaque policy simulate --operation gitlab.set_ci_variable
  code: policy_denied

  hint: This operation was denied by the security policy.
    • Check policy: opaque policy show
    • Request approval or check pending leases: opaque leases
```

No prompt, no network call, no GitLab token required — the request died at the
policy engine because no rule named it. That is deny-by-default working, and it
is why adding a provider is a deliberate act rather than an accident.

---

## 7. Read the audit trail

Every decision above was recorded:

```sh
opaque audit tail --limit 10
```

```
Audit log — 10 event(s)
  WHEN                       EVENT                    OPERATION                  OUTCOME
  -------------------------  -----------------------  -------------------------  ----------
  1m ago  18:53:40.668Z      operation.succeeded      github.set_actions_secret  [ok]
  1m ago  18:53:40.651Z      provider.fetch.finished  github.set_actions_secret  [created]
  1m ago  18:53:40.648Z      secret.resolved          github.set_actions_secret  [resolved]
  1m ago  18:53:40.644Z      operation.started        github.set_actions_secret  [unknown]
  1m ago  18:53:40.641Z      approval.granted         github.set_actions_secret  [allowed]
```

Every decision is there in order — the request, the approval requirement, the
approval being granted and by whom, the secret being resolved, the provider
call, and the denial of the GitLab request — each row carrying the correlation
ID that ties one operation's events together.

The log is not just a file — it is a hash chain:

```sh
opaque audit verify
```

```
✔  Audit chain intact — 34 records verified
```

If anyone edited, reordered, or deleted a record — including truncating the end —
this command says so and exits nonzero. Wire it into a cron job and you have
continuous integrity checking for free.

---

## 8. Point your agent at it

Now hand this capability to Claude Code. Add the MCP server to your config:

```json
{
  "mcpServers": {
    "opaque": {
      "command": "/usr/local/bin/opaque-mcp"
    }
  }
}
```

Restart Claude Code and ask it, in plain language:

> "Set the GitHub Actions secret TUTORIAL_KEY for YOUR_ORG/YOUR_REPO using my
> keychain token."

You will get the same approval prompt. The agent drove the operation; you
authorized it; the secret never entered the model's context. Ask the agent to
*show* you the secret instead and it cannot — there is no operation that returns
one.

---

## What you just proved

| You did | It demonstrated |
|---|---|
| Ran an operation with a secret ref | The model gets operations, never plaintext |
| Approved with Touch ID | Presence is proven by an act an agent cannot perform |
| Saw a lease on the second `test.noop` | Approval scope is a policy decision, not a default |
| Got denied on the GitLab request | Deny-by-default, with no implicit allowances |
| Verified the chain | Tamper-evidence you can check in one command |

---

## Where to go next

**Harden it.** Everything above ran in *session mode*, where the daemon shares
your user account. That means an attacker holding your uid could read the
daemon's keys — you would detect it afterward, but not prevent it. The
[trust-domain split](deployment.md) moves the daemon to its own service account
or container, where custody is enforced at startup and the guarantees become
prevention rather than evidence.

**Add real identity.** [Identity](identity.md) connects your IdP over OIDC, so
approvals name a verified human and agents act *on behalf of* someone with
delegation tokens — not anonymously.

**Approve from your phone or a hardware key.** The
[approval factors](identity.md#audit) include a paired second device and
FIDO2/passkeys, which produce a cryptographically signed approver in the audit
chain instead of a session-bound name.

**Govern a fleet.** [Federation](federation.md) lets one org signature carry
policy to every daemon, streams the audit chain to your SIEM in a form it can
verify, and lets daemons prove their posture before receiving keys.

**Go deeper on the rules.** [Policy](policy.md) covers targets, workspaces,
secret-name constraints, leases, and segregation of duties.

---

## Troubleshooting

**`Is the daemon running? Try: opaque service start`** — the CLI could not reach
the socket. Check the `opaqued` terminal for a startup error.

**The approval prompt never appears (Linux)** — polkit needs a desktop session
and the helper installed; see [Linux polkit](linux-polkit.md). On a headless box
use a second-device or FIDO2 factor instead, since there is no local prompt to
show.

**`config is unsealed`** — a warning, not an error. `opaque setup --seal` binds
your config to a keyed HMAC so later edits are detected.

**`policy_denied` when you expected success** — compare your rule's
`operation_pattern` and any `target` constraints against what you actually ran;
`opaque audit tail` shows the decision and which rule matched.
