# Bounded agent work

Beyond one-shot operations (`opaque execute`, `opaque github set-secret`),
Opaque can hand an agent a **task**: an immutable manifest, approved once as
a whole, executed once, with a receipt. **plan → review → approve → run →
inspect**.

A task's authority is a **grant** — the manifest itself, pinned by content
hash. A different manifest is a different task; scope can't change after
planning.

---

## The three operation families

| Family | What it does | Action type | Enforcement |
|---|---|---|---|
| Repository & release work | Publish one GitHub secret, or dispatch one reviewed staging-release workflow | `PublishSecret`, `StagingRelease` | Pinned repo/workflow/branch/image digest; atomic single-use slot; provider reconciliation |
| Application evidence | Run a fixed inference/query against a tenant-scoped source and disclose the result to an approved model | `Inference` | Tenant binding, source snapshot hash, model/profile hash, current-authority recheck before disclosure |
| Host operations | Run one fixed command against one host over a Vault-signed, short-lived SSH certificate | `SshHealth` | Exact host key + principal + command binding, session deadline, host-side revocation check |

Every family shares one manifest shape (`opaque_core::task::TaskManifest`):
`schema_version`, `title`, `expires_in_secs`, and a list of typed `actions`.
Legacy and typed action kinds cannot be mixed in the same manifest, and a
manifest holds at most 32 actions with a maximum total lifetime of one hour.

## Planning a task

```sh
# Resolve exact repositories/refs and pin a manifest for review
opaque task plan --manifest ./release.json

# Plan a fixed host health check via the tenant's Vault SSH signer
opaque task plan-ssh --title "Service health on approved host" --expires-in-secs 300

# Plan three fixed public-source completions in the authenticated tenant
opaque task plan-inference --title "Tenant public data inference" --expires-in-secs 600
```

Planning resolves everything up front — repo IDs, workflow byte hashes, host
keys, Vault CA/role bindings — so the reviewer approves resolved facts, not
names that could still resolve to something else at run time.

## Reviewing and approving

A planned task is reviewed as a whole, not action-by-action. Set
`factors = ["paired_workstation"]` on the task's approval policy to require a
trusted workstation approver (`crates/opaque-approver/README.md`): a
separate machine with its own Ed25519 key that fetches the full manifest,
verifies its hash and deadline, and signs only after native authentication.
The agent never sees the review UI or holds the approver's key.

```sh
opaque task run <task-id>       # request approval, then execute once
opaque task show <task-id>      # exact scope, charged slots, provider outcomes
opaque task reconcile <task-id> # re-read correlated evidence without re-dispatching
opaque task revoke <task-id>    # block future writes on this task
opaque task list                # tasks owned by the authenticated caller
```

## Lifecycle

```
Planned --run--> Running --> Completed
                         \--> Partial   (some actions charged, ambiguous outcome)
   \--revoke------------------> Revoked
   \--expire (deadline passes)-> Expired
```

A slot charges **atomically before dispatch**, never after. Retry, restart,
or an ambiguous provider response never refunds it — an uncertain outcome
counts as consumed. `Partial` marks "charged, provider result unconfirmed"
as its own state, rather than guessing success or failure.

## Maturity

Repository/release work is production-real: manifest format, atomic ledger,
and `paired_workstation` approval are exercised end-to-end against real
providers in tests and dogfooding.

Host operations (`SshHealth`) are validated against disposable Vault/OpenSSH
fixtures — real certs, real host-side guards, real revocation — see
`examples/bounded-ssh/README.md` for the enforcement table. Provisioning a
real host and running native approval against it is on you; `opaque task
plan-ssh` doesn't do that part.

Application-evidence (`Inference`) tasks need a tenant-aware source adapter
and a real IdP/resource-token contract — see
[enterprise architecture](enterprise-architecture.md). Without that wired
up, there's no source for the task to read.

## Related docs

- [Identity](identity.md) — the delegation token an agent session presents when planning a task on a human's behalf
- Trusted workstation approvals (`crates/opaque-approver/README.md`) — the `paired_workstation` full-manifest review flow
- [HashiCorp Vault](vault.md) — the SSH certificate signer for `SshHealth` actions
- [Enterprise architecture](enterprise-architecture.md) — tenant/IdP wiring for `Inference` actions
