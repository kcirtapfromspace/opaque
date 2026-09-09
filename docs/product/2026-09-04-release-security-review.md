# Bounded release and workstation approval review

## Posture

- The agent supplies a typed request, while broker policy, credential custody,
  trusted workstation enrollment, and a durable ledger control execution.
- Each immutable task slot permits one provider dispatch attempt. An unknown
  result consumes that allowance; reconciliation supplies evidence only.
- The signed workstation response binds the complete review, broker, request,
  operation, nonce, decision, and expiry. It cannot establish remote biometric
  attestation independently of the trusted workstation application.
- The Docker fixture demonstrates distinct workload and broker identities and
  mount access. The host administrator remains trusted.

## Assumptions and boundaries

Assets are provider credentials, broker state and policy, workstation signing
keys, approval authority, and receipt integrity. The attacker is an agent with
access to the delegated broker socket and its own workspace, including mutable
Git metadata. It does not control the Docker host, broker configuration or data
volume, or trusted workstation account.

The reviewed paths are task planning/execution/reconciliation, workstation
enrollment and signed decisions, provider dispatch, and workspace verification
used before those operations. The fixed workflow and its protected repository
are trusted execution components. GitHub branch dispatch is not an atomic
compare-and-set on the broker's observed commit.

## Findings addressed in this increment

### P1: mutable Git filter configuration could execute before approval

**Evidence:** `verify_workspace_blocking` in
`crates/opaqued/src/main.rs` previously read
configured Git filter names, disabled those names, then ran status against the
original repository configuration. Adding a differently named filter between
those steps bypassed the disabled-name list. A disposable local reproduction
executed a harmless marker command through the exact status invocation.

**Impact:** an agent-controlled repository could run a command under the broker
account before task policy and approval completed. In a shared-filesystem broker
deployment this crosses the credential-custody boundary.

**Fix:** status now uses private broker-owned Git metadata and safe built-in
configuration instead of consulting the mutable repository configuration.
The implementation reconstructs index state without trusting working-tree stat
cache shortcuts, prevents automatic transport/lazy fetch, rejects unsupported
external filters and workspace forms, and bounds copied metadata. Metadata opens
reject non-regular files without waiting on a FIFO.

**Verification:** focused regressions cover a filter added after snapshot
creation, clean and dirty workspaces, same-size content changes, unsupported
index flags, and non-regular metadata. The final implementation handoff records
the corresponding workspace and dogfood runs.

### P2: preliminary Git reads could wait indefinitely on hostile files

**Evidence:** replacing a disposable repository's `.git/config` with a FIFO made
the preliminary `rev-parse` invocation wait indefinitely. Nonblocking opens for
copied metadata did not cover files read internally by Git.

**Impact:** an agent-controlled workspace could leave verifier processes and
blocking worker capacity occupied before approval.

**Fix:** all workspace Git invocations use the bounded runner in
`crates/opaqued/src/workspace_process.rs`. It drains
pipes without detached reader threads, enforces a five-second deadline and
output caps during collection, and kills the process group and reaps the child
on timeout, overflow, or error. Standard input defaults to null; explicitly
provided private attribute/index inputs remain supported. Preliminary reads use
a 128 KiB output cap; other workspace commands allow at most 16 MiB stdout and
128 KiB stderr.

**Verification:** regressions exercise blocked config reads, excess output,
subprocess cleanup, and supplied stdin alongside the workspace checks.

## Remaining limits

The isolated metadata removes repository-configured program execution from
status. Git still parses agent-controlled repository objects and metadata. This
is not a process sandbox or a guarantee against parser vulnerabilities. A
production broker accepting arbitrary external workspaces should use a
constrained verifier process with no credential access. Runtime and output bounds
are necessary limits, but do not replace that privilege boundary.

Supported verification includes SHA-1 repositories, built-in EOL conversion,
staged changes, and ordinary linked worktrees. Active external filters, sparse
or split indexes, assume-unchanged/skip-worktree shortcuts, and external attribute
files fail closed. Submodule contents retain the existing `ignore-submodules=all`
semantics; this check does not establish that nested submodule files are clean.

Repository state can change after verification. Each provider dispatch has its
own final policy, identity, and durable-authority check, but a local workspace
check is not proof that an arbitrary checkout remains immutable. The release
operation separately binds authoritative provider identities and workflow
content. Read-only workflow correlation is evidence from GitHub, not an Opaque
signature generated by the runner.

## Next validation inputs

No additional input was required to fix the workspace issue. Live dogfood still
needs an owner-completed native review and a reviewed live provider contract.
The GPU experiment additionally needs a designated namespace/access path, model
identity, and approved load; those inputs do not affect the local release tests.

## Priorities

1. Complete an actual native human approval and examine the resulting receipt.
2. Run one useful, protected staging workflow with scoped broker credentials.
3. Run production workspace verification in a separate constrained process
   without provider credentials, adding OS memory and CPU limits.
4. Exercise the proposed fixed-model inference contract against allocated cluster
   capacity, retaining the same unknown-effect accounting.
5. Test onboarding, revoked authority, uncertain results, and repeat use before
   widening operation scope or adding a Kubernetes controller.
