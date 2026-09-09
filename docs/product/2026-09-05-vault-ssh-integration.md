# Vault SSH and broker authorization

Private implementation record, September 5, 2026. This extends the earlier
[attestor/host fixture](2026-09-05-attestor-ssh-progress.md); it does not replace
that historical evidence. No AWX component is used. Vault owns its SSH CA;
Opaque owns approval, task authority and the ephemeral client private key.

## Implemented contract

`opaque task plan-ssh --title "Read fixture health" --expires-in-secs 60`
creates a schema-4 task from one sealed operator profile. MCP exposes the same
narrow request as `opaque_task_plan_ssh`. The caller chooses title and expiry;
the broker supplies destination, pinned host key, source IP, host principal,
Vault role/CA/credential reference, command and maximum session duration.
Planning neither signs a certificate nor installs host authority.

The manifest binds the tenant and broker lineage, authenticated subject,
delegation ID, observed workload UID/executable hash, exact profile digest,
canonical IP/port, login user, host-specific principal and a new grant UUID.
The only operation is `opaque-service-health`, reading the fixed synthetic
`fixture-api` health endpoint. Expiry is at most 300 seconds; a session is at
most 30 seconds. Existing whole-task approval shows these bindings and the
trusted Vault/control endpoints. Child policy and live identity are rechecked
before approval, after review, before dispatch and during the SSH operation.

After approval and durable slot reservation, the broker generates an ephemeral
Ed25519 key and asks only the configured Vault role to sign its public key.
It cryptographically verifies the returned CA signature, key, user certificate
type, grant UUID, exact principal and lifetime. It requires exactly the
`force-command` and `source-address` critical options and no extensions.
The CA private key never enters the broker or host configuration.

The broker signs a separate host grant with its own Ed25519 control key. The
host accepts only its pinned broker key and exact tenant/profile/host/principal/
Vault bindings. Signed requests have bounded timestamps, UUID nonces and durable
replay protection. Host authority is stored alongside the existing single-use
ledger, not in an independent approval system. A revoke that arrives before a
grant leaves a durable revoked entry, preventing a delayed grant from reopening
authority. Restart cannot replenish consumed work.

OpenSSH uses a fresh private temporary key file, a pinned host-key alias, a fixed
command and no user configuration, agent, shell interpolation, proxy, PTY or
forwarding. The host's root-owned principal hook and guard impose the same fixed
operation. The guard drops privileges and checks revocation, monotonic session
duration, wall-clock expiry and output bounds while supervising the probe.
Certificate expiry alone does not terminate an authenticated SSH session.

The host signs its exact manifest, expiry and terminal response with a separate
receipt key. The broker verifies that envelope before accepting health evidence,
including the exact complete output hash and expected health JSON. Task receipts
retain validated metadata, bounded output and the signed-envelope hash. Raw
signed envelopes are not retained by the broker; independent later signature
verification requires separately retained private operator evidence.

Cancellation kills the local SSH process group and schedules a bounded signed
host revocation attempt. Explicit task revocation first persists local denial,
then requests a host acknowledgement. Outage or process death still relies on
the host's expiry/duration enforcement. The daemon records whether the host
acknowledged; it does not claim that losing an SSH connection recalls a remote
operation. A lost Vault response is an unknown signer effect, with no host
dispatch. Unknown outcomes consume their slot permanently.

## Operator configuration

Enable task grants and configure a tenant-isolated broker with
`identity.required = true` and explicit allowed subjects. Startup rejects an
SSH profile without those prerequisites. Production tenant isolation uses the
existing custody enforcement; the temporary integration harness uses synthetic
identity and test authorization and does not claim native human review.

The `[ssh]` configuration is defined by `SshProfileConfig` in
`crates/opaqued/src/ssh.rs`. It contains public keys and pins, exact endpoints,
the Vault credential reference, receipt verification key and an absolute path
to the separate broker grant-signing key. That key must be a broker-owned,
private regular file containing exactly 32 raw bytes. Resolve credentials
through the existing broker secret resolver; never put token values or private
keys in the configuration or repository. Additional public TLS CA PEM is
supported. HTTP is accepted only for an explicitly enabled literal-loopback
fixture. Redirects and proxy environment configuration are disabled.

Use the [narrow Vault role](../../examples/bounded-ssh/vault-role.json) with the
[signer policy](../../examples/bounded-ssh/vault-signer-policy.hcl). The example
mount is `ssh-client-signer`, the signing role is `fixture-health`, and its only allowed
principal is `opaque-fixture-a-health`. A Vault administrator provisions the CA
and role; the runtime broker token receives only `update` on that signing path.
Use an Ed25519 SSH CA and pin the returned public key, not an administrative
Vault token. Public-key SHA-256 pins are lowercase hex over the decoded OpenSSH
wire-key blob, not the textual `SHA256:` display fingerprint.

The host's root-owned `/etc/opaque-ssh/broker.json` pins the exact profile digest,
tenant, destination, principal, source, Vault role/CA/reference and broker public
key. It also supplies the receipt private-key and control TLS certificate/key
paths. It must agree with the sealed broker profile before a task can run.
Rotate profile keys, endpoints or trust material by updating the trusted profile
and host pins, then plan/review a new task. Old profile approvals fail closed.

Primary references: [Vault SSH signing API](https://developer.hashicorp.com/vault/api-docs/secret/ssh)
and [Vault signed SSH certificates](https://developer.hashicorp.com/vault/docs/secrets/ssh/signed-ssh-certificates).

## Validation and remaining deployment gates

Core/CLI, enclave approval, broker certificate/receipt checks and Linux host
control tests cover rejected authority and single-use behavior. The disposable
`scripts/ssh_vault_dogfood.py` runner exercises a real Vault signer and OpenSSH;
its optional native Rust phase invokes the actual executor with synthetic
identity and a test authorization callback. Consult its private `result.json`
for the exact image identities, checks and cleanup result.

Fresh validation on September 5:

| Check | Observed result |
| --- | --- |
| `cargo test -p opaque-core` | 403 passed, including the final self-revocation regression |
| CLI unit/integration tests | 148 + 4 passed |
| MCP tests | 38 passed |
| `cargo test -p opaqued --bin opaqued` | 1,044 passed; three existing ignored tests and the separately invoked live SSH test |
| Real daemon identity integration | 4 passed |
| Metrics unit/HTTP gateway tests | 32 + 33 passed |
| Broker resource integration | Real daemon + HTTP gateway passed |
| SSH host guard and signed control in Linux | 26 passed, including peer credentials, parent death and reordered revocation |
| Production metadata preflight tests | 10 passed |
| `scripts/ssh_vault_dogfood.py --no-build` | All 47 checks passed; no cleanup failures |
| Workspace check; daemon all-target Clippy with warnings denied | Passed |

The real SSH run used Vault **1.21.4** and OpenSSH **9.2p1**. Its native Rust
phase invoked `execute_ssh_action`, obtained and verified a Vault-signed
certificate, accepted the signed host health receipt, refused grant replay and
observed exactly **one** source read. The host tests also prove that a certificate
without a broker grant cannot execute the operation, and that signed active
revocation terminates the probe and suppresses output. The signing token cannot
change the role/CA, sign for another role/principal, request host certificates,
add PTY extensions or exceed the role TTL.

Private raw evidence:
`/var/folders/5z/j6x9mlc504l6txlg7bwjwfyc0000gn/T/opaque-vault-ssh-72vcihcu/result.json`.
The adjacent `rust-result.json` and `rust-execution.log` record the native phase.
That directory also contains runtime private keys and fixture tokens: keep it
outside Git and public artifacts. All containers and the network created by the
run were removed. The fixture publishes service ports on literal loopback using
a disposable bridge; it does not establish outbound network isolation.

Fixture image: `sha256:fd8e646d993ceb02ac0affced007a1f2fa1d50e39f6cfc2265202f41876e9197`.
Vault image: `sha256:4e33b126a59c0c333b76fb4e894722462659a6bec7c48c9ee8cea56fccfd2569`.
The result records exact fixture source hashes. Test setup failures were fixed
before this pass: root file ownership when seeding Docker, fixed loopback port
mapping across restart, and a separate TLS server leaf signed by the fixture CA.

Rust SSH source SHA-256 values at the successful execution:

- `crates/opaqued/src/ssh.rs`: `537eb30b85d56406e1accfafbf8ffadc4adccdb73a2ca4bd4e409c44a4e7d4ee`.
- `crates/opaque-core/src/ssh.rs`: `fd22f3747e6f51ce705905c3c53a6fda4f13b29abfba511034e79bad9519d0f4`.
- `crates/opaqued/src/enclave/task.rs`: `a7cdf76e5cbef128fbe297da62d84508a8c21f557dd79d9521b723705043f043`.

This fixed fixture is not an interactive-shell service or a production host
deployment. Host root, Vault administration and the sealed broker operator
remain trusted. The dedicated host account must have no alternative local
execution path. Termination cannot undo a source request already accepted.
Native human approval and a selected real host operation remain deployment
gates; no live application or production workload was changed.

Gateway admission/revocation now goes through the
[broker resource authority](2026-09-05-broker-resource-authority.md). Logout can
durably revoke its original token after role removal or account disablement;
restoring those permissions does not restore the logged-out token. A real
daemon/gateway regression also verifies outage retry and local sign-out without
claiming durable revocation for a missing or expired cookie. Actual
application and IdP provisioning remains separate: the
[connection preflight](2026-09-05-production-connection-preflight.md) found that
the candidate Quant API lacks an applicable tenant authorization contract, and
the existing Dex issuer has no selected Opaque resource/client configuration.
No adapter invents private-data tenancy or a resource-token contract.
