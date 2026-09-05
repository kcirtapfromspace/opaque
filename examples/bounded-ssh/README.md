# Bounded SSH health operation — private fixture

The original operator fixture below remains available. The new
[Vault/broker integration](../../docs/product/2026-09-05-vault-ssh-integration.md)
adds schema-4 broker approval, Vault certificate signing, signed host grants and
signed receipts. Run `python3 scripts/ssh_vault_dogfood.py` for that disposable
integration. It uses synthetic identity and test authorization; native human
review and production host provisioning remain separate gates.

This fixture exercises real OpenSSH against two disposable Linux containers.
The only operation is `opaque-service-health`: read the fixed local
`http://127.0.0.1:8080/healthz` endpoint of a synthetic `fixture-api` service and
return its validated service name, status and version. It changes no running
application, cluster, host SSH configuration or deployment.

```sh
python3 scripts/ssh_dogfood.py
python3 -m unittest discover -s scripts -p 'test_ssh_host_guard.py' -v
```

Docker, Python 3 and OpenSSH client tools are required. The runner builds only
the narrow `examples/bounded-ssh/` context, creates an internal Docker network
with no published ports, and removes only its uniquely named containers and
network in `finally`. A private temporary directory retains the generated keys,
build log, host logs and `result.json`; delete that printed directory after
review. Never add those artifacts to Git. The local image contains fixture code
and packages, but no runtime keys. `--skip-build` reuses the image and must only
be used when its code is current.

## Exact authority

| Boundary | Enforcement |
| --- | --- |
| Destination | Client pins each host key obtained through the Docker operator channel. `fixture-a` accepts only `opaque-fixture-a-health`; `fixture-b` accepts a different principal, even with the same CA. The ledger independently checks the local host and principal. |
| Caller | SSH authenticates a fresh Ed25519 key/certificate as the dedicated unprivileged account `opaque` (UID/GID 7382). The certificate restricts its source to the observed client container IPv4 address `/32`. Raw public-key, root, password and keyboard-interactive login are disabled. |
| Certificate | Normally 120 seconds, never later than its corresponding grant. Extensions are cleared. A critical forced command binds the exact grant UUID. The CA key remains in the runner's private temporary custody; hosts receive only its public key and the client receives only its own ephemeral private key/certificates. |
| Host command | Root-owned `AuthorizedPrincipalsCommand` validates the certificate's UUID key ID and supplies an exact forced dispatcher command and local principal. This restriction also applies if the CA omits `force-command`; conflicting certificate commands are refused by sshd. The dispatcher accepts only the exact original command `opaque-service-health`. |
| Sessions | PTY, agent/TCP/Unix/X11 forwarding, tunnels, user rc and user environment are disabled. Only one session channel per connection is allowed. Authenticated connections without a channel close after three seconds; inactive session channels close after 35 seconds. Shells, SCP/SFTP and arbitrary arguments never reach the probe. A refused PTY may still be followed by a permitted command without a PTY, per OpenSSH behavior. |
| Work budget | A root-owned SQLite ledger reserves each UUID exactly once before spawning. Concurrent sessions share that single allowance. Failure, timeout, uncertain delivery and restart never refund it. |
| Active lifetime | Host guard runs a fixed argv without a shell, drops to UID/GID 7382, clears supplementary groups/environment and closes inherited descriptors. It kills the process group at the earlier of the monotonic duration limit or grant expiry. It checks durable revocation at most every 50 ms during normal processing, then rechecks authorization before releasing a result. |
| Output and evidence | Maximum 4096 bytes, validated JSON. A successful receipt binds UUID, host, principal, fixed operation, timestamps and output SHA-256. Failed/expired/revoked operations release no result. Receipts persist fixed metadata and hashes, not raw output. |

The host control-plane CLI permits grants only for the next 300 seconds and
durations of 1–30 seconds. Normal fixture work has a five-second maximum. The
runner deliberately injects a slow source using a root-only fixture file to
prove active timeout, expiry and revocation, rather than merely checking that
an expired certificate cannot open a new connection.

OpenSSH certificate validity restricts authentication. It does not by itself
stop an established command. The host supervisor is responsible for that
separate boundary. See the primary [certificate options](https://man.openbsd.org/ssh-keygen)
and [sshd restrictions](https://man.openbsd.org/sshd_config) references.

## What the fixture establishes

The runner checks the permitted read and receipt, replay before/after host
restart, concurrent single-use consumption, foreign host/principal/source/user,
host-key mismatch, expired certificate, command injection, shell/subsystem/PTY
and forwarding denial, missing/conflicting certificate command restrictions,
revocation before use, active termination and absence of remaining probe
processes. It verifies exact terminal receipts, source read counts and probe
absence separately after timeout, expiry and revocation. Unit coverage exercises
host-ledger and guard edge cases separately, including Linux peer credentials,
process-group cleanup and the fixed probe's Linux parent-death signal. The result
file records source hashes, image identity, OpenSSH version and cleanup failures.

This is a test operator issuing grants directly, **not a human-approved broker
SSH operation**. The source is synthetic. No production IdP, real staging host,
broker delegation or software/hardware attestation is established by an SSH
certificate. The dedicated host account must have no alternative login or local
code execution path; its UID is the guard's local trust boundary. Host/root and
Docker administrators remain trusted. The root-owned ledger is an authority
database and local evidence store, not a signed or independently witnessed
audit chain.

Terminating the probe cannot undo a read already accepted by the source. The
fixture reports source reads separately from successful result delivery. A
host/process crash leaves consumed work unknown; this fixture does not provide
a production cgroup supervisor or a general interactive-session service.

The broker integration now uses an immutable manifest binding tenant,
broker, authenticated subject/session, attestor evidence, host-key pin, exact
principal, source address, fixed operation, grant UUID, expiry and allowance.
Native review authorizes that manifest before CA signing. The host receives
broker-authenticated grant/revocation state, reserves before execution,
and returns authenticated receipts. Granting a generic
shell or exporting a reusable CA credential would exceed this contract.
