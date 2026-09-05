# Vault-signed SSH with broker authorization

The broker approves and executes the fixed health operation. Vault signs the
ephemeral client key through one narrowly permitted SSH role. The host requires
both the Vault certificate and the exact broker-signed, single-use manifest.
Vault's CA private key never enters the broker, SSH client or target host.

## Run the disposable integration

```sh
python3 -B scripts/ssh_vault_dogfood.py
python3 -B -m unittest discover -s scripts -p 'test_ssh_broker_control.py' -v
python3 -B -m unittest discover -s scripts -p 'test_ssh_host_guard.py' -v
```

Requires Docker, Rust/Cargo, OpenSSH client tools, Python 3 and Python
`cryptography`. The fixture image installs its own `python3-cryptography` for
the Linux host helper. The runner builds the fixture image, fetches the selected
Vault image if absent, creates fresh private temporary state and a uniquely
named Docker bridge, and removes only its own containers/network in `finally`.
All published ports bind literal host loopback. It records image identities and
makes no outbound-network isolation claim. `--no-build` reuses the current
fixture image; `--vault-image` selects another Vault image explicitly.

The default run exercises both the signed Python host protocol and the actual
Rust `execute_ssh_action` implementation. The Rust phase prepares its exact
profile digest and key-custody checks, then issues through real Vault, verifies
the returned certificate, dispatches OpenSSH, authenticates the host receipt
and proves a replay causes no second source read. `--skip-rust-check` explicitly
skips that phase. The fixture uses synthetic identities and its own broker
signing key; neither phase performs a native human approval ceremony or connects
a production host, Vault or IdP.

The printed temporary directory contains runtime credentials and private keys.
Keep it private and outside Git; delete it when evidence review is complete.
`result.json` contains sanitized checks, hashes and runtime metadata.
`rust-result.json` contains the verified synthetic receipt. No plaintext probe
output is stored in the host ledger; the Rust task receipt may hold the exact
fixed synthetic health response approved for release.

## Host control contract

When `/etc/opaque-ssh/broker.json` exists, the root host starts a TLS control
listener on port 8443 and requires broker authority for every guard execution.
The local operator's legacy `host_guard.py grant` command alone cannot create
usable authority in this mode. Without that configuration, the original
standalone fixture retains its existing behavior.

`POST /v1/ssh-control` accepts exactly `payload` and `signature`. `payload` is
standard base64 of the exact JSON bytes; the lowercase-hex Ed25519 signature
covers `opaque.ssh-control.v1\0` followed by those bytes. Signature verification
precedes JSON interpretation. The decoded JSON contains exactly `action`
(`grant` or `revoke`), `manifest` (the complete `SshHealthAction`), `issued_at`,
`expires_at`, and canonical UUID `nonce`. Duplicate/unknown fields fail closed.

The host compares the full tenant/broker, profile, destination/port, host key,
Vault role/CA/reference, principal, login account and source address with its
root-owned configuration. The operation and command are fixed, the session is
at most 30 seconds, authority expires within 300 seconds, and control messages
must be recent. The same SQLite transaction records the nonce, immutable
authority and existing host grant. No separate approval decision occurs here.

Revocation changes that same grant's live revocation bit. A valid revocation
that arrives before its grant creates an exact revoked tombstone, so delayed
admission cannot restore authority, including after restart. Reusing a grant
UUID, changing any binding or replaying a nonce cannot refill the allowance.

Control acknowledgments and guard results use the corresponding envelope with
the signature domain `opaque.ssh-receipt.v1\0`; payload fields are exactly
`manifest`, `expires_at`, and `response`. The complete approved manifest stays
bound to the result. Only completed results contain the exact `output_text`,
whose bytes must match the signed receipt's SHA-256. Expiry/revocation/timeout
releases no output. The broker verifies signatures and all bindings before
interpreting or persisting result evidence.

## Production provisioning

The operator provisions a Vault SSH CA and narrowly scoped signing role before
work is admitted. The role allows only the host-specific principal, user
certificates, a short maximum TTL, `force-command`/`source-address` critical
options and no PTY/forwarding extensions. Its signing credential should permit
only `update` on the exact `ssh-client-signer/sign/<role>` path; it must not
change roles, CA keys or unrelated credentials. The broker further verifies
the actual returned certificate and binds the exact dispatcher UUID/source.

The runner, [role template](vault-role.json) and
[signer policy](vault-signer-policy.hcl) use mount `ssh-client-signer` and role
`fixture-health`. The deployed profile's `vault_mount`, policy path and
configured Vault mount must match.

The host mounts only the Vault CA public key at `/etc/opaque-ssh/ca.pub` and
its own host/receipt/TLS keys. `broker.json` pins a separate broker Ed25519
verification key; that key authorizes operations and is unrelated to the Vault
CA. Host configuration and keys are root-owned, private keys mode 0600, with
root-protected paths. Start-up checks reject substituted host or CA public keys.

The selected production host, Vault URL/mount/role, admitted tenant/principal,
source IP, key-custody locations and TLS/SSH pins remain deployment inputs.
The existing dedicated host account must have no alternative local execution
path. Host/Docker administrators remain trusted, and the process-group guard
is a bounded fixture supervisor, not a production cgroup/session manager.

Vault certificate expiry limits authentication, not an already established
command. The host's ledger, expiry/revocation polling and process termination
continue to enforce the operation lifetime. Termination cannot undo a source
read already accepted upstream.
[Vault signed SSH certificates](https://developer.hashicorp.com/vault/docs/secrets/ssh/signed-ssh-certificates),
[Vault SSH API](https://developer.hashicorp.com/vault/api-docs/secret/ssh).

## Recorded validation

The September 5, 2026 run passed 47 checks with Vault 1.21.4 and OpenSSH 9.2p1,
including the native Rust executor, exact output hash, replay before/after host
restart, signed-manifest tampering, foreign tenant/source, wrong client/host
keys, command/PTY/shell restrictions, certificate expiry, scoped signer
restrictions and active revocation. Cleanup reported no failures.

All 26 Linux host guard/control tests passed, including socket peer credentials,
parent-death cleanup, concurrent single-use execution and the three reordered
revocation tests. An earlier concurrent-test run under load returned a
fail-closed guard result; its focused rerun and final full suite passed.

Private evidence:
`/var/folders/5z/j6x9mlc504l6txlg7bwjwfyc0000gn/T/opaque-vault-ssh-72vcihcu/result.json`.
