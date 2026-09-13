# Read one service's health over SSH

An operator configures the host, service and endpoint. A user then plans and
approves one bounded read:

```sh
opaque task plan-ssh --title "Check payments API health" --expires-in-secs 60
opaque task run TASK_ID_FROM_PLAN
opaque task show TASK_ID_FROM_PLAN
```

This source implementation requires a release containing the configurable SSH
health contract and the [Linux host package](../packaging/ssh-host/README.md).
The broker and host require separate deployment. Local tests establish protocol
behavior; they do not establish qualification on your Vault/OpenSSH deployment.

## Select the service in the trusted broker profile

The broker must already have a tenant binding and a sealed `[ssh]` profile.
Set its `health_contract` explicitly for every new deployment:

```toml
[ssh.health_contract]
service = "payments-api"
version = "2026.09.1"
host = "127.0.0.1"
port = 9000
path = "/ready/health"
```

The endpoint must return HTTP 200 and exactly this JSON object (whitespace and
key order may differ):

```json
{"service":"payments-api","status":"ok","version":"2026.09.1"}
```

Only literal `127.0.0.1` or `::1`, a nonzero port, and a bounded absolute path
containing letters, digits, `/`, `_`, `-` and `.` are accepted. Empty path
segments, traversal, query strings, fragments and percent escapes are rejected.
Service and version are 1–64 character labels. The probe performs one GET with a
2-second socket timeout and a 4096-byte response cap. It does not follow redirects.
The host guard applies the approved total lifetime and session timeout even if a
response stalls.

The enclosing `[ssh]` profile pins `profile_id`, canonical `destination_host`,
`destination_port`, Ed25519 `host_public_key` and `host_key_sha256`, `principal`,
non-root `login_user`, the broker's exact `source_address`, and `max_session_secs`
(1–30). Configure the HTTPS `vault_url`, `vault_mount`, `vault_role`,
`vault_token_ref`, pinned Ed25519 `vault_ca_public_key` and `vault_ca_sha256`;
HTTPS `control_url`, optional public `tls_ca_pem`, the host's
`receipt_public_key_hex`, and an absolute broker-owned `grant_signing_key_path`.
Both digest fields are lowercase SHA-256 of the decoded OpenSSH wire blob,
not the printed `SHA256:` fingerprint. Grant and receipt keys are separate
Ed25519 keys; seed files contain exactly 32 raw bytes with mode 0600.

For a headless broker, enroll a [trusted workstation reviewer](../crates/opaque-approver/README.md)
and require `factors = ["paired_workstation"]` for both `ssh.health_manifest`
and `ssh.service_health`. The broker and reviewer must both include SSH task
support in their workstation protocol. The workstation displays the complete
health contract before native authentication; remote review does not enable
shell commands or bypass the host's single-use grant checks.

The profile digest and every contract field are part of the approved action.
The certificate pins the source IP, principal, grant ID and fixed command.
It carries no extensions. Configure a dedicated
[Vault SSH signing role](https://developer.hashicorp.com/vault/docs/secrets/ssh/signed-ssh-certificates)
that permits that principal, the `force-command` and `source-address` critical
options, user certificates, a maximum 300-second TTL and no default extensions.
The broker token only needs update access to that role's signing endpoint. The
Vault CA private key stays in Vault; the workload receives neither signer token
nor private SSH key.

Existing schema-4 actions with no `health_contract` retain the old
`fixture-api` / version `1` response expectation and identical serialization.
The packaged host requires an explicit contract. Migrate the broker and host
configuration together, then plan a fresh task; old grants cannot silently gain
a new service or endpoint.

## Install and configure the Linux host

Use a dedicated unprivileged SSH account with a usable shell, no password login,
and no alternate authorized keys. Install Python 3.11+, the distro's maintained
`python3-cryptography`, OpenSSH with `ChannelTimeout`/`UnusedConnectionTimeout`
support, and systemd. Reserve a dedicated SSH listening IP/port; the package does
not replace the host's administrative SSH listener.

After reviewing the package on the selected host:

```sh
sudo sh packaging/ssh-host/install.sh
```

This installs source and unit files. It creates no keys, accounts, configuration
or running listeners. Deploy these operator-managed files under `/etc/opaque-ssh`:

| File | Contents and custody |
| --- | --- |
| `health.json` | The five contract fields shown above, as JSON; root-owned 0644. |
| `principals` | Exactly the configured SSH principal, with a final newline; root-owned 0644. |
| `host_key`, `host_key.pub` | Dedicated Ed25519 OpenSSH host key; private file 0600, public file 0644. |
| `ca.pub` | Pinned Vault Ed25519 CA public key, 0644. |
| `receipt.key` | Host receipt signing seed, 32 raw bytes, 0600. |
| `control.crt`, `control.key` | HTTPS certificate for the broker's control URL and private key; 0644 / 0600. |
| `sshd_config` | Adapt the packaged dedicated listener example to the selected IP, port and account; root-owned 0644. |
| `broker.json` | Exact broker/profile pins, explicit health contract, public grant key, local key paths and control listener; root-owned 0644. |

All parent directories must be root-owned and not writable by group or others.
The private ledger directory remains root-only. The guard checks the Unix
socket peer UID against the configured SSH account and drops the probe to that
account with empty supplementary groups and a fixed environment.

Create `broker.json` from an operator-reviewed planned task so its profile digest
and pins match the broker. Planning does not contact the host or execute the
probe:

```sh
opaque --json task plan-ssh --expires-in-secs 60 > planned-ssh.json
python3 packaging/ssh-host/render_host_config.py \
  --task planned-ssh.json \
  --broker-public-key-hex "$BROKER_GRANT_PUBLIC_KEY_HEX" \
  --control-host "$HOST_CONTROL_IP" > broker.json
```

`BROKER_GRANT_PUBLIC_KEY_HEX` is the public key corresponding to the broker's
configured grant seed. The renderer never reads private keys or uses the network.
Review its output against the operator's intended host/service before installing
it. The control listener port defaults to 8443 and can be set with
`--control-port`; it must match the broker's `control_url`. Install `broker.json`
with root ownership and copy its `health_contract` exactly into `health.json`.
After provisioning is complete, discard that planning task and create a fresh
one for the user's approval.

Review the [OpenSSH settings](https://github.com/openssh/openssh-portable/blob/master/sshd_config.5)
and validate the dedicated instance before activation:

```sh
sudo /usr/sbin/sshd -t -f /etc/opaque-ssh/sshd_config
sudo systemctl daemon-reload
sudo systemctl enable --now opaque-ssh-guard opaque-ssh-control opaque-ssh-sshd
```

The guard and control service fail closed if the configured public host/CA keys,
principal, account, local health contract or file custody disagree. Root-owned
configuration selects all transport endpoints. SSH accepts only the fixed
`opaque-service-health` command, whose forced dispatcher submits one grant UUID
to the root-owned guard; it cannot choose a URL, shell, arguments or environment.

## Verify authority and observation

Local checks can run without credentials or host changes:

```sh
cargo test --locked -p opaque-core -p opaque-bounded-work ssh:: --lib
python3 -m unittest discover -s packaging/ssh-host/tests -v
```

They cover configured service/version results, every endpoint field, signed
admission and receipts, replay and expiry, revocation overtaking admission,
crash recovery, local configuration drift, and suppression of output after a
revocation. Host tests use an isolated SQLite ledger and temporary signing keys;
the HTTP test calls a local test listener. Linux peer credentials, process death,
OpenSSH, Vault permissions and systemd deployment require a separately authorized
host acceptance run.

For that run, use the normal broker plan/review/run flow on the approved test
service and inspect the authenticated health observation. Retain sanitized
revision/configuration digests and denial evidence for repeated grants,
revocation, expiry and changed health identity. A fixture pass or signed grant
admission alone is not evidence that the real service was observed. Failed or
unknown attempts stay consumed; reconcile before authorizing another attempt.
