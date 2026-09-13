# Install the bounded SSH health host

Follow [the host and broker setup](../../docs/ssh-health.md). This directory
contains the fixed Linux probe, durable host guard, signed grant control service,
principal hook and systemd/OpenSSH installation files. The source package does
not include accounts, keys, endpoint configuration or a synthetic health service.

Run local checks with Python 3.11+ and `cryptography` installed:

```sh
python3 -m unittest discover -s packaging/ssh-host/tests -v
```

These checks exercise the actual local HTTP probe and signed host protocol with
temporary keys and an isolated SQLite ledger. They do not establish deployed
OpenSSH/Vault qualification or modify a host configuration.
