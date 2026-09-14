# CLI setup, diagnostics and service acceptance

`cargo test -p opaque --test admin_cli_e2e` runs the actual compiled CLI with a
private HOME, config, binary directory and socket. It asserts exit codes, seal
and key files, custody modes, service state, command failures and diagnostic
responses. On macOS the fixture first proves a sandbox blocks `/usr/bin/security`;
this keeps all seal commands away from the login Keychain. The tests qualify the
real seal-file fallback, not an OS Keychain integration.

The launchctl/systemctl scripts in that Rust target are explicitly synthetic
command boundaries. The controlled doctor socket serves only ping and version
responses. Neither is evidence of a real service manager or daemon.

`contained.py` separately exercises the real CLI, real opaqued and real systemd
user manager. It creates one disposable account, seals its config, installs and
starts its unit, observes successful authenticated ping, checks stop/start/restart
PIDs, uninstalls, and verifies an actual systemctl connection failure. It removes
its account and manager in cleanup and records binary checksums and outcomes.

Use an owned disposable `tests/contained-ssh` systemd container with
`libpam-systemd` installed. The layered Dockerfile adds that dependency:

```sh
docker build -f tests/service/Dockerfile \
  --build-arg CONTAINED_IMAGE=opaque-contained-ssh:local \
  -t opaque-contained-service:local .
```

Inside that owned container, mount the source read-only and provide a writable
private evidence directory; then run:

```sh
python3 -B tests/service/contained.py \
  --opaque /target/debug/opaque --opaqued /target/debug/opaqued \
  --output /evidence/service-fresh
```

The output path must be fresh. The runner refuses a non-root process, a non-systemd
PID1, or an environment without the contained image marker. No public vendor
account, physical native approval, real launchd registration, or 100% coverage is
qualified by these tests. Standalone ordinary binaries do not contribute LLVM
coverage unless the enclosing collection instruments and retains them.

The optional `--coverage-input` accepts only the enclosing collector's validated
service input (exact source snapshot, toolchain, flags and `opaque`/`opaqued`
objects). It restores those explicit profile settings after environment clearing
and installs them in this account's user manager. Every observed Rust CLI and
daemon PID must have a nonempty continuous profile; cleanup removes the manager
settings. Ambient coverage variables are never forwarded.
