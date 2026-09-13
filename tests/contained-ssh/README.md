# Run real contained SSH acceptance unattended

From public core, run:

```sh
python3 -B tests/contained-ssh/run.py --output /tmp/opaque-contained-run-1
```

The output directory must not exist. Docker must be able to launch a privileged
Linux container with a private cgroup namespace. The image runs actual systemd
as PID 1 and generates fresh Vault, SSH, TLS and review credentials at runtime.
It publishes no host ports. Normal completion, failures and interrupt handling
remove only the container carrying this run's exact ownership label. Existing
Docker containers, networks and cache volumes are preserved.

Two SSH tests in the synthesized `contained` profile establish:

- Signed controlled OIDC identities, delegated agent authority and a scripted
  workstation decision over the production pinned TLS review protocol.
- A real scoped Vault SSH certificate, OpenSSH authentication and the installed
  systemd host guard. Broker, RPC caller and host login use actual distinct NSS
  accounts and kernel peer identity; no synthetic `whoami` override is used.
- Exactly one Vault signing request in Vault's audit sink and one fixed local
  health read. A signed host denial rejects the consumed grant, and task replay
  after daemon restart creates no further probe.
- Killing the actual guard during an observed stalled health read leaves the
  broker slot `unknown`, recovers host `restart_unknown`, revokes the grant and
  kills the fixed probe. It neither fabricates a completion nor refunds replay.

A third test covers inference task RPC with a controlled HTTP peer. It rejects
planning authority revoked during a metadata read, verifies three typed
protocol completions, and revokes a reserved task during execution metadata.
No further completion is dispatched, the reservation remains charged, and
restart retains the revoked state. These responses are synthetic protocol
data; they do not qualify actual model completions or model quality.

These are Linux service and protocol checks in one disposable host. They do not
qualify inter-host network isolation, customer Vault deployments, macOS custody
or native human presence. The scripted review is explicitly recorded as
`insecure_test`; production approval checks remain enabled.

To collect actual production counters, including daemon subprocesses and the
three contained cases, use a separate fresh output:

```sh
python3 -B tests/contained-ssh/run.py --coverage --output /tmp/opaque-contained-coverage-1
```

This installs the collector's pinned nightly compiler and LLVM tools in the
disposable container, then runs the critical coverage collector with
`--contained`. A completed collection reports `collected`; the literal 100%
gate is a separate result in `container/coverage/coverage-summary.json` and must
be enforced independently by CI. Normal acceptance runs do not measure source
coverage. Linux results never substitute for a separate macOS report.

Optional `--registry-cache VOLUME` and `--target-cache VOLUME` accept existing
Docker volumes. Do not share one target cache with concurrent builds. The
wrapper never deletes cache volumes. It records the resolved image identity,
source snapshot, report hashes and owned-container cleanup in `run.json`.
Raw logs, profiles and ephemeral service data belong in private temporary
storage, not public site assets or committed validation records.

The Python resource-lifecycle regressions can run without Docker:

```sh
python3 -B -m unittest discover -s tests/contained-ssh -p 'test_*.py' -v
```
