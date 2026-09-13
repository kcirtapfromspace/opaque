# Exercise an installed build candidate

Run the actual installer and compiled tools from a source-bound release archive
inside temporary homes. The runner checks checksums, all eight installed payloads,
CLI revision identity, private workstation custody across fresh processes, and
rejection of permission, link, identity and delegated-session mutations.

Build all tools and package a native build candidate first:

```sh
cargo build --locked --workspace --bins
python3 tests/packaged/build.py --binary-dir target/debug --output /tmp/opaque-packaged-candidate
```

```sh
python3 tests/packaged/run.py \
  --archive /tmp/opaque-packaged-candidate/candidate.tar.gz \
  --version 0.3.0 --revision "$(git rev-parse HEAD)" \
  --target "$(rustc -vV | sed -n 's/^host: //p')" \
  --output /tmp/opaque-packaged-result.json
```

The archive must satisfy `scripts/release_artifacts.py verify` and match the
executing platform. `--allow-dirty` admits a locally labeled candidate only.
An inert executable cannot qualify. On macOS the archive must include a signed
reviewer app; local ad-hoc integrity is sufficient for this test. The relocated
app must pass strict signature verification and its native launcher self-test.

On Linux, run in a disposable container or CI runner as root and supply
`--owner-user` and `--peer-user` for two existing, distinct non-root accounts.
The runner drops supplementary groups and executes the installed approver as
both accounts. The peer cannot load or directly read owner custody even with
the owner's temporary HOME. It does not create accounts or change host services.

The installer uses a strict local download transport with the selected archive's
exact bytes. No GitHub release, vendor account or published signature is claimed.
Native diagnostics query capability without requesting approval. A headless host
must report the expected denial; it cannot qualify as human presence. No daemon,
native review window, enrollment, Keychain access or service registration starts.
The JSON report contains hashes and named outcomes, never custody contents.

Run transport and report-rejection tests with:

```sh
python3 -B -m unittest discover -s tests/packaged -p 'test_*.py'
```
