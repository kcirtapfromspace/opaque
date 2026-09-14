# Run actual model completions unattended

Run the pinned CPU model and the real broker in one disposable Linux host:

```sh
python3 -B tests/contained-ssh/run.py --real-model --output /tmp/opaque-model-run
```

The wrapper downloads the public GGUF from an immutable Hugging Face revision,
checks its length and SHA-256, builds the pinned `llama-server`, and mounts the
model read-only. `--model-file /absolute/path/model.gguf` reuses already verified
bytes. `--registry-cache` and `--target-cache` reuse existing Docker volumes;
never share a target cache with another running build. Docker must support the
contained host's privileged systemd and private cgroup namespace.

The test observes actual generation counters and three actual completion
receipts through the production inference client. A signed rejection must
produce zero generation and no reservation. An approved fresh task must retain
its three charged slots, exact output hashes and typed receipts across broker
restart; replay must cause no additional model generation. Approval uses the
production signed review protocol with an explicit scripted test signer.

The server uses one slot, a 1,024-token context, two CPU threads and no GPU.
Fresh process ownership, model and executable hashes before/after execution,
metadata identity, generation counters and cleanup are mandatory. It binds
only to literal loopback inside the disposable host; no host port is published.

The pins are:

- GGUF: `unsloth/SmolLM2-135M-Instruct-GGUF`, revision
  `9e6855bc4be717fca1ef21360a1db4b29d5c559a`, file
  `SmolLM2-135M-Instruct-Q4_K_M.gguf`, 105,454,144 bytes,
  SHA-256 `ed5fa30c487b282ec156c29062f1222e5c20875a944ac98289dbd242e947f747`.
- llama.cpp: `c1d0e7a004015f23bc0233470b747b596f29b264`.
  The locally built executable's actual hash and build metadata are recorded;
  this is not a claim of identical binaries across compilers or architectures.

`container/model-service.json` and `container/suite/report.json` contain scoped
results. Server logs, profile files and raw test output stay in the private
output directory. Failed preparation, changed artifacts or uncertain cleanup
cannot produce a passing result. The wrapper removes only its owned container.

The prompts contain fixed synthetic public receipts. This profile qualifies
actual model execution and the approval/charge/replay protocol. It does not
qualify live GitHub observations, model answer quality, vendor account access,
physical authenticator use or native human presence.

Runner regressions, without downloading a model or starting Docker:

```sh
python3 -B -m unittest discover -s tests/real-model -p 'test_*.py' -v
```
# Actual completions in workspace coverage

Run the existing completion and signed-review check against instrumented Rust
objects in the same owned Linux host:

```sh
python3 -B tests/contained-ssh/run.py --coverage \
  --acceptance packaged --acceptance browser --acceptance model --acceptance service \
  --output /tmp/opaque-workspace-acceptance-coverage
```

The collector compiles every Cargo workspace package once with the same pinned
nightly instrumentation, then gives the model runner an explicit prebuilt test
object. The pinned engine still performs real completions; its native metadata,
artifact hashes, observed generation and signed-review/replay checks remain
mandatory. Rust daemon, test and peer counters join the native workspace report.
The external model engine is not counted as Rust workspace source. Stable model
acceptance retains its original toolchain and does not inherit coverage inputs.
`--coverage-acceptance-only` is a partial development probe and cannot report a
full workspace collection; dirty candidates require `--coverage-allow-dirty`.
