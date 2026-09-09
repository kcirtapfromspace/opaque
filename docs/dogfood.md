# Dogfood bounded tasks locally

The runner starts the real `opaqued`, CLI, MCP transport, and dashboard against local GitHub and Vault API fixtures. It names our three repositories, but sends every provider request to `127.0.0.1` and uses six fake values. It does not modify GitHub or read production secrets.

## Run the repeatable check

```bash
python3 scripts/dogfood.py --check
```

The runner builds the four binaries, creates a short isolated directory under `/tmp`, and verifies:

1. Plan six exact writes: two secret names for each of `kcirtapfromspace/opaque`, `kcirtapfromspace/no_drake_in_the_house`, and `Nereus-Data/admachina`.
2. Pin Vault source version 1 and resolve GitHub's numeric repository IDs before review.
3. Execute all six writes through the broker and confirm six encrypted provider requests.
4. Attempt the same task again and confirm rejection without another provider write.
5. Simulate one uncertain GitHub 500 response and confirm its slot becomes `unknown`, remains consumed, and cannot be retried.
6. Verify public manifest digests, pinned references, and native/test approval provenance survive sanitization, without plaintext in receipts.
7. Restart the daemon and confirm both receipts remain readable and neither task can write again.
8. Start the real stdio MCP server with only the isolated socket, discover its task tools (asserting at least `opaque_task_plan`, `_run`, `_get`, `_list`, and `_revoke` are present — the current catalog also includes `_plan_ssh`, `_plan_inference`, and `_reconcile`), inspect/list the completed receipt, and verify an MCP replay returns a tool error without an extra write. Provider credentials are not passed to the agent transport.

The final `PASS` line means these checks passed. Paths for the config, manifests, logs, receipt databases, and fixture write log are retained for inspection. `fixture-writes.jsonl` records targets, HTTP status, and ciphertext length only. The fixture verifies encryption's wire format and absence of plaintext; it does not prove GitHub storage or decrypt the sealed value.

## Use the dashboard and agent workflow

```bash
python3 scripts/dogfood.py --serve
```

Keep that terminal open. The runner prints the dashboard URL (default `http://127.0.0.1:7382`), an exact planned task ID, and commands to inspect and run it. Open **Tasks** to review the six slots, then run the printed `opaque --socket … task run …` command in another terminal. The dashboard polls for updated receipts.

`--serve` uses explicit **insecure auto-approval**, confined to this local simulation. The config and environment both opt into that backend, and the daemon audits its use. It is useful for testing the mechanics repeatedly; it does not exercise human consent.

For the actual approval experience against the same local fixtures:

```bash
python3 scripts/dogfood.py --serve --native
```

`--native` selects the OS approval backend and omits `OPAQUE_INSECURE_AUTO_APPROVE`. Run the printed task command and complete the native prompt yourself. Cancellation should produce a denied/partial task with no successful provider writes. The local dashboard remains read-only and cannot approve tasks.

To let an agent exercise the protocol, give it the printed manifest path and explicit socket, plus the printed CLI command. Source values are resolved in the daemon; the manifest and receipt contain references only. The runner also prints an MCP launch command for connecting an agent client to the same fixture daemon. For repeated work, create a fresh plan with `opaque --socket … task plan --manifest …`; a completed or uncertain task is deliberately not reusable. Use `opaque --socket … task revoke TASK_ID` to stop future dispatches on a planned task.

## Useful options

```bash
# Skip rebuilding after a successful build.
python3 scripts/dogfood.py --check --no-build

# Choose a free dashboard port.
python3 scripts/dogfood.py --serve --port 8080

# Keep a named isolated workspace (empty or previously created by this runner).
python3 scripts/dogfood.py --serve --data-dir /tmp/opaque-team-dogfood
```

Do not point `--data-dir` at an existing installation. The runner rejects `~/.opaque` and directories without its dogfood marker. It never changes `HOME`. If a local port is already in use, choose another `--port`. Ctrl-C stops the child services; all state remains in the printed directory.

The check mode also accepts `--native`, but it will require you to complete approval prompts. Automated checks should use the default simulation backend.

## What to test before real provider onboarding

- Is the approval clear about the six exact target writes, fixed source versions, and expiry?
- Can you explain the distinction between planned, consumed, API accepted, rejected, and unknown from the receipt?
- Does a cancelled/revoked task avoid new provider dispatches? Are writes already in flight clearly represented?
- Can your agents plan and inspect work using the isolated socket without receiving source values?
- Does the disconnected dashboard explain recovery without displaying synthetic success?

This runner tests the first workflow and local integration. Bounded tasks currently support the native full-manifest review followed by the local biometric factor; other approval factor combinations remain unavailable for this workflow. The source must be an explicit Vault KV v2 version, and each manifest is limited to 32 exact writes with at most a one-hour lifetime. Real GitHub/Vault onboarding, production credential scope, external provider behavior, native approval completion, and adoption in each application's release process still require separate verification. A GitHub API acceptance receipt does not verify a deployment.
