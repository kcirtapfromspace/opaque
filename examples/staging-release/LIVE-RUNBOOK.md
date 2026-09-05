# One native-approved private artifact check

**Prepared local procedure; no remote workflow, environment or live effect is
established by these files.** This path uses the production broker and GitHub API.
`scripts/release_dogfood.py` remains a disposable provider fixture and must never
receive a real provider credential. Its native M1 evidence keeps the exact
workflow hash exercised at that time; this revised workflow needs a fresh pin.

## Complete the destination contract first

The reviewed workflow exists locally at
`.github/workflows/opaque-staging-release.yml`, byte-identical to
`examples/staging-release/opaque-staging-release.workflow.yml`. Its job guard
requires the exact private repository name, numeric ID and private visibility.
It has only a manual `workflow_dispatch` trigger. Creating or committing this
file locally neither installs it on GitHub nor enables Actions.

Before any dispatch, use the repository's reviewed change process to install the
workflow on private `main`. Preserve the inherited publication guards. Establish
effective required review/CODEOWNERS, required checks, administrator enforcement,
no force pushes/deletion and protection against conflicting dispatch tags. The
`staging` environment must admit only the approved branch, require an independent
reviewer, prevent self-review and disallow administrator bypass. Retain the
reviewer/plan evidence: private environment required reviewers are unavailable
on GitHub Free, Pro and Team. Do not remove this requirement or change visibility
to make the preflight pass. [GitHub environment protection rules](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)

Build the immutable amd64 artifact from the final approved commit using the
local builder in [README.md](README.md#prepare-and-validate-the-artifact-locally).
Publication is separate: verify private repository and package destinations,
record the actual registry digest and exact workflow pull access, then replace
the sentinel in a private temporary copy of `opaque.json`. Record the same
approved commit and the current reviewed workflow SHA-256 in that copy.

```sh
python3 scripts/staging_release_preflight.py \
  --manifest /private/operator/staging-manifest.json --json
```

Resolve every `blocked` result and both operator-required evidence items before
continuing. The read-only report deliberately cannot prove artifact execution
or effective authority and never changes those assertions into passes by flag.
It may therefore exit 1 after its API checks pass; that does not waive the
remaining operator checks. A missing/ambiguous prerequisite is a stop condition.

## Provision separate broker and reviewer custody

Use an independently administered service account or the existing
[container split](../../docs/deployment.md#containers-compose-kubernetes).
Give this live deployment fresh named state/socket volumes or service paths;
retain existing workloads and M1 fixture state. The workload sees the socket,
manifest and client binaries only. Provider credentials, config/seal and broker
state stay in broker custody. Workstation private state remains outside both.

This dedicated example uses one socket/peer-UID-bound workload and requires paired
human approval for every task. It explicitly retains the daemon's default
`enforce_agent_sessions = false`; it does not demonstrate delegated identity or
session-token enforcement. Do not apply that setting over a deployment that
requires sessions. Such a deployment must keep its controls and complete its
existing human/session bootstrap before using these task commands. Changing only
the session approval factor is not a substitute for that bootstrap.

On the trusted workstation, check the actual reviewer/helper and initialize
fresh live-workstation custody under an existing protected parent:

```sh
opaque-approver check-native
opaque-approver init \
  --state-dir /trusted/operator/opaque-staging-approver \
  --name "Staging release reviewer"
```

Copy `broker.live.example.toml` into broker-owned `/etc/opaque/config.toml` and
replace only its public-key placeholder with the public enrollment key just
printed. Choose the actual approval listener/tunnel binding. Preserve
`workstation_test_mode = false`, the trust-domain split, both paired-workstation
approval rules and the read-only observation rule. Seal this config under the
daemon account through the selected deployment's bootstrap; start only after
its custody checks pass.

Configure these references and exact contract fields in the broker's service
environment, never in the agent environment:

```text
OPAQUE_CONFIG=/etc/opaque/config.toml
OPAQUE_GITHUB_API_URL=https://api.github.com
OPAQUE_GITHUB_TOKEN_REF=env:OPAQUE_STAGING_GITHUB_TOKEN
OPAQUE_STAGING_REPO=kcirtapfromspace/opaque-dogfood
OPAQUE_STAGING_WORKFLOW_PATH=.github/workflows/opaque-staging-release.yml
OPAQUE_STAGING_WORKFLOW_SHA256=REPLACE_WITH_REVIEWED_WORKFLOW_SHA256
OPAQUE_STAGING_IMAGE_REPOSITORY=ghcr.io/kcirtapfromspace/opaque-dogfood
OPAQUE_STAGING_REF=main
```

The operator supplies `OPAQUE_STAGING_GITHUB_TOKEN` only through an existing
protected broker environment file, such as `/etc/opaque/staging-provider.env`
owned by the broker with mode `0600`, or changes the reference to a configured
broker-owned keychain entry. This procedure does not retrieve or print a token.
The selected credential needs metadata/contents read and Actions read/write for
this repository. Do not use a production credential as a fixture token, include
credentials in manifests/receipts, or set `OPAQUE_DOGFOOD_LOOPBACK` in this live
deployment. The workflow uses its own short-lived package-read credential.

Obtain the broker ID and SHA-256 TLS certificate fingerprint through the
operator channel, then enroll the workstation as described in the
[approver runbook](../../crates/opaque-approver/README.md#enroll-using-trusted-operator-channels).
Do not infer these pins from an unverified network response. Confirm the workload
can reach its socket but cannot read broker or workstation custody.

## Plan, review, run and reconcile

The following `opaque` commands run in the workload/client context of the selected
split deployment. Use its real socket and the prepared, references-only manifest.
Planning performs provider reads; `task run` is the operation that requests
approval and may dispatch. Keep its client running during native review.

```sh
opaque --socket /run/opaque/opaqued.sock --json task plan \
  --manifest /input/staging-manifest.json
opaque --socket /run/opaque/opaqued.sock task show TASK_UUID
opaque --socket /run/opaque/opaqued.sock task run TASK_UUID
```

In a second terminal on the trusted workstation:

```sh
opaque-approver list --state-dir /trusted/operator/opaque-staging-approver
opaque-approver review \
  --state-dir /trusted/operator/opaque-staging-approver \
  --approval-id APPROVAL_UUID
```

The human checks repository/workflow, exact commit and workflow hash, immutable
artifact, `staging`, one dispatch, expiry and uncertain-outcome meaning, then
completes native authentication. Separately, the configured independent GitHub
environment reviewer completes the provider-side review. A displayed window,
test signature or enrollment alone is not an approval result.

```sh
opaque --socket /run/opaque/opaqued.sock --json task reconcile TASK_UUID
opaque --socket /run/opaque/opaqued.sock task show TASK_UUID
```

Retain sanitized evidence of `paired_workstation` approval, one consumed slot,
exact GitHub run correlation and terminal smoke result. Provider acceptance and
workflow success are distinct. Success proves only `/usr/local/bin/opaque
--version` in the approved artifact, not service health or rollout. An unknown
dispatch remains consumed even if later workflow evidence arrives; do not create
a replacement task merely because the first response was uncertain.

As the same workload owner, repeat `task run TASK_UUID`; expect denial with no
second broker dispatch. Restart only this live broker through its service
manager, then repeat `task show`, `task reconcile` and the denied replay. Retain
the same slot/run evidence. Reconciliation cannot replenish authority. Stop if
run identity, repeated attempts or workflow evidence becomes ambiguous. Raw
logs, keys, tokens and temporary runtime artifacts remain outside Git.
