# Review public GitHub CI with bounded inference

Plan three model requests using a real, broker-captured sample of GitHub Actions
runs. This adapter is implemented in source; it requires a broker built with this
change and an operator-configured tenant and llama.cpp service.

```sh
opaque task plan-inference --title "Review public GitHub CI" --expires-in-secs 600
opaque task show <task-id>
opaque task run <task-id>
opaque task show <task-id>
```

The plan captures up to three recent runs from one public repository, numeric
workflow ID and branch. It includes run IDs, attempt numbers, commit hashes,
statuses, conclusions and observation time. The exact snapshot, prompt hashes,
model identity and source configuration are bound to the reviewed task. There
are no custom prompts, repository content, commit messages, CI logs or private
repository credentials in this source path.

## Configure the source

In the broker's existing `[inference]` configuration, replace the synthetic
`source_id` and remove `source_snapshot_sha256`. Add the nested source table:

```toml
[inference]
# Retain your verified profile_id, api_url, model_id, model_path,
# model_artifact_sha256, chat_template_sha256, server_build, service_uid,
# credential_ref and allow_loopback_http settings.
source_id = "github-ci-v1"

[inference.github_ci]
repository = "your-organization/your-public-repository"
workflow_id = 123456789
branch = "main"
```

The example ID is a placeholder; find the actual workflow ID in GitHub's
[workflow listing API](https://docs.github.com/en/rest/actions/workflows#list-repository-workflows).
This is a source fragment, not a complete broker configuration. The existing
tenant enrollment, trusted model profile, identity and complete-review policies
for `inference.fixed_manifest` and `inference.fixed_completion` remain required.
Policies can bind the profile ID/digest, tenant, model and `source_id`. The
profile digest includes the repository, workflow and branch.

The broker calls `https://api.github.com` anonymously with redirects and proxies
disabled. It requires a public repository response and matching repository,
workflow and branch identifiers on every run. No configurable GitHub endpoint or
ambient GitHub token is used. Rate limits, unavailable evidence, malformed data or
oversized responses fail planning explicitly. The result is a bounded sample,
not a claim that all workflow history was traversed. See GitHub's
[workflow-runs contract](https://docs.github.com/en/rest/actions/workflow-runs).

## Review and execution

Policy and tenant checks precede source capture. Planning sends the captured
public prompts to the configured model's template/tokenizer endpoints to check
the existing 512-input-token limit; it does not generate completions. This
preprocessing discloses the public snapshot to that provider before human
execution approval. A future private-source adapter would need a different
disclosure gate.

Trusted review shows the complete three prompts and their source observations.
Execution requires the unchanged profile and source snapshot, then rechecks
model metadata, current authority and the single-use allowance. Each attempt
reserves 96 output tokens. Timeouts and contract violations remain charged and
stop subsequent requests. Neither the metadata API nor model output proves
model-file bytes, GPU time, cancellation, deployment or service health.

The captured observation is immutable. `task show` displays that observation;
it does not claim the runs are still in the same state. New evidence requires a
new plan and review. Raw `task plan` requests cannot inject a GitHub snapshot;
use `task plan-inference`, which accepts only a title and expiry.

Legacy synthetic profiles remain supported under `opaque-public-receipts-v1`.
The optional snapshot field preserves old schema-3 serialization. Old binaries
reject GitHub tasks rather than silently treating them as synthetic evidence.

## Validate the actual source without a model

```sh
cargo run --locked -p opaque-bounded-work --example capture_public_github_ci -- \
  your-organization/your-public-repository 123456789 main
```

This read-only diagnostic uses the production source adapter. It captures no
credentials and grants no task authority. Source validation alone does not
qualify the model service or prove a successful approval/execution ceremony.
