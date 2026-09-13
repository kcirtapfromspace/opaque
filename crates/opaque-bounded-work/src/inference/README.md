# Fixed public-data inference adapter

The broker selects a public GitHub CI source or the legacy synthetic source,
plus the tenant and model profile. The caller supplies a title and expiry, never
an endpoint, repository override, prompt or generation options. Private source
OAuth, warehouse queries and shared-server tenant isolation are not implemented.

`InferenceProfileConfig::bind` adds the persisted `TenantBinding`. The profile
digest binds that tenant, endpoint, credential reference, operator-attested model
identity, template hash and source selection. For `github-ci-v1`, selection means
an exact public repository, numeric workflow ID and branch.

`public_demo_manifest` builds three actions. For GitHub these are planning seeds,
not executable source evidence: `action_prompt` refuses a seed before credentials
or model I/O. After policy preflight, `plan_inference_manifest` captures up to
three typed runs anonymously from the fixed GitHub API, attaches the same snapshot
to each action, and computes the exact snapshot/prompt digests. Full preflight
runs again before persistence. Raw `task_plan` cannot supply a GitHub snapshot.

Only numeric identifiers, commit hashes, bounded labels, enumerated statuses and
conclusions, plus the observation time enter the prompts. Repository text, logs
and titles are discarded. The snapshot is immutable after review; it is a sample
of observed runs, not branch-HEAD, deployment or service-health evidence. The
legacy source keeps its existing digest over the three compiled public prompts.
See [source configuration](../../../../docs/github-ci-inference.md).

## Provider requests

The client disables redirects, proxy inheritance, and automatic retries. HTTPS
is required except for explicit trusted loopback configuration, suitable for a
fixture or operator-controlled tunnel. It never sends a request to an endpoint
from an agent-supplied manifest.

1. Read `/health`, `/props`, and `/v1/models`. Require one ready model matching
   the configured model name, path, build string, template hash, and one server
   slot with sufficient context.
2. Apply the server's chat template to one reviewed public user message, then
   tokenize the formatted prompt. Both responses have bounded sizes. Reject
   empty, invalid, or more than 512 token IDs.
3. Recheck provider identity after asynchronous preparation, then invoke the
   caller's final live policy and durable-dispatch gate.
4. Send one native `/completion` request containing those exact token IDs,
   `n_predict=96`, one completion, greedy temperature sampling, seed zero,
   cache reuse disabled, and streaming disabled. The generated payload is fixed;
   arbitrary tools, LoRA selections, extra samplers, or other request fields are
   not forwarded.

Using token IDs prevents a later implicit string-tokenization step from adding
unaccounted prompt tokens. The generation request has a 30-second client
deadline. Metadata and preprocessing requests have ten-second deadlines.
Planning may send the configured **public snapshot and its fixed questions**
to the template and tokenizer endpoints. Any future private-source preprocessing must happen after
approval, reservation, and live authorization because preprocessing also sends
data to the provider.

The protocol was checked against the official
[server documentation](https://github.com/ggml-org/llama.cpp/blob/268d61e/tools/server/README.md),
including template application, tokenizer options, and token-array completion
prompts. The documented prediction ceiling has a UTF-8 caveat; the corresponding
[server implementation](https://github.com/ggml-org/llama.cpp/blob/268d61e/tools/server/server-context.cpp)
checks its remaining token budget during generation. This source comparison is
not proof of the bytes running on an operator’s model service.

## Receipts and uncertainty

The caller reserves 96 output-token allowance units before each dispatch and
never refunds them from observed usage. Three slots reserve 288 units. A
successful receipt requires matching model identity, complete/non-truncated
response, exact evaluated input count, no more than 96 reported output tokens,
matching returned token count, and the requested prediction limit. It retains
at most 4096 UTF-8 bytes of output, rejects unsafe controls and existing secret
patterns, and stores SHA-256 of the exact retained text. Output is untrusted
data and must be rendered as text.

Definitive 4xx responses except 408 are rejected. Timeouts, connection failures,
5xx responses, redirects, malformed evidence, identity/count mismatches, and
unsafe output cannot establish completion. They consume the attempt without
retry. Raw provider errors and rejected output are not retained. These receipts
describe requested limits and observed responses, not GPU seconds, cost,
server-side cancellation, or an independently enforced compute quota.

The process mutex serializes client attempts. A timeout does not prove the
server stopped computing; the caller must stop remaining task slots after an
unknown result. A new task requires fresh authority. This does not establish
global backend concurrency or cancellation across broker restarts or operators.

The HTTP API does not prove the GGUF or executable hash. `model_artifact_sha256`
and service UID are operator-attested profile metadata. Deployment acceptance
must verify those artifacts separately. Protocol fixtures alone do not qualify
a live generation service.

## Local evidence

Provider fixture tests cover the exact request body and output receipt,
scope/digest/credential tampering, delayed final-gate denial, tokenizer overflow,
model drift, 4xx/408/5xx/redirect accounting, malformed/overrun/unsafe output,
deadline uncertainty, trusted profile restrictions, typed GitHub capture,
snapshot substitution and rejection of uncaptured planning seeds. The fixtures use no
live credentials and perform no cluster operations.
