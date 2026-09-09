# Fixed public-data inference adapter

This adapter implements the initial synthetic-data demonstration. It does not
implement datasource OAuth, warehouse queries, private document retrieval, or
shared-server tenant isolation. The broker selects the tenant and model profile;
the agent supplies neither an endpoint nor model options.

`InferenceProfileConfig::bind` adds the broker's persisted `TenantBinding` at
runtime. The profile digest covers that binding, endpoint, credential reference,
reported server/model identities, template hash, and exact public source
snapshot. `public_demo_manifest` constructs three actions from this profile.
`prepare_inference_manifest` validates the entire offered manifest and rejects
changed authority; it does not repair or overwrite a mismatched request.

The source snapshot is SHA-256 over the canonical JSON array of the three
compiled public prompts. Each action also binds its exact prompt digest and
ordinal. Only this known source is supported by this adapter. The core fields
`source_id` and `source_snapshot_sha256` provide a binding for later governed
sources; they do not establish that a datasource authorization flow exists.

## Provider requests

The client disables redirects, proxy inheritance, and automatic retries. HTTPS
is required except for explicit trusted loopback configuration, suitable for a
fixture or operator-controlled tunnel. It never sends a request to an endpoint
from an agent-supplied manifest.

1. Read `/health`, `/props`, and `/v1/models`. Require one ready model matching
   the configured model name, path, build string, template hash, and one server
   slot with sufficient context.
2. Apply the server's chat template to one compiled public user message, then
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
Planning may send **only these compiled public prompts** to the template and
tokenizer endpoints. Any future private-source preprocessing must happen after
approval, reservation, and live authorization because preprocessing also sends
data to the provider.

The protocol was checked against the official
[server documentation](https://github.com/ggml-org/llama.cpp/blob/268d61e/tools/server/README.md),
including template application, tokenizer options, and token-array completion
prompts. The documented prediction ceiling has a UTF-8 caveat; the corresponding
[server implementation](https://github.com/ggml-org/llama.cpp/blob/268d61e/tools/server/server-context.cpp)
checks its remaining token budget during generation. This source comparison is
not proof of the bytes currently running on the discovered cluster.

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
and service UID are operator-attested profile metadata. The discovered Gemma
service had an empty model digest and mutable host-mounted weights/executable.
No live generation or tokenizer request has been performed by this work.

## Local evidence

Nine provider fixture tests cover the exact request body and output receipt,
scope/digest/credential tampering, delayed final-gate denial, tokenizer overflow,
model drift, 4xx/408/5xx/redirect accounting, malformed/overrun/unsafe output,
deadline uncertainty, and trusted profile restrictions. The fixtures use no
live credentials and perform no cluster operations.
