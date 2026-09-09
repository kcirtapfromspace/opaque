# Demo model catalog and small-model candidates

Research date: **4 September 2026, America/Denver**. Public model cards, small
configuration files, upstream source and publisher artifact metadata were read.
The initial research made no weight downloads, model calls or infrastructure
changes. The operator subsequently qualified Qwen 4B with the packaged runtime
and enabled Gemma and Qwen choices in the public demo. A real public Qwen lease
completed an application/manual-review watch, three denials and verified cleanup.
A fresh public Gemma default selection also completed its combined query with
correct units and window, followed by verified cleanup.

Keep Gemma as the measured baseline and use **Qwen3.5-4B Q4_K_M** as the first
qualified alternative. Qwen3.5-2B Q4_K_M remains a possible lower-memory
comparison. The bounded checks below establish working requests, not a general
quality ranking or a claim that Qwen outperforms Gemma.

## Shortlist and memory budget

| Model | Role and evidence | GGUF download | Planning memory allowance |
| --- | --- | --- | --- |
| Gemma 4 E2B IT, existing Q3_K_M | Known baseline: real credit tool calls have worked, with observed missing-argument and explanation-unit errors. Google documents native function calling and 2.3B effective / 5.1B total parameters including embeddings. | Publisher reference: 2,536,786,016 bytes, **2.363 GiB**. This does not establish the installed file's hash. | Approximately **3.5–5 GiB** for a short-context, single-slot text service; prefer the running service's measured footprint. |
| Qwen3.5-4B, Q4_K_M | Packaged-runtime and public watch/denial checks passed on Jetson 1; enabled as a public choice. Official 4B model with agent/tool-use guidance; 32 layers combine recurrent and full attention. Thinking defaults on and is explicitly disabled for this bounded demo. | **2,740,937,888 bytes / 2.553 GiB**, downloaded and hash-verified by the operator. | Original allowance **3.5–5 GiB**. Configured request **4 GiB**, limit **5,500 MiB**. Observed cgroup peak **4,239,224,832 bytes / 3.948 GiB** during these checks; not a future peak guarantee. |
| Qwen3.5-2B, Q4_K_M | Memory fallback. Official card defaults to non-thinking and describes its intended scale as prototyping, task-specific tuning and development. Tool reliability must be measured independently. | 1,280,835,840 bytes, **1.193 GiB**. | Approximately **2–3.5 GiB**, with a **4 GiB** initial reservation target if available. Untested on this cluster. |

Model characteristics and licenses come from the official
[Gemma E2B card](https://huggingface.co/google/gemma-4-E2B-it),
[Qwen 4B card](https://huggingface.co/Qwen/Qwen3.5-4B) and
[Qwen 2B card](https://huggingface.co/Qwen/Qwen3.5-2B). All three repositories
currently label their public, ungated weights **Apache-2.0**. No third-party
leaderboard comparison or model-card benchmark is treated as a Jetson result.

Estimated memory ranges above are **engineering allowances, not fit guarantees**;
the Qwen row separately identifies an observed peak. Estimates assume text only,
one sequence, 2,048–4,096 tokens, conservative
batching and no multimodal projector. They add room beyond the weight bytes for
CUDA/runtime allocations, compute buffers, attention cache and recurrent state.
Using the official attention dimensions, an F16 conventional K+V cache alone
is roughly 64/128 MiB at 2K/4K for Qwen 4B, and 24/48 MiB for Qwen 2B. Recurrent
state and implementation buffers are additional; these cache calculations are
not total inference memory. [4B configuration](https://huggingface.co/Qwen/Qwen3.5-4B/blob/851bf6e806efd8d0a36b00ddf55e13ccb7b8cd0a/config.json),
[2B configuration](https://huggingface.co/Qwen/Qwen3.5-2B/blob/15852e8c16360a2fea060d615a32b45270f8a8fc/config.json).

The operator reports three Jetsons with **7,264,312 KiB, approximately 6.93 GiB,
allocatable memory each** and six CPU cores. This is allocatable capacity, not
currently free memory. The original placement used Gemma on Jetson 3 and
Qwen3-14B Q4_K_M with a head on Jetson 1 and RPC workers on 2 and 3. The operator
found the old head stalled with RPC not listening, backed it up and scaled only
that head to zero. Qwen3.5 now uses the released Jetson 1 GPU; RPC workers 2/3
and Gemma were left unchanged. A smaller file does not create spare capacity or imply
safe co-residency. Use an explicit drained replacement/benchmark window rather
than infer spare capacity from the model sizes. Do not adopt the cards' 128K or
262K context limits on an 8 GB node.

## Exact publisher artifacts

These began as **publisher-reported LFS SHA-256 values** from Hugging Face
metadata. The operator has since verified the downloaded Qwen 4B bytes against
the recorded size and hash; the other entries remain publisher references.
Pin the revision and verify downloaded content before use. The GGUF
publisher is Unsloth; the upstream model authors are Google and Qwen.

| Candidate | Pinned file and revision | SHA-256 |
| --- | --- | --- |
| Qwen 4B Q4 | [Qwen3.5-4B-Q4_K_M.gguf](https://huggingface.co/unsloth/Qwen3.5-4B-GGUF/blob/e87f176479d0855a907a41277aca2f8ee7a09523/Qwen3.5-4B-Q4_K_M.gguf), revision `e87f176479d0855a907a41277aca2f8ee7a09523` | `00fe7986ff5f6b463e62455821146049db6f9313603938a70800d1fb69ef11a4` |
| Qwen 2B Q4 | [Qwen3.5-2B-Q4_K_M.gguf](https://huggingface.co/unsloth/Qwen3.5-2B-GGUF/blob/f6d5376be1edb4d416d56da11e5397a961aca8ae/Qwen3.5-2B-Q4_K_M.gguf), revision `f6d5376be1edb4d416d56da11e5397a961aca8ae` | `aaf42c8b7c3cab2bf3d69c355048d4a0ee9973d48f16c731c0520ee914699223` |
| Gemma Q3 reference | [gemma-4-E2B-it-Q3_K_M.gguf](https://huggingface.co/unsloth/gemma-4-E2B-it-GGUF/blob/0314792d7f1f7e229411f620751375812bb9faf2/gemma-4-E2B-it-Q3_K_M.gguf), revision `0314792d7f1f7e229411f620751375812bb9faf2` | `086e2f5ba85057f8f19712e3160a644728f74f323c9feeac4cd73fab11b43085` |

Request only the selected GGUF, not the whole quantization repository. The text
demo does not need the separate vision projector. Allow staging/rollback disk
space beyond the listed download size. Do not assume that a similarly named
file already in the cluster matches this publisher reference.

## llama.cpp compatibility to verify

Upstream revision `4d9176092d00586775af140581bb0b558ddc4389` was inspected. It
contains the [Qwen3.5 model implementation](https://github.com/ggml-org/llama.cpp/blob/4d9176092d00586775af140581bb0b558ddc4389/src/models/qwen35.cpp),
a [Qwen3.5-4B tool-aware template](https://github.com/ggml-org/llama.cpp/blob/4d9176092d00586775af140581bb0b558ddc4389/models/templates/Qwen3.5-4B.jinja),
explicit Qwen3.5 XML tool-format handling and Gemma 4 handling in
[chat.cpp](https://github.com/ggml-org/llama.cpp/blob/4d9176092d00586775af140581bb0b558ddc4389/common/chat.cpp),
and corresponding [parser tests](https://github.com/ggml-org/llama.cpp/blob/4d9176092d00586775af140581bb0b558ddc4389/tests/test-chat.cpp).
This establishes upstream support. Separately, the operator's image below loaded
the Qwen 4B artifact and passed the bounded packaged-runtime checks.

## Operator deployment and qualification status

The dedicated `opaque-models/llama-server-qwen35` service reports **1/1 ready** on
Jetson 1, using `llama.cpp` build **b1-fc6545d**, image
`192.168.25.201:5050/llamacpp-jetson@sha256:d69eef7f2933b3d689f21c893767f05dbdf7bab345c83cbb88e93360a6678bf7`.
It reports **4,205,751,296 parameters**, text-only execution, a 2,048-token context
and one parallel sequence. The model is on an 8 GiB PVC mounted read-only by the
non-root server, without a host mount. The deployment specification is
`deploy/hosted-demo/qwen35-model.yaml`; its checked-in replica count is now **one**
for the qualified deployment. Initial installs must first stage it at zero until
the download and explicit GPU allocation are complete.

The actual Qwen packaged runtime rejected the three explicit forbidden questions
before a source-evidence file existed. A combined allowed request completed in
**14.25 seconds**, returning two results from one source query and correctly
explaining **150.00 apps/min** and **6.67% identity mismatch**. Its prose omitted
the time window; the validated UI evidence retained **60 seconds**. A manual-review
watch completed in **19.23 seconds**, with five results and a final explanation of
**20.47%** over 60 seconds. The final source count was six. These are individual
synthetic observations, not success-rate or latency benchmarks.

Server logs for those four planning/explanation requests reported **10.45–10.80
generated tokens per second**. After the checks, cgroup memory was 3,837,538,304
bytes with a recorded peak of 4,239,224,832 bytes; host `MemAvailable` was
1,002,324 KiB. These observations do not promise memory headroom under other
workloads. Runtime health matched the Qwen profile and actual model name and
reported zero request/model activity with `uncertain: false`; the local runtime
was stopped. A separate Gemma check using the new catalog runtime completed in
8.93 seconds with correct **48 apps/min**, **0% identity mismatch** and a 60-second
window, then was confirmed quiescent and stopped. The runs used different
synthetic observations and are not a controlled speed comparison.

The fixed lease catalog now has `gemma4-e2b`, `qwen35-4b` and the legacy
`qwen3-14b` alias. The last is disabled pending qualification and its old head is
currently stopped; catalog presence is not availability. Qwen 2B is not in this
runtime catalog and has not been downloaded or deployed. The model-choice release
is now deployed, enabling Gemma and Qwen 4B with Gemma as the default. A normal
Turnstile flow selected Qwen at generation 9. Its public application/manual-review
watch returned five snapshots and correct final units, followed by three denials
that left source queries unchanged at five. Cleanup verified resource absence
and retained the Qwen binding at generation 10. A fresh Gemma default selection
at generation 11 correctly explained **627.00 apps/min** and **4.63% identity
mismatch** over a 60-second window. Source evidence disclosed partial initial
coverage of 56 seconds. Its cleanup verified resource absence and retained the
Gemma binding at generation 12. Legacy leases map
explicitly to Gemma, and a lease cannot change its model after admission. See
the operational rollback contract in `deploy/hosted-demo/OPERATIONS.md` before
attempting a binary rollback across the state migrations.

Use `--jinja` and a matching tool-aware template; inspect server properties and
test the actual OpenAI-compatible `tool_calls` response, including stringified
JSON arguments. Qwen 4B's non-thinking control is
`chat_template_kwargs: {"enable_thinking": false}`; verify the resulting prompt
and output rather than rely on a model-name switch. Start with ordinary F16 KV
storage: llama.cpp warns that aggressive cache quantization can harm tool
calling. [llama.cpp function-calling guide](https://github.com/ggml-org/llama.cpp/blob/4d9176092d00586775af140581bb0b558ddc4389/docs/function-calling.md).

## Admission to the demo catalog

Benchmark the same bounded Opaque requests: each allowed metric, the combined
query, all required arguments, no extra authority fields, and explanations that
preserve values, units and window. Include the three early denials and verify
that model/source call counts stay unchanged. Record success counts, first-token
and complete-request latency, output tokens, loaded memory and peak memory.
Treat the few recorded timings above as observations, not estimates for a new
workload. Pin binary, template and model hashes
with the result. Promote only a tested backend; changing a model cannot expand
tenant, source or metric permissions.
