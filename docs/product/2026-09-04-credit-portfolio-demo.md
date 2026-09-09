# Credit portfolio assistant: the Opaque security layer

**Status, 4 September 2026:** Gemma and Qwen model choices are live. Public sessions passed aggregate watches, three forbidden-request checks without added source queries, and cleanup. A fresh Gemma default selection also correctly explained application and identity-mismatch rates with the expected units and window. The model choice remains fixed for the session and cannot expand data permissions.

Harborlight Credit Union is a fictional lender. A visitor takes the demo role of a portfolio operations analyst and asks an assistant to monitor synthetic application activity. Opaque authorizes a small set of customer-bound aggregate reads, keeps the source credential on the server, and supplies evidence for the answer. The analyst can inspect what was allowed and why a broader request was denied.

The product proposition is concrete: **give a customer an AI assistant that can answer useful questions within the data access that customer has been granted.** The application remains conversational; the authority remains in the gateway, token admission and source mapping. A model proposal cannot change the customer, credential, permitted metrics or destination.

## Why this scenario fits the market

Experian's 2 June 2026 announcement describes an Agent Operating System within Ascend and identifies portfolio monitoring and reporting among lending workflows, alongside access control, governance and human oversight. This is evidence of demand for governed financial-services agents, not evidence of Experian's internal implementation or a connection to Opaque. [Experian announcement](https://www.experianplc.com/newsroom/press-releases/2026/experian-brings-trusted-agentic-ai-to-financial-services-with-th).

Ascend's public product page includes portfolio risk management, analytics and an AI chatbot. Experian Assistant describes natural-language exploration of data and analytical support. Our inference is that a customer-facing portfolio assistant is a recognizable demonstration for this audience. Opaque's small aggregate demo does not reproduce these products or their lending capabilities. [Ascend](https://www.experian.com/business/products/ascend), [Experian Assistant](https://www.experian.com/business/products/experian-assistant).

## The demonstration

Start with “Watch my manual review rate live.” The assistant proposes a bounded aggregate query, Opaque checks it, and the UI shows changing values with units, history window, timestamps and source evidence. An identity-mismatch indicator is a synthetic operational signal, not a finding of fraud or an individual's identity status.

| Request | Intended result | What the visitor learns |
|---|---|---|
| Application rate | Allowed: `credit_applications_per_minute` | Useful customer-specific activity without borrower records. |
| Manual review rate | Allowed: `manual_review_rate_percent` | An approved aggregate can be monitored and explained. |
| Identity mismatch rate | Allowed: `identity_mismatch_rate_percent` | Different metrics require their own permission. |
| Average credit score | Denied for this demo grant: `average_credit_score` | A plausible business question does not expand the grant. |
| Borrower names, SSNs or raw applications | Denied | The tool has no raw-record capability. |
| Another lender's portfolio | Denied | Chat cannot choose a different customer or source. |

Close by inspecting the policy trail and ending the session. The visible story is an allowed answer, an enforced boundary, and evidence for both. Do not describe the result as a loan approval, underwriting recommendation, fraud determination or validated causal explanation.

## Claims the implementation must support

- A verified, admitted access token binds the customer and scopes. The process is configured for one tenant; every MCP query checks that authority. The source mapping is trusted configuration, and returned evidence must match the authorized tenant and requested metrics.
- The browser holds an opaque session cookie. The chat service holds the access token; a separate server-side credential authenticates the aggregate source. Neither credential is part of the model's tool arguments, browser response or metric evidence.
- Only bounded metric names and a rolling window reach the aggregate tool. Unknown arguments, tenant overrides, URLs, SQL, source credentials, raw rows and writes are rejected. The model's proposed tool call undergoes server validation.
- Read permission and metric scopes control source access. Streaming and disclosure to the configured model require their separate scopes. Expiry and revocation are checked throughout the answer; authorized aggregate evidence and the question may reach the trusted model.
- Explicit unsupported questions receive early, clear denials. This natural-language check improves feedback; the aggregate-only schema and server authorization are the security boundary. A phrase matcher cannot prove arbitrary prompt-injection resistance.
- The policy trail reports observed gateway decisions. Display “source not accessed” only for a denial that the runtime verified occurred before access, and “source accessed” only after validated evidence returned. A timeout, generic error or missing event does not prove no access. Local evidence hashes and audit files are not independent signatures or tamper-proof receipts.

## Hard boundaries and acceptance evidence

All portfolio data and identities are synthetic; Harborlight is fictional and unaffiliated with Experian. Bot verification admits a temporary visitor. The demo's OAuth issuer and assigned role do not verify employment, a real customer organization, production SSO or a real financial-data entitlement. No production credit bureau or warehouse is connected, and visitors should not enter private information.

Each workspace has a ten-minute lease and at most twelve questions. Queue, concurrency, cleanup and uncertainty accounting remain service-controlled. Session resources and credentials are separated; the model is a shared trusted processor. This demonstrates application authorization, not a TEE, confidential inference, microVM execution, GPU-memory isolation or proven cross-network isolation. It makes no FCRA or other regulatory-compliance claim.

The public manual-review watch issued five source queries and displayed a 60-second aggregate representing 491 samples: approximately 20.3666%, explained by Gemma as 20.37 percent. Subsequent borrower-record, foreign-customer and average-credit-score questions displayed `raw_records_denied`, `customer_scope_denied` and `metric_scope_denied`. The source query count remained five after all three. Each denial reported no source access at that denied check. These values describe a particular synthetic observation.

The following combined query returned 696 apps/min and 5.3161% identity mismatch from the source, while Gemma incorrectly used req/s for the application rate in its explanation. This is why the numeric evidence and its units remain essential. Providing the actual metric units to the model corrected a local real-Gemma retest: 169 apps/min, 3.55% identity mismatch and a 60-second window were explained correctly. That fix is deployed; the earlier error remains part of the record. The first credit session's cleanup was confirmed at 20:36 MDT with no lease resources remaining and retained generation 8.

The new Qwen3.5 4B packaged runtime also passed the three early denials, a combined application/identity query and a five-result manual-review watch. The public queue now offers a fixed choice of Gemma or Qwen; the choice cannot change customer or data permissions. These few successful checks do not establish a model-quality ranking. The [model catalog](2026-09-04-demo-model-catalog.md) records exact artifacts, observed memory and qualification limits.

The local suite separately validates strict tool arguments, source/tenant rejection and continued streaming-scope enforcement. Narrow inspection of the two successful local model payloads found no Authorization field, source-key environment-variable name or JWT-shaped string; that is not a universal credential-absence proof. Live revocation during streaming and an independent two-visitor handoff remain unverified here. Keep allowed metric values distinct from model prose, which may omit context or make mistakes. Operator details are in `deploy/hosted-demo/CREDIT-VALIDATION.md`.
