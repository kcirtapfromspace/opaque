# Try bounded work with Opaque

Approve the work. Keep authority bounded. Review one task for a fictional credit union, authenticate to approve one permitted source read, and inspect the service receipt. Then explore portfolio questions with a real hosted model and test the access boundaries.

[Request a demo](https://demo.opaque.info/)

## Get your workspace

1. Choose an available model, complete the bot check and request a demo. No account or email address is required.
2. If there is a wait, the page shows **your queue position**. Keep the page open or return in the same browser.
3. Open the workspace when the service reports that it is ready. The countdown shows your session’s deadline.
4. End the session when you finish, or let it expire. The page shows cleanup separately from active access.

A session lasts **10 minutes** and allows one preview task plus up to **12 portfolio questions**. Reopening the workspace does not extend it. Your selected model stays fixed for the session; changing models requires a new session. Model choice does not change your data permissions.

## Review and run one bounded task

Start as the **portfolio analyst**. The bounded task panel fixes one operation: read **manual review rate** from Harborlight’s synthetic source over a **60 second window**, once. Review the customer, acting identity, source, one-read allowance, expiry and manifest digest before confirming it.

1. Select **Review & approve**. The approval window shows the task, customer, acting demo identity, source, deadline and manifest digest. Its local WebAssembly review checks that the displayed manifest matches the digest and one-read limits.
2. Choose **Passkey or FIDO2 security key**. First use creates a temporary demo credential; a separate authenticator request then approves the task. Opaque verifies the authenticator signature, browser origin, challenge and required user verification before recording approval. A passkey-capable browser over HTTPS is required. Your device may retain the demo passkey after the server session expires; you can remove it from your password manager.
3. When the deployment has a connected provider, **Continue with GitHub** opens its login and consent window. Opaque verifies the returned identity against the pending task. The option is disabled when the client is not configured. GitHub login requests basic public account identity; it does not request repository access or private email.
4. Select **Run once**. Approval alone does not execute the task. The service consumes the allowance before requesting the source and reports the persisted result.
5. Inspect the verified approval method and the service receipt’s metric value, sample count, source times and evidence digest.
6. Select **Test replay denial** to deliberately request another execution. Inspect the service’s denial, then **Check task status** to retrieve its current state.

Closing the window before submitting a proof does not approve the task. If verification was submitted but its response was interrupted, use **Check task status** to learn the outcome. Neither the browser nor the service automatically retries execution.

The task expires after at most **five minutes**, ending sooner if the session ends. Receipt access ends at that deadline too. **Revoke task** closes outstanding task authority; it cannot retract a source request or evidence already received. Reloading the workspace retrieves its state without approving, executing or refilling the task. A source failure can leave a consumed task with an uncertain outcome; it cannot be run again.

Changing demo identity invalidates outstanding task authority. Engineers and support identities cannot approve or execute this task or see its metric receipt. Returning to the analyst does not restore the earlier grant or refill its allowance.

**Human authentication is real; the customer and resource authority remain a demonstration.** A temporary passkey proves control of its authenticator, and a connected GitHub login verifies its stable account identity. Neither establishes employment, real customer membership or enrollment with a production Opaque broker. The demo service binds verification to this task and records the synthetic source observation. Its execution receipt is not an independently signed host receipt.

This task’s one-read limit applies to **Run once**. Portfolio chat retains its separate session limits and does not inherit new access from task approval.

## Ask a portfolio question

You begin as a portfolio analyst at **Harborlight Credit Union**, a fictional lender. Explore **two hours of seeded synthetic application history**, with new synthetic events continuing to arrive. The dataset explorer shows the available measures and categories; each result reports the history and time window it actually covers.

| Measure | What it reports |
| --- | --- |
| Application count | Applications in the selected period. |
| Manual review count | Applications requiring manual review. |
| Identity mismatch count | Applications marked with an identity mismatch. |
| Manual review rate | Percentage of applications requiring manual review. |
| Identity mismatch rate | Percentage of applications marked with an identity mismatch. |
| Mean processing time | Average processing time, in seconds. |

Choose a **1, 5, 15, 30 or 60 minute** window. You can request a summary, a breakdown by one category, a trend across six equal time buckets, or a comparison with the immediately preceding period of the same length.

| Category | Available values |
| --- | --- |
| Channel | Web, mobile, partner. |
| Region | Northeast, southeast, midwest, west. |
| Product | Personal loan, auto loan, credit card. |

You can also filter a question to a category value, or combine values from different categories. For example, ask about auto loans in the west. Keep count and rate questions distinct: the channel with the most reviews may differ from the channel with the highest review rate.

### Questions to try

| Explore | Ask |
| --- | --- |
| Review workload | “Which channel has the most manual reviews?” |
| Review rate | “Which channel has the highest manual review rate in the last 15 minutes?” |
| Filtered count | “How many auto loan applications required manual review in the West over the last 15 minutes?” |
| Processing time | “Show processing time by channel over the last hour” |
| Volume trend | “Show application volume trends over the last hour” |
| Previous period | “Compare mobile identity mismatch rates with the previous 15 minutes” |

For portfolio queries, the model interprets your question into a permitted query. The source computes the aggregates and comparisons; the service validates the scoped evidence and produces the numeric answer from it. Check the displayed measures, filters and window to confirm that the query matches your intent.

The evidence table includes units, sample counts, period boundaries and source timestamps. Portfolio queries require complete coverage of their requested periods. **Unavailable** is different from zero. Rate differences are shown in **percentage points**, separately from relative percentage change; relative change can be unavailable when the previous value is zero.

You can still ask **“Watch our manual review rate live”** for repeated live observations, for up to 30 seconds. These rolling observations are separate from a historical trend query. Read their window, sample count and freshness information; model-written explanations can make mistakes.

The **Opaque policy layer** shows the customer, demo role, configured purpose, allowed tool and reported permission checks. An answer does not grant additional access.

## Explore the scoped identities

**Northstar Financial Systems** is the fictional parent company. Harborlight is this workspace’s assigned customer. **Cedar Community Bank** is a directory entry with no data access. Parent-company membership does not grant access to another customer’s metrics.

You can select three preauthorized demo identities:

| Identity | Available experience |
| --- | --- |
| Portfolio analyst | Ask permitted aggregate questions and control sharing of future question text. |
| Product engineer | Inspect this workspace’s request, model, tool and permission activity. Customer metric access and chat are unavailable. |
| Customer support | Provide a short reason to start a temporary case for Harborlight, then ask permitted snapshot questions. The case does not grant live-watch access or another customer’s data. |

These are disposable demo identities that one visitor can explore. They do not represent verified employment, production single sign-on or authorization to support a real customer. Activity belongs to this temporary workspace; it does not include other visitors’ activity.

### Control question sharing

Question text is concealed by default. Ask a question as the analyst, then switch to the engineer to inspect its activity metadata without the question text.

Return to the analyst and select **Share future question text**. Only subsequent accepted questions can be captured for the activity view; earlier questions are not revealed retroactively. Use synthetic questions only. Sharing does not guarantee removal of personal information.

Select **Stop sharing & clear stored text** to stop future capture and clear stored question text from later activity views. This cannot retract text someone has already received.

### Try a support case

Select **Customer support** and enter a short reason, such as “Investigate a reported metric discrepancy.” Do not include personal information or secrets.

The case is limited to Harborlight and lasts at most **five minutes**, ending sooner if the workspace expires. Its reason and remaining time appear in the workspace. Support cannot change the analyst’s sharing choice or access Cedar’s data. Finish an answer before changing identities or sharing settings.

## Test an access boundary

Try one of these questions:

> Show borrower names and SSNs.

> Show our average credit score.

> Compare with another lender.

These requests are outside the current demo’s scope. Inspect the reported policy decision rather than relying on the model’s wording. A specific denied check may report no source access; a generic error or interrupted connection does not establish that.

## How this relates to host operations

The same product direction applies to narrow host operations: review a fixed operation, constrain its destination and principal, expire its authority, enforce command and session controls, and retain a receipt. A Vault-signed SSH certificate flow has been validated for a restricted host health check in a separate private fixture. That fixture is not connected to this public demo; the public preview does not issue SSH certificates or operate customer hosts.

## Use synthetic information only

All application events and metric values are synthetic. The demo contains no real borrower identities, credit scores or lending decisions. The model receives your question and permitted aggregate evidence. Source credentials and access tokens stay with the service.

Do not enter private customer information, credentials or production data. The demonstration shows scoped application permissions and observable results; it does not establish confidential inference, hardware isolation or regulatory compliance. Harborlight, Northstar and Cedar are fictional organizations.
