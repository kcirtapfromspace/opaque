# Try the portfolio demo

Ask an AI assistant about a fictional credit union’s application portfolio, then inspect the permission checks and source evidence behind its answer.

[Request a demo](https://demo.opaque.info/)

## Get your workspace

1. Choose an available model, complete the bot check and request a demo. No account or email address is required.
2. If there is a wait, the page shows **your queue position**. Keep the page open or return in the same browser.
3. Open the workspace when the service reports that it is ready. The countdown shows your session’s deadline.
4. End the session when you finish, or let it expire. The page shows cleanup separately from active access.

A session lasts **10 minutes** and allows up to **12 questions**. Reopening the workspace does not extend it. Your selected model stays fixed for the session; changing models requires a new session. Model choice does not change your data permissions.

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

## Use synthetic information only

All application events and metric values are synthetic. The demo contains no real borrower identities, credit scores or lending decisions. The model receives your question and permitted aggregate evidence. Source credentials and access tokens stay with the service.

Do not enter private customer information, credentials or production data. The demonstration shows scoped application permissions and observable results; it does not establish confidential inference, hardware isolation or regulatory compliance. Harborlight, Northstar and Cedar are fictional organizations.
