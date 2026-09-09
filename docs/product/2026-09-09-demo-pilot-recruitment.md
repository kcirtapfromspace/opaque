# Demo contact capture and first pilot recruitment

Private product and operator plan. Exclude from public routes, assets, search,
sitemaps and preview deployments. Contact records, credentials and exports do
not belong in this document or this repository.

The user approved adding an optional contact invitation to the demo and using
it to recruit the first pilot teams. This document defines the initial workflow
and proposed learning experiments. It is not evidence of customer demand.

## Visitor experience

The demo remains usable without an email address. A visitor can request a pilot
conversation while waiting or return to the contact form after a useful result.
The form asks for an email address and an answer to **“What task do you stop
your agent from doing today?”** A separate, initially unchecked consent field
authorizes an email about that workflow and an Opaque pilot. GitHub approval
continues to verify task approval only; it does not enroll a contact.

The form confirms receipt only after private storage succeeds. Failure retains
the entered text for an explicit retry. Contact submission does not reserve a
workspace, alter queue priority, extend a session, or contact a model. There is
no automatic email, newsletter subscription or third-party CRM integration.
Addresses remain unverified until the team establishes contact.

The private record contains the submitted email and workflow, consent version
and timestamps, an allowlisted campaign/referral source, and whether the form
was reached from the workspace result invitation. Campaign and entry-point
fields are browser-reported attribution, not trusted proof of a completed task.
No chat text, GitHub identity, bearer token, raw referring URL or raw IP address
is added to a lead. Referral paths and arbitrary URL parameters are discarded.
The browser retains only bounded attribution metadata, never entered email or
workflow text in browser storage. Records expire from the live inbox after 90 days.
Cloudflare's separate storage recovery history can retain older database states
for 30 days; a live-row deletion is not a claim of immediate removal from that
history. See the [storage API](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/).
Do not restore contact data from a recovery snapshot without reapplying expiry
and honoring deletion requests.

## First customer hypothesis

Recruit hands-on platform or engineering leads whose teams already use coding
agents on GitHub but still manually perform or withhold a specific repository,
CI or release action because available credentials or approvals are too broad.
Security and the resource owner should join a pilot once that workflow is clear.
The synthetic financial portfolio demonstrates controls; it does not establish
financial analysts as the first market.

Qualify a conversation with four questions:

1. What specific task do you stop the agent from doing, and how often is it needed?
2. Who performs or approves it today, and what makes the current process painful?
3. What access would a bounded pilot need, and who owns that resource?
4. What observable result would justify keeping Opaque installed?

Prefer a task the customer already needs repeatedly. A team wanting a general
agent platform without a concrete operation is useful discovery, but not yet a
qualified pilot. These criteria follow the existing unified product strategy.

## Recruitment experiments

Treat **30 relevant teams, 10 conversations and 3 pilot teams** as learning
targets, not forecasts or promised conversions. Do not purchase traffic before
the message and workflow have been tested with these initial conversations.

| Experiment | Preparation and channel | Evidence to record privately |
| --- | --- | --- |
| Warm introductions | Identify matching teams through the founder's network and public engineering posts. Ask for a short conversation about one blocked agent task. | Fit, actual workflow, current manual effort, named resource owner, willingness to evaluate. |
| Technical demonstration | Prepare a short clip showing useful permitted work, a genuinely denied outside-scope request and inspectable evidence. Share in two relevant practitioner discussions where this is welcome. | Tagged source, qualified contact requests, objections and questions. Avoid presenting synthetic task evidence as production enforcement. |
| Assisted pilot | Help one to three teams evaluate one supported recurring operation against their existing process. Define access, success criteria and exit conditions before connecting resources. | Useful tasks completed repeatedly, setup/support effort, manual interventions, reason to continue and purchasing owner. |

Use campaign links with short non-identifying values, for example
`https://demo.opaque.info/?utm_source=founder&utm_medium=introduction&utm_campaign=first_pilots`.
Do not put recipient names, email addresses, company secrets or access tokens in
campaign parameters. Do not infer a visitor's identity from an anonymous session.

The first message should describe the observed problem and ask whether it fits.
An example draft, to personalize only against verified public facts:

> We are working on giving coding agents permission for one reviewed operation
> without handing them broad access. What repository or release task do you
> still keep manual? We have a short synthetic demo and are looking for teams
> to help test one real workflow.

No outreach messages have been authorized for sending by this plan. The user
can review named recipients and concrete messages before a sending action.

## Learning and follow-up

Review new requests manually. Follow up only for the purpose the visitor chose;
an unverified submitted address is not a bulk-mail audience. Track contact →
conversation → qualified workflow → pilot → repeated useful work in protected
operator storage. Do not mistake demo activity, founder-created tasks, or
email count for retained adoption.

The initial implementation records submitted contacts and their attribution;
it does not create a complete traffic analytics system or measure every visit.
Use the campaign results to decide which message merits another experiment.
If teams enjoy the demonstration but will not connect a resource or repeat the
workflow, revise the workflow hypothesis before adding more integrations.

## Private operator access

`scripts/demo_leads.py` reads one bounded page or deletes one lead by ID.
The service uses a dedicated `LEAD_ADMIN_SECRET`, distinct from the controller
credential. The controller cannot read contacts. An unconfigured contact backend
reports unavailable instead of pretending to save submissions.

Keep the admin credential in an owner-only file outside the repository and set
`OPAQUE_LEAD_ADMIN_SECRET_FILE` to its path. Do not paste the token into command
arguments, source, screenshots or logs. The CLI refuses a credential file with
group/other permissions, refuses redirects, and never prints contact details.
Choose a new export filename; exports are created with mode `0600` and existing
files are not overwritten.

```sh
export OPAQUE_LEAD_ADMIN_SECRET_FILE=/Users/thinkstudio/.config/opaque/demo-leads-admin-token
python3 scripts/demo_leads.py list --limit 25 --output /private/tmp/opaque-pilot-requests.json
```

The JSON export contains `leads` and `next_cursor`. Pass the opaque cursor with
`--cursor` to read the next page into another new protected file. Use the record's
`id` with `delete --id` to remove it. A confirmed deletion response is the same
whether the record was present or already absent. Remove local exports when
finished; the service's 90-day expiry cannot remove a downloaded copy.

The tool sends no mail and performs no enrichment. A real CRM or email provider
can be selected later if request volume makes the manual workflow inadequate.
