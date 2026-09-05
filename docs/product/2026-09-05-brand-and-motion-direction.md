# Opaque brand and architecture motion

Private design direction · September 5, 2026

## User direction

The user explicitly likes the animations, architecture snippets and design style
of [Oleander](https://oleander.dev/), [ArcBox](https://arcbox.dev/) and
[Google Antigravity](https://antigravity.google/). These are the references for
Opaque's brand and its matching demo experience. The user also proposed showing
glimpses of architecture workflows in real time within the demo.

Treat this as a continuing design preference. The synthesis below is a proposed
translation of that preference, not user approval of every individual token or
layout. Reference pages were inspected on September 5; they can change.

## What to carry forward

| Reference | Observed treatment | Opaque application |
| --- | --- | --- |
| Oleander | Numbered query/routing/result scenes; selectable routing preference; compact code and run metadata; thin grid; playful pixel detail | Explain one bounded operation through a sequence of small interactive architecture scenes, each with a useful snippet. |
| ArcBox | Warm dark surfaces, orange emphasis, large left-aligned type; isometric hero; changing environment cells beside an event trace | Let visitors connect a changing system diagram to an understandable event. Make an authority boundary a recognizable Opaque graphic. |
| Antigravity | Spacious light composition, oversized type, restrained navigation, particle atmosphere and fluid presentation | Give the main message and product demonstrations room. Use staged reveals and subtle depth to focus attention. |

These references share technical specificity and visible behavior. Color alone
will not produce the desired result. Borrow the design principles, while keeping
Opaque's own identity, copy and illustrations.

## Proposed Opaque visual language

**Precise, spacious, quietly alive.** Architecture should be a first-class brand
asset. A request approaches a clearly drawn boundary, receives only the authority
it needs, and returns permitted evidence. A denied request visibly stops at the
relevant check.

- Retain the established redaction motif and amber accent. Explore a warm
  charcoal ground with a coordinated paper theme; treat those as two appearances
  of the same system. Use semantic outcome colors sparingly and with text.
- Use a strong sans-serif for headlines and interface text, with a consistent
  monospace for commands, constraints and evidence. Start from the existing
  Archivo / IBM Plex Mono pairing and assess it visually before replacing it.
- Favor large editorial headings, generous space, fine rules, deliberate
  alignment and small architecture illustrations. Keep snippets short enough to
  read in place. Use disclosure for detailed evidence.
- Build an original boundary/redaction graphic. Opaque's recognizable motion is
  a controlled crossing, a stopped request, and an evidence return. Avoid
  substituting the references' flower, cube or particle brand marks.
- Give the marketing page, demo admission page and workspace the same wordmark,
  type, spacing, color roles, controls and diagram grammar. Harborlight remains
  the fictional customer context inside the Opaque interface.

The existing public site uses graphite/amber and Archivo/Plex. The admission
page uses another dark token set, while the portfolio workspace switches to
pale green and Avenir. Harmonizing these is the first design-system change.
Relevant files: `docs/stylesheets/extra.css`, `docs/overrides/home.html`,
`deploy/cloudflare-demo/public/index.html`, and
`crates/opaque-metrics/static/index.html`.

Keep the existing brand line, “Secrets stay secret. Agents stay powerful.”
Use “Approve the work. Keep authority bounded.” for the bounded task workflow,
consistent with the [product direction](2026-09-05-unified-product-strategy.md).

## Motion as explanation

Use short input feedback, deliberate transitions between states, and one-shot
path highlights when an event arrives. Proposed starting timings are 140–180 ms
for controls and 300–450 ms for diagram transitions. These are design values,
not measurements of any reference page or of Opaque's execution latency.

For a landing-page explanation, illustrative playback can make the flow legible.
Label it as an example and provide a replay control. In the working demo,
advance only on the relevant validated service evidence. Never delay the result
or invent intermediate confirmations to complete an animation. Honor reduced
motion, pause nonessential motion offscreen, and keep the state readable without
animation or color.

## Demo: “Follow this request”

Add a compact architecture view beside the current request, with a readable
vertical layout on small screens. Show the active boundary and a short event
trace together. Selecting a node reveals its role and the available scoped
evidence. Preserve the question and result as the primary workspace content.

There are two actual workflows, with different enforcement paths:

| Workflow | Architecture shown | Current evidence |
| --- | --- | --- |
| Portfolio chat | Request / model tool selection → scoped Opaque MCP boundary → synthetic customer source → validated aggregate evidence → answer | Existing `status`, `policy`, `tool`, `result` / `portfolio_result`, `answer`, `error`, `done` SSE events. Checks occur at multiple boundaries, not only once. |
| One bounded read | Review manifest → visitor confirmation → durable reservation → direct synthetic-source read → service receipt | Public task state (`planned`, `approved`, `reserved`, `completed`, `unknown`, `revoked`, `expired`) and task responses. Execution currently returns JSON rather than streaming every stage. |

The first incremental implementation should reuse the chat UI's validated event
handlers (`receivePolicy`, `receiveResult`, `receivePortfolioResult`,
`handleEvent`) in `crates/opaque-metrics/static/index.html`. Add a small state
projection and a diagram without changing authority or provider access.
`crates/opaque-metrics/src/server.rs` emits these events. The separate bounded
task model lives in `crates/opaque-metrics/src/bounded_demo.rs`.

Map `policy.tool_check` to the reported check, `tool.request` to an attempted
scoped call, and `policy.source_read` / validated results to received source
evidence. A tool request alone does not prove the source was read. Show unknown
or interrupted states without completing downstream nodes. Show no source access
only for a check whose service evidence explicitly reports it.

Do not pretend the bounded-read confirmation is production signed approval, or
its unsigned service receipt is an independently signed host receipt. Do not
route that task through MCP in the diagram: its current implementation reads
the synthetic source directly after reservation. More precise live intermediate
task animation requires additional server events.

`done` means the application answer ended. It does not prove model/runtime
shutdown; that has a separate controller event, `opaque_execution_complete`.
The first view should stay focused on the request rather than claim cluster
lifecycle visibility.

## Acceptance for implementation

- The same design system is recognizable from site to admission to workspace.
- An allowed operation, an explicit denial, and an interrupted request have
  distinct, comprehensible states. All motion has a reduced-motion equivalent.
- Diagram state follows validated current-session evidence, remains inspectable
  after completion, and clears with identity changes or expiry.
- No operator audit feed, internal hostnames, raw prompts from other users,
  credentials, or private deployment records enter the visitor view.
- Existing identity, queue, allowance, expiry, model-choice and task controls
  keep their current enforcement behavior.
- Before any public deployment, inspect generated routes, search, sitemap and
  assets for private content. This document stays under excluded `product/**`.

## Implementation status — September 5, 2026

The source implementation now carries this direction across three surfaces:

- The marketing hero uses an original layered boundary diagram, pixel request
  and evidence sprites, and allowed, denied and interrupted illustrations.
- The admission page uses the same redaction glyph, warm palette and isometric
  architecture language, with independent scenario, pause and replay controls.
- The metrics workspace adds **Follow the work**, driven by validated events
  for the current chat turn. It records reported permission checks, distinguishes
  attempted tool calls from source evidence, and preserves uncertainty after
  interruption. Identity changes and expiry clear its state.

Motion pauses offscreen and in hidden documents, and respects reduced motion.
Marketing and admission scenes are labeled illustrations. The live workspace
does not simulate server milestones or conflate the separate bounded-read path
with portfolio chat. The private motion study remains an illustrative concept.

Validation includes automated event-projection regressions, existing admission
and privacy checks, browser checks against an explicitly labeled local fixture,
and inspection of the generated documentation site for private content.
These source changes have not been deployed to the public demo or running
cluster. Local fixture confirmations are simulated and have no production
connection.
