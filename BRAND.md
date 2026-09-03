# Opaque — brand

The point of this file is that the next redesign starts from here instead of
from scratch. The first landing page carried a slogan that was lost when the
site moved to MkDocs, because it lived only in one HTML file on an unmerged
branch. It is written down now.

## The slogan

> **Secrets stay ███████. Agents stay powerful.**

Two lines, in that order, always. The first line makes the promise and then
performs it: the word `secret` is present in the markup — screen readers and
search engines read "Secrets stay secret" — and a redaction bar covers it. The
second line is the reason anyone tolerates the first: the point is not to lock
the agent out, it is to keep it useful without handing it the values.

Do not paraphrase it into "Secrets stay hidden" or "Agents stay productive".
Do not use line one alone; half the slogan is an unfinished argument.

Where it lives: the landing hero (`docs/overrides/home.html`), `README.md`,
`docs/index.md`, and `site_description` in `mkdocs.yml`.

## The redaction motif

Redaction is the one visual idea. It appears in three forms, and nothing else
in the design competes with it:

| Form | Where | Class |
|---|---|---|
| Bar covering a word | Hero slogan | `.op-redacted` — the bar wipes across in 0.55s and stays |
| Word readable on a redaction ground | Emphasis in headings | `.op-redact` |
| `████` inline blocks | Terminal transcripts, prose | `.t-mask`, or literal block characters |

The bar is drawn in `--op-redact-bg`: warm cream on the graphite ground, near-
black on the paper ground — a censored document in both directions. It never
animates on `prefers-reduced-motion`; it is simply already there.

## Type and color

The tokens in `docs/stylesheets/extra.css` are the source of truth; this is the
short version.

- **Type:** Archivo (300/400/700) for everything, IBM Plex Mono for code,
  commands, and machine output. Headline tracking is negative (`-0.028em` at
  hero size), body is not.
- **Ground:** graphite `#0f1317` (dark) / warm paper `#f7f6f2` (light). Both are
  designed; neither is a fallback for the other.
- **Accent:** one amber "seal" — `#d9a544` on graphite, `#7a5504` on paper.
  Used for links, stage labels, and approval markers. If something needs a
  second accent, it usually needs less emphasis instead.
- **Semantic:** green reads as verified (`Audit chain intact`), never as
  decoration.

## Voice

- Lead with the threat model, not the feature list.
- Name the pipeline in its own terms: Policy → Approval → Execute → Sanitize →
  Audit.
- Never write "secure" without saying how, and never claim a guarantee the
  daemon does not enforce. The threat model is stated honestly on the site,
  including what session mode does *not* prevent — that honesty is the brand.
- Monospace for anything a machine reads: commands, config keys, refs, IDs.
