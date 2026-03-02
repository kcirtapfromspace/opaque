# Opaque — Brand Identity Kit

> "What is hidden stays hidden."

## 1. Logo — The Redacted-Data Mark

The Opaque logo is a rounded rectangle containing three horizontal bars of decreasing opacity — a visual metaphor for redacted data. It signals that information passes through Opaque but is never revealed.

**SVG (32 x 32):**
```svg
<svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
  <rect x="2" y="2" width="28" height="28" rx="7"
        fill="rgba(59,130,246,0.08)"
        stroke="rgba(139,92,246,0.5)" stroke-width="1.2"/>
  <rect x="7" y="9"  width="18" height="3.5" rx="1.75" fill="#e8ecf1" opacity="0.7"/>
  <rect x="7" y="15" width="13" height="3.5" rx="1.75" fill="#e8ecf1" opacity="0.4"/>
  <rect x="7" y="21" width="9"  height="3.5" rx="1.75" fill="#e8ecf1" opacity="0.18"/>
</svg>
```

**Usage rules:**
- Always display on dark backgrounds (`#0a0c10` or darker).
- Minimum size: 24 px. Preferred: 28–32 px in headers.
- Do not rotate, recolor, or add drop shadows.

---

## 2. Color Palette

### Core

| Token          | Hex        | Usage                          |
|----------------|------------|--------------------------------|
| `--bg-deep`    | `#050709`  | Deepest background, overlays   |
| `--bg`         | `#0a0c10`  | Page background                |
| `--surface`    | `#0f1218`  | Cards, code blocks             |
| `--surface-hi` | `#161a22`  | Elevated surfaces, hover       |
| `--border`     | `#1c2028`  | Default borders                |
| `--border-hi`  | `#2a2f3a`  | Active / hover borders         |

### Text

| Token          | Hex        | Usage                          |
|----------------|------------|--------------------------------|
| `--text`       | `#e8ecf1`  | Primary body text              |
| `--text-sec`   | `#8b919e`  | Secondary / supporting text    |
| `--text-dim`   | `#555b67`  | Dimmed labels, captions        |

### Accent Triad

| Token          | Hex        | Usage                          |
|----------------|------------|--------------------------------|
| `--accent-1`   | `#3b82f6`  | Blue — links, primary actions  |
| `--accent-2`   | `#8b5cf6`  | Violet — secondary accents     |
| `--accent-3`   | `#06b6d4`  | Cyan — tertiary highlights     |

**Gradient:** `linear-gradient(135deg, #3b82f6, #8b5cf6, #06b6d4)`
Used on CTAs, headings, and decorative accents.

### Semantic

| Token          | Hex        | Usage                          |
|----------------|------------|--------------------------------|
| `--green`      | `#10b981`  | Approved, success, safe        |
| `--green-dim`  | `#059669`  | Quiet success indicators       |
| `--amber`      | `#f59e0b`  | Warnings, pending              |
| `--red`        | `#f43f5e`  | Denied, errors, destructive    |

### Redaction

| Token          | Hex        | Usage                          |
|----------------|------------|--------------------------------|
| `--redact`     | `#2a2f3a`  | Redacted block background      |
| `--redact-hi`  | `#353b48`  | Highlighted redaction block    |

---

## 3. Typography

| Role      | Family            | Weight   | Size (landing)    |
|-----------|-------------------|----------|-------------------|
| Headings  | Inter             | 700–900  | 36–72 px          |
| Body      | Inter             | 400–500  | 15–17 px          |
| Code      | JetBrains Mono    | 400–600  | 13–15 px          |
| Mono UI   | JetBrains Mono    | 500      | 13 px             |

**Letter-spacing:** Body text uses `-0.01em` tracking. Section labels use `0.15em` uppercase tracking.

---

## 4. Visual Language — 9 Principles

### 4.1 Opacity as Language
Opacity levels communicate information hierarchy. Full opacity = visible/approved. Fading opacity = hidden/redacted. The logo itself embodies this: three bars fading from 70% to 18% opacity.

### 4.2 Redaction Motif
Inline `████` blocks (styled with `--redact` background and `color: transparent`) appear throughout the design to represent censored data. They reinforce the core promise: secrets never leak.

### 4.3 Film Grain Noise
A full-viewport SVG noise overlay (`feTurbulence`, `baseFrequency: 0.8`, 4 octaves) at ~3% opacity with `mix-blend-mode: overlay`. Creates a subtle analog texture that makes the digital feel tangible and slightly obscured.

### 4.4 CRT Scanlines
A `repeating-linear-gradient` of 2 px transparent / 2 px semi-black stripes at low opacity. Adds a retro surveillance-monitor aesthetic without impacting readability.

### 4.5 Blur-Reveal Animation
Content blocks start with `filter: blur(8px); opacity: 0; translateY(20px)` and transition to clear on scroll (IntersectionObserver, `threshold: 0.15`). Secrets "declassify" as the user scrolls — on-brand interaction.

### 4.6 Glassmorphism / Frosted Surfaces
Cards and containers use `backdrop-filter: blur(20px)` with semi-transparent backgrounds (`rgba(15,18,24,0.6)`). Borders are 1 px with low-opacity white or brand colors. Creates layered depth.

### 4.7 Mesh Background
Three large blurred color orbs (accent-1, accent-2, accent-3) positioned behind content with `filter: blur(140px); opacity: 0.1`. They float with a 25-second ease-in-out animation, creating gentle ambient color movement.

### 4.8 Grid Overlay
A subtle 80 px grid of near-invisible lines (`rgba(255,255,255,0.012)`) masked with a radial gradient. Adds structure without visual clutter.

### 4.9 Frosted Dividers
Section breaks use a 1 px line styled as `linear-gradient(90deg, transparent, var(--border-hi), transparent)`. Light, elegant, barely there.

---

## 5. Component Patterns

### Buttons
- **Primary:** Gradient fill (accent-1 → accent-2), white text, `0 0 24px` blue glow, lifts 1 px on hover.
- **Ghost:** Transparent with 1 px border (`--border`), lightens on hover.

### Cards
- Background: `rgba(15,18,24,0.5)` with `backdrop-filter: blur(20px)`.
- Border: 1 px `--border`, shifts to `--border-hi` on hover.
- Radius: 12 px (`--radius`).
- Optional gradient top-line (3 px accent gradient).

### Badges / Chips
- Pill-shaped (`border-radius: 100px`).
- 1 px border, accent-tinted background at 6% opacity.
- 13 px text, 500 weight.

### Code Blocks
- Background: `--surface` (`#0f1218`).
- 3 px gradient top-line (accent triad).
- JetBrains Mono, syntax highlighting uses brand colors.
- Copy button in top-right corner.

### Tables
- Header row: `--surface-hi` background, uppercase, dimmed text.
- Alternating rows: subtle `rgba(255,255,255,0.01)` stripe.
- Border-collapse with 1 px `--border` separators.

---

## 6. Voice & Tone

### Brand Voice
- **Precise** — no fluff, no hand-waving. Every word earns its place.
- **Quiet confidence** — Opaque doesn't shout. The architecture speaks.
- **Technical-first** — written for engineers who build with AI daily.
- **Zero-knowledge framing** — we talk about what the LLM *doesn't* see.

### Taglines
- Primary: *"Zero-Knowledge Secrets Broker for AI Agents"*
- Supporting: *"LLMs get operations, never raw values."*
- Motto: *"What is hidden stays hidden."*

### Copywriting Rules
1. Lead with the threat model, not the feature.
2. Use concrete pipeline terms: Policy → Approve → Execute → Sanitize → Audit.
3. Prefer monospace styling for technical nouns (env vars, commands, config keys).
4. Never say "secure" without saying *how*.
5. Use `████` redacted blocks as visual punctuation in marketing copy.

---

## 7. Deployment Map

| Asset              | Location             | Hosting             |
|--------------------|----------------------|---------------------|
| Landing page       | `landing/index.html` | Cloudflare Pages    |
| Brand kit          | `landing/BRAND.md`   | Repository          |
| Documentation      | `docs/`              | GitHub Pages        |
| Docs CSS overrides | `docs/stylesheets/`  | GitHub Pages        |
| Docs template      | `docs/overrides/`    | GitHub Pages        |
| MkDocs config      | `mkdocs.yml`         | Repository          |

---

## 8. License

Apache-2.0 — displayed in the landing page footer and repository root.
