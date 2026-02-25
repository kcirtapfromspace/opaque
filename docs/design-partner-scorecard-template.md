# Opaque Design-Partner Scorecard Template

Date: 2026-02-25
Owner: PO (program), GTM (execution), ENG (technical follow-up)

Use one scorecard per partner account and update weekly.

## 1. Partner Profile

- Partner name:
- Primary contact:
- Segment fit (`AI-native startup team` / other):
- Team size:
- Current secret stack (Vault/1Password/Bitwarden/GitHub/GitLab/etc):
- Agent stack (Claude Code/Codex/other):
- Start date:

## 2. Qualification Rubric (Pass/Fail)

- Uses coding agents weekly in production-adjacent workflows.
- Has at least one CI/CD secret-write workflow to improve.
- Can commit to weekly 30-minute feedback cadence for 4 weeks.
- Willing to share sanitized evidence of baseline vs Opaque workflow outcomes.

## 3. JTBD and Baseline

- Primary JTBD (pick one): safe GitHub secret sync / safe GitLab variable sync / sandboxed command execution / mixed.
- Baseline workflow summary (before Opaque):
- Baseline pain points (top 3):
- Baseline risk concerns (top 3):
- Baseline time-to-complete workflow (minutes):

## 4. Weekly Adoption Scorecard

### Week:

- Active this week (`yes`/`no`):
- Number of Opaque-backed operations executed:
- Number of distinct workflows completed with Opaque:
- Time-to-first-successful-secure-operation (minutes):
- Blocking incidents (count):
- Policy/approval friction notes:
- Any secret exposure incident observed (`yes`/`no`, details):

### Weekly Sentiment (1-5)

- Security confidence:
- Developer speed impact:
- Setup clarity:
- Reliability:
- Overall "better than baseline":

## 5. Evidence Log

- Workflow evidence links (audit screenshots/log snippets, sanitized):
- Before/after comparison notes:
- Concrete quote from partner ("what improved", "what is still hard"):

## 6. Decision and Actions

- Partner status (`healthy` / `at risk` / `inactive`):
- Top blocker to resolve next week:
- Product action owner (`ENG`/`SEC`/`GTM`/`PO`):
- Due date:
- Escalation needed (`yes`/`no`):

## 7. Program-Level Weekly Rollup (Across Partners)

- Active partners this week:
- Partners with weekly production usage:
- Median time-to-first-successful-secure-operation:
- Percentage reporting "materially better than baseline" (>=4/5):
- Open critical blockers count:
- Go/no-go signal for alpha->beta progression:

## 8. Exit Criteria (Per Partner)

- 4 consecutive weeks of active usage.
- At least one production-relevant workflow repeated successfully.
- No unresolved critical safety/regression issue.
- Partner confirms Opaque is materially better than baseline.
