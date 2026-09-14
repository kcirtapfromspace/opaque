# Certification roadmap

Written 2026-09-14. This document lays out three tracks: product prework
underway now, company certifications to pursue when a deal demands them, and
the federal posture. Dates are planning targets, not commitments; the
principle throughout is to build the artifacts buyers actually ask for before
paying for audits nobody has requested yet.

Context that shapes every decision below: Opaque is a **self-hosted**
product. Customers run the daemon inside their own environment. That means
most of what an enterprise security review or an agency assessment needs from
us is product evidence (control mapping, SBOM, hardening guide, signed
releases, disclosure policy), not a certificate for a service we do not
operate.

## Track 1: product prework (now)

Work that makes the product reviewable, regardless of which certification a
future deal names.

| Item | Status (2026-09-14) | Notes |
|---|---|---|
| Control mapping (SOC 2 TSC + NIST 800-53 rev 5) | Done, this directory | [control mapping](control-mapping.md). Every row cites code; gaps stated inline. |
| Deployment hardening guide | Done, this directory | [hardening guide](hardening.md). Grounded in the shipped `deploy/` artifacts and real config keys. |
| SBOM in release CI | In progress | Release CI today signs tarballs with Sigstore cosign and publishes SHA-256 checksums (`.github/workflows/release.yml`); an SBOM generation step is being added so each release ships a machine-readable SBOM alongside the signatures. Required for federal buyers (EO 14028 expectations) and increasingly requested in enterprise reviews. |
| FIPS-capable build assessment | Not started | Today's crypto stack (`ring`, `ed25519-dalek`, `p256`, `crypto_box`, rustls on `ring`, `jsonwebtoken` on `aws_lc_rs`; workspace `Cargo.toml`) contains no validated FIPS 140 module. The assessment scopes what a FIPS-capable build variant would take (candidate direction: consolidating on a validated module for TLS and digests, and inventorying every primitive that has no validated implementation, notably Ed25519 signing paths). Output is a feasibility memo, not a commitment to ship. |
| Close open security-assessment findings | Partially done | Per [security assessment](../security-assessment.md) status notes (2026-09-09): all 2026-02-14 adversarial findings resolved; C-6 (socket umask race) still open; macOS startup session-detection preflight (H-8) specified but not implemented; `codesign_team_id` client verification inert. These are small, named, and should be closed before the first serious enterprise review. |
| Supply-chain posture (already in place) | Done | `cargo-deny` (advisories, licenses, bans, sources; `deny.toml`) in CI (`.github/workflows/ci.yml`), GitHub dependency review (`.github/workflows/dependency-review.yml`), OSSF Scorecard (`.github/workflows/scorecard.yml`), pinned `Cargo.lock`, cosign-signed release artifacts. |
| Vulnerability disclosure policy | Done | `SECURITY.md`: private reporting via GitHub Security Advisories, 72-hour acknowledgment, 90-day coordinated disclosure. |

Not on this track on purpose: penetration testing by an external firm. Worth
buying immediately before the first paid enterprise deployment, wasteful
before the open findings above are closed.

## Track 2: company certifications (when a deal demands them)

These certify the company's operations, not the product binary. They cost
real money and annual upkeep, so the trigger is a named deal that requires
them, not general readiness.

### SOC 2

- **Trigger**: first enterprise contract or security questionnaire that
  requires it. Many will accept the Track 1 artifacts plus a roadmap
  statement in the interim.
- **Sequence**: readiness assessment, then SOC 2 Type I (point-in-time), then
  Type II after a 3 to 6 month observation window. Run it on a compliance
  automation platform (Vanta, Drata, or equivalent) rather than hand-built
  evidence collection; the company is small enough that platform-collected
  evidence covers most criteria.
- **Scope note**: because the product is self-hosted, the audit scope is the
  company's development and release practices (change management, access to
  the repo and CI, endpoint management, vendor management), not a production
  SaaS environment. If a hosted offering ever exists, its infrastructure
  joins the scope and the observation window restarts for that system.
- **Reusable inputs from Track 1**: the control mapping doubles as the
  control matrix starting point; CI supply-chain checks and signed releases
  are direct evidence for change-management criteria.

### ISO 27001

- **Trigger**: buyer demand only, typically international or EU-headquartered
  enterprises that prefer it over SOC 2. Do not run both proactively; the
  overlap is large and SOC 2 is the default ask in the current pipeline.
- If triggered, do it after SOC 2 Type II so the ISMS documentation can reuse
  the SOC 2 evidence base.

## Track 3: federal posture

The federal strategy is: **the self-hosted product supports the customer
agency's own ATO**. An agency deploys Opaque inside its boundary and
authorizes it as a component of its own system under its own risk process.
Opaque's job is to make that assessment cheap.

What the product must supply for an agency ATO package, and where it stands:

| Artifact | Status | Notes |
|---|---|---|
| NIST 800-53 rev 5 control mapping | Done | [control mapping](control-mapping.md), including an explicit customer-responsibility section, which is exactly the inherited-vs-provided split an SSP author needs. |
| Hardening guide | Done | [hardening guide](hardening.md); maps naturally onto CM-6 configuration baselines. |
| SBOM per release | In progress | Track 1 item. |
| FIPS-validated crypto option | Gap | Track 1 assessment first. Until a FIPS-capable build exists, deployments with a hard FIPS requirement (SC-13 with validated-module policy) cannot be satisfied; say so to prospects early rather than late. |
| Signed releases and provenance | Done | cosign signatures and checksums in release CI. |
| Vulnerability disclosure and support policy | Done | `SECURITY.md`; note it commits to patching the latest release only, which an agency will read as a support-lifecycle statement. |
| Audit evidence integration | Done | Tamper-evident chain with SIEM export and offline verification (`opaque audit verify`) supports the agency's AU family implementation directly. |

Positioning boundaries, so nobody oversells:

- **FedRAMP does not apply to the self-hosted product.** FedRAMP authorizes
  cloud services. It becomes relevant only if a hosted offering is ever sold
  to federal customers, and then the realistic paths are FedRAMP 20x or
  riding an already-authorized platform partner rather than a standalone
  agency-sponsored authorization. No work on this until a hosted federal
  offering is a real plan.
- **CMMC / NIST 800-171** enters only if defense contractors handling CUI
  become customers. Opaque itself would be assessed as part of the
  contractor's environment; the 800-53 mapping translates to 800-171
  families with modest effort. Treat as demand-driven documentation work,
  not a certification to pursue.
- Never claim "FedRAMP ready", "FIPS compliant", or "800-53 certified" in
  any material. The accurate sentence is: "self-hosted deployments run
  inside your ATO boundary; we provide the 800-53 mapping, SBOM, hardening
  guide, and signed releases to support your assessment, and FIPS-validated
  crypto is on our assessed roadmap, not in the current build."

## Sequencing summary

1. Now: finish SBOM in release CI, close C-6 and the macOS preflight, run the
   FIPS-capable build assessment. Everything else in Track 1 is done.
2. On first qualifying deal: readiness assessment and SOC 2 Type I on a
   compliance platform; Type II after the observation window.
3. On federal interest: hand over the Track 3 artifact set; scope FIPS work
   only if the specific deployment requires validated modules.
4. Deferred until demand exists: ISO 27001, CMMC/800-171 documentation,
   anything FedRAMP.
