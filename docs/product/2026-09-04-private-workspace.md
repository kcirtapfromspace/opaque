# Private workspace and public documentation boundary

**Private operational record, 4 September 2026 (America/Denver).** The user
directed that all dogfooding work belong in a private repository. This record
captures the containment checkpoint; it is excluded from the public MkDocs site.

## Repository boundary

The existing checkout at `/Users/thinkstudio/opaque` now uses
`git@github.com:kcirtapfromspace/opaque-dogfood.git` as its fetch and push
`origin`. The operator verified that repository as **PRIVATE**, and GitHub
Actions are disabled for it. The original public product repository remains
available as the `upstream` fetch remote, with its push URL explicitly set to
`disabled://public-upstream`. No dogfood source push to the public repository is
part of this checkpoint.

The complete workspace stays together in the private repository. Cargo sibling
dependencies, test-fixture includes, script root paths and hosted Docker build
paths therefore remain intact. Dogfood implementations, synthetic sources,
controller manifests, operator runbooks, private product notes, evaluation
scripts and validation records share this private boundary. A future public
product change requires a deliberate selection and review of generic product
code and documentation; a private-origin setting does not automatically make a
later public export safe.

The private snapshot was still being prepared at this checkpoint. Temporary
operator evidence under `/private/tmp` is not a durable repository archive, and
credentials, environment files, session cookies and private runtime keys must
not be copied into documentation or committed as evidence.

## Public-site containment

The initial publication path built Markdown from the working directory,
including untracked files and pages absent from navigation. Merely omitting a
page from the menu did not prevent its HTML or search-index publication.

The public MkDocs configuration now excludes `product/**`, `dogfood.md`,
`release-dogfood.md` and `tenant-boundaries.md`, in addition to the pre-existing
README/override exclusions. The public hosted guide and README were stripped of
internal evidence links and operator details. Customer-facing instructions may
remain public; internal product plans, dogfood recipes and validation ledgers do
not belong in the public build or its search index.

The operator published the cleaned Pages deployment identified by `dd4ae1e5`,
deleted three earlier deployments verified to expose private material, and also
deleted the temporary deployment identified by `5ee`. This is a record of those
specific containment actions, not a claim that every past copy or third-party
cache has been erased.

The later expanded visitor guide was published as Pages deployment `e9a777d2`.
Its public search index and sitemap were checked for internal material, while
private product and dogfood routes continued returning `404`. This public
visitor-guide update did not publish the private validation or product notes.

A separate documentation guard Worker was first deployed as `6105ce0b`.
The final deployment, `d2c132f8-7d96-495d-b27b-c632104a2703`, covers the following
five route patterns on **both** `opaque.info` and `www.opaque.info`, for ten
configured routes:

- `/product/*`
- `/product`
- `/dogfood*`
- `/release-dogfood*`
- `/tenant-boundaries*`

The guard returns `404` without forwarding to an origin, with
`Cache-Control: no-store` and `X-Robots-Tag: noindex, noarchive`. The operator
verified that a previously cached organization product-note URL returned `404`.
The final eight representative route checks across the two hostnames all
returned `404` with `no-store`, as recorded in
`/private/tmp/opaque-portfolio-deployment/evidence/public/privacy-routes-final.json`.
The route guard prevents these public document paths from serving content; it
does not replace the MkDocs exclusions or control access to the private Git
repository. Previously downloaded or independently archived content cannot be
recalled by these actions.

## Bounded secret-scan review

The source snapshot's redacted Gitleaks report contained thirteen findings. A
read-only comparison against current source classified twelve as test-fixture
detections and one as a Cargo dependency-name false positive. No operational
credential was identified within those thirteen findings. All flagged material
already existed in `HEAD`; the scanned files matched the current source.

The RSA PEM under `crates/opaqued/tests/fixtures/` is a valid, deliberately
committed test private key, rather than an operational signing credential. The
hosted runtime generates a fresh key for each lease and replaces the fixture
signer/JWKS configuration. JWT redaction samples, handshake canaries, mock key
responses and public-key parsing samples account for the other fixture hits.
No credential values are reproduced here.

This review did not require excluding those fixtures or rotating a production
credential. It was a bounded review of the thirteen findings, not a claim that
the repository is globally free of secrets. Detection rules remain applicable
to future changes; these findings do not justify blanket JWT or private-key
allowlists.

Before the private branch snapshot, the operator repeated the index secret
preflight. It reported the same thirteen fixture/false-positive findings and no
new detections. That repeat does not broaden the bounded review into a guarantee
about all past repository history.

## Evidence and limits

The operator retained the pre-containment Pages inventory at
`/private/tmp/opaque-pages-deployments-before-private.json` and the redacted
source scan at `/private/tmp/opaque-private-source-gitleaks.json`. Local remotes,
MkDocs exclusions and the guard implementation are inspectable in this private
checkout. Repository visibility, Actions status, deployment deletion and live
HTTP observations above were reported by the deploying operator.

The completed organization validation remains a historical record. The richer
[portfolio analytics](2026-09-04-portfolio-analytics.md) increment is deployed,
with public Gemma and Qwen checks completed and both leases cleaned up. Its
validation ledger records those observations and their limits separately. This
privacy checkpoint does not rewrite earlier test or deployment results.
