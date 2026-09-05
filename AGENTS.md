# Private dogfooding workspace

This checkout belongs to `kcirtapfromspace/opaque-dogfood`, a private repository.
Keep dogfooding code, fixtures, app/repository configuration, cluster operations,
research, and validation records here. Verify the destination is private before
pushing. `upstream` is the public product repository and has a disabled push URL.
Do not publish internal work to that repository.

The customer-facing demo and visitor documentation may be deployed publicly.
Internal documentation under `docs/product/`, dogfooding guides, deployment
records, and operator evidence must remain excluded from site routes, search,
sitemaps, preview deployments, and assets. Check the generated site, not only
the navigation list, before publishing.

Never commit runtime credentials, access tokens, private keys, local environment
files, browser state, generated binaries, or raw session artifacts, even here.
Keep those in ignored or temporary storage. Preserve existing local work and
running cluster workloads when changing the demo.
