# Visitor documentation deployment

Private operator evidence, 2026-09-09. Exclude this record from public HTML, assets, search, sitemaps, and preview deployments.

The user authorized pushing the integrated code and deploying. This record covers only the visitor documentation published to the existing Cloudflare Pages project. Worker and hosted-runtime rollout are separate operations.

| Field | Observed value |
| --- | --- |
| Pages project | `opaque` |
| Production domains | `https://opaque.info`, `https://www.opaque.info` |
| Source commit | `3b322f24d2743d768406a9ce6e069a9b9f9b0af2` |
| Production branch | `main` |
| Deployment ID | `84d94d19-ad8a-4373-acac-a2d606546b84` |
| Direct deployment | `https://84d94d19.opaque-3pv.pages.dev` |
| Completion observed | 2026-09-09 11:16 UTC |
| Wrangler | Pinned `4.129.0` |
| Upload | 74 inspected files; 9 uploaded and 65 reused from the asset cache |

The updated public pages explain audit retention/durability, transport uncertainty and bounded MCP calls, and the dashboard's registry-derived catalog and catch-up behavior. No internal assessment or operator evidence was included.

## Exact artifact checks

Python 3.12.11 with `scripts/requirements-test.txt` ran a strict MkDocs build into `/private/tmp/opaque-pages-quality-oqn0crk2/site`. The privacy inspector then checked that exact upload directory: HTML allowlist, all asset bytes, search locations, and ordinary/compressed sitemaps passed. A separate fresh build with 43 marked private source fixtures also passed before upload. After this private record was added, another marked-source build passed with 44 excluded fixtures. The temporary directory retains file hashes and a compact HTTP verification report; it is not a durable evidence archive.

Publication command, executed successfully:

```sh
npx --yes wrangler@4.129.0 pages deploy /private/tmp/opaque-pages-quality-oqn0crk2/site --project-name=opaque --branch=main --commit-hash=3b322f24d2743d768406a9ce6e069a9b9f9b0af2 --commit-message='Publish validated quality documentation' --commit-dirty=false
```

Read-only deployment listing confirmed the complete deployment ID, production environment, branch, and source revision afterward.

## Live verification

All 42 unauthenticated HTTP checks passed across the apex domain, `www`, and the direct deployment domain:

- Homepage, visitor guide, audit analytics, MCP integration, and web dashboard returned 200. The three changed pages contained their new behavior descriptions on every domain. All five checked pages on the direct deployment domain matched the upload bytes exactly; production-domain HTML was checked for content rather than claimed byte-identical.
- Product root, the quality implementation and merge records, dogfood, release-dogfood, and tenant-boundaries returned 404 on every domain. The direct deployment checks establish artifact exclusion independently of the production privacy Worker.
- Search, sitemap, and compressed sitemap returned 200 with nonempty indexes, no unreviewed routes, and no quality-record/private-sentinel references.

The existing `opaque-docs-privacy` Worker was left unchanged. Preflight also confirmed its production private-route responses use `no-store` and `noindex, noarchive`. No Worker, queue, secret, repository setting, or publication workflow guard was changed by this Pages operation.

The private repository's GitHub Actions setting was observed as disabled, and inherited publication workflows additionally require the public product repository. The preceding private push does not itself publish these docs; this verified direct upload performed publication.
