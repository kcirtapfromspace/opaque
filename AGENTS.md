# Opaque core product repo

This is `kcirtapfromspace/opaque`, the public core product: the daemon,
CLI, MCP server, and every crate except the demo. Two sibling repos hold
what doesn't belong here:

- `kcirtapfromspace/opaque-dogfood` (private) — strategy docs, PRDs,
  dogfooding fixtures, and validation records.
- `kcirtapfromspace/opaque-demo` (private) — the customer-facing demo
  (`opaque-showcase`, hosted-demo infra, the Cloudflare Worker).

Never commit runtime credentials, access tokens, private keys, local
environment files, browser state, generated binaries, or raw session
artifacts. Keep those in ignored or temporary storage.
