# Qualifying one third-party MCP tool

Opaque can admit a signed, pinned HTTPS MCP tool under a finite argument contract.
The broker owns its credential, requires native full review, reserves one durable
attempt and checks current authority before dispatch. A route may disclose a small
signed selection of typed result fields; arbitrary upstream text remains withheld.

This is a bounded MCP 2025-06-18 Streamable HTTP implementation, not universal MCP
interoperability. Qualify the selected server, credential type, catalog and schema
before enrolling it. No bundled example establishes compatibility with a live service.

## Separate the advertised schema from admitted input

Registry version 1 is unchanged: `input_schema` is both the finite admitted schema
and the exact upstream pin; output is `withhold`. Existing serialized records and
prepared-call v2 digests retain their prior meaning. Its legacy response hash and
byte count remain observable metadata: v1 withholding is not a confidentiality
guarantee for values inferable from predictable responses. Use v2 to omit those fields.
Legacy response metadata is also withheld after authority loss; receipt reads apply
current policy, identity, registry, expiry and invocation-revocation checks before
returning that metadata. Control-state receipts remain available to their owner.

Registry version 2 requires an `upstream_input_schema` for every route. That is the
exact advertised `inputSchema`, including supported annotations. `input_schema`
separately describes the narrower arguments an agent may submit. Each call must
pass **both** validators. An upstream `number` can accept an admitted bounded integer;
it cannot enable fractions, expand integer bounds or permit unlisted arguments.
Version 2 routes use domain-separated prepared-call v3 digests.

The upstream subset permits objects, arrays, strings, integers, numbers, booleans,
enums, ordinary length/range bounds, and string `description`/`title` annotations.
It may omit string/array upper bounds and object closure. Those constraints remain
mandatory in the admitted schema. References, regexes, combinators, defaults,
unknown keywords and unsupported types are rejected before schema compilation.
There is no remote schema retrieval. Each v2 schema is at most 64 KiB, with at most
1,024 schema nodes and eight nesting levels; annotation strings are at most 4 KiB.

The runtime still requires exact advertised schema equality. A changed description
inside the pinned schema is drift, even if it does not alter argument validation.
Reenroll and sign a new registry version deliberately; never strip catalog fields
to make a changed pin appear equal. Descriptions outside the input schema are not
agent instructions and do not become authority or override the enrolled tool alias.

## Offline qualification

The contract utility reads bounded regular files and never connects to a daemon,
upstream endpoint, credential store or schema server:

```sh
cargo build --locked -p opaque-mcp --bin opaque-mcp-contract
target/debug/opaque-mcp-contract validate registry.json
target/debug/opaque-mcp-contract qualify registry.json catalog.json
target/debug/opaque-mcp-contract prepare registry.json call.json
```

`catalog.json` is a captured `tools/list` result or JSON-RPC result envelope.
Qualification accepts at most 256 KiB and 128 tools, with no pagination. Diagnostics
are `pinned_schema_matches`, `tool_missing`, `duplicate_tool` or
`upstream_schema_drift`; rejected upstream text is not echoed. Unsupported catalogs
fail closed. Exit 0 means every selected pin matches; exit 2 means failure.
This compares a supplied file, not authenticated endpoint provenance. Successful
qualification neither authorizes a call nor proves every admitted input satisfies
the upstream schema. `prepare` validates one concrete input against both schemas.

The synthetic fixtures demonstrate a GitHub-style comment schema containing
unbounded strings, descriptions and an upstream number with stricter admitted input:

- [Registry v2](https://github.com/kcirtapfromspace/opaque/blob/main/crates/opaque-mcp/tests/fixtures/gateway-registry-v2.json)
- [Catalog](https://github.com/kcirtapfromspace/opaque/blob/main/crates/opaque-mcp/tests/fixtures/gateway-catalog-v2.json)
- [Bounded call](https://github.com/kcirtapfromspace/opaque/blob/main/crates/opaque-mcp/tests/fixtures/gateway-call-v2.json)

These are illustrative source-shape fixtures at `mcp.example.com`. They are not
captured GitHub schemas or a ready-to-run GitHub integration. In particular, a real
tool may not return the synthetic `structuredContent` fields used in this example.

## Signed typed result disclosure

A v2 route with `output_policy: "typed_fields"` must contain `output_projection`:

```json
{
  "fields": [
    {
      "source": "id",
      "name": "resource_id",
      "value_type": { "kind": "integer_id", "maximum": 1000000 }
    },
    {
      "source": "status",
      "name": "status",
      "value_type": { "kind": "status", "values": ["created", "queued"] }
    }
  ]
}
```

Only top-level fields of the successful tool result's `structuredContent` are read.
The projection permits at most eight fields and 1,024 serialized output bytes.
Numeric IDs must be integers between one and the signed maximum, capped at 2^53−1.
Status values must match one of at most sixteen signed tokens, each at most 32 bytes.
Source/destination names are fixed signed identifiers, not JSON pointers or caller
input. There are no arbitrary string, URL, nested object or raw content projections.
Unknown fields are ignored. A missing, malformed or out-of-range selected field
withholds the entire projection. Server-reported tool errors never disclose values.

The complete projection, upstream schema digest and admitted schema digest are part
of canonical review and action binding. Changing them requires a new approved action.
Policy rules can match `output_policy`, `output_projection_digest` and
`upstream_schema_digest`; these static fields are available during discovery too.
Use the projection digest for matching, since policy field strings use glob syntax
and serialized projection JSON contains characters with special glob meaning.
Typed values remain untrusted provider claims; shape validation does not prove their
truth, nor that the provider performed a business effect. Choose fields appropriate
for the receiving principal and the workflow's disclosure policy.

After the effect, policy, requester identity, registry, expiry and invocation
revocation are checked again. The broker repeats its final disclosure fence after
asynchronous identity/audit work. Authority lost before that fence removes all
projected values while preserving the charged outcome. Revocation after an authorized
dispatch cannot undo the provider effect; revocation after authorized disclosure
cannot recall bytes already released.

An authorized response adds `output` and `disclosure: "projected"` beside `receipt`.
Otherwise `disclosure` explains `withheld_invalid_projection`, `withheld_tool_error`
or `withheld_authority_changed` when applicable. No raw response body enters a receipt.
Version 2 receipts retain only projection-validation control state, not projected
values, response hashes or response sizes. A digest of a small enum or predictable
identifier can reveal its value by enumeration, so it is not safe withholding.
`mcp_get` never rediscloses prior values, including after restart. Losing the response
does not authorize retry. Use independent readback before proposing any new work.

## Outcome interpretation and production limits

`accepted` means a valid tool result was observed. `rejected` can follow a server
error **after an effect occurred**. The v2 receipt's `dispatch_status` distinguishes
`not_attempted`, `attempted` and crash-recovery `attempt_uncertain`; none establishes
provider business success. `attempt_charged` remains true after reservation,
including failed admission during handshake, error, expiry, revocation or timeout.
An interrupted dispatched call becomes `unknown`; it is never resumed or refunded.
Every invocation UUID is single-use; a new UUID requires separate approval.

Production still requires a sealed tenant, separate broker custody, admitted
delegated identity, enforced agent sessions, public HTTPS DNS on port 443 and actual
native review. Private-address destinations, ambient proxies, redirects, retries,
OAuth negotiation, server callbacks and open-ended streams are unsupported.
Remote task approval receipts do not authorize MCP calls. A real pilot must verify
that its agent cannot bypass the broker using another credential or dispatch path.
