# Attestor, SSH and gateway progress

This records the first September 5 slice. Subsequent
[Vault/broker SSH integration](2026-09-05-vault-ssh-integration.md) and
[shared resource authority](2026-09-05-broker-resource-authority.md) supersede
the corresponding integration next steps below; historical results remain intact.

Private implementation/evidence record, September 5, 2026. Base revision:
`f8182a2c30b74951b71a26cc7364aebc102f9f44`, with the working changes described here.
Existing release preparation and roadmap changes were preserved. No commit,
push, public deployment, cluster change or production host operation was made.

## Implemented slices

The Unix daemon listener now binds a `PeercredAttestor` after privilege drop,
using its captured effective UID. Canonical workload identity contains validated
namespaced selectors, an ordered strength and the attestor source. Same-UID
callers are `weak`; separate-UID callers are `medium`. Neither label establishes
hardware measurement or separation between sibling agents sharing one UID.
Legacy `ClientIdentity` construction, policy fields and lease fingerprints
remain in use.

Missing/invalid attestor observations clear the identity and refuse dispatch,
with `attestation_unavailable` audit evidence. Handshake and request-envelope
attempts to assert an attestor, substrate, selectors or strength are refused.
Dispatched requests record the listener's attestor, achieved strength and
selector count through the existing chained audit detail field. Duplicate-field
request rejection and historical audit serialization are preserved. A real
daemon/socket test checks both the observed identity and denied caller claims,
then verifies the audit chain.

The gateway now requires `client_id` in every admission, in addition to its
existing tenant, issuer/subject, audience and scope restrictions. The exact
client check applies to direct MCP bearer requests and subsequent access checks;
the organization directory must agree. Both fixture configuration generators
were updated. **Existing hand-written gateway configurations must add the exact
client ID before restarting the updated gateway; missing bindings fail closed.**
This closes a specific client-binding gap, not the shared-authority milestone.

The [bounded SSH fixture](../../examples/bounded-ssh/README.md) now performs one
specific host operation: a fixed read of synthetic `fixture-api` health on
`fixture-a`. Its real OpenSSH boundary includes pinned host keys, a host-specific
principal, a source-address `/32`, short-lived certificate and a root-owned
principal hook that forces the exact grant dispatcher. It denies root/raw-key/
password login, alternate commands, interactive shells, subsystems, PTY and
forwarding. An authenticated connection with no channel closes after three
seconds; inactive session channels close after 35 seconds.

A separate root-owned host ledger atomically consumes a single allowance before
the fixed probe starts. The probe runs unprivileged with fixed argv and cleared
environment. The host stops its process group at the duration/expiry limit or on
revocation, bounds output and checks authority again before releasing JSON.
Linux parent-death protection stops the fixed probe if its supervisor disappears.
Reserved work becomes unknown on guard restart and cannot be retried. Receipts
record exact grant, host, principal, operation, terminal reason and output hash.

## Fresh validation

| Command/suite | Observed result |
| --- | --- |
| `cargo test -p opaque-core` | 386 passed |
| `cargo test -p opaqued --bin opaqued` | 1,033 passed; 3 existing ignored tests |
| `cargo test -p opaqued --test identity_e2e` | 4 passed, including real listener/audit evidence |
| Final focused workload regressions after duplicate-field preservation | 6 unit tests and 1 real-daemon test passed |
| `cargo test -p opaque-metrics` | 41 unit and 33 HTTP gateway tests passed |
| Core/daemon and metrics Clippy, all targets, warnings denied | Passed with no diagnostics |
| `cargo check --workspace` | Passed, including downstream audit-event consumers |
| Hosted runtime Python tests | 22 passed |
| Updated native two-tenant metrics fixture | 26 negative cases; wrong-client 403 for both tenants; denied authority caused no source/model requests; streaming/logout/revocation checks passed |
| `python3 -m unittest discover -s scripts -p 'test_ssh_host_guard.py' -v` on macOS | 13 passed; 2 explicit Linux-only skips |
| Same host-guard suite in isolated Linux container | All 15 passed, including peer credentials and supervisor-death cleanup |
| `python3 scripts/ssh_dogfood.py` | 30 real-OpenSSH checks passed; no cleanup errors |
| Formatting/whitespace | New Rust files and touched Rust functions formatted; changed-file whitespace check passed; Python compiles |

SSH checks prove one permitted source read and bound receipt, denied replay
before/after host restart, six concurrent sessions consuming exactly one unit,
foreign destination/principal/source/user and wrong host-key rejection, expired
certificates, forced-command conflicts, absent certificate command restrictions,
shell/subsystem/PTY/forwarding denials, and active timeout/expiry/revocation.
Each active-work test confirms a source read, the exact terminal receipt and
absence of the probe afterward. The runner tracks resource names before Docker
creation, attempts each cleanup independently, and records cleanup failures.
Unrelated containers are outside its removal list.

Retained raw evidence is private temporary state, not committed material:

- Metrics: `/private/tmp/omf-z219660c/check-evidence.json`.
- Final SSH run: `/var/folders/5z/j6x9mlc504l6txlg7bwjwfyc0000gn/T/opaque-ssh-cpk5rrwl/result.json`.

The SSH report records exact fixture source hashes, local image identity and
OpenSSH version. Its directory also contains private runtime keys and host logs;
do not publish or commit it. The Docker build removes package-generated host
keys in the same layer; fresh fixture host keys are generated at runtime.

## What remains

M4a is partially implemented. Policy selector matching/minimum-strength floors,
the complete policy golden corpus, selector-derived lease fingerprints and a
multi-listener registry remain. Counted generic approval leases, native macOS
codesign identity and enterprise provisioning also remain separate work.

M4e now has exercised host controls, but grants are issued by the test operator,
not the broker or a native human approval. The host guard trusts its dedicated
UID plus grant UUID; an alternative local execution path under that UID would
cross the intended boundary. This fixture is not a general shell service, a
production cgroup supervisor, or a signed host receipt protocol. Termination
cannot undo a source request already accepted upstream. Source reads and result
delivery are therefore checked separately.

The next broker integration must approve an immutable manifest binding tenant,
broker, subject/session, observed workload, pinned destination, exact principal,
source address, fixed operation, UUID, expiry and allowance. CA signing follows
that approval. Host admission/revocation must derive from authenticated broker
state; host receipts must be authenticated and reconciled without redispatch.
The SSH fixture ledger must not become a second production approval authority.

M3 still needs an operator-selected application source and production IdP.
Historical discovery named Quant API's read-only DuckDB and Argo Dex/GitHub as
candidates; their existence is not a configured Opaque issuer/resource/client
contract. No application data or production tokens were accessed in this work.
Gateway admission/token revocation and broker principal/delegation revocation
still have separate owners. Unification must resolve admission and current
revocation through the broker's authority on every source-read and disclosure
boundary, including active work, with two actual test tenants. Exact client-ID
matching alone does not establish that integration.
