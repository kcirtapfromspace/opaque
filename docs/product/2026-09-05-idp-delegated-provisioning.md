# IdP persona and delegated metrics access

**Private implementation/runbook record · September 5, 2026**

This first profile grants bounded read access to existing metrics resources for
users who have already enrolled through the broker's configured IdP. A human
administrator reviews a named profile and delegates a finite issuance allowance
to one configured service. That service may issue access to exact, already known
IdP subjects whose current verified group snapshot satisfies the profile.

The broker owns the policy, persona evidence, mandate, issuance counter and
revocation records. The service supplies a profile reference or exact recipient,
never an authoritative group list, role assignment or replacement policy. New
persona-mode logins receive no implicit roles. Provisioning does not create IdP
accounts, change IdP groups, provision external applications, grant administrator
roles or permit redelegation.

Keep this record, operator evidence, enrollment material and assertion files out
of public routes, search, sitemaps, preview assets and Git runtime artifacts.

## Required deployment and identity preparation

Use an existing independently isolated tenant broker with sealed configuration,
separate service/workload custody and its broker-owned resource authority. The
resource authority must use the same required IdP issuer and immutable tenant /
broker binding, exact subject/client admissions, and its dedicated gateway
credential. The gateway never reads the identity database. See the private
[resource authority contract](2026-09-05-broker-resource-authority.md).

Establish an admitted human administrator through the existing initial login
procedure **before enabling persona or provisioning**. The legacy first-human
bootstrap remains available only outside persona mode; turning on persona with
an empty principal database does not manufacture an administrator. Preserve
that administrator's current explicit issuer/subject admission and existing
roles when activating the new capability.

The following is a configuration fragment to merge into the reviewed broker
configuration, not a standalone deployment file. Replace the example issuer,
subjects, public workstation key and paths with the provisioned values. Retain
the existing resource-authority listener, credential reference, auth verifier
and tenant-bound admissions rather than creating a fixture authority.

```toml
require_seal = true
enforce_agent_sessions = true
workstation_test_mode = false
workstation_approvers = [
  { name = "Identity administrator workstation", public_key_hex = "REPLACE_WITH_ENROLLED_PUBLIC_KEY_HEX" },
]

[tenant]
id = "engineering"

[trust_domain]
enforce = true
socket_group = "7999"
socket_path = "/run/opaque/opaqued.sock"

[approval]
fido2 = true
fido2_rp_id = "opaque.example.internal"
session_factor = "paired_workstation"
server_bind = "127.0.0.1:7381"
timeout_secs = 300

[identity]
issuer = "https://idp.example.com"
client_id = "opaque-native-client"
required = true
allowed_subjects = ["existing-admin-subject", "existing-employee-subject"]

[identity.persona]
groups_claim = "groups"
max_age_secs = 300

[[identity.service_principals]]
name = "onboarding"
roles = []

[[provisioning.profiles]]
id = "engineering-metrics"
revision = 1
eligible_group = "Engineering"
scopes = ["metrics:read", "metrics:metric:requests_per_second"]
max_ttl_secs = 600
max_mandate_ttl_secs = 3600
max_issuances = 20
```

The profile scope vocabulary is restricted to the existing `metrics:read`,
`metrics:stream`, `metrics:explain` and named `metrics:metric:*` entries in
`METRIC_SCOPES`; arbitrary wildcard, portfolio, organization and role scopes are
rejected. Global limits are 24 hours per access grant, seven days per mandate,
10,000 cumulative issuances per mandate and 64 configured profiles. A profile
may set smaller limits. Counts are cumulative; expiry and revocation do not
refund them.

Provisioning startup requires an existing admitted human administrator, required
identity with explicit subjects and persona freshness, enforced agent sessions,
sealed isolated tenant custody, FIDO2, a resource authority, and an enrolled
paired workstation. Session/provisioning review uses the explicitly configured
paired-workstation factor so the isolated broker does not require a desktop.
The exact binding/mandate start operations carry complete bounded review text;
role and unrelated control operations retain their existing approval rules.

The administrator and recipients must complete fresh IdP login after persona is
enabled. The IdP must supply the configured exact group claim plus valid `iat`,
`exp` and `auth_time` in the signed ID token. Missing, stale, malformed or
foreign claims fail before enrollment or snapshot replacement. Display names,
email addresses and client-supplied group claims are not recipient identifiers.

## Operator transport and authenticator prerequisites

Use the deployment's established operator transport to run login, enrollment
and session-bootstrap commands while `enforce_agent_sessions` remains enabled.
The examples use the installed `opaque` CLI. Its operator bootstrap must already
match the deployment's reviewed human-client identity. The wrapped child may use
the same binary: a supplied session token is validated even when the executable
is classified as Human, and an invalid token never falls back to an unwrapped
connection. Agent-classified clients still require a token under enforcement.
The wrapper and child run as the intended workload UID, distinct from the broker
UID. Verify this transport arrangement before starting a mandate; do not disable
session enforcement to make a command connect.

Enroll the workstation through the existing trusted-channel broker-ID/TLS-pin
procedure in the [approver runbook](../../crates/opaque-approver/README.md). Have an
existing registered USB FIDO2 credential for the broker's RP ID, with user
verification configured. `scripts/provisioning_passkey.py` answers challenges
using that credential; it does not enroll a key, set a PIN or modify the broker.
It uses pinned `python-fido2` through `uv run` and requires a human interactive
terminal and exactly one accessible USB authenticator. Platform passkeys and a
generic browser enrollment UI are not provided by this helper.

```sh
opaque --socket /run/opaque/opaqued.sock login
opaque --socket /run/opaque/opaqued.sock key ls
umask 077
provisioning_ceremony_dir=$(mktemp -d "${TMPDIR:-/tmp}/opaque-provisioning.XXXXXX")
```

Keep the resulting directory in trusted operator custody. Challenge and
assertion files are transient ceremony material; retain only sanitized outcomes.

## Bind the existing key to the administrator

Start the binding with the registered credential ID from `key ls`:

```sh
opaque --socket /run/opaque/opaqued.sock --json \
  provisioning bind-start REGISTERED_CREDENTIAL_ID \
  > "$provisioning_ceremony_dir/bind-begin.json"
```

This command waits for complete out-of-band human review. In the trusted
workstation terminal, list and review the exact pending round:

```sh
opaque-approver list --state-dir /trusted/operator/opaque-approver
opaque-approver review --state-dir /trusted/operator/opaque-approver \
  --approval-id APPROVAL_UUID
```

Inspect the tenant/broker, exact IdP issuer/subject, principal and key identity.
After native review completes, the begin result contains a short-lived FIDO
challenge and `challenge_id`. The human then answers it using the existing key:

```sh
uv run scripts/provisioning_passkey.py \
  --begin "$provisioning_ceremony_dir/bind-begin.json" \
  --output "$provisioning_ceremony_dir/bind-assertion.json"
opaque --socket /run/opaque/opaqued.sock --json \
  provisioning bind-complete BIND_CHALLENGE_UUID \
  --assertion "$provisioning_ceremony_dir/bind-assertion.json"
```

The broker verifies the challenge, RP/origin, signature, user presence and user
verification. It binds the credential immutably to that administrator's exact
IdP identity and tenant/broker. A key already bound to another identity cannot
be repurposed. Expired, rejected or consumed challenges require fresh review.

## Authorize the service's finite mandate

```sh
opaque --socket /run/opaque/opaqued.sock --json \
  provisioning mandate-start --service onboarding \
  --profile engineering-metrics --ttl-secs 3600 --max-issuances 20 \
  > "$provisioning_ceremony_dir/mandate-begin.json"
```

Complete the new workstation review, checking profile revision/epoch, exact
eligible group, scopes, maximum child lifetime, cumulative count, expiry and
prohibition on redelegation. The same administrator must still have a fresh
persona, active login and current administrator authority. Then perform the
separate bound FIDO ceremony and submit its result:

```sh
uv run scripts/provisioning_passkey.py \
  --begin "$provisioning_ceremony_dir/mandate-begin.json" \
  --output "$provisioning_ceremony_dir/mandate-assertion.json"
opaque --socket /run/opaque/opaqued.sock --json \
  provisioning mandate-complete MANDATE_CHALLENGE_UUID \
  --assertion "$provisioning_ceremony_dir/mandate-assertion.json"
```

Record the returned mandate UUID. The store rechecks the reviewed profile and
issuer epochs and the matching unrevoked login inside the creation transaction.
An authority change during review requires a new ceremony. This is a grant of
bounded issuance authority; it grants no read access until an eligible recipient
receives an access grant.

## Issue access from an autonomous service session

Start the existing wrapper as the intended workload UID. Session creation itself
still requires a fresh workstation approval; `--mode autonomous` selects the
configured service principal rather than bypassing approval. Default wrapper
mode remains `delegated`; `--service` is valid only with `--mode autonomous`.

```sh
opaque --socket /run/opaque/opaqued.sock \
  agent run --mode autonomous --service onboarding --ttl-secs 900 -- /bin/sh
```

After that session's human review, run the following inside the wrapper's child
shell or the equivalent already wrapped agent. Its session token is injected by
the wrapper and must not be printed, copied into a prompt or saved in Git.

```sh
provisioning_request_id=$(python3 -c 'import uuid; print(uuid.uuid4())')
opaque --json provisioning issue \
  --mandate MANDATE_UUID --issuer https://idp.example.com \
  --subject existing-employee-subject --ttl-secs 300 \
  --request-id "$provisioning_request_id"
opaque --json provisioning list
opaque --json provisioning show access ACCESS_GRANT_UUID
```

The recipient must already be an enabled human principal, admitted by the broker
and holding a fresh verified snapshot containing the exact eligible group. The
service's persisted autonomous delegation is rechecked atomically at issuance.
The receipt records its actual actor and delegation ID. A service cannot issue
under another service's mandate, grant to a service/agent principal, choose
unreviewed scopes or exceed the parent's lifetime/count.

For an uncertain RPC response, retry the identical issuer, subject, TTL and
request UUID **inside the same live service delegation**. A delayed retry returns
the original grant and original expiry; it neither extends access nor consumes
another issuance. A changed request or a revoked/expired earlier grant fails.
Do not create a new request UUID merely because the first response was lost.

The resource authority rechecks live provisioning for each incoming OAuth
resource request. The access token must still pass signature, issuer, audience,
tenant, exact client/subject admission, expiry and token-revocation checks. A
non-administrator's pre-existing Operator/Auditor role cannot substitute for a
provisioning grant while this mode is enabled. Token scopes must be a subset of
the recipient's currently valid grant scopes. Administrators retain their
separately configured administrative resource role scopes.

## Inspect, revoke and retain evidence

An administrator with a fresh admitted login can inspect or revoke:

```sh
opaque --socket /run/opaque/opaqued.sock --json provisioning list
opaque --socket /run/opaque/opaqued.sock --json \
  provisioning show mandate MANDATE_UUID
opaque --socket /run/opaque/opaqued.sock --json \
  provisioning revoke access ACCESS_GRANT_UUID
opaque --socket /run/opaque/opaqued.sock --json \
  provisioning revoke mandate MANDATE_UUID
```

`show` includes the immutable historical profile terms for the grant's approved
epoch. Service listings are limited to that service's mandates and children.
Explicit access revocation also fences all further issuance to that recipient
under the same parent; restoring access requires a new human-approved mandate.

| Change | Durable effect |
| --- | --- |
| Profile content/revision changes, removal, disable/restore | Monotonic policy epoch; old mandates cannot revive. Historical approved terms remain readable. |
| Issuer loses administrator role, is disabled or leaves configured admission | Old mandates are revoked; restoring identity or roles does not revive them. Pending approval is bound to the earlier issuer epoch. |
| Configured service removed/disabled | Its mandates and future issuance fail; startup persists admission withdrawal. |
| Recipient group removed and later restored in verified snapshots | Persona revision changes; old access does not regain authority. |
| Persona becomes stale or policy changes | Resource authorization fails. A grant observed invalid is tombstoned; refreshing persona cannot revive it. |
| Administrator explicitly revokes recipient access | Existing sibling grants under that mandate are revoked and the parent/recipient pair is fenced against new request UUIDs. |
| Parent mandate or bound FIDO credential revoked | Child access fails at the next authority check. Removed credential IDs are permanently denied for new mandates, including concurrent creation and re-enrollment; restoring a key does not restore old mandates. A newly enrolled credential ID requires fresh binding and approval. |
| Session/delegation revoked before issuance transaction | No grant is created and no issuance is consumed. |
| Access/mandate expires, or a request is retried | No budget refund. Idempotent retry preserves original grant identity and expiry. |
| Broker restart | Policy history, counts, fences and revocations persist. Pending approval challenges are lost and require fresh review. |
| User self-revokes the resource token | The token remains denied across restart and later grants, even when self-revoked while access was already withdrawn. |

Persona is a freshness-bounded OIDC snapshot, **not push IdP revocation**. A group
removal at the IdP is observed only through new verified evidence or expiry of
the existing freshness window. Calls recheck that window; they do not query the
IdP directory synchronously. Keep the configured window appropriate to the
resource and require fresh login when evidence is stale. No immediate upstream
revocation or external directory reconciliation is claimed.

Retain sanitized mandate/access IDs, tenant/broker, exact profile epoch, actor
and delegation identity, approval provenance, allowance consumed and observed
authorization results. Raw ID/access tokens, session credentials, assertion
files, PINs, private keys and browser state stay in protected temporary/runtime
custody. Restart only the selected broker when validating persistence.

## Validation status

Centralized checks passed: 1,091 daemon tests (four intentionally ignored), 151
CLI tests, five workstation tests, and 16 Python helper tests using pinned
`fido2==2.2.1`. This includes 15 provisioning engine tests and four full RPC
ceremony tests with synthetic assertion fixtures. Coverage includes strict
persona claims, exact review/FIDO binding, finite service issuance, delayed
idempotent retry, policy/persona/role restoration, revocation/restart behavior,
credential removal concurrent with mandate creation, and actual signed OAuth
resource authorization. Synthetic fixture keys and mock IdP evidence do not
establish a live IdP integration or physical authenticator ceremony.

The Linux ARM64 daemon suite also passed: **1,102 passed, zero failed, five
ignored**, using the pinned Rust image and existing offline build caches. Git
was installed only in the temporary test container to satisfy repository
fixtures; the network was disconnected before the tests. A parallel run exposed
an existing Doppler test race over a shared environment variable; the complete
serial run passed. Ignored kernel/root/live checks were not forced. GitHub
Actions is disabled in this private repository, so these are local checks rather
than hosted CI results.

No real hardware authentication, live IdP provisioning, external application
change or production deployment is claimed by this implementation record.
