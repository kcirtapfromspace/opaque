# Three-app live dogfood template

These files prepare six disposable marker writes: `OPAQUE_DOGFOOD_MARKER` and
`OPAQUE_DOGFOOD_ROTATION` in each repository. They do not configure application
credentials, deploy applications, provision Vault, or execute remote workflows.

| App | Repository | Verified numeric ID | Local checkout |
| --- | --- | --- | --- |
| Opaque | `kcirtapfromspace/opaque` | `1156844526` | `/Users/thinkstudio/opaque` |
| No Drake in the House | `kcirtapfromspace/no_drake_in_the_house` | `1064455796` | `/Users/thinkstudio/repos/no_drake_in_the_house` |
| Adanima | `Nereus-Data/admachina` | `1183003039` | `/Users/thinkstudio/ai_ad_agency` |

The repository mapping was checked through local Git remotes and GitHub's read
API. **No live secret publishing was tested.** Source paths below are proposals,
not provisioned Vault secrets. The native macOS review window rendered during a
synthetic check; scrolling through the final action and completing biometric
approval remain manual checks.

## Files and authority

- `three-apps.json`: six exact actions, a ten-minute lifetime, proposed pinned
  sources, and the GitHub credential reference `keychain:opaque/github-pat`.
- `live-config.toml`: opt-in task support, native approval, one exact task
  operation rule, and six exact repository/marker child-operation rules. Every
  rule requires `local_bio`; other operations remain denied by default.
- `verify-markers.workflow.yml`: optional manual-only workflow template. It checks
  both markers are nonempty and prints only a fixed success/failure message.

The daemon replaces manifest API URLs with its trusted environment configuration
and resolves repository numeric IDs again during planning. The template's IDs
are reference information, not caller-supplied authority. The invalid example
Vault hostname is also replaced; configure the real Vault URL in the daemon's
environment. Execution rechecks the approved repository identity and provider
URLs before writing.

Planning may resolve the GitHub PAT and read repository metadata. It does not
fetch the six marker values. Running the task fetches the exact Vault version,
requires full native review and biometric approval, and permanently charges each
attempted slot. API acceptance means GitHub accepted a write; it does not verify
an application deployment or the plaintext value.

## Prepare disposable sources and credentials

Use the trusted Vault administration flow to create a KV v2 secret at the
proposed logical location `kv/opaque-dogfood`. Its API path is
`kv/data/opaque-dogfood`. The proposed version-1 fields are:

| Repository | Marker field | Rotation field |
| --- | --- | --- |
| `kcirtapfromspace/opaque` | `OPAQUE_MARKER` | `OPAQUE_ROTATION` |
| `kcirtapfromspace/no_drake_in_the_house` | `NDITH_MARKER` | `NDITH_ROTATION` |
| `Nereus-Data/admachina` | `ADANIMA_MARKER` | `ADANIMA_ROTATION` |

Use disposable, nonproduction marker values. If that Vault path already exists,
choose a separate path and its actual immutable version, then update both the
manifest and policy refs. The template pins version 1; it never follows latest.
Changing a source version requires a new plan and fresh approval.

Provision the GitHub PAT and Vault token through your trusted credential store,
using `keychain:opaque/github-pat` and `keychain:opaque/vault-token` or your own
explicit refs. The GitHub credential must have the permissions needed to read
metadata and write Actions secrets in these named repositories. Access to both
owners must be verified separately; an existing credential is not assumed to
cover all three repositories. Do not put credential values in these templates,
shell arguments, task manifests, or agent messages.

## Start an isolated native daemon

Run from the Opaque checkout. Build the approval helper alongside the daemon:

```bash
cargo build -p opaque -p opaqued -p opaque-approve-helper
export OPAQUE_LIVE_DATA="$(mktemp -d /tmp/olf.XXXXXX)"
python3 - "$OPAQUE_LIVE_DATA" <<'PY'
from pathlib import Path
import sys
directory = Path(sys.argv[1]).resolve()
template = Path("examples/dogfood/live-config.toml").read_text()
config = template.replace("/tmp/opaque-live-dogfood", str(directory))
(directory / "config.toml").write_text(config)
(directory / "config.toml").chmod(0o600)
PY
export OPAQUE_CONFIG="$OPAQUE_LIVE_DATA/config.toml"
export OPAQUE_SOCK="$OPAQUE_LIVE_DATA/run/opaqued.sock"
export OPAQUE_GITHUB_API_URL="https://api.github.com"
export OPAQUE_VAULT_URL="https://YOUR-VAULT-HOST"
export OPAQUE_GITHUB_TOKEN_REF="keychain:opaque/github-pat"
export OPAQUE_VAULT_TOKEN_REF="keychain:opaque/vault-token"
unset OPAQUE_INSECURE_AUTO_APPROVE OPAQUE_DOGFOOD_LOOPBACK OPAQUE_AWS_ALLOW_INSECURE
printf 'Dogfood socket: %s\n' "$OPAQUE_SOCK"
target/debug/opaqued
```

Replace `YOUR-VAULT-HOST` with your configured Vault endpoint before starting.
These environment variables name endpoints and credential references only. If
you deliberately use a local Vault over HTTP, set its loopback URL and
`OPAQUE_DOGFOOD_LOOPBACK=1`; retain `approval_backend = "native"` and do not enable
auto-approval. Remote providers require HTTPS.

You may choose your own new, private data directory instead of `mktemp`. Keep the
socket path under 100 bytes for macOS and keep this state separate from an
existing Opaque installation. The sample is a shared-UID developer setup; it
does not establish isolation from other processes running as the same OS user.
It permits agents and the CLI to request only the configured operations, with
native approval required before writes.

## Plan, review, run, and inspect

In another terminal, set `OPAQUE_SOCK` to the socket printed above. Keep the
daemon terminal open. Planning produces an immutable task and its ID:

```bash
target/debug/opaque --socket "$OPAQUE_SOCK" task plan \
  --manifest examples/dogfood/three-apps.json
target/debug/opaque --socket "$OPAQUE_SOCK" task show TASK_ID
target/debug/opaque --socket "$OPAQUE_SOCK" task run TASK_ID
target/debug/opaque --socket "$OPAQUE_SOCK" task show TASK_ID
```

Replace `TASK_ID` with the planned ID. Before confirming the native review, check
all six repository/marker pairs, numeric IDs, exact source versions, credential
refs, and expiry. Scroll through the last action and fingerprint, then complete
the biometric prompt yourself. CLI/dashboard text is useful inspection output;
the native review and factor form the trusted approval flow.

An agent can use the same explicit socket, manifest file, and CLI commands.
It receives references and receipts; the broker resolves marker values and the
GitHub credential. A consumed or uncertain task cannot be retried. Investigate
the receipt before making a new plan. To revoke remaining authority:

```bash
target/debug/opaque --socket "$OPAQUE_SOCK" task revoke TASK_ID
```

Revocation stops writes that have not passed the final dispatch gate. It cannot
cancel a write already authorized for dispatch. Keep the state directory for
receipts, including after stopping the daemon.

## Optional manual marker-consumption check

Review `verify-markers.workflow.yml` before deliberately copying it into a
target repository's `.github/workflows/` directory and committing it through
that repository's normal process. This template has not been installed anywhere
or dispatched. It has only a `workflow_dispatch` trigger, no checkout, no
deployment steps, and no GitHub write permissions.

After approved marker publishing, a person may run the installed workflow from
GitHub Actions. A successful run establishes that this workflow received two
nonempty marker secrets. It does not verify their exact values, prove rotation,
or exercise the application's deployment process. This workflow and all live
provider behavior remain untested.

For repeatable local fixtures without touching these repositories, use
`python3 scripts/dogfood.py --check`; see `docs/dogfood.md`.
