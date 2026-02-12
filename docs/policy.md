# Policy Model (Draft)

AgentPass policy answers two questions:

1. **Who** is calling (client identity)?
2. **What** are they allowed to do (operation + target + secret refs), and under what conditions (approval factors, TTL, sandbox)?

This doc proposes a simple allowlist policy that is enforceable on macOS + Linux.

## 1. Client Identity

Minimum viable (v1):

- Unix domain socket peer credentials: `uid`, `gid`, `pid`
- Executable path and content hash (`sha256`)

Stronger (macOS):

- code signature verification (Team ID, signing identity), treat unsigned clients as higher risk

Recommended client identifiers:

- `client.name`: human-readable label (ex: `"Claude Code"`)
- `client.fingerprint`: stable machine-verified identifier
  - `uid:<uid>:sha256:<hash>`
  - optionally `codesign_team_id:<TEAMID>`

## 2. Operation + Target

Every request should be represented as:

- `operation`: a string like `github.set_actions_secret`
- `target`: operation-specific structured fields (repo/project/cluster/namespace/etc)
- `inputs`: may include `secret_ref`s (never raw values)

Policies should match on:

- operation name
- target patterns (repo glob, project id, cluster name, namespace allowlist)
- secret references (by name/tag, not by value)

## 3. Approval Requirements

Approval is a first-class policy attribute.

Suggested knobs:

- `require_approval`: `always` | `first_use` | `never`
- `factors`: any-of / all-of set (ex: `["fido2"]` or `["fido2","ios"]`)
- `lease_ttl`: duration (ex: `10m`)
- `one_time`: boolean

Supported factors (v1+ roadmap):

- `local_bio`: native OS prompt on the same machine (macOS LocalAuthentication, Linux polkit)
- `ios_faceid`: second-device approval using paired iOS device (QR pairing + Face ID)
- `fido2`: hardware security key/passkey (future / optional)

Example:

- GitHub secret writes: require FIDO2 every time, one-time.
- Low-risk reads: allow for 10 minutes after approval.

## 4. Sandbox Requirements (Exec Mode)

Exec mode is only safe against a malicious agent if the executed process is constrained.

Policy should support:

- allowed command allowlist (path + sha256)
- environment allowlist (which variable names may be injected)
- network egress allowlist (domains/IPs/ports)
- filesystem allowlist (read-only mounts, deny access to keychain dirs, etc)
- stdout/stderr redaction (best-effort; not a primary control)

Linux can enforce this in v1 using namespaces/seccomp.

macOS likely needs a VM/container runner for strong per-command egress policy; treat as a roadmap item unless you commit to a specific mechanism (pf anchors, NEFilter, VM-based runner).

## 5. Draft Policy Format (TOML)

This is a strawman format to make rules concrete:

```toml
version = 1

[[clients]]
name = "claude-code"
match.uid = 501
match.exe_path = "/Applications/Claude Code.app/Contents/MacOS/claude-code"
match.exe_sha256 = "..."

[[rules]]
clients = ["claude-code"]
operation = "github.set_actions_secret"
targets.repo = "org/*"
approval.require = "always"
approval.factors = ["fido2"]
approval.one_time = true

[[rules]]
clients = ["claude-code"]
operation = "k8s.set_secret"
targets.cluster = "prod-*"
targets.namespace = ["apps", "infra"]
approval.require = "always"
approval.factors = ["fido2", "ios"] # step-up for prod clusters
approval.one_time = true
```

## 6. Non-Goals

- Policy is not meant to be a full IAM language.
- Deny rules and complex precedence can be added later; start with explicit allowlists.
