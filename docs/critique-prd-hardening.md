# Devil's Advocate Critique: PRD "Secure Approval and Audit Hardening"

## 1. Executive Summary

This PRD attempts to retrofit security-critical properties -- operation-bound approvals, client identity verification, error sanitization, and audit integrity -- onto a codebase that currently has none of these things. The existing implementation (`crates/opaqued/src/main.rs`) is approximately 200 lines of code that can handle `ping`, `version`, a completely unauthenticated `approval.prompt`, and a stubbed `whoami`. There is no policy engine, no client identity verification beyond raw `PeerInfo` extraction, no audit log, no operation model, no provider connectors, and no error sanitization. The PRD reads as a reasonable wish list, but it conflates a ground-up security framework build with a "hardening" pass, underestimates the implementation surface area by an order of magnitude, and leaves critical design decisions as open questions that will block every user story. Several of the proposed features (LanceDB semantic search, Arrow/Parquet analytics exports) are premature optimization for a system that does not yet have a single working operation executor. The threat model has real gaps, particularly around same-UID attacks, daemon impersonation, and the fundamental tension between "broker performs operations" and actually supporting the breadth of provider integrations described in the architecture doc.

---

## 2. Threat Model Gaps

### 2.1 Same-UID Attacks Are Not "Addressed", They Are Structural

The PRD (US-003, FR-2) relies on Unix socket peer credentials (`uid/gid/pid`) plus executable hash as the client identity foundation. The architecture doc (`docs/architecture.md`, Section 6) confirms this. But:

- **Any process running as the same UID can connect to the socket.** The socket is at `~/.opaque/run/opaqued.sock` with mode `0600` (see `lock_down_socket_path` in `crates/opaqued/src/main.rs`, line 96-104). This means every process the user runs -- including the LLM agent runtime, any malware the agent downloads, any npm postinstall script, any compromised VS Code extension -- can connect.
- **Executable hash is a speed bump, not a barrier.** The PRD says the daemon computes `exe_path + sha256`. But `/proc/<pid>/exe` on Linux is a symlink that a malicious process can manipulate via mount namespaces. On macOS, the executable path from `LOCAL_PEERPID` is more reliable but still trusts that the binary has not been replaced between hash computation and actual use (TOCTOU).
- **PID reuse.** The current `PeerInfo` struct (`crates/opaque-core/src/peer.rs`) captures PID. PIDs are recycled. On Linux, PID exhaustion/cycling attacks are well-documented. The PRD does not mention PID reuse as a threat. If a malicious process can cause the legitimate client to exit and then reuse its PID before the daemon notices, any PID-scoped lease or identity check is broken.
- **macOS code-sign identity is "when available" (PRD line 49).** This means all unsigned binaries get a degraded identity model. Most developer tools (Claude Code installed via npm, Codex via pip, custom scripts) are unsigned. The "stronger" identity path will almost never be exercised in practice.

**What is missing:** The PRD does not address daemon impersonation -- a malicious process could race to bind the socket path before the legitimate daemon starts. The stale-socket check in `main.rs` (lines 40-53) tries a connect and removes the file if it fails, but this is itself racy. There is no file locking, no pidfile, and no mechanism for clients to verify they are talking to the real daemon.

### 2.2 The "Untrusted Agent Runtime" Model Breaks Down

The architecture doc (Section 2) correctly identifies that if an LLM agent can run arbitrary commands, it can exfiltrate anything it can read. The PRD then proceeds to ignore this by defining an approval-based security model that assumes the agent will politely go through the Opaque RPC interface.

In practice:
- Claude Code and Codex run shell commands. They can `cat ~/.opaque/run/opaqued.sock` (not useful) but they can also read the policy TOML files, read the SQLite audit database, read the OS keychain metadata, and enumerate what secrets exist.
- The agent can observe the timing and content of approval prompts (by watching for the approval dialog process on Linux, or by monitoring process lists) even if it cannot directly approve them.
- The agent can attempt denial-of-service by flooding the daemon with requests, exhausting the single-permit approval semaphore, or crashing the daemon via malformed input.

**What is missing:** The PRD does not define a threat model document. There is no enumeration of threat actors, no attack tree, and no explicit statement of what is in-scope vs out-of-scope for defense. The "Important Constraint" in `architecture.md` Section 2 is the closest thing, but the PRD does not reference it or build on it.

### 2.3 Approval Fatigue as an Attack Vector

The PRD mentions "approval fatigue" in Success Metrics (line 152) and proposes leases (US-004) to reduce it. But approval fatigue is itself an attack vector: if a malicious client can trigger enough legitimate-looking approval requests, the user will eventually approve without reading. The PRD's solution -- leases -- actually makes this worse: once a user approves under fatigue, the lease gives the attacker a window of access instead of just one operation.

The PRD does not define rate limiting for approval requests per client, per operation, or per time window. The only concurrency control is the single-permit semaphore (`approval_gate` in `main.rs` line 63), which serializes prompts but does not limit their rate.

### 2.4 No Consideration of Supply Chain Attacks

The policy model (`docs/policy.md`) matches clients by `exe_path` and `exe_sha256`. But there is no discussion of what happens when the client binary is legitimately updated (new version of Claude Code). Every update changes the hash, which means:
- Policy rules with hardcoded hashes break on every client update.
- If hashes are not checked (to avoid breakage), the identity model collapses to just `exe_path`, which any process can spoof by naming itself accordingly.
- There is no key rotation or update ceremony for client identity.

---

## 3. Architectural Weaknesses

### 3.1 Single Points of Failure in the Approval Flow

The approval flow is entirely synchronous and single-threaded at the approval gate level. From `crates/opaqued/src/main.rs` (lines 181-183):

```rust
let Ok(_permit) = state.approval_gate.acquire().await else {
    return Response::err(Some(req.id), "internal", "approval gate closed");
};
```

This is a `Semaphore::new(1)` (line 63). Problems:

1. **If the approval UI hangs, the entire system is deadlocked.** The macOS implementation has a 120-second timeout (`approval.rs` line 88), but during those 120 seconds, no other approval can proceed. A malicious client can trigger an approval, causing the user to dismiss it, and then immediately trigger another one, keeping the gate locked.
2. **If the semaphore is poisoned (panic in the approval task), it is permanently closed.** The `Semaphore` will return `Err` on `acquire()` if it is closed, and the code returns an error, but there is no recovery path.
3. **The approval gate is global, not per-client.** A misbehaving client blocks approvals for all clients.

### 3.2 Race Conditions in Approval Flow

The PRD proposes operation-bound approvals (US-001) where the approval is tied to a specific `OperationRequest`. But the current architecture has no binding between the approval prompt and the operation. The sequence is:

1. Client sends request.
2. Daemon evaluates policy.
3. Daemon shows approval prompt (which currently is just a text reason string).
4. User approves.
5. Daemon executes operation.

Between steps 3 and 5, there is no cryptographic binding. The PRD says the approval summary should be "derived from this schema and hashed for signing/verifying" (US-002), but:
- For `local_bio` (macOS LocalAuthentication), the OS prompt shows a text reason and returns a boolean. There is no signature over the request content. The user is approving "a thing" but there is no proof that the daemon actually executes the thing the user saw.
- For polkit on Linux, the `details` HashMap is passed to the auth agent, but there is no cryptographic binding between what the user approved and what the daemon does afterward.
- Only the iOS factor (Secure Enclave signing over a challenge hash) provides real cryptographic binding, and that is a future/optional factor.

**The PRD claims operation-bound approvals but the available approval mechanisms cannot actually provide this property for the two primary v1 factors (local_bio on macOS and polkit on Linux).** The approval is bound only by trust in the daemon process itself, which is exactly the same trust model as the current unauthenticated `approval.prompt`.

### 3.3 Unix Socket Auth Model Limitations

Beyond the same-UID issues discussed in Section 2.1:

- **`XDG_RUNTIME_DIR` vs `~/.opaque/run`**: The socket path logic in `crates/opaque-core/src/socket.rs` (lines 6-22) falls back from `XDG_RUNTIME_DIR` to `~/.opaque/run`. On many Linux systems, `XDG_RUNTIME_DIR` is `/run/user/<uid>`, which is a tmpfs with correct ownership. But `~/.opaque/run` is on the user's home filesystem, which may be NFS-mounted, shared, or have different permission semantics. The PRD does not acknowledge this.
- **No authentication of the daemon to the client.** The client connects to a socket path and trusts that the daemon is legitimate. There is no challenge-response, no shared secret, and no daemon identity verification. A malicious process that races to bind the socket can impersonate the daemon and intercept all requests.
- **`OPAQUE_SOCK` environment variable override**: Any process can set `OPAQUE_SOCK` to redirect the client to a malicious socket. This is mentioned nowhere in the threat model.

### 3.4 Length-Delimited JSON over UDS

The protocol uses `tokio_util::codec::LengthDelimitedCodec` with a 1MB max frame size (`crates/opaque/src/main.rs` line 79, `crates/opaqued/src/main.rs` line 136). Issues:

- **1MB frame size is generous for what should be small JSON requests.** A malicious client can send 1MB of JSON and force the daemon to allocate and parse it. There is no request size validation beyond the frame limit.
- **No protocol versioning.** The PRD (US-002) calls for versioned envelopes, but the current `Request` struct (`crates/opaque-core/src/proto.rs`) has no version field. Adding one is a breaking change.
- **No request timeout.** A client can open a connection, send a partial frame (enough bytes to start the length-delimited read but not enough to complete it), and hold the connection indefinitely. There is no per-connection or per-request timeout in the daemon.
- **The protocol is synchronous request-response on a persistent connection** (the `while let Some(frame)` loop in `handle_conn`). This means a client that sends a request and then blocks before reading the response ties up a server task indefinitely. There is no mechanism to cancel or timeout stale connections.

The PRD says "use a typed internal request model even if the external protocol is JSON" (Technical Considerations, line 133) but does not question whether JSON over UDS is the right choice at all. For a security-critical local IPC protocol, alternatives like Cap'n Proto, FlatBuffers, or even a simple binary protocol with fixed-size headers would avoid the parsing attack surface of JSON (deeply nested objects, huge strings, unicode edge cases).

### 3.5 "Broker Performs Operations" Scalability

The architecture doc (Section 9) defines the broker as responsible for executing GitHub API calls, GitLab API calls, Kubernetes API calls, AWS SDK calls, and arbitrary HTTP requests. The PRD's Non-Goals (line 118) say "Implementing full GitHub/GitLab/Kubernetes/AWS connectors" is out of scope, but the functional requirements (FR-3, FR-4) and user stories (US-001, US-003) assume these operations exist and can be policy-gated.

The fundamental problem: **every new provider integration is a new attack surface inside the trusted daemon.** The daemon must:
- Parse provider-specific request parameters.
- Authenticate to the provider (managing tokens, OAuth flows, service accounts).
- Execute the API call (handling retries, rate limits, pagination).
- Sanitize the response (which requires understanding the provider's response format).

This is not a secrets broker -- it is a full API gateway. The PRD does not address:
- How provider connectors are developed, tested, and updated independently of the core daemon.
- What happens when a provider connector has a vulnerability (the entire daemon is compromised because it runs in one process).
- How to sandbox provider connectors from each other (a bug in the GitHub connector should not be able to access Vault credentials).

---

## 4. PRD-Specific Critique (User Stories)

### US-001: Replace `approval.prompt` with operation-bound approvals

- **Scope:** The story says "The daemon no longer exposes a generic approval.prompt RPC callable by clients." This is trivial -- delete the `"approval.prompt"` match arm in `main.rs` line 174. The hard part is building the entire operation request pipeline that replaces it, which is all of US-002 through US-008.
- **Acceptance criteria gap:** "The approval UI shows operation, target, client identity, and requested lease TTL." How? On macOS, `LAContext.evaluatePolicy` accepts a `localizedReason` string. You can put text in it, but the user has no way to verify that the text matches reality. On Linux, polkit `details` may or may not be shown depending on the auth agent (this is acknowledged in US-006 but not in US-001). The acceptance criteria are not testable as stated because they depend on UI behavior that varies by platform and environment.
- **Missing edge case:** What happens if the daemon is restarted between the time a request is submitted and the approval is granted? The PRD says leases are not revived on restart (US-004), but does not say what happens to pending approval requests. They are presumably lost (in-memory), but the client is still waiting on the socket. The client timeout and retry behavior is unspecified.

### US-002: Implement a typed, versioned OperationRequest envelope

- **Scope:** Reasonable, but the schema design is doing a lot of heavy lifting. The `OperationRequest` must be the canonical input to policy evaluation, approval, execution, and audit. Getting this wrong poisons everything downstream.
- **Acceptance criteria:** "The approval summary is derived from this schema and hashed for signing/verifying." Signing by whom? The daemon signs it for the iOS factor, but for `local_bio` there is no signature -- it is just a text prompt. This criterion is aspirational, not achievable for macOS/Linux v1 factors.
- **Missing:** There is no mention of request canonicalization. If the same logical request can be serialized in multiple ways (JSON key ordering, whitespace, optional fields), the hash will differ. The PRD needs to specify a canonical serialization (e.g., RFC 8785 JSON Canonicalization Scheme) or define the hash input format explicitly.

### US-003: Enforce client identity + allowlist policy on every request

- **Scope:** This is the entire policy engine. "Enforce client identity + allowlist policy on every request" is a feature, not a story.
- **Acceptance criteria:** "Default behavior is deny-all until policy permits." This is correct, but it means the system is unusable out of the box. First-run experience will be: install Opaque, try to use it, get denied on everything, have to manually write TOML policy rules. There is no onboarding flow, no interactive policy setup, and no way to discover what clients need to be allowed.
- **Dependency:** This story depends on US-002 (you need the `OperationRequest` to evaluate policy against). It also implicitly depends on having at least one operation implemented, or the policy engine has nothing to gate. These dependencies are not stated.
- **Missing:** The `exe_sha256` computation requires reading the client binary at connection time. For large binaries (VS Code is hundreds of MB), this adds latency to every connection. The PRD does not discuss caching, lazy evaluation, or the performance impact.

### US-004: Add approval leases with explicit TTL and scope

- **Scope:** Reasonable.
- **Acceptance criteria:** "Leases expire automatically and are not revived on daemon restart (fail closed)." This is correct for security but terrible for UX. If the daemon crashes during a CI/CD workflow, the user must re-approve everything. The PRD does not discuss graceful degradation.
- **Missing edge case:** What happens when the system clock is adjusted (NTP jump, timezone change, manual adjustment)? Lease expiration based on wallclock time is fragile. Use monotonic clocks for TTL enforcement.
- **Missing edge case:** What happens when the user's laptop sleeps and wakes? Does the lease TTL continue ticking during sleep? If it uses wallclock, yes. If it uses monotonic, it depends on the OS (Linux `CLOCK_MONOTONIC` does not tick during suspend, `CLOCK_BOOTTIME` does).

### US-005: Harden error handling and response sanitization

- **Scope:** This is a cross-cutting concern, not a user story. Every operation, every provider connector, every error path needs sanitization. Calling it one story suggests it can be done in one pass, but it is an ongoing discipline.
- **Acceptance criteria:** "Add tests for redaction/sanitization for representative provider/API failures." "Representative" is doing a lot of work. The real risk is the non-representative failure -- the edge case where a provider returns an error message containing a secret (e.g., AWS STS returning the access key ID in an error, or Vault returning the secret path in a 403 response).
- **Missing:** The current code (`main.rs` line 144) sends `e.to_string()` directly in error responses. This is exactly the pattern the PRD says to eliminate, but the acceptance criteria do not include "retrofit all existing error paths." There is no inventory of current error leak points.

### US-006: Linux approvals must show user-visible intent or fail closed

- **Acceptance criteria:** "If the environment cannot display intent ... the operation is denied with `approval_unavailable`." How does the daemon detect this? The current implementation (`approval.rs` lines 97-136) calls `polkit.CheckAuthorization` and returns whatever polkit returns. There is no mechanism to detect whether the auth agent actually displayed the intent details. Polkit does not provide a "did the user see the details" callback. The auth agent may display them, or it may just show "Authentication required" with no details.
- **Open question acknowledged but not resolved:** The PRD (Open Question 1) asks "Which desktop environments/auth agents are officially supported?" This is a blocking question. You cannot test this story without answering it. The story should be blocked on this decision, and the PRD should say so explicitly.
- **Missing:** The polkit policy file (`assets/linux/polkit/com.opaque.approve.policy`) defines a single action ID `com.opaque.approve` with a static message. There is no mechanism to pass per-operation details through the policy action. You would need multiple action IDs (one per operation type) or a custom auth agent that reads the `details` HashMap, which most standard auth agents do not do in a user-visible way.

### US-007: macOS approvals must work when daemon is packaged/backgrounded

- **Acceptance criteria:** "Define and validate the supported packaging model." This is a research task, not a user story with testable acceptance criteria. The answer depends on Apple's behavior with `LAContext` in background processes, which may change between macOS versions.
- **Blocking dependency:** Open Question 2 asks whether opaqued runs as a LaunchAgent or app bundle helper. This must be decided before any testing can begin. The story is not implementable until this is answered.
- **Missing:** The current `prompt_macos_blocking` implementation (`approval.rs` lines 48-94) calls `LAContext.evaluatePolicy` from a `spawn_blocking` task. If the daemon is a LaunchAgent without access to the login session's window server, this call may hang or fail silently. The 120-second timeout is the only safety net, and it means the daemon is unresponsive for two minutes before failing.

### US-008: Build append-only audit log with role-gated live feed

- **Scope:** This is at least three separate features (append-only log, role-gated access, live feed) bundled into one story.
- **Acceptance criteria:** "Subscribers are authenticated/authorized by client identity and policy." This requires the entire policy engine (US-003) to be working first. Dependency not stated.
- **Missing:** "Append-only" in what sense? SQLite does not provide append-only guarantees -- any process with write access to the database file can modify or delete rows. The PRD does not discuss tamper detection (hash chains, Merkle trees, write-ahead log integrity) or file-level write protection.
- **Missing:** What is the storage budget? Audit events for every request/approval/operation in a busy development session could generate thousands of events per day. The PRD mentions retention (90 days in `audit-analytics.md`) but does not include it in the acceptance criteria.

### US-009: Semantic search over sanitized audit events (Arrow-native)

- **This story should not exist in this PRD.** It is a nice-to-have analytics feature that has zero bearing on the "Secure Approval and Audit Hardening" mission stated in the title. It introduces two new complex dependencies (LanceDB, an embedding model) into a system that cannot yet execute a single operation.
- **Acceptance criteria:** "Embed asynchronously and store in an Arrow-native index (LanceDB) keyed by event_id." This requires choosing and integrating an embedding model. Open Question 4 asks "Are embeddings computed locally or via a cloud API?" If locally, the dependency surface area expands enormously (ONNX runtime, model weights, GPU acceleration). If via cloud API, you are sending sanitized but still potentially sensitive audit event text to a third party from a security tool. Either answer is problematic and the PRD defers this decision.
- **Missing dependency:** This depends on US-008 (audit log must exist), US-005 (sanitization must work), and a not-yet-defined embedding pipeline. None of these are stated.

---

## 5. Operational Realism

### 5.1 Approvals Blocking CI/CD Pipelines

The PRD does not address the most common real-world scenario: an LLM agent is running a workflow that requires setting a GitHub secret, and the user is in a meeting, asleep, or away from their desk. The approval prompt appears, the user does not respond, and the entire workflow times out.

The macOS implementation has a 120-second timeout. The PRD does not specify:
- What the client-side timeout should be.
- What happens when the approval times out (does the operation fail? retry? queue?).
- Whether there is a way to approve asynchronously (e.g., via the iOS app) when the desktop is locked.
- Whether batch approvals are supported (approve "set all secrets for repo X" rather than approving each one individually).

For real CI/CD use, approval leases (US-004) help, but only after the first approval. The first-time-use experience for a new repo or operation is always blocking.

### 5.2 Daemon Restarts Mid-Operation

The PRD says leases are not revived on restart (US-004). But what about in-flight operations?

1. Client sends `github.set_actions_secret` request.
2. Daemon approves, starts executing (fetches secret from Vault, encrypts for GitHub, calls GitHub API).
3. Daemon crashes between the GitHub API call and the response to the client.
4. Client gets a connection reset.
5. Client retries. Daemon restarts, requires re-approval.

The PRD mentions "operations idempotent via request_id where possible" (Technical Considerations, line 138) but does not define:
- How `request_id` is generated and tracked across daemon restarts.
- Whether partial operations are rolled back or re-executed.
- What the client should do on connection failure (retry immediately? back off? report to user?).

### 5.3 Corrupted Audit Logs

The PRD says SQLite is the system of record for audit (FR-9, `storage.md` Section 1.3). If the SQLite database is corrupted (disk error, incomplete write during crash, accidental deletion), there is:
- No backup mechanism defined.
- No WAL checkpoint strategy defined.
- No integrity verification (checksums on audit entries).
- No recovery procedure documented.

For a system that claims "100% of operations have a complete correlated event chain in the audit log" (Success Metrics, line 156), there is no discussion of what happens when this invariant is violated.

### 5.4 Debugging Approval Failures Without Exposing Secrets

The PRD (US-005) says verbose error details are logged at debug level. But debug logging is exactly what you turn on when debugging approval failures, and approval failures often involve provider credentials (expired tokens, invalid API keys, wrong permissions).

There is no structured approach to:
- Safe debug logging (what fields are always safe, what fields require masking).
- Debug log access control (who can read debug logs, where are they stored).
- Temporary debug log enabling with automatic expiration (to prevent leaving debug logging on in production).

### 5.5 Polkit Intent Visibility

The PRD (US-006, Open Question 1) acknowledges that polkit auth agents may not show the `details` HashMap to the user. In practice:

- **GNOME** (`polkit-gnome-authentication-agent-1`): shows only the `<message>` from the policy XML and optionally the `<description>`. Does NOT display arbitrary details from `CheckAuthorization`.
- **KDE** (`polkit-kde-authentication-agent-1`): similar behavior.
- **MATE, XFCE, others**: varies, generally does not display details.
- **Headless/SSH**: no auth agent at all.

This means that on virtually all Linux desktops, the user sees "Authentication is required to approve an Opaque operation" (from the policy file, line 8 of `com.opaque.approve.policy`) with no indication of which operation, target, or client is requesting approval. The user is literally approving blind.

The PRD's Design Consideration (line 125) suggests "ship a minimal local UI helper for approvals" as a fallback, but this is not in any user story and has no acceptance criteria. It is a hand-wave toward the correct solution.

---

## 6. Missing Requirements

### 6.1 Requirements That Should Be in the PRD But Are Not

1. **Daemon lifecycle management.** How is the daemon started, stopped, upgraded, and monitored? LaunchAgent plist? systemd unit? The PRD mentions packaging (US-007) for macOS but has no equivalent for Linux.

2. **Socket cleanup and daemon locking.** The current stale-socket detection (`main.rs` lines 40-53) is racy. There should be a proper pidfile and advisory file lock mechanism.

3. **Client timeout and retry specification.** The client (`crates/opaque/src/main.rs`) has no timeout on the connection or response. If the daemon hangs, the client hangs forever.

4. **Graceful shutdown behavior.** What happens to in-flight requests when the daemon receives SIGTERM? The current code (line 77-79) just breaks out of the accept loop. In-flight tasks are dropped when the tokio runtime shuts down. Clients get connection resets.

5. **Multi-connection behavior.** Can the same client open multiple connections? Can different clients have concurrent in-flight requests? The daemon spawns a task per connection but has a global approval gate. These interactions are unspecified.

6. **Secret material memory safety.** The architecture doc says secrets should only exist in `opaqued` memory, but there is no discussion of:
   - Zeroing secret memory after use (`zeroize` crate).
   - Preventing secrets from being paged to swap (`mlock`).
   - Preventing secrets from appearing in core dumps (setting `PR_SET_DUMPABLE` on Linux, `KERN_PROC_PROT` on macOS).

7. **MCP integration specification.** The architecture doc mentions MCP server integration, and this is one of the primary use cases (LLM tools use MCP). But the PRD does not define how the MCP server process relates to the daemon process, how it authenticates, or what operations it can expose.

### 6.2 Missing Non-Functional Requirements

1. **Latency budgets.** The Success Metrics mention "p95 approval prompt time-to-interaction < 2s" but do not specify:
   - Maximum acceptable latency for policy evaluation.
   - Maximum acceptable latency for provider secret fetch.
   - Maximum acceptable end-to-end latency for a complete operation (request to response).
   - Maximum connection establishment latency.

2. **Resource limits.** No specification for:
   - Maximum concurrent connections.
   - Maximum memory usage.
   - Maximum disk usage for audit logs and semantic index.
   - CPU usage bounds for embedding computation.

3. **Availability.** No SLA or availability target. For a tool that blocks CI/CD workflows, daemon downtime is directly costly. Is restart time measured? Is there a health check endpoint? (There is `ping`, but no readiness/liveness distinction.)

4. **Compatibility matrix.** No specification of:
   - Minimum macOS version (LocalAuthentication API availability varies).
   - Minimum Linux kernel version (for `SO_PEERCRED`).
   - Required polkit version.
   - Supported file systems (NFS behavior with Unix sockets is different from local FS).

### 6.3 Missing Compliance/Regulatory Considerations

1. **Biometric data handling.** The system uses Touch ID and Face ID. In jurisdictions with BIPA (Illinois Biometric Information Privacy Act), GDPR Article 9 (special categories of data), or similar laws, processing biometric data has specific requirements. The PRD does not discuss data protection impact assessment, consent requirements, or legal basis for biometric processing.

2. **Audit log retention.** If audit logs are used for compliance, there are often minimum retention periods (SOX: 7 years, HIPAA: 6 years). The PRD mentions 30-90 day SQLite retention with Parquet rolloff but does not discuss compliance-driven retention requirements.

3. **Data residency.** If embeddings are computed via a cloud API (Open Question 4), audit event text leaves the machine. This may violate data residency requirements or data processing agreements.

---

## 7. Overengineering Risks

### 7.1 LanceDB / Semantic Search (US-009)

This feature adds:
- A dependency on LanceDB (Rust bindings, Arrow integration).
- A dependency on an embedding model (local ONNX runtime or cloud API).
- An asynchronous indexing pipeline.
- A query interface with role-based access.

For a system that does not yet have a single audit event, this is premature by at least two major versions. The justification is "find similar events" but:
- The event vocabulary is tiny (a handful of operation types, a handful of targets). Full-text search over SQLite (`FTS5`) would cover 99% of use cases with zero additional dependencies.
- Semantic search over structured audit events is a solution looking for a problem. Users do not search audit logs with natural language; they search by time range, operation type, target, and outcome -- all of which are structured fields that SQL handles trivially.

**Cut this from v1 entirely.** If users ask for it after the system has real usage, add it in v2.

### 7.2 Arrow/Parquet Analytics Exports (FR-11)

Same argument as above. Parquet export is useful when:
- You have millions of events.
- You need to run analytical queries across long time ranges.
- You need to share data with external BI tools.

None of these apply to a single-user local daemon in v1. SQLite is more than sufficient for the audit volumes this system will generate. The PRD adds Parquet as a requirement (FR-11) before the system has a single user, let alone enough data to justify columnar storage.

**Cut this from v1.** Keep the SQLite schema extensible for future Parquet export, but do not build the export pipeline yet.

### 7.3 Live Feed with SSE/Arrow Flight (audit-analytics.md Section 4)

The audit-analytics doc proposes three feed transport options: UDS stream, HTTP SSE, and Arrow Flight. For v1:
- `tokio::broadcast` in-process is sufficient.
- A simple `opaque tail --follow` over UDS is a nice-to-have.
- HTTP SSE and Arrow Flight are enterprise features that add HTTP server dependencies to a local daemon.

**Cut SSE and Arrow Flight from v1.** Implement in-process broadcast and a simple UDS tail.

### 7.4 iOS Mobile Approvals (mentioned in PRD, designed in mobile-approvals.md)

The mobile approvals design is comprehensive and well-thought-out, but it requires:
- An iOS app (development, testing, App Store review).
- QR pairing protocol implementation.
- Local network discovery (mDNS or explicit IP).
- Push notification infrastructure (APNs).
- Secure Enclave key management.

This is a project in itself. The PRD correctly lists it as a non-goal for full implementation (line 119) but still references `ios_faceid` as a factor in FR-6 and in policy examples. Either commit to building it in this PRD or remove all references to it.

---

## 8. Recommendations

### 8.1 Must Fix Before Implementation (Priority 1)

1. **Write a threat model document.** Enumerate threat actors (malicious LLM agent, compromised dependency, local malware, physical attacker, social engineering), attack vectors (socket impersonation, approval spam, TOCTOU on exe hash, PID reuse, environment variable hijacking), and explicitly state what is defended against and what is not.

2. **Solve the daemon impersonation problem.** Add a daemon identity mechanism: generate a random token at first run, store it in OS keychain, and include it in a well-known file (with strict permissions) that clients verify before connecting. Or use a fixed socket path in a daemon-owned directory with verified ownership.

3. **Add rate limiting to approval requests.** Per-client, per-operation, with configurable limits. Include an exponential backoff on denied approvals.

4. **Define the protocol version negotiation.** The first message on a new connection should include `api_version` (from `opaque-core/src/lib.rs` line 5, which defines `API_VERSION: u32 = 1` but never uses it). Define forward/backward compatibility rules.

5. **Add connection and request timeouts.** Both client-side and server-side. A request that has not received a response within N seconds should be cancelled. A connection that has been idle for M seconds should be closed.

6. **Decide the macOS packaging model (Open Question 2) and the Linux auth agent story (Open Question 1).** These are blocking decisions. Do not start implementation until they are answered.

7. **Add `zeroize` for secret material in memory.** This is a basic security hygiene requirement for a secrets broker.

### 8.2 Cut from v1

1. **US-009 (Semantic search / LanceDB).** Replace with SQLite FTS5 full-text search over sanitized event text, if any search is needed at all.
2. **FR-11 (Arrow/Parquet exports).** Defer to v2.
3. **All references to `ios_faceid` as a v1 factor.** Keep the design doc but remove it from FR-6 and from policy examples. v1 factors are `local_bio` only.
4. **Arrow Flight / SSE live feed transports.** v1 feed is in-process broadcast + optional UDS tail.
5. **HTTP proxy operation (`http.request_with_auth`).** This is a generic authenticated HTTP proxy, which is an enormous attack surface. Defer to v2 and focus on the specific provider operations (GitHub, GitLab, K8s) where the request/response formats are well-understood.

### 8.3 Add to v1

1. **Daemon health check and lifecycle management.** Pidfile, file locking, systemd/launchd integration, graceful shutdown with in-flight request draining.
2. **Client retry and timeout specification.** Define what clients should do on connection failure, request timeout, and approval timeout.
3. **Policy bootstrapping / first-run experience.** Interactive `opaque init` that detects installed tools, generates a starter policy, and walks the user through a first approval.
4. **Approval rate limiting and anti-spam.** Per-client request throttling, approval prompt cooldown, maximum pending approvals.
5. **Memory safety for secrets.** `zeroize`, `mlock`, disable core dumps.
6. **Integration tests for the approval flow.** The current code has zero tests. At minimum: policy deny, policy allow with approval, approval timeout, malformed request handling, concurrent approval requests.
7. **Specify the Linux approval UI story concretely.** If polkit auth agents cannot show intent, commit to shipping a custom approval UI (GTK/Qt dialog or a terminal-based approval flow) and include it in v1 scope. Do not ship a "blind approval" system.

### 8.4 Structural Recommendations

1. **Split US-003 into at least three stories:** client identity computation, policy rule evaluation, and deny-by-default enforcement. Each is independently testable and deployable.
2. **Split US-008 into at least two stories:** append-only audit log (write path) and role-gated live feed (read path). These have different dependencies and different risk profiles.
3. **Add explicit dependency links between stories.** US-001 depends on US-002. US-003 depends on US-002. US-004 depends on US-003. US-008 depends on US-003 (for subscriber auth). US-009 depends on US-008. None of these are stated in the PRD.
4. **Add a story for the protocol upgrade** (versioned envelope, `api_version` negotiation, deprecation of the current unversioned `Request` format). This is a prerequisite for US-002 and should be its own story.
5. **Consider process isolation for provider connectors.** Run each provider connector as a separate process or at minimum in a separate tokio task group with resource limits. A panicking GitHub connector should not take down the daemon.

---

## Appendix: Code-Level Observations

The following are specific issues in the current codebase that the PRD should acknowledge as technical debt to be resolved.

| File | Line(s) | Issue |
|------|---------|-------|
| `crates/opaqued/src/main.rs` | 144 | `e.to_string()` sent directly in error response -- exactly the leak pattern US-005 aims to fix. |
| `crates/opaqued/src/main.rs` | 63 | `Semaphore::new(1)` -- no recovery if the semaphore is closed after a panic. |
| `crates/opaqued/src/main.rs` | 40-53 | Stale socket detection is racy (no file lock). |
| `crates/opaqued/src/main.rs` | 122-168 | No connection timeout, no request timeout, no max concurrent connections. |
| `crates/opaqued/src/main.rs` | 174-189 | `approval.prompt` is callable by any same-UID client with any reason string -- the exact problem the PRD identifies. |
| `crates/opaqued/src/approval.rs` | 88 | 120-second timeout is hardcoded, not configurable. During this time the approval gate is locked. |
| `crates/opaqued/src/approval.rs` | 121 | `details` HashMap passed to polkit is not displayed by standard auth agents, making Linux approvals blind. |
| `crates/opaque-core/src/peer.rs` | 5-9 | `PeerInfo` has no `exe_path` or `exe_sha256` -- the PRD assumes these exist but they are not implemented. |
| `crates/opaque-core/src/proto.rs` | 4-9 | `Request` has no `version` field, no `request_id` (uses `id: u64`), and `params` is untyped `serde_json::Value`. |
| `crates/opaque-core/src/socket.rs` | 24-39 | `ensure_socket_parent_dir` uses `create_dir_all` which may create intermediate directories with wrong permissions before `set_permissions` is called. |
| `crates/opaque/src/main.rs` | 67-102 | Client has no connection timeout, no response timeout, and retries are not implemented. |

---

*This critique was written to be harsh and specific. The core idea of Opaque -- a secrets broker that prevents LLM agents from seeing secrets -- is sound and worth building. But the PRD as written conflates too many concerns, defers too many blocking decisions, and includes features that distract from the security-critical foundation that does not yet exist. Build the foundation first: identity, policy, one working operation, hardened approvals on one platform, and audit. Everything else is premature.*
