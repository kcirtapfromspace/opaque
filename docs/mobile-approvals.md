# Mobile Approvals (QR Pairing + Face ID)

This document describes a second-device approval factor where an iOS app gates approvals with Face ID. The goal is "proof of life" on a separate device, and an approval path that never returns plaintext secrets to the LLM client.

## 1. Terminology: "Passkey" vs "Device Key"

There are two viable models:

1. **True passkeys (WebAuthn)**:
   - Uses Apple's passkey UX (often includes a QR code flow when approving on a nearby iPhone).
   - Requires a WebAuthn relying party identifier (a domain) and typically a browser/webview ceremony.
   - Best when you want standards-based auth and can accept a small webview/browser dependency.
2. **AgentPass device key (recommended for v1 mobile app)**:
   - The AgentPass iOS app creates a device-bound signing key in Secure Enclave.
   - Each approval requires Face ID to use the key (user verification).
   - Pairing happens via a QR code that transfers the daemon identity + one-time pairing secret.

This repo uses the phrase "passkey" loosely in conversation; for implementation we recommend model (2) first because it stays local-first and avoids requiring a domain/Associated Domains to bootstrap WebAuthn.

## 2. Pairing Flow (QR Code)

### Goal

Allow the user to pair exactly one (or more) iOS devices with `agentpassd` so the daemon can later accept signed approvals.

### Pairing data carried in QR

The QR payload should be a compact JSON or URI containing:

- `server_id`: stable daemon ID (UUID)
- `server_pubkey`: daemon public key used for request encryption and/or server identity pinning
- `pairing_code`: one-time secret (high-entropy) with short TTL (e.g. 5 minutes)
- `endpoint`: how the phone reaches the daemon
  - v1 (local network): `https://<host>:<port>` with pinned self-signed cert fingerprint OR embedded server pubkey
  - v2 (push): an APNs token/route or relay endpoint if you add a cloud relay
- `created_at`, `expires_at`

### Pairing handshake (high level)

1. User runs: `agentpass pair ios` on desktop.
2. `agentpassd` creates a pairing session and shows QR.
3. iOS app scans QR and pins the daemon identity (server pubkey or cert fingerprint).
4. iOS app generates a Secure Enclave signing key and sends:
   - `device_id`
   - `device_pubkey`
   - `device_name` (optional)
   - `pairing_code`
5. `agentpassd` verifies `pairing_code` + TTL and stores the device public key.

## 3. Approval Flow (Face ID Gate)

### Data model

An approval request must bind the signature to the exact human-visible intent:

- `request_id` (random)
- `created_at`, `expires_at`
- `client_identity` (uid/pid/exe hash, codesign info)
- `operation` + `target` (repo/project/cluster/namespace/etc)
- `policy`: which factor(s) are required and what lease TTL is requested

### Sequence

1. `agentpassd` creates an approval request and places it in a pending queue.
2. iOS app fetches pending requests (pull) or receives a push notification (push).
3. User taps "Approve" in the iOS app.
4. The iOS app prompts Face ID and then signs a challenge:
   - challenge = `H(server_id || request_id || sha256(request_summary_json) || expires_at)`
5. iOS app submits `device_id`, `request_id`, `signature`.
6. `agentpassd` verifies signature using stored `device_pubkey`, checks TTL, marks approved and issues an approval lease.

The daemon should never accept approvals where the app did not do a biometric user-verification step (iOS must enforce this via Secure Enclave key access control).

## 4. Transport Options

### Local-network only (recommended v1)

- `agentpassd` runs a small HTTPS server bound to LAN (or loopback + mDNS, depending on needs).
- iOS app talks directly to the daemon when on the same network.
- Pros: no cloud dependency, simpler threat model.
- Cons: phone must be on same network and app must be opened to approve (unless you add background modes).

### Push / relay (v2)

- Use APNs + optional relay to reach the phone reliably.
- Requires Apple Developer provisioning and some server component (or a relay mode on the desktop).

## 5. Policy Integration

Policy should be able to require mobile approvals for high-risk operations:

- GitHub/GitLab secret writes in prod repos
- Kubernetes secret writes in prod clusters
- AWS operations that could exfiltrate data or mint credentials

The policy engine should support "step-up":

- require `local_bio` for most approvals
- require `local_bio + ios_faceid` for production targets

## 6. Security Notes

- Fail closed if the mobile factor is required but no paired device is available.
- Rate-limit pairing attempts and approval submissions.
- Support device revocation (`agentpass devices remove <id>`).
- Store device public keys and audit log in a local DB (SQLite) with strict filesystem permissions.

