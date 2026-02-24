// ApprovalView.swift
// Face ID / Touch ID approval prompt for incoming requests.

import SwiftUI

/// View that displays an incoming approval request and prompts
/// the user to approve or deny via Face ID / Touch ID.
///
/// When the user taps "Approve":
/// 1. Trigger biometric authentication (Face ID / Touch ID).
/// 2. On success, use the Secure Enclave key to sign the challenge.
/// 3. Send the signed response back to the daemon.
///
/// The daemon will verify the signature against the stored device public key
/// and, if valid, approve the operation.
struct ApprovalView: View {
    let request: ApprovalRequest
    var onResult: (ApprovalResult) -> Void

    @State private var isProcessing = false
    @State private var errorMessage: String?

    var body: some View {
        VStack(spacing: 20) {
            // Header
            HStack {
                Image(systemName: "shield.checkered")
                    .font(.title)
                    .foregroundColor(.orange)
                Text("Approval Required")
                    .font(.title2)
                    .fontWeight(.bold)
            }
            .padding(.top)

            // Operation details
            VStack(alignment: .leading, spacing: 12) {
                DetailRow(label: "Operation", value: request.operationName)
                DetailRow(label: "Summary", value: request.operationSummary)
                DetailRow(label: "Client", value: request.clientIdentity)

                if !request.target.isEmpty {
                    ForEach(Array(request.target.sorted(by: { $0.key < $1.key })), id: \.key) { key, value in
                        DetailRow(label: key, value: value)
                    }
                }

                HStack {
                    Image(systemName: "clock")
                        .foregroundColor(request.isExpired ? .red : .secondary)
                    Text(request.timeRemaining)
                        .foregroundColor(request.isExpired ? .red : .secondary)
                }
                .font(.callout)
            }
            .padding()
            .background(Color(.systemGray6))
            .cornerRadius(12)
            .padding(.horizontal)

            if let error = errorMessage {
                Text(error)
                    .font(.callout)
                    .foregroundColor(.red)
            }

            Spacer()

            // Action buttons
            if !request.isExpired {
                VStack(spacing: 12) {
                    Button(action: approve) {
                        HStack {
                            Image(systemName: "faceid")
                            Text("Approve with Face ID")
                        }
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.green)
                        .foregroundColor(.white)
                        .cornerRadius(12)
                    }
                    .disabled(isProcessing)

                    Button(action: deny) {
                        Text("Deny")
                            .font(.headline)
                            .frame(maxWidth: .infinity)
                            .padding()
                            .foregroundColor(.red)
                    }
                    .disabled(isProcessing)
                }
                .padding(.horizontal, 32)
            } else {
                Text("This request has expired.")
                    .foregroundColor(.secondary)
            }

            if isProcessing {
                ProgressView("Authenticating...")
            }
        }
        .padding(.bottom, 32)
    }

    private func approve() {
        isProcessing = true
        errorMessage = nil

        // TODO: Implement actual approval flow:
        // 1. Call KeyManager.signChallenge(challengeHex:, serverId:)
        //    - This triggers Face ID via Secure Enclave key access control
        // 2. On success, return the signature via onResult(.approved(signatureHex:))
        // 3. On failure, set errorMessage

        // Placeholder:
        // Task {
        //     do {
        //         let signature = try await KeyManager.shared.signChallenge(
        //             challengeHex: request.challengeHex,
        //             serverId: request.serverId
        //         )
        //         onResult(.approved(signatureHex: signature))
        //     } catch {
        //         errorMessage = error.localizedDescription
        //         isProcessing = false
        //     }
        // }
    }

    private func deny() {
        onResult(.denied)
    }
}

/// A labeled detail row for the approval view.
private struct DetailRow: View {
    let label: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.caption)
                .foregroundColor(.secondary)
            Text(value)
                .font(.body)
        }
    }
}

#if DEBUG
struct ApprovalView_Previews: PreviewProvider {
    static var previews: some View {
        ApprovalView(
            request: ApprovalRequest(
                id: "req-001",
                serverId: "server-001",
                createdAt: Date(),
                expiresAt: Date().addingTimeInterval(120),
                operationSummary: "Set GitHub Actions secret AWS_KEY on org/repo",
                operationName: "github.set_actions_secret",
                target: ["repo": "myorg/myrepo"],
                clientIdentity: "uid=501 pid=1234 exe=/usr/bin/claude-code",
                challengeHex: "abcdef0123456789"
            ),
            onResult: { _ in }
        )
    }
}
#endif
