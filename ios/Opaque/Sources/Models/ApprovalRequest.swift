// ApprovalRequest.swift
// Model for an incoming approval request from the paired daemon.

import Foundation

/// An incoming approval request from an opaqued daemon.
///
/// The daemon sends this when a policy-gated operation requires
/// iOS Face ID / Touch ID approval.
struct ApprovalRequest: Identifiable, Codable {
    /// Unique request identifier (UUID).
    let id: String

    /// Server ID that sent this request.
    let serverId: String

    /// When the request was created.
    let createdAt: Date

    /// When the request expires (approval must complete before this time).
    let expiresAt: Date

    /// Human-readable operation description (e.g., "Set GitHub Actions secret on org/repo").
    let operationSummary: String

    /// The operation name (e.g., "github.set_actions_secret").
    let operationName: String

    /// Target details (e.g., repo name, cluster, namespace).
    let target: [String: String]

    /// Client identity that triggered the operation.
    let clientIdentity: String

    /// The challenge bytes (hex-encoded) that must be signed.
    /// Constructed as: H(server_id || request_id || sha256(operation_summary) || expires_at)
    let challengeHex: String
}

// MARK: - Approval status

/// The result of processing an approval request.
enum ApprovalResult {
    /// User approved via Face ID / Touch ID and the signature was sent.
    case approved(signatureHex: String)

    /// User explicitly denied the request.
    case denied

    /// The request expired before the user could respond.
    case expired

    /// An error occurred during approval (e.g., biometric failure).
    case error(String)
}

// MARK: - Display helpers

extension ApprovalRequest {
    /// Whether this request has expired.
    var isExpired: Bool {
        Date() > expiresAt
    }

    /// Time remaining until expiry, as a human-readable string.
    var timeRemaining: String {
        let remaining = expiresAt.timeIntervalSince(Date())
        if remaining <= 0 {
            return "Expired"
        }
        let minutes = Int(remaining) / 60
        let seconds = Int(remaining) % 60
        if minutes > 0 {
            return "\(minutes)m \(seconds)s"
        }
        return "\(seconds)s"
    }
}
