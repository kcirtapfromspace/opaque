// ApprovalClient.swift
// HTTPS client for communicating with the opaqued daemon.

import Foundation

/// HTTPS client for the opaqued approval API.
///
/// Communicates with the daemon over local-network HTTPS using
/// server public key pinning (no CA trust required).
///
/// Endpoints:
/// - `POST /pair` — complete device pairing
/// - `GET  /approvals` — fetch pending approval requests
/// - `POST /approvals/:id/respond` — submit signed approval response
final class ApprovalClient {
    /// The server endpoint (e.g., "https://192.168.1.100:8443").
    let endpoint: String

    /// The server's pinned public key (hex-encoded).
    /// Used to verify server identity without trusting a CA.
    let serverPublicKey: String

    init(endpoint: String, serverPublicKey: String) {
        self.endpoint = endpoint
        self.serverPublicKey = serverPublicKey
    }

    // MARK: - Pairing

    /// Complete device pairing by sending the device public key.
    ///
    /// - Parameters:
    ///   - nonce: The pairing nonce from the QR code.
    ///   - devicePublicKey: The device's Ed25519/P-256 public key (hex-encoded).
    ///   - deviceName: Human-readable device name.
    /// - Returns: The assigned device ID.
    func completePairing(
        nonce: String,
        devicePublicKey: String,
        deviceName: String
    ) async throws -> String {
        // TODO: Implement HTTPS POST to /pair
        //
        // let url = URL(string: "\(endpoint)/pair")!
        // var request = URLRequest(url: url)
        // request.httpMethod = "POST"
        // request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        // request.httpBody = try JSONEncoder().encode(PairRequest(
        //     nonce: nonce,
        //     devicePublicKey: devicePublicKey,
        //     deviceName: deviceName
        // ))
        //
        // let session = makePinnedSession()
        // let (data, response) = try await session.data(for: request)
        // guard let httpResponse = response as? HTTPURLResponse,
        //       httpResponse.statusCode == 200 else {
        //     throw ApprovalClientError.pairingFailed
        // }
        //
        // let result = try JSONDecoder().decode(PairResponse.self, from: data)
        // return result.deviceId

        fatalError("TODO: Implement pairing request")
    }

    // MARK: - Approval requests

    /// Fetch pending approval requests from the server.
    ///
    /// - Parameter deviceId: This device's ID for authentication.
    /// - Returns: Array of pending approval requests.
    func fetchPendingApprovals(deviceId: String) async throws -> [ApprovalRequest] {
        // TODO: Implement HTTPS GET to /approvals
        //
        // let url = URL(string: "\(endpoint)/approvals?device_id=\(deviceId)")!
        // let session = makePinnedSession()
        // let (data, _) = try await session.data(from: url)
        // return try JSONDecoder().decode([ApprovalRequest].self, from: data)

        fatalError("TODO: Implement approval fetch")
    }

    /// Submit a signed approval response.
    ///
    /// - Parameters:
    ///   - requestId: The approval request ID.
    ///   - deviceId: This device's ID.
    ///   - signatureHex: The Ed25519/P-256 signature over the challenge (hex-encoded).
    func submitApproval(
        requestId: String,
        deviceId: String,
        signatureHex: String
    ) async throws {
        // TODO: Implement HTTPS POST to /approvals/:id/respond
        //
        // let url = URL(string: "\(endpoint)/approvals/\(requestId)/respond")!
        // var request = URLRequest(url: url)
        // request.httpMethod = "POST"
        // request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        // request.httpBody = try JSONEncoder().encode(ApprovalResponse(
        //     deviceId: deviceId,
        //     signatureHex: signatureHex
        // ))
        //
        // let session = makePinnedSession()
        // let (_, response) = try await session.data(for: request)
        // guard let httpResponse = response as? HTTPURLResponse,
        //       httpResponse.statusCode == 200 else {
        //     throw ApprovalClientError.approvalFailed
        // }

        fatalError("TODO: Implement approval submission")
    }

    // MARK: - HTTPS session with public key pinning

    /// Create a URLSession that pins the server's public key.
    ///
    /// This allows secure communication with a self-signed certificate
    /// by verifying the server's public key matches the one received
    /// during pairing (from the QR code).
    private func makePinnedSession() -> URLSession {
        // TODO: Implement URLSession with custom URLSessionDelegate
        // that performs public key pinning against self.serverPublicKey.
        //
        // class PinningDelegate: NSObject, URLSessionDelegate {
        //     let pinnedKey: String
        //     init(pinnedKey: String) { self.pinnedKey = pinnedKey }
        //
        //     func urlSession(
        //         _ session: URLSession,
        //         didReceive challenge: URLAuthenticationChallenge
        //     ) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        //         guard let trust = challenge.protectionSpace.serverTrust,
        //               let certificate = SecTrustGetCertificateAtIndex(trust, 0),
        //               let publicKey = SecCertificateCopyKey(certificate) else {
        //             return (.cancelAuthenticationChallenge, nil)
        //         }
        //         // Compare public key with pinnedKey
        //         // ...
        //         return (.useCredential, URLCredential(trust: trust))
        //     }
        // }

        return URLSession.shared  // TODO: Replace with pinned session
    }
}

/// Errors from the approval client.
enum ApprovalClientError: Error, LocalizedError {
    case pairingFailed
    case approvalFailed
    case serverUnreachable
    case invalidResponse

    var errorDescription: String? {
        switch self {
        case .pairingFailed:
            return "Failed to complete device pairing"
        case .approvalFailed:
            return "Failed to submit approval"
        case .serverUnreachable:
            return "Server is not reachable"
        case .invalidResponse:
            return "Invalid response from server"
        }
    }
}
