// PairedServer.swift
// Model for a paired opaqued daemon server.

import Foundation

/// Represents a paired opaqued daemon that this device can approve requests for.
struct PairedServer: Identifiable, Codable {
    /// Unique server identifier (UUID from daemon).
    let id: String

    /// Human-readable server name (e.g., hostname or user-assigned label).
    var name: String

    /// Server's Ed25519 public key (hex-encoded, 64 chars).
    /// Used to verify server identity and encrypt communications.
    let serverPublicKey: String

    /// HTTPS endpoint for reaching the daemon (e.g., "https://192.168.1.100:8443").
    var endpoint: String

    /// When this device was paired with the server (ISO 8601).
    let pairedAt: Date

    /// When the last successful approval was completed.
    var lastUsed: Date?

    /// The device key ID registered with this server.
    /// Corresponds to the `device_id` in the daemon's paired_devices.json.
    let deviceKeyId: String
}

// MARK: - Convenience initializer for QR pairing

extension PairedServer {
    /// Create a PairedServer from QR payload data after successful pairing.
    ///
    /// - Parameters:
    ///   - qrPayload: Decoded QR payload from daemon.
    ///   - deviceKeyId: The device key ID assigned by the daemon.
    ///   - endpoint: The HTTPS endpoint for the daemon.
    init(
        serverId: String,
        serverPublicKey: String,
        deviceKeyId: String,
        endpoint: String
    ) {
        self.id = serverId
        self.name = "Opaque Server"  // TODO: Resolve hostname via Bonjour
        self.serverPublicKey = serverPublicKey
        self.endpoint = endpoint
        self.pairedAt = Date()
        self.lastUsed = nil
        self.deviceKeyId = deviceKeyId
    }
}
