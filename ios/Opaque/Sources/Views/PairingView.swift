// PairingView.swift
// QR code scanner view for initial pairing with opaqued.

import SwiftUI

/// View that presents a camera-based QR code scanner for pairing
/// with a local opaqued daemon.
///
/// Flow:
/// 1. User runs `opaque device pair` on their desktop.
/// 2. Daemon displays a QR code in the terminal.
/// 3. User scans the QR code with this view.
/// 4. App generates a Secure Enclave key pair.
/// 5. App sends device_id + public_key + pairing_code to daemon.
/// 6. Daemon stores the device key and confirms pairing.
struct PairingView: View {
    @EnvironmentObject var appState: AppState
    @State private var isScanning = false
    @State private var pairingError: String?
    @State private var isPairing = false

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "qrcode.viewfinder")
                .font(.system(size: 80))
                .foregroundColor(.accentColor)

            Text("Pair with Opaque")
                .font(.title)
                .fontWeight(.bold)

            Text("Run `opaque device pair` on your computer, then scan the QR code to connect.")
                .font(.body)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)

            if let error = pairingError {
                Text(error)
                    .font(.callout)
                    .foregroundColor(.red)
                    .padding()
            }

            Button(action: startScanning) {
                HStack {
                    Image(systemName: "camera.fill")
                    Text("Scan QR Code")
                }
                .font(.headline)
                .frame(maxWidth: .infinity)
                .padding()
                .background(Color.accentColor)
                .foregroundColor(.white)
                .cornerRadius(12)
            }
            .padding(.horizontal, 32)
            .disabled(isPairing)

            if isPairing {
                ProgressView("Pairing...")
            }

            Spacer()
        }
        .navigationTitle("Setup")
    }

    private func startScanning() {
        // TODO: Present AVCaptureSession-based QR scanner.
        // On successful scan:
        // 1. Parse QR JSON payload (server_id, public_key, port, nonce, expires_at)
        // 2. Validate nonce and expiry
        // 3. Generate Secure Enclave key via KeyManager
        // 4. Send pairing request to daemon endpoint
        // 5. On success, create PairedServer and add to appState
        isScanning = true
        pairingError = nil
    }

    // TODO: Implement QR scan result handler
    // private func handleQRResult(_ payload: QRPayload) async { ... }
}

/// Decoded QR payload from daemon.
///
/// Matches the `QrPayload` struct in `crates/opaqued/src/pairing/mod.rs`.
struct QRPayload: Codable {
    let serverId: String
    let publicKey: String
    let port: Int
    let nonce: String
    let createdAt: Int64
    let expiresAt: Int64

    enum CodingKeys: String, CodingKey {
        case serverId = "server_id"
        case publicKey = "public_key"
        case port
        case nonce
        case createdAt = "created_at"
        case expiresAt = "expires_at"
    }
}

#if DEBUG
struct PairingView_Previews: PreviewProvider {
    static var previews: some View {
        NavigationStack {
            PairingView()
                .environmentObject(AppState())
        }
    }
}
#endif
