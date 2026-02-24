// KeyManager.swift
// Secure Enclave key generation and Ed25519 signing for device authentication.

import Foundation
import CryptoKit
import LocalAuthentication

/// Manages device signing keys in the Secure Enclave.
///
/// Each paired server gets its own Secure Enclave key. Key access is gated
/// by biometric authentication (Face ID / Touch ID), ensuring that the
/// daemon can never receive a signed approval without the user's explicit
/// consent.
///
/// Key storage:
/// - Private key: Secure Enclave (never exportable)
/// - Public key: Sent to daemon during pairing, stored in Keychain for reference
/// - Key tag: "com.opaque.device-key.<server_id>"
final class KeyManager {
    static let shared = KeyManager()
    private init() {}

    /// Key tag prefix for Secure Enclave keys.
    private static let keyTagPrefix = "com.opaque.device-key."

    /// Generate a new Secure Enclave key pair for a server.
    ///
    /// - Parameter serverId: The server's unique identifier.
    /// - Returns: The public key bytes (32 bytes for Ed25519-equivalent).
    /// - Throws: If key generation fails.
    ///
    /// TODO: Implement using SecKey API with kSecAttrTokenIDSecureEnclave.
    /// The Secure Enclave supports P-256 (not Ed25519 directly), so we may
    /// need to use P-256 for the actual Secure Enclave key and adapt the
    /// protocol, or use a software-based Ed25519 key protected by
    /// LAContext biometric gating.
    func generateKeyPair(serverId: String) throws -> Data {
        // TODO: Implement Secure Enclave key generation.
        //
        // Approach A (recommended): Use Secure Enclave P-256 key:
        //   let access = SecAccessControlCreateWithFlags(
        //       nil,
        //       kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        //       [.privateKeyUsage, .biometryCurrentSet],
        //       nil
        //   )
        //   let attributes: [String: Any] = [
        //       kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        //       kSecAttrKeySizeInBits as String: 256,
        //       kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        //       kSecPrivateKeyAttrs as String: [
        //           kSecAttrIsPermanent as String: true,
        //           kSecAttrApplicationTag as String: keyTag(for: serverId),
        //           kSecAttrAccessControl as String: access!
        //       ]
        //   ]
        //   var error: Unmanaged<CFError>?
        //   guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        //       throw KeyManagerError.generationFailed(error!.takeRetainedValue().localizedDescription)
        //   }
        //   let publicKey = SecKeyCopyPublicKey(privateKey)!
        //   return SecKeyCopyExternalRepresentation(publicKey, nil)! as Data
        //
        // Approach B: Use CryptoKit Curve25519 with LAContext gating
        //   (software key, but biometric-gated access)

        fatalError("TODO: Implement Secure Enclave key generation")
    }

    /// Sign a challenge using the Secure Enclave key for the given server.
    ///
    /// This will trigger Face ID / Touch ID authentication.
    ///
    /// - Parameters:
    ///   - challengeHex: The challenge bytes as a hex string.
    ///   - serverId: The server whose key should be used for signing.
    /// - Returns: The signature as a hex string.
    /// - Throws: If signing fails or biometric authentication is denied.
    func signChallenge(challengeHex: String, serverId: String) async throws -> String {
        // TODO: Implement challenge signing.
        //
        // 1. Load private key from Keychain using the server-specific tag.
        // 2. The key access control requires biometric auth, so this will
        //    trigger Face ID / Touch ID automatically.
        // 3. Sign the challenge bytes.
        // 4. Return the hex-encoded signature.
        //
        // let query: [String: Any] = [
        //     kSecClass as String: kSecClassKey,
        //     kSecAttrApplicationTag as String: keyTag(for: serverId),
        //     kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        //     kSecReturnRef as String: true
        // ]
        // var item: CFTypeRef?
        // let status = SecItemCopyMatching(query as CFDictionary, &item)
        // guard status == errSecSuccess else { throw KeyManagerError.keyNotFound }
        //
        // let privateKey = item as! SecKey
        // let data = Data(hexString: challengeHex)!
        // var error: Unmanaged<CFError>?
        // guard let signature = SecKeyCreateSignature(
        //     privateKey,
        //     .ecdsaSignatureMessageX962SHA256,
        //     data as CFData,
        //     &error
        // ) else {
        //     throw KeyManagerError.signingFailed(error!.takeRetainedValue().localizedDescription)
        // }
        // return (signature as Data).hexString

        fatalError("TODO: Implement challenge signing")
    }

    /// Delete the key pair for a server (used when unpairing).
    ///
    /// - Parameter serverId: The server whose key should be deleted.
    func deleteKeyPair(serverId: String) throws {
        // TODO: Implement key deletion from Keychain.
        //
        // let query: [String: Any] = [
        //     kSecClass as String: kSecClassKey,
        //     kSecAttrApplicationTag as String: keyTag(for: serverId)
        // ]
        // SecItemDelete(query as CFDictionary)
    }

    /// Get the public key for a server (for display/export).
    func getPublicKey(serverId: String) throws -> Data {
        // TODO: Implement public key retrieval from Keychain.
        fatalError("TODO: Implement public key retrieval")
    }

    /// Build the Keychain tag for a server-specific key.
    private func keyTag(for serverId: String) -> Data {
        let tag = "\(Self.keyTagPrefix)\(serverId)"
        return tag.data(using: .utf8)!
    }
}

/// Errors from the key manager.
enum KeyManagerError: Error, LocalizedError {
    case generationFailed(String)
    case keyNotFound
    case signingFailed(String)
    case biometricDenied
    case biometricUnavailable

    var errorDescription: String? {
        switch self {
        case .generationFailed(let msg):
            return "Key generation failed: \(msg)"
        case .keyNotFound:
            return "Device key not found for this server"
        case .signingFailed(let msg):
            return "Signing failed: \(msg)"
        case .biometricDenied:
            return "Biometric authentication was denied"
        case .biometricUnavailable:
            return "Biometric authentication is not available"
        }
    }
}
