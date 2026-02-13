//! GitHub Actions secret encryption using NaCl sealed boxes.
//!
//! GitHub requires secrets to be encrypted with the repository's public key
//! using libsodium sealed boxes (X25519 + XSalsa20-Poly1305).

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use crypto_box::PublicKey;

/// Errors from GitHub secret encryption.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid base64 in public key")]
    InvalidBase64,

    #[error("invalid public key length: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),
}

/// Encrypt a secret value for the GitHub Actions API using sealed box encryption.
///
/// Takes the plaintext secret and the repo's base64-encoded Curve25519 public key.
/// Returns a base64-encoded ciphertext suitable for the `PUT /repos/.../actions/secrets/...` API.
pub fn encrypt_secret(plaintext: &[u8], public_key_b64: &str) -> Result<String, CryptoError> {
    let key_bytes = BASE64
        .decode(public_key_b64)
        .map_err(|_| CryptoError::InvalidBase64)?;

    if key_bytes.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(key_bytes.len()));
    }

    let key_array: [u8; 32] = key_bytes.try_into().expect("length already checked");

    let public_key = PublicKey::from(key_array);

    let mut rng = crypto_box::aead::OsRng;
    let ciphertext = public_key
        .seal(&mut rng, plaintext)
        .expect("sealed box encryption should not fail with valid key");

    Ok(BASE64.encode(&ciphertext))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_box::SecretKey;

    /// Generate a test keypair and return (public_key_b64, secret_key).
    fn test_keypair() -> (String, SecretKey) {
        let mut rng = crypto_box::aead::OsRng;
        let secret_key = SecretKey::generate(&mut rng);
        let public_key = secret_key.public_key();
        let pk_b64 = BASE64.encode(public_key.as_bytes());
        (pk_b64, secret_key)
    }

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let (pk_b64, sk) = test_keypair();
        let plaintext = b"super-secret-value-42";

        let encrypted_b64 = encrypt_secret(plaintext, &pk_b64).unwrap();

        // Decrypt to verify.
        let ciphertext = BASE64.decode(&encrypted_b64).unwrap();
        let decrypted = sk.unseal(&ciphertext).expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_empty_plaintext() {
        let (pk_b64, sk) = test_keypair();
        let encrypted_b64 = encrypt_secret(b"", &pk_b64).unwrap();

        let ciphertext = BASE64.decode(&encrypted_b64).unwrap();
        let decrypted = sk.unseal(&ciphertext).expect("decryption should succeed");
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn invalid_base64_key_rejected() {
        let result = encrypt_secret(b"test", "not-valid-base64!!!");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidBase64));
    }

    #[test]
    fn wrong_key_length_rejected() {
        let short_key = BASE64.encode(b"too-short");
        let result = encrypt_secret(b"test", &short_key);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CryptoError::InvalidKeyLength(_)
        ));
    }

    #[test]
    fn crypto_error_display() {
        let err = CryptoError::InvalidBase64;
        assert!(format!("{err}").contains("invalid base64"));

        let err = CryptoError::InvalidKeyLength(16);
        let msg = format!("{err}");
        assert!(msg.contains("expected 32 bytes"));
        assert!(msg.contains("16"));
    }

    #[test]
    fn encrypted_output_is_valid_base64() {
        let (pk_b64, _sk) = test_keypair();
        let encrypted_b64 = encrypt_secret(b"hello world", &pk_b64).unwrap();
        assert!(BASE64.decode(&encrypted_b64).is_ok());
    }

    #[test]
    fn each_encryption_produces_different_ciphertext() {
        let (pk_b64, _sk) = test_keypair();
        let plaintext = b"same-input";
        let enc1 = encrypt_secret(plaintext, &pk_b64).unwrap();
        let enc2 = encrypt_secret(plaintext, &pk_b64).unwrap();
        // Sealed box uses ephemeral keypair, so ciphertexts differ.
        assert_ne!(enc1, enc2);
    }
}
