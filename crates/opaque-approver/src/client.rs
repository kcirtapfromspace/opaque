//! TLS certificate pinning is mandatory before credentials leave custody.
use std::sync::Arc;
use std::time::Duration;

use opaque_core::workstation::{decode_hex, hex};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};

#[derive(Debug)]
struct PinnedCertificate {
    fingerprint: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // The exact self-signed certificate was pinned through the operator's
        // trusted channel. Its key and broker identity, not DNS/mDNS, are the
        // authority. Never fall back to accepting an unpinned certificate.
        if Sha256::digest(end_entity.as_ref()).as_slice() != self.fingerprint {
            return Err(rustls::Error::General(
                "Opaque broker certificate pin mismatch".into(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub struct BrokerClient {
    client: reqwest::Client,
    endpoint: String,
}

impl BrokerClient {
    pub fn new(endpoint: &str, fingerprint: &str) -> Result<Self, String> {
        let parsed = reqwest::Url::parse(endpoint).map_err(|_| "invalid broker endpoint")?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            return Err(
                "broker endpoint must be an exact HTTPS origin without credentials or a path"
                    .into(),
            );
        }
        let fingerprint = decode_hex::<32>(fingerprint)
            .map_err(|_| "broker TLS pin must be a SHA256 fingerprint")?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| "TLS configuration unavailable")?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedCertificate {
                fingerprint,
                provider,
            }))
            .with_no_client_auth();
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|_| "pinned TLS client unavailable")?;
        Ok(Self {
            client,
            endpoint: endpoint.trim_end_matches('/').into(),
        })
    }

    pub async fn request<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        route: &str,
        body: Option<serde_json::Value>,
        credentials: Option<(&str, &str)>,
    ) -> Result<T, String> {
        if !route.starts_with("/workstation/")
            || route.contains("..")
            || !route
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/-_".contains(&byte))
        {
            return Err("invalid workstation route".into());
        }
        let mut request = self
            .client
            .request(method, format!("{}{route}", self.endpoint));
        if let Some((device, token)) = credentials {
            request = request.header("X-Opaque-Device", device).bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| "broker TLS connection failed; verify the configured certificate pin")?;
        if !response.status().is_success() {
            return Err(format!(
                "broker rejected workstation request (HTTP {})",
                response.status().as_u16()
            ));
        }
        const MAX_RESPONSE: usize = 256 * 1024;
        if response
            .content_length()
            .is_some_and(|size| size > MAX_RESPONSE as u64)
        {
            return Err("broker response exceeds the review limit".into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "broker response interrupted")?
        {
            if bytes.len() + chunk.len() > MAX_RESPONSE {
                return Err("broker response exceeds the review limit".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.is_empty() {
            bytes.extend_from_slice(b"null");
        }
        serde_json::from_slice(&bytes)
            .map_err(|_| "broker returned an invalid workstation response".into())
    }
}

pub fn certificate_fingerprint(certificate: &[u8]) -> String {
    hex(&Sha256::digest(certificate))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pin_verification_has_no_untrusted_certificate_fallback() {
        let certificate = CertificateDer::from(vec![1, 2, 3]);
        let verifier = PinnedCertificate {
            fingerprint: decode_hex(&certificate_fingerprint(&certificate)).unwrap(),
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        };
        let name = ServerName::try_from("broker.example").unwrap();
        assert!(
            verifier
                .verify_server_cert(
                    &certificate,
                    &[],
                    &name,
                    &[],
                    UnixTime::since_unix_epoch(Duration::from_secs(1))
                )
                .is_ok()
        );
        assert!(
            verifier
                .verify_server_cert(
                    &CertificateDer::from(vec![1, 2, 4]),
                    &[],
                    &name,
                    &[],
                    UnixTime::since_unix_epoch(Duration::from_secs(1))
                )
                .is_err()
        );
        assert!(BrokerClient::new("http://localhost:8000", &"00".repeat(32)).is_err());
        assert!(
            BrokerClient::new("https://user:password@broker.example", &"00".repeat(32)).is_err()
        );
        assert!(BrokerClient::new("https://broker.example/path", &"00".repeat(32)).is_err());
    }
}
