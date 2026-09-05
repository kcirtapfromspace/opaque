//! Shared OAuth validation; production admission belongs to the broker.
pub use opaque_core::resource_auth::{
    Admission, AuthConfig, AuthError, BrokerClientConfig, METRIC_SCOPES, VerifiedAccess,
};
use opaque_core::resource_auth::{AuthVerifier as StaticVerifier, BrokerClient};

pub enum AuthVerifier {
    Fixture(Box<StaticVerifier>),
    Broker(Box<BrokerClient>),
}
impl AuthVerifier {
    /// Compatibility constructor for explicit standalone fixtures.
    pub fn new(config: AuthConfig) -> Result<Self, AuthError> {
        StaticVerifier::new(config).map(|verifier| Self::Fixture(Box::new(verifier)))
    }
    pub fn broker(
        config: BrokerClientConfig,
        issuer: String,
        audience: String,
    ) -> Result<Self, AuthError> {
        BrokerClient::new(config, issuer, audience).map(|client| Self::Broker(Box::new(client)))
    }
    pub fn verify_bearer(&self, value: Option<&str>) -> Result<VerifiedAccess, AuthError> {
        match self {
            Self::Fixture(v) => v.verify_bearer(value),
            Self::Broker(v) => broker_call(|| v.verify_bearer(value)),
        }
    }
    pub fn check_access(&self, access: &VerifiedAccess) -> Result<(), AuthError> {
        match self {
            Self::Fixture(v) => v.check_access(access),
            Self::Broker(v) => broker_call(|| v.check_access(access)),
        }
    }
    pub fn revoke_bearer(&self, authorization: Option<&str>) -> Result<String, AuthError> {
        match self {
            Self::Fixture(verifier) => {
                let token = verifier.revocable_bearer(authorization)?;
                verifier.revoke_jti(&token.jti)?;
                Ok(token.jti)
            }
            Self::Broker(client) => {
                broker_call(|| client.revoke_bearer(authorization)).map(|token| token.jti)
            }
        }
    }
}

// Release a Tokio worker while the bounded Unix call waits. The standalone
// sync interface also works outside a runtime (configuration tools/tests).
fn broker_call<T>(operation: impl FnOnce() -> T) -> T {
    if tokio::runtime::Handle::try_current()
        .is_ok_and(|handle| handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
    {
        tokio::task::block_in_place(operation)
    } else {
        operation()
    }
}
