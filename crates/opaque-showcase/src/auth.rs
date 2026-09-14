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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn synchronous_and_current_thread_callers_preserve_errors_without_replay() {
        for runtime in [false, true] {
            let mut attempts = 0;
            let mut operation = || {
                broker_call(|| {
                    attempts += 1;
                    Err::<(), _>("fixture broker rejected authority")
                })
            };
            let result = if runtime {
                tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap()
                    .block_on(async { operation() })
            } else {
                operation()
            };
            assert_eq!(result, Err("fixture broker rejected authority"));
            assert_eq!(attempts, 1);
        }
    }

    #[test]
    fn blocking_broker_call_releases_the_only_tokio_worker_for_other_requests() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let (entered, entry) = tokio::sync::oneshot::channel();
            let (reply, response) = std::sync::mpsc::channel();
            let broker = tokio::spawn(async move {
                broker_call(|| {
                    entered.send(()).unwrap();
                    response.recv_timeout(std::time::Duration::from_secs(2))
                })
            });
            let other_request = tokio::spawn(async move {
                entry.await.unwrap();
                reply.send("other request progressed").unwrap();
            });
            assert_eq!(broker.await.unwrap().unwrap(), "other request progressed");
            other_request.await.unwrap();
        });
    }
}
