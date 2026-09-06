//! Short-lived WebAuthn ceremonies for the hosted synthetic-data task.
//! Credentials and ceremony state stay in this process and expire with the
//! browser session. Enrollment proves control of a new credential; it does not
//! establish employment, tenant membership, or production broker enrollment.
use crate::bounded_demo::{Approval, ApprovalVerification};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;
use webauthn_rs::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Binding {
    pub session_id: String,
    pub jti: String,
    pub task_id: String,
    pub manifest_sha256: String,
    pub generation: u64,
    pub expires_at: i64,
}

enum Ceremony {
    Registration(PasskeyRegistration),
    Authentication(PasskeyAuthentication),
}
struct Pending {
    binding: Binding,
    expires_at: i64,
    ceremony: Ceremony,
}
struct Enrollment {
    jti: String,
    expires_at: i64,
    passkey: Passkey,
}
pub(crate) enum Finish {
    Registered,
    Approved(Approval),
}
pub(crate) struct PasskeyApprover {
    webauthn: Webauthn,
    rp_id: String,
    pending: HashMap<String, Pending>,
    credentials: HashMap<String, Enrollment>,
}
impl PasskeyApprover {
    pub fn new(origin: &str) -> Result<Self, String> {
        let origin = Url::parse(origin).map_err(|_| "Invalid approval origin")?;
        if origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || !(origin.scheme() == "https"
                || origin.scheme() == "http"
                    && origin.host_str().is_some_and(|host| {
                        host == "localhost"
                            || host
                                .parse::<std::net::IpAddr>()
                                .is_ok_and(|ip| ip.is_loopback())
                    }))
        {
            return Err(
                "Approval requires a canonical HTTPS origin or loopback development origin".into(),
            );
        }
        let rp_id = origin
            .host_str()
            .ok_or("Approval origin has no host")?
            .to_string();
        let webauthn = WebauthnBuilder::new(&rp_id, &origin)
            .map_err(|_| "Invalid WebAuthn relying party")?
            .rp_name("Opaque demo task approval")
            .build()
            .map_err(|_| "WebAuthn configuration failed")?;
        Ok(Self {
            webauthn,
            rp_id,
            pending: HashMap::new(),
            credentials: HashMap::new(),
        })
    }
    pub fn capabilities(&self) -> Value {
        json!({"available":true,"rp_id":self.rp_id,"user_verification":"required",
            "enrollment":"temporary_browser_session","notice":"A newly enrolled passkey proves control of that credential, not employment or production tenant membership."})
    }
    fn prune(&mut self, now: i64) {
        self.pending.retain(|_, value| value.expires_at > now);
        self.credentials.retain(|_, value| value.expires_at > now);
    }
    pub fn start(&mut self, binding: Binding, now: i64) -> Result<Value, String> {
        self.prune(now);
        if binding.expires_at <= now {
            return Err("Task approval expired".into());
        }
        // Only the latest challenge for this browser is usable.
        self.pending
            .retain(|_, value| value.binding.session_id != binding.session_id);
        if self.pending.len() >= 256 {
            return Err("Too many pending approvals".into());
        }
        let enrolled = self
            .credentials
            .get(&binding.session_id)
            .filter(|value| value.jti == binding.jti);
        let (kind, public_key, ceremony) = if let Some(enrolled) = enrolled {
            let (options, state) = self
                .webauthn
                .start_passkey_authentication(std::slice::from_ref(&enrolled.passkey))
                .map_err(|_| "Passkey authentication could not start")?;
            (
                "authentication",
                serde_json::to_value(options).map_err(|_| "Invalid passkey options")?["publicKey"]
                    .clone(),
                Ceremony::Authentication(state),
            )
        } else {
            let user = Uuid::new_v4();
            let (options, state) = self
                .webauthn
                .start_passkey_registration(
                    user,
                    &format!("demo-{user}"),
                    "Temporary Opaque demo visitor",
                    None,
                )
                .map_err(|_| "Passkey enrollment could not start")?;
            (
                "registration",
                serde_json::to_value(options).map_err(|_| "Invalid passkey options")?["publicKey"]
                    .clone(),
                Ceremony::Registration(state),
            )
        };
        let transaction_id = Uuid::new_v4().to_string();
        let expires_at = binding.expires_at.min(now + 120);
        self.pending.insert(
            transaction_id.clone(),
            Pending {
                binding,
                expires_at,
                ceremony,
            },
        );
        Ok(
            json!({"transaction_id":transaction_id,"kind":kind,"public_key":public_key,"expires_at":expires_at}),
        )
    }
    pub fn finish(
        &mut self,
        binding: &Binding,
        transaction_id: &str,
        credential: Value,
        now: i64,
    ) -> Result<Finish, String> {
        self.prune(now);
        // Consume before any validation or cryptographic work; failures never
        // leave a reusable challenge behind.
        let pending = self
            .pending
            .remove(transaction_id)
            .ok_or("Approval challenge expired or was already used")?;
        if pending.binding != *binding || pending.expires_at <= now {
            return Err("Approval challenge does not match current task authority".into());
        }
        match pending.ceremony {
            Ceremony::Registration(state) => {
                let credential: RegisterPublicKeyCredential = serde_json::from_value(credential)
                    .map_err(|_| "Invalid passkey registration")?;
                let passkey = self
                    .webauthn
                    .finish_passkey_registration(&credential, &state)
                    .map_err(|_| "Passkey registration verification failed")?;
                if self
                    .credentials
                    .values()
                    .any(|entry| entry.passkey.cred_id() == passkey.cred_id())
                {
                    return Err("This passkey is already enrolled in another session".into());
                }
                if self.credentials.len() >= 256 {
                    return Err("Passkey enrollment capacity reached".into());
                }
                self.credentials.insert(
                    binding.session_id.clone(),
                    Enrollment {
                        jti: binding.jti.clone(),
                        expires_at: binding.expires_at,
                        passkey,
                    },
                );
                Ok(Finish::Registered)
            }
            Ceremony::Authentication(state) => {
                let credential: PublicKeyCredential =
                    serde_json::from_value(credential).map_err(|_| "Invalid passkey assertion")?;
                let verified = self
                    .webauthn
                    .finish_passkey_authentication(&credential, &state)
                    .map_err(|_| "Passkey assertion verification failed")?;
                if !verified.user_verified() {
                    return Err("Passkey user verification is required".into());
                }
                let enrollment = self
                    .credentials
                    .get_mut(&binding.session_id)
                    .ok_or("Passkey enrollment expired")?;
                if enrollment.jti != binding.jti
                    || enrollment.passkey.update_credential(&verified).is_none()
                {
                    return Err("Passkey does not belong to the current browser session".into());
                }
                let credential_sha256 =
                    format!("{:x}", Sha256::digest(verified.cred_id().as_ref()));
                Ok(Finish::Approved(Approval {
                    kind: "webauthn".into(),
                    approved_at: now,
                    verification: Some(ApprovalVerification {
                        issuer: None,
                        subject: "temporary_demo_visitor".into(),
                        credential_sha256: Some(credential_sha256),
                        user_verified: Some(true),
                    }),
                }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};

    fn binding() -> Binding {
        Binding {
            session_id: "browser-session".into(),
            jti: "token-id".into(),
            task_id: Uuid::new_v4().to_string(),
            manifest_sha256: "a".repeat(64),
            generation: 1,
            expires_at: 300,
        }
    }
    fn registration(
        approver: &mut PasskeyApprover,
        binding: &Binding,
        authenticator: &mut WebauthnAuthenticator<SoftPasskey>,
    ) {
        let start = approver.start(binding.clone(), 100).unwrap();
        assert_eq!(start["kind"], "registration");
        assert_eq!(
            start["public_key"]["authenticatorSelection"]["userVerification"],
            "required"
        );
        let options = serde_json::from_value(json!({"publicKey":start["public_key"]})).unwrap();
        let credential = authenticator
            .do_registration(Url::parse("https://demo.example.com").unwrap(), options)
            .unwrap();
        let finish = approver
            .finish(
                binding,
                start["transaction_id"].as_str().unwrap(),
                serde_json::to_value(credential).unwrap(),
                101,
            )
            .unwrap();
        assert!(matches!(finish, Finish::Registered));
    }
    #[test]
    fn passkey_enrollment_requires_fresh_verified_assertion_and_replay_is_denied() {
        let mut approver = PasskeyApprover::new("https://demo.example.com").unwrap();
        // SoftPasskey's UV switch is an explicit virtual authenticator fixture.
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let binding = binding();
        registration(&mut approver, &binding, &mut authenticator);
        let start = approver.start(binding.clone(), 102).unwrap();
        assert_eq!(start["kind"], "authentication");
        assert_eq!(start["public_key"]["userVerification"], "required");
        let options = serde_json::from_value(json!({"publicKey":start["public_key"]})).unwrap();
        let credential = serde_json::to_value(
            authenticator
                .do_authentication(Url::parse("https://demo.example.com").unwrap(), options)
                .unwrap(),
        )
        .unwrap();
        let id = start["transaction_id"].as_str().unwrap();
        let result = approver
            .finish(&binding, id, credential.clone(), 103)
            .unwrap();
        let Finish::Approved(proof) = result else {
            panic!("assertion must produce verified approval")
        };
        assert_eq!(proof.kind, "webauthn");
        assert_eq!(proof.verification.unwrap().user_verified, Some(true));
        assert!(approver.finish(&binding, id, credential, 104).is_err());
    }
    #[test]
    fn changed_authority_and_expired_or_replaced_ceremonies_are_rejected() {
        let mut approver = PasskeyApprover::new("https://demo.example.com").unwrap();
        let binding = binding();
        for field in 0..6 {
            let start = approver.start(binding.clone(), 100).unwrap();
            let mut changed = binding.clone();
            match field {
                0 => changed.session_id.push('x'),
                1 => changed.jti.push('x'),
                2 => changed.task_id.push('x'),
                3 => changed.manifest_sha256 = "b".repeat(64),
                4 => changed.generation += 1,
                _ => changed.expires_at -= 1,
            }
            let id = start["transaction_id"].as_str().unwrap();
            assert!(approver.finish(&changed, id, Value::Null, 101).is_err());
            assert!(approver.finish(&binding, id, Value::Null, 101).is_err());
        }
        let old = approver.start(binding.clone(), 100).unwrap();
        let latest = approver.start(binding.clone(), 100).unwrap();
        assert!(
            approver
                .finish(
                    &binding,
                    old["transaction_id"].as_str().unwrap(),
                    Value::Null,
                    101
                )
                .is_err()
        );
        assert!(
            approver
                .finish(
                    &binding,
                    latest["transaction_id"].as_str().unwrap(),
                    Value::Null,
                    220
                )
                .is_err()
        );
    }
    #[test]
    fn tampered_browser_origin_fails_cryptographic_registration() {
        let mut approver = PasskeyApprover::new("https://demo.example.com").unwrap();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let binding = binding();
        let start = approver.start(binding.clone(), 100).unwrap();
        let options = serde_json::from_value(json!({"publicKey":start["public_key"]})).unwrap();
        let mut credential = serde_json::to_value(
            authenticator
                .do_registration(Url::parse("https://demo.example.com").unwrap(), options)
                .unwrap(),
        )
        .unwrap();
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let mut client_data: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(credential["response"]["clientDataJSON"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        client_data["origin"] = json!("https://evil.example.com");
        credential["response"]["clientDataJSON"] =
            json!(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&client_data).unwrap()));
        assert!(
            approver
                .finish(
                    &binding,
                    start["transaction_id"].as_str().unwrap(),
                    credential,
                    101
                )
                .is_err()
        );
    }
    #[test]
    fn configured_origin_rejects_unsafe_remote_http_and_url_paths() {
        assert!(PasskeyApprover::new("http://demo.example.com").is_err());
        assert!(PasskeyApprover::new("https://demo.example.com/path").is_err());
        assert!(PasskeyApprover::new("https://demo.example.com?x=y").is_err());
        assert!(PasskeyApprover::new("http://localhost:8081").is_ok());
        assert!(PasskeyApprover::new("http://127.0.0.1:8081").is_err());
    }
    #[test]
    fn registration_without_user_verification_is_denied() {
        let mut approver = PasskeyApprover::new("https://demo.example.com").unwrap();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(false));
        let binding = binding();
        let start = approver.start(binding.clone(), 100).unwrap();
        let mut options = json!({"publicKey":start["public_key"]});
        // A malicious browser can change options but cannot change the
        // server-held policy; this response has a real signature and no UV.
        options["publicKey"]["authenticatorSelection"]["userVerification"] = json!("preferred");
        let credential = authenticator
            .do_registration(
                Url::parse("https://demo.example.com").unwrap(),
                serde_json::from_value(options).unwrap(),
            )
            .unwrap();
        assert!(
            approver
                .finish(
                    &binding,
                    start["transaction_id"].as_str().unwrap(),
                    serde_json::to_value(credential).unwrap(),
                    101
                )
                .is_err()
        );
    }
    #[test]
    fn signed_assertions_without_uv_or_from_a_subdomain_are_denied() {
        let mut approver = PasskeyApprover::new("https://demo.example.com").unwrap();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let binding = binding();
        registration(&mut approver, &binding, &mut authenticator);
        for malicious_origin in [false, true] {
            let start = approver.start(binding.clone(), 102).unwrap();
            let mut options = json!({"publicKey":start["public_key"]});
            if !malicious_origin {
                options["publicKey"]["userVerification"] = json!("preferred");
            }
            let origin = if malicious_origin {
                "https://sub.demo.example.com"
            } else {
                "https://demo.example.com"
            };
            let credential = authenticator
                .do_authentication(
                    Url::parse(origin).unwrap(),
                    serde_json::from_value(options).unwrap(),
                )
                .unwrap();
            assert!(
                approver
                    .finish(
                        &binding,
                        start["transaction_id"].as_str().unwrap(),
                        serde_json::to_value(credential).unwrap(),
                        103
                    )
                    .is_err()
            );
        }
    }
}
