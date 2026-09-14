//! Configuration admission and final synchronous identity fences over real
//! SQLite state. Deliberately corrupted login rows are defensive-input cases,
//! not evidence that ordinary lifecycle APIs create those inconsistent rows.
use super::*;
use opaque_core::identity::{AccessMode, now_unix};
use serde_json::json;
use std::collections::BTreeSet;

fn config() -> IdentityConfig {
    serde_json::from_value(json!({
        "issuer":"https://identity.example.invalid",
        "client_id":"runtime-fixture"
    }))
    .unwrap()
}

#[test]
fn invalid_identity_configuration_is_rejected_before_creating_custody() {
    for case in 0..6 {
        let directory = tempfile::tempdir().unwrap();
        let mut config = config();
        let expected = match case {
            0 => {
                config.issuer.push('/');
                "invalid [identity] issuer: must not end with '/'"
            }
            1 => {
                config.client_id = " \t\n".into();
                "invalid [identity] client_id: empty"
            }
            _ => {
                config.allowed_subjects = vec![match case {
                    2 => String::new(),
                    3 => "x".repeat(256),
                    4 => "subject\nother".into(),
                    _ => "subject\u{0085}other".into(),
                }];
                "invalid [identity] allowed_subjects"
            }
        };
        assert_eq!(config.validate().unwrap_err(), expected);
        assert_eq!(
            IdentityRuntime::initialize(config, directory.path())
                .err()
                .expect("invalid config cannot yield a runtime"),
            expected
        );
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }
}

#[test]
fn valid_identity_boundaries_keep_explicit_audience_and_bounded_session_lifetime() {
    let directory = tempfile::tempdir().unwrap();
    let mut cfg = config();
    cfg.allowed_subjects = vec!["x".repeat(255), "réviewer".into()];
    cfg.validate().unwrap();
    assert_eq!(cfg.audience(), "runtime-fixture");
    assert_eq!(cfg.session_ttl_secs(), 43_200);
    cfg.audience = Some("specific-resource".into());
    for (requested, expected) in [
        (0, 300),
        (300, 300),
        (604_800, 604_800),
        (u64::MAX, 604_800),
    ] {
        cfg.session_ttl_secs = Some(requested);
        assert_eq!(cfg.session_ttl_secs(), expected);
    }
    let runtime = IdentityRuntime::initialize(cfg, directory.path()).unwrap();
    assert_eq!(runtime.config.audience(), "specific-resource");
    assert!(runtime.store.list_principals().unwrap().is_empty());
    assert!(runtime.store.list_delegations().unwrap().is_empty());
    assert!(directory.path().join("identity.db").is_file());
    assert!(directory.path().join("identity.key").is_file());
}

struct Fixture {
    runtime: IdentityRuntime,
    context: PrincipalContext,
    _directory: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let runtime = IdentityRuntime::initialize(config(), directory.path()).unwrap();
        let human = runtime
            .store
            .upsert_human(
                &runtime.config.issuer,
                "requester",
                None,
                None,
                &BTreeSet::from([Role::Operator]),
            )
            .unwrap();
        let actor = runtime.store.upsert_agent("fixture-agent").unwrap();
        let session = runtime
            .store
            .create_human_session(&human.id, 600, &runtime.config.issuer)
            .unwrap();
        let context = PrincipalContext {
            sub: human.id.clone(),
            sub_label: human.display_label(),
            sub_roles: human.roles.clone(),
            sub_teams: vec![],
            act: actor.id.clone(),
            act_label: actor.display_label(),
            mode: AccessMode::Delegated,
            jti: uuid::Uuid::new_v4().to_string(),
            human_session_id: Some(session.id),
        };
        runtime
            .store
            .record_delegation(&store::DelegationRecord {
                jti: context.jti.clone(),
                sub_principal: context.sub.clone(),
                act_principal: context.act.clone(),
                mode: context.mode,
                human_session_id: context.human_session_id.clone(),
                approved_by: Some(human.id),
                created_at: now_unix(),
                expires_at: now_unix() + 600,
                revoked_at: None,
            })
            .unwrap();
        Self {
            runtime,
            context,
            _directory: directory,
        }
    }
    fn snapshot(&self) -> String {
        format!(
            "{:?}\n{:?}\n{:?}",
            self.runtime.store.list_principals().unwrap(),
            self.runtime.store.list_delegations().unwrap(),
            self.runtime
                .store
                .get_human_session(self.context.human_session_id.as_ref().unwrap())
                .unwrap(),
        )
    }
    fn allow_once(&self) {
        let before = self.snapshot();
        let mut calls = 0;
        self.runtime
            .with_dispatch_authority(Some(&self.context), None, &mut || {
                calls += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(self.snapshot(), before);
    }
    fn deny_unchanged(&self, expected: &str) {
        let before = self.snapshot();
        let mut calls = 0;
        for _ in 0..2 {
            assert_eq!(
                self.runtime
                    .with_dispatch_authority(Some(&self.context), None, &mut || {
                        calls += 1;
                        Ok(())
                    })
                    .unwrap_err(),
                expected
            );
        }
        assert_eq!(calls, 0);
        assert_eq!(self.snapshot(), before);
    }
}

#[test]
fn dispatch_rechecks_actor_status_and_subject_roles_in_persisted_state() {
    for disable_actor in [true, false] {
        let fixture = Fixture::new();
        fixture.allow_once();
        if disable_actor {
            fixture
                .runtime
                .store
                .set_disabled(&fixture.context.act, true)
                .unwrap();
        } else {
            fixture
                .runtime
                .store
                .set_roles(&fixture.context.sub, &BTreeSet::from([Role::Auditor]))
                .unwrap();
        }
        fixture.deny_unchanged("requester authority changed before dispatch");
        let delegation = fixture
            .runtime
            .store
            .get_delegation(&fixture.context.jti)
            .unwrap()
            .unwrap();
        assert!(
            delegation.revoked_at.is_some(),
            "the principal mutation must also invalidate the durable delegation"
        );
    }
}

#[test]
fn corrupt_or_expired_login_binding_cannot_authorize_a_live_delegation_snapshot() {
    for mutation in [
        "UPDATE human_sessions SET expires_at=0",
        "UPDATE human_sessions SET revoked_at=0",
        "UPDATE human_sessions SET idp_issuer='https://foreign.example.invalid'",
        "UPDATE human_sessions SET principal_id=(SELECT id FROM principals WHERE kind='agent')",
    ] {
        let fixture = Fixture::new();
        fixture.allow_once();
        // Deliberate stored-input mutations isolate the login check from the
        // earlier delegation check. Ordinary revocation has separate E2E tests.
        fixture
            .runtime
            .store
            .lock()
            .execute_batch(mutation)
            .unwrap();
        fixture.deny_unchanged("requester login revoked or expired");
        let delegation = fixture
            .runtime
            .store
            .get_delegation(&fixture.context.jti)
            .unwrap()
            .unwrap();
        assert!(delegation.revoked_at.is_none());
        assert!(delegation.expires_at > now_unix());
    }
}

#[test]
fn admin_role_on_a_service_never_substitutes_for_a_human_reviewer() {
    let directory = tempfile::tempdir().unwrap();
    let mut cfg = config();
    cfg.service_principals.push(ServicePrincipalConfig {
        name: "fixture-service".into(),
        roles: vec!["admin".into()],
    });
    let runtime = IdentityRuntime::initialize(cfg, directory.path()).unwrap();
    let service = runtime.store.upsert_service("fixture-service").unwrap();
    assert!(runtime.principal_permitted(&service));
    assert!(service.has_role(Role::Admin));
    let epoch = runtime.store.authority_epoch(&service.id).unwrap();
    let mut calls = 0;
    assert_eq!(
        runtime
            .with_reviewer_authority(&service.id, Role::Admin, epoch, &mut || {
                calls += 1;
                Ok(())
            })
            .unwrap_err(),
        "reviewer authority changed before dispatch"
    );
    assert_eq!(calls, 0);
    assert_eq!(runtime.store.authority_epoch(&service.id).unwrap(), epoch);
    assert!(
        runtime
            .store
            .get_principal(&service.id)
            .unwrap()
            .unwrap()
            .has_role(Role::Admin)
    );
}
