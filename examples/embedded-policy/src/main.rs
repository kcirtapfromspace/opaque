//! Synthetic policy evaluation inside another application. No daemon, database,
//! provider credentials or enterprise component is started by this example.
use opaque_core::operation::{ClientIdentity, ClientType, OperationRequest, OperationSafety};
use opaque_core::policy::{PolicyEngine, PolicyRule};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rule: PolicyRule = serde_json::from_value(serde_json::json!({
        "name": "synthetic-reviewed-read",
        "operation_pattern": "example.read_summary",
        "client_types": ["agent"],
        "allow": true
    }))?;
    let engine = PolicyEngine::with_rules(vec![rule]);
    // A real embedding must obtain identity from a trusted verifier. These are
    // explicit fixture values, not identity claims to send to a broker.
    let mut request = OperationRequest {
        request_id: uuid::Uuid::new_v4(),
        client_identity: ClientIdentity {
            uid: 1000,
            gid: 1000,
            pid: None,
            exe_path: None,
            exe_sha256: None,
            codesign_team_id: None,
        },
        client_type: ClientType::Agent,
        operation: "example.read_summary".into(),
        target: Default::default(),
        secret_ref_names: vec![],
        created_at: std::time::SystemTime::now(),
        expires_at: None,
        params: serde_json::json!({}),
        workspace: None,
        principal: None,
    };
    assert!(engine.evaluate(&request, OperationSafety::Safe).allowed);
    assert!(!engine.evaluate(&request, OperationSafety::Reveal).allowed);
    request.operation = "example.unlisted_write".into();
    assert!(!engine.evaluate(&request, OperationSafety::Safe).allowed);
    println!("Policy evaluation: allowed synthetic read; denied reveal and unlisted operation.");
    println!("No authority was granted and no provider action was executed.");
    Ok(())
}
