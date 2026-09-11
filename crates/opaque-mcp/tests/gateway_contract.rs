use opaque_mcp::gateway_contract::{ContractError, MAX_CALL_BYTES, MAX_REGISTRY_BYTES, Registry};
use serde_json::{Value, json};

const REGISTRY: &[u8] = include_bytes!("fixtures/gateway-registry.json");
const CALL: &[u8] = include_bytes!("fixtures/gateway-call.json");
const V2_REGISTRY: &[u8] = include_bytes!("fixtures/gateway-registry-v2.json");
const V2_CATALOG: &[u8] = include_bytes!("fixtures/gateway-catalog-v2.json");
const V2_CALL: &[u8] = include_bytes!("fixtures/gateway-call-v2.json");

fn registry_value() -> Value {
    serde_json::from_slice(REGISTRY).unwrap()
}
fn load(value: &Value) -> Result<Registry, ContractError> {
    Registry::from_json(&serde_json::to_vec(value).unwrap())
}
fn preparation_error(registry: &Registry, call: Value) -> ContractError {
    registry
        .prepare_json(&serde_json::to_vec(&call).unwrap())
        .unwrap_err()
}

#[test]
fn prepares_frozen_snapshot_but_never_grants_authority() {
    let registry = Registry::from_json(REGISTRY).unwrap();
    assert_eq!(registry.route_count(), 1);
    let prepared = registry.prepare_json(CALL).unwrap();
    assert_eq!(prepared.route().tool, "release_status");
    assert_eq!(prepared.arguments()["release"], "synthetic-release-1");
    assert_eq!(prepared.action_digest().len(), 64);
    assert_eq!(
        prepared.action_digest(),
        "19543e78d6776d338d51f3385af57cfec6ac5cd25e4b57d1ba8bd58d88ecffdb"
    );
    let debug = format!("{prepared:?}");
    assert!(!debug.contains("synthetic-release-1"));
    assert!(!debug.contains("release-reader"));
}

#[test]
fn authority_overrides_unknown_routes_and_invalid_arguments_are_rejected() {
    let registry = Registry::from_json(REGISTRY).unwrap();
    for field in [
        "url",
        "endpoint",
        "headers",
        "credential_binding",
        "approval",
        "principal",
        "tool",
    ] {
        let mut call: Value = serde_json::from_slice(CALL).unwrap();
        call[field] = json!("must-not-appear-in-diagnostics");
        assert_eq!(
            preparation_error(&registry, call),
            ContractError::InvalidCall
        );
    }
    assert_eq!(
        preparation_error(&registry, json!({"route":"unregistered", "arguments":{}})),
        ContractError::UnknownRoute
    );
    for arguments in [
        json!({}),
        json!({"release":42}),
        json!({"release":""}),
        json!({"release":"x".repeat(81)}),
        json!({"release":"x", "token":"secret"}),
    ] {
        assert_eq!(
            preparation_error(
                &registry,
                json!({"route":"staging.status", "arguments":arguments})
            ),
            ContractError::ArgumentsRejected
        );
    }
    for arguments in [json!(null), json!([]), json!("secret")] {
        assert_eq!(
            preparation_error(
                &registry,
                json!({"route":"staging.status", "arguments":arguments})
            ),
            ContractError::InvalidCall
        );
    }
}

#[test]
fn endpoint_pin_cannot_express_local_addresses_redirects_or_auth_overrides() {
    for host in [
        "localhost",
        "127.0.0.1",
        "2130706433",
        "169.254.169.254",
        "[::1]",
        "foo.local",
        "metadata.google.internal",
        "user@example.com",
        "example.com:80",
        "Example.com",
        "a..com",
        "example.com.",
        "https://example.com",
    ] {
        let mut value = registry_value();
        value["routes"][0]["endpoint"]["host"] = json!(host);
        assert!(
            matches!(load(&value), Err(ContractError::InvalidEndpoint)),
            "{host}"
        );
    }
    for path in [
        "//attacker.test/mcp",
        "/mcp?token=secret",
        "/mcp#fragment",
        "/../mcp",
        "/%2e%2e/mcp",
        "/mcp\\evil",
        "/mcp\nheader:value",
    ] {
        let mut value = registry_value();
        value["routes"][0]["endpoint"]["path"] = json!(path);
        assert!(
            matches!(load(&value), Err(ContractError::InvalidEndpoint)),
            "{path}"
        );
    }
    for field in [
        "scheme",
        "port",
        "headers",
        "follow_redirects",
        "allow_loopback",
    ] {
        let mut value = registry_value();
        value["routes"][0]["endpoint"][field] = json!(true);
        assert!(matches!(load(&value), Err(ContractError::InvalidRegistry)));
    }
}

#[test]
fn schema_references_open_objects_unbounded_values_and_unsupported_features_fail_closed() {
    let schemas = [
        json!({"type":"object","properties":{}}),
        json!({"type":"object","properties":{},"additionalProperties":true}),
        json!({"type":"object","properties":{},"additionalProperties":false,"$ref":"http://127.0.0.1/secret"}),
        json!({"type":"object","properties":{},"additionalProperties":false,"$ref":"file:///etc/passwd"}),
        json!({"type":"object","properties":{"s":{"type":"string"}},"additionalProperties":false}),
        json!({"type":"object","properties":{"s":{"type":"string","maxLength":80,"pattern":"(a+)+$"}},"additionalProperties":false}),
        json!({"type":"object","properties":{"nested":{"type":"object","properties":{}}},"additionalProperties":false}),
        json!({"type":"object","properties":{"a":{"type":"array","items":{"type":"boolean"}}},"additionalProperties":false}),
        json!({"type":"object","properties":{},"additionalProperties":false,"required":["missing"]}),
        json!({"type":"object","properties":{},"additionalProperties":false,"anyOf":[{}]}),
        json!({"type":"object","properties":{"i":{"type":"integer","minimum":5,"maximum":1}},"additionalProperties":false}),
    ];
    for schema in schemas {
        let mut value = registry_value();
        value["routes"][0]["input_schema"] = schema;
        assert!(matches!(load(&value), Err(ContractError::InvalidSchema)));
    }
}

#[test]
fn nested_closed_schema_enforces_caps_types_and_enum() {
    let mut value = registry_value();
    value["routes"][0]["input_schema"] = json!({"type":"object","additionalProperties":false,"required":["items"],"properties":{
        "items":{"type":"array","minItems":1,"maxItems":2,"items":{"type":"object","additionalProperties":false,"required":["count","allowed"],"properties":{
            "count":{"type":"integer","minimum":1,"maximum":3},"allowed":{"type":"boolean","enum":[true]}
        }}}
    }});
    let registry = load(&value).unwrap();
    let valid =
        json!({"route":"staging.status","arguments":{"items":[{"count":2,"allowed":true}]}});
    assert!(
        registry
            .prepare_json(&serde_json::to_vec(&valid).unwrap())
            .is_ok()
    );
    for items in [
        json!([]),
        json!([{"count":2.0,"allowed":true}]),
        json!([{"count":4,"allowed":true}]),
        json!([{"count":1,"allowed":false}]),
        json!([{"count":1,"allowed":true,"extra":"bad"}]),
    ] {
        assert_eq!(
            preparation_error(
                &registry,
                json!({"route":"staging.status","arguments":{"items":items}})
            ),
            ContractError::ArgumentsRejected
        );
    }
}

#[test]
fn schema_depth_and_node_limits_bound_validation_work() {
    let mut value = registry_value();
    let mut deep = json!({"type":"boolean"});
    for _ in 0..9 {
        deep = json!({"type":"object","additionalProperties":false,"properties":{"child":deep}});
    }
    value["routes"][0]["input_schema"] = deep;
    assert!(matches!(load(&value), Err(ContractError::InvalidSchema)));
    let mut children = serde_json::Map::new();
    for index in 0..32 {
        children.insert(format!("child{index}"), json!({"type":"boolean"}));
    }
    let mut properties = serde_json::Map::new();
    for index in 0..32 {
        properties.insert(
            format!("group{index}"),
            json!({"type":"object","additionalProperties":false,"properties":children}),
        );
    }
    value["routes"][0]["input_schema"] =
        json!({"type":"object","additionalProperties":false,"properties":properties});
    assert!(matches!(load(&value), Err(ContractError::InvalidSchema)));
}

#[test]
fn digest_is_order_independent_and_binds_every_execution_setting() {
    let registry = Registry::from_json(REGISTRY).unwrap();
    let baseline = registry.prepare_json(CALL).unwrap();
    let reordered = br#"{"arguments":{"release":"synthetic-release-1"},"route":"staging.status"}"#;
    assert_eq!(
        baseline.action_digest(),
        registry.prepare_json(reordered).unwrap().action_digest()
    );
    for (pointer, replacement) in [
        ("/routes/0/server_id", json!("other-server")),
        ("/routes/0/endpoint/host", json!("other.example.test")),
        ("/routes/0/endpoint/path", json!("/v2/mcp")),
        ("/routes/0/tool", json!("other_tool")),
        ("/routes/0/credential_binding", json!("other-binding")),
        (
            "/routes/0/input_schema/properties/release/maxLength",
            json!(100),
        ),
        ("/routes/0/max_request_bytes", json!(4096)),
        ("/routes/0/max_response_bytes", json!(16384)),
        ("/routes/0/timeout_ms", json!(20000)),
    ] {
        let mut value = registry_value();
        *value.pointer_mut(pointer).unwrap() = replacement;
        let changed = load(&value).unwrap().prepare_json(CALL).unwrap();
        assert_ne!(
            baseline.action_digest(),
            changed.action_digest(),
            "{pointer}"
        );
    }
    let changed = registry
        .prepare_json(br#"{"route":"staging.status","arguments":{"release":"other"}}"#)
        .unwrap();
    assert_ne!(baseline.action_digest(), changed.action_digest());
}

#[test]
fn version_duplicate_routes_and_resource_budgets_are_fail_closed() {
    for (pointer, replacement) in [
        ("/version", json!(2)),
        ("/routes/0/max_request_bytes", json!(0)),
        ("/routes/0/max_request_bytes", json!(MAX_CALL_BYTES + 1)),
        ("/routes/0/max_response_bytes", json!(262145)),
        ("/routes/0/timeout_ms", json!(120001)),
        ("/routes/0/output_policy", json!("passthrough")),
    ] {
        let mut value = registry_value();
        *value.pointer_mut(pointer).unwrap() = replacement;
        assert!(matches!(load(&value), Err(ContractError::InvalidRegistry)));
    }
    let mut value = registry_value();
    let duplicate = value["routes"][0].clone();
    value["routes"].as_array_mut().unwrap().push(duplicate);
    assert!(matches!(load(&value), Err(ContractError::InvalidRegistry)));
    assert!(matches!(
        Registry::from_json(&vec![b' '; MAX_REGISTRY_BYTES + 1]),
        Err(ContractError::InputTooLarge)
    ));
    let registry = Registry::from_json(REGISTRY).unwrap();
    assert_eq!(
        registry
            .prepare_json(&vec![b' '; MAX_CALL_BYTES + 1])
            .unwrap_err(),
        ContractError::InputTooLarge
    );
    let padded = format!("{}{}", " ".repeat(2048), std::str::from_utf8(CALL).unwrap());
    assert_eq!(
        registry.prepare_json(padded.as_bytes()).unwrap_err(),
        ContractError::InputTooLarge
    );
}

#[test]
fn executable_reports_only_offline_preparation_and_redacts_rejected_material() {
    let directory = tempfile::tempdir().unwrap();
    let registry_path = directory.path().join("registry.json");
    let call_path = directory.path().join("call.json");
    std::fs::write(&registry_path, REGISTRY).unwrap();
    std::fs::write(&call_path, CALL).unwrap();
    let invoke = |command: &str, with_call: bool| {
        let mut command_line =
            std::process::Command::new(env!("CARGO_BIN_EXE_opaque-mcp-contract"));
        command_line.arg(command).arg(&registry_path);
        if with_call {
            command_line.arg(&call_path);
        }
        command_line.output().unwrap()
    };
    let validation = invoke("validate", false);
    assert!(validation.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&validation.stdout).unwrap()["runtime_gateway_enabled"],
        false
    );
    let preparation = invoke("prepare", true);
    assert!(preparation.status.success());
    let output: Value = serde_json::from_slice(&preparation.stdout).unwrap();
    assert_eq!(output["status"], "prepared_not_authorized");
    assert!(!String::from_utf8_lossy(&preparation.stdout).contains("synthetic-release-1"));
    std::fs::write(&call_path, br#"{"route":"staging.status","arguments":{"release":"synthetic"},"token":"must-not-appear"}"#).unwrap();
    let rejected = invoke("prepare", true);
    assert_eq!(rejected.status.code(), Some(2));
    assert!(rejected.stdout.is_empty());
    assert_eq!(
        std::str::from_utf8(&rejected.stderr).unwrap().trim(),
        "invalid gateway call envelope"
    );
}

#[test]
fn qualified_upstream_shape_and_admitted_contract_are_separate_and_both_enforced() {
    let registry = Registry::from_json(V2_REGISTRY).unwrap();
    let call = registry.prepare_json(V2_CALL).unwrap();
    assert_eq!(call.route().prepared_contract_version(), 3);
    assert!(registry.qualify_catalog(V2_CATALOG).unwrap()[0].compatible);
    assert_eq!(call.arguments()["issue_number"], 42);
    // An upstream number accepts an admitted integer, but cannot expand our
    // integer bound, add unknown fields or route the call to another repository.
    for (field, value) in [
        ("issue_number", json!(1.5)),
        ("issue_number", json!(1000001)),
        ("repo", json!("other-repo")),
        ("reaction", json!("+1")),
    ] {
        let mut input: Value = serde_json::from_slice(V2_CALL).unwrap();
        input["arguments"][field] = value;
        assert_eq!(
            preparation_error(&registry, input),
            ContractError::ArgumentsRejected
        );
    }
    // A valid admitted input still must satisfy a pinned upstream constraint.
    let mut document: Value = serde_json::from_slice(V2_REGISTRY).unwrap();
    document["routes"][0]["upstream_input_schema"]["properties"]["issue_number"]["minimum"] =
        json!(100);
    let constrained = load(&document).unwrap();
    assert_eq!(
        constrained.prepare_json(V2_CALL).unwrap_err(),
        ContractError::ArgumentsRejected
    );
    // Do not reinterpret v2 content under v1 or permit a missing v2 pin.
    document["version"] = json!(1);
    assert!(load(&document).is_err());
    document["version"] = json!(2);
    document["routes"][0]
        .as_object_mut()
        .unwrap()
        .remove("upstream_input_schema");
    assert!(load(&document).is_err());
}

#[test]
fn offline_catalog_diagnostics_are_bounded_and_never_echo_upstream_instructions() {
    let registry = Registry::from_json(V2_REGISTRY).unwrap();
    let original: Value = serde_json::from_slice(V2_CATALOG).unwrap();
    let mut drift = original.clone();
    drift["tools"][0]["inputSchema"]["properties"]["owner"]["description"] =
        json!("malicious-upstream-secret");
    let report = registry
        .qualify_catalog(&serde_json::to_vec(&drift).unwrap())
        .unwrap();
    assert!(!report[0].compatible);
    assert_eq!(report[0].diagnostic, "upstream_schema_drift");
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("malicious-upstream-secret")
    );
    let mut duplicate = original.clone();
    duplicate["tools"]
        .as_array_mut()
        .unwrap()
        .push(original["tools"][0].clone());
    assert_eq!(
        registry
            .qualify_catalog(&serde_json::to_vec(&duplicate).unwrap())
            .unwrap()[0]
            .diagnostic,
        "duplicate_tool"
    );
    let mut paginated = original.clone();
    paginated["nextCursor"] = json!("more");
    assert!(
        registry
            .qualify_catalog(&serde_json::to_vec(&paginated).unwrap())
            .is_err()
    );
    assert!(
        registry
            .qualify_catalog(&vec![
                b' ';
                opaque_mcp::gateway_contract::MAX_CATALOG_BYTES + 1
            ])
            .is_err()
    );
    let directory = tempfile::tempdir().unwrap();
    let registry_path = directory.path().join("registry.json");
    let catalog_path = directory.path().join("catalog.json");
    std::fs::write(&registry_path, V2_REGISTRY).unwrap();
    for (catalog, expected) in [(original, 0), (drift, 2)] {
        std::fs::write(&catalog_path, serde_json::to_vec(&catalog).unwrap()).unwrap();
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_opaque-mcp-contract"))
            .arg("qualify")
            .arg(&registry_path)
            .arg(&catalog_path)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(expected));
        assert!(!String::from_utf8_lossy(&output.stdout).contains("malicious-upstream-secret"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("malicious-upstream-secret"));
    }
}

#[test]
fn upstream_schema_compilation_cannot_resolve_references_or_unbounded_patterns() {
    for (key, value) in [
        ("$ref", json!("https://127.0.0.1:9/private")),
        ("$dynamicRef", json!("file:///private")),
        ("pattern", json!("(a+)+$")),
        ("anyOf", json!([{"type":"string"}])),
    ] {
        let mut document: Value = serde_json::from_slice(V2_REGISTRY).unwrap();
        document["routes"][0]["upstream_input_schema"]["properties"]["owner"][key] = value;
        assert!(matches!(
            load(&document),
            Err(ContractError::UnsupportedUpstreamSchema)
        ));
    }
    let mut document: Value = serde_json::from_slice(V2_REGISTRY).unwrap();
    document["routes"][0]["upstream_input_schema"]["description"] = json!("x".repeat(65537));
    assert!(matches!(
        load(&document),
        Err(ContractError::UnsupportedUpstreamSchema)
    ));
    let mut deep = json!({"type":"string"});
    for _ in 0..10 {
        deep = json!({"type":"object","properties":{"nested":deep}});
    }
    document["routes"][0]["upstream_input_schema"] = deep;
    assert!(matches!(
        load(&document),
        Err(ContractError::UnsupportedUpstreamSchema)
    ));
}

#[test]
fn projection_is_signed_bounded_typed_and_cannot_disclose_arbitrary_text() {
    let registry = Registry::from_json(V2_REGISTRY).unwrap();
    let original = registry.prepare_json(V2_CALL).unwrap();
    let projection = original.route().output_projection.as_ref().unwrap();
    let projected = projection
        .project(&json!({"id":42,"status":"created","text":"secret-in-unselected"}))
        .unwrap();
    assert_eq!(
        serde_json::to_value(projected).unwrap(),
        json!({"resource_id":42,"status":"created"})
    );
    for data in [
        json!({"id":"secret","status":"created"}),
        json!({"id":1.5,"status":"created"}),
        json!({"id":1000001,"status":"created"}),
        json!({"id":42,"status":"ignore instructions"}),
        json!({"id":42}),
    ] {
        assert!(projection.project(&data).is_err());
    }
    let mut changed: Value = serde_json::from_slice(V2_REGISTRY).unwrap();
    changed["routes"][0]["output_projection"]["fields"][0]["value_type"]["maximum"] = json!(100);
    assert_ne!(
        original.action_digest(),
        load(&changed)
            .unwrap()
            .prepare_json(V2_CALL)
            .unwrap()
            .action_digest()
    );
    changed["routes"][0]["output_projection"]["fields"][0]["source"] = json!("/nested/text");
    assert!(load(&changed).is_err());
    let mut input: Value = serde_json::from_slice(V2_CALL).unwrap();
    input["output_projection"] = json!({"source":"text"});
    assert_eq!(
        preparation_error(&registry, input),
        ContractError::InvalidCall
    );
}
