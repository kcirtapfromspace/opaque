//! Run with cargo bench --locked -p opaque-core --bench validation.
//! Diagnostic release-mode baseline; compare runs on the same idle host.
use std::collections::HashMap;
use std::hint::black_box;
use std::time::Instant;

use opaque_core::audit::TargetSummary;
use opaque_core::operation::{
    ApprovalRequirement, OperationDef, OperationRegistry, OperationSafety,
};
use opaque_core::validate::InputValidator;

fn measure(name: &str, iterations: u32, mut run: impl FnMut()) {
    for _ in 0..100 {
        run();
    }
    let mut samples = Vec::new();
    for _ in 0..7 {
        let start = Instant::now();
        for _ in 0..iterations {
            run();
        }
        samples.push(start.elapsed().as_nanos() / u128::from(iterations));
    }
    samples.sort_unstable();
    println!(
        "{name},{iterations},{},{},{}",
        samples[0], samples[3], samples[6]
    );
}

fn main() {
    println!("case,iterations,min_ns,median_ns,max_ns");
    let target = HashMap::from([("repo".into(), "example/project".into())]);
    let refs = vec!["vault:secrets/data/marker".to_string()];
    let empty = HashMap::new();
    measure("empty_target", 10_000, || {
        black_box(InputValidator::validate_target(black_box(&empty)).unwrap());
    });
    measure("small_target", 10_000, || {
        black_box(InputValidator::validate_target(black_box(&target)).unwrap());
    });
    measure("target_summary", 10_000, || {
        black_box(TargetSummary::sanitized(black_box(&target)));
    });
    // Valid reference metadata, not credential material.
    measure("secret_references", 10_000, || {
        black_box(InputValidator::validate_secret_ref_names(black_box(&refs)).unwrap());
    });
    let schema = serde_json::json!({"type":"object", "required":["name"], "properties":{"name":{"type":"string"}}});
    let params = serde_json::json!({"name":"marker"});
    let mut registry = OperationRegistry::new();
    registry
        .register(OperationDef {
            name: "bench.validate".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Never,
            default_factors: vec![],
            description: "benchmark fixture".into(),
            params_schema: Some(schema.clone()),
            allowed_target_keys: vec![],
            secret_ref_param_keys: vec![],
        })
        .unwrap();
    measure("cached_schema", 10_000, || {
        black_box(registry.validate_params("bench.validate", black_box(&params))).unwrap();
    });
    measure("compile_and_validate_schema", 1_000, || {
        black_box(opaque_core::operation::validate_params(
            black_box(&schema),
            black_box(&params),
        ))
        .unwrap();
    });
}
