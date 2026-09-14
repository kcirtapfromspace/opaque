//! CLI projections of synthetic broker receipts. These assertions qualify
//! response handling, not provider execution or human approval.
use super::*;
use opaque_core::task::TaskManifest;

fn tenant() -> Value {
    json!({"schema_version":1,"tenant_id":"fixture","broker_id":"00000000-0000-4000-8000-000000000001"})
}

fn manifest(kind: &str) -> Value {
    let action = match kind {
        "publish" => {
            json!({"repo":"fixture/repo","repository_id":42,"secret_name":"MARKER","value_ref":"vault:kv/data/fixture?version=7#MARKER","github_token_ref":"keychain:fixture"})
        }
        "release" => {
            json!({"operation":"github.dispatch_staging_workflow","repo":"fixture/repo","repository_id":42,"workflow_path":".github/workflows/staging.yml","workflow_id":51,"workflow_ref":"main","approved_commit_sha":"a".repeat(40),"workflow_sha256":"b".repeat(64),"image_repository":"ghcr.io/fixture/service","image_digest":format!("sha256:{}","c".repeat(64)),"environment":"staging","github_token_ref":"keychain:fixture"})
        }
        "ssh" => {
            json!({"operation":"ssh.service_health","tenant":tenant(),"subject":"svc_00000000000000000000000000000001","delegation_id":"grant-fixture","workload_uid":1001,"profile_id":"fixture-ssh","profile_sha256":"a".repeat(64),"destination_host":"192.0.2.3","destination_port":2222,"host_key_sha256":"b".repeat(64),"vault_role":"fixture-health","vault_ca_sha256":"c".repeat(64),"vault_token_ref":"keychain:fixture","principal":"fixture-principal","login_user":"operator","source_address":"192.0.2.4","command":"opaque-service-health","health_contract":{"service":"fixture-service","version":"v2","host":"127.0.0.1","port":8080,"path":"/health"},"max_session_secs":20,"grant_id":"00000000-0000-4000-8000-000000000002"})
        }
        "inference" => {
            json!({"operation":opaque_core::inference::INFERENCE_OPERATION,"ordinal":1,"tenant":tenant(),"profile_id":"fixture-model","profile_sha256":"a".repeat(64),"model_id":"fixture/model","model_artifact_sha256":"b".repeat(64),"source_id":"fixture-source","source_snapshot_sha256":"c".repeat(64),"prompt_sha256":"d".repeat(64),"options":opaque_core::inference::InferenceOptions::default()})
        }
        _ => panic!("unknown receipt fixture"),
    };
    let actions: Vec<Value> = if kind == "inference" {
        (1..=3)
            .map(|ordinal| {
                let mut a = action.clone();
                a["ordinal"] = json!(ordinal);
                a
            })
            .collect()
    } else {
        vec![action]
    };
    let schema = match kind {
        "publish" => 1,
        "release" => 2,
        "inference" => 3,
        "ssh" => 4,
        _ => unreachable!(),
    };
    let value = json!({"schema_version":schema,"title":format!("Fixture {kind} receipt"),"expires_in_secs":120,"github_api_url":if matches!(kind,"publish"|"release") {"https://api.github.com"} else {""},"vault_api_url":if kind == "publish" {"https://vault.example.com"} else {""},"actions":actions});
    let parsed: TaskManifest = serde_json::from_value(value.clone()).unwrap();
    parsed.validate().unwrap();
    value
}

fn receipt(kind: &str, state: &str, slot_state: &str) -> Value {
    let manifest = manifest(kind);
    let digest = serde_json::from_value::<TaskManifest>(manifest.clone())
        .unwrap()
        .digest()
        .unwrap();
    let slots: Vec<Value> = manifest["actions"].as_array().unwrap().iter().enumerate().map(|(n, action)| {
        json!({"id":format!("task-fixture:{n}"),"action":action,"state":slot_state,"request_id":null,"reserved_at":null,"finished_at":null,"outcome":null})
    }).collect();
    json!({"id":"task-fixture","manifest_digest":digest,"manifest":manifest,"owner_key":"fixture-owner","tenant":tenant(),"created_at":100,"expires_at":220,"approved_at":101,"approval_mode":"paired_workstation","state":state,"slots":slots})
}

fn call_task(command: &str, result: Value, mode: &str, exit: i32) -> Output {
    let method = match command {
        "show" => "task_get",
        "run" => "task_run",
        "reconcile" => "task_reconcile",
        "revoke" => "task_revoke",
        "list" => "task_list",
        _ => unreachable!(),
    };
    let params = if command == "list" {
        json!({"cursor":"older-fixture","workspace":null})
    } else {
        json!({"task_id":"task-fixture","workspace":null})
    };
    let peer = Peer::new(vec![(
        method,
        Box::new(move |request| {
            assert_eq!(request["params"], params);
            json!({"id":1,"result":result})
        }),
    )]);
    let mut invocation = peer.command();
    invocation
        .current_dir(peer._dir.path())
        .args(["task", command]);
    if command == "list" {
        invocation.args(["--cursor", "older-fixture"]);
    } else {
        invocation.arg("task-fixture");
    }
    if !mode.is_empty() {
        invocation.arg(mode);
    }
    let output = run(&mut invocation);
    assert_exit(&output, exit);
    assert_eq!(peer.finish().len(), 1, "CLI must not repeat task requests");
    output
}

fn output_text(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}
fn includes(output: &Output, expected: &[&str], absent: &[&str]) {
    let text = output_text(output);
    for value in expected {
        assert!(text.contains(value), "missing {value:?}: {text}");
    }
    for value in absent {
        assert!(!text.contains(value), "unexpected {value:?}: {text}");
    }
}

#[test]
fn completed_ssh_receipt_describes_host_evidence_and_fresh_approval() {
    let mut task = receipt("ssh", "completed", "api_accepted");
    let host_output = r#"{"service":"fixture-service","status":"ok","version":"v2"}"#;
    let ssh = json!({"tenant":tenant(),"profile_sha256":"a".repeat(64),"grant_id":"00000000-0000-4000-8000-000000000002","host_key_sha256":"b".repeat(64),"code":"health_observed","host":"192.0.2.3","principal":"fixture-principal","operation":"ssh.service_health","started_at":102,"completed_at":103,"output_sha256":opaque_core::inference::sha256(host_output.as_bytes()),"output_text":host_output,"signed_receipt_sha256":"e".repeat(64)});
    serde_json::from_value::<opaque_core::ssh::SshReceipt>(ssh.clone())
        .unwrap()
        .validate(&serde_json::from_value(task["slots"][0]["action"].clone()).unwrap())
        .unwrap();
    task["slots"][0]["outcome"] =
        json!({"state":"api_accepted","code":"api_accepted","ssh_receipt":ssh});
    let output = call_task("show", json!({"task":task}), "", 0);
    includes(
        &output,
        &[
            "SSH health: 192.0.2.3:2222",
            "Health contract: fixture-service / v2 at 127.0.0.1:8080/health",
            "authenticated health observation",
            "Authenticated host result: HealthObserved",
            "Signed receipt SHA-256:",
            &format!("Host output: {host_output}"),
            "further SSH",
            "fresh approval",
        ],
        &["GitHub accepted these writes", "writes\n"],
    );
}

#[test]
fn inference_receipts_bind_observations_to_profile_source_and_charged_allowance() {
    for observed in [true, false] {
        for github in [true, false] {
            let state = if observed { "completed" } else { "partial" };
            let slot_state = if observed { "api_accepted" } else { "unknown" };
            let mut task = receipt("inference", state, slot_state);
            for n in 0..3 {
                if github {
                    let snapshot: opaque_core::inference::github::GithubCiSnapshot = serde_json::from_value(json!({"source":{"repository":"fixture/repo","workflow_id":51,"branch":"main"},"repository_id":42,"observed_at":100,"runs":[{"id":81,"attempt":2,"head_sha":"e".repeat(40),"status":"completed","conclusion":"success"}]})).unwrap();
                    task["manifest"]["actions"][n]["source_id"] =
                        json!(opaque_core::inference::github::SOURCE_ID);
                    task["manifest"]["actions"][n]["source_snapshot_sha256"] =
                        json!(snapshot.digest());
                    task["manifest"]["actions"][n]["prompt_sha256"] =
                        json!(opaque_core::inference::sha256(
                            snapshot.prompt(n as u32 + 1).unwrap().as_bytes()
                        ));
                    task["manifest"]["actions"][n]["github_ci_snapshot"] = json!(snapshot);
                    task["slots"][n]["action"] = task["manifest"]["actions"][n].clone();
                }
                let action = &task["slots"][n]["action"];
                let evidence = json!({"tenant":tenant(),"profile_sha256":action["profile_sha256"],"prompt_sha256":action["prompt_sha256"],"code":if observed {"completion_observed"} else {"transport_unknown"},"reserved_output_tokens":opaque_core::inference::INFERENCE_OUTPUT_TOKENS,"input_tokens":20,"observed_output_tokens":if observed {Some(7)} else {None},"output_sha256":if observed {Some(opaque_core::inference::sha256(b"fixture model response"))} else {None},"output_text":if observed {Some("fixture model response")} else {None},"duration_ms":100,"completed_at":103});
                serde_json::from_value::<opaque_core::inference::InferenceReceipt>(
                    evidence.clone(),
                )
                .unwrap()
                .validate(&serde_json::from_value(action.clone()).unwrap())
                .unwrap();
                task["slots"][n]["outcome"] = json!({"state":slot_state,"code":if observed {"api_accepted"} else {"transport_unknown"},"inference_receipt":evidence});
            }
            task["manifest_digest"] = json!(
                serde_json::from_value::<TaskManifest>(task["manifest"].clone())
                    .unwrap()
                    .digest()
                    .unwrap()
            );
            let output = call_task("show", json!({"task":task}), "", 0);
            includes(
                &output,
                &[
                    "Charged: 3/3 attempts",
                    "Model: fixture/model",
                    "Profile: fixture-model",
                    "Input tokens: 20",
                    "Reserved output units:",
                ],
                &["GitHub accepted these writes"],
            );
            assert_eq!(
                output_text(&output)
                    .contains("GitHub repository: fixture/repo | Workflow: 51 | Branch: main"),
                github
            );
            if github {
                includes(
                    &output,
                    &[
                        "1 sampled runs",
                        "Run 81 attempt 2: Completed / Some(Success)",
                    ],
                    &[],
                );
            }
            if observed {
                includes(
                    &output,
                    &[
                        "Three model completions recorded",
                        "Observed output tokens: Some(7)",
                        "Model output: fixture model response",
                        "does not attest GPU time",
                    ],
                    &[],
                );
            } else {
                includes(
                    &output,
                    &[
                        "unknown (charged; do not retry)",
                        "Observed output tokens: None",
                        "fresh approval",
                    ],
                    &["Model output:", "Three model completions recorded"],
                );
            }
        }
    }
}

#[test]
fn receipt_provenance_and_legacy_ssh_contract_are_explicit() {
    for (mode, label) in [
        (json!("native"), "native approval"),
        (json!("insecure_test"), "INSECURE TEST APPROVAL"),
        (Value::Null, "approval mode unavailable"),
    ] {
        let mut task = receipt("ssh", "revoked", "rejected");
        task["approval_mode"] = mode;
        task["slots"][0]["action"]["health_contract"] = Value::Null;
        task["manifest"]["actions"][0]["health_contract"] = Value::Null;
        task["manifest_digest"] = json!(
            serde_json::from_value::<TaskManifest>(task["manifest"].clone())
                .unwrap()
                .digest()
                .unwrap()
        );
        let output = call_task("revoke", task, "", 0);
        includes(
            &output,
            &[
                label,
                "legacy fixture-api / version 1",
                "rejected (charged)",
                "This task is closed",
            ],
            &[
                "authenticated health observation",
                "GitHub accepted these writes",
            ],
        );
    }
}

#[test]
fn malformed_receipts_fail_automation_in_every_output_mode() {
    for command in ["show", "list", "run"] {
        for mode in ["", "--json", "--quiet"] {
            for malformed in [
                json!({}),
                json!({"task":{"state":"completed"}}),
                json!({"tasks":{}}),
            ] {
                let output = call_task(command, malformed.clone(), mode, 3);
                if mode == "--json" {
                    assert_eq!(
                        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
                        json!({"id":1,"result":malformed})
                    );
                } else {
                    assert!(
                        String::from_utf8_lossy(&output.stderr).contains("invalid task receipt")
                    );
                    assert!(output.stdout.is_empty());
                }
            }
        }
    }
}

#[test]
fn task_run_exit_status_and_receipt_preserve_closed_and_pending_states() {
    for state in [
        "planned",
        "running",
        "partial",
        "revoked",
        "expired",
        "completed",
    ] {
        for mode in ["", "--json", "--quiet"] {
            let task = receipt(
                "publish",
                state,
                if state == "completed" {
                    "api_accepted"
                } else {
                    "unknown"
                },
            );
            let output = call_task(
                "run",
                json!({"task":task}),
                mode,
                if state == "completed" { 0 } else { 1 },
            );
            if mode == "--json" {
                assert_eq!(
                    serde_json::from_slice::<Value>(&output.stdout).unwrap()["result"]["task"],
                    task
                );
            } else if mode == "--quiet" {
                assert_eq!(
                    serde_json::from_slice::<Value>(&output.stdout).unwrap()["task"],
                    task
                );
            } else {
                includes(
                    &output,
                    &[
                        &format!("State: {state}"),
                        "Charged: 1/1 writes",
                        "fixture/repo / MARKER",
                        "paired workstation approval",
                        "Credential reference: keychain:fixture",
                    ],
                    &[],
                );
                if state != "completed" {
                    includes(
                        &output,
                        &["unknown (charged; do not retry)"],
                        &["GitHub accepted these writes"],
                    );
                }
            }
        }
    }
}

#[test]
fn receipt_list_displays_owner_scope_pagination_and_legacy_provenance() {
    let empty = call_task("list", json!({"tasks":[]}), "", 0);
    assert!(
        String::from_utf8_lossy(&empty.stdout).contains("No tasks for this authenticated owner")
    );
    for (has_more, cursor) in [
        (true, Some("next-page")),
        (false, Some("next-page")),
        (true, None),
    ] {
        let mut task = receipt("publish", "planned", "pending");
        task["approved_at"] = Value::Null;
        task["approval_mode"] = Value::Null;
        task["tenant"] = Value::Null;
        let output = call_task(
            "list",
            json!({"tasks":[task],"has_more":has_more,"next_cursor":cursor}),
            "",
            0,
        );
        includes(
            &output,
            &[
                "Approval: not granted",
                "not attempted",
                "Charged: 0/1 writes",
                "opaque task run task-fixture",
            ],
            &["paired workstation approval"],
        );
        assert_eq!(
            output_text(&output).contains("opaque task list --cursor next-page"),
            has_more && cursor.is_some()
        );
    }
}

#[test]
fn release_reconciliation_reports_evidence_without_claiming_service_health() {
    for state in ["pending", "running", "succeeded", "failed", "ambiguous"] {
        for mode in ["", "--json"] {
            let mut task = receipt("release", "completed", "api_accepted");
            task["release_observation"] = json!({"state":state,"correlation":"dispatch_response","code":"fixture_observation","run_id":81,"run_url":"https://github.com/fixture/repo/actions/runs/81","observed_commit_sha":"a".repeat(40),"checked_at":130,"run_attempt":2});
            let output = call_task(
                "reconcile",
                json!({"task":task}),
                mode,
                if matches!(state, "failed" | "ambiguous") {
                    1
                } else {
                    0
                },
            );
            if mode == "--json" {
                assert_eq!(
                    serde_json::from_slice::<Value>(&output.stdout).unwrap()["result"]["task"],
                    task
                );
            } else {
                includes(
                    &output,
                    &[
                        "Workflow: .github/workflows/staging.yml [workflow 51]",
                        "Dispatch recorded",
                        "fixture_observation",
                        "(attempt 2)",
                        "does not independently prove service health",
                    ],
                    &["GitHub accepted these writes"],
                );
            }
        }
    }
}
