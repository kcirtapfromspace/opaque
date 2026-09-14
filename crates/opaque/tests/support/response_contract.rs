//! Actual CLI request/response contracts against the parent's synthetic IPC peer.
//! These tests assert rendering and dispatch, not vendor or human approval.
use super::*;

fn exchange(
    args: &[&str],
    method: &'static str,
    mut params: Value,
    reply: Value,
    exit: i32,
) -> Output {
    if method == "github" || method.starts_with("task_") {
        params["workspace"] = Value::Null;
    }
    let peer = Peer::new(vec![(
        method,
        Box::new(move |request| {
            assert_eq!(request["params"], params, "CLI dispatch changed");
            assert_eq!(request["id"], 1);
            reply
        }),
    )]);
    let output = run(peer.command().current_dir(peer._dir.path()).args(args));
    assert_exit(&output, exit);
    assert_eq!(peer.finish().len(), 1);
    output
}

fn rendered(args: &[&str], method: &'static str, params: Value, result: Value) -> Output {
    exchange(args, method, params, json!({"id":1,"result":result}), 0)
}

fn contains(output: &Output, expected: &[&str], forbidden: &[&str]) {
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for token in expected {
        assert!(text.contains(token), "missing {token:?} in {text}");
    }
    for token in forbidden {
        assert!(!text.contains(token), "unexpected {token:?} in {text}");
    }
    assert!(
        !text.contains('\u{1b}'),
        "NO_COLOR output contains ANSI control sequences"
    );
}

#[test]
fn liveness_and_version_outputs_preserve_daemon_status() {
    for (result, expected) in [
        (json!({"status":"ok"}), "Daemon is alive"),
        (json!({"status":"degraded"}), "status: degraded"),
        (json!({}), "Pong"),
    ] {
        contains(
            &rendered(&["ping"], "ping", Value::Null, result),
            &[expected],
            &[],
        );
    }
    contains(
        &rendered(
            &["version"],
            "version",
            Value::Null,
            json!({"version":"test-build-123"}),
        ),
        &["opaqued", "test-build-123"],
        &[],
    );
    contains(
        &rendered(
            &["version"],
            "version",
            Value::Null,
            json!({"unsupported":true}),
        ),
        &["\"unsupported\": true"],
        &[],
    );
}

#[test]
fn whoami_distinguishes_legacy_signed_out_required_and_signed_in() {
    for (result, expected, forbidden) in [
        (
            json!({"uid":42,"executable":"/fixture/agent"}),
            vec!["42", "/fixture/agent"],
            vec!["not signed in", "opaque login"],
        ),
        (
            json!({"identity":null}),
            vec!["not signed in"],
            vec!["requires identity"],
        ),
        (
            json!({"identity_required":true}),
            vec!["not signed in", "requires identity", "opaque login"],
            vec![],
        ),
        (
            json!({"identity_required":true,"identity":{"label":"Test Human","principal_id":"hum_test","email":"human@example.test","roles":["auditor","operator"],"issuer":"https://idp.example.test","session_expires_at_utc_ms":0}}),
            vec![
                "Test Human",
                "hum_test",
                "human@example.test",
                "auditor, operator",
                "https://idp.example.test",
                "expired",
            ],
            vec!["not signed in", "\"identity\""],
        ),
        (
            json!({"identity":{}}),
            vec!["Identity"],
            vec!["not signed in", "roles:"],
        ),
        (
            json!(["legacy-shape"]),
            vec!["legacy-shape"],
            vec!["not signed in"],
        ),
    ] {
        contains(
            &rendered(&["whoami"], "whoami", Value::Null, result),
            &expected,
            &forbidden,
        );
    }
}

#[test]
fn sandbox_output_only_exposes_lengths_and_exit_state() {
    let params = json!({"profile":"fixture","command":["true"]});
    for (exit, stdout, stderr, truncated) in [
        (0, 0, 0, false),
        (0, 12, 0, true),
        (3, 0, 7, false),
        (3, 11, 13, true),
    ] {
        let output = rendered(
            &["exec", "--profile", "fixture", "--", "true"],
            "exec",
            params.clone(),
            json!({"exit_code":exit,"stdout_length":stdout,"stderr_length":stderr,"truncated":truncated,"duration_ms":17,"stdout":"PRIVATE_STDOUT_MARKER","stderr":"PRIVATE_STDERR_MARKER"}),
        );
        let outcome = if exit == 0 {
            "Sandbox exec succeeded"
        } else {
            "Sandbox exec failed"
        };
        contains(
            &output,
            &[outcome, "17ms"],
            &["PRIVATE_STDOUT_MARKER", "PRIVATE_STDERR_MARKER"],
        );
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(text.contains("output withheld"), stdout > 0 || stderr > 0);
        assert_eq!(text.contains("Output truncated"), truncated);
    }
}

#[test]
fn generic_operations_render_scope_without_null_fields() {
    let params = json!({"operation":"fixture.operation","params":{},"target":{},"secret_ref_names":[],"workspace":null});
    for (result, expected) in [
        (json!({"status":"ok"}), vec!["Operation succeeded"]),
        (
            json!({"status":"success","secret_name":"TOKEN","repo":"org/repo","environment":"staging","omitted":null}),
            vec!["Set TOKEN on org/repo (env: staging)", "env:"],
        ),
        (
            json!({"status":"created","secret_name":"TOKEN","repo":"org/repo"}),
            vec!["Set TOKEN on org/repo"],
        ),
        (
            json!({"status":"updated","secret_name":"TOKEN","org":"fixture-org"}),
            vec!["Set TOKEN on org fixture-org"],
        ),
        (
            json!({"status":"ok","secret_name":"TOKEN","scope":"user"}),
            vec!["Set TOKEN (user-level)"],
        ),
        (
            json!({"status":"ok","secret_name":"TOKEN","scope":"other","environment":"orphan","attempts":2}),
            vec!["Operation completed: TOKEN", "other", "attempts:", "2"],
        ),
        (
            json!({"status":"unknown"}),
            vec!["Operation returned status: unknown"],
        ),
        (json!(["fallback-result"]), vec!["fallback-result"]),
    ] {
        contains(
            &rendered(
                &["execute", "fixture.operation"],
                "execute",
                params.clone(),
                result,
            ),
            &expected,
            &["omitted"],
        );
    }
}

#[test]
fn secret_inventory_rendering_keeps_names_and_update_metadata() {
    let output = rendered(
        &["github", "list-secrets", "--repo", "org/repo"],
        "github",
        json!({"action":"list_secrets","scope":"actions","repo":"org/repo"}),
        json!({"total_count":3,"secrets":[{"name":"FIRST","updated_at":"2026-01-02"},{"name":"SECOND"},{}]}),
    );
    contains(
        &output,
        &[
            "3 secret(s)",
            "FIRST",
            "updated 2026-01-02",
            "SECOND",
            "(unknown)",
        ],
        &[],
    );
    let output = rendered(
        &["github", "list-secrets"],
        "github",
        json!({"action":"list_secrets","scope":"actions"}),
        json!({"secrets":[{"name":"ONLY"}]}),
    );
    contains(&output, &["1 secret(s)", "ONLY"], &[]);
}

#[test]
fn onepassword_shapes_preserve_exact_explicitly_returned_field_value() {
    for (args, params, result, expected) in [
        (
            vec!["onepassword", "list-vaults"],
            json!({"action":"list_vaults"}),
            json!({"vaults":[{"name":"team","description":"shared"},{"name":"personal"},{}]}),
            vec!["3 vault(s)", "team", "shared", "personal", "(unknown)"],
        ),
        (
            vec!["onepassword", "list-items", "--vault", "team"],
            json!({"action":"list_items","vault":"team"}),
            json!({"vault":"team","items":[{"title":"build","category":"API_CREDENTIAL"},{"title":"plain"},{}]}),
            vec![
                "3 item(s)",
                "team",
                "build",
                "[API_CREDENTIAL]",
                "plain",
                "(unknown)",
            ],
        ),
        (
            vec!["onepassword", "list-items", "--vault", "team"],
            json!({"action":"list_items","vault":"team"}),
            json!({"items":[]}),
            vec!["0 item(s)", "(unknown)"],
        ),
        (
            vec![
                "onepassword",
                "read-field",
                "--vault",
                "team",
                "--item",
                "build",
                "--field",
                "password",
            ],
            json!({"action":"read_field","vault":"team","item":"build","field":"password"}),
            json!({"vault":"team","item":"build","field":"password","value":"  fixture\nsecond\tline  "}),
            vec!["team/build/password", "  fixture\nsecond\tline  "],
        ),
        (
            vec!["onepassword", "list-vaults"],
            json!({"action":"list_vaults"}),
            json!({"field":null}),
            vec!["?/?/?"],
        ),
        (
            vec!["onepassword", "list-vaults"],
            json!({"action":"list_vaults"}),
            json!({"other":true}),
            vec!["\"other\": true"],
        ),
    ] {
        let output = rendered(&args, "onepassword", params.clone(), result.clone());
        contains(&output, &expected, &[]);
        if let Some(value) = result.get("value").and_then(Value::as_str) {
            assert!(
                output.stderr.is_empty(),
                "field value must not reach stderr"
            );
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert_eq!(stdout.matches(value).count(), 1);
            assert!(stdout.ends_with(&format!("{value}\n")));
            let mut json_args = args;
            json_args.push("--json");
            let output = rendered(&json_args, "onepassword", params, result.clone());
            assert!(output.stderr.is_empty());
            let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(envelope, json!({"id":1,"result":result}));
        }
    }
}

#[test]
fn leases_display_ttl_charge_budget_and_exhaustion() {
    contains(
        &rendered(&["leases"], "leases", Value::Null, json!({})),
        &["No active approval leases"],
        &[],
    );
    let output = rendered(
        &["leases"],
        "leases",
        Value::Null,
        json!({"count":3,"leases":[{"operation":"fixture.op","target":"a\u{0000}b","ttl_remaining_secs":125,"client_fingerprint":"fp-one","one_time":true,"remaining_uses":0,"spent":4},{"ttl_remaining_secs":9,"remaining_uses":2},{}]}),
    );
    contains(
        &output,
        &[
            "3 active lease(s)",
            "2m 5s remaining",
            "a, b",
            "client:fp-one",
            "one-time",
            "0 attempts remaining, 4 spent",
            "exhausted",
            "9s remaining",
            "2 attempts remaining, 0 spent",
        ],
        &["\u{0000}"],
    );
    contains(
        &rendered(&["leases"], "leases", Value::Null, json!({"count":1})),
        &["1 active lease(s)", "\"count\": 1"],
        &[],
    );
}

#[test]
fn agent_listing_and_revocation_render_actual_session_state() {
    contains(
        &rendered(
            &["agent", "list"],
            "agent_session_list",
            Value::Null,
            json!({}),
        ),
        &["No active agent sessions"],
        &[],
    );
    contains(
        &rendered(
            &["agent", "list"],
            "agent_session_list",
            Value::Null,
            json!({"count":2,"sessions":[{"session_id":"session-A","label":"worker","ttl_remaining_secs":61},{}]}),
        ),
        &[
            "2 active agent session(s)",
            "session-A",
            "[worker]",
            "1m 1s",
            "0s remaining",
        ],
        &[],
    );
    contains(
        &rendered(
            &["agent", "list"],
            "agent_session_list",
            Value::Null,
            json!({"count":1}),
        ),
        &["\"count\": 1"],
        &[],
    );
    for (status, expected) in [
        ("ended", "Ended agent session session-A"),
        ("not_found", "Agent session not found: session-A"),
        ("unexpected", "\"status\": \"unexpected\""),
    ] {
        contains(
            &rendered(
                &["agent", "end", "session-A"],
                "agent_session_end",
                json!({"session_id":"session-A"}),
                json!({"status":status,"session_id":"session-A"}),
            ),
            &[expected],
            &[],
        );
    }
    contains(
        &rendered(
            &["agent", "end", "--all"],
            "agent_session_end",
            json!({"all":true}),
            json!({"all":true,"ended_count":3}),
        ),
        &["Ended 3 wrapped-agent session(s)"],
        &[],
    );
}

#[test]
fn identity_lists_distinguish_disabled_expired_and_revoked_records() {
    for (result, expected) in [
        (json!({}), vec!["{}"]),
        (json!({"principals":[]}), vec!["No principals registered"]),
        (
            json!({"principals":[{"id":"hum_0123456789abcdef","kind":"human","label":"Jane\nAdmin","disabled":true,"roles":["admin",null],"last_seen":1},{}]}),
            vec![
                "hum_01234567…",
                "human",
                "Jane  Admin",
                "admin",
                "DISABLED",
                "[OK]",
            ],
        ),
    ] {
        contains(
            &rendered(
                &["identity", "ls"],
                "identity.principal_list",
                Value::Null,
                result,
            ),
            &expected,
            &["Jane\nAdmin"],
        );
    }
    let future = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600) as i64;
    for (result, expected) in [
        (json!({}), vec!["{}"]),
        (json!({"delegations":[]}), vec!["No delegations recorded"]),
        (
            json!({"delegations":[{"jti":"del_0123456789abcdef","mode":"delegated","sub_label":"Jane","act_label":"Builder","approved_by":"hum_0123456789abcdef","revoked_at":1},{"sub":"subject","act":"agent","revoked_at":null,"expires_at":0},{"expires_at":future},{}]}),
            vec![
                "del_01234567…",
                "Jane",
                "Builder",
                "subject",
                "agent",
                "REVOKED",
                "EXPIRED",
                "expires in",
            ],
        ),
    ] {
        contains(
            &rendered(
                &["identity", "delegations"],
                "identity.delegation_list",
                Value::Null,
                result,
            ),
            &expected,
            &[],
        );
    }
}

#[test]
fn identity_role_and_logout_results_do_not_invent_revocations() {
    for (result, expected) in [
        (
            json!({"label":"Jane","roles":["admin"]}),
            "Updated roles for Jane: admin",
        ),
        (
            json!({"id":"hum_test","roles":[]}),
            "Updated roles for hum_test: -",
        ),
        (json!({}), "Updated roles for principal: -"),
    ] {
        contains(
            &rendered(
                &["identity", "roles", "hum_test", "admin,operator", "auditor"],
                "identity.role_set",
                json!({"principal_id":"hum_test","roles":["admin","operator","auditor"]}),
                result,
            ),
            &[expected],
            &[],
        );
    }
    for (result, expected) in [
        (json!({}), "No active login sessions"),
        (json!({"revoked":2}), "Revoked 2 login session(s)"),
    ] {
        contains(
            &rendered(&["logout"], "identity.logout", Value::Null, result),
            &[expected],
            &[],
        );
    }
}

#[test]
fn device_pairing_requires_confirmation_and_distinguishes_revoked_devices() {
    let future = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 60;
    for result in [
        json!({}),
        json!({"server_addr":"127.0.0.1:9443","qr_payload":{"expires_at":future,"test":"pairing"}}),
        json!({"qr_payload":{"expires_at":0}}),
    ] {
        let has_payload = result.get("qr_payload").is_some();
        let output = rendered(
            &["device", "pair"],
            "device_pair_start",
            Value::Null,
            result,
        );
        contains(
            &output,
            &[
                "Device pairing started",
                "MATCH the key",
                "device has no approval authority",
            ],
            &["it now holds approval authority"],
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).contains("pairing window ends"),
            has_payload
        );
    }
    contains(
        &rendered(&["device", "ls"], "device_list", Value::Null, json!({})),
        &["No paired devices"],
        &[],
    );
    contains(
        &rendered(
            &["device", "ls"],
            "device_list",
            Value::Null,
            json!({"devices":[{"name":"active","device_id":"dev-A","fingerprint":"fp-A","confirmed":true,"paired_by":"Jane"},{"name":"revoked","confirmed":false,"revoked":true},{"name":"pending","device_id":"dev-P"},{}]}),
        ),
        &[
            "4 paired device(s)",
            "ACTIVE",
            "REVOKED",
            "UNCONFIRMED",
            "fp-A",
            "paired by Jane",
            "opaque device confirm dev-P",
        ],
        &["opaque device confirm dev-A"],
    );
    contains(
        &rendered(
            &["device", "confirm", "dev-P"],
            "device_pair_confirm",
            json!({"device_id":"dev-P"}),
            json!({"name":"phone"}),
        ),
        &["Device \"phone\" confirmed"],
        &[],
    );
    contains(
        &rendered(
            &["device", "revoke", "dev-P"],
            "device_revoke",
            json!({"device_id":"dev-P"}),
            json!({"device_id":"dev-P"}),
        ),
        &["Device dev-P revoked"],
        &[],
    );
}

#[test]
fn hardware_key_inventory_and_removal_keep_credential_identity() {
    contains(
        &rendered(&["key", "ls"], "fido2_list", Value::Null, json!({})),
        &["No FIDO2 credentials registered"],
        &[],
    );
    contains(
        &rendered(
            &["key", "ls"],
            "fido2_list",
            Value::Null,
            json!({"credentials":[{"label":"security key","credential_id":"cred-A","created_at":"2026-01-02"},{}]}),
        ),
        &[
            "2 FIDO2 credential(s)",
            "security key",
            "id cred-A",
            "registered 2026-01-02",
        ],
        &[],
    );
    contains(
        &rendered(
            &["key", "remove", "cred-A"],
            "fido2_remove",
            json!({"credential_id":"cred-A"}),
            json!({}),
        ),
        &["Credential removed", "approval authority revoked"],
        &[],
    );
}

#[test]
fn daemon_error_codes_have_correct_exit_status_and_actionable_hints() {
    for (code, exit, hint) in [
        ("policy_denied", 4, "security policy"),
        ("DENIED", 4, "security policy"),
        ("not_found", 3, "Resource not found"),
        ("NOT_FOUND", 3, "Resource not found"),
        ("invalid", 3, "input parameters"),
        ("INVALID", 3, "input parameters"),
        ("config", 3, "configuration issue"),
        ("CONFIG", 3, "configuration issue"),
        ("unexpected", 3, "opaque doctor"),
        ("", 3, ""),
    ] {
        let output = exchange(
            &["ping"],
            "ping",
            Value::Null,
            json!({"id":1,"error":{"code":code,"message":"fixture rejection"}}),
            exit,
        );
        contains(&output, &["fixture rejection", hint], &["Daemon is alive"]);
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).contains("code:"),
            !code.is_empty()
        );
    }
    let output = exchange(
        &["--json", "ping"],
        "ping",
        Value::Null,
        json!({"id":1,"error":{"code":"denied","message":"fixture rejection"}}),
        3,
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], "denied");
    assert_eq!(value["error"]["message"], "fixture rejection");
}

#[test]
fn quiet_json_and_verbose_output_keep_their_automation_contract() {
    let result = json!({"uid":42,"fixture":"visible"});
    let output = rendered(
        &["--quiet", "whoami"],
        "whoami",
        Value::Null,
        result.clone(),
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        result
    );
    contains(&output, &[], &["Client Identity"]);
    let output = rendered(
        &["--quiet", "ping"],
        "ping",
        Value::Null,
        json!({"status":"ok"}),
    );
    assert!(output.stdout.is_empty());
    let output = rendered(&["--json", "whoami"], "whoami", Value::Null, result.clone());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        json!({"id":1,"result":result})
    );
    let output = rendered(
        &[
            "--verbose",
            "--plain",
            "execute",
            "fixture.operation",
            "--target",
            "repo=org/repo",
            "--secret",
            "PRIVATE_REF_MARKER",
        ],
        "execute",
        json!({"operation":"fixture.operation","params":{},"target":{"repo":"org/repo"},"secret_ref_names":["PRIVATE_REF_MARKER"],"workspace":null}),
        json!({"status":"ok"}),
    );
    contains(
        &output,
        &[
            "method=execute",
            "parameters omitted",
            "Operation succeeded",
        ],
        &["PRIVATE_REF_MARKER"],
    );
}

#[test]
fn github_dispatch_preserves_scope_and_optional_authority_parameters() {
    let common = [
        "--secret-name",
        "TOKEN",
        "--value-ref",
        "bitwarden:fixture/TOKEN",
    ];
    for (sub, extra, expected) in [
        (
            "set-secret",
            vec!["--repo", "org/repo"],
            json!({"scope":"repo_actions","repo":"org/repo"}),
        ),
        (
            "set-secret",
            vec![
                "--repo",
                "org/repo",
                "--environment",
                "staging",
                "--github-token-ref",
                "keychain:fixture",
            ],
            json!({"scope":"env_actions","repo":"org/repo","environment":"staging","github_token_ref":"keychain:fixture"}),
        ),
        (
            "set-codespaces-secret",
            vec![],
            json!({"scope":"codespaces_user"}),
        ),
        (
            "set-codespaces-secret",
            vec![
                "--repo",
                "org/repo",
                "--github-token-ref",
                "keychain:fixture",
                "--selected-repository-ids",
                "12,34",
            ],
            json!({"scope":"codespaces_repo","repo":"org/repo","github_token_ref":"keychain:fixture","selected_repository_ids":[12,34]}),
        ),
        (
            "set-dependabot-secret",
            vec!["--repo", "org/repo"],
            json!({"scope":"dependabot","repo":"org/repo"}),
        ),
        (
            "set-dependabot-secret",
            vec![
                "--repo",
                "org/repo",
                "--github-token-ref",
                "keychain:fixture",
            ],
            json!({"scope":"dependabot","repo":"org/repo","github_token_ref":"keychain:fixture"}),
        ),
        (
            "set-org-secret",
            vec!["--org", "fixture-org"],
            json!({"scope":"org_actions","org":"fixture-org","visibility":"private"}),
        ),
        (
            "set-org-secret",
            vec![
                "--org",
                "fixture-org",
                "--visibility",
                "selected",
                "--selected-repository-ids",
                "12,34",
                "--github-token-ref",
                "keychain:fixture",
            ],
            json!({"scope":"org_actions","org":"fixture-org","visibility":"selected","selected_repository_ids":[12,34],"github_token_ref":"keychain:fixture"}),
        ),
    ] {
        let mut args = vec!["github", sub];
        args.extend(common);
        args.extend(extra);
        let mut expected = expected;
        expected["secret_name"] = json!("TOKEN");
        expected["value_ref"] = json!("bitwarden:fixture/TOKEN");
        contains(
            &rendered(&args, "github", expected, json!({"status":"ok"})),
            &["Operation succeeded"],
            &[],
        );
    }
    for action in ["list-secrets", "delete-secret"] {
        for options in [false, true] {
            let mut args = vec!["--yes", "github", action];
            let mut params = json!({"action":action.replace('-',"_"),"scope":"actions"});
            if action == "delete-secret" {
                args.extend(["--secret-name", "TOKEN"]);
                params["secret_name"] = json!("TOKEN");
            }
            if options {
                args.extend([
                    "--repo",
                    "org/repo",
                    "--org",
                    "fixture-org",
                    "--environment",
                    "staging",
                    "--github-token-ref",
                    "keychain:fixture",
                ]);
                for (k, v) in [
                    ("repo", "org/repo"),
                    ("org", "fixture-org"),
                    ("environment", "staging"),
                    ("github_token_ref", "keychain:fixture"),
                ] {
                    params[k] = json!(v);
                }
            }
            contains(
                &rendered(&args, "github", params, json!({"status":"ok"})),
                &["Operation succeeded"],
                &[],
            );
        }
    }
}

#[test]
fn publish_env_and_manifest_report_partial_failure_without_replaying() {
    for manifest in [false, true] {
        for keep_going in [false, true] {
            for json_output in [false, true] {
                for (error_code, malformed) in [("provider_failed", false), ("", false), ("", true)]
                {
                    let mut replies: Vec<(&'static str, Reply)> = vec![(
                        "github",
                        Box::new(move |r| {
                            assert_eq!(
                                r["params"],
                                json!({"scope":"env_actions","repo":"org/repo","environment":"staging","github_token_ref":"keychain:fixture","secret_name":"FIRST","value_ref":"bitwarden:fixture/FIRST","workspace":null})
                            );
                            if malformed {
                                json!({"id":1})
                            } else {
                                json!({"id":1,"error":{"code":error_code,"message":"fixture provider rejection"}})
                            }
                        }),
                    )];
                    if keep_going {
                        replies.push((
                            "github",
                            Box::new(|r| {
                                assert_eq!(
                                    r["params"],
                                    json!({"scope":"env_actions","repo":"org/repo","environment":"staging","github_token_ref":"keychain:fixture","secret_name":"SECOND","value_ref":"bitwarden:fixture/SECOND","workspace":null})
                                );
                                json!({"id":1,"result":{"status":"updated"}})
                            }),
                        ));
                    }
                    let peer = Peer::new(replies);
                    std::fs::write(
                        peer._dir.path().join("env.example"),
                        "FIRST=PRIVATE_ENV_VALUE\nSECOND=OTHER_PRIVATE_VALUE\n",
                    )
                    .unwrap();
                    std::fs::write(peer._dir.path().join("manifest.json"),serde_json::to_vec(&json!({"repo":"ignored/repo","environment":"ignored-environment","entries":[{"secret_name":"FIRST","value_ref":"bitwarden:fixture/FIRST"},{"secret_name":"SECOND","value_ref":"bitwarden:fixture/SECOND"}]})).unwrap()).unwrap();
                    let mut command = peer.command();
                    command.current_dir(peer._dir.path());
                    command.args(if manifest {
                        vec![
                            "github",
                            "publish-manifest",
                            "--manifest-file",
                            "manifest.json",
                        ]
                    } else {
                        vec![
                            "github",
                            "publish-env",
                            "--env-file",
                            "env.example",
                            "--value-ref-template",
                            "bitwarden:fixture/{name}",
                        ]
                    });
                    command.args([
                        "--repo",
                        "org/repo",
                        "--environment",
                        "staging",
                        "--github-token-ref",
                        "keychain:fixture",
                    ]);
                    if keep_going {
                        command.arg("--continue-on-error");
                    }
                    if json_output {
                        command.arg("--json");
                    }
                    let output = run(&mut command);
                    assert_exit(&output, 1);
                    assert_eq!(peer.finish().len(), if keep_going { 2 } else { 1 });
                    contains(
                        &output,
                        &["publish failed: "],
                        &["PRIVATE_ENV_VALUE", "OTHER_PRIVATE_VALUE"],
                    );
                    if json_output {
                        let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
                        assert_eq!(summary["attempted"], if keep_going { 2 } else { 1 });
                        assert_eq!(summary["failed"], 1);
                        assert_eq!(summary["published"], u64::from(keep_going));
                        assert_eq!(
                            summary[if manifest {
                                "total_entries"
                            } else {
                                "total_discovered"
                            }],
                            2,
                            "discovered scope must survive fail-fast"
                        );
                        assert_eq!(summary["items"][0]["secret_name"], "FIRST");
                        assert_eq!(summary["items"][0]["status"], "failed");
                        if malformed {
                            assert!(
                                summary["items"][0]["error"]
                                    .as_str()
                                    .unwrap()
                                    .contains("outcome unknown")
                            );
                        }
                        if keep_going {
                            assert_eq!(summary["items"][1]["status"], "updated");
                        }
                    } else {
                        contains(&output, &["FIRST", "failed"], &[]);
                    }
                }
            }
        }
    }
}

#[test]
fn publish_plans_are_refs_only_and_make_no_broker_requests() {
    for json_output in [false, true] {
        let peer = Peer::new(vec![]);
        std::fs::write(
            peer._dir.path().join("env.example"),
            "FIRST=PRIVATE_ENV_VALUE\nSECOND=OTHER_PRIVATE_VALUE\n",
        )
        .unwrap();
        let mut command = peer.command();
        command.current_dir(peer._dir.path()).args([
            "github",
            "build-manifest",
            "--env-file",
            "env.example",
            "--value-ref-template",
            "bitwarden:fixture/{name}",
            "--out",
            "nested/manifest.json",
            "--repo",
            "org/repo",
            "--environment",
            "staging",
        ]);
        if json_output {
            command.arg("--json");
        }
        let output = run(&mut command);
        assert_exit(&output, 0);
        contains(&output, &[], &["PRIVATE_ENV_VALUE", "OTHER_PRIVATE_VALUE"]);
        let manifest: Value = serde_json::from_slice(
            &std::fs::read(peer._dir.path().join("nested/manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            manifest["entries"],
            json!([{"secret_name":"FIRST","value_ref":"bitwarden:fixture/FIRST"},{"secret_name":"SECOND","value_ref":"bitwarden:fixture/SECOND"}])
        );
        for manifest_mode in [false, true] {
            let mut command = peer.command();
            command.current_dir(peer._dir.path());
            command.args(if manifest_mode {
                vec![
                    "github",
                    "publish-manifest",
                    "--manifest-file",
                    "nested/manifest.json",
                ]
            } else {
                vec![
                    "github",
                    "publish-env",
                    "--env-file",
                    "env.example",
                    "--repo",
                    "org/repo",
                    "--value-ref-template",
                    "bitwarden:fixture/{name}",
                ]
            });
            command.arg("--dry-run");
            if json_output {
                command.arg("--json");
            }
            let output = run(&mut command);
            assert_exit(&output, 0);
            contains(&output, &[], &["PRIVATE_ENV_VALUE", "OTHER_PRIVATE_VALUE"]);
            if json_output {
                let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(summary["attempted"], 0);
                assert_eq!(summary["published"], 0);
                assert_eq!(summary["failed"], 0);
                assert_eq!(summary["items"].as_array().unwrap().len(), 2);
                assert!(
                    summary["items"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .all(|i| i["status"] == "planned")
                );
            } else {
                contains(
                    &output,
                    &["Dry run complete: 2 secret(s) planned", "mode:", "dry-run"],
                    &[],
                );
            }
        }
        assert!(peer.finish().is_empty());
    }
}

#[test]
fn login_start_errors_are_distinct_from_authenticated_completion() {
    for json_output in [false, true] {
        for code in ["identity_not_configured", "provider_failed"] {
            let args = if json_output {
                vec!["--json", "login", "--no-browser"]
            } else {
                vec!["login", "--no-browser"]
            };
            let output = exchange(
                &args,
                "identity.login_start",
                Value::Null,
                json!({"id":1,"error":{"code":code,"message":"identity fixture rejection"}}),
                3,
            );
            if json_output {
                assert_eq!(
                    serde_json::from_slice::<Value>(&output.stdout).unwrap()["error"]["code"],
                    code
                );
            } else if code == "identity_not_configured" {
                contains(
                    &output,
                    &[
                        "Identity is not configured",
                        "Enable OIDC login",
                        "[identity]",
                    ],
                    &["Signed in as"],
                );
            } else {
                contains(&output, &["identity fixture rejection"], &["Signed in as"]);
            }
        }
    }
    for (result, error) in [
        (json!({}), "no attempt_id"),
        (json!({"attempt_id":"attempt"}), "no auth_url"),
    ] {
        let output = exchange(
            &["login", "--no-browser"],
            "identity.login_start",
            Value::Null,
            json!({"id":1,"result":result}),
            3,
        );
        contains(&output, &[error], &["Signed in as"]);
    }
}

#[test]
fn login_polling_preserves_completion_failure_and_unknown_status() {
    for json_output in [false, true] {
        for state in ["complete", "failed", "error", "unexpected"] {
            let status = state.to_string();
            let peer = Peer::new(vec![
                (
                    "identity.login_start",
                    result(
                        json!({"attempt_id":"attempt","auth_url":"https://idp.example.test/synthetic","expires_in_secs":30}),
                    ),
                ),
                (
                    "identity.login_status",
                    Box::new(move |r| {
                        assert_eq!(r["params"], json!({"attempt_id":"attempt"}));
                        if status == "error" {
                            json!({"id":1,"error":{"code":"fixture_failed","message":"login poll rejected"}})
                        } else {
                            json!({"id":1,"result":{"status":status,"reason":"fixture reason","identity":{"label":"Fixture Human","roles":["auditor"]}}})
                        }
                    }),
                ),
            ]);
            let mut command = peer.command();
            command
                .current_dir(peer._dir.path())
                .args(["login", "--no-browser"]);
            if json_output {
                command.arg("--json");
            }
            let output = run(&mut command);
            assert_exit(
                &output,
                match state {
                    "complete" => 0,
                    "failed" => 4,
                    _ => 3,
                },
            );
            assert_eq!(peer.finish().len(), 2);
            if state == "complete" {
                contains(&output, &["Fixture Human", "auditor"], &["Sign-in failed"]);
            } else if state == "failed" {
                contains(&output, &["fixture reason"], &["Signed in as"]);
            } else if state == "error" {
                contains(&output, &["login poll rejected"], &["Signed in as"]);
            } else {
                contains(&output, &["unexpected login status"], &["Signed in as"]);
            }
            if json_output && state != "unexpected" {
                let value: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert!(value.is_object());
            }
        }
    }
}

fn policy_command(body: &str, args: &[&str]) -> Output {
    let peer = Peer::new(vec![]);
    let file = peer._dir.path().join("policy.toml");
    std::fs::write(&file, body).unwrap();
    let output = run(peer
        .command()
        .current_dir(peer._dir.path())
        .env("OPAQUE_CONFIG", &file)
        .args(args));
    assert!(peer.finish().is_empty());
    output
}

#[test]
fn policy_show_displays_each_client_constraint_and_approval_obligation() {
    let common = "[[rules]]\nname='fixture rule'\noperation_pattern='fixture.*'\nallow=true\nclient_types=['human','agent']\n";
    for (constraint, expected) in [
        ("exe_path='/fixture/agent'", "exe=/fixture/agent"),
        ("exe_sha256='abcdef0123456789'", "sha256=abcdef01"),
        ("codesign_team_id='FIXTURETEAM'", "team=FIXTURETEAM"),
        ("uid=42", "uid=42"),
        ("attestor='local.unix'", "attestor=local.unix"),
        ("min_attestation='medium'", "min_attestation=medium"),
        ("selectors=['unix:uid:42']", "selector=unix:uid:42"),
    ] {
        let output = policy_command(
            &format!("{common}[rules.client]\n{constraint}\n"),
            &["policy", "show"],
        );
        assert_exit(&output, 0);
        contains(
            &output,
            &[
                "ALLOW",
                "fixture rule",
                "fixture.*",
                "human, agent",
                expected,
            ],
            &["DENY"],
        );
    }
    let complete = format!(
        "{common}[rules.client]\nexe_path='/fixture/agent'\nexe_sha256='abcdef0123456789'\ncodesign_team_id='FIXTURETEAM'\nuid=42\nattestor='local.unix'\nmin_attestation='strong'\nselectors=['unix:uid:42']\n[rules.target.fields]\nrepo='org/repo'\n[rules.workspace]\nremote_url_pattern='https://github.com/org/*'\nbranch_pattern='main'\nrequire_clean=true\n[rules.secret_names]\npatterns=['TOKEN_*']\n[rules.approval]\nrequire='first_use'\nfactors=['local_bio']\nlease_ttl=60\none_time=true\nbudget=2\n"
    );
    let output = policy_command(&complete, &["policy", "show"]);
    assert_exit(&output, 0);
    contains(
        &output,
        &[
            "repo=org/repo",
            "remote=https://github.com/org/*",
            "branch=main",
            "clean-only",
            "TOKEN_*",
            "firstuse",
            "LocalBio",
            "lease=60s",
            "one-time",
            "budget=2 total attempts",
        ],
        &[],
    );
    for constraint in ["branch_pattern='main'", "require_clean=true"] {
        let output = policy_command(
            &format!("{common}[rules.workspace]\n{constraint}\n"),
            &["policy", "show"],
        );
        assert_exit(&output, 0);
        contains(&output, &["workspace:"], &[]);
    }
    let output = policy_command(
        "[[rules]]\nname='deny fixture'\noperation_pattern='*'\nallow=false\n",
        &["policy", "show"],
    );
    assert_exit(&output, 0);
    contains(
        &output,
        &["DENY", "deny fixture"],
        &["ALLOW", "clients:", "client:", "workspace:"],
    );
    let output = policy_command("rules=[]\n", &["policy", "show"]);
    assert_exit(&output, 0);
    contains(&output, &["default deny-all"], &["ALLOW"]);
    let output = policy_command("not valid [", &["policy", "show"]);
    assert_exit(&output, 1);
    contains(&output, &["TOML parse error"], &["ALLOW"]);
}

#[test]
fn policy_simulation_reports_matched_denial_default_denial_and_required_approval() {
    let policy = "[[rules]]\nname='explicit-denial'\noperation_pattern='fixture.denied'\nallow=false\n[[rules]]\nname='bounded allow'\noperation_pattern='fixture.allowed'\nallow=true\n[rules.target.fields]\nrepo='org/repo'\n[rules.secret_names]\npatterns=['TOKEN_*']\n[rules.approval]\nrequire='first_use'\nfactors=['local_bio']\nlease_ttl=60\none_time=true\nbudget=2\n";
    let output = policy_command(
        policy,
        &[
            "policy",
            "simulate",
            "--operation",
            "fixture.allowed",
            "--client-type",
            "agent",
            "--target",
            "repo=org/repo",
            "--secret-ref",
            "TOKEN_ONE",
        ],
    );
    assert_exit(&output, 0);
    contains(
        &output,
        &[
            "ALLOW (rule: bounded allow)",
            "agent",
            "repo=org/repo",
            "TOKEN_ONE",
            "LocalBio",
            "60s",
            "one-time:",
            "2 total attempts",
        ],
        &["DENY"],
    );
    let output = policy_command(
        policy,
        &["policy", "simulate", "--operation", "fixture.denied"],
    );
    assert_exit(&output, 0);
    contains(
        &output,
        &["DENY:", "matched rule:", "explicit-denial"],
        &["ALLOW"],
    );
    let output = policy_command(
        policy,
        &["policy", "simulate", "--operation", "fixture.other"],
    );
    assert_exit(&output, 0);
    contains(&output, &["DENY:"], &["matched rule:", "ALLOW"]);
    let output = policy_command(
        policy,
        &[
            "policy",
            "simulate",
            "--operation",
            "fixture.allowed",
            "--client-type",
            "invalid",
        ],
    );
    assert_exit(&output, 1);
    contains(&output, &["unknown client type"], &["ALLOW"]);
    let output = policy_command(
        "invalid [",
        &["policy", "simulate", "--operation", "fixture.allowed"],
    );
    assert_exit(&output, 1);
    contains(&output, &["TOML parse error"], &["ALLOW"]);
}
