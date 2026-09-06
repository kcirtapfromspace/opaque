//! Mock model responses test the real planner protocol, not language-model
//! quality. No paid endpoint, portfolio source or human approval is exercised.
use super::*;
use crate::exploration::Finding;
use crate::portfolio::{Dimension, Measure, View};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn model(server: &MockServer) -> ChatModel {
    ChatModel::new(ModelConfig::OpenaiCompatible {
        base_url: server.uri(),
        model: "synthetic-planning-model".into(),
        allow_loopback_http: true,
    })
    .unwrap()
}

fn completed(content: Value) -> Value {
    json!({"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":content.to_string()}}]})
}

async fn reply(server: &MockServer, body: Value) {
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .expect(1)
        .mount(server)
        .await;
}

fn query() -> Value {
    json!({"view":"summary","window_secs":900,"measures":["application_count"]})
}

fn proposal(queries: Vec<Value>) -> Value {
    json!({"kind":"query","interpretation":"Inspect the last 15 minutes of synthetic portfolio aggregates.","queries":queries})
}

#[tokio::test]
async fn exploration_accepts_model_interpretations_without_keyword_planning() {
    let server = MockServer::start().await;
    let model = model(&server);
    for question in [
        "What stands out?",
        "Where would you focus an operations investigation?",
        "Are we getting bogged down anywhere, and has that shifted?",
        "Help me understand how mobile compares with partner intake.",
    ] {
        server.reset().await;
        let queries = vec![
            json!({"view":"comparison","window_secs":900,"measures":["mean_processing_seconds","manual_review_rate_percent"]}),
            json!({"view":"breakdown","window_secs":900,"measures":["application_count","mean_processing_seconds"],"dimension":"channel"}),
            json!({"view":"trend","window_secs":900,"measures":["mean_processing_seconds"],"filters":{"channel":"mobile"}}),
        ];
        reply(&server, completed(proposal(queries.clone()))).await;
        let ExplorationPlan::Query {
            queries: actual, ..
        } = model
            .plan_exploration(question, &Measure::ALL)
            .await
            .unwrap()
        else {
            panic!("expected query proposal")
        };
        assert_eq!(serde_json::to_value(actual).unwrap(), json!(queries));
        let requests = server.received_requests().await.unwrap();
        let body: Value = requests[0].body_json().unwrap();
        assert_eq!(
            body["messages"].as_array().unwrap().last().unwrap()["content"],
            question
        );
        assert!(body.get("tools").is_none());
        assert_eq!(body["response_format"]["json_schema"]["strict"], true);
        assert_eq!(body["chat_template_kwargs"]["enable_thinking"], false);
        let schema = &body["response_format"]["json_schema"]["schema"]["oneOf"][0];
        assert_eq!(schema["properties"]["queries"]["maxItems"], 4);
        assert_eq!(
            schema["properties"]["queries"]["items"]["oneOf"][0]["properties"]["window_secs"]["enum"],
            json!([900])
        );
        assert_eq!(
            schema["properties"]["queries"]["items"]["oneOf"][0]["properties"]["measures"]["items"]
                ["enum"],
            json!(Measure::ALL)
        );
        assert_eq!(
            schema["properties"]["queries"]["items"]["oneOf"][0]["additionalProperties"],
            false
        );
        let instruction = body["messages"][0]["content"].as_str().unwrap();
        for detail in [
            "SYNTHETIC",
            "six equal time buckets",
            "EACH period length",
            "source computes every number",
            "cannot prove causes",
            "northeast",
            "personal_loan",
        ] {
            assert!(
                instruction.contains(detail),
                "missing schema detail: {detail}"
            );
        }
        assert!(!instruction.contains("server-derived query constraints"));
    }
}

#[tokio::test]
async fn exploration_schema_contains_only_authorized_measures_and_rejects_expansion() {
    let server = MockServer::start().await;
    let model = model(&server);
    let allowed = [Measure::ApplicationCount];
    reply(
        &server,
        completed(proposal(vec![
            json!({"view":"summary","window_secs":900,"measures":["manual_review_rate_percent"]}),
        ])),
    )
    .await;
    assert!(
        model
            .plan_exploration("What deserves attention?", &allowed)
            .await
            .is_err()
    );
    let requests = server.received_requests().await.unwrap();
    let body: Value = requests[0].body_json().unwrap();
    assert_eq!(
        body["response_format"]["json_schema"]["schema"]["oneOf"][0]["properties"]["queries"]["items"]
            ["oneOf"][0]["properties"]["measures"]["items"]["enum"],
        json!(["application_count"])
    );
    assert!(
        !body["messages"][0]["content"]
            .as_str()
            .unwrap()
            .contains("manual_review_rate_percent")
    );
}

#[tokio::test]
async fn exploration_preserves_clarify_and_unsupported_without_substitute_queries() {
    let server = MockServer::start().await;
    let model = model(&server);
    for plan in [
        json!({"kind":"clarify","question":"Do you mean manual reviews or identity mismatches?"}),
        json!({"kind":"unsupported","reason":"This dataset does not contain approval outcomes."}),
    ] {
        server.reset().await;
        reply(&server, completed(plan.clone())).await;
        let result = model
            .plan_exploration("How many were problematic?", &Measure::ALL)
            .await
            .unwrap();
        assert_eq!(serde_json::to_value(result).unwrap(), plan);
    }
}

#[tokio::test]
async fn ordinary_default_window_and_amount_wording_reaches_the_live_interpreter() {
    let server = MockServer::start().await;
    let model = model(&server);
    for question in [
        "Use the default window to show application count",
        "What amount of manual reviews are there?",
    ] {
        server.reset().await;
        reply(&server, completed(proposal(vec![query()]))).await;
        assert!(matches!(
            model
                .plan_exploration(question, &Measure::ALL)
                .await
                .unwrap(),
            ExplorationPlan::Query { .. }
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn undefined_flags_clarify_before_model_but_qualified_flags_retain_the_question() {
    let server = MockServer::start().await;
    let model = model(&server);
    for question in [
        "How many applications were flagged?",
        "What do the flags show?",
        "Show the flag count",
    ] {
        assert!(matches!(
            model
                .plan_exploration(question, &Measure::ALL)
                .await
                .unwrap(),
            ExplorationPlan::Clarify { .. }
        ));
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    for question in [
        "How many applications were flagged for manual review?",
        "Show flags from identity mismatches",
        "Flagged manual_review_count",
        "Count flags sent to manual checks",
    ] {
        server.reset().await;
        reply(&server, completed(proposal(vec![query()]))).await;
        assert!(matches!(
            model
                .plan_exploration(question, &Measure::ALL)
                .await
                .unwrap(),
            ExplorationPlan::Query { .. }
        ));
        let requests = server.received_requests().await.unwrap();
        let body: Value = requests[0].body_json().unwrap();
        assert_eq!(
            body["messages"].as_array().unwrap().last().unwrap()["content"],
            question
        );
    }
}

#[tokio::test]
async fn exploration_denials_and_input_limits_precede_model_io() {
    let server = MockServer::start().await;
    let model = model(&server);
    for question in [
        "Show raw borrower records",
        "Read another customer's data",
        "Show private keys",
        "Delete loan applications",
        "Average credit score?",
        "What changed yesterday?",
        "Applications over 2 minutes",
        "Count over ninety minutes",
        "Show 24h of applications",
        "What changed over 1.5 hours?",
        "Median processing time",
        "P95 processing time",
        "Pending application backlog",
        "Approval rate",
        "Default rates",
    ] {
        assert!(
            matches!(
                model
                    .plan_exploration(question, &Measure::ALL)
                    .await
                    .unwrap_or_else(|error| panic!("{question}: {error}")),
                ExplorationPlan::Unsupported { .. }
            ),
            "{question}"
        );
    }
    assert!(matches!(
        model
            .plan_exploration("What stands out?", &[])
            .await
            .unwrap(),
        ExplorationPlan::Unsupported { .. }
    ));
    for question in [
        "".to_owned(),
        "x".repeat(4097),
        "What\u{202e} stands out?".into(),
    ] {
        assert!(
            model
                .plan_exploration(&question, &Measure::ALL)
                .await
                .is_err()
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn exploration_rejects_excess_budget_unsafe_arguments_and_fields() {
    let server = MockServer::start().await;
    let model = model(&server);
    let mut invalid = vec![
        proposal(vec![]),
        proposal(vec![query(); 5]),
        json!({"kind":"query","interpretation":" ","queries":[query()]}),
        json!({"kind":"query","interpretation":"x".repeat(1025),"queries":[query()]}),
        json!({"kind":"query","interpretation":"pretend\u{202e}result","queries":[query()]}),
        json!({"kind":"clarify","question":"x".repeat(513)}),
        json!({"kind":"unsupported","reason":""}),
        json!({"kind":"write","queries":[query()]}),
    ];
    for (field, value) in [
        ("window_secs", json!(120)),
        ("view", json!("sql")),
        ("dimension", json!("region")),
        (
            "measures",
            json!(["application_count", "application_count"]),
        ),
        ("measures", json!(Measure::ALL)),
        ("filters", json!({"channel":"mobile OR true"})),
        ("filters", json!({"customer_id":"foreign"})),
        ("filters", json!({"region":"x".repeat(3000)})),
        ("filters", json!({"product":"mortgage"})),
    ] {
        let mut bad = query();
        bad[field] = value;
        invalid.push(proposal(vec![bad]));
    }
    invalid.push(proposal(vec![
        json!({"view":"breakdown","window_secs":900,"measures":["application_count"]}),
    ]));
    for field in [
        "tenant_id",
        "source_id",
        "credential",
        "grant",
        "scope",
        "sql",
        "base_url",
    ] {
        let mut bad = query();
        bad[field] = json!("untrusted");
        invalid.push(proposal(vec![bad]));
        let mut bad = proposal(vec![query()]);
        bad[field] = json!("untrusted");
        invalid.push(bad);
    }
    for bad in invalid {
        server.reset().await;
        reply(&server, completed(bad.clone())).await;
        assert!(
            model
                .plan_exploration("Explain the portfolio", &Measure::ALL)
                .await
                .is_err(),
            "accepted {bad}"
        );
    }
}

#[tokio::test]
async fn duplicate_queries_keep_first_operands_and_distinct_views_in_original_order() {
    let server = MockServer::start().await;
    let model = model(&server);
    let comparison = json!({"view":"comparison","window_secs":900,"measures":["mean_processing_seconds","application_count","manual_review_rate_percent","identity_mismatch_rate_percent"]});
    let trend = json!({"view":"trend","window_secs":900,"measures":["mean_processing_seconds","application_count","manual_review_rate_percent","identity_mismatch_rate_percent"]});
    let mut repeated = comparison.clone();
    repeated["measures"].as_array_mut().unwrap().reverse();
    let breakdown = json!({"view":"breakdown","dimension":"channel","window_secs":900,"measures":["mean_processing_seconds","application_count","manual_review_rate_percent","identity_mismatch_rate_percent"]});
    let original = proposal(vec![
        comparison.clone(),
        trend.clone(),
        repeated,
        breakdown.clone(),
    ]);
    reply(&server, completed(original.clone())).await;
    let result = serde_json::to_value(
        model
            .plan_exploration("What stands out in our portfolio?", &Measure::ALL)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(result["interpretation"], original["interpretation"]);
    assert_eq!(result["queries"], json!([comparison, trend, breakdown]));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn deduplication_does_not_hide_invalid_queries_or_weaken_request_constraints() {
    let server = MockServer::start().await;
    let model = model(&server);
    let invalid_measure = json!({"view":"summary","window_secs":900,"measures":["application_count","application_count"]});
    let unauthorized =
        json!({"view":"summary","window_secs":900,"measures":["manual_review_rate_percent"]});
    for invalid in [
        vec![query(); 5],
        vec![query(), query(), invalid_measure.clone(), invalid_measure],
        vec![query(), query(), unauthorized.clone(), unauthorized],
    ] {
        server.reset().await;
        reply(&server, completed(proposal(invalid))).await;
        assert!(
            model
                .plan_exploration("Show application count", &[Measure::ApplicationCount])
                .await
                .is_err()
        );
    }
    for (question, query) in [
        (
            "How are application counts moving over time?",
            json!({"view":"breakdown","dimension":"region","window_secs":900,"measures":["application_count"]}),
        ),
        (
            "Compare counts for mobile and partner",
            json!({"view":"summary","window_secs":900,"measures":["application_count"],"filters":{"channel":"mobile"}}),
        ),
    ] {
        server.reset().await;
        reply(&server, completed(proposal(vec![query.clone(), query]))).await;
        assert!(
            model
                .plan_exploration(question, &Measure::ALL)
                .await
                .is_err()
        );
    }
    server.reset().await;
    let mobile = json!({"view":"summary","window_secs":900,"measures":["application_count"],"filters":{"channel":"mobile"}});
    let partner = json!({"view":"summary","window_secs":900,"measures":["application_count"],"filters":{"channel":"partner"}});
    reply(
        &server,
        completed(proposal(vec![
            mobile.clone(),
            mobile.clone(),
            partner.clone(),
            partner.clone(),
        ])),
    )
    .await;
    let result = model
        .plan_exploration("Compare counts for mobile and partner", &Measure::ALL)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(result).unwrap()["queries"],
        json!([mobile, partner])
    );
}

#[tokio::test]
async fn exploration_rejects_non_json_truncation_extra_calls_and_large_payloads() {
    let server = MockServer::start().await;
    let model = model(&server);
    let valid = completed(proposal(vec![query()]));
    let mut invalid = Vec::new();
    for text in [
        "Here is your answer".to_owned(),
        "{}".into(),
        format!("{}{}", proposal(vec![query()]), " ".repeat(8192)),
        "{\"kind\":\"clarify\",\"question\":\"one\",\"question\":\"two\"}".into(),
    ] {
        let mut bad = valid.clone();
        bad["choices"][0]["message"]["content"] = json!(text);
        invalid.push(bad);
    }
    let mut bad = valid.clone();
    bad["choices"][0]["finish_reason"] = json!("length");
    invalid.push(bad);
    let mut bad = valid.clone();
    bad["choices"][0]["message"]["tool_calls"] = json!([{"type":"function"}]);
    invalid.push(bad);
    let mut bad = valid.clone();
    bad["choices"][0]["truncated"] = json!(true);
    invalid.push(bad);
    let mut bad = valid.clone();
    bad["choices"]
        .as_array_mut()
        .unwrap()
        .push(valid["choices"][0].clone());
    invalid.push(bad);
    for response in invalid {
        server.reset().await;
        reply(&server, response).await;
        assert!(
            model
                .plan_exploration("Explain the portfolio", &Measure::ALL)
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn broad_fixture_is_reproducible_labeled_and_never_drops_extra_filters() {
    let model = ChatModel::new(ModelConfig::Fixture).unwrap();
    for question in [
        "What stands out?",
        "What changed?",
        "What has changed?",
        "Where should I investigate?",
        "What should I investigate?",
    ] {
        let ExplorationPlan::Query {
            interpretation,
            queries,
        } = model
            .plan_exploration(question, &Measure::ALL)
            .await
            .unwrap()
        else {
            panic!("expected deterministic fixture")
        };
        assert!(interpretation.contains("no language model"));
        assert_eq!(queries.len(), 3);
        assert_eq!(queries[0].view, View::Comparison);
        assert_eq!(queries[1].view, View::Trend);
        assert_eq!(queries[2].dimension, Some(Dimension::Channel));
        assert!(queries.iter().all(|query| query.window_secs == 900));
    }
    assert!(matches!(
        model
            .plan_exploration(
                "What stands out in the West over 30 minutes?",
                &Measure::ALL
            )
            .await
            .unwrap(),
        ExplorationPlan::Clarify { .. }
    ));
    let ExplorationPlan::Query { queries, .. } = model
        .plan_exploration(
            "Show mobile manual review rates over 15 minutes",
            &Measure::ALL,
        )
        .await
        .unwrap()
    else {
        panic!("expected existing targeted fixture")
    };
    assert_eq!(queries[0].filters.channel.as_deref(), Some("mobile"));
}

fn findings() -> Vec<Finding> {
    vec![Finding { id:"q1:application_count".into(), evidence_id:"evidence-one".into(), text:"Synthetic source computed 120 applications over 15 minutes from 120 samples.".into() },
         Finding { id:"q2:manual_review_rate_percent".into(), evidence_id:"evidence-two".into(), text:"Synthetic source computed a manual review rate of 5.00 % over 15 minutes from 120 samples.".into() }]
}

#[tokio::test]
async fn finding_selection_returns_only_known_ids_and_preserves_computed_text_in_context() {
    let server = MockServer::start().await;
    let model = model(&server);
    let facts = findings();
    reply(&server, completed(json!({"finding_ids":[facts[1].id]}))).await;
    let result = model
        .select_findings("Where is review work concentrated?", &facts)
        .await
        .unwrap();
    assert_eq!(result, [facts[1].id.clone()]);
    let requests = server.received_requests().await.unwrap();
    let body: Value = requests[0].body_json().unwrap();
    let context = body["messages"][2]["content"].as_str().unwrap();
    let encoded: Value = serde_json::from_str(
        context
            .strip_prefix("Authorized source-computed findings:\n")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        encoded,
        json!(
            facts
                .iter()
                .map(|fact| json!({"id":fact.id,"text":fact.text}))
                .collect::<Vec<_>>()
        )
    );
    assert_eq!(
        body["response_format"]["json_schema"]["schema"]["properties"]["finding_ids"]["maxItems"],
        8
    );
    let fixture = ChatModel::new(ModelConfig::Fixture).unwrap();
    assert_eq!(
        fixture
            .select_findings("What stands out?", &facts)
            .await
            .unwrap(),
        facts.iter().map(|fact| fact.id.clone()).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn finding_selection_rejects_unknown_evidence_ids_duplicates_and_generated_answers() {
    let server = MockServer::start().await;
    let model = model(&server);
    let facts = findings();
    for selected in [
        json!([]),
        json!(["made-up:9000"]),
        json!([facts[0].evidence_id]),
        json!([facts[0].id, facts[0].id]),
        json!(vec![facts[0].id.clone(); 9]),
    ] {
        server.reset().await;
        reply(&server, completed(json!({"finding_ids":selected}))).await;
        assert!(
            model
                .select_findings("What stands out?", &facts)
                .await
                .is_err()
        );
    }
    server.reset().await;
    reply(
        &server,
        completed(json!({"finding_ids":[facts[0].id],"answer":"Fraud doubled to 9999."})),
    )
    .await;
    assert!(
        model
            .select_findings("What stands out?", &facts)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn finding_input_budget_and_duplicate_ids_precede_model_io() {
    let server = MockServer::start().await;
    let model = model(&server);
    let facts = findings();
    for invalid in [
        vec![],
        vec![facts[0].clone(); 129],
        vec![facts[0].clone(), facts[0].clone()],
    ] {
        assert!(
            model
                .select_findings("What stands out?", &invalid)
                .await
                .is_err()
        );
    }
    let mut invalid = facts.clone();
    invalid[0].text = "x".repeat(2049);
    assert!(
        model
            .select_findings("What stands out?", &invalid)
            .await
            .is_err()
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[test]
fn finding_context_compaction_is_lossless_including_units_filters_and_samples() {
    let mut facts = findings();
    let suffix = " Window: 15 minutes versus the preceding equal period. Filters: channel=Mobile. Samples: Current 120; Previous 100.";
    for fact in &mut facts {
        fact.text.push_str(suffix);
    }
    let context = finding_selection_context(&facts);
    assert_eq!(context["contexts"].as_array().unwrap().len(), 1);
    for (original, compact) in facts.iter().zip(context["findings"].as_array().unwrap()) {
        let shared = context["contexts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|value| value["id"] == compact["context_id"])
            .unwrap();
        assert_eq!(compact["id"], original.id);
        assert_eq!(
            format!(
                "{} {}",
                compact["text"].as_str().unwrap(),
                shared["text"].as_str().unwrap()
            ),
            original.text
        );
        assert!(compact.get("evidence_id").is_none());
    }
    assert_eq!(facts[0].evidence_id, "evidence-one");
}

#[test]
fn exploration_schema_forbids_dimension_except_required_breakdown_dimension() {
    let schema = exploration_schema(
        &Measure::ALL,
        &ExplorationConstraints::resolve("What stands out?").unwrap(),
    );
    let branches = schema["oneOf"][0]["properties"]["queries"]["items"]["oneOf"]
        .as_array()
        .unwrap();
    assert_eq!(branches.len(), 2);
    assert_eq!(
        branches[0]["properties"]["view"]["enum"],
        json!(["summary", "trend", "comparison"])
    );
    assert!(branches[0]["properties"].get("dimension").is_none());
    assert_eq!(branches[0]["additionalProperties"], false);
    assert_eq!(
        branches[1]["properties"]["view"]["enum"],
        json!(["breakdown"])
    );
    assert!(
        branches[1]["required"]
            .as_array()
            .unwrap()
            .contains(&json!("dimension"))
    );
    assert_eq!(
        branches[1]["properties"]["dimension"]["enum"],
        json!(["channel", "region", "product"])
    );
    for branch in branches {
        assert_eq!(
            branch["properties"]["measures"]["items"]["enum"],
            json!(Measure::ALL)
        );
        assert_eq!(
            branch["properties"]["filters"]["additionalProperties"],
            false
        );
        assert_eq!(
            branch["properties"]["filters"]["properties"]["channel"]["enum"],
            json!(["web", "mobile", "partner"])
        );
    }
}

#[test]
fn explicit_windows_preserve_units_aliases_lists_and_default() {
    for (question, expected) in [
        ("What stands out?", vec![900]),
        (
            "Which region is quickest in the last five minutes?",
            vec![300],
        ),
        ("Counts from the past hour", vec![3600]),
        ("Changes over the last half-hour", vec![1800]),
        ("Changes over half an hour", vec![1800]),
        ("Changes over a half hour", vec![1800]),
        ("Compare one hour to five minutes", vec![300, 3600]),
        ("Compare 5 and 15 minutes", vec![300, 900]),
        ("Trend for 300s", vec![300]),
        ("Past minute", vec![60]),
    ] {
        assert_eq!(
            exploration_windows(question).unwrap(),
            expected,
            "{question}"
        );
    }
    for question in [
        "Last two minutes",
        "1.5 hours",
        "hour and a half",
        "one and a half hours",
        "two and a half hour",
        "sixty five minutes",
        "half minute",
        "ninety minutes",
        "7 and 15 minutes",
        "yesterday",
        "24h",
    ] {
        assert!(exploration_windows(question).is_err(), "{question}");
    }
}

#[test]
fn explicit_filters_bind_unique_scoped_entities_without_collapsing_pairs() {
    for (question, expected) in [
        (
            "How many for partner submissions in the past hour?",
            json!({"channel":"partner"}),
        ),
        ("Manual checks on the website", json!({"channel":"web"})),
        ("Rates from our phone app", json!({"channel":"mobile"})),
        (
            "Review shares for auto loans in West",
            json!({"region":"west","product":"auto_loan"}),
        ),
        (
            "Rates for mobile credit-card applications",
            json!({"channel":"mobile","product":"credit_card"}),
        ),
        (
            "Compare processing in West with the rest of the portfolio",
            json!({}),
        ),
        (
            "For partner, are reviews higher than the overall rate?",
            json!({}),
        ),
        (
            "For partner show total counts",
            json!({"channel":"partner"}),
        ),
        (
            "Counts among credit-card applications in the Midwest",
            json!({"region":"midwest","product":"credit_card"}),
        ),
        ("Compare mobile and partner", json!({})),
        ("For mobile versus partner, compare processing", json!({})),
        ("Compare Southeast and Midwest", json!({})),
        (
            "For partner, compare Southeast and Midwest",
            json!({"channel":"partner"}),
        ),
        (
            "In West, compare mobile and partner",
            json!({"region":"west"}),
        ),
        ("Counts for Chicago", json!({})),
        ("Counts from all channels except mobile", json!({})),
        ("Counts for mobile or West", json!({})),
    ] {
        let constraints = ExplorationConstraints::resolve(question).unwrap();
        assert_eq!(
            serde_json::to_value(&constraints.filters).unwrap(),
            expected,
            "{question}"
        );
    }
    let pair =
        ExplorationConstraints::resolve("For partner, compare Southeast and Midwest").unwrap();
    assert_eq!(
        serde_json::to_value(pair.named_filter_values).unwrap(),
        json!({"channel":["partner"],"region":["southeast","midwest"]})
    );
}

#[tokio::test]
async fn live_proposals_must_preserve_resolved_windows_and_filters_without_rewriting() {
    let server = MockServer::start().await;
    let model = model(&server);
    for (question, expected) in [
        (
            "Count applications for partner submissions in the past hour",
            json!({"view":"summary","window_secs":3600,"measures":["application_count"],"filters":{"channel":"partner"}}),
        ),
        (
            "Which region is quickest in the last five minutes?",
            json!({"view":"breakdown","dimension":"region","window_secs":300,"measures":["mean_processing_seconds"]}),
        ),
        (
            "What share required manual review for auto loans in West in the last half hour?",
            json!({"view":"summary","window_secs":1800,"measures":["manual_review_rate_percent"],"filters":{"region":"west","product":"auto_loan"}}),
        ),
    ] {
        server.reset().await;
        reply(&server, completed(proposal(vec![expected.clone()]))).await;
        let plan = model
            .plan_exploration(question, &Measure::ALL)
            .await
            .unwrap();
        assert_eq!(serde_json::to_value(plan).unwrap()["queries"][0], expected);
        let body: Value = server.received_requests().await.unwrap()[0]
            .body_json()
            .unwrap();
        for branch in body["response_format"]["json_schema"]["schema"]["oneOf"][0]["properties"]["queries"]["items"]["oneOf"].as_array().unwrap() {
            assert_eq!(branch["properties"]["window_secs"]["enum"], json!([expected["window_secs"]]));
            if let Some(filters) = expected.get("filters").and_then(Value::as_object) {
                assert!(branch["required"].as_array().unwrap().contains(&json!("filters")));
                for (dimension, value) in filters {
                    assert_eq!(branch["properties"]["filters"]["properties"][dimension]["enum"], json!([value]));
                    assert!(branch["properties"]["filters"]["required"].as_array().unwrap().contains(&json!(dimension)));
                }
            }
        }
    }
    for (question, invalid) in [
        (
            "Count for partner in the past hour",
            json!({"view":"summary","window_secs":3600,"measures":["application_count"]}),
        ),
        (
            "Count for partner in the past hour",
            json!({"view":"summary","window_secs":900,"measures":["application_count"],"filters":{"channel":"partner"}}),
        ),
        (
            "Count for partner in the past hour",
            json!({"view":"summary","window_secs":3600,"measures":["application_count"],"filters":{"channel":"mobile"}}),
        ),
        (
            "Count for auto loans in West",
            json!({"view":"summary","window_secs":900,"measures":["application_count"],"filters":{"region":"west","product":"auto_loan","channel":"web"}}),
        ),
        (
            "What stands out?",
            json!({"view":"summary","window_secs":60,"measures":["application_count"]}),
        ),
    ] {
        server.reset().await;
        reply(&server, completed(proposal(vec![invalid]))).await;
        assert!(
            model
                .plan_exploration(question, &Measure::ALL)
                .await
                .unwrap_err()
                .contains("did not preserve"),
            "{question}"
        );
    }
}

#[tokio::test]
async fn named_pairs_remain_model_choices_and_scoped_unknowns_cannot_escape_schema() {
    let server = MockServer::start().await;
    let model = model(&server);
    let question = "For partner, compare Southeast and Midwest";
    let queries = vec![
        json!({"view":"summary","window_secs":900,"measures":["application_count"],"filters":{"channel":"partner","region":"southeast"}}),
        json!({"view":"summary","window_secs":900,"measures":["application_count"],"filters":{"channel":"partner","region":"midwest"}}),
        json!({"view":"breakdown","dimension":"region","window_secs":900,"measures":["application_count"],"filters":{"channel":"partner"}}),
    ];
    reply(&server, completed(proposal(queries.clone()))).await;
    let actual = model
        .plan_exploration(question, &Measure::ALL)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(actual).unwrap()["queries"],
        json!(queries)
    );
    let body: Value = server.received_requests().await.unwrap()[0]
        .body_json()
        .unwrap();
    let properties = &body["response_format"]["json_schema"]["schema"]["oneOf"][0]["properties"]["queries"]
        ["items"]["oneOf"][0]["properties"]["filters"]["properties"];
    assert_eq!(
        properties["region"]["enum"],
        json!(["southeast", "midwest"])
    );
    assert!(properties.get("product").is_none());
    for (question, allowed, invalid) in [
        (
            question,
            Measure::ALL.to_vec(),
            json!({"view":"summary","window_secs":900,"measures":["application_count"],"filters":{"channel":"partner","region":"west"}}),
        ),
        (
            "Count applications for Chicago",
            Measure::ALL.to_vec(),
            json!({"view":"summary","window_secs":900,"measures":["application_count"],"filters":{"region":"chicago"}}),
        ),
        (
            "Review rates for partner",
            vec![Measure::ApplicationCount],
            json!({"view":"summary","window_secs":900,"measures":["manual_review_rate_percent"],"filters":{"channel":"partner"}}),
        ),
    ] {
        server.reset().await;
        reply(&server, completed(proposal(vec![invalid]))).await;
        assert!(model.plan_exploration(question, &allowed).await.is_err());
    }
}

#[tokio::test]
async fn explicit_benchmark_comparisons_allow_both_segment_and_unfiltered_queries() {
    let server = MockServer::start().await;
    let model = model(&server);
    let question = "For partner, are reviews higher than the overall rate?";
    let queries = vec![
        json!({"view":"summary","window_secs":900,"measures":["manual_review_rate_percent"],"filters":{"channel":"partner"}}),
        json!({"view":"summary","window_secs":900,"measures":["manual_review_rate_percent"]}),
    ];
    reply(&server, completed(proposal(queries.clone()))).await;
    assert_eq!(
        serde_json::to_value(
            model
                .plan_exploration(question, &Measure::ALL)
                .await
                .unwrap()
        )
        .unwrap()["queries"],
        json!(queries)
    );
    let body: Value = server.received_requests().await.unwrap()[0]
        .body_json()
        .unwrap();
    let branch = &body["response_format"]["json_schema"]["schema"]["oneOf"][0]["properties"]["queries"]
        ["items"]["oneOf"][0];
    assert!(
        !branch["required"]
            .as_array()
            .unwrap()
            .contains(&json!("filters"))
    );
    assert_eq!(
        branch["properties"]["filters"]["properties"]["channel"]["enum"],
        json!(["partner"])
    );
}

#[tokio::test]
async fn named_category_pairs_restrict_optional_filters_even_without_a_required_segment() {
    let server = MockServer::start().await;
    let model = model(&server);
    for (question, dimension, values, wrong, window) in [
        (
            "Compare identity-mismatch percentages in the Southeast and Midwest during the last minute.",
            "region",
            ["southeast", "midwest"],
            "northeast",
            60,
        ),
        (
            "Compare identity mismatch rates across South East and Mid West",
            "region",
            ["southeast", "midwest"],
            "west",
            900,
        ),
        (
            "How does manual review differ between phone and partner applications?",
            "channel",
            ["mobile", "partner"],
            "web",
            900,
        ),
        (
            "Compare processing for credit cards or auto loans",
            "product",
            ["credit_card", "auto_loan"],
            "personal_loan",
            900,
        ),
    ] {
        for queries in [
            vec![json!({"view":"breakdown","dimension":dimension,"window_secs":window,"measures":["identity_mismatch_rate_percent"]})],
            values.iter().map(|value| json!({"view":"summary","window_secs":window,"measures":["identity_mismatch_rate_percent"],"filters":{dimension:value}})).collect(),
        ] {
            server.reset().await;
            reply(&server, completed(proposal(queries.clone()))).await;
            let plan = model
                .plan_exploration(question, &Measure::ALL)
                .await
                .unwrap();
            let actual = serde_json::to_value(plan).unwrap();
            assert_eq!(actual["queries"], json!(queries));
            let body: Value = server.received_requests().await.unwrap()[0]
                .body_json()
                .unwrap();
            for branch in body["response_format"]["json_schema"]["schema"]["oneOf"][0]["properties"]
                ["queries"]["items"]["oneOf"]
                .as_array()
                .unwrap()
            {
                if branch["properties"]["view"]["enum"] == json!(["breakdown"])
                    && branch["properties"]["dimension"]["enum"] == json!([dimension]) {
                    assert!(branch["properties"]["filters"]["properties"].get(dimension).is_none());
                } else {
                    assert_eq!(branch["properties"]["filters"]["properties"][dimension]["enum"], json!(values));
                }
                assert!(
                    !branch["required"]
                        .as_array()
                        .unwrap()
                        .contains(&json!("filters"))
                );
            }
        }
        for invalid in [
            vec![
                json!({"view":"breakdown","dimension":dimension,"window_secs":window,"measures":["identity_mismatch_rate_percent"],"filters":{dimension:wrong}}),
            ],
            vec![
                json!({"view":"breakdown","dimension":dimension,"window_secs":window,"measures":["identity_mismatch_rate_percent"],"filters":{dimension:values[0]}}),
            ],
            vec![
                json!({"view":"summary","window_secs":window,"measures":["identity_mismatch_rate_percent"],"filters":{dimension:values[0]}}),
            ],
            vec![
                json!({"view":"summary","window_secs":window,"measures":["identity_mismatch_rate_percent"],"filters":{dimension:values[0]}}),
                json!({"view":"summary","window_secs":window,"measures":["application_count"],"filters":{dimension:values[1]}}),
            ],
        ] {
            server.reset().await;
            reply(&server, completed(proposal(invalid))).await;
            assert!(
                model
                    .plan_exploration(question, &Measure::ALL)
                    .await
                    .is_err(),
                "{question}"
            );
        }
    }
}

#[tokio::test]
async fn comparison_coverage_retains_other_filters_and_rejects_incomparable_participants() {
    let server = MockServer::start().await;
    let model = model(&server);
    let question = "For partner, compare Southeast and Midwest over 5 and 15 minutes";
    let grouped = json!({"view":"breakdown","dimension":"region","window_secs":300,"measures":["manual_review_rate_percent"],"filters":{"channel":"partner"}});
    reply(&server, completed(proposal(vec![grouped.clone()]))).await;
    assert_eq!(
        serde_json::to_value(
            model
                .plan_exploration(question, &Measure::ALL)
                .await
                .unwrap()
        )
        .unwrap()["queries"],
        json!([grouped])
    );
    let body: Value = server.received_requests().await.unwrap()[0]
        .body_json()
        .unwrap();
    let branches = body["response_format"]["json_schema"]["schema"]["oneOf"][0]["properties"]["queries"]["items"]["oneOf"].as_array().unwrap();
    let region = branches
        .iter()
        .find(|branch| branch["properties"]["dimension"]["enum"] == json!(["region"]))
        .unwrap();
    assert!(
        region["properties"]["filters"]["properties"]
            .get("region")
            .is_none()
    );
    assert_eq!(
        region["properties"]["filters"]["properties"]["channel"]["enum"],
        json!(["partner"])
    );
    assert_eq!(
        region["properties"]["filters"]["required"],
        json!(["channel"])
    );
    server.reset().await;
    reply(&server, completed(proposal(vec![
        json!({"view":"summary","window_secs":300,"measures":["manual_review_rate_percent"],"filters":{"channel":"partner","region":"southeast"}}),
        json!({"view":"summary","window_secs":900,"measures":["manual_review_rate_percent"],"filters":{"channel":"partner","region":"midwest"}}),
    ]))).await;
    assert!(
        model
            .plan_exploration(question, &Measure::ALL)
            .await
            .unwrap_err()
            .contains("comparable evidence")
    );

    // A common measure can be compared even when one participant also has an
    // extra contextual measure; exact measure-array equality is not required.
    server.reset().await;
    reply(&server, completed(proposal(vec![
        json!({"view":"summary","window_secs":300,"measures":["manual_review_rate_percent","application_count"],"filters":{"channel":"partner","region":"southeast"}}),
        json!({"view":"summary","window_secs":300,"measures":["manual_review_rate_percent"],"filters":{"channel":"partner","region":"midwest"}}),
    ]))).await;
    assert!(
        model
            .plan_exploration(question, &Measure::ALL)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn joint_counts_are_unavailable_but_separate_counts_still_reach_the_model() {
    let server = MockServer::start().await;
    let model = model(&server);
    for question in [
        "How many applications had both manual review and identity mismatch?",
        "Count applications with both manual checks and identity mismatches",
        "Show the overlap of manual review and identity mismatch",
    ] {
        assert!(matches!(
            model
                .plan_exploration(question, &Measure::ALL)
                .await
                .unwrap(),
            ExplorationPlan::Unsupported { .. }
        ));
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    reply(&server, completed(proposal(vec![json!({"view":"summary","window_secs":900,"measures":["manual_review_count","identity_mismatch_count"]})]))).await;
    assert!(matches!(
        model
            .plan_exploration(
                "Show both manual review and identity mismatch counts side by side",
                &Measure::ALL
            )
            .await
            .unwrap(),
        ExplorationPlan::Query { .. }
    ));
}

#[test]
fn temporal_contract_is_literal_and_preserves_category_and_object_contexts() {
    for question in [
        "How has the percentage of applications with identity mismatches been moving over the last fifteen minutes?",
        "How are identity mismatch rates moving over time?",
        "Show the trajectory of the identity mismatch percentage across the recent window",
        "Has the share of identity mismatches gone up or down over the observation period?",
        "Show manual review rate trends",
        "Trace mean processing time as a time series",
        "Show the application count trend rather than breakdown",
        "\"How are identity mismatch rates moving over time?\"",
        "Original question:\nWhat do flags show?\n\nUser clarification 1:\nIdentity mismatch rates moving over time",
    ] {
        assert_eq!(
            exploration_temporal_views(question).unwrap(),
            Some(vec![View::Trend, View::Comparison]),
            "{question}"
        );
    }
    for question in [
        "What stands out in our portfolio?",
        "Compare mobile and partner manual review percentages",
        "Which lending product takes longest on average?",
        "Compare identity-mismatch percentages in the Southeast and Midwest during the last minute.",
        "What does the word trend mean?",
        "Define trajectory",
        "Show the field named Trend",
        "Read the Trend column",
        "Compare application counts by region, not trend",
        "Compare application counts by region rather than trend",
        "Compare application counts by region, no trend over time",
    ] {
        assert_eq!(
            exploration_temporal_views(question).unwrap(),
            None,
            "{question}"
        );
    }
}

#[tokio::test]
async fn temporal_views_are_constrained_in_schema_and_verified_before_any_source_query() {
    let server = MockServer::start().await;
    let model = model(&server);
    let question =
        "How has the identity mismatch percentage been moving over the last fifteen minutes?";
    for view in ["trend", "comparison"] {
        server.reset().await;
        let expected =
            json!({"view":view,"window_secs":900,"measures":["identity_mismatch_rate_percent"]});
        reply(&server, completed(proposal(vec![expected.clone()]))).await;
        assert_eq!(
            serde_json::to_value(
                model
                    .plan_exploration(question, &[Measure::IdentityMismatchRatePercent])
                    .await
                    .unwrap()
            )
            .unwrap()["queries"],
            json!([expected])
        );
        let body: Value = server.received_requests().await.unwrap()[0]
            .body_json()
            .unwrap();
        let branches = body["response_format"]["json_schema"]["schema"]["oneOf"][0]["properties"]["queries"]["items"]["oneOf"].as_array().unwrap();
        assert_eq!(branches.len(), 1);
        assert_eq!(
            branches[0]["properties"]["view"]["enum"],
            json!(["trend", "comparison"])
        );
        assert!(branches[0]["properties"].get("dimension").is_none());
        assert_eq!(
            branches[0]["properties"]["measures"]["items"]["enum"],
            json!(["identity_mismatch_rate_percent"])
        );
        let prompt = body["messages"][0]["content"].as_str().unwrap();
        assert!(prompt.contains("\"allowed_views\":[\"trend\",\"comparison\"]"));
        assert!(!prompt.contains("\"view\":\"breakdown\""));
        assert!(!prompt.contains("\"view\":\"summary\""));
    }
    for invalid in [
        vec![
            json!({"view":"breakdown","dimension":"region","window_secs":900,"measures":["identity_mismatch_rate_percent"]}),
        ],
        vec![
            json!({"view":"summary","window_secs":900,"measures":["identity_mismatch_rate_percent"]}),
        ],
        vec![
            json!({"view":"trend","window_secs":900,"measures":["identity_mismatch_rate_percent"]}),
            json!({"view":"breakdown","dimension":"channel","window_secs":900,"measures":["identity_mismatch_rate_percent"]}),
        ],
        vec![json!({"view":"trend","window_secs":900,"measures":["application_count"]})],
    ] {
        server.reset().await;
        reply(&server, completed(proposal(invalid))).await;
        assert!(
            model
                .plan_exploration(question, &[Measure::IdentityMismatchRatePercent])
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn mixed_temporal_category_requests_have_explicit_workflow_limit_without_clarification_loop()
{
    let server = MockServer::start().await;
    let model = model(&server);
    for question in [
        "Show the review rate trend by region",
        "Show manual review movement over time and which product is slowest",
        "Show identity mismatch trends and channel breakdown",
        "Original question:\nShow flags by region\n\nUser clarification 1:\nIdentity mismatch trend",
    ] {
        let result = model
            .plan_exploration(question, &Measure::ALL)
            .await
            .unwrap();
        let ExplorationPlan::Unsupported { reason } = result else {
            panic!("{question}: expected workflow limit");
        };
        assert!(reason.contains("workflow"));
        assert!(reason.contains("Both views are available separately"));
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    reply(
        &server,
        completed(proposal(vec![
            json!({"view":"trend","window_secs":900,"measures":["identity_mismatch_rate_percent"]}),
        ])),
    )
    .await;
    assert!(matches!(model.plan_exploration("Original question:\nWhat do flags show?\n\nUser clarification 1:\nIdentity mismatch rates moving over time", &Measure::ALL).await.unwrap(), ExplorationPlan::Query {..}));
}
