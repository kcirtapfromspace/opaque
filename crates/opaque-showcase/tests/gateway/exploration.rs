//! Open-ended planning is a proposal, never a source or answer authority.
use super::*;

pub(super) async fn model_plan(fixture: &Fixture, plan: Value, selection: Option<Value>) {
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(move |request: &wiremock::Request| {
            let request: Value = request.body_json().unwrap();
            let content = match request.pointer("/response_format/json_schema/name").and_then(Value::as_str) {
                Some("portfolio_exploration") => plan.clone(),
                Some("portfolio_findings") => selection.clone().unwrap_or_else(|| {
                    let ids = request.pointer("/response_format/json_schema/schema/properties/finding_ids/items/enum").and_then(Value::as_array).expect("selection schema names only computed facts");
                    json!({"finding_ids":ids.iter().take(8).collect::<Vec<_>>()})
                }),
                other => panic!("unexpected model request: {other:?}"),
            };
            ResponseTemplate::new(200).set_body_json(json!({"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":content.to_string()}}]}))
        })
        .mount(&fixture.model)
        .await;
}

fn query(view: &str, measure: &str) -> Value {
    json!({"view":view,"window_secs":900,"measures":[measure]})
}

fn investigative_plan() -> Value {
    json!({"kind":"query","interpretation":"Inspect the last 15 minutes and the preceding equal period, then compare channels; these aggregates do not establish causes.","queries":[
        query("comparison","manual_review_rate_percent"),
        {"view":"breakdown","window_secs":900,"measures":["manual_review_count"],"dimension":"channel"},
        query("trend","mean_processing_seconds")
    ]})
}

fn values(events: &str, kind: &str) -> Vec<Value> {
    let name = format!("event: {kind}");
    events
        .split("\n\n")
        .filter(|frame| frame.lines().any(|line| line == name))
        .map(|frame| {
            serde_json::from_str(
                frame
                    .lines()
                    .find_map(|line| line.strip_prefix("data: "))
                    .unwrap(),
            )
            .unwrap()
        })
        .collect()
}

async fn wait_for_first_read(fixture: &Fixture) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture.source.received_requests().await.unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn natural_paraphrases_use_live_proposals_and_multiple_authorized_reads() {
    for question in [
        "Give me a feel for where the process is getting sticky.",
        "Anything in the recent mix deserve a closer look?",
        "Help me decide where to dig into this portfolio first.",
    ] {
        let fixture = Fixture::portfolio(true, false).await;
        portfolio_source(&fixture, Duration::ZERO).await;
        let plan = investigative_plan();
        model_plan(&fixture, plan.clone(), None).await;
        let token = credit_token(&fixture);
        let cookie = fixture.login(&token).await;
        let events = chat_events(&fixture, &cookie, question).await;
        let results = values(&events, "portfolio_result");
        assert_eq!(results.len(), 3, "{events}");
        assert_eq!(event_value(&events, "interpretation")["query_count"], 3);
        let reads = fixture.source.received_requests().await.unwrap();
        assert_eq!(reads.len(), 3);
        for (index, read) in reads.iter().enumerate() {
            assert_eq!(read.url.path(), "/v1/portfolio/query");
            assert_eq!(read.body_json::<Value>().unwrap(), plan["queries"][index]);
            assert_eq!(read.headers["authorization"], "Bearer opaque-showcase");
            assert_eq!(results[index]["coverage"], "complete");
            assert_eq!(results[index]["partial"], true);
        }
        let requests = fixture.model.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        let planning = requests[0].body_json::<Value>().unwrap();
        assert_eq!(planning["messages"][1]["content"], question);
        let answer_event = event_value(&events, "answer");
        assert_eq!(answer_event["kind"], "grounded");
        assert_eq!(answer_event["summary_mode"], "model_selected_evidence");
        assert_eq!(answer_event["findings"].as_array().unwrap().len(), 3);
        let answer = answer_event["text"].as_str().unwrap().to_owned();
        assert!(
            answer.contains("Partner has the highest manual reviews: 30 applications"),
            "{answer}"
        );
        assert!(answer.contains("do not establish causes"));
        assert!(!events.contains(&token));
        assert!(!String::from_utf8_lossy(&requests[1].body).contains(&token));
    }
}

#[tokio::test]
async fn deterministic_broad_scenarios_read_comparison_trend_and_breakdown() {
    let fixture = Fixture::portfolio(false, false).await;
    portfolio_source(&fixture, Duration::ZERO).await;
    let cookie = fixture.login(&credit_token(&fixture)).await;
    for question in [
        "What stands out?",
        "What changed?",
        "Where should I investigate?",
    ] {
        let before = fixture.source.received_requests().await.unwrap().len();
        let events = chat_events(&fixture, &cookie, question).await;
        assert_eq!(values(&events, "portfolio_result").len(), 3, "{events}");
        let reads = fixture.source.received_requests().await.unwrap();
        assert_eq!(reads.len() - before, 3);
        let views = reads[before..]
            .iter()
            .map(|read| {
                read.body_json::<Value>().unwrap()["view"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            views,
            BTreeSet::from(["comparison".into(), "trend".into(), "breakdown".into()])
        );
        assert!(events.contains("no language model"), "{events}");
    }
    assert!(fixture.model.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn clarification_and_unsupported_plans_never_read_the_customer_source() {
    for (plan, expected) in [
        (
            json!({"kind":"clarify","question":"Should I compare application counts or review rates?"}),
            "Should I compare application counts or review rates?",
        ),
        (
            json!({"kind":"unsupported","reason":"The aggregate source does not contain a calibrated forecast."}),
            "The aggregate source does not contain a calibrated forecast.",
        ),
    ] {
        let fixture = Fixture::portfolio(true, false).await;
        let kind = if plan["kind"] == "clarify" {
            "clarification"
        } else {
            "unsupported"
        };
        model_plan(&fixture, plan, None).await;
        let cookie = fixture.login(&credit_token(&fixture)).await;
        let events = chat_events(&fixture, &cookie, "Can you help me understand this?").await;
        assert!(events.contains(expected), "{events}");
        assert_eq!(event_value(&events, "answer")["kind"], kind);
        assert_eq!(event_value(&events, "answer")["source_accessed"], false);
        assert!(!events.contains("event: portfolio_result"));
        assert!(fixture.source.received_requests().await.unwrap().is_empty());
        assert_eq!(fixture.model.received_requests().await.unwrap().len(), 1);
        assert!(
            !policy_events(&events)
                .iter()
                .any(|entry| entry["source_accessed"] == true)
        );
    }
}

#[tokio::test]
async fn duplicate_valid_queries_read_once_and_preserve_the_first_query_and_evidence() {
    let first = json!({"view":"breakdown","window_secs":900,"measures":["manual_review_count","application_count"],"dimension":"channel"});
    let mut reordered = first.clone();
    reordered["measures"] = json!(["application_count", "manual_review_count"]);
    for queries in [
        json!([first.clone(), first.clone()]),
        json!([first.clone(), reordered]),
        json!([first.clone(), first.clone(), first.clone(), first.clone()]),
    ] {
        let fixture = Fixture::portfolio(true, false).await;
        portfolio_source(&fixture, Duration::ZERO).await;
        model_plan(&fixture, json!({"kind":"query","interpretation":"Inspect application counts and manual reviews by channel.","queries":queries}), None).await;
        let token = credit_token(&fixture);
        let cookie = fixture.login(&token).await;
        let events = chat_events(
            &fixture,
            &cookie,
            "Show application counts and manual reviews by channel.",
        )
        .await;
        assert_eq!(event_value(&events, "interpretation")["query_count"], 1);
        let reads = fixture.source.received_requests().await.unwrap();
        assert_eq!(reads.len(), 1, "{events}");
        assert_eq!(reads[0].url.path(), "/v1/portfolio/query");
        assert_eq!(reads[0].body_json::<Value>().unwrap(), first);
        assert_eq!(reads[0].headers["authorization"], "Bearer opaque-showcase");

        let results = values(&events, "portfolio_result");
        assert_eq!(results.len(), 1, "{events}");
        assert_eq!(results[0]["query"], first);
        assert_eq!(results[0]["source_id"], "fixture-aggregates");
        assert_eq!(results[0]["tenant_id"], "customer-a");
        assert_eq!(results[0]["coverage"], "complete");
        let answer = event_value(&events, "answer");
        assert_eq!(answer["kind"], "grounded");
        assert_eq!(answer["summary_mode"], "model_selected_evidence");
        let findings = answer["findings"].as_array().unwrap();
        assert!(!findings.is_empty());
        assert!(
            findings
                .iter()
                .all(|finding| finding["evidence_id"] == results[0]["evidence_id"])
        );
        assert!(
            answer["text"]
                .as_str()
                .unwrap()
                .contains("Partner has the highest manual reviews: 30 applications"),
            "{events}"
        );
        let model_requests = fixture.model.received_requests().await.unwrap();
        assert_eq!(model_requests.len(), 2);
        assert!(!events.contains(&token));
        assert!(!String::from_utf8_lossy(&model_requests[1].body).contains(&token));
    }
}

#[tokio::test]
async fn invalid_or_foreign_proposals_never_dispatch_even_one_valid_prefix_query() {
    let valid = query("summary", "application_count");
    let mut foreign = valid.clone();
    foreign["source_id"] = json!("https://foreign.example/private");
    let mut wrong_filter = valid.clone();
    wrong_filter["filters"] = json!({"channel":"unlisted-private-channel"});
    let mut repeated_measure = valid.clone();
    repeated_measure["measures"] = json!(["application_count", "application_count"]);
    for queries in [
        json!([
            valid.clone(),
            valid.clone(),
            query("summary", "manual_review_rate_percent")
        ]),
        json!([valid.clone(), foreign.clone(), foreign]),
        json!([
            valid.clone(),
            valid.clone(),
            wrong_filter.clone(),
            wrong_filter
        ]),
        json!([valid.clone(), repeated_measure.clone(), repeated_measure]),
        json!([
            valid.clone(),
            valid.clone(),
            valid.clone(),
            valid.clone(),
            valid.clone()
        ]),
    ] {
        let fixture = Fixture::portfolio(true, false).await;
        model_plan(&fixture, json!({"kind":"query","interpretation":"Inspect authorized aggregates.","queries":queries}), None).await;
        let token = fixture.token(&fixture.claims(&[
            "portfolio:read",
            "portfolio:measure:application_count",
            "metrics:explain",
        ]));
        let cookie = fixture.login(&token).await;
        let events = chat_events(&fixture, &cookie, "What can we learn from recent volume?").await;
        assert!(events.contains("event: error"), "{events}");
        assert!(!events.contains("event: portfolio_result"));
        assert!(!events.contains("event: answer"));
        assert!(fixture.source.received_requests().await.unwrap().is_empty());
        assert_eq!(fixture.model.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn fabricated_finding_ids_and_prose_fall_back_to_computed_observations() {
    for selection in [
        json!({"finding_ids":["q99:invented_metric_999999"]}),
        json!({"finding_ids":["q1:manual_review_rate_percent"],"answer":"Invented crisis affects 999999 borrowers"}),
    ] {
        let fixture = Fixture::portfolio(true, false).await;
        portfolio_source(&fixture, Duration::ZERO).await;
        model_plan(&fixture, investigative_plan(), Some(selection)).await;
        let cookie = fixture.login(&credit_token(&fixture)).await;
        let events = chat_events(&fixture, &cookie, "What deserves attention?").await;
        assert_eq!(
            event_value(&events, "answer")["summary_mode"],
            "computed_fallback"
        );
        let answer = event_value(&events, "answer")["text"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(
            answer.contains("could not select a valid summary"),
            "{answer}"
        );
        assert!(answer.contains("computed observations"));
        assert!(!events.contains("999999"));
        assert!(!events.contains("Invented crisis"));
        assert_eq!(fixture.source.received_requests().await.unwrap().len(), 3);
        assert_eq!(fixture.model.received_requests().await.unwrap().len(), 2);
    }
}

#[tokio::test]
async fn interpretation_cannot_display_fabricated_findings_before_source_evidence() {
    let fixture = Fixture::portfolio(true, false).await;
    portfolio_source(&fixture, Duration::ZERO).await;
    let mut plan = investigative_plan();
    plan["interpretation"] =
        json!("Fraud increased to 999999 applications because staff ignored warnings.");
    model_plan(&fixture, plan, None).await;
    let cookie = fixture.login(&credit_token(&fixture)).await;
    let events = chat_events(&fixture, &cookie, "What deserves attention?").await;
    assert!(!events.contains("999999"));
    assert!(!events.contains("staff ignored"));
    let interpretation = event_value(&events, "interpretation");
    let text = interpretation["text"].as_str().unwrap();
    assert!(
        text.contains(
            "Manual review rate (%) for the last 15 minutes with the preceding 15 minutes"
        )
    );
    assert!(text.contains("Manual reviews (applications) by channel"));
    assert!(text.contains("Mean processing time (seconds) across six equal intervals"));
    assert_eq!(event_value(&events, "answer")["kind"], "grounded");
    assert_eq!(fixture.source.received_requests().await.unwrap().len(), 3);
}

#[tokio::test]
async fn logout_during_first_read_prevents_later_reads_selection_and_queued_data() {
    let fixture = Fixture::portfolio(true, false).await;
    portfolio_source(&fixture, Duration::from_millis(300)).await;
    model_plan(&fixture, investigative_plan(), None).await;
    let cookie = fixture.login(&credit_token(&fixture)).await;
    let response = fixture
        .browser(
            "POST",
            "/api/chat",
            &cookie,
            json!({"message":"Where might the process need attention?"}),
        )
        .await;
    wait_for_first_read(&fixture).await;
    assert_eq!(
        fixture
            .browser("POST", "/auth/logout", &cookie, Value::Null)
            .await
            .status(),
        StatusCode::OK
    );
    let events = String::from_utf8(
        tokio::time::timeout(
            Duration::from_secs(5),
            to_bytes(response.into_body(), 65536),
        )
        .await
        .unwrap()
        .unwrap()
        .to_vec(),
    )
    .unwrap();
    assert!(!events.contains("event: portfolio_result"), "{events}");
    assert!(!events.contains("event: answer"));
    assert!(events.contains("auth_expired"));
    assert_eq!(fixture.source.received_requests().await.unwrap().len(), 1);
    assert_eq!(fixture.model.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn cancelled_exploration_never_starts_the_next_source_read_or_selection() {
    let fixture = Fixture::portfolio(true, false).await;
    portfolio_source(&fixture, Duration::from_millis(250)).await;
    model_plan(&fixture, investigative_plan(), None).await;
    let cookie = fixture.login(&credit_token(&fixture)).await;
    let response = fixture
        .browser(
            "POST",
            "/api/chat",
            &cookie,
            json!({"message":"Help me investigate this mix."}),
        )
        .await;
    wait_for_first_read(&fixture).await;
    drop(response);
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert_eq!(fixture.source.received_requests().await.unwrap().len(), 1);
    assert_eq!(fixture.model.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn role_removal_and_restore_between_queries_invalidates_the_whole_investigation() {
    let fixture = Fixture::portfolio(true, true).await;
    portfolio_source(&fixture, Duration::ZERO).await;
    model_plan(&fixture, investigative_plan(), None).await;
    let (_, analyst) = org_identity(&fixture, Persona::CustomerAnalyst).await;
    let (_, engineer) = org_identity(&fixture, Persona::Engineer).await;
    let response = fixture
        .browser(
            "POST",
            "/api/chat",
            &analyst,
            json!({"message":"Where should we investigate the latest mix?"}),
        )
        .await;
    wait_for_first_read(&fixture).await;
    // Leave the bounded SSE receiver paused. The first source response cannot
    // authorize a second read or disclose queued data after a role epoch change.
    activate(&fixture, &engineer, Persona::Engineer, None).await;
    activate(&fixture, &analyst, Persona::CustomerAnalyst, None).await;
    let events = String::from_utf8(
        tokio::time::timeout(
            Duration::from_secs(5),
            to_bytes(response.into_body(), 65536),
        )
        .await
        .unwrap()
        .unwrap()
        .to_vec(),
    )
    .unwrap();
    assert!(events.contains("auth_expired"), "{events}");
    assert!(!events.contains("event: portfolio_result"));
    assert!(!events.contains("event: answer"));
    assert_eq!(fixture.source.received_requests().await.unwrap().len(), 1);
    assert_eq!(fixture.model.received_requests().await.unwrap().len(), 1);
}
