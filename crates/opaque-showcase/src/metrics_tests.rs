use super::*;
use serde_json::{Value, json};
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn config(base_url: String, tenant: &str) -> MetricsSourceConfig {
    MetricsSourceConfig {
        tenant_id: tenant.into(),
        source_id: format!("{tenant}-metrics"),
        base_url,
        credential_env: format!("OPAQUE_{}_SOURCE", tenant.to_uppercase().replace('-', "_")),
        allowed_metrics: METRIC_NAMES.iter().map(|name| (*name).into()).collect(),
        allowed_portfolio_measures: vec![],
        max_window_secs: 300,
        max_staleness_secs: 60,
        allow_loopback_http: true,
    }
}

fn query() -> MetricsQuery {
    MetricsQuery {
        window_secs: 60,
        metrics: vec!["active_sessions".into()],
    }
}

fn snapshot(tenant: &str) -> Value {
    json!({"tenant_id":tenant,"window_secs":60,"as_of":now(),"watermark":now()-2,
        "metrics":[{"name":"active_sessions","value":12.0,"count":30}]})
}

fn client(configs: Vec<MetricsSourceConfig>) -> MetricsClient {
    MetricsClient::from_configs(configs, |name| Some(format!("fixture-{name}"))).unwrap()
}

#[tokio::test]
async fn tenant_mapping_selects_exact_source_and_credential_without_disclosing_custody() {
    let first = MockServer::start().await;
    let second = MockServer::start().await;
    for (server, tenant, credential) in [
        (&first, "tenant-a", "Bearer fixture-OPAQUE_TENANT_A_SOURCE"),
        (&second, "tenant-b", "Bearer fixture-OPAQUE_TENANT_B_SOURCE"),
    ] {
        Mock::given(method("POST"))
            .and(path("/v1/metrics/query"))
            .and(header("authorization", credential))
            .and(body_json(
                json!({"window_secs":60,"metrics":["active_sessions"]}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(snapshot(tenant)))
            .expect(1)
            .mount(server)
            .await;
    }
    let client = client(vec![
        config(first.uri(), "tenant-a"),
        config(second.uri(), "tenant-b"),
    ]);
    for tenant in ["tenant-a", "tenant-b"] {
        let evidence = client.query(tenant, query()).await.unwrap();
        assert_eq!(evidence.tenant_id, tenant);
        assert_eq!(evidence.source_id, format!("{tenant}-metrics"));
        assert_eq!(evidence.metrics[0].count, 30);
        assert!(evidence.watermark <= evidence.as_of && evidence.as_of <= evidence.observed_at + 5);
        let encoded = serde_json::to_string(&evidence).unwrap();
        assert!(
            !encoded.contains("http")
                && !encoded.contains("Bearer")
                && !encoded.contains("OPAQUE_")
        );
    }
    assert_eq!(
        client.query("foreign-tenant", query()).await.unwrap_err(),
        MetricsError::TenantUnavailable
    );
}

#[tokio::test]
async fn scope_rejections_happen_before_source_io() {
    let server = MockServer::start().await;
    let mut source = config(server.uri(), "tenant-a");
    source.allowed_metrics = vec!["active_sessions".into()];
    let client = client(vec![source]);
    for query in [
        MetricsQuery {
            window_secs: 0,
            metrics: vec!["active_sessions".into()],
        },
        MetricsQuery {
            window_secs: 301,
            metrics: vec!["active_sessions".into()],
        },
        MetricsQuery {
            window_secs: 60,
            metrics: vec![],
        },
        MetricsQuery {
            window_secs: 60,
            metrics: vec!["active_sessions".into(); 2],
        },
        MetricsQuery {
            window_secs: 60,
            metrics: vec!["p95_latency_ms".into()],
        },
        MetricsQuery {
            window_secs: 60,
            metrics: vec!["SELECT * FROM customers".into()],
        },
    ] {
        assert_eq!(
            client.query("tenant-a", query).await.unwrap_err(),
            MetricsError::InvalidQuery
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    for field in ["tenant_id", "base_url", "credential_env", "sql"] {
        let mut value = serde_json::to_value(query()).unwrap();
        value[field] = json!("caller-supplied");
        assert!(serde_json::from_value::<MetricsQuery>(value).is_err());
    }
}

#[tokio::test]
async fn rejects_cross_tenant_stale_malformed_and_expanded_source_evidence() {
    let server = MockServer::start().await;
    let client = client(vec![config(server.uri(), "tenant-a")]);
    let mut malformed = Vec::new();
    for (field, value) in [
        ("tenant_id", json!("tenant-b")),
        ("window_secs", json!(61)),
        ("as_of", json!(now() + 100)),
        ("watermark", json!(now() - 61)),
        ("watermark", json!(now() + 10)),
        ("watermark", json!(0)),
        ("raw_rows", json!([{ "customer": "private" }])),
    ] {
        let mut response = snapshot("tenant-a");
        response[field] = value;
        malformed.push(response);
    }
    for (field, value) in [
        ("name", json!("unapproved_metric")),
        ("value", json!(-1)),
        ("value", json!(12.5)),
        ("value", json!(1.0e16)),
        ("count", json!(-1)),
        ("count", json!(1_000_000_000_001_u64)),
        ("customer_id", json!("raw-data")),
    ] {
        let mut response = snapshot("tenant-a");
        response["metrics"][0][field] = value;
        malformed.push(response);
    }
    let mut duplicate = snapshot("tenant-a");
    let duplicate_row = duplicate["metrics"][0].clone();
    duplicate["metrics"]
        .as_array_mut()
        .unwrap()
        .push(duplicate_row);
    malformed.push(duplicate);
    let mut missing = snapshot("tenant-a");
    missing["metrics"] = json!([]);
    malformed.push(missing);
    for response in malformed {
        server.reset().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            client.query("tenant-a", query()).await.unwrap_err(),
            MetricsError::InvalidEvidence
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
    assert!(serde_json::from_str::<SourceSnapshot>(r#"{"tenant_id":"tenant-a","window_secs":60,"as_of":1,"watermark":1,"metrics":[{"name":"active_sessions","value":NaN,"count":1}]}"#).is_err());
}

#[tokio::test]
async fn redirects_failures_oversized_bodies_and_deadlines_never_retry() {
    let server = MockServer::start().await;
    let trap = MockServer::start().await;
    let mut client = client(vec![config(server.uri(), "tenant-a")]);
    for (status, expected) in [
        (302, MetricsError::SourceUnavailable),
        (401, MetricsError::SourceRejected),
        (429, MetricsError::SourceRejected),
        (500, MetricsError::SourceUnavailable),
        (503, MetricsError::SourceUnavailable),
    ] {
        server.reset().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("location", format!("{}/credential-trap", trap.uri()))
                    .set_body_string("SOURCE-SECRET-must-never-be-returned"),
            )
            .expect(1)
            .mount(&server)
            .await;
        let error = client.query("tenant-a", query()).await.unwrap_err();
        assert_eq!(error, expected);
        assert!(!error.to_string().contains("SECRET"));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
    assert!(trap.received_requests().await.unwrap().is_empty());
    server.reset().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(" ".repeat(MAX_BODY_BYTES + 1)))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        client.query("tenant-a", query()).await.unwrap_err(),
        MetricsError::InvalidEvidence
    );
    server.reset().await;
    client.http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(Duration::from_millis(30))
        .build()
        .unwrap();
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(150))
                .set_body_json(snapshot("tenant-a")),
        )
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        client.query("tenant-a", query()).await.unwrap_err(),
        MetricsError::SourceUnavailable
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[test]
fn invalid_authority_and_missing_or_malformed_credentials_fail_at_startup() {
    for url in [
        "http://example.com",
        "file:///metrics",
        "https://user:pass@example.com",
        "https://example.com/custom",
        "https://example.com/?token=x",
        "https://example.com/#fragment",
    ] {
        assert!(
            MetricsClient::from_configs(vec![config(url.into(), "tenant-a")], |_| Some(
                "fixture".into()
            ))
            .is_err()
        );
    }
    let source = config("https://metrics.example.invalid".into(), "tenant-a");
    for credential in [
        None,
        Some("".into()),
        Some("has space".into()),
        Some("token\r\nHeader:value".into()),
    ] {
        assert!(MetricsClient::from_configs(vec![source.clone()], |_| credential.clone()).is_err());
    }
    assert!(
        MetricsClient::from_configs(vec![source.clone(), source.clone()], |_| Some(
            "fixture".into()
        ))
        .is_err()
    );
    let mut invalid = source.clone();
    invalid.allowed_metrics.push("customer_email".into());
    assert!(MetricsClient::from_configs(vec![invalid], |_| Some("fixture".into())).is_err());
    let mut invalid = source.clone();
    invalid.max_window_secs = 3601;
    assert!(MetricsClient::from_configs(vec![invalid], |_| Some("fixture".into())).is_err());
    let mut invalid = source;
    invalid.credential_env = "../token".into();
    assert!(MetricsClient::from_configs(vec![invalid], |_| Some("fixture".into())).is_err());
}

#[test]
fn percentage_and_clock_bounds_are_enforced() {
    let source = config("https://metrics.example.invalid".into(), "tenant-a");
    let request = MetricsQuery {
        window_secs: 60,
        metrics: vec!["error_rate_percent".into()],
    };
    let requested = validate_query(&source, &request).unwrap();
    let mut response: SourceSnapshot = serde_json::from_value(snapshot("tenant-a")).unwrap();
    response.metrics[0].name = "error_rate_percent".into();
    response.metrics[0].value = 100.0;
    let observed = now();
    response.as_of = observed + 5;
    response.watermark = observed;
    assert!(validate_snapshot(&source, &request, &requested, &response, observed).is_ok());
    response.metrics[0].value = 100.1;
    assert!(validate_snapshot(&source, &request, &requested, &response, observed).is_err());
    response.metrics[0].value = f64::INFINITY;
    assert!(validate_snapshot(&source, &request, &requested, &response, observed).is_err());
}

#[test]
fn credit_percentages_and_scores_have_typed_numeric_limits() {
    let source = config("http://127.0.0.1:1234".into(), "tenant-a");
    for (metric, ceiling) in [
        ("manual_review_rate_percent", 100.0),
        ("identity_mismatch_rate_percent", 100.0),
        ("average_credit_score", 850.0),
    ] {
        let request = MetricsQuery {
            window_secs: 60,
            metrics: vec![metric.into()],
        };
        let requested = validate_query(&source, &request).unwrap();
        let mut response: SourceSnapshot = serde_json::from_value(snapshot("tenant-a")).unwrap();
        response.metrics[0].name = metric.into();
        for accepted in [0.0, ceiling] {
            response.metrics[0].value = accepted;
            assert!(validate_snapshot(&source, &request, &requested, &response, now()).is_ok());
        }
        for rejected in [-0.1, ceiling + 0.01, f64::INFINITY, f64::NAN] {
            response.metrics[0].value = rejected;
            assert!(validate_snapshot(&source, &request, &requested, &response, now()).is_err());
        }
    }
}

#[tokio::test]
async fn portfolio_transport_has_exact_custody_no_retry_and_strict_response_binding() {
    use crate::portfolio::{Measure, PortfolioQuery};
    let server = MockServer::start().await;
    let trap = MockServer::start().await;
    let mut source = config(server.uri(), "tenant-a");
    source.allowed_portfolio_measures = Measure::ALL.to_vec();
    let client = client(vec![source]);
    let query:PortfolioQuery=serde_json::from_value(json!({"view":"summary","window_secs":3600,"measures":["application_count","manual_review_count","manual_review_rate_percent"]})).unwrap();
    let valid = json!({"tenant_id":"tenant-a","query":query,"as_of":now(),"watermark":now(),"history_start":now()-7205,"history_kind":"synthetic_seeded_and_live","rows":[{"key":"all","period_start":now()-3600,"period_end":now(),"sample_count":100,"values":{"application_count":100,"manual_review_count":20,"manual_review_rate_percent":20}}],"comparison":[]});
    Mock::given(method("POST"))
        .and(path("/v1/portfolio/query"))
        .and(header(
            "authorization",
            "Bearer fixture-OPAQUE_TENANT_A_SOURCE",
        ))
        .and(body_json(serde_json::to_value(&query).unwrap()))
        .respond_with(ResponseTemplate::new(200).set_body_json(valid.clone()))
        .expect(1)
        .mount(&server)
        .await;
    let evidence = client
        .query_portfolio("tenant-a", query.clone())
        .await
        .unwrap();
    assert_eq!(evidence.source_id, "tenant-a-metrics");
    assert_eq!(evidence.snapshot.rows[0].sample_count, 100);
    assert!(
        !serde_json::to_string(&evidence)
            .unwrap()
            .contains("OPAQUE_")
    );
    for field in [
        "tenant_id",
        "query",
        "raw_rows",
        "watermark",
        "history_start",
    ] {
        server.reset().await;
        let mut invalid = valid.clone();
        invalid[field] = match field {
            "tenant_id" => json!("foreign"),
            "query" => json!({"view":"summary","window_secs":900,"measures":["application_count"]}),
            "watermark" => json!(now() - 1000),
            "history_start" => json!(now() - 300),
            _ => json!([]),
        };
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(invalid))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            client
                .query_portfolio("tenant-a", query.clone())
                .await
                .unwrap_err(),
            MetricsError::InvalidEvidence
        );
    }
    server.reset().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", trap.uri()))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        client
            .query_portfolio("tenant-a", query.clone())
            .await
            .unwrap_err(),
        MetricsError::SourceUnavailable
    );
    assert!(trap.received_requests().await.unwrap().is_empty());
    server.reset().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(MAX_BODY_BYTES + 1)))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        client
            .query_portfolio("tenant-a", query.clone())
            .await
            .unwrap_err(),
        MetricsError::InvalidEvidence
    );
    assert_eq!(
        client.query_portfolio("foreign", query).await.unwrap_err(),
        MetricsError::TenantUnavailable
    );
}

#[tokio::test]
async fn absent_portfolio_permission_or_unscoped_measure_never_contacts_source() {
    use crate::portfolio::{Measure, PortfolioQuery};
    let server = MockServer::start().await;
    let request: PortfolioQuery = serde_json::from_value(
        json!({"view":"summary","window_secs":900,"measures":["manual_review_count"]}),
    )
    .unwrap();
    for allowed in [vec![], vec![Measure::ApplicationCount]] {
        let mut source = config(server.uri(), "tenant-a");
        source.allowed_portfolio_measures = allowed;
        assert_eq!(
            client(vec![source])
                .query_portfolio("tenant-a", request.clone())
                .await
                .unwrap_err(),
            MetricsError::InvalidQuery
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}
