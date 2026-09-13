use super::*;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn inventory(total: i64, start: usize, length: usize) -> serde_json::Value {
    serde_json::json!({
        "total_count": total,
        "secrets": (start..start + length).map(|index| serde_json::json!({
            "name": format!("SECRET_{index}"),
            "created_at": "2026-09-12T00:00:00Z",
            "updated_at": "2026-09-12T00:00:00Z",
        })).collect::<Vec<_>>()
    })
}

async fn mount_page(server: &MockServer, route: &str, page: usize, response: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path(route))
        .and(query_param("per_page", "100"))
        .and(query_param("page", page.to_string()))
        .and(header("Authorization", "Bearer fixture-token"))
        .and(header("X-GitHub-Api-Version", GITHUB_API_VERSION))
        .respond_with(response)
        .expect(1)
        .mount(server)
        .await;
}

fn repo_scope() -> SecretScope<'static> {
    SecretScope::RepoActions {
        owner: "owner",
        repo: "repo",
    }
}

#[tokio::test]
async fn every_supported_scope_returns_all_pages_on_the_pinned_enterprise_path() {
    let scopes = [
        repo_scope(),
        SecretScope::EnvActions {
            owner: "owner",
            repo: "repo",
            environment: "production",
        },
        SecretScope::CodespacesUser,
        SecretScope::CodespacesRepo {
            owner: "owner",
            repo: "repo",
        },
        SecretScope::Dependabot {
            owner: "owner",
            repo: "repo",
        },
        SecretScope::OrgActions {
            org: "organization",
        },
    ];
    for scope in scopes {
        let server = MockServer::start().await;
        let route = format!("/api/v3{}", scope.list_secrets_path());
        mount_page(
            &server,
            &route,
            1,
            ResponseTemplate::new(200).set_body_json(inventory(101, 0, 100)),
        )
        .await;
        mount_page(
            &server,
            &route,
            2,
            ResponseTemplate::new(200).set_body_json(inventory(101, 100, 1)),
        )
        .await;
        let result = GitHubClient::with_base_url(format!("{}/api/v3", server.uri()))
            .list_secrets_scoped("fixture-token", &scope)
            .await
            .unwrap();
        assert_eq!(result.total_count, 101);
        assert_eq!(result.secrets.len(), 101);
        assert_eq!(result.secrets[100].name, "SECRET_100");
        server.verify().await;
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }
}

#[tokio::test]
async fn link_urls_cannot_change_scope_or_receive_credentials() {
    let server = MockServer::start().await;
    let destination = MockServer::start().await;
    let scope = repo_scope();
    let route = scope.list_secrets_path();
    mount_page(
        &server,
        &route,
        1,
        ResponseTemplate::new(200)
            .insert_header(
                "Link",
                format!("<{}/steal?token=sentinel>; rel=\"next\"", destination.uri()),
            )
            .set_body_json(inventory(101, 0, 100)),
    )
    .await;
    mount_page(
        &server,
        &route,
        2,
        ResponseTemplate::new(200).set_body_json(inventory(101, 100, 1)),
    )
    .await;
    let result = GitHubClient::with_base_url(server.uri())
        .list_secrets_scoped("fixture-token", &scope)
        .await
        .unwrap();
    assert_eq!(result.secrets.len(), 101);
    server.verify().await;
    assert!(destination.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn incomplete_or_inconsistent_inventory_never_returns_a_partial_success() {
    for second_page in [
        inventory(101, 100, 0), // Truncated final page.
        inventory(102, 100, 2), // Inventory grew during enumeration.
        inventory(99, 100, 0),  // Inventory shrank during enumeration.
        inventory(101, 0, 1),   // Duplicate from the previous page.
        inventory(101, 100, 2), // More records than the declared total.
    ] {
        let server = MockServer::start().await;
        let scope = repo_scope();
        let route = scope.list_secrets_path();
        mount_page(
            &server,
            &route,
            1,
            ResponseTemplate::new(200).set_body_json(inventory(101, 0, 100)),
        )
        .await;
        mount_page(
            &server,
            &route,
            2,
            ResponseTemplate::new(200).set_body_json(second_page),
        )
        .await;
        let error = GitHubClient::with_base_url(server.uri())
            .list_secrets_scoped("fixture-token", &scope)
            .await
            .unwrap_err();
        assert!(matches!(error, GitHubApiError::InvalidInventory));
        server.verify().await;
    }
}

#[tokio::test]
async fn later_page_failure_does_not_retry_or_return_a_partial_inventory() {
    for status in [401, 403, 404, 429, 500] {
        let server = MockServer::start().await;
        let scope = repo_scope();
        let route = scope.list_secrets_path();
        mount_page(
            &server,
            &route,
            1,
            ResponseTemplate::new(200).set_body_json(inventory(101, 0, 100)),
        )
        .await;
        mount_page(
            &server,
            &route,
            2,
            ResponseTemplate::new(status).set_body_string("private-api-error-sentinel"),
        )
        .await;
        let error = GitHubClient::with_base_url(server.uri())
            .list_secrets_scoped("fixture-token", &scope)
            .await
            .unwrap_err();
        assert!(!error.to_string().contains("private-api-error-sentinel"));
        assert!(!format!("{error:?}").contains("fixture-token"));
        match status {
            401 | 403 => assert!(matches!(error, GitHubApiError::Unauthorized)),
            404 => assert!(matches!(error, GitHubApiError::NotFound(_))),
            429 => assert!(matches!(error, GitHubApiError::RateLimited)),
            500 => assert!(matches!(error, GitHubApiError::ServerError)),
            _ => unreachable!(),
        }
        server.verify().await;
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }
}

#[tokio::test]
async fn inventory_redirect_cannot_receive_credentials() {
    let server = MockServer::start().await;
    let destination = MockServer::start().await;
    let scope = repo_scope();
    mount_page(
        &server,
        &scope.list_secrets_path(),
        1,
        ResponseTemplate::new(307).insert_header("Location", destination.uri()),
    )
    .await;
    let error = GitHubClient::with_base_url(server.uri())
        .list_secrets_scoped("fixture-token", &scope)
        .await
        .unwrap_err();
    assert!(matches!(error, GitHubApiError::UnexpectedStatus(307)));
    server.verify().await;
    assert!(destination.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn inventory_entry_and_page_byte_limits_fail_closed() {
    for response in [
        ResponseTemplate::new(200).set_body_json(inventory(
            (INVENTORY_PAGE_SIZE * MAX_INVENTORY_PAGES + 1) as i64,
            0,
            100,
        )),
        ResponseTemplate::new(200).set_body_string("x".repeat(MAX_INVENTORY_PAGE_BYTES + 1)),
    ] {
        let server = MockServer::start().await;
        let scope = repo_scope();
        mount_page(&server, &scope.list_secrets_path(), 1, response).await;
        let error = GitHubClient::with_base_url(server.uri())
            .list_secrets_scoped("fixture-token", &scope)
            .await
            .unwrap_err();
        assert!(matches!(error, GitHubApiError::InventoryLimitExceeded));
        server.verify().await;
    }
}

#[tokio::test]
async fn malformed_count_json_and_duplicate_names_are_rejected_without_echoing_body() {
    let mut duplicate = inventory(2, 0, 2);
    duplicate["secrets"][1]["name"] = "secret_0".into();
    for response in [
        ResponseTemplate::new(200).set_body_json(inventory(-1, 0, 0)),
        ResponseTemplate::new(200).set_body_json(inventory(101, 0, 30)),
        ResponseTemplate::new(200).set_body_string("private-response-sentinel"),
        ResponseTemplate::new(200).set_body_json(duplicate),
    ] {
        let server = MockServer::start().await;
        let scope = repo_scope();
        mount_page(&server, &scope.list_secrets_path(), 1, response).await;
        let error = GitHubClient::with_base_url(server.uri())
            .list_secrets_scoped("fixture-token", &scope)
            .await
            .unwrap_err();
        assert!(matches!(error, GitHubApiError::InvalidInventory));
        assert!(!format!("{error:?}").contains("private-response-sentinel"));
        server.verify().await;
    }
}

#[tokio::test]
async fn empty_and_exact_page_inventories_need_no_extra_request() {
    for count in [0, 100] {
        let server = MockServer::start().await;
        let scope = repo_scope();
        mount_page(
            &server,
            &scope.list_secrets_path(),
            1,
            ResponseTemplate::new(200).set_body_json(inventory(count as i64, 0, count)),
        )
        .await;
        let result = GitHubClient::with_base_url(server.uri())
            .list_secrets_scoped("fixture-token", &scope)
            .await
            .unwrap();
        assert_eq!(result.secrets.len(), count);
        server.verify().await;
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}
