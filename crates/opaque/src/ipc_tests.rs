use super::*;
use std::os::unix::fs::PermissionsExt;
use tokio::io::AsyncReadExt;
use tokio::net::UnixListener;

fn fixture() -> (tempfile::TempDir, PathBuf, UnixListener) {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(directory.path().join("daemon.token"), "fixture-token").unwrap();
    let socket = directory.path().join("daemon.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    (directory, socket, listener)
}

#[tokio::test]
async fn response_timeout_reports_unknown_and_does_not_reconnect() {
    let (_directory, socket, listener) = fixture();
    let daemon = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
        framed.next().await.unwrap().unwrap();
        let request: Request =
            serde_json::from_slice(&framed.next().await.unwrap().unwrap()).unwrap();
        assert_eq!(request.method, "exec");
        // Keep the connection open but never answer. Timeout must close it.
        assert!(framed.next().await.is_none());
        assert!(
            tokio::time::timeout(Duration::from_millis(300), listener.accept())
                .await
                .is_err()
        );
    });
    let error = call_with_timeout(
        &socket,
        "exec",
        serde_json::json!({"profile":"fixture","command":["true"]}),
        Duration::from_millis(100),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(error.to_string().contains("outcome unknown"));
    assert!(error.to_string().contains("not retried"));
    tokio::time::timeout(Duration::from_secs(2), daemon)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn reset_during_request_delivery_never_replays_exec() {
    let (_directory, socket, listener) = fixture();
    let daemon = tokio::spawn(async move {
        let mut requests = 0;
        while let Ok(Ok((mut stream, _))) =
            tokio::time::timeout(Duration::from_millis(1600), listener.accept()).await
        {
            let handshake_length = stream.read_u32().await.unwrap();
            let mut handshake = vec![0; handshake_length as usize];
            stream.read_exact(&mut handshake).await.unwrap();
            let request_length = stream.read_u32().await.unwrap();
            assert!(request_length > 64);
            let mut prefix = [0; 64];
            stream.read_exact(&mut prefix).await.unwrap();
            assert!(
                std::str::from_utf8(&prefix)
                    .unwrap()
                    .contains("\"method\":\"exec\"")
            );
            requests += 1;
            // Close with unread request bytes, which resets the peer instead of
            // returning a normal response. The client cannot prove non-execution.
            drop(stream);
        }
        requests
    });
    let error = call_with_timeout(
        &socket,
        "exec",
        serde_json::json!({"profile":"fixture", "command":["echo", "x".repeat(100_000)]}),
        Duration::from_secs(5),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            error.kind(),
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
        ),
        "fixture must trigger an error that the former retry loop replayed: {error}"
    );
    assert!(error.to_string().contains("outcome unknown"));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), daemon)
            .await
            .unwrap()
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn connection_unavailable_can_retry_before_sending_any_request() {
    let (_directory, socket, listener) = fixture();
    drop(listener);
    std::fs::remove_file(&socket).unwrap();
    let daemon_socket = socket.clone();
    let daemon = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let listener = UnixListener::bind(&daemon_socket).unwrap();
        std::fs::set_permissions(&daemon_socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
        framed.next().await.unwrap().unwrap();
        let request: Request =
            serde_json::from_slice(&framed.next().await.unwrap().unwrap()).unwrap();
        assert_eq!(request.method, "ping");
        framed
            .send(
                serde_json::to_vec(&Response::ok(1, serde_json::json!({"ready":true})))
                    .unwrap()
                    .into(),
            )
            .await
            .unwrap();
    });
    let response = call_with_timeout(
        &socket,
        "ping",
        serde_json::Value::Null,
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert_eq!(response.result.unwrap()["ready"], true);
    daemon.await.unwrap();
}

#[tokio::test]
async fn malformed_and_mismatched_daemon_responses_cannot_claim_success() {
    for envelope in [
        serde_json::json!({"id":1}),
        serde_json::json!({"id":2,"result":{"ok":true}}),
        serde_json::json!({"id":1,"result":{},"error":{"code":"bad","message":"bad"}}),
        serde_json::json!({"id":1,"error":null}),
    ] {
        let (_directory, socket, listener) = fixture();
        let daemon = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
            framed.next().await.unwrap().unwrap();
            framed.next().await.unwrap().unwrap();
            framed
                .send(serde_json::to_vec(&envelope).unwrap().into())
                .await
                .unwrap();
        });
        let error = call_with_timeout(
            &socket,
            "exec",
            serde_json::json!({}),
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("outcome unknown"));
        daemon.await.unwrap();
    }
}
