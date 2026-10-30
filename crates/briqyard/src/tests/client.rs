//! The client against a stub API on loopback.

use super::*;

#[tokio::test]
async fn the_client_sends_the_token_and_the_body() {
    let (url, stub) = stub(vec![
        (
            StatusCode::OK,
            JSON.to_vec(),
            r#"{"id":"m1","state":"running"}"#,
        ),
        (StatusCode::NO_CONTENT, vec![], ""),
        (StatusCode::OK, JSON.to_vec(), r#"[]"#),
    ])
    .await;
    let c = client(&format!("{url}/"), Some("t0k"));
    assert_eq!(c.base, url, "a trailing slash is dropped");
    let v: serde_json::Value = c
        .call(
            reqwest::Method::POST,
            "/v1/machines/m1/stop",
            Some(&api::StopRequest {
                suspend: true,
                timeout_sec: 0,
            }),
        )
        .await
        .unwrap();
    assert_eq!(v["id"], "m1");
    let text = c
        .raw(reqwest::Method::DELETE, "/v1/machines/m1", NONE)
        .await
        .unwrap();
    assert_eq!(text, "");
    let open = client(&url, None);
    let v: Vec<api::Machine> = open
        .call(reqwest::Method::GET, "/v1/machines?namespace=t1", NONE)
        .await
        .unwrap();
    assert!(v.is_empty());
    let seen = stub.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].path, "/v1/machines/m1/stop");
    assert_eq!(seen[0].authorization.as_deref(), Some("Bearer t0k"));
    assert_eq!(seen[0].content_type.as_deref(), Some("application/json"));
    assert_eq!(seen[0].body, r#"{"suspend":true,"timeout_sec":0}"#);
    assert_eq!(seen[1].method, "DELETE");
    assert_eq!(seen[1].content_type, None, "no body, no content type");
    assert_eq!(seen[1].body, "");
    assert_eq!(
        seen[2].path, "/v1/machines?namespace=t1",
        "the query goes along"
    );
    assert_eq!(seen[2].authorization, None, "no token, no header");
}

#[tokio::test]
async fn a_run_waits_for_its_create_again_and_again_and_keeps_its_host() {
    let m = |state: &str, host: &str| {
        serde_json::to_string(&api::Machine {
            id: "m1".into(),
            state: state.into(),
            host: host.into(),
            ..Default::default()
        })
        .unwrap()
    };
    let not_ready = format!(
        r#"{{"error":"machine m1 is still creating","code":"not_ready","machine":{}}}"#,
        m("creating", "")
    );
    let failed = r#"{"error":"pull failed: pull x: manifest unknown","code":"pull_failed"}"#;
    let running = m("running", "");
    let (url, stub) = stub(vec![
        (StatusCode::CONFLICT, JSON.to_vec(), &not_ready),
        (StatusCode::OK, JSON.to_vec(), &running),
        (StatusCode::CONFLICT, JSON.to_vec(), failed),
    ])
    .await;
    let c = client(&url, None);
    let creating = || serde_json::from_str::<api::Machine>(&m("creating", "h1")).unwrap();
    // ADR 0048: a wait that runs out on the way is waited again; through a fleet, the create's
    // answer named the host and the wait's does not.
    let done = c.running(creating()).await.unwrap();
    assert_eq!((done.state.as_str(), done.host.as_str()), ("running", "h1"));
    let err = c.running(creating()).await.unwrap_err();
    assert!(refused_with(&err, "pull_failed"), "{err:#}");
    let paths: Vec<String> = stub
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|s| s.path.clone())
        .collect();
    assert_eq!(
        paths,
        vec!["/v1/machines/m1/wait?for=running&timeout=600"; 3]
    );
    // A machine past `creating` (a daemon from before ADR 0048 answers at `running`): as is.
    let old = serde_json::from_str::<api::Machine>(&m("running", "")).unwrap();
    assert_eq!(c.running(old).await.unwrap().state, "running");
    assert_eq!(stub.seen.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn an_empty_answer_is_only_fine_when_nothing_is_expected() {
    let (url, _stub) = stub(vec![
        (StatusCode::OK, vec![], ""),
        (StatusCode::OK, vec![], ""),
    ])
    .await;
    let c = client(&url, None);
    c.call::<()>(reqwest::Method::POST, "/v1/machines/m1/touch", NONE)
        .await
        .unwrap();
    let err = c
        .call::<api::Machine>(reqwest::Method::GET, "/v1/machines/m1", NONE)
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "empty response");
}

#[tokio::test]
async fn errors_name_the_code_and_the_request() {
    let (url, _stub) = stub(vec![
        (
            StatusCode::NOT_FOUND,
            vec![("content-type", "application/json"), ("x-request-id", "r-1")],
            r#"{"error":"machine not found","code":"not_found","request_id":"r-1"}"#,
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            JSON.to_vec(),
            r#"{"error":"host d1 is down: its machines answer again once it does","code":"host_down"}"#,
        ),
        (StatusCode::BAD_GATEWAY, vec![], "  <html>upstream timed out</html>\n"),
        (StatusCode::OK, JSON.to_vec(), r#"{"id":"m1""#),
    ])
    .await;
    let c = client(&url, Some("t"));
    let get = |path: &'static str| c.call::<api::Machine>(reqwest::Method::GET, path, NONE);
    assert_eq!(
        get("/v1/machines/m9").await.unwrap_err().to_string(),
        "machine not found (not_found, request r-1)",
        "the request id from the daemon's body, for a support ticket"
    );
    assert_eq!(
        get("/v1/machines/m1").await.unwrap_err().to_string(),
        "host d1 is down: its machines answer again once it does (host_down)",
        "the fleet's own errors have no request id"
    );
    assert_eq!(
        get("/v1/machines/m1").await.unwrap_err().to_string(),
        "502 Bad Gateway: <html>upstream timed out</html>",
        "a body that is not an API error is shown as is, trimmed"
    );
    let err = get("/v1/machines/m1").await.unwrap_err().to_string();
    assert!(
        err.contains("EOF") || err.contains("expected"),
        "a broken JSON answer: {err}"
    );
    // Nothing listens: the error names the base URL.
    let dead = client("http://127.0.0.1:1", None);
    let err = format!(
        "{:#}",
        dead.call::<api::Status>(reqwest::Method::GET, "/v1/status", NONE)
            .await
            .unwrap_err()
    );
    assert!(err.starts_with("request http://127.0.0.1:1: "), "{err}");
}

#[tokio::test]
async fn raw_upload_encodes_the_path_and_sends_plain_bytes() {
    let (url, stub) = stub(vec![(StatusCode::NO_CONTENT, vec![], "")]).await;
    let c = client(&url, Some("token"));
    let local = std::env::temp_dir().join(format!("briqyard-file-test-{}", std::process::id()));
    std::fs::write(&local, b"raw content").unwrap();
    let result = c
        .put_file("m1", local.to_str().unwrap(), "/tmp/a & b?")
        .await;
    let _ = std::fs::remove_file(&local);
    result.unwrap();
    let seen = stub.seen.lock().unwrap();
    assert_eq!(seen[0].method, "PUT");
    assert_eq!(
        seen[0].path,
        "/v1/machines/m1/files/content?path=%2Ftmp%2Fa+%26+b%3F"
    );
    assert_eq!(seen[0].body, "raw content");
    assert_eq!(
        seen[0].content_type.as_deref(),
        Some("application/octet-stream")
    );
    assert_eq!(seen[0].authorization.as_deref(), Some("Bearer token"));
}
