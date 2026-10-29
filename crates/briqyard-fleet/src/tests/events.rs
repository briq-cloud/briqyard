//! Events (ADR 0019).

use super::*;

#[tokio::test]
async fn a_scoped_read_goes_to_one_host_with_its_own_cursor() {
    let (f, ds) = fleet_with_daemons(2).await;
    ds[0].stub.add("t1", "web", 512);
    let m = ds[1].stub.add("t2", "db", 512);
    poll_static_hosts_once(&f.st).await;
    ds[0].stub.log(1, "t1", "created");
    ds[1].stub.log(2, "t2", "created");
    // A namespace's: its host alone, the query as it came, the host named.
    let (s, headers, body) =
        call(&f.st, "GET", "/v1/events?namespace=t1&since=0", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d1");
    let page: api::EventsPage = serde_json::from_str(&body).unwrap();
    assert_eq!((page.events.len(), page.next.as_str()), (1, "1"));
    assert_eq!(
        page.events[0].host, "",
        "one host's log: no host on each event"
    );
    assert_eq!(
        ds[0].stub.calls().last().unwrap(),
        "GET /v1/events?namespace=t1&since=0"
    );
    assert!(!ds[1]
        .stub
        .calls()
        .iter()
        .any(|c| c.starts_with("GET /v1/events")));
    // A machine's: found where it runs.
    let q = format!("/v1/events?machine={}", m.id);
    let (s, headers, _) = call(&f.st, "GET", &q, "api", None).await;
    assert_eq!(
        (s, &headers["x-briqyard-host"]),
        (StatusCode::OK, &HeaderValue::from_static("d2"))
    );
    // Neither known: 404, the way to a destroyed machine's events in the message.
    let (s, _, body) = call(&f.st, "GET", "/v1/events?namespace=nobody", "api", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{body}");
    let (s, _, body) = call(&f.st, "GET", "/v1/events?machine=m_gone", "api", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(
        json(&body)["error"]
            .as_str()
            .unwrap()
            .contains("?namespace=…&machine=m_gone"),
        "{body}"
    );
    // The host's refusal passes through: a cursor past its log.
    let (s, _, body) = call(&f.st, "GET", "/v1/events?namespace=t1&since=9", "api", None).await;
    assert_eq!(
        (s, json(&body)["code"].as_str()),
        (StatusCode::GONE, Some("gone"))
    );
}

#[tokio::test]
async fn a_fleet_wide_read_merges_every_host_by_time_and_is_never_partial() {
    let (f, ds) = fleet_with_daemons(2).await;
    ds[0].stub.log(1, "t1", "created");
    ds[1].stub.log(2, "t2", "created");
    ds[0].stub.log(3, "t1", "started");
    ds[1].stub.log(4, "t2", "started");
    ds[0].stub.log(5, "t1", "stopped");
    let (s, _, body) = call(&f.st, "GET", "/v1/events", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let page: api::EventsPage = serde_json::from_str(&body).unwrap();
    let got: Vec<(&str, u64)> = page
        .events
        .iter()
        .map(|e| (e.host.as_str(), e.seq))
        .collect();
    assert_eq!(got, [("d1", 1), ("d2", 1), ("d1", 2), ("d2", 2), ("d1", 3)]);
    assert_eq!(page.next, "d1:3,d2:2");
    // From that cursor: each host from its own seq; nothing new, the cursor stays.
    ds[1].stub.log(6, "t2", "stopped");
    let (s, _, body) = call(&f.st, "GET", "/v1/events?since=d1:3,d2:2", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let page: api::EventsPage = serde_json::from_str(&body).unwrap();
    assert_eq!(page.events.len(), 1);
    assert_eq!(
        (page.events[0].host.as_str(), page.next.as_str()),
        ("d2", "d1:3,d2:3")
    );
    assert_eq!(ds[0].stub.calls().last().unwrap(), "GET /v1/events?since=3");
    // A page past its limit: each host's cursor is its last event kept, nothing is skipped.
    let (_, _, body) = call(&f.st, "GET", "/v1/events?limit=3", "api", None).await;
    let page: api::EventsPage = serde_json::from_str(&body).unwrap();
    let got: Vec<(&str, u64)> = page
        .events
        .iter()
        .map(|e| (e.host.as_str(), e.seq))
        .collect();
    assert_eq!(got, [("d1", 1), ("d2", 1), ("d1", 2)]);
    assert_eq!(page.next, "d1:2,d2:1");
    assert_eq!(
        ds[1].stub.calls().last().unwrap(),
        "GET /v1/events?since=0&limit=3",
        "the rest of the query as it came"
    );
    let (_, _, body) = call(
        &f.st,
        "GET",
        &format!("/v1/events?since={}", page.next),
        "api",
        None,
    )
    .await;
    let page: api::EventsPage = serde_json::from_str(&body).unwrap();
    let got: Vec<(&str, u64)> = page
        .events
        .iter()
        .map(|e| (e.host.as_str(), e.seq))
        .collect();
    assert_eq!(got, [("d2", 2), ("d1", 3), ("d2", 3)]);
    // A cursor that is not the fleet's, and a watch of every host, are refused.
    for q in [
        "/v1/events?since=12",
        "/v1/events?since=d1:x",
        "/v1/events?watch=true",
    ] {
        let (s, _, body) = call(&f.st, "GET", q, "api", None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{q}: {body}");
        assert_eq!(json(&body)["code"], "invalid");
    }
    // A host down fails the whole read: events missing a host are a partial story.
    set_state(&f.st, "d2", "down");
    let (s, _, body) = call(&f.st, "GET", "/v1/events", "api", None).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(json(&body)["code"], "host_down");
}

#[tokio::test]
async fn a_scoped_watch_is_streamed_through_as_it_comes() {
    let (f, ds) = fleet_with_daemons(1).await;
    ds[0].stub.add("t1", "web", 512);
    poll_static_hosts_once(&f.st).await;
    ds[0].stub.log(1, "t1", "created");
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", ln.local_addr().unwrap());
    let app = app(f.st.clone());
    tokio::spawn(async move { axum::serve(ln, app).await.unwrap() });
    let mut w = reqwest::Client::new()
        .get(format!("{url}/v1/events?namespace=t1&watch=true"))
        .bearer_auth("api")
        .send()
        .await
        .unwrap();
    assert_eq!(w.status(), StatusCode::OK);
    assert_eq!(w.headers()["content-type"], "application/x-ndjson");
    assert_eq!(w.headers()["x-briqyard-host"], "d1");
    assert_eq!(chunk(&mut w).await["reason"], "created");
    // The host's next line reaches the client while the stream stays open.
    let live = serde_json::to_string(&ds[0].stub.log(2, "t1", "started")).unwrap() + "\n";
    let tx = ds[0].stub.watcher.lock().unwrap().clone().unwrap();
    tx.send(live).await.unwrap();
    assert_eq!(chunk(&mut w).await["reason"], "started");
}

#[tokio::test]
async fn if_match_is_passed_to_the_host() {
    let (f, ds) = fleet_with_daemons(1).await;
    let m = ds[0].stub.add("t1", "web", 512);
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/v1/machines/{}/start", m.id))
        .header(header::AUTHORIZATION, "Bearer api")
        .header(header::IF_MATCH, "7")
        .body(Body::empty())
        .unwrap();
    let resp = app(f.st.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // To the call it was sent with, not to the search for the machine's host before it.
    assert_eq!(*ds[0].stub.if_match.lock().unwrap(), ["7"]);
}
