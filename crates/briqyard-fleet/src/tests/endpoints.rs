//! Endpoints and gateways.

use super::*;

#[tokio::test]
async fn endpoints_are_indexed_to_their_host_and_listed_whole() {
    let (f, ds) = fleet_with_daemons(2).await;
    let m1 = ds[0].stub.add("t1", "web", 512);
    let m2 = ds[1].stub.add("t2", "db", 512);
    // Opened through the fleet: indexed at once.
    let (s, headers, body) = call(
        &f.st,
        "POST",
        &format!("/v1/machines/{}/endpoints", m1.id),
        "api",
        Some(serde_json::json!({"port": 80})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d1");
    let e1: api::Endpoint = serde_json::from_str(&body).unwrap();
    assert_eq!(
        f.st.reg
            .lock()
            .unwrap()
            .endpoints
            .get(&e1.id)
            .map(String::as_str),
        Some("d1")
    );
    assert_eq!(
        saved(&f.st).endpoints.get(&e1.id).map(String::as_str),
        Some("d1")
    );
    // Opened elsewhere: the listing asks every host and learns.
    let e2 = ds[1].stub.add_endpoint(&m2.id);
    let (s, _, body) = call(&f.st, "GET", "/v1/endpoints", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let eps: Vec<api::Endpoint> = serde_json::from_str(&body).unwrap();
    let ids: Vec<&str> = eps.iter().map(|e| e.id.as_str()).collect();
    assert_eq!(ids, [e1.id.as_str(), e2.id.as_str()]);
    assert_eq!(
        f.st.reg
            .lock()
            .unwrap()
            .endpoints
            .get(&e2.id)
            .map(String::as_str),
        Some("d2")
    );
    // Indexed: a call goes to its host alone.
    let d1_before = ds[0].stub.calls().len();
    let (s, headers, body) = call(
        &f.st,
        "GET",
        &format!("/v1/endpoints/{}", e2.id),
        "api",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d2");
    assert_eq!(ds[0].stub.calls().len(), d1_before, "d1 was not asked");
    // Not indexed (a fleet restarted with an empty registry): found by asking each host.
    f.st.reg.lock().unwrap().endpoints.clear();
    let (s, headers, _) = call(
        &f.st,
        "DELETE",
        &format!("/v1/endpoints/{}", e2.id),
        "api",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(headers["x-briqyard-host"], "d2");
    assert_eq!(
        ds[0].stub.calls().last().unwrap(),
        &format!("GET /v1/endpoints/{}", e2.id),
        "the search asked d1 first"
    );
    assert_eq!(
        f.st.reg.lock().unwrap().endpoints.get(&e2.id),
        None,
        "a delete drops the entry"
    );
    let (s, _, body) = call(&f.st, "DELETE", "/v1/endpoints/ep_x", "api", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(json(&body)["error"], "endpoint ep_x not found");
    // The listing is never partial: a host down fails it, like machines.
    set_state(&f.st, "d2", "down");
    let (s, _, body) = call(&f.st, "GET", "/v1/endpoints", "api", None).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(json(&body)["code"], "host_down");
    set_state(&f.st, "d2", "ready");
    f.st.reg.lock().unwrap().hosts.get_mut("d2").unwrap().url = "http://127.0.0.1:1".into();
    let (s, _, body) = call(&f.st, "GET", "/v1/endpoints", "api", None).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(json(&body)["code"], "host_unreachable");
}

#[tokio::test]
async fn a_gateway_places_a_new_namespace_and_is_forwarded_to_its_host() {
    let (f, ds) = fleet_with_daemons(2).await;
    // d1 is the fuller: a new namespace's gateway goes to d2, as its first machine would.
    ds[0].stub.add("t0", "big", 50_000);
    poll_static_hosts_once(&f.st).await;
    let (s, headers, body) = call(
        &f.st,
        "PUT",
        "/v1/namespaces/t1/gateway",
        "api",
        Some(gateway_body()),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d2");
    let t: api::Namespace = serde_json::from_str(&body).unwrap();
    assert_eq!(t.host, "d2", "the host is added to the body");
    assert_eq!(t.gateway.map(|g| g.port), Some(3128));
    assert_eq!(
        ds[1].stub.calls().last().unwrap(),
        "PUT /v1/namespaces/t1/gateway"
    );
    assert_eq!(pinned(&f.st, "t1").as_deref(), Some("d2"));
    assert_eq!(
        saved(&f.st).namespaces.get("t1").map(String::as_str),
        Some("d2")
    );
    assert_eq!(
        f.st.reg.lock().unwrap().hosts["d2"].used.memory_mb,
        256,
        "the gateway's size, reserved until the host reports"
    );
    // The namespace lives there now: its machines follow, its reads and removal go there.
    let (s, headers, _) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t1", "sbx", 512)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(headers["x-briqyard-host"], "d2");
    let (s, _, body) = call(&f.st, "GET", "/v1/namespaces/t1", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let t: api::Namespace = serde_json::from_str(&body).unwrap();
    assert_eq!((t.host.as_str(), t.machines), ("d2", 1));
    assert!(t.gateway.is_some());
    assert_eq!(ds[1].stub.calls().last().unwrap(), "GET /v1/namespaces/t1");
    let (s, _, body) = call(&f.st, "DELETE", "/v1/namespaces/t1/gateway", "api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(
        ds[1].stub.calls().last().unwrap(),
        "DELETE /v1/namespaces/t1/gateway"
    );
    // A namespace the fleet never placed: no host is asked.
    let before: Vec<usize> = ds.iter().map(|d| d.stub.calls().len()).collect();
    let (s, _, body) = call(&f.st, "GET", "/v1/namespaces/nobody", "api", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(json(&body)["code"], "not_found");
    let (s, _, _) = call(
        &f.st,
        "DELETE",
        "/v1/namespaces/nobody/gateway",
        "api",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let after: Vec<usize> = ds.iter().map(|d| d.stub.calls().len()).collect();
    assert_eq!(before, after);
}

#[tokio::test]
async fn a_gateway_refused_is_answered_as_the_host_said() {
    let (f, ds) = fleet_with_daemons(1).await;
    // The host filled up since the fleet looked: the first gateway's pin goes with the refusal.
    ds[0].stub.add("t0", "big", 63_900);
    let (s, _, body) = call(
        &f.st,
        "PUT",
        "/v1/namespaces/t1/gateway",
        "api",
        Some(gateway_body()),
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(json(&body)["code"], "capacity");
    assert_eq!(pinned(&f.st, "t1"), None);
    assert_eq!(saved(&f.st).namespaces.get("t1"), None, "written");
    // A removal the host refuses passes through.
    ds[0].stub.add("kept", "sbx", 10);
    poll_static_hosts_once(&f.st).await;
    let (s, _, body) = call(&f.st, "DELETE", "/v1/namespaces/kept/gateway", "api", None).await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");
    assert_eq!(json(&body)["code"], "gateway_in_use");
    // A bad namespace id or body is refused before any host.
    let before = ds[0].stub.calls().len();
    for (path, body) in [
        ("/v1/namespaces/Bad/gateway", gateway_body()),
        (
            "/v1/namespaces/t2/gateway",
            serde_json::json!({"image": "proxy:1"}),
        ),
    ] {
        let (s, _, text) = call(&f.st, "PUT", path, "api", Some(body)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{path}: {text}");
        assert_eq!(json(&text)["code"], "invalid");
    }
    assert_eq!(ds[0].stub.calls().len(), before);
    assert_eq!(pinned(&f.st, "t2"), None);
}
