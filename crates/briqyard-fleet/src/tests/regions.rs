//! Placement by region, labels, quotas, logs follow (ADR 0025).

use super::*;

fn in_region(namespace: &str, name: &str, region: &str) -> serde_json::Value {
    let mut b = create_body(namespace, name, 512);
    b["region"] = region.into();
    b
}

#[tokio::test]
async fn a_namespace_is_placed_in_its_region_and_never_leaves_it() {
    let (f, ds) = fleet_in_regions(&["gra", "vin"]).await;
    // d1 is fuller: by memory alone, t1 would go to d2.
    ds[0].stub.add("t0", "big", 10_000);
    poll_static_hosts_once(&f.st).await;
    let create = |body| call(&f.st, "POST", "/v1/machines", "api", Some(body));
    let (s, headers, body) = create(in_region("t1", "a", "gra")).await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d1");
    assert_eq!(f.st.reg.lock().unwrap().region_of("t1"), Some("gra"));
    // Its next machine in another region: refused before any host is asked.
    let before: Vec<usize> = ds.iter().map(|d| d.stub.calls().len()).collect();
    let (s, _, body) = create(in_region("t1", "b", "vin")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["code"], "invalid");
    assert_eq!(
        json(&body)["error"],
        "namespace t1 is in region \"gra\" (host d1), not \"vin\": a namespace never spans regions"
    );
    // A fork is bound to its source's host, so to its region.
    let src = json(&create(in_region("t1", "c", "")).await.2)["id"]
        .as_str()
        .unwrap()
        .to_string();
    let mut fork = in_region("t1", "f", "vin");
    fork["fork"] = serde_json::json!({ "machine_id": src });
    let (s, _, body) = create(fork).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    let after: Vec<usize> = ds.iter().map(|d| d.stub.calls().len()).collect();
    assert_eq!(after[1], before[1], "d2 was never asked");
    // No region: any, and a pinned namespace stays.
    let (s, headers, _) = create(in_region("t2", "a", "")).await;
    assert_eq!(
        (s, &headers["x-briqyard-host"]),
        (StatusCode::CREATED, &HeaderValue::from_static("d2"))
    );
    // A region with no host: 503, naming it.
    let (s, _, body) = create(in_region("t3", "a", "sgp")).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(json(&body)["code"], "capacity");
    assert_eq!(
        json(&body)["error"],
        "no host in region sgp has room for this machine"
    );
    assert_eq!(pinned(&f.st, "t3"), None);
    // The namespaces say where they are.
    let (_, _, body) = call(&f.st, "GET", "/v1/namespaces", "api", None).await;
    let ts: Vec<api::Namespace> = serde_json::from_str(&body).unwrap();
    let t1 = ts.iter().find(|t| t.id == "t1").unwrap();
    assert_eq!((t1.host.as_str(), t1.region.as_str()), ("d1", "gra"));
    let (_, _, body) = call(&f.st, "GET", "/v1/namespaces/t1", "api", None).await;
    assert_eq!(json(&body)["region"], "gra");
    // A gateway places a new namespace in the region its query names.
    let (s, headers, body) = call(
        &f.st,
        "PUT",
        "/v1/namespaces/t4/gateway?region=vin",
        "api",
        Some(gateway_body()),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d2");
    assert_eq!(
        ds[1].stub.calls().last().unwrap(),
        "PUT /v1/namespaces/t4/gateway",
        "where to place is the fleet's: the host gets the spec"
    );
}

#[tokio::test]
async fn a_quota_goes_to_the_namespaces_host_and_places_a_new_one() {
    let (f, ds) = fleet_in_regions(&["gra", "vin"]).await;
    let quota = serde_json::json!({"machines": 3, "memory_mb": 2048});
    // No host yet: placed in the region asked, with no need, and forwarded there.
    let (s, headers, body) = call(
        &f.st,
        "PUT",
        "/v1/namespaces/t1/quota?region=vin",
        "api",
        Some(quota.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d2");
    assert_eq!(pinned(&f.st, "t1").as_deref(), Some("d2"));
    assert_eq!(
        saved(&f.st).namespaces.get("t1").map(String::as_str),
        Some("d2")
    );
    assert_eq!(f.st.reg.lock().unwrap().hosts["d2"].used.memory_mb, 0);
    let (s, _, body) = call(&f.st, "GET", "/v1/namespaces/t1/quota", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let q: api::NamespaceQuota = serde_json::from_str(&body).unwrap();
    assert_eq!((q.quota.machines, q.quota.memory_mb), (Some(3), Some(2048)));
    assert_eq!(
        ds[1].stub.calls().last().unwrap(),
        "GET /v1/namespaces/t1/quota"
    );
    // Pinned: the next put goes to its host, and another region is refused.
    let (s, _, _) = call(
        &f.st,
        "PUT",
        "/v1/namespaces/t1/quota",
        "api",
        Some(quota.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(ds[1].stub.quotas.lock().unwrap().len(), 2);
    let (s, _, body) = call(
        &f.st,
        "PUT",
        "/v1/namespaces/t1/quota?region=gra",
        "api",
        Some(quota),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    // A body that is not a quota is refused before anything is placed; a namespace with no host
    // has no quota to read.
    let (s, _, _) = call(
        &f.st,
        "PUT",
        "/v1/namespaces/t2/quota",
        "api",
        Some(serde_json::json!({"machines": -1})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(pinned(&f.st, "t2"), None);
    let (s, _, _) = call(&f.st, "GET", "/v1/namespaces/t2/quota", "api", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(ds[0].stub.quotas.lock().unwrap().is_empty());
}

#[tokio::test]
async fn labels_are_passed_to_the_hosts_and_a_listing_stays_whole() {
    let (f, ds) = fleet_with_daemons(2).await;
    let label = |d: &Running, namespace: &str, name: &str, app: &str| {
        let mut m = d.stub.add(namespace, name, 256);
        m.metadata.insert("app".into(), app.into());
        let mut ms = d.stub.machines.lock().unwrap();
        *ms.iter_mut().find(|x| x.id == m.id).unwrap() = m.clone();
        m
    };
    let web1 = label(&ds[0], "t1", "web", "web");
    label(&ds[0], "t1", "db", "db");
    let web2 = label(&ds[1], "t2", "web", "web");
    poll_static_hosts_once(&f.st).await;
    let ids = |body: &str| -> Vec<String> {
        let ms: Vec<api::Machine> = serde_json::from_str(body).unwrap();
        ms.into_iter().map(|m| m.id).collect()
    };
    // Every host, the query as it came.
    let (s, _, body) = call(&f.st, "GET", "/v1/machines?label=app%3Dweb", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(ids(&body), [web1.id.as_str(), web2.id.as_str()]);
    for d in &ds {
        assert_eq!(
            d.stub.calls().last().unwrap(),
            "GET /v1/machines?label=app%3Dweb"
        );
    }
    // A namespace's: its host alone.
    let before = ds[1].stub.calls().len();
    let (_, _, body) = call(
        &f.st,
        "GET",
        "/v1/machines?namespace=t1&label=app=web&label=app",
        "api",
        None,
    )
    .await;
    assert_eq!(ids(&body), [web1.id.as_str()]);
    assert_eq!(ds[1].stub.calls().len(), before);
    // One host down: the selection fails whole, as any listing.
    set_state(&f.st, "d2", "down");
    let (s, _, body) = call(&f.st, "GET", "/v1/machines?label=app", "api", None).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(json(&body)["code"], "host_down");
}

#[tokio::test]
async fn a_logs_follow_is_streamed_through_as_it_comes() {
    let (f, ds) = fleet_with_daemons(1).await;
    let m = ds[0].stub.add("t1", "web", 512);
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", ln.local_addr().unwrap());
    let app = app(f.st.clone());
    tokio::spawn(async move { axum::serve(ln, app).await.unwrap() });
    let mut w = reqwest::Client::new()
        .get(format!(
            "{url}/v1/machines/{}/logs?since=12&follow=true",
            m.id
        ))
        .bearer_auth("api")
        .send()
        .await
        .unwrap();
    assert_eq!(w.status(), StatusCode::OK);
    assert_eq!(w.headers()["content-type"], "application/x-ndjson");
    assert_eq!(w.headers()["x-briqyard-host"], "d1");
    assert_eq!(
        ds[0].stub.calls().last().unwrap(),
        &format!("GET /v1/machines/{}/logs?since=12&follow=true", m.id)
    );
    // Each line the host sends reaches the client while the stream stays open.
    let tx = ds[0].stub.watcher.lock().unwrap().clone().unwrap();
    for line in ["one", "two"] {
        let l = serde_json::json!({"ts": "2026-10-21T10:00:00Z", "line": line});
        tx.send(l.to_string() + "\n").await.unwrap();
        assert_eq!(chunk(&mut w).await["line"], line);
    }
}
