//! Lookups and the lists asked of every host.

use super::*;

#[tokio::test]
async fn a_machine_is_found_through_the_index_then_by_searching() {
    let (f, ds) = fleet_with_daemons(2).await;
    let m = ds[1].stub.add("t1", "web", 512);
    let path = format!("/v1/machines/{}", m.id);
    // Not in the index: every ready host is asked, in order, until one has it.
    let (s, headers, body) = call(&f.st, "GET", &path, "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d2");
    assert_eq!(json(&body)["host"], "d2", "a plain get carries the host");
    assert_eq!(ds[0].stub.calls().last().unwrap(), &format!("GET {path}"));
    assert_eq!(
        ds[1]
            .stub
            .calls()
            .iter()
            .filter(|c| *c == &format!("GET {path}"))
            .count(),
        2,
        "the search, then the forward"
    );
    assert_eq!(
        f.st.reg
            .lock()
            .unwrap()
            .machines
            .get(&m.id)
            .map(String::as_str),
        Some("d2"),
        "learned"
    );
    // In the index: straight to its host, d1 is not asked.
    let d1_before = ds[0].stub.calls().len();
    let (s, headers, body) = call(&f.st, "POST", &format!("{path}/start"), "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d2");
    assert_eq!(
        headers["x-request-id"], "d-req-2",
        "the daemon's request id passes through"
    );
    assert_eq!(ds[0].stub.calls().len(), d1_before);
    assert_eq!(
        ds[1].stub.calls().last().unwrap(),
        &format!("POST {path}/start")
    );
    // A sub-path answer that is not a plain get is passed as is: no host added.
    assert!(json(&body).get("host").is_none(), "{body}");
    // Unknown anywhere: 404 from the fleet, after asking every host.
    let (s, _, body) = call(&f.st, "GET", "/v1/machines/m_nope", "api", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(json(&body)["code"], "not_found");
    assert!(ds.iter().all(|d| d
        .stub
        .calls()
        .contains(&"GET /v1/machines/m_nope".to_string())));
    // A query changes nothing of what the call is: a get carries the host, a delete drops
    // the index entry.
    let with_namespace = format!("{path}?namespace=t1");
    let (s, _, body) = call(&f.st, "GET", &with_namespace, "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(json(&body)["host"], "d2");
    let (s, _, _) = call(&f.st, "DELETE", &with_namespace, "api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(f.st.reg.lock().unwrap().machines.get(&m.id), None);
    assert!(!saved(&f.st).machines.contains_key(&m.id), "written");
}

#[tokio::test]
async fn a_listing_adds_the_host_and_is_never_partial() {
    let (f, ds) = fleet_with_daemons(2).await;
    let a = ds[0].stub.add("t1", "web", 512);
    let b = ds[1].stub.add("t2", "db", 1024);
    let (s, _, body) = call(&f.st, "GET", "/v1/machines", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let ms: Vec<api::Machine> = serde_json::from_str(&body).unwrap();
    let got: Vec<(String, String)> = ms.iter().map(|m| (m.id.clone(), m.host.clone())).collect();
    assert_eq!(
        got,
        [(a.id.clone(), "d1".into()), (b.id.clone(), "d2".into())]
    );
    {
        let reg = f.st.reg.lock().unwrap();
        assert_eq!(reg.machines.get(&a.id).map(String::as_str), Some("d1"));
        assert_eq!(reg.machines.get(&b.id).map(String::as_str), Some("d2"));
    }
    // A host down fails the whole listing: a reader takes a missing machine for gone.
    set_state(&f.st, "d2", "down");
    let d2_before = ds[1].stub.calls().len();
    let (s, _, body) = call(&f.st, "GET", "/v1/machines", "api", None).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    let v = json(&body);
    assert_eq!(v["code"], "host_down");
    assert!(
        v["error"].as_str().unwrap().contains("host d2 is down"),
        "{v}"
    );
    assert_eq!(
        ds[1].stub.calls().len(),
        d2_before,
        "a down host is not asked"
    );
    // A host that does not answer (nothing listens where its record points) fails it too.
    set_state(&f.st, "d2", "ready");
    f.st.reg.lock().unwrap().hosts.get_mut("d2").unwrap().url = "http://127.0.0.1:1".into();
    let (s, _, body) = call(&f.st, "GET", "/v1/machines", "api", None).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(json(&body)["code"], "host_unreachable");
}

#[tokio::test]
async fn a_host_under_pressure_takes_no_new_namespace_and_refuses_its_own() {
    let (f, ds) = fleet_with_daemons(2).await;
    let src = ds[0].stub.add("t1", "web", 512);
    ds[1].stub.add("t0", "big", 30_000);
    *ds[0].stub.conditions.lock().unwrap() = vec![
        pressure(api::condition::MEMORY_PRESSURE, false),
        pressure(api::condition::DISK_PRESSURE, true),
    ];
    poll_static_hosts_once(&f.st).await;
    assert_eq!(pinned(&f.st, "t1").as_deref(), Some("d1"));
    assert_eq!(
        hosts(&f.st)[0].conditions[1],
        ds[0].stub.conditions.lock().unwrap()[1],
        "the poll keeps what the host said"
    );
    // A new namespace goes to d2, though d1 is emptier.
    let (s, headers, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t2", "web", 512)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d2");
    // The namespace on d1: refused before d1 is asked, with the condition, as `capacity`; so is
    // a fork of its machine and its gateway.
    f.st.reg
        .lock()
        .unwrap()
        .machines
        .insert(src.id.clone(), "d1".into());
    let mut fork = create_body("t9", "fork", 512);
    fork["fork"] = serde_json::json!({"machine_id": src.id});
    for (method, path, body) in [
        ("POST", "/v1/machines", create_body("t1", "db", 512)),
        ("POST", "/v1/machines", fork),
        ("PUT", "/v1/namespaces/t1/gateway", gateway_body()),
    ] {
        let (s, _, body) = call(&f.st, method, path, "api", Some(body)).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{path}: {body}");
        assert_eq!(json(&body)["code"], "capacity");
        assert_eq!(
            json(&body)["error"],
            "host d1 is under disk_pressure: pool 4.0 GB free of 100.0 (4%), under 10%"
        );
    }
    assert!(
        !ds[0]
            .stub
            .calls()
            .iter()
            .any(|c| c.starts_with("POST") || c.starts_with("PUT")),
        "d1 was not asked"
    );
    assert_eq!(pinned(&f.st, "t1").as_deref(), Some("d1"), "still pinned");
    // Cleared at the next report: the namespace's create goes through.
    ds[0].stub.conditions.lock().unwrap()[1].status = false;
    poll_static_hosts_once(&f.st).await;
    let (s, headers, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t1", "db", 512)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d1");
}

#[tokio::test]
async fn top_asks_the_namespaces_host_or_every_host_never_partially() {
    let (f, ds) = fleet_with_daemons(2).await;
    ds[0].stub.add("t1", "web", 512);
    ds[1].stub.add("t2", "db", 512);
    poll_static_hosts_once(&f.st).await;
    let d2_before = ds[1].stub.calls().len();
    let (s, _, body) = call(&f.st, "GET", "/v1/top?namespace=t1", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let ms: Vec<api::TopMachine> = serde_json::from_str(&body).unwrap();
    let got: Vec<(&str, &str)> = ms
        .iter()
        .map(|m| (m.name.as_str(), m.host.as_str()))
        .collect();
    assert_eq!(got, [("web", "d1")]);
    assert_eq!(
        ds[0].stub.calls().last().unwrap(),
        "GET /v1/top?namespace=t1"
    );
    assert_eq!(ds[1].stub.calls().len(), d2_before, "d2 was not asked");
    let (s, _, body) = call(&f.st, "GET", "/v1/top", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let ms: Vec<api::TopMachine> = serde_json::from_str(&body).unwrap();
    let got: Vec<(&str, &str)> = ms
        .iter()
        .map(|m| (m.name.as_str(), m.host.as_str()))
        .collect();
    assert_eq!(got, [("web", "d1"), ("db", "d2")]);
    // A host down fails the whole answer.
    set_state(&f.st, "d2", "down");
    let (s, _, body) = call(&f.st, "GET", "/v1/top", "api", None).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(json(&body)["code"], "host_down");
}

#[tokio::test]
async fn usage_asks_every_host_and_is_never_partial() {
    let (f, ds) = fleet_with_daemons(2).await;
    let q = "/v1/usage?from=2026-10-20T14:00:00Z&to=2026-10-20T15:00:00Z&namespace=t1";
    let (s, _, body) = call(&f.st, "GET", q, "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let bs: Vec<api::UsageBucket> = serde_json::from_str(&body).unwrap();
    let got: Vec<(&str, &str)> = bs
        .iter()
        .map(|b| (b.machine_id.as_str(), b.host.as_str()))
        .collect();
    assert_eq!(got, [("m_d1", "d1"), ("m_d2", "d2")]);
    for d in &ds {
        assert_eq!(
            d.stub.calls().last().unwrap(),
            &format!("GET {q}"),
            "every host, the query as it came"
        );
    }
    // The hosts check the range: their refusal is the answer.
    let (s, _, body) = call(&f.st, "GET", "/v1/usage?to=x", "api", None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["code"], "invalid");
    // A host down fails the whole report, without asking it: a report missing a host
    // undercounts.
    set_state(&f.st, "d2", "down");
    let d2_before = ds[1].stub.calls().len();
    let (s, _, body) = call(&f.st, "GET", q, "api", None).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(json(&body)["code"], "host_down");
    assert_eq!(ds[1].stub.calls().len(), d2_before);
    // A host that does not answer fails it too.
    set_state(&f.st, "d2", "ready");
    f.st.reg.lock().unwrap().hosts.get_mut("d2").unwrap().url = "http://127.0.0.1:1".into();
    let (s, _, body) = call(&f.st, "GET", q, "api", None).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(json(&body)["code"], "host_unreachable");
}

#[tokio::test]
async fn a_namespace_listing_asks_its_host_alone() {
    let (f, ds) = fleet_with_daemons(2).await;
    ds[0].stub.add("t1", "web", 512);
    ds[1].stub.add("t2", "db", 512);
    poll_static_hosts_once(&f.st).await;
    assert_eq!(
        pinned(&f.st, "t1").as_deref(),
        Some("d1"),
        "the poll pins the namespaces the hosts list"
    );
    set_state(&f.st, "d2", "down");
    let d2_before = ds[1].stub.calls().len();
    let (s, _, body) = call(&f.st, "GET", "/v1/machines?namespace=t1", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let ms: Vec<api::Machine> = serde_json::from_str(&body).unwrap();
    assert_eq!(ms.len(), 1);
    assert_eq!(ms[0].namespace, "t1");
    assert_eq!(ms[0].host, "d1");
    assert_eq!(
        ds[0].stub.calls().last().unwrap(),
        "GET /v1/machines?namespace=t1",
        "the query is passed on"
    );
    assert_eq!(ds[1].stub.calls().len(), d2_before, "d2 was not asked");
    // Its own host down: the namespace's listing fails, nothing else is asked.
    let (s, _, body) = call(&f.st, "GET", "/v1/machines?namespace=t2", "api", None).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    // A namespace the fleet has not pinned: every host, so the answer is still whole.
    set_state(&f.st, "d2", "ready");
    let (s, _, body) = call(&f.st, "GET", "/v1/machines?namespace=t3", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(json(&body).as_array().unwrap().len(), 0);
    assert_eq!(
        ds[1].stub.calls().last().unwrap(),
        "GET /v1/machines?namespace=t3"
    );
}

#[tokio::test]
async fn a_machine_on_a_down_host_answers_503() {
    let (f, ds) = fleet_with_daemons(1).await;
    let m = ds[0].stub.add("t1", "web", 512);
    f.st.reg
        .lock()
        .unwrap()
        .machines
        .insert(m.id.clone(), "d1".into());
    set_state(&f.st, "d1", "down");
    let before = ds[0].stub.calls().len();
    for (method, path) in [
        ("GET", format!("/v1/machines/{}", m.id)),
        ("POST", format!("/v1/machines/{}/stop", m.id)),
        ("DELETE", format!("/v1/machines/{}", m.id)),
    ] {
        let (s, _, body) = call(&f.st, method, &path, "api", None).await;
        assert_eq!(
            s,
            StatusCode::SERVICE_UNAVAILABLE,
            "{method} {path}: {body}"
        );
        let v = json(&body);
        assert_eq!(v["code"], "host_down");
        assert!(
            v["error"].as_str().unwrap().contains("host d1 is down"),
            "{v}"
        );
    }
    assert_eq!(ds[0].stub.calls().len(), before, "the host was not asked");
    assert_eq!(
        f.st.reg
            .lock()
            .unwrap()
            .machines
            .get(&m.id)
            .map(String::as_str),
        Some("d1"),
        "a failed delete keeps the index entry"
    );
}

#[tokio::test]
async fn the_namespaces_are_listed_as_their_hosts_know_them() {
    let (f, ds) = fleet_with_daemons(3).await;
    ds[0].stub.add("t1", "web", 512);
    ds[0].stub.add("t1", "db", 512);
    ds[1].stub.add("t2", "web", 512);
    ds[2].stub.add("t3", "web", 512);
    {
        let mut reg = f.st.reg.lock().unwrap();
        for (t, h) in [("t1", "d1"), ("t2", "d2"), ("t3", "d3")] {
            reg.namespaces.insert(t.into(), h.into());
        }
    }
    let list = || async {
        let (s, _, body) = call(&f.st, "GET", "/v1/namespaces", "api", None).await;
        assert_eq!(s, StatusCode::OK, "{body}");
        serde_json::from_str::<Vec<api::Namespace>>(&body).unwrap()
    };
    let ts = list().await;
    let got: Vec<_> = ts
        .iter()
        .map(|t| {
            (
                t.id.as_str(),
                t.host.as_str(),
                t.machines,
                t.subnet.as_str(),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            ("t1", "d1", 2, "10.1.0.0/24"),
            ("t2", "d2", 1, "10.2.0.0/24"),
            ("t3", "d3", 1, "10.3.0.0/24"),
        ]
    );
    assert!(ts
        .iter()
        .all(|t| t.host_state.is_empty() && t.router.ends_with(".0.1")));
    assert!(ts.iter().all(|t| t.region == "fsn"));
    // A host the fleet marked down is not asked; its namespace stays, marked.
    set_state(&f.st, "d2", "down");
    let d2_before = ds[1].stub.calls().len();
    let ts = list().await;
    assert_eq!(
        ds[1].stub.calls().len(),
        d2_before,
        "a down host is not asked"
    );
    let t2 = ts.iter().find(|t| t.id == "t2").unwrap();
    assert_eq!((t2.host.as_str(), t2.host_state.as_str()), ("d2", "down"));
    assert_eq!((t2.machines, t2.subnet.as_str()), (0, ""));
    // A host that does not answer is marked the same way; the others keep their numbers.
    set_state(&f.st, "d2", "ready");
    f.st.reg.lock().unwrap().hosts.get_mut("d3").unwrap().url = "http://127.0.0.1:1".into();
    let ts = list().await;
    let state: Vec<_> = ts.iter().map(|t| t.host_state.as_str()).collect();
    assert_eq!(state, ["", "", "unreachable"]);
    assert_eq!(
        (ts[0].machines, ts[1].machines, ts[1].subnet.as_str()),
        (2, 1, "10.2.0.0/24")
    );
    // The mark is on the wire only when set.
    let (_, _, body) = call(&f.st, "GET", "/v1/namespaces", "api", None).await;
    let v = json(&body);
    assert!(v[0].get("host_state").is_none(), "{v}");
    assert_eq!(v[2]["host_state"], "unreachable");
}
