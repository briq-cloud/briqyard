//! Exec sessions (ADR 0029).

use super::*;

/// The fleet on a port of its own: an upgrade needs a real connection.
async fn serve_fleet(f: &Fleet) -> String {
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    let app = app(f.st.clone());
    tokio::spawn(async move { axum::serve(ln, app).await.unwrap() });
    addr.to_string()
}

#[tokio::test]
async fn a_session_is_relayed_unchanged_to_the_machines_host() {
    use api::session::{channel, message, parse};
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};
    let (f, ds) = fleet_with_daemons(2).await;
    let m = ds[1].stub.add("t1", "sbx", 512);
    let addr = serve_fleet(&f).await;
    let mut req = format!("ws://{addr}/v1/machines/{}/exec?cmd=sh&tty=true", m.id)
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("authorization", "Bearer api".parse().unwrap());
    let tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let (mut ws, resp) = tokio_tungstenite::client_async(req, tcp).await.unwrap();
    assert_eq!(resp.headers()["x-briqyard-host"], "d2");
    // The handshake reached the machine's host, with its query and the host's token.
    assert_eq!(
        ds[1].stub.calls().last().unwrap(),
        &format!("GET /v1/machines/{}/exec?cmd=sh&tty=true", m.id)
    );
    ws.send(Message::Binary(message(channel::STDIN, b"hi\n")))
        .await
        .unwrap();
    let Some(Ok(Message::Binary(b))) = ws.next().await else {
        panic!("no echo")
    };
    assert_eq!(parse(&b), Some((channel::STDOUT, &b"hi\n"[..])));
    ws.send(Message::Binary(message(channel::CLOSE, &[channel::STDIN])))
        .await
        .unwrap();
    let Some(Ok(Message::Binary(b))) = ws.next().await else {
        panic!("no exit")
    };
    assert_eq!(parse(&b), Some((channel::EXIT, &br#"{"exit_code":7}"#[..])));
}

#[tokio::test]
async fn a_session_refused_by_the_host_or_not_a_websocket_is_an_answer() {
    let (f, ds) = fleet_with_daemons(1).await;
    let m = ds[0].stub.add("t1", "sbx", 512);
    let addr = serve_fleet(&f).await;
    let http = reqwest::Client::new();
    // Not an upgrade: refused by the fleet, before any host is asked.
    let r = http
        .get(format!("http://{addr}/v1/machines/{}/exec?cmd=sh", m.id))
        .bearer_auth("api")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(&r.text().await.unwrap())["code"], "invalid");
    // A machine no host has: 404, as for every machine route.
    let upgrade = |url: String| {
        http.get(url)
            .bearer_auth("api")
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .send()
    };
    let r = upgrade(format!("http://{addr}/v1/machines/m_none/exec?cmd=sh"))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    // The host's refusal comes back as it said it.
    ds[0].stub.machines.lock().unwrap()[0].state = api::state::STOPPED.into();
    let r = upgrade(format!("http://{addr}/v1/machines/{}/exec?cmd=sh", m.id))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(r.headers()["x-briqyard-host"], "d1");
    assert_eq!(json(&r.text().await.unwrap())["code"], "not_running");
}

#[tokio::test]
async fn a_host_unreachable_never_shows_the_sessions_query() {
    // The query holds the session's env: an error names the host, never the URL.
    let (f, ds) = fleet_with_daemons(1).await;
    let m = ds[0].stub.add("t1", "sbx", 512);
    f.st.reg
        .lock()
        .unwrap()
        .machines
        .insert(m.id.clone(), "d1".into());
    f.st.reg.lock().unwrap().hosts.get_mut("d1").unwrap().url = "http://127.0.0.1:1".into();
    let addr = serve_fleet(&f).await;
    let r = reqwest::Client::new()
        .get(format!(
            "http://{addr}/v1/machines/{}/exec?cmd=sh&env=TOKEN=hunter2",
            m.id
        ))
        .bearer_auth("api")
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_GATEWAY);
    let body = r.text().await.unwrap();
    assert_eq!(json(&body)["code"], "host_unreachable");
    assert!(
        !body.contains("hunter2") && !body.contains("exec?"),
        "{body}"
    );
}

/// A create with `restore` opens that restore for its host while the forward lasts, and closes
/// it after: a backup's key is asked for during the create, never after it (ADR 0035).
#[tokio::test]
async fn a_forwarded_restore_is_open_during_its_create_alone() {
    let (f, ds) = fleet_with_daemons(1).await;
    let rs = api::RestoreSpec {
        machine_id: "m_src".into(),
        backup: "b1".into(),
    };
    let restore = |name: &str| {
        let mut body = create_body("t1", name, 256);
        body["restore"] = serde_json::to_value(&rs).unwrap();
        Some(body)
    };
    let seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let (st, seen, rs) = (f.st.clone(), seen.clone(), rs.clone());
        *ds[0].stub.on_create.lock().unwrap() = Some(Box::new(move || {
            let open = st.restores.take("d1", &rs, std::time::Instant::now());
            seen.store(open, Ordering::SeqCst);
        }));
    }
    let (s, _, body) = call(&f.st, "POST", "/v1/machines", "api", restore("r1")).await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert!(seen.load(Ordering::SeqCst), "open while the host made it");
    // A forward that never asked: closed once it is over.
    *ds[0].stub.on_create.lock().unwrap() = None;
    let (s, _, body) = call(&f.st, "POST", "/v1/machines", "api", restore("r2")).await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert!(
        !f.st.restores.take("d1", &rs, std::time::Instant::now()),
        "closed after"
    );
}

#[tokio::test]
async fn the_former_names_are_still_answered() {
    // ADR 0055: `/v1/tenants` is `/v1/namespaces`, and `tenant=` is `namespace=`.
    let (f, ds) = fleet_with_daemons(1).await;
    ds[0].stub.add("kept", "db", 512);
    poll_static_hosts_once(&f.st).await;
    let (s, _, body) = call(&f.st, "GET", "/v1/tenants", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let (s, _, body) = call(&f.st, "POST", "/v1/tenants/kept/unpin", "api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(pinned(&f.st, "kept"), None);
    for q in ["namespace=kept", "tenant=kept"] {
        let uri: Uri = format!("/v1/top?{q}").parse().unwrap();
        assert_eq!(query_namespace(&uri).as_deref(), Some("kept"), "{q}");
    }
}

#[test]
fn a_registry_written_before_the_rename_loads() {
    let old = r#"{"hosts":{},"tenants":{"t1":"h1"},"machines":{}}"#;
    let reg: Registry = serde_json::from_str(old).unwrap();
    assert_eq!(reg.namespaces.get("t1").map(String::as_str), Some("h1"));
    let now = serde_json::to_value(&reg).unwrap();
    assert!(now.get("tenants").is_none());
    assert_eq!(now["namespaces"]["t1"], "h1");
}

/// The fleet and two daemons with a machine `web` in `t1` on d1, an endpoint on it, and
/// namespace `t2` on d2.
async fn fleet_with_a_machine_to_move() -> (Fleet, Vec<Running>, api::Machine) {
    let (f, ds) = fleet_with_daemons(2).await;
    let web = ds[0].stub.add("t1", "web", 512);
    ds[0].stub.add_endpoint(&web.id);
    ds[1].stub.add("t2", "db", 512);
    poll_static_hosts_once(&f.st).await;
    {
        let mut reg = f.st.reg.lock().unwrap();
        reg.machines.insert(web.id.clone(), "d1".into());
        reg.namespaces.insert("t1".into(), "d1".into());
        reg.namespaces.insert("t2".into(), "d2".into());
    }
    (f, ds, web)
}

fn move_to(namespace: &str) -> Option<serde_json::Value> {
    Some(serde_json::json!({ "namespace": namespace }))
}

#[tokio::test]
async fn a_move_within_a_host_is_the_hosts_and_pins_a_new_namespace() {
    let (f, ds, web) = fleet_with_a_machine_to_move().await;
    let path = format!("/v1/machines/{}/move", web.id);
    let (s, _, body) = call(&f.st, "POST", &path, "api", move_to("t7")).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let r: api::MoveResult = serde_json::from_str(&body).unwrap();
    assert_eq!((r.from.as_str(), r.restarted), ("t1", false));
    assert_eq!(
        (r.machine.namespace.as_str(), r.machine.host.as_str()),
        ("t7", "d1")
    );
    assert_eq!(
        pinned(&f.st, "t7").as_deref(),
        Some("d1"),
        "pinned where it was made"
    );
    assert!(
        ds[1].stub.calls().iter().all(|c| !c.contains("move")),
        "d2 not asked"
    );
    // Into a namespace the host has: a restart, a new address.
    let (s, _, body) = call(&f.st, "POST", &path, "api", move_to("t1")).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    ds[0].stub.add("t8", "other", 128);
    let (s, _, body) = call(&f.st, "POST", &path, "api", move_to("t8")).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let r: api::MoveResult = serde_json::from_str(&body).unwrap();
    assert!(r.restarted && r.machine.ip == "10.9.0.7" && r.previous_ip != r.machine.ip);
    // A namespace id that is not one is refused before any host.
    let (s, _, _) = call(&f.st, "POST", &path, "api", move_to("../x")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_move_to_a_namespace_on_another_host_is_refused_before_anything_happens() {
    let (f, ds, web) = fleet_with_a_machine_to_move().await;
    let before: Vec<usize> = ds.iter().map(|d| d.stub.calls().len()).collect();
    let path = format!("/v1/machines/{}/move", web.id);
    let (s, _, body) = call(&f.st, "POST", &path, "api", move_to("t2")).await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");
    let v = json(&body);
    assert_eq!(v["code"], "other_host");
    let msg = v["error"].as_str().unwrap();
    assert!(
        msg.contains("t2")
            && msg.contains("d2")
            && msg.contains("d1")
            && msg.contains("not supported yet"),
        "{msg}"
    );
    // Neither host was asked, and the machine is where it was.
    let after: Vec<usize> = ds.iter().map(|d| d.stub.calls().len()).collect();
    assert_eq!(before, after, "no call to either host");
    assert_eq!(ds[0].stub.machines.lock().unwrap().len(), 1);
    assert_eq!(
        f.st.reg
            .lock()
            .unwrap()
            .machines
            .get(&web.id)
            .map(String::as_str),
        Some("d1")
    );
}

#[tokio::test]
async fn a_fork_may_name_a_namespace_of_its_hosts_and_not_one_of_another() {
    let (f, ds, web) = fleet_with_a_machine_to_move().await;
    // A new namespace: made on the source's host and pinned there.
    let mut body = create_body("t9", "web-fork", 256);
    body["fork"] = serde_json::json!({"machine_id": web.id});
    let (s, headers, _) = call(&f.st, "POST", "/v1/machines", "api", Some(body)).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(headers["x-briqyard-host"], "d1");
    assert_eq!(pinned(&f.st, "t9").as_deref(), Some("d1"));
    // A namespace that lives on d2: refused, nothing sent to either host.
    let before: usize = ds.iter().map(|d| d.stub.calls().len()).sum();
    let mut body = create_body("t2", "web-fork", 256);
    body["fork"] = serde_json::json!({"machine_id": web.id});
    let (s, _, body) = call(&f.st, "POST", "/v1/machines", "api", Some(body)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        json(&body)["error"]
            .as_str()
            .unwrap()
            .contains("on its source's host"),
        "{body}"
    );
    let after: usize = ds.iter().map(|d| d.stub.calls().len()).sum();
    assert_eq!(before, after);
}
