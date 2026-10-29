//! Adding, retiring, draining, forgetting and the poll of static hosts; namespaces unpinned.

use super::*;

/// The fleet buys no server (ADR 0042): the order route is gone, and nothing is recorded.
#[tokio::test]
async fn there_is_no_order() {
    let f = fleet(config::Config::default());
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/hosts/order",
        "",
        Some(serde_json::json!({"reason": "x"})),
    )
    .await;
    assert!(
        matches!(s, StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED),
        "{s}: {body}"
    );
    assert!(hosts(&f.st).is_empty(), "nothing recorded");
}

/// A fleet that bootstraps the hosts added to it, its APIs on the 10.42.0.0/16 vRack.
fn bootstrapping_fleet() -> Fleet {
    let mut cfg = config::Config::default();
    cfg.bootstrap.enabled = true;
    cfg.bootstrap.private_network = "10.42.0.0/16".into();
    cfg.bootstrap.public_tcp_ports = vec![80, 443];
    fleet(cfg)
}

#[tokio::test]
async fn a_server_bought_by_hand_is_added_for_the_bootstrap() {
    let f = bootstrapping_fleet();
    let add = |body: serde_json::Value| {
        let st = f.st.clone();
        async move { call(&st, "POST", "/v1/hosts", "", Some(body)).await }
    };
    let (s, _, body) =
        add(serde_json::json!({"ssh": "51.68.1.2", "address": "10.42.0.11", "region": "gra"}))
            .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{body}");
    let h: api::Host = serde_json::from_str(&body).unwrap();
    assert_eq!(h.id, "h_10-42-0-11");
    assert_eq!(
        h.url, "https://10.42.0.11:7420",
        "its API on the vRack, over TLS"
    );
    assert_eq!(h.ssh, "51.68.1.2");
    assert_eq!(
        (h.state.as_str(), h.provider.as_str(), h.region.as_str()),
        ("provisioning", "manual", "gra")
    );
    assert_eq!(h.tls_fingerprint, "", "pinned by the bootstrap");
    {
        let reg = f.st.reg.lock().unwrap();
        let rec = &reg.hosts["h_10-42-0-11"];
        assert_eq!(rec.token.len(), 32, "a token of its own for its API");
        let picked: Vec<String> = bootstrap::to_install(&reg)
            .into_iter()
            .map(|h| h.id)
            .collect();
        assert_eq!(picked, ["h_10-42-0-11"], "the bootstrap takes it");
    }
    assert!(saved(&f.st).hosts.contains_key("h_10-42-0-11"), "written");
    assert_eq!(
        h.public_tcp_ports,
        [80, 443],
        "the fleet's, kept on the host"
    );
    // One address only: the API there too, its id named; no public ports of its own (a host
    // without an edge), whatever the fleet's are.
    let (s, _, body) = add(serde_json::json!({
        "ssh": "51.68.1.3", "id": "gra-2", "public_tcp_ports": []
    }))
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{body}");
    let h: api::Host = serde_json::from_str(&body).unwrap();
    assert_eq!(
        (h.id.as_str(), h.url.as_str(), h.ssh.as_str()),
        ("gra-2", "https://51.68.1.3:7420", "")
    );
    assert_eq!(
        f.st.reg.lock().unwrap().hosts["gra-2"].public_tcp_ports,
        Some(vec![]),
        "its own, empty: never the fleet's"
    );
    // The same server again, by its address, its id or its SSH address.
    for body in [
        serde_json::json!({"ssh": "51.68.1.9", "address": "10.42.0.11"}),
        serde_json::json!({"ssh": "51.68.1.9", "address": "10.42.0.12", "id": "gra-2"}),
        serde_json::json!({"ssh": "51.68.1.2", "address": "10.42.0.13"}),
    ] {
        let (s, _, text) = add(body).await;
        assert_eq!(s, StatusCode::CONFLICT, "{text}");
        assert_eq!(json(&text)["code"], "conflict", "{text}");
    }
    // What makes no host.
    for (body, msg) in [
        (
            serde_json::json!({"ssh": ""}),
            "ssh \"\": want the server's address or name",
        ),
        (
            serde_json::json!({"ssh": "-oProxyCommand=x"}),
            "want the server's address or name",
        ),
        (
            serde_json::json!({"ssh": "root@1.2.3.4"}),
            "want the server's address or name",
        ),
        (
            serde_json::json!({"ssh": "1.2.3.4:2222"}),
            "want the server's address or name",
        ),
        (
            serde_json::json!({"ssh": "server.example"}),
            "address \"server.example\": want the API's IPv4 address",
        ),
        (
            serde_json::json!({"ssh": "51.68.1.2", "address": "192.168.1.5"}),
            "is not in bootstrap.private_network",
        ),
        (
            serde_json::json!({"ssh": "51.68.1.4", "id": "Gra 1"}),
            "id \"Gra 1\": a-z, 0-9, _ and -",
        ),
        (
            serde_json::json!({"ssh": "51.68.1.4", "public_tcp_ports": [443, 0]}),
            "public_tcp_ports: 0 is not a port",
        ),
    ] {
        let (s, _, text) = add(body.clone()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}: {text}");
        let m = json(&text)["error"].as_str().unwrap().to_string();
        assert!(m.contains(msg), "{body}: {m}");
    }
    assert_eq!(hosts(&f.st).len(), 2, "nothing recorded for a refusal");
    // A fleet that bootstraps nothing adds nothing.
    let off = fleet(config::Config::default());
    let (s, _, text) = call(
        &off.st,
        "POST",
        "/v1/hosts",
        "",
        Some(serde_json::json!({"ssh": "51.68.1.2"})),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{text}");
    assert_eq!(json(&text)["code"], "bootstrap_off");
}

#[tokio::test]
async fn an_added_host_turns_ready_at_its_first_heartbeat_on_its_private_address() {
    let f = bootstrapping_fleet();
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/hosts",
        "",
        Some(serde_json::json!({"ssh": "51.68.1.2", "address": "10.42.0.11"})),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{body}");
    let token = f.st.reg.lock().unwrap().hosts["h_10-42-0-11"].token.clone();
    let fp = "ab".repeat(32);
    bootstrap::bootstrapped(
        f.st.reg
            .lock()
            .unwrap()
            .hosts
            .get_mut("h_10-42-0-11")
            .unwrap(),
        "bootstrapped".into(),
        fp.clone(),
    );
    let mut hb = heartbeat("https://10.42.0.11:7420", 64_000, &[]);
    hb["tls_fingerprint"] = fp.clone().into();
    // From its public address, it is no host the fleet expects.
    let mut public = hb.clone();
    public["url"] = "https://51.68.1.2:7420".into();
    let (s, _, text) = call(&f.st, "POST", "/v1/hosts/register", &token, Some(public)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{text}");
    let (s, _, text) = call(&f.st, "POST", "/v1/hosts/register", &token, Some(hb)).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{text}");
    let h = &hosts(&f.st)[0];
    assert_eq!((h.state.as_str(), h.provider.as_str()), ("ready", "manual"));
    assert_eq!(h.ssh, "51.68.1.2", "kept for the next bootstrap");
    assert_eq!(h.tls_fingerprint, fp);
}

#[tokio::test]
async fn retire_forgets_an_empty_host_at_once() {
    let f = fleet(config::Config::default());
    seed(&f.st, "h_a", 1000, 0, 0, &[]);
    {
        let mut reg = f.st.reg.lock().unwrap();
        // Stale index entries from a machine long gone and a namespace never confirmed.
        reg.machines.insert("m9".into(), "h_a".into());
        reg.endpoints.insert("e9".into(), "h_a".into());
        reg.namespaces.insert("t9".into(), "h_a".into());
    }
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/h_a/retire", "", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let h: api::Host = serde_json::from_str(&body).unwrap();
    assert_eq!(h.id, "h_a");
    assert_eq!(h.state, "retired");
    assert!(hosts(&f.st).is_empty(), "forgotten");
    assert!(!saved(&f.st).hosts.contains_key("h_a"), "and written");
    {
        let reg = f.st.reg.lock().unwrap();
        assert!(reg.machines.is_empty(), "its index goes with it");
        assert!(reg.endpoints.is_empty());
        assert!(reg.namespaces.is_empty());
    }
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/h_a/retire", "", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn retire_keeps_a_busy_host_until_it_empties() {
    let f = fleet(config::Config::default());
    seed(&f.st, "h_b", 64_000, 4_000, 2, &["t1"]);
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/h_b/retire", "", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let h: api::Host = serde_json::from_str(&body).unwrap();
    assert_eq!(h.state, "retiring");
    assert_eq!(h.machines, 2);
    let listed = hosts(&f.st);
    assert_eq!(listed.len(), 1, "still here");
    assert_eq!(listed[0].state, "retiring");
    assert!(f.st.reg.lock().unwrap().retirable().is_empty());
    // Asked again while busy: still retiring, not forgotten.
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/h_b/retire", "", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(json(&body)["state"], "retiring");
    // Its last machine goes (a heartbeat says so): `forget_retired`'s pass would forget it.
    {
        let mut reg = f.st.reg.lock().unwrap();
        let mut empty = reg.hosts["h_b"].clone();
        empty.machines = 0;
        empty.namespaces.clear();
        reg.heartbeat(empty, Utc::now());
        reg.namespaces.clear();
        assert_eq!(reg.retirable().len(), 1);
    }
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/h_b/retire", "", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(json(&body)["state"], "retired");
    assert!(hosts(&f.st).is_empty());
}

#[tokio::test]
async fn drain_and_forget() {
    let f = fleet(config::Config::default());
    seed(&f.st, "h_a", 64_000, 0, 1, &["t1"]);
    seed(&f.st, "h_b", 64_000, 0, 1, &["t2"]);
    f.st.reg
        .lock()
        .unwrap()
        .machines
        .insert("m1".into(), "h_a".into());
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/h_a/drain", "", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(hosts(&f.st)[0].state, "draining");
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/h_x/drain", "", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(json(&body)["code"], "not_found");
    // Placement goes elsewhere now, and the pins on h_a stay.
    assert_eq!(
        f.st.reg
            .lock()
            .unwrap()
            .place("t3", "", 512, 0, &f.st.policy)
            .as_deref(),
        Some("h_b")
    );

    let (s, _, _) = call(&f.st, "DELETE", "/v1/hosts/h_a", "", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let ids: Vec<String> = hosts(&f.st).into_iter().map(|h| h.id).collect();
    assert_eq!(ids, ["h_b"]);
    {
        let reg = f.st.reg.lock().unwrap();
        assert_eq!(
            reg.namespaces.get("t1"),
            None,
            "its namespaces are unpinned"
        );
        assert_eq!(reg.namespaces.get("t2").map(String::as_str), Some("h_b"));
        assert_eq!(reg.machines.get("m1"), None);
    }
    let (s, _, _) = call(&f.st, "DELETE", "/v1/hosts/h_a", "", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "forgetting twice is fine");
    assert!(!saved(&f.st).hosts.contains_key("h_a"));
}

#[tokio::test]
async fn the_poll_fills_a_static_host_in_and_marks_a_silent_one_down() {
    let d = start_daemon("d1", "tok-1").await;
    d.stub.add("t1", "web", 512);
    let cfg = config::Config {
        hosts: vec![
            config::StaticHost {
                id: "d1".into(),
                url: d.url.clone(),
                token: "tok-1".into(),
                region: "fsn".into(),
                ..Default::default()
            },
            config::StaticHost {
                id: "gone".into(),
                // Nothing listens there.
                url: "http://127.0.0.1:1".into(),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let f = fleet(cfg);
    assert_eq!(
        hosts(&f.st)[0].capacity.memory_mb,
        0,
        "nothing known before the first poll"
    );
    let unseen = poll_static_hosts_once(&f.st).await;
    assert!(unseen, "a host that never answered is asked again soon");
    let hs = hosts(&f.st);
    assert_eq!(hs[0].id, "d1");
    assert_eq!(hs[0].state, "ready");
    assert_eq!(hs[0].capacity.memory_mb, 64_000);
    assert_eq!(hs[0].used.memory_mb, 512);
    assert_eq!(hs[0].machines, 1);
    assert_eq!(hs[0].namespaces, ["t1"]);
    assert_eq!(hs[0].version, "0.1-stub");
    assert_eq!(hs[1].id, "gone");
    assert_eq!(hs[1].state, "ready", "silent but not yet past the grace");
    assert_eq!(
        d.stub.calls(),
        ["GET /v1/status", "GET /v1/tenants"],
        "the poll asks for status and namespaces (the path every daemon serves), with the host's token"
    );
    // Past the grace, a silent host is down; the next answer brings it back.
    {
        let mut reg = f.st.reg.lock().unwrap();
        for h in reg.hosts.values_mut() {
            h.last_seen = Utc::now() - Duration::minutes(2);
        }
    }
    poll_static_hosts_once(&f.st).await;
    let hs = hosts(&f.st);
    assert_eq!((hs[0].id.as_str(), hs[0].state.as_str()), ("d1", "ready"));
    assert_eq!((hs[1].id.as_str(), hs[1].state.as_str()), ("gone", "down"));
    // A forgotten static host is back on the next poll: it leaves by leaving the configuration.
    let (s, _, _) = call(&f.st, "DELETE", "/v1/hosts/d1", "", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    poll_static_hosts_once(&f.st).await;
    assert_eq!(hosts(&f.st)[0].id, "d1");
}

#[tokio::test]
async fn deleting_a_namespace_unpins_it() {
    let (f, ds) = fleet_with_daemons(2).await;
    ds[0].stub.add("t1", "web", 512);
    ds[0].stub.add("kept", "db", 512);
    poll_static_hosts_once(&f.st).await;
    let (s, _, body) = call(&f.st, "DELETE", "/v1/namespaces/t1", "api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(
        ds[0].stub.calls().last().unwrap(),
        "DELETE /v1/namespaces/t1"
    );
    assert_eq!(pinned(&f.st, "t1"), None);
    // The host refused: the pin stays.
    let (s, _, body) = call(&f.st, "DELETE", "/v1/namespaces/kept", "api", None).await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        json(&body)["code"],
        "busy",
        "the host's answer passes through"
    );
    assert_eq!(pinned(&f.st, "kept").as_deref(), Some("d1"));
    // A namespace the fleet never placed: nothing to do, no host asked.
    let before: Vec<usize> = ds.iter().map(|d| d.stub.calls().len()).collect();
    let (s, _, _) = call(&f.st, "DELETE", "/v1/namespaces/nobody", "api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let after: Vec<usize> = ds.iter().map(|d| d.stub.calls().len()).collect();
    assert_eq!(before, after);
}

#[tokio::test]
async fn unpin_releases_a_namespace_without_asking_its_host() {
    let (f, ds) = fleet_with_daemons(2).await;
    ds[0].stub.add("kept", "db", 512);
    poll_static_hosts_once(&f.st).await;
    assert_eq!(pinned(&f.st, "kept").as_deref(), Some("d1"));
    set_state(&f.st, "d1", "down");
    let before: Vec<usize> = ds.iter().map(|d| d.stub.calls().len()).collect();
    let (s, _, body) = call(&f.st, "POST", "/v1/namespaces/kept/unpin", "api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    let after: Vec<usize> = ds.iter().map(|d| d.stub.calls().len()).collect();
    assert_eq!(before, after, "no host asked, down or not");
    assert_eq!(pinned(&f.st, "kept"), None);
    assert_eq!(saved(&f.st).namespaces.get("kept"), None, "written");
    // Its next machine is placed afresh: d1 is down, so on d2.
    let (s, headers, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("kept", "db-restored", 512)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d2");
    let (s, _, _) = call(&f.st, "POST", "/v1/namespaces/nobody/unpin", "api", None).await;
    assert_eq!(
        s,
        StatusCode::NO_CONTENT,
        "unpinning what is not pinned is fine"
    );
}

#[tokio::test]
async fn a_drained_host_is_never_forgotten_and_undrains() {
    let f = fleet(config::Config::default());
    seed(&f.st, "h_a", 64_000, 0, 0, &[]);
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/h_a/drain", "", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(
        f.st.reg.lock().unwrap().retirable().is_empty(),
        "an empty drained host is kept: only a retire forgets"
    );
    // A heartbeat keeps the drain.
    let h = f.st.reg.lock().unwrap().hosts["h_a"].clone();
    f.st.reg.lock().unwrap().heartbeat(h, Utc::now());
    assert_eq!(hosts(&f.st)[0].state, "draining");
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/h_a/undrain", "", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(hosts(&f.st)[0].state, "ready");
    // Undrain of a ready host, or of one that is not there.
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/h_a/undrain", "", None).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(json(&body)["error"], "host h_a is ready");
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/h_x/undrain", "", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // A retire is undone the same way, before the host empties.
    seed(&f.st, "h_b", 64_000, 0, 1, &["t1"]);
    call(&f.st, "POST", "/v1/hosts/h_b/retire", "", None).await;
    assert_eq!(f.st.reg.lock().unwrap().hosts["h_b"].state, "retiring");
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/h_b/undrain", "", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(f.st.reg.lock().unwrap().hosts["h_b"].state, "ready");
}

/// A fleet whose SSH key is a file that exists, so an upgrade gets past its own checks (the
/// key is only read by `ssh`).
fn fleet_with_key() -> Fleet {
    let mut cfg = config::Config::default();
    cfg.bootstrap.ssh_key = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml").into();
    fleet(cfg)
}

#[tokio::test]
async fn an_upgrade_refuses_what_it_cannot_do() {
    let up = |r: &str| Some(serde_json::json!({ "release": r }));
    // No SSH key: nothing can be installed. Named, not the default: a dev VM has that one.
    let mut cfg = config::Config::default();
    cfg.bootstrap.ssh_key = "/nonexistent/briqyard-fleet-key".into();
    let f = fleet(cfg);
    seed(&f.st, "h_a", 64_000, 0, 0, &[]);
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/h_a/upgrade", "", up("0.2.0")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(
        json(&body)["error"]
            .as_str()
            .unwrap()
            .contains("(bootstrap.ssh_key)"),
        "{body}"
    );
    let f = fleet_with_key();
    seed(&f.st, "h_a", 64_000, 0, 0, &[]);
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/h_a/upgrade", "", up("latest")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(
        json(&body)["error"],
        "release \"latest\": a URL, or a version such as 0.2.0"
    );
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/h_x/upgrade", "", up("0.2.0")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    for state in ["down", "retiring", "provisioning", "upgrading"] {
        set_state(&f.st, "h_a", state);
        let (s, _, body) = call(&f.st, "POST", "/v1/hosts/h_a/upgrade", "", up("0.2.0")).await;
        assert_eq!(s, StatusCode::CONFLICT, "{state}");
        assert!(
            json(&body)["error"].as_str().unwrap().contains(state),
            "{body}"
        );
    }
    // One at a time: while another upgrade holds the turn, nothing moves.
    set_state(&f.st, "h_a", "ready");
    let _turn = f.st.upgrade.clone().try_lock_owned().unwrap();
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/h_a/upgrade", "", up("0.2.0")).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(
        json(&body)["error"],
        "another host is upgrading: one at a time"
    );
    assert_eq!(hosts(&f.st)[0].state, "ready");
    // An upgrading host's state is the upgrade's: no drain, undrain or retire meanwhile.
    set_state(&f.st, "h_a", "upgrading");
    for op in ["drain", "undrain", "retire"] {
        let (s, _, _) = call(&f.st, "POST", &format!("/v1/hosts/h_a/{op}"), "", None).await;
        assert_eq!(s, StatusCode::CONFLICT, "{op}");
    }
    // And a heartbeat keeps it.
    let h = f.st.reg.lock().unwrap().hosts["h_a"].clone();
    f.st.reg.lock().unwrap().heartbeat(h, Utc::now());
    assert_eq!(hosts(&f.st)[0].state, "upgrading");
}

#[tokio::test]
async fn an_upgrade_waits_for_a_new_start_of_the_version_installed() {
    let f = fleet_with_key();
    seed(&f.st, "h_a", 64_000, 0, 1, &["t1"]);
    let before = Utc::now() - Duration::minutes(5);
    let beat = |version: &str, started: Option<api::DaemonStart>| {
        let mut h = f.st.reg.lock().unwrap().hosts["h_a"].clone();
        h.version = version.into();
        h.started = started;
        f.st.reg.lock().unwrap().heartbeat(h, Utc::now());
    };
    let start = |at, adopted, stopped, gone| {
        Some(api::DaemonStart {
            at,
            adopted,
            stopped,
            gone,
        })
    };
    let wait = |ms| {
        upgrade::come_back(
            &f.st,
            "h_a",
            Some(before),
            "0.2.0+b",
            std::time::Duration::from_millis(ms),
        )
    };
    // The old daemon still answering, or a new one of another build: not yet.
    beat("0.1.0+a", start(before, 0, 0, 0));
    let err = wait(600).await.unwrap_err();
    assert_eq!(err, "no heartbeat from a new start of 0.2.0+b within 0 s");
    beat("0.2.0+b", start(before, 0, 0, 0));
    assert!(wait(600).await.is_err(), "the same start is not a new one");
    // A daemon older than ADR 0027 reports no start: never the one installed.
    beat("0.2.0+b", None);
    assert!(wait(600).await.is_err(), "no start is not a new one");
    // The new start, which adopted the machine; one whose process had exited meanwhile is gone,
    // not a failure.
    let now = Utc::now();
    beat("0.2.0+b", start(now, 1, 0, 1));
    let started = wait(600).await.unwrap();
    assert_eq!((started.at, started.adopted, started.gone), (now, 1, 1));
    // One that stopped a machine it could not take over fails the upgrade.
    beat("0.2.0+b", start(now, 1, 2, 0));
    let err = wait(600).await.unwrap_err();
    assert_eq!(
        err,
        "0.2.0+b started and stopped 2 machines it could not take over (1 adopted)"
    );
}

#[tokio::test]
async fn an_upgrade_ends_in_the_hosts_state_or_drained() {
    let f = fleet_with_key();
    seed(&f.st, "h_a", 64_000, 0, 0, &[]);
    let was = f.st.reg.lock().unwrap().hosts["h_a"].clone();
    set_state(&f.st, "h_a", "upgrading");
    let started = api::DaemonStart {
        at: Utc::now(),
        adopted: 3,
        stopped: 0,
        gone: 0,
    };
    let h = upgrade::finish(&f.st, &was, "file:///r", Ok(("0.2.0+b".into(), started)))
        .await
        .unwrap();
    assert_eq!(h.state, "ready");
    assert!(h.note.starts_with("upgraded to 0.2.0+b at "), "{}", h.note);
    assert!(h.note.ends_with("; machines handed over: 3"), "{}", h.note);
    // A failure leaves it drained, the reason in its note, whatever it was before.
    set_state(&f.st, "h_a", "upgrading");
    let err = upgrade::finish(
        &f.st,
        &was,
        "file:///r",
        Err("install: ssh exited 255".into()),
    )
    .await
    .unwrap_err();
    assert_eq!(err, "install: ssh exited 255");
    let h = &hosts(&f.st)[0];
    assert_eq!(h.state, "draining");
    assert!(
        h.note.starts_with("upgrade to file:///r failed at "),
        "{}",
        h.note
    );
    assert!(
        h.note
            .ends_with(": install: ssh exited 255; undrain once it is fixed"),
        "{}",
        h.note
    );
    // A fleet that stopped during an upgrade finds the host drained at its start.
    set_state(&f.st, "h_a", "upgrading");
    upgrade::interrupted(&mut f.st.reg.lock().unwrap());
    let h = &hosts(&f.st)[0];
    assert_eq!(h.state, "draining");
    assert!(
        h.note
            .ends_with("interrupted by a fleet restart; undrain once checked"),
        "{}",
        h.note
    );
}

#[tokio::test]
async fn a_heartbeat_carries_the_daemons_start() {
    let f = fleet(config::Config::default());
    let mut h = static_host(
        &config::StaticHost {
            id: "h_a".into(),
            url: "http://10.0.0.1:7420".into(),
            ..Default::default()
        },
        Utc::now(),
    );
    h.started = Some(api::DaemonStart {
        at: Utc::now(),
        adopted: 4,
        stopped: 1,
        gone: 2,
    });
    f.st.reg.lock().unwrap().heartbeat(h.clone(), Utc::now());
    assert_eq!(hosts(&f.st)[0].started, h.started);
}
