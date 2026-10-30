//! Creating a machine: placement, reservations and forks.

use super::*;

#[tokio::test]
async fn a_create_is_placed_and_forwarded_with_its_host() {
    let (f, ds) = fleet_with_daemons(2).await;
    let (s, headers, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t1", "web", 512)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    let m: api::Machine = serde_json::from_str(&body).unwrap();
    let host = headers["x-briqyard-host"].to_str().unwrap().to_string();
    assert!(host == "d1" || host == "d2", "{host}");
    assert_eq!(m.host, host, "the host is added to the body");
    assert_eq!(m.name, "web");
    let on = ds.iter().find(|d| d.stub.id == host).unwrap();
    assert_eq!(on.stub.calls().last().unwrap(), "POST /v1/machines");
    assert_eq!(on.stub.machines.lock().unwrap().len(), 1);
    {
        let reg = f.st.reg.lock().unwrap();
        assert_eq!(
            reg.machines.get(&m.id).map(String::as_str),
            Some(host.as_str())
        );
        assert_eq!(
            reg.namespaces.get("t1").map(String::as_str),
            Some(host.as_str())
        );
        assert_eq!(
            reg.hosts[&host].used.memory_mb, 512,
            "reserved until the host reports"
        );
    }
    // The namespace's next machine lands on the same host, whatever the other has free.
    let other = if host == "d1" { "d2" } else { "d1" };
    f.st.reg
        .lock()
        .unwrap()
        .hosts
        .get_mut(&host)
        .unwrap()
        .used
        .memory_mb = 60_000;
    let (s, headers, _) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t1", "db", 512)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(headers["x-briqyard-host"], host.as_str());
    // A new namespace goes to the emptiest host.
    let (s, headers, _) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t2", "web", 512)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(headers["x-briqyard-host"], other);
    assert_eq!(saved(&f.st).machines.len(), 3, "the registry was written");
}

#[tokio::test]
async fn a_burst_of_creates_is_spread_by_what_each_one_reserved() {
    let (f, _ds) = fleet_with_daemons(2).await;
    // Three namespaces, created before any poll could show the first's memory as used: each
    // sees what the ones before it reserved, so the two larger ones land apart.
    let mut on = Vec::new();
    for (t, mb) in [("t1", 30_000), ("t2", 20_000), ("t3", 20_000)] {
        let (s, headers, body) = call(
            &f.st,
            "POST",
            "/v1/machines",
            "api",
            Some(create_body(t, "web", mb)),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{body}");
        on.push(headers["x-briqyard-host"].to_str().unwrap().to_string());
    }
    assert_ne!(on[0], on[1], "t2 saw t1's 30 GB taken: {on:?}");
    assert_eq!(
        on[1], on[2],
        "t3 saw 30 GB on one host and 20 GB on the other: {on:?}"
    );
    let used: Vec<u32> = {
        let reg = f.st.reg.lock().unwrap();
        on.iter().map(|h| reg.hosts[h].used.memory_mb).collect()
    };
    assert_eq!(used, [30_000, 40_000, 40_000]);
    // The hosts report: what they run is what is used, no more.
    poll_static_hosts_once(&f.st).await;
    let used: Vec<u32> = {
        let reg = f.st.reg.lock().unwrap();
        on.iter().map(|h| reg.hosts[h].used.memory_mb).collect()
    };
    assert_eq!(used, [30_000, 40_000, 40_000]);
}

/// ADR 0044: what a create held is given back when the host does not make it, and what a
/// destroy freed is room at once, not at the host's next heartbeat.
#[tokio::test]
async fn room_comes_back_at_a_failed_create_and_at_a_destroy() {
    let (f, ds) = fleet_with_daemons(1).await;
    let used = |f: &Fleet| f.st.reg.lock().unwrap().hosts["d1"].used.memory_mb;
    // The host refuses (a bad name): nothing stays held.
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t0", "Bad Name", 30_000)),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(used(&f), 0);
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t1", "big", 50_000)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    let big = json(&body)["id"].as_str().unwrap().to_string();
    assert_eq!(used(&f), 50_000, "held until a report counts it");
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t2", "web", 20_000)),
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "no room: {body}");
    // The destroy answers once the host has freed it: the next create fits, no poll between.
    let path = format!("/v1/machines/{big}");
    let (s, _, body) = call(&f.st, "DELETE", &path, "api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(used(&f), 0, "the host's figure, asked after the destroy");
    let (free, _) = f.st.reg.lock().unwrap().room(&f.st.policy)["fsn"];
    assert_eq!(free.memory_mb, DAEMON_MEMORY_MB as u64, "the signals' too");
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t2", "web", 20_000)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert_eq!(used(&f), 20_000);
    assert_eq!(ds[0].stub.used_mb(), 20_000);
}

/// A caller that hangs up mid-create drops its handler, and the hold with it (ADR 0044). The
/// host takes the connection and never answers.
#[tokio::test]
async fn a_create_whose_caller_hangs_up_gives_its_hold_back() {
    let f = fleet(config::Config::default());
    seed(&f.st, "h_a", 64_000, 0, 0, &[]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    f.st.reg.lock().unwrap().hosts.get_mut("h_a").unwrap().url =
        format!("http://{}", listener.local_addr().unwrap());
    let (asked, mut forwarded) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        let mut open = Vec::new();
        while let Ok((conn, _)) = listener.accept().await {
            open.push(conn);
            let _ = asked.try_send(());
        }
    });
    let used = |f: &Fleet| f.st.reg.lock().unwrap().hosts["h_a"].used.memory_mb;
    let st = f.st.clone();
    let create = tokio::spawn(async move {
        let body = create_body("t1", "web", 20_000);
        call(&st, "POST", "/v1/machines", "", Some(body)).await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), forwarded.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(used(&f), 20_000, "held while the host makes it");
    create.abort();
    assert!(create.await.unwrap_err().is_cancelled());
    assert_eq!(used(&f), 0, "given back");
}

#[tokio::test]
async fn a_capacity_answer_unpins_a_namespaces_first_machine_only() {
    let (f, ds) = fleet_with_daemons(1).await;
    // The host filled up since the fleet last looked: the fleet pins t1 to it and asks; the
    // host refuses; the pin goes, so a retry can be placed where there is room.
    ds[0].stub.add("t0", "big", 50_000);
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t1", "web", 20_000)),
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(
        json(&body)["code"],
        "capacity",
        "the host's answer passes through"
    );
    assert_eq!(ds[0].stub.calls().last().unwrap(), "POST /v1/machines");
    assert_eq!(pinned(&f.st, "t1"), None, "unpinned");
    assert_eq!(saved(&f.st).namespaces.get("t1"), None, "written");
    // A namespace already on the host keeps its pin through a refusal: its network is there.
    poll_static_hosts_once(&f.st).await;
    assert_eq!(pinned(&f.st, "t0").as_deref(), Some("d1"));
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t0", "more", 20_000)),
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(pinned(&f.st, "t0").as_deref(), Some("d1"), "still pinned");
    // A refusal that is not `capacity` leaves a first machine's pin: the host had room, the
    // request was wrong.
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t2", "Bad Name", 256)),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["code"], "invalid");
    assert_eq!(pinned(&f.st, "t2").as_deref(), Some("d1"));
}

#[tokio::test]
async fn a_create_without_room_or_sense_is_refused_before_any_host() {
    let (f, ds) = fleet_with_daemons(1).await;
    let before = ds[0].stub.calls().len();
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t1", "big", 100_000)),
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(json(&body)["code"], "capacity");
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(serde_json::json!({"namespace": "t1"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["code"], "invalid");
    assert_eq!(ds[0].stub.calls().len(), before, "no host was asked");
    assert!(f.st.reg.lock().unwrap().namespaces.is_empty());
}

#[tokio::test]
async fn a_fork_lands_where_its_source_is() {
    let (f, ds) = fleet_with_daemons(2).await;
    let src = ds[1].stub.add("t1", "web", 512);
    f.st.reg
        .lock()
        .unwrap()
        .machines
        .insert(src.id.clone(), "d2".into());
    // d1 is emptier (d2 has a machine after a poll), and d1 would be the pick for a new namespace.
    poll_static_hosts_once(&f.st).await;
    let mut body = create_body("t9", "web-fork", 512);
    body["fork"] = serde_json::json!({"machine_id": src.id});
    let (s, headers, _) = call(&f.st, "POST", "/v1/machines", "api", Some(body)).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(headers["x-briqyard-host"], "d2");
    assert!(
        !ds[0].stub.calls().iter().any(|c| c.starts_with("POST")),
        "d1 was not asked"
    );
    assert_eq!(
        f.st.reg.lock().unwrap().hosts["d2"].used.memory_mb,
        1024,
        "the fork is reserved on the source's host"
    );
}

#[tokio::test]
async fn a_cpu_patch_is_refused_before_forwarding_to_a_legacy_host() {
    let (f, ds) = fleet_with_daemons(1).await;
    let machine = ds[0].stub.add("t1", "legacy", 256);
    poll_static_hosts_once(&f.st).await;
    f.st.reg
        .lock()
        .unwrap()
        .hosts
        .get_mut("d1")
        .unwrap()
        .capacity
        .cpu_millis = None;
    let path = format!("/v1/machines/{}", machine.id);
    let (status, _, body) = call(
        &f.st,
        "PATCH",
        &path,
        "api",
        Some(serde_json::json!({
            "size": {"vcpus": 1, "memory_mb": 256, "cpu_millis": 250}
        })),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body.contains("must be upgraded"));
    assert!(
        !ds[0]
            .stub
            .calls()
            .iter()
            .any(|call| call.starts_with("PATCH")),
        "an old daemon would silently ignore the requested CPU limit"
    );
}

fn sized_restore_backup(id: &str, millis: u32) -> serde_json::Value {
    serde_json::json!({
        "id":id, "machine_id":"m_gone", "namespace":"old", "name":"db",
        "created_at":"2026-10-29T10:00:00Z", "bytes":1, "incremental":false, "disks":[],
        "size":{"vcpus":1,"memory_mb":512,"cpu_millis":millis}
    })
}

#[tokio::test]
async fn restore_placement_uses_backup_cpu_and_pins_the_selected_backup() {
    for which in ["latest", "", "b1"] {
        let (f, ds) = fleet_with_daemons(2).await;
        for daemon in &ds {
            *daemon.stub.backup_records.lock().unwrap() = vec![
                sized_restore_backup("b2", 500),
                sized_restore_backup("b1", 250),
            ];
        }
        {
            let mut reg = f.st.reg.lock().unwrap();
            let full = reg.hosts.get_mut("d1").unwrap();
            full.used.cpu_millis = Some(32_000);
            // With a zero CPU request d1 wins on memory; the resolved request must choose d2.
            reg.hosts.get_mut("d2").unwrap().capacity.memory_mb = 63_000;
        }
        let expected = if which == "b1" { 250 } else { 500 };
        let held = Arc::new(std::sync::atomic::AtomicBool::new(false));
        {
            let (st, held) = (f.st.clone(), held.clone());
            *ds[1].stub.on_create.lock().unwrap() = Some(Box::new(move || {
                let reg = st.reg.lock().unwrap();
                assert_eq!(reg.hosts["d2"].used.cpu_millis(), expected);
                assert_eq!(reg.hosts["d2"].used.memory_mb, 512);
                held.store(true, Ordering::SeqCst);
            }));
        }
        let (status, headers, body) = call(&f.st, "POST", "/v1/machines", "api", Some(serde_json::json!({
            "namespace":"restored", "name":"copy", "size":{"vcpus":0,"memory_mb":0}, "restore":{"machine_id":"m_gone","backup":which}
        }))).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(headers["x-briqyard-host"], "d2");
        assert!(held.load(Ordering::SeqCst));
        assert!(ds[0].stub.creates.lock().unwrap().is_empty());
        let creates = ds[1].stub.creates.lock().unwrap();
        assert_eq!(creates[0].size.cpu_millis(), expected);
        assert_eq!(
            creates[0].restore.as_ref().unwrap().backup,
            if which == "b1" { "b1" } else { "b2" }
        );
    }
}

#[tokio::test]
async fn unknown_restore_size_is_refused_without_placement_but_explicit_size_still_works() {
    let (f, ds) = fleet_with_daemons(1).await;
    let mut backup = sized_restore_backup("b1", 250);
    backup.as_object_mut().unwrap().remove("size");
    *ds[0].stub.backup_records.lock().unwrap() = vec![backup];
    let mut request = serde_json::json!({
        "namespace":"restored", "name":"copy", "size":{"vcpus":0,"memory_mb":0}, "restore":{"machine_id":"m_gone","backup":"b1"}
    });
    let (status, _, body) = call(&f.st, "POST", "/v1/machines", "api", Some(request.clone())).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("explicit restore size"));
    assert!(f.st.reg.lock().unwrap().namespaces.is_empty());
    assert!(ds[0].stub.creates.lock().unwrap().is_empty());
    request["size"] = serde_json::json!({"vcpus":1,"memory_mb":256,"cpu_millis":250});
    let (status, _, body) = call(&f.st, "POST", "/v1/machines", "api", Some(request)).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(ds[0].stub.creates.lock().unwrap()[0].size.cpu_millis(), 250);
}

#[tokio::test]
async fn a_fork_still_requires_an_explicit_valid_size() {
    let (f, ds) = fleet_with_daemons(1).await;
    let (status, _, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(serde_json::json!({
            "namespace":"forked", "name":"copy", "fork":{"machine_id":"m_source"}
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(ds[0].stub.creates.lock().unwrap().is_empty());
    assert!(f.st.reg.lock().unwrap().namespaces.is_empty());
}

#[tokio::test]
async fn inherited_restore_size_can_be_read_when_the_original_host_is_down() {
    let (f, ds) = fleet_with_daemons(2).await;
    *ds[1].stub.backup_records.lock().unwrap() = vec![sized_restore_backup("b1", 250)];
    {
        let mut reg = f.st.reg.lock().unwrap();
        reg.machines.insert("m_gone".into(), "d1".into());
        reg.hosts.get_mut("d1").unwrap().state = "down".into();
    }
    let (status, headers, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(serde_json::json!({
            "namespace":"restored", "name":"copy", "size":{"vcpus":0,"memory_mb":0},
            "restore":{"machine_id":"m_gone","backup":"latest"}
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d2");
    assert_eq!(ds[1].stub.creates.lock().unwrap()[0].size.cpu_millis(), 250);
}

#[tokio::test]
async fn cpu_reservations_survive_reports_and_release_exactly_once() {
    let (f, _) = fleet_with_daemons(1).await;
    let mut reg = f.st.reg.lock().unwrap();
    let first = reg.hold("d1", 128, 0, 250);
    let second = reg.hold("d1", 128, 0, 500);
    // A legacy used report still means 1000m for each reported guest vCPU.
    reg.hosts.get_mut("d1").unwrap().report(
        api::Capacity {
            memory_mb: 256,
            vcpus: 1,
            cpu_millis: None,
        },
        100_000,
        Utc::now(),
    );
    assert_eq!(reg.hosts["d1"].used.cpu_millis(), 1750);
    reg.release("d1", first);
    reg.release("d1", first);
    assert_eq!(reg.hosts["d1"].used.cpu_millis(), 1500);
    reg.made("d1", second, Utc::now());
    reg.hosts.get_mut("d1").unwrap().report(
        api::Capacity {
            memory_mb: 384,
            vcpus: 2,
            cpu_millis: Some(1500),
        },
        100_000,
        Utc::now() + Duration::seconds(1),
    );
    assert_eq!(reg.hosts["d1"].used.cpu_millis(), 1500);
    reg.release("d1", second);
    assert_eq!(
        reg.hosts["d1"].used.cpu_millis(),
        1500,
        "a completed hold incorporated by the host must not be subtracted again"
    );
}
