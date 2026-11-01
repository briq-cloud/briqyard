use super::*;

fn admission_body(machine: &str) -> serde_json::Value {
    serde_json::json!({"region":"fsn", "size":{"vcpus":1,"memory_mb":256},
        "sandbox_seed":{"machine_id":machine,"snapshot":"s_one","generation":"g_one"}})
}
fn admission_path(namespace: &str, id: &str) -> String {
    format!("/v1/namespaces/{namespace}/sandbox-admissions/{id}")
}
fn source(f: &Fleet, d: &Running, machine: &str) {
    let host = d.stub.id.clone();
    {
        let mut reg = f.st.reg.lock().unwrap();
        reg.machines.insert(machine.into(), host.clone());
        let h = reg.hosts.get_mut(&host).unwrap();
        h.named_memory_fork_v1 = true;
        h.named_memory_profiles = vec!["sandbox-ready-v1".into()];
    }
    d.stub.snapshots.lock().unwrap().push(api::Snapshot {
        id: "s_one".into(),
        machine_id: machine.into(),
        name: None,
        created_at: Utc::now(),
        disks: vec!["root".into(), "data".into()],
        memory: true,
        clone_profile: Some("sandbox-ready-v1".into()),
        source_host: Some(host),
        clone_size: Some(api::Size {
            vcpus: 1,
            memory_mb: 256,
            cpu_millis: None,
        }),
        clone_ram_marker: None,
        clone_generation: Some("g_one".into()),
    });
}
async fn admit(f: &Fleet, namespace: &str, id: &str, machine: &str) -> (StatusCode, String) {
    let (s, _, b) = call(
        &f.st,
        "PUT",
        &admission_path(namespace, id),
        "api",
        Some(admission_body(machine)),
    )
    .await;
    (s, b)
}
async fn create_admitted(
    f: &Fleet,
    namespace: &str,
    id: &str,
    machine: Option<&str>,
) -> (StatusCode, HeaderMap, String) {
    let mut body = create_body(namespace, "sandbox", 256);
    body["region"] = "fsn".into();
    if let Some(machine) = machine {
        body["sandbox_seed"] = serde_json::json!({"machine_id":machine,"snapshot":"s_one","generation":"g_one","request_id":id});
        body["start"] = true.into();
        body["volume"] = serde_json::json!({"size_gb":2,"mount":"/work"});
    }
    call_with(
        &f.st,
        "127.0.0.1".parse().unwrap(),
        &[(crate::sandbox_admissions::HEADER, id)],
        "POST",
        "/v1/machines",
        "api",
        Some(body),
    )
    .await
}

#[tokio::test]
async fn admission_gateway_and_consumer_follow_source_when_normal_placement_prefers_other_host() {
    let (f, ds) = fleet_with_daemons(2).await;
    source(&f, &ds[1], "m_seed");
    {
        let mut reg = f.st.reg.lock().unwrap();
        reg.hosts
            .get_mut(&ds[0].stub.id)
            .unwrap()
            .capacity
            .memory_mb = 128_000;
    }
    {
        let mut hypothetical = f.st.reg.lock().unwrap().clone();
        assert_eq!(
            hypothetical.place("normal", "fsn", 256, 0, 1000, &f.st.policy),
            Some(ds[0].stub.id.clone())
        );
    }
    let (s, b) = admit(&f, "destination", "req_one", "m_seed").await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(json(&b)["mode"], "sandbox-seed");
    let (s, h, b) = call(
        &f.st,
        "PUT",
        "/v1/namespaces/destination/gateway?region=fsn&placement_request_id=req_one",
        "api",
        Some(gateway_body()),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(h["x-briqyard-host"], ds[1].stub.id);
    let (s, h, b) = create_admitted(&f, "destination", "req_one", Some("m_seed")).await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    assert_eq!(h["x-briqyard-host"], ds[1].stub.id);
    // A retry may need to repair CA registration after dispatch, on the same pin only.
    let (gs, gh, gb) = call(
        &f.st,
        "PUT",
        "/v1/namespaces/destination/gateway?region=fsn&placement_request_id=req_one",
        "api",
        Some(gateway_body()),
    )
    .await;
    assert_eq!(gs, StatusCode::OK, "{gb}");
    assert_eq!(gh["x-briqyard-host"], ds[1].stub.id);
    let (gs, gh, gb) = call(
        &f.st,
        "PUT",
        "/v1/namespaces/destination/gateway?region=fsn",
        "api",
        Some(gateway_body()),
    )
    .await;
    assert_eq!(gs, StatusCode::OK, "{gb}");
    assert_eq!(gh["x-briqyard-host"], ds[1].stub.id);
    assert!(ds[0].stub.creates.lock().unwrap().is_empty());
    let (s, _, _) = call(
        &f.st,
        "DELETE",
        &admission_path("destination", "req_one"),
        "api",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    let reg = Registry::load(&f.st.state_path).unwrap();
    assert!(!crate::create_replay::namespace_unresolved(
        &reg,
        "destination"
    ));
    assert!(!crate::sandbox_admissions::namespace_pending(
        &reg,
        "destination"
    ));
    assert_eq!(reg.sandbox_requests.len(), 1);
}

#[tokio::test]
async fn ordinary_first_member_and_admission_serialize_in_both_orders() {
    let (f, ds) = fleet_with_daemons(2).await;
    source(&f, &ds[1], "m_seed");
    {
        let mut r = f.st.reg.lock().unwrap();
        r.hosts.get_mut(&ds[0].stub.id).unwrap().capacity.memory_mb = 128_000;
    }
    let (s, _, b) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("ordinary-first", "first", 256)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let (s, b) = admit(&f, "ordinary-first", "req_cold", "m_seed").await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(json(&b)["mode"], "cold");
    // Removing the old pin cannot change the frozen decision, even across a registry reload.
    {
        let mut r = f.st.reg.lock().unwrap();
        r.unpin("ordinary-first");
    }
    f.st.save().await.unwrap();
    *f.st.reg.lock().unwrap() = Registry::load(&f.st.state_path).unwrap();
    assert_eq!(
        json(&admit(&f, "ordinary-first", "req_cold", "m_seed").await.1)["mode"],
        "cold"
    );
    let (cs, _, cb) = create_admitted(&f, "ordinary-first", "req_cold", None).await;
    assert_eq!(cs, StatusCode::CREATED, "{cb}");
    assert!(ds[0]
        .stub
        .creates
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .sandbox_seed
        .is_none());
    let (s, b) = admit(&f, "admission-first", "req_seed", "m_seed").await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let (s, h, b) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("admission-first", "first", 256)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    assert_eq!(h["x-briqyard-host"], ds[1].stub.id);
    // Simultaneous first-member requests can only take one of those two serial orders.
    let a = admit(&f, "concurrent", "req_race", "m_seed");
    let c = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("concurrent", "first", 256)),
    );
    let ((s, b), (cs, ch, cb)) = tokio::join!(a, c);
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(cs, StatusCode::CREATED, "{cb}");
    let reg = f.st.reg.lock().unwrap();
    assert_eq!(
        reg.namespaces["concurrent"],
        ch["x-briqyard-host"].to_str().unwrap()
    );
    if json(&b)["mode"] == "sandbox-seed" {
        assert_eq!(reg.namespaces["concurrent"], ds[1].stub.id);
    }
}

#[tokio::test]
async fn competing_sources_choose_one_seed_and_persist_cold_for_the_other() {
    let (f, ds) = fleet_with_daemons(2).await;
    source(&f, &ds[0], "m_a");
    source(&f, &ds[1], "m_b");
    let (a, b) = tokio::join!(
        admit(&f, "shared", "req_a", "m_a"),
        admit(&f, "shared", "req_b", "m_b")
    );
    assert_eq!(a.0, StatusCode::OK, "{}", a.1);
    assert_eq!(b.0, StatusCode::OK, "{}", b.1);
    let modes = [json(&a.1)["mode"].clone(), json(&b.1)["mode"].clone()];
    assert_eq!(modes.iter().filter(|m| **m == "sandbox-seed").count(), 1);
    assert_eq!(modes.iter().filter(|m| **m == "cold").count(), 1);
    *f.st.reg.lock().unwrap() = Registry::load(&f.st.state_path).unwrap();
    assert_eq!(
        json(&admit(&f, "shared", "req_a", "m_a").await.1)["mode"],
        modes[0]
    );
    assert_eq!(
        json(&admit(&f, "shared", "req_b", "m_b").await.1)["mode"],
        modes[1]
    );
}

#[tokio::test]
async fn pending_admission_survives_heartbeat_restart_and_blocks_identity_cleanup() {
    let (f, ds) = fleet_with_daemons(1).await;
    source(&f, &ds[0], "m_seed");
    assert_eq!(
        admit(&f, "destination", "req_one", "m_seed").await.0,
        StatusCode::OK
    );
    {
        let mut reg = f.st.reg.lock().unwrap();
        let mut host = reg.hosts[&ds[0].stub.id].clone();
        host.namespaces.clear();
        reg.heartbeat(host, Utc::now() + Duration::minutes(11));
        reg.unpin("destination");
        reg.forget(&ds[0].stub.id);
        assert_eq!(reg.namespaces["destination"], ds[0].stub.id);
        assert!(reg.hosts.contains_key(&ds[0].stub.id));
    }
    f.st.save().await.unwrap();
    *f.st.reg.lock().unwrap() = Registry::load(&f.st.state_path).unwrap();
    for path in ["/v1/namespaces/destination", "/v1/hosts/d1"] {
        assert_eq!(
            call(&f.st, "DELETE", path, "api", None).await.0,
            StatusCode::CONFLICT
        );
    }
    assert_eq!(
        call(
            &f.st,
            "POST",
            "/v1/namespaces/destination/unpin",
            "api",
            None
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let mut changed = admission_body("m_seed");
    changed["region"] = "other".into();
    assert_eq!(
        call(
            &f.st,
            "PUT",
            &admission_path("destination", "req_one"),
            "api",
            Some(changed)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn cancellation_is_durable_and_cannot_undo_dispatched_route_or_shared_gateway() {
    let (f, ds) = fleet_with_daemons(1).await;
    source(&f, &ds[0], "m_seed");
    assert_eq!(
        admit(&f, "destination", "req_one", "m_seed").await.0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &f.st,
            "PUT",
            "/v1/namespaces/destination/gateway?region=fsn&placement_request_id=req_one",
            "api",
            Some(gateway_body())
        )
        .await
        .0,
        StatusCode::OK
    );
    let c = call(
        &f.st,
        "DELETE",
        &admission_path("destination", "req_one"),
        "api",
        None,
    )
    .await;
    assert_eq!(c.0, StatusCode::NO_CONTENT);
    *f.st.reg.lock().unwrap() = Registry::load(&f.st.state_path).unwrap();
    assert_eq!(
        admit(&f, "destination", "req_one", "m_seed").await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        create_admitted(&f, "destination", "req_one", Some("m_seed"))
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(ds[0].stub.gateways.lock().unwrap().len(), 1);
    // Cancellation arriving before an in-flight admission finishes also leaves a tombstone.
    assert_eq!(
        call(
            &f.st,
            "DELETE",
            &admission_path("destination", "req_late"),
            "api",
            None
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        admit(&f, "destination", "req_late", "m_seed").await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        admit(&f, "racing", "req_race", "m_seed").await.0,
        StatusCode::OK
    );
    let path = admission_path("racing", "req_race");
    let ((cs, _, cb), (ds, _, db)) = tokio::join!(
        create_admitted(&f, "racing", "req_race", Some("m_seed")),
        call(&f.st, "DELETE", &path, "api", None)
    );
    assert!(
        (cs == StatusCode::CREATED && ds == StatusCode::CONFLICT)
            || (cs == StatusCode::CONFLICT && ds == StatusCode::NO_CONTENT),
        "{cs} {cb}; {ds} {db}"
    );
}

#[tokio::test]
async fn admission_authentication_strict_input_and_gateway_hint_fail_closed() {
    let (f, ds) = fleet_with_daemons(1).await;
    source(&f, &ds[0], "m_seed");
    assert_eq!(
        call(
            &f.st,
            "PUT",
            &admission_path("destination", "req_one"),
            "",
            Some(admission_body("m_seed"))
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let mut bad = admission_body("m_seed");
    bad["host"] = "d1".into();
    assert_eq!(
        call(
            &f.st,
            "PUT",
            &admission_path("destination", "req_one"),
            "api",
            Some(bad)
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        call(
            &f.st,
            "PUT",
            "/v1/namespaces/destination/gateway?region=fsn&placement_request_id=missing",
            "api",
            Some(gateway_body())
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        admit(&f, "destination", "req_one", "m_seed").await.0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &f.st,
            "PUT",
            "/v1/namespaces/destination/gateway?region=other&placement_request_id=req_one",
            "api",
            Some(gateway_body())
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(
            &f.st,
            "PUT",
            "/v1/namespaces/other/gateway?region=fsn&placement_request_id=req_one",
            "api",
            Some(gateway_body())
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (ms, mb) = admit(&f, "missing-source", "req_missing", "m_absent").await;
    assert_eq!(ms, StatusCode::NOT_FOUND, "{mb}");
    let mut stale = admission_body("m_seed");
    stale["sandbox_seed"]["generation"] = "g_old".into();
    assert_eq!(
        call(
            &f.st,
            "PUT",
            &admission_path("stale", "req_stale"),
            "api",
            Some(stale)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert!(!f.st.reg.lock().unwrap().namespaces.contains_key("stale"));
    let no_auth = fleet(config::Config::default());
    assert_eq!(
        call(
            &no_auth.st,
            "PUT",
            &admission_path("destination", "req_one"),
            "",
            Some(admission_body("m_seed"))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn seed_admission_before_move_refuses_cross_host_destination_without_forwarding() {
    let (f, ds) = fleet_with_daemons(2).await;
    source(&f, &ds[1], "m_seed");
    let machine = ds[0].stub.add("original", "web", 256);
    f.st.reg
        .lock()
        .unwrap()
        .machines
        .insert(machine.id.clone(), ds[0].stub.id.clone());
    assert_eq!(
        admit(&f, "destination", "req_one", "m_seed").await.0,
        StatusCode::OK
    );
    let path = format!("/v1/machines/{}/move", machine.id);
    let (s, _, b) = call(
        &f.st,
        "POST",
        &path,
        "api",
        Some(serde_json::json!({"namespace":"destination"})),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{b}");
    assert!(ds[0].stub.calls().iter().all(|c| !c.contains("/move")));
    assert_eq!(ds[0].stub.machines.lock().unwrap()[0].namespace, "original");
    assert_eq!(
        f.st.reg.lock().unwrap().namespaces["destination"],
        ds[1].stub.id
    );
}

#[tokio::test]
async fn move_reserves_durable_destination_before_admission_and_releases_only_on_confirmed_success()
{
    let (f, ds) = fleet_with_daemons(2).await;
    source(&f, &ds[1], "m_seed");
    let machine = ds[0].stub.add("original", "web", 256);
    f.st.reg
        .lock()
        .unwrap()
        .machines
        .insert(machine.id.clone(), ds[0].stub.id.clone());
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    *ds[0].stub.move_gate.lock().unwrap() = Some((entered.clone(), release.clone()));
    let path = format!("/v1/machines/{}/move", machine.id);
    let st = f.st.clone();
    let moving = tokio::spawn(async move {
        call(
            &st,
            "POST",
            &path,
            "api",
            Some(serde_json::json!({"namespace":"destination"})),
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    let durable = Registry::load(&f.st.state_path).unwrap();
    assert_eq!(durable.namespaces["destination"], ds[0].stub.id);
    assert_eq!(durable.namespace_moves.len(), 1);
    let (s, b) = admit(&f, "destination", "req_one", "m_seed").await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(json(&b)["mode"], "cold");
    release.notify_one();
    assert_eq!(moving.await.unwrap().0, StatusCode::OK);
    assert!(f.st.reg.lock().unwrap().namespace_moves.is_empty());
    assert!(Registry::load(&f.st.state_path)
        .unwrap()
        .namespace_moves
        .is_empty());
    assert_eq!(
        ds[0].stub.machines.lock().unwrap()[0].namespace,
        "destination"
    );
    assert_eq!(
        json(&admit(&f, "destination", "req_one", "m_seed").await.1)["mode"],
        "cold"
    );
}

#[tokio::test]
async fn cancelled_delayed_move_keeps_durable_fence_through_heartbeat_restart_and_late_commit() {
    let (f, ds) = fleet_with_daemons(2).await;
    source(&f, &ds[1], "m_seed");
    let machine = ds[0].stub.add("original", "web", 256);
    f.st.reg
        .lock()
        .unwrap()
        .machines
        .insert(machine.id.clone(), ds[0].stub.id.clone());
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let finished = Arc::new(tokio::sync::Notify::new());
    *ds[0].stub.move_gate.lock().unwrap() = Some((entered.clone(), release.clone()));
    *ds[0].stub.move_finished.lock().unwrap() = Some(finished.clone());
    let path = format!("/v1/machines/{}/move", machine.id);
    let st = f.st.clone();
    let moving = tokio::spawn(async move {
        call(
            &st,
            "POST",
            &path,
            "api",
            Some(serde_json::json!({"namespace":"destination"})),
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    moving.abort();
    assert!(moving.await.unwrap_err().is_cancelled());
    {
        let mut reg = f.st.reg.lock().unwrap();
        let mut host = reg.hosts[&ds[0].stub.id].clone();
        host.namespaces.clear();
        reg.heartbeat(host, Utc::now() + Duration::minutes(11));
        reg.unpin("destination");
        reg.forget(&ds[0].stub.id);
        assert_eq!(reg.namespaces["destination"], ds[0].stub.id);
        assert!(reg.hosts.contains_key(&ds[0].stub.id));
    }
    f.st.save().await.unwrap();
    *f.st.reg.lock().unwrap() = Registry::load(&f.st.state_path).unwrap();
    assert_eq!(
        call(&f.st, "DELETE", "/v1/namespaces/destination", "api", None)
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(
            &f.st,
            "POST",
            "/v1/namespaces/destination/unpin",
            "api",
            None
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (s, b) = admit(&f, "destination", "req_one", "m_seed").await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(json(&b)["mode"], "cold");
    release.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(5), finished.notified())
        .await
        .unwrap();
    assert_eq!(
        ds[0].stub.machines.lock().unwrap()[0].namespace,
        "destination"
    );
    // The host finishing does not retroactively confirm the cancelled fleet response.
    assert_eq!(
        Registry::load(&f.st.state_path)
            .unwrap()
            .namespace_moves
            .len(),
        1
    );
    assert_eq!(f.st.reg.lock().unwrap().namespace_moves.len(), 1);
}

#[tokio::test]
async fn overlapping_move_completion_settles_only_its_own_monotonic_generation() {
    let (f, ds) = fleet_with_daemons(1).await;
    let machine = ds[0].stub.add("original", "web", 256);
    f.st.reg
        .lock()
        .unwrap()
        .machines
        .insert(machine.id.clone(), ds[0].stub.id.clone());
    let mut jobs = Vec::new();
    let mut releases = Vec::new();
    let mut generations = Vec::new();
    for _ in 0..2 {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        *ds[0].stub.move_gate.lock().unwrap() = Some((entered.clone(), release.clone()));
        let st = f.st.clone();
        let path = format!("/v1/machines/{}/move", machine.id);
        jobs.push(tokio::spawn(async move {
            call(
                &st,
                "POST",
                &path,
                "api",
                Some(serde_json::json!({"namespace":"destination"})),
            )
            .await
        }));
        tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        generations.push(f.st.reg.lock().unwrap().namespace_version("destination"));
        releases.push(release);
    }
    assert!(generations[1] > generations[0]);
    assert_eq!(f.st.reg.lock().unwrap().namespace_moves.len(), 2);
    releases[0].notify_one();
    assert_eq!(jobs.remove(0).await.unwrap().0, StatusCode::OK);
    assert_eq!(f.st.reg.lock().unwrap().namespace_moves.len(), 1);
    assert_eq!(
        Registry::load(&f.st.state_path)
            .unwrap()
            .namespace_moves
            .len(),
        1
    );
    assert_eq!(
        call(&f.st, "DELETE", "/v1/namespaces/destination", "api", None)
            .await
            .0,
        StatusCode::CONFLICT
    );
    releases[1].notify_one();
    assert_eq!(jobs.remove(0).await.unwrap().0, StatusCode::OK);
    let reg = f.st.reg.lock().unwrap();
    assert!(reg.namespace_moves.is_empty());
    assert_eq!(reg.namespace_version("destination"), generations[1]);
}
