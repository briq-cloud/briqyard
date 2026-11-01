use super::*;

#[tokio::test]
async fn catalog_routes_keep_namespace_host_and_refuse_extra_request_fields_before_forwarding() {
    let (f, ds) = fleet_with_daemons(2).await;
    {
        let mut reg = f.st.reg.lock().unwrap();
        reg.pin("team", "d1");
        reg.hosts.get_mut("d1").unwrap().warm_pool_profiles = vec!["init-ready-v1".into()];
    }
    for daemon in &ds {
        daemon.stub.calls.lock().unwrap().clear();
    }
    let path = "/v1/namespaces/team/warm-catalog";
    let _ = call(&f.st, "GET", path, "api", None).await;
    assert_eq!(ds[0].stub.calls(), [format!("GET {path}")]);
    assert!(ds[1].stub.calls().is_empty());
    let (status, _, _) = call(
        &f.st,
        "PUT",
        &format!("{path}/shell-small"),
        "api",
        Some(serde_json::json!({"desired":1,"source_machine":"m_injected"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(ds[0].stub.calls().len(), 1);
    let _ = call(
        &f.st,
        "PUT",
        &format!("{path}/shell-small"),
        "api",
        Some(serde_json::json!({"desired":1})),
    )
    .await;
    assert_eq!(
        ds[0].stub.calls().last().unwrap(),
        &format!("PUT {path}/shell-small")
    );
    assert!(ds[1].stub.calls().is_empty());
}

#[tokio::test]
async fn warm_claim_capability_is_required_and_legacy_poll_revokes_it() {
    let (f, ds) = fleet_with_daemons(1).await;
    f.st.reg.lock().unwrap().pin("team", "d1");
    ds[0].stub.calls.lock().unwrap().clear();
    let request = serde_json::json!({"name":"worker","request_id":"stable","fail_fast":true});
    let (status, _, body) = call(
        &f.st,
        "POST",
        "/v1/namespaces/team/warm-pools/tools/claims",
        "api",
        Some(request.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(json(&body)["code"], "capability_unsupported");
    assert!(ds[0].stub.calls().is_empty());
    f.st.reg
        .lock()
        .unwrap()
        .hosts
        .get_mut("d1")
        .unwrap()
        .warm_pool_profiles = vec!["init-ready-v1".into()];
    poll_static_hosts_once(&f.st).await;
    assert!(f.st.reg.lock().unwrap().hosts["d1"]
        .warm_pool_profiles
        .is_empty());
}

#[tokio::test]
async fn warm_claim_transfers_existing_reservation_even_when_host_has_no_new_capacity() {
    let (f, ds) = fleet_with_daemons(1).await;
    let slot = ds[0].stub.machine("team", "warm-slot", 256);
    let id = slot.id.clone();
    ds[0].stub.machines.lock().unwrap().push(slot);
    {
        let mut reg = f.st.reg.lock().unwrap();
        reg.pin("team", "d1");
        let host = reg.hosts.get_mut("d1").unwrap();
        host.warm_pool_profiles = vec!["init-ready-v1".into()];
        host.used = host.capacity;
    }
    let state = f.st.clone();
    *ds[0].stub.on_create.lock().unwrap() = Some(Box::new(move || {
        let reg = state.reg.lock().unwrap();
        let host = &reg.hosts["d1"];
        assert!(host.holds.is_empty());
        assert_eq!(host.used.memory_mb, host.capacity.memory_mb);
    }));
    let request = serde_json::json!({"name":"worker","request_id":"stable","fail_fast":true});
    let (status, headers, body) = call(
        &f.st,
        "POST",
        "/v1/namespaces/team/warm-pools/tools/claims",
        "api",
        Some(request),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d1");
    assert_eq!(json(&body)["id"], id);
    let reg = f.st.reg.lock().unwrap();
    assert_eq!(reg.machines[&id], "d1");
    assert!(reg.hosts["d1"].holds.is_empty());
}
