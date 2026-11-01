use super::*;

#[tokio::test]
async fn template_build_never_reaches_hosts_without_explicit_capability() {
    let (f, ds) = fleet_with_daemons(1).await;
    ds[0].stub.calls.lock().unwrap().clear();
    let mut body = create_body("new", "builder", 256);
    body["template_build"] = "init-ready-v1".into();
    let (status, _, response) = call(&f.st, "POST", "/v1/machines", "api", Some(body)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{response}");
    assert_eq!(json(&response)["code"], "capability_unsupported");
    assert!(!f.st.reg.lock().unwrap().namespaces.contains_key("new"));
    assert!(ds[0].stub.calls().is_empty());
}

#[tokio::test]
async fn named_fork_is_bound_to_source_capability_and_legacy_report_revokes_it() {
    let (f, ds) = fleet_with_daemons(1).await;
    let id = ds[0].stub.id.clone();
    {
        let mut reg = f.st.reg.lock().unwrap();
        reg.machines.insert("m_source".into(), id.clone());
        reg.hosts.get_mut(&id).unwrap().named_memory_fork_v1 = true;
    }
    poll_static_hosts_once(&f.st).await;
    assert!(!f.st.reg.lock().unwrap().hosts[&id].named_memory_fork_v1);
    ds[0].stub.calls.lock().unwrap().clear();
    let mut body = create_body("new", "clone", 256);
    body["fork"] = serde_json::json!({"machine_id":"m_source","snapshot":"ready"});
    let (status, _, response) = call(&f.st, "POST", "/v1/machines", "api", Some(body)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{response}");
    assert_eq!(json(&response)["code"], "capability_unsupported");
    assert!(ds[0].stub.calls().is_empty());
}

#[tokio::test]
async fn placement_only_selects_the_advertised_init_ready_profile() {
    let (f, ds) = fleet_with_daemons(1).await;
    let id = ds[0].stub.id.clone();
    {
        let mut reg = f.st.reg.lock().unwrap();
        let host = reg.hosts.get_mut(&id).unwrap();
        host.named_memory_fork_v1 = true;
        host.named_memory_profiles = vec!["service-ready-v1".into()];
    }
    let mut body = create_body("new", "builder", 256);
    body["template_build"] = "init-ready-v1".into();
    body["sleep"] = "never".into();
    let (status, _, response) =
        call(&f.st, "POST", "/v1/machines", "api", Some(body.clone())).await;
    assert_eq!(status, StatusCode::CONFLICT, "{response}");
    f.st.reg
        .lock()
        .unwrap()
        .hosts
        .get_mut(&id)
        .unwrap()
        .named_memory_profiles = vec!["init-ready-v1".into()];
    let (status, headers, response) = call(&f.st, "POST", "/v1/machines", "api", Some(body)).await;
    assert_eq!(status, StatusCode::CREATED, "{response}");
    assert_eq!(headers["x-briqyard-host"], id);
    assert_eq!(
        ds[0].stub.creates.lock().unwrap()[0]
            .template_build
            .as_deref(),
        Some("init-ready-v1")
    );
}

fn sandbox_body() -> serde_json::Value {
    let mut body = create_body("destination", "sandbox", 256);
    body["sandbox_seed"] = serde_json::json!({"machine_id":"m_operator","snapshot":"s_one","generation":"g_one","request_id":"req_one"});
    body["start"] = true.into();
    body["volume"] = serde_json::json!({"size_gb":2,"mount":"/work"});
    body
}
#[tokio::test]
async fn sandbox_selector_pins_source_host_generation_and_existing_namespace_placement() {
    let (f, ds) = fleet_with_daemons(2).await;
    let id = ds[0].stub.id.clone();
    {
        let mut reg = f.st.reg.lock().unwrap();
        reg.machines.insert("m_operator".into(), id.clone());
        let host = reg.hosts.get_mut(&id).unwrap();
        host.named_memory_fork_v1 = true;
        host.named_memory_profiles = vec!["sandbox-ready-v1".into()];
    }
    ds[0].stub.snapshots.lock().unwrap().push(api::Snapshot {
        id: "s_one".into(),
        machine_id: "m_operator".into(),
        name: None,
        created_at: Utc::now(),
        disks: vec!["root".into(), "data".into()],
        memory: true,
        clone_profile: Some("sandbox-ready-v1".into()),
        source_host: Some(id.clone()),
        clone_size: Some(api::Size {
            vcpus: 1,
            memory_mb: 256,
            cpu_millis: None,
        }),
        clone_ram_marker: None,
        clone_generation: Some("g_one".into()),
    });
    let mut stale = sandbox_body();
    stale["sandbox_seed"]["generation"] = "g_old".into();
    let (status, _, _) = call(&f.st, "POST", "/v1/machines", "api", Some(stale)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(ds[0].stub.creates.lock().unwrap().is_empty());
    f.st.reg
        .lock()
        .unwrap()
        .namespaces
        .insert("destination".into(), ds[1].stub.id.clone());
    let (status, _, _) = call(&f.st, "POST", "/v1/machines", "api", Some(sandbox_body())).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(ds[0].stub.creates.lock().unwrap().is_empty());
    f.st.reg.lock().unwrap().namespaces.remove("destination");
    let (status, headers, response) =
        call(&f.st, "POST", "/v1/machines", "api", Some(sandbox_body())).await;
    assert_eq!(status, StatusCode::CREATED, "{response}");
    assert_eq!(headers["x-briqyard-host"], id);
    assert_eq!(
        ds[0].stub.creates.lock().unwrap()[0]
            .sandbox_seed
            .as_ref()
            .unwrap()
            .generation,
        "g_one"
    );
    assert!(ds[1].stub.creates.lock().unwrap().is_empty());
}
#[tokio::test]
async fn sandbox_seed_is_unavailable_without_configured_fleet_authentication() {
    let f = fleet(config::Config::default());
    let (status, _, _) = call(&f.st, "POST", "/v1/machines", "", Some(sandbox_body())).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(f.st.reg.lock().unwrap().namespaces.is_empty());
}

#[tokio::test]
async fn accepted_sandbox_lookup_precedes_removed_source_disabled_profile_and_full_capacity() {
    use sha2::{Digest, Sha256};
    let (f, ds) = fleet_with_daemons(1).await;
    let id = ds[0].stub.id.clone();
    let existing = ds[0].stub.machine("destination", "sandbox", 256);
    *ds[0].stub.sandbox_lookup.lock().unwrap() =
        Some((StatusCode::OK, serde_json::to_value(&existing).unwrap()));
    {
        let mut reg = f.st.reg.lock().unwrap();
        reg.namespaces.insert("destination".into(), id.clone());
        let host = reg.hosts.get_mut(&id).unwrap();
        host.named_memory_profiles.clear();
        host.named_memory_fork_v1 = false;
        host.used = host.capacity;
        host.state = "draining".into();
    }
    let body = sandbox_body();
    let parsed: api::CreateMachineRequest = serde_json::from_value(body.clone()).unwrap();
    crate::create_replay::insert_route(
        &mut f.st.reg.lock().unwrap(),
        crate::create_replay::request_route(&parsed, id.clone())
            .unwrap_or_else(|_| panic!("valid routing fixture")),
    );
    let (status, headers, response) = call(&f.st, "POST", "/v1/machines", "api", Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(headers["x-briqyard-host"], id);
    assert_eq!(json(&response)["id"], existing.id);
    assert!(ds[0].stub.creates.lock().unwrap().is_empty());
    assert_eq!(
        ds[0].stub.sandbox_lookups.lock().unwrap()[0].create_sha256,
        format!(
            "{:x}",
            Sha256::digest(parsed.sandbox_create_bytes().unwrap())
        )
    );
    let (status, _, _) = call(&f.st, "DELETE", "/v1/namespaces/destination", "api", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(!f
        .st
        .reg
        .lock()
        .unwrap()
        .namespaces
        .contains_key("destination"));
    assert!(
        crate::create_replay::existing_route(&f.st.reg.lock().unwrap(), &parsed)
            .unwrap_or_else(|_| panic!("valid routing fixture"))
            .is_some()
    );
    f.st.reg
        .lock()
        .unwrap()
        .namespaces
        .insert("destination".into(), "new-host".into());
    let (status, _, _) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(serde_json::to_value(&parsed).unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        f.st.reg.lock().unwrap().namespaces["destination"],
        "new-host"
    );
    f.st.reg.lock().unwrap().forget(&id);
    let (status, _, _) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(serde_json::to_value(&parsed).unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        crate::create_replay::existing_route(&f.st.reg.lock().unwrap(), &parsed)
            .unwrap_or_else(|_| panic!("valid routing fixture"))
            .is_some()
    );
}
#[tokio::test]
async fn existing_dispatch_intent_never_authorizes_another_create_even_after_authoritative_miss() {
    for (response_status, body, expected) in [
        (
            StatusCode::NOT_FOUND,
            serde_json::json!({"code":"not_found","error":"missing"}),
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({"code":"host_unreachable","error":"unreachable"}),
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            StatusCode::OK,
            serde_json::json!({"id":"m_bad"}),
            StatusCode::BAD_GATEWAY,
        ),
        (
            StatusCode::CONFLICT,
            serde_json::json!({"code":"conflict","error":"changed"}),
            StatusCode::CONFLICT,
        ),
        (
            StatusCode::NOT_FOUND,
            serde_json::json!({"code":"sandbox_request_unknown","error":"unknown"}),
            StatusCode::CONFLICT,
        ),
    ] {
        let (f, ds) = fleet_with_daemons(1).await;
        let id = ds[0].stub.id.clone();
        let request: api::CreateMachineRequest = serde_json::from_value(sandbox_body()).unwrap();
        crate::create_replay::insert_route(
            &mut f.st.reg.lock().unwrap(),
            crate::create_replay::request_route(&request, id)
                .unwrap_or_else(|_| panic!("valid routing fixture")),
        );
        *ds[0].stub.sandbox_lookup.lock().unwrap() = Some((response_status, body));
        let (status, _, _) = call(&f.st, "POST", "/v1/machines", "api", Some(sandbox_body())).await;
        // Even an authoritative daemon miss cannot replay an existing dispatch intent.
        assert_eq!(status, expected);
        assert!(ds[0].stub.creates.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn stale_namespace_delete_response_does_not_unpin_a_new_create_placement() {
    let (f, ds) = fleet_with_daemons(1).await;
    let id = ds[0].stub.id.clone();
    f.st.reg.lock().unwrap().pin("destination", &id);
    let state = f.st.clone();
    *ds[0].stub.on_delete_namespace.lock().unwrap() = Some(Box::new(move || {
        state
            .reg
            .lock()
            .unwrap()
            .note_namespace_create("destination");
    }));
    let (status, _, _) = call(&f.st, "DELETE", "/v1/namespaces/destination", "api", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(f.st.reg.lock().unwrap().namespaces["destination"], id);
}
#[tokio::test]
async fn new_request_after_namespace_cleanup_may_use_another_host_without_replaying_the_old_key() {
    let (f, ds) = fleet_with_daemons(2).await;
    let old_id = ds[0].stub.id.clone();
    let new_id = ds[1].stub.id.clone();
    let old_body = sandbox_body();
    let old_req: api::CreateMachineRequest = serde_json::from_value(old_body.clone()).unwrap();
    crate::create_replay::insert_route(
        &mut f.st.reg.lock().unwrap(),
        crate::create_replay::request_route(&old_req, old_id.clone())
            .unwrap_or_else(|_| panic!("valid routing fixture")),
    );
    f.st.reg.lock().unwrap().pin("destination", &old_id);
    let (status, _, _) = call(&f.st, "DELETE", "/v1/namespaces/destination", "api", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(!f
        .st
        .reg
        .lock()
        .unwrap()
        .namespaces
        .contains_key("destination"));
    {
        let mut reg = f.st.reg.lock().unwrap();
        reg.machines.insert("m_second".into(), new_id.clone());
        let host = reg.hosts.get_mut(&new_id).unwrap();
        host.named_memory_fork_v1 = true;
        host.named_memory_profiles = vec!["sandbox-ready-v1".into()];
    }
    ds[1].stub.snapshots.lock().unwrap().push(api::Snapshot {
        id: "s_two".into(),
        machine_id: "m_second".into(),
        name: None,
        created_at: Utc::now(),
        disks: vec!["root".into(), "data".into()],
        memory: true,
        clone_profile: Some("sandbox-ready-v1".into()),
        source_host: Some(new_id.clone()),
        clone_size: Some(api::Size {
            vcpus: 1,
            memory_mb: 256,
            cpu_millis: None,
        }),
        clone_ram_marker: None,
        clone_generation: Some("g_two".into()),
    });
    let mut body = sandbox_body();
    body["sandbox_seed"] = serde_json::json!({"machine_id":"m_second","snapshot":"s_two","generation":"g_two","request_id":"req_two"});
    let (status, headers, response) = call(&f.st, "POST", "/v1/machines", "api", Some(body)).await;
    assert_eq!(status, StatusCode::CREATED, "{response}");
    assert_eq!(headers["x-briqyard-host"], new_id);
    let (status, _, _) = call(&f.st, "POST", "/v1/machines", "api", Some(old_body)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(ds[0].stub.creates.lock().unwrap().is_empty());
    assert_eq!(ds[1].stub.creates.lock().unwrap().len(), 1);
    assert_eq!(f.st.reg.lock().unwrap().namespaces["destination"], new_id);
}

#[tokio::test]
async fn namespace_delete_waits_for_an_admitted_create_but_tombstones_hold_no_network_resources() {
    let (f, ds) = fleet_with_daemons(1).await;
    let host = ds[0].stub.id.clone();
    let hold = {
        let mut reg = f.st.reg.lock().unwrap();
        reg.pin("destination", &host);
        let hold = reg.hold(&host, 256, 2048, 1000);
        reg.bind_hold_namespace(&host, hold, "destination");
        hold
    };
    let (status, _, _) = call(&f.st, "DELETE", "/v1/namespaces/destination", "api", None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    f.st.reg.lock().unwrap().release(&host, hold);
    let request: api::CreateMachineRequest = serde_json::from_value(sandbox_body()).unwrap();
    crate::create_replay::insert_route(
        &mut f.st.reg.lock().unwrap(),
        crate::create_replay::request_route(&request, host)
            .unwrap_or_else(|_| panic!("valid routing fixture")),
    );
    let (status, _, _) = call(&f.st, "DELETE", "/v1/namespaces/destination", "api", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(!f
        .st
        .reg
        .lock()
        .unwrap()
        .namespaces
        .contains_key("destination"));
    assert!(
        crate::create_replay::existing_route(&f.st.reg.lock().unwrap(), &request)
            .unwrap_or_else(|_| panic!("valid routing fixture"))
            .is_some()
    );
}
