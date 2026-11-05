//! Evacuation authority and restart boundaries, with the ordinary stub daemons.
use super::*;
use crate::evacuations::{driver, Evacuation, MachineCopy};

async fn fixture() -> (Fleet, Vec<Running>, String, String) {
    let (f, ds) = fleet_with_daemons(2).await;
    for d in &ds {
        d.stub.evacuate_v1.store(true, Ordering::SeqCst);
    }
    let mut machine = ds[0].stub.add("t1", "db", 256);
    machine.state = "stopped".into();
    *ds[0].stub.machines.lock().unwrap() = vec![machine.clone()];
    let ep = ds[0].stub.add_endpoint(&machine.id);
    let job = Evacuation {
        job: "ev_test".into(),
        namespace: "t1".into(),
        from: "d1".into(),
        to: "d2".into(),
        step: "planned".into(),
        machines: vec![MachineCopy {
            id: machine.id.clone(),
            name: machine.name,
            manifest: serde_json::json!({"id":machine.id,"config_digest":"config","root_bytes":1<<20,"data_bytes":0,"ip":machine.ip}),
            backup: None,
            restored: false,
            verified: false,
            ip: String::new(),
        }],
        endpoints: vec![ep.clone()],
        quota: Default::default(),
        started: Utc::now(),
        error: None,
        cancel_requested: false,
        drop_snapshots: false,
        reservation: 0,
    };
    {
        let mut reg = f.st.reg.lock().unwrap();
        reg.namespaces.insert("t1".into(), "d1".into());
        reg.machines.insert(machine.id.clone(), "d1".into());
        reg.endpoints.insert(ep.id.clone(), "d1".into());
        reg.evacuations.insert("t1".into(), job);
        driver::reserve(&mut reg, "t1");
    }
    f.st.save().await.unwrap();
    (f, ds, machine.id, ep.id)
}

#[tokio::test]
async fn duplicate_ids_never_change_authority_and_rollback_ignores_stale_indexes() {
    let (f, ds, id, ep) = fixture().await;
    let m = ds[0].stub.machines.lock().unwrap()[0].clone();
    ds[1].stub.machines.lock().unwrap().push(m);
    let endpoint = ds[0].stub.endpoints.lock().unwrap()[0].clone();
    ds[1].stub.endpoints.lock().unwrap().push(endpoint);
    for path in [
        "/v1/machines",
        "/v1/machines?namespace=t1",
        "/v1/machines?label=absent",
        "/v1/endpoints",
    ] {
        let (status, _, bytes) = call(&f.st, "GET", path, "api", None).await;
        assert_eq!(status, StatusCode::OK, "{bytes}");
        let expected = if path.contains("label=") { 0 } else { 1 };
        assert_eq!(json(&bytes).as_array().unwrap().len(), expected, "{path}");
    }
    assert_eq!(f.st.reg.lock().unwrap().machines[&id], "d1");
    assert_eq!(f.st.reg.lock().unwrap().endpoints[&ep], "d1");
    let (status, _, _) = call(
        &f.st,
        "POST",
        &format!("/v1/machines/{id}/start"),
        "api",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    for (step, owner) in [("switched", "d2"), ("cancelled", "d1")] {
        {
            let mut reg = f.st.reg.lock().unwrap();
            reg.evacuations.get_mut("t1").unwrap().step = step.into();
            reg.machines
                .insert(id.clone(), if owner == "d1" { "d2" } else { "d1" }.into());
            reg.endpoints
                .insert(ep.clone(), if owner == "d1" { "d2" } else { "d1" }.into());
        }
        for path in [format!("/v1/machines/{id}"), format!("/v1/endpoints/{ep}")] {
            let (status, headers, bytes) = call(&f.st, "GET", &path, "api", None).await;
            assert_eq!(status, StatusCode::OK, "{bytes}");
            assert_eq!(headers["x-briqyard-host"], owner);
        }
    }
}

#[tokio::test]
async fn restart_after_each_failed_effect_finishes_without_deleting_an_unverified_source() {
    let effects = [
        (0, "POST /v1/machines/ID/hold"),
        (0, "POST /v1/machines/ID/backups"),
        (1, "PUT /v1/namespaces/t1/quota"),
        (1, "POST /v1/machines"),
        (1, "GET /v1/machines/ID/evacuation-manifest"),
        (1, "POST /v1/machines/ID/endpoints"),
        (1, "DELETE /v1/machines/ID/hold"),
        (0, "DELETE /v1/machines/ID"),
        (0, "DELETE /v1/namespaces/t1"),
    ];
    for (which, path) in effects {
        for lose_response in [false, true] {
            let (f, ds, id, ep) = fixture().await;
            let path = path.replace("ID", &id);
            if lose_response {
                *ds[which].stub.evacuation_lost_response.lock().unwrap() = Some(path.clone());
            } else {
                *ds[which].stub.evacuation_fault.lock().unwrap() = Some(path.clone());
            }
            assert!(driver::run(&f.st, "t1").await.is_err(), "{path}");
            let durable = saved(&f.st);
            if ds[0].stub.machines.lock().unwrap().is_empty() {
                let job = &durable.evacuations["t1"];
                assert!(
                    job.switched() && job.machines.iter().all(|m| m.verified),
                    "{path}"
                );
                assert_eq!(durable.namespaces["t1"], "d2");
            }
            // Drop all fleet memory; only its durable registry and the daemons survive.
            *f.st.reg.lock().unwrap() = durable;
            *ds[which].stub.evacuation_fault.lock().unwrap() = None;
            *ds[which].stub.evacuation_lost_response.lock().unwrap() = None;
            driver::run(&f.st, "t1")
                .await
                .unwrap_or_else(|e| panic!("{path}: {e:#}"));
            let durable = saved(&f.st);
            assert_eq!(durable.evacuations["t1"].step, "done", "{path}");
            assert_eq!(durable.machines[&id], "d2");
            assert_eq!(durable.endpoints[&ep], "d2");
            assert!(ds[0].stub.machines.lock().unwrap().is_empty());
            assert_eq!(ds[1].stub.machines.lock().unwrap()[0].id, id);
            assert!(ds[1].stub.holds.lock().unwrap().is_empty());
        }
    }
}

#[tokio::test]
async fn cancel_before_switch_preserves_the_source_and_removes_only_the_held_target() {
    let (f, ds, id, _) = fixture().await;
    ds[0]
        .stub
        .holds
        .lock()
        .unwrap()
        .insert(id.clone(), "ev_test".into());
    let m = ds[0].stub.machines.lock().unwrap()[0].clone();
    ds[1].stub.machines.lock().unwrap().push(m);
    ds[1]
        .stub
        .holds
        .lock()
        .unwrap()
        .insert(id.clone(), "ev_test".into());
    f.st.reg
        .lock()
        .unwrap()
        .evacuations
        .get_mut("t1")
        .unwrap()
        .cancel_requested = true;
    driver::run(&f.st, "t1").await.unwrap();
    assert_eq!(saved(&f.st).evacuations["t1"].step, "cancelled");
    assert_eq!(ds[0].stub.machines.lock().unwrap()[0].id, id);
    assert!(ds[0].stub.holds.lock().unwrap().is_empty());
    assert!(ds[1].stub.machines.lock().unwrap().is_empty());
    let (status, _, _) = call(
        &f.st,
        "POST",
        &format!("/v1/machines/{id}/start"),
        "api",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[test]
fn previous_registry_without_evacuation_field_loads_and_preserves_retired_keys() {
    let mut old = serde_json::to_value(Registry::default()).unwrap();
    old.as_object_mut().unwrap().remove("evacuations");
    old["retired_keys"] =
        serde_json::json!([{"host":"h_old","key":"00".repeat(32),"retired_at":Utc::now()}]);
    let reg: Registry = serde_json::from_value(old).unwrap();
    assert!(reg.evacuations.is_empty());
    assert_eq!(reg.retired_keys.len(), 1);
    assert_eq!(reg.retired_keys[0].host, "h_old");
}

#[tokio::test]
async fn verification_failure_rolls_back_and_keeps_source_data_authoritative() {
    let (f, ds, id, _) = fixture().await;
    ds[1].stub.manifest_mismatch.store(true, Ordering::SeqCst);
    assert!(driver::run(&f.st, "t1").await.is_err());
    let reg = saved(&f.st);
    assert_eq!(reg.evacuations["t1"].step, "cancelled");
    assert!(reg.evacuations["t1"]
        .error
        .as_ref()
        .unwrap()
        .contains("config_digest"));
    assert_eq!(reg.machines[&id], "d1");
    assert_eq!(ds[0].stub.machines.lock().unwrap()[0].id, id);
    assert!(ds[1].stub.machines.lock().unwrap().is_empty());
    assert!(!ds[0]
        .stub
        .calls()
        .contains(&format!("DELETE /v1/machines/{id}")));
}

#[tokio::test]
async fn preflight_refuses_gateway_running_old_version_and_no_room_before_any_hold() {
    for case in ["gateway", "running", "capability_unsupported", "no_room"] {
        let (f, ds, _, _) = fixture().await;
        f.st.reg.lock().unwrap().evacuations.clear();
        ds[0]
            .stub
            .quotas
            .lock()
            .unwrap()
            .push(("t1".into(), Default::default()));
        match case {
            "gateway" => ds[0].stub.gateways.lock().unwrap().push(("t1".into(), 128)),
            "running" => ds[0].stub.machines.lock().unwrap()[0].state = "running".into(),
            "capability_unsupported" => ds[0].stub.evacuate_v1.store(false, Ordering::SeqCst),
            "no_room" => {
                f.st.reg
                    .lock()
                    .unwrap()
                    .hosts
                    .get_mut("d2")
                    .unwrap()
                    .disk_free_mb = Some(0)
            }
            _ => unreachable!(),
        }
        let (status, _, body) = call(
            &f.st,
            "POST",
            "/v1/namespaces/t1/evacuate",
            "api",
            Some(serde_json::json!({"to":"d2"})),
        )
        .await;
        assert!(!status.is_success(), "{case}: {body}");
        assert_eq!(json(&body)["code"], case, "{body}");
        assert!(ds.iter().all(|d| d.stub.holds.lock().unwrap().is_empty()));
        assert!(ds[0].stub.calls().iter().all(|c| !c.ends_with("/backups")));
    }
}

#[tokio::test]
async fn heartbeat_and_host_forget_cannot_remove_an_open_jobs_authority() {
    let (f, _, id, _) = fixture().await;
    {
        let mut reg = f.st.reg.lock().unwrap();
        let mut source = reg.hosts["d1"].clone();
        source.namespaces.clear();
        reg.heartbeat(source, Utc::now() + Duration::hours(1));
        let mut target = reg.hosts["d2"].clone();
        target.namespaces = vec!["t1".into()];
        reg.heartbeat(target, Utc::now() + Duration::hours(1));
        assert_eq!(reg.namespaces["t1"], "d1");
        reg.forget("d1");
        reg.forget("d2");
        assert!(reg.hosts.contains_key("d1") && reg.hosts.contains_key("d2"));
        assert_eq!(reg.machines[&id], "d1");
    }
    for path in ["/v1/hosts/d1/retire", "/v1/hosts/d2/retire"] {
        let (status, _, _) = call(&f.st, "POST", path, "api", None).await;
        assert_eq!(status, StatusCode::CONFLICT);
    }
}
