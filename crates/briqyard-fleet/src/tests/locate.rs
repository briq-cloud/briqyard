//! Deletion after the machine index was lost still needs the namespace owner's answer.

use super::*;

#[tokio::test]
async fn unindexed_delete_keeps_pinned_down_unreachable_and_missing_host_errors() {
    let (f, ds) = fleet_with_daemons(1).await;
    let m = ds[0].stub.add("kept", "web", 512);
    f.st.reg.lock().unwrap().pin("kept", "d1");
    set_state(&f.st, "d1", "down");
    let before = ds[0].stub.calls();
    let written = std::fs::read(&f.st.state_path).unwrap();
    for query in ["namespace=kept", "tenant=kept"] {
        let (s, _, body) = call(
            &f.st,
            "DELETE",
            &format!("/v1/machines/{}?{query}", m.id),
            "api",
            None,
        )
        .await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(json(&body)["code"], "host_down");
    }
    assert_eq!(ds[0].stub.calls(), before, "down host is never asked");
    assert_eq!(ds[0].stub.machines.lock().unwrap().len(), 1);
    assert!(!f.st.reg.lock().unwrap().machines.contains_key(&m.id));
    assert_eq!(std::fs::read(&f.st.state_path).unwrap(), written);

    set_state(&f.st, "d1", "ready");
    f.st.reg.lock().unwrap().hosts.get_mut("d1").unwrap().url = "http://127.0.0.1:1".into();
    let path = format!("/v1/machines/{}?namespace=kept", m.id);
    let (s, _, body) = call(&f.st, "DELETE", &path, "api", None).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(json(&body)["code"], "host_unreachable");
    f.st.reg.lock().unwrap().hosts.remove("d1");
    f.st.reg
        .lock()
        .unwrap()
        .machines
        .insert(m.id.clone(), "d1".into());
    let (s, _, body) = call(&f.st, "DELETE", &path, "api", None).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(json(&body)["code"], "host_unreachable");
    assert_eq!(pinned(&f.st, "kept").as_deref(), Some("d1"));
    assert_eq!(
        f.st.reg
            .lock()
            .unwrap()
            .machines
            .get(&m.id)
            .map(String::as_str),
        Some("d1")
    );
    assert_eq!(std::fs::read(&f.st.state_path).unwrap(), written);
}

#[tokio::test]
async fn unindexed_delete_reaches_pinned_host_despite_failed_get_and_refreshes_only_success() {
    let (f, ds) = fleet_with_daemons(2).await;
    // The owner cannot answer discovery GET, but still handles DELETE correctly.
    *ds[0].stub.machine_get_reply.lock().unwrap() = Some((
        StatusCode::SERVICE_UNAVAILABLE,
        serde_json::json!({"code": "busy"}),
    ));
    f.st.reg.lock().unwrap().pin("kept", "d1");
    for query in ["namespace=kept", "tenant=kept"] {
        let m = ds[0].stub.add("kept", "web", 512);
        f.st.reg
            .lock()
            .unwrap()
            .hosts
            .get_mut("d1")
            .unwrap()
            .used
            .memory_mb = 512;
        let before = ds[0].stub.calls().len();
        let path = format!("/v1/machines/{}?{query}", m.id);
        let (s, headers, body) = call_with(
            &f.st,
            "127.0.0.1".parse().unwrap(),
            &[("If-Match", "7")],
            "DELETE",
            &path,
            "api",
            None,
        )
        .await;
        assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
        assert_eq!(headers["x-briqyard-host"], "d1");
        assert_eq!(
            &ds[0].stub.calls()[before..],
            &[
                format!("GET /v1/machines/{}", m.id),
                format!("DELETE {path}"),
                "GET /v1/status".into(),
            ]
        );
        assert_eq!(ds[0].stub.if_match.lock().unwrap().last().unwrap(), "7");
        assert!(ds[0].stub.machines.lock().unwrap().is_empty());
        assert!(!saved(&f.st).machines.contains_key(&m.id));
        assert_eq!(f.st.reg.lock().unwrap().hosts["d1"].used.memory_mb, 0);
        assert_eq!(pinned(&f.st, "kept").as_deref(), Some("d1"));

        // Only the owner's actual 404 confirms absence; it is forwarded unchanged.
        let before = ds[0].stub.calls().len();
        let (s, headers, _) = call(&f.st, "DELETE", &path, "api", None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert_eq!(headers["x-briqyard-host"], "d1");
        assert_eq!(
            &ds[0].stub.calls()[before..],
            &[
                format!("GET /v1/machines/{}", m.id),
                format!("DELETE {path}"),
            ]
        );
    }
    assert!(!ds[1].stub.calls().iter().any(|c| c.starts_with("DELETE")));
}

#[tokio::test]
async fn delete_hint_never_overrides_indexed_or_discovered_machine_owner() {
    let (f, ds) = fleet_with_daemons(2).await;
    f.st.reg.lock().unwrap().pin("other", "d2");
    set_state(&f.st, "d2", "down");
    for indexed in [true, false] {
        let m = ds[0].stub.add("kept", "web", 512);
        if indexed {
            f.st.reg
                .lock()
                .unwrap()
                .machines
                .insert(m.id.clone(), "d1".into());
        }
        let before = ds[1].stub.calls();
        let (s, headers, body) = call(
            &f.st,
            "DELETE",
            &format!("/v1/machines/{}?namespace=other", m.id),
            "api",
            None,
        )
        .await;
        assert_eq!(s, StatusCode::NO_CONTENT, "{indexed}: {body}");
        assert_eq!(headers["x-briqyard-host"], "d1");
        assert_eq!(ds[1].stub.calls(), before);
        assert!(ds[0].stub.machines.lock().unwrap().is_empty());
        assert_eq!(pinned(&f.st, "other").as_deref(), Some("d2"));
    }
    // A wrong hint after failed discovery reaches only that pin. It does not search
    // another namespace's owner for deletion or touch that owner's hidden machine.
    set_state(&f.st, "d2", "ready");
    let hidden = ds[0].stub.add("kept", "hidden", 512);
    ds[1].stub.add("other", "unrelated", 512);
    *ds[0].stub.machine_get_reply.lock().unwrap() = Some((
        StatusCode::SERVICE_UNAVAILABLE,
        serde_json::json!({"code": "busy"}),
    ));
    let before = ds[0].stub.calls().len();
    let (s, headers, _) = call(
        &f.st,
        "DELETE",
        &format!("/v1/machines/{}?namespace=other", hidden.id),
        "api",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(headers["x-briqyard-host"], "d2");
    assert!(!ds[0].stub.calls()[before..]
        .iter()
        .any(|c| c.starts_with("DELETE")));
    assert_eq!(ds[0].stub.machines.lock().unwrap().len(), 1);
    assert_eq!(ds[1].stub.machines.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn delete_fallback_requires_valid_existing_pin_and_exact_delete_path() {
    let (f, ds) = fleet_with_daemons(1).await;
    f.st.reg.lock().unwrap().pin("kept", "d1");
    set_state(&f.st, "d1", "down");
    let before = ds[0].stub.calls();
    let written = std::fs::read(&f.st.state_path).unwrap();
    for (method, path) in [
        ("DELETE", "/v1/machines/m_gone"),
        ("DELETE", "/v1/machines/m_gone?namespace=absent"),
        ("GET", "/v1/machines/m_gone?namespace=kept"),
        ("POST", "/v1/machines/m_gone/start?namespace=kept"),
        ("DELETE", "/v1/machines/m_gone/endpoints?namespace=kept"),
    ] {
        let (s, _, body) = call(&f.st, method, path, "api", None).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{method} {path}: {body}");
        assert_eq!(json(&body)["code"], "not_found");
    }
    for query in [
        "namespace=Bad",
        "tenant=",
        "namespace=kept%26tenant%3Dother",
    ] {
        let (s, _, body) = call(
            &f.st,
            "DELETE",
            &format!("/v1/machines/m_gone?{query}"),
            "api",
            None,
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{query}: {body}");
        assert_eq!(json(&body)["code"], "invalid");
    }
    assert_eq!(ds[0].stub.calls(), before);
    assert_eq!(pinned(&f.st, "absent"), None);
    assert_eq!(pinned(&f.st, "kept").as_deref(), Some("d1"));
    assert_eq!(std::fs::read(&f.st.state_path).unwrap(), written);
}

/// Fleet routing must preserve the adapter's flattened payload and CAS header.
/// The HTTP peer is a stub: daemon lifecycle/authority belongs to Manager/native tests.
#[tokio::test]
async fn stopped_spec_patch_preserves_wire_body_cas_and_registered_host_routing() {
    for different_registration in [false, true] {
        for reports_cpu in [false, true] {
            let (f, ds) = fleet_with_daemons(1).await;
            let machine = ds[0].stub.add("destination", "home", 256);
            ds[0].stub.machines.lock().unwrap()[0].state = api::state::STOPPED.into();
            poll_static_hosts_once(&f.st).await;
            let registered = if different_registration {
                "h_registered"
            } else {
                "d1"
            };
            {
                let mut reg = f.st.reg.lock().unwrap();
                let mut host = reg.hosts.remove("d1").unwrap();
                host.id = registered.into();
                if !reports_cpu {
                    host.capacity.cpu_millis = None;
                }
                reg.hosts.insert(registered.into(), host);
                reg.machines.insert(machine.id.clone(), registered.into());
                reg.namespaces
                    .insert("destination".into(), registered.into());
            }
            let path = format!("/v1/machines/{}?namespace=destination", machine.id);
            ds[0].stub.calls();
            for resource in 0..4 {
                let mut body = serde_json::json!({
                    "image": "alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "env": if resource == 1 { serde_json::json!({}) } else { serde_json::json!({"REPLACEMENT":"new"}) }
                });
                if resource > 0 {
                    body["size"] = serde_json::json!({"vcpus":1,"memory_mb":256});
                    if resource >= 2 {
                        body["size"]["cpu_millis"] =
                            serde_json::json!(if resource == 3 { 0 } else { 1000 });
                    }
                    body["disk_limits"] =
                        serde_json::json!({"bandwidth_mb":100,"iops":1000,"burst_sec":1});
                }
                let before = ds[0].stub.patches.lock().unwrap().len();
                let cas_before = ds[0].stub.if_match.lock().unwrap().len();
                let (status, _, answer) = call_with(
                    &f.st,
                    std::net::IpAddr::from([127, 0, 0, 1]),
                    &[("if-match", "7")],
                    "PATCH",
                    &path,
                    "api",
                    Some(body.clone()),
                )
                .await;
                if resource >= 2 && !reports_cpu {
                    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{answer}");
                    assert_eq!(ds[0].stub.patches.lock().unwrap().len(), before);
                    assert_eq!(ds[0].stub.if_match.lock().unwrap().len(), cas_before);
                } else {
                    assert_eq!(status, StatusCode::OK, "{answer}");
                    let patches = ds[0].stub.patches.lock().unwrap();
                    assert_eq!(patches.len(), before + 1);
                    assert_eq!(patches.last().unwrap(), &(machine.id.clone(), body));
                    assert_eq!(
                        ds[0]
                            .stub
                            .if_match
                            .lock()
                            .unwrap()
                            .last()
                            .map(String::as_str),
                        Some("7")
                    );
                }
                let reg = f.st.reg.lock().unwrap();
                assert_eq!(reg.machines[&machine.id], registered);
                assert_eq!(reg.namespaces["destination"], registered);
            }
            assert!(!ds[0]
                .stub
                .calls()
                .iter()
                .any(|call| call.contains("/start")));
            assert_eq!(
                ds[0].stub.machines.lock().unwrap()[0].state,
                api::state::STOPPED
            );
        }
    }
}
