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
