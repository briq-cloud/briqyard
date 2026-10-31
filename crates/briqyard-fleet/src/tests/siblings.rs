//! Capability-gated placement and forwarding through a mixed-version fleet.
use super::*;

fn request(namespace: &str) -> serde_json::Value {
    let mut body = create_body(namespace, "consumer", 128);
    body["egress"] = serde_json::json!({"mode":"via","via":"gateway","siblings":true});
    body
}

#[tokio::test]
async fn only_capable_hosts_receive_an_opt_in_and_downgrade_revokes_capability() {
    let (f, ds) = fleet_with_daemons(2).await;
    for d in &ds {
        d.stub.calls.lock().unwrap().clear();
    }
    let (status, _, body) = call(&f.st, "POST", "/v1/machines", "api", Some(request("new"))).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(json(&body)["code"], "capability_unsupported");
    assert!(!f.st.reg.lock().unwrap().namespaces.contains_key("new"));
    assert!(ds.iter().all(|d| d.stub.calls().is_empty()));
    f.st.reg
        .lock()
        .unwrap()
        .hosts
        .get_mut("d2")
        .unwrap()
        .egress_siblings_v1 = true;
    let (status, headers, body) =
        call(&f.st, "POST", "/v1/machines", "api", Some(request("new"))).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d2");
    assert!(ds[0].stub.calls().is_empty());
    assert!(
        ds[1].stub.creates.lock().unwrap()[0]
            .egress
            .as_ref()
            .unwrap()
            .siblings
    );
    // A subsequent legacy report clears the capability; the namespace stays pinned.
    poll_static_hosts_once(&f.st).await;
    ds[1].stub.calls.lock().unwrap().clear();
    let (status, _, body) = call(&f.st, "POST", "/v1/machines", "api", Some(request("new"))).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(json(&body)["code"], "capability_unsupported");
    assert!(ds[1].stub.calls().is_empty());
    assert_eq!(f.st.reg.lock().unwrap().namespaces["new"], "d2");
}

#[tokio::test]
async fn opt_in_patch_is_never_forwarded_to_a_legacy_host() {
    let (f, ds) = fleet_with_daemons(1).await;
    f.st.reg
        .lock()
        .unwrap()
        .hosts
        .get_mut("d1")
        .unwrap()
        .egress_siblings_v1 = false;
    let m = ds[0].stub.add("old", "consumer", 128);
    f.st.reg
        .lock()
        .unwrap()
        .machines
        .insert(m.id.clone(), "d1".into());
    ds[0].stub.calls.lock().unwrap().clear();
    let (status, _, body) = call(
        &f.st,
        "PATCH",
        &format!("/v1/machines/{}", m.id),
        "api",
        Some(serde_json::json!({"egress":{"mode":"via","via":"gateway","siblings":true}})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(json(&body)["code"], "capability_unsupported");
    assert!(ds[0]
        .stub
        .calls()
        .iter()
        .all(|call| !call.starts_with("PATCH")));
}
