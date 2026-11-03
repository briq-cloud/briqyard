//! Placement by runtime class (ADR 0088).

use super::*;

fn in_class(namespace: &str, name: &str, class: &str) -> serde_json::Value {
    let mut b = create_body(namespace, name, 512);
    if !class.is_empty() {
        b["runtime_class"] = class.into();
    }
    b
}

fn nested() -> Vec<api::RuntimeClassInfo> {
    vec![api::RuntimeClassInfo {
        name: "nested".into(),
        nested: true,
        kernel_release: "6.18.54-briqyard-nested".into(),
        openzfs: "2.4.1".into(),
    }]
}

/// d1 serves `nested`; d2 serves only `default`.
async fn two_hosts() -> (Fleet, Vec<Running>) {
    let (f, ds) = fleet_in_regions(&["gra", "gra"]).await;
    *ds[0].stub.runtime_classes.lock().unwrap() = nested();
    poll_static_hosts_once(&f.st).await;
    (f, ds)
}

#[tokio::test]
async fn a_hosts_classes_come_with_its_report_and_show_in_the_listing() {
    let (f, _ds) = two_hosts().await;
    assert_eq!(
        f.st.reg.lock().unwrap().hosts["d1"].runtime_classes,
        nested()
    );
    assert!(f.st.reg.lock().unwrap().hosts["d2"]
        .runtime_classes
        .is_empty());
    let (_, _, body) = call(&f.st, "GET", "/v1/hosts", "api", None).await;
    let hosts: Vec<api::Host> = serde_json::from_str(&body).unwrap();
    assert_eq!(
        hosts.iter().find(|h| h.id == "d1").unwrap().runtime_classes,
        nested()
    );
}

#[tokio::test]
async fn a_new_namespace_naming_a_class_goes_to_a_host_that_serves_it() {
    let (f, ds) = two_hosts().await;
    // d2 has the memory free; d1 is fuller.
    ds[0].stub.add("t0", "big", 10_000);
    poll_static_hosts_once(&f.st).await;
    let (s, headers, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(in_class("t1", "a", "nested")),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d1");
    // Its next machines stay there, in the class or not.
    let (s, headers, _) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(in_class("t1", "b", "")),
    )
    .await;
    assert_eq!(
        (s, &headers["x-briqyard-host"]),
        (StatusCode::CREATED, &HeaderValue::from_static("d1"))
    );
}

#[tokio::test]
async fn a_default_namespace_avoids_the_host_that_serves_nested_while_another_has_room() {
    let (f, ds) = two_hosts().await;
    // d1 is the emptier; by memory alone t1 would go there.
    ds[1].stub.add("t0", "big", 10_000);
    poll_static_hosts_once(&f.st).await;
    let (s, headers, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(in_class("t1", "a", "")),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d2");
    // When d2 has no room it goes to d1 all the same.
    ds[1]
        .stub
        .add("t0", "full", daemon::DAEMON_MEMORY_MB - 10_000);
    poll_static_hosts_once(&f.st).await;
    let (s, headers, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(in_class("t3", "a", "")),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d1");
}

#[tokio::test]
async fn a_namespace_on_a_host_without_the_class_is_refused_and_so_is_a_class_nobody_serves() {
    let (f, ds) = two_hosts().await;
    ds[0].stub.add("t0", "big", 10_000);
    poll_static_hosts_once(&f.st).await;
    // t1 is placed on d2 (it serves no nested and has the room).
    let (s, headers, _) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(in_class("t1", "a", "")),
    )
    .await;
    assert_eq!(
        (s, &headers["x-briqyard-host"]),
        (StatusCode::CREATED, &HeaderValue::from_static("d2"))
    );
    let before = ds[1].stub.calls().len();
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(in_class("t1", "b", "nested")),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["code"], "invalid");
    assert_eq!(
        json(&body)["error"],
        "namespace t1 is on host d2, which does not serve runtime class nested"
    );
    assert_eq!(ds[1].stub.calls().len(), before, "d2 was never asked");
    // No host serves it at all.
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(in_class("t2", "a", "gvisor")),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["error"], "no host serves runtime class gvisor");
    assert_eq!(pinned(&f.st, "t2"), None);
}
