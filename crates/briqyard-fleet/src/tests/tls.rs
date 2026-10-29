//! TLS to the hosts (ADR 0020).

use super::*;

#[tokio::test]
async fn an_added_host_is_pinned_at_bootstrap_then_forwarded_to_over_tls() {
    let (cert, fp) = certificate();
    let d = start_daemon_on("d1", "tok", Some(&cert)).await;
    assert!(d.url.starts_with("https://127.0.0.1:"));
    let f = fleet(config::Config::default());
    {
        let mut added = static_host(&config::StaticHost::default(), Utc::now());
        added.id = "h_srv-9".into();
        added.url = d.url.clone();
        added.state = "provisioning".into();
        added.provider = "manual".into();
        added.token = "tok".into();
        f.st.reg
            .lock()
            .unwrap()
            .hosts
            .insert(added.id.clone(), added);
    }
    let mut hb = heartbeat(&d.url, 64_000, &[]);
    hb["tls_fingerprint"] = fp.clone().into();
    // The daemon is up before the bootstrap has read its certificate: not taken on its word.
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/register", "tok", Some(hb.clone())).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(json(&body)["code"], "tls_mismatch");
    assert!(json(&body)["error"]
        .as_str()
        .unwrap()
        .contains("no fingerprint is pinned"));
    assert_eq!(hosts(&f.st)[0].state, "provisioning");
    // The bootstrap pins it; the next heartbeat makes the host ready.
    {
        let mut reg = f.st.reg.lock().unwrap();
        let r = reg.hosts.get_mut("h_srv-9").unwrap();
        bootstrap::bootstrapped(r, "bootstrapped".into(), fp.clone());
    }
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/register", "tok", Some(hb.clone())).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    let h = &hosts(&f.st)[0];
    assert_eq!(
        (h.state.as_str(), h.tls_fingerprint.as_str()),
        ("ready", fp.as_str())
    );
    assert_eq!(saved(&f.st).hosts["h_srv-9"].tls_fingerprint, fp, "written");
    // A create is forwarded over TLS, to the pinned certificate.
    let (s, headers, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "",
        Some(create_body("t1", "web", 512)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert_eq!(headers["x-briqyard-host"], "h_srv-9");
    assert_eq!(d.stub.calls(), ["POST /v1/machines"]);
    // Another machine at that address: refused, the pin kept.
    let (_, other) = certificate();
    hb["tls_fingerprint"] = other.clone().into();
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/register", "tok", Some(hb)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
    let why = json(&body)["error"].as_str().unwrap().to_string();
    assert!(
        why.starts_with(&format!("certificate {other} is not the one pinned ({fp})")),
        "{why}"
    );
    assert_eq!(hosts(&f.st)[0].tls_fingerprint, fp);
}

#[tokio::test]
async fn a_host_presenting_another_certificate_is_not_forwarded_to() {
    let (served, _) = certificate();
    let (_, pinned) = certificate();
    let d = start_daemon_on("d1", "tok", Some(&served)).await;
    d.stub.add("t1", "web", 512);
    let f = fleet(config::Config {
        hosts: vec![config::StaticHost {
            id: "d1".into(),
            url: d.url.clone(),
            token: "tok".into(),
            tls_fingerprint: pinned.clone(),
            ..Default::default()
        }],
        ..Default::default()
    });
    let (s, _, body) = call(&f.st, "GET", "/v1/machines", "", None).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY, "{body}");
    let v = json(&body);
    assert_eq!(v["code"], "host_unreachable");
    let why = v["error"].as_str().unwrap();
    assert!(
        why.contains(&format!("is not the pinned {pinned}")),
        "{why}"
    );
    assert!(
        d.stub.calls().is_empty(),
        "no request reached it, token included"
    );
    // The poll asks it nothing either: its capacity stays unknown.
    poll_static_hosts_once(&f.st).await;
    assert_eq!(hosts(&f.st)[0].capacity.memory_mb, 0);
    assert!(d.stub.calls().is_empty());
}
