//! What Prometheus scrapes (ADR 0054).

use super::*;

#[tokio::test]
async fn the_targets_are_every_host_through_the_relay_at_the_address_asked() {
    let f = fleet(config::Config {
        token: "api".into(),
        ..Default::default()
    });
    seed(&f.st, "a", 64_000, 0, 0, &[]);
    seed(&f.st, "b", 64_000, 0, 0, &[]);
    seed(&f.st, "c", 64_000, 0, 0, &[]);
    seed(&f.st, "new", 64_000, 0, 0, &[]);
    f.st.reg.lock().unwrap().hosts.get_mut("a").unwrap().region = "gra".into();
    set_state(&f.st, "b", "down");
    set_state(&f.st, "c", "draining");
    set_state(&f.st, "new", "provisioning");
    let host = [("host", "fleet.example.com")];
    let peer = std::net::IpAddr::from([127, 0, 0, 1]);
    let (s, _, body) = call_with(
        &f.st,
        peer,
        &host,
        "GET",
        "/v1/metrics/targets",
        "api",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let want = serde_json::json!([
        { "targets": ["fleet.example.com"], "labels": { "instance": "fleet" } },
        { "targets": ["fleet.example.com"], "labels": {
            "__metrics_path__": "/v1/hosts/a/metrics", "instance": "a", "host": "a", "region": "gra" } },
        // A down host is still a target: scraped, it is `up == 0`.
        { "targets": ["fleet.example.com"], "labels": {
            "__metrics_path__": "/v1/hosts/b/metrics", "instance": "b", "host": "b", "region": "" } },
        { "targets": ["fleet.example.com"], "labels": {
            "__metrics_path__": "/v1/hosts/c/metrics", "instance": "c", "host": "c", "region": "" } },
        // A host still being bootstrapped has no daemon to scrape yet.
    ]);
    assert_eq!(json(&body), want);
    // Retired and forgotten: gone from the next answer.
    f.st.reg.lock().unwrap().hosts.remove("c");
    let (_, _, body) = call_with(
        &f.st,
        peer,
        &host,
        "GET",
        "/v1/metrics/targets",
        "api",
        None,
    )
    .await;
    assert_eq!(json(&body).as_array().unwrap().len(), 3);
    // No Host header: no address to give.
    let (s, _, body) = call(&f.st, "GET", "/v1/metrics/targets", "api", None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
}

/// A host whose `/metrics` answers its text, over TLS when `cert` is given.
async fn metrics_host(cert: Option<&rcgen::CertifiedKey>) -> String {
    async fn text(headers: HeaderMap) -> Response {
        if headers.get(header::AUTHORIZATION).map(|v| v.as_bytes()) != Some(b"Bearer h-tok") {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        (
            [(
                header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            "briqyard_machines_total 3\n",
        )
            .into_response()
    }
    let app = Router::new()
        .route("/metrics", get(text))
        .into_make_service();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    match cert {
        None => {
            tokio::spawn(axum_server::from_tcp(listener).serve(app));
            format!("http://{addr}")
        }
        Some(c) => {
            let cfg = api::tls::server_config(
                c.cert.pem().as_bytes(),
                c.key_pair.serialize_pem().as_bytes(),
            )
            .unwrap();
            let cfg = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(cfg));
            tokio::spawn(axum_server::from_tcp_rustls(listener, cfg).serve(app));
            format!("https://{addr}")
        }
    }
}

fn metrics_fleet(url: &str, fingerprint: &str) -> Fleet {
    fleet(config::Config {
        token: "api".into(),
        hosts: vec![config::StaticHost {
            id: "h1".into(),
            url: url.into(),
            token: "h-tok".into(),
            tls_fingerprint: fingerprint.into(),
            ..Default::default()
        }],
        ..Default::default()
    })
}

#[tokio::test]
async fn a_hosts_metrics_are_relayed_over_its_pinned_certificate_with_its_token() {
    let (cert, fp) = certificate();
    let url = metrics_host(Some(&cert)).await;
    let f = metrics_fleet(&url, &fp);
    let (s, headers, body) = call(&f.st, "GET", "/v1/hosts/h1/metrics", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(
        body, "briqyard_machines_total 3\n",
        "the host's text as it is"
    );
    assert_eq!(
        headers[header::CONTENT_TYPE],
        "text/plain; version=0.0.4; charset=utf-8"
    );
    assert_eq!(headers["x-briqyard-host"], "h1");
    // Another certificate at that address: not the host, nothing sent to it.
    let (_, other) = certificate();
    let f = metrics_fleet(&url, &other);
    let (s, _, body) = call(&f.st, "GET", "/v1/hosts/h1/metrics", "api", None).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY, "{body}");
    assert!(
        body.contains(&format!("is not the pinned {other}")),
        "{body}"
    );
    // A host's own refusal is relayed as it is: a token the host does not take.
    let url = metrics_host(None).await;
    let f = metrics_fleet(&url, "");
    f.st.reg.lock().unwrap().hosts.get_mut("h1").unwrap().token = "stale".into();
    let (s, _, _) = call(&f.st, "GET", "/v1/hosts/h1/metrics", "api", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_host_down_or_silent_is_not_scraped_as_up() {
    let url = metrics_host(None).await;
    let f = metrics_fleet(&url, "");
    set_state(&f.st, "h1", "down");
    let (s, _, body) = call(&f.st, "GET", "/v1/hosts/h1/metrics", "api", None).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(json(&body)["code"], "host_down");
    // Ready in the registry, nothing listening: it does not answer.
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let f = metrics_fleet(&format!("http://{closed}"), "");
    let (s, _, body) = call(&f.st, "GET", "/v1/hosts/h1/metrics", "api", None).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(json(&body)["code"], "host_unreachable");
    assert!(
        json(&body)["error"]
            .as_str()
            .unwrap()
            .starts_with("host h1: "),
        "{body}"
    );
    let (s, _, body) = call(&f.st, "GET", "/v1/hosts/nope/metrics", "api", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn a_body_cut_short_is_a_host_that_did_not_answer() {
    async fn cut() -> Response {
        let chunks: Vec<std::io::Result<Bytes>> = vec![
            Ok(Bytes::from_static(b"briqyard_machines_total 3\n")),
            Err(std::io::Error::other("gone")),
        ];
        Body::from_stream(futures::stream::iter(chunks)).into_response()
    }
    let app = Router::new()
        .route("/metrics", get(cut))
        .into_make_service();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum_server::from_tcp(listener).serve(app));
    let f = metrics_fleet(&format!("http://{addr}"), "");
    let (s, _, body) = call(&f.st, "GET", "/v1/hosts/h1/metrics", "api", None).await;
    assert_eq!(
        s,
        StatusCode::BAD_GATEWAY,
        "a 200 with half a body would read as up: {body}"
    );
    assert_eq!(json(&body)["code"], "host_unreachable");
}

#[tokio::test]
async fn a_keyed_host_is_forgotten_only_by_force() {
    let f = fleet(config::Config {
        hosts: vec![config::StaticHost {
            id: "s1".into(),
            url: "http://10.0.0.1:7420".into(),
            token: "s1-token".into(),
            ..Default::default()
        }],
        ..Default::default()
    });
    seed(&f.st, "plain", 64_000, 0, 0, &[]);
    let (s, _, _) = call(&f.st, "DELETE", "/v1/hosts/plain", "", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "no key: forgotten as before");
    let ask = Some(serde_json::json!({ "url": "http://10.0.0.1:7420" }));
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/key", "s1-token", ask).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, body) = call(&f.st, "DELETE", "/v1/hosts/s1", "", None).await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");
    assert_eq!(json(&body)["code"], "pool_key");
    assert!(
        body.contains("the pool is unreadable at the host's next restart; retire it, or --force"),
        "{body}"
    );
    assert!(f.st.reg.lock().unwrap().hosts.contains_key("s1"), "kept");
    let (s, _, body) = call(&f.st, "DELETE", "/v1/hosts/s1?force=true", "", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    assert!(
        !saved(&f.st).hosts.contains_key("s1"),
        "forgotten, its key with it"
    );
}

/// A key the registry could not be written with is not kept: the next ask is refused the same
/// way rather than served a key only memory holds (ADR 0026).
#[tokio::test]
async fn a_key_that_could_not_be_written_is_not_served() {
    let dir = tempfile::tempdir().unwrap();
    let nowhere = dir.path().join("missing").join("registry.json");
    let f = fleet_at(
        config::Config {
            hosts: vec![config::StaticHost {
                id: "s1".into(),
                url: "http://10.0.0.1:7420".into(),
                token: "s1-token".into(),
                ..Default::default()
            }],
            ..Default::default()
        },
        dir,
        nowhere.clone(),
    );
    let ask = Some(serde_json::json!({ "url": "http://10.0.0.1:7420" }));
    for attempt in 1..=2 {
        let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s1-token", ask.clone()).await;
        assert_eq!(
            s,
            StatusCode::INTERNAL_SERVER_ERROR,
            "attempt {attempt}: {body}"
        );
        assert_eq!(json(&body)["code"], "registry");
        assert!(
            f.st.reg.lock().unwrap().hosts["s1"].pool_key.is_empty(),
            "attempt {attempt}"
        );
    }
    std::fs::create_dir_all(nowhere.parent().unwrap()).unwrap();
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s1-token", ask).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(
        saved(&f.st).hosts["s1"].pool_key.expose(),
        json(&body)["key"].as_str().unwrap()
    );
}

#[tokio::test]
async fn a_registry_that_cannot_be_written_fails_the_request() {
    let dir = tempfile::tempdir().unwrap();
    let nowhere = dir.path().join("missing").join("registry.json");
    let f = fleet_at(config::Config::default(), dir, nowhere.clone());
    seed(&f.st, "h_a", 64_000, 0, 0, &[]);
    for (method, path) in [
        ("POST", "/v1/hosts/h_a/drain"),
        ("POST", "/v1/namespaces/t1/unpin"),
        ("DELETE", "/v1/hosts/h_a"),
    ] {
        let (s, _, text) = call(&f.st, method, path, "", None).await;
        assert_eq!(
            s,
            StatusCode::INTERNAL_SERVER_ERROR,
            "{method} {path}: {text}"
        );
        let v = json(&text);
        assert_eq!(v["code"], "registry", "{method} {path}");
        assert!(
            v["error"]
                .as_str()
                .unwrap()
                .contains(&format!("write registry {}", nowhere.display())),
            "{v}"
        );
    }
    assert!(!nowhere.exists());
    // A create is refused before any host is asked: a pin the fleet would forget on restart
    // could put the namespace's next machine on another host.
    let d = start_daemon("d1", "tok").await;
    let dir = tempfile::tempdir().unwrap();
    let nowhere = dir.path().join("missing").join("registry.json");
    let g = fleet_at(
        config::Config {
            hosts: vec![config::StaticHost {
                id: "d1".into(),
                url: d.url.clone(),
                token: "tok".into(),
                ..Default::default()
            }],
            ..Default::default()
        },
        dir,
        nowhere,
    );
    poll_static_hosts_once(&g.st).await;
    let before = d.stub.calls().len();
    let (s, _, body) = call(
        &g.st,
        "POST",
        "/v1/machines",
        "",
        Some(create_body("t1", "web", 512)),
    )
    .await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(json(&body)["code"], "registry");
    assert_eq!(d.stub.calls().len(), before, "the host was not asked");
}

/// ADR 0043: writes take turns, each writing the registry as it is when its turn comes.
/// Hundreds at once all succeed, every read of the file in between parses, and the file
/// ends with every change.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn writes_at_once_all_land_and_the_file_ends_with_every_change() {
    use std::sync::atomic::AtomicBool;
    let f = fleet(config::Config::default());
    let stop = Arc::new(AtomicBool::new(false));
    let reader = {
        let (path, stop) = (f.st.state_path.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut reads = 0;
            while !stop.load(Ordering::SeqCst) {
                if let Ok(data) = std::fs::read(&path) {
                    serde_json::from_slice::<Registry>(&data).expect("a read parses");
                    reads += 1;
                }
            }
            reads
        })
    };
    let writes: Vec<_> = (0..300)
        .map(|i| {
            let st = f.st.clone();
            tokio::spawn(async move {
                st.reg
                    .lock()
                    .unwrap()
                    .namespaces
                    .insert(format!("t{i}"), "h_a".into());
                st.save().await
            })
        })
        .collect();
    for w in writes {
        w.await.unwrap().expect("a write");
    }
    stop.store(true, Ordering::SeqCst);
    assert!(reader.join().unwrap() > 0);
    assert_eq!(
        saved(&f.st).namespaces.len(),
        300,
        "the last write holds them all"
    );
    assert!(!f.st.state_path.with_extension("json.tmp").exists());
}

/// Creates at once never fail on the registry's write, and each machine is in the file.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn creates_at_once_all_land_in_the_registry() {
    let (f, _ds) = fleet_with_daemons(2).await;
    let creates: Vec<_> = (0..64)
        .map(|i| {
            let st = f.st.clone();
            tokio::spawn(async move {
                let body = create_body(&format!("t{i}"), "web", 256);
                call(&st, "POST", "/v1/machines", "api", Some(body)).await
            })
        })
        .collect();
    for c in creates {
        let (s, _, body) = c.await.unwrap();
        assert_eq!(s, StatusCode::CREATED, "{body}");
    }
    let reg = saved(&f.st);
    assert_eq!((reg.machines.len(), reg.namespaces.len()), (64, 64));
}

/// A machine the host made is the caller's answer even when the write after it fails: a 500
/// there would leave a machine nobody knows the id of. The next write records it.
#[tokio::test]
async fn a_machine_made_is_answered_when_the_write_after_it_fails() {
    let d = start_daemon("d1", "tok").await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    std::fs::create_dir(&state).unwrap();
    let g = fleet_at(
        config::Config {
            hosts: vec![config::StaticHost {
                id: "d1".into(),
                url: d.url.clone(),
                token: "tok".into(),
                ..Default::default()
            }],
            ..Default::default()
        },
        dir,
        state.join("registry.json"),
    );
    poll_static_hosts_once(&g.st).await;
    // The host makes it; meanwhile the fleet's state directory goes.
    let gone = state.with_extension("gone");
    {
        let (state, gone) = (state.clone(), gone.clone());
        *d.stub.on_create.lock().unwrap() =
            Some(Box::new(move || std::fs::rename(&state, &gone).unwrap()));
    }
    let (s, _, body) = call(
        &g.st,
        "POST",
        "/v1/machines",
        "",
        Some(create_body("t1", "web", 512)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    let id = json(&body)["id"].as_str().unwrap().to_string();
    assert_eq!(g.st.reg.lock().unwrap().machines[&id], "d1");
    std::fs::rename(&gone, &state).unwrap();
    assert!(!saved(&g.st).machines.contains_key(&id));
    poll_static_hosts_once(&g.st).await;
    assert_eq!(saved(&g.st).machines[&id], "d1", "the next write has it");
}
