//! Auth, status and hosts.

use super::*;

#[test]
fn a_static_host_without_an_id_is_named_by_its_url() {
    let now = Utc::now();
    let h = static_host(
        &config::StaticHost {
            url: "http://10.0.0.5:7420".into(),
            token: "t".into(),
            ..Default::default()
        },
        now,
    );
    assert_eq!(h.id, "http://10.0.0.5:7420");
    assert_eq!(h.state, "ready");
    assert_eq!(h.provider, "static");
    assert_eq!(h.token, "t");
    let named = static_host(
        &config::StaticHost {
            id: "h1".into(),
            url: "http://10.0.0.5:7420".into(),
            ..Default::default()
        },
        now,
    );
    assert_eq!(named.id, "h1");
}

#[test]
fn with_host_marks_a_machine_body_and_leaves_the_rest() {
    let out = with_host(Bytes::from(r#"{"id":"m1","host":""}"#), "d1");
    assert_eq!(json(std::str::from_utf8(&out).unwrap())["host"], "d1");
    let list = Bytes::from(r#"[{"id":"m1"}]"#);
    assert_eq!(
        with_host(list.clone(), "d1"),
        list,
        "not an object: untouched"
    );
    let text = Bytes::from("not json");
    assert_eq!(with_host(text.clone(), "d1"), text);
    assert_eq!(
        error_code(br#"{"error":"full","code":"capacity"}"#),
        "capacity"
    );
    assert_eq!(error_code(b"[]"), "");
}

#[tokio::test]
async fn a_bearer_token_guards_every_route_but_healthz_and_register() {
    let f = fleet(config::Config {
        token: "api".into(),
        ..Default::default()
    });
    let (s, _, body) = call(&f.st, "GET", "/healthz", "", None).await;
    assert_eq!((s, body.as_str()), (StatusCode::OK, "ok\n"));
    let (s, _, body) = call(&f.st, "GET", "/v1/status", "", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(json(&body)["code"], "unauthorized");
    let (s, _, _) = call(&f.st, "GET", "/v1/status", "wrong", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _, _) = call(&f.st, "GET", "/v1/status", "api", None).await;
    assert_eq!(s, StatusCode::OK);
    // The register route is checked against the host's own token, not the API's: with the
    // API token it gets as far as the handler, which knows no host at that address.
    let hb = heartbeat("http://10.0.0.1:7420", 1000, &[]);
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/register", "api", Some(hb)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(json(&body)["code"], "unknown_host");

    // No token configured: nothing is asked of API clients.
    let open = fleet(config::Config::default());
    let (s, _, _) = call(&open.st, "GET", "/v1/hosts", "", None).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn a_registration_is_taken_only_for_the_host_that_expects_it() {
    let f = fleet(config::Config {
        token: "api".into(),
        hosts: vec![
            config::StaticHost {
                id: "s1".into(),
                url: "http://10.0.0.1:7420".into(),
                token: "s1-token".into(),
                region: "fsn".into(),
                ..Default::default()
            },
            config::StaticHost {
                id: "open".into(),
                url: "http://10.0.0.2:7420".into(),
                ..Default::default()
            },
        ],
        ..Default::default()
    });
    // An address no record expects: refused whatever it presents.
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/hosts/register",
        "s1-token",
        Some(heartbeat("http://10.0.0.9:7420", 1000, &[])),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
    let v = json(&body);
    assert_eq!(v["code"], "unknown_host");
    assert!(v["error"].as_str().unwrap().contains("10.0.0.9"), "{v}");
    assert_eq!(hosts(&f.st).len(), 2, "nothing was added");
    // The expected address with another host's token, the API token, or none: refused.
    for token in ["", "api", "wrong", "s1-toke"] {
        let (s, _, body) = call(
            &f.st,
            "POST",
            "/v1/hosts/register",
            token,
            Some(heartbeat("http://10.0.0.1:7420", 1000, &[])),
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "token {token:?}: {body}");
        assert_eq!(json(&body)["code"], "unauthorized");
    }
    assert_eq!(hosts(&f.st)[1].capacity.memory_mb, 0, "nothing was taken");
    // A host listed without a token is polled only: no token opens its registration.
    let (s, _, _) = call(
        &f.st,
        "POST",
        "/v1/hosts/register",
        "",
        Some(heartbeat("http://10.0.0.2:7420", 1000, &[])),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // Its own token: taken, under the id the fleet knows it by, whatever the daemon calls itself.
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/hosts/register",
        "s1-token",
        Some(heartbeat("http://10.0.0.1:7420", 64_000, &["t1"])),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    let hs = hosts(&f.st);
    assert_eq!(hs.len(), 2);
    assert_eq!(hs[1].id, "s1");
    assert_eq!(hs[1].capacity.memory_mb, 64_000);
    assert_eq!(hs[1].region, "par");
    assert_eq!(hs[1].namespaces, ["t1"]);
    assert_eq!(pinned(&f.st, "t1").as_deref(), Some("s1"));
    assert_eq!(
        f.st.reg.lock().unwrap().hosts["s1"].token,
        "s1-token",
        "a heartbeat never changes a token"
    );
    assert!(
        saved(&f.st).hosts["s1"].capacity.memory_mb == 64_000,
        "written"
    );
}

/// A host's pool key (ADR 0026): made at its first ask and the same after, served to the host
/// at its address with its own token and to nobody else, written (`0600`) before it is
/// answered, in no listing, and no longer the host's once its record is forgotten.
#[tokio::test]
async fn a_host_gets_its_own_pool_key_and_no_other() {
    let host = |id: &str, n: u8| config::StaticHost {
        id: id.into(),
        url: format!("http://10.0.0.{n}:7420"),
        token: format!("{id}-token"),
        ..Default::default()
    };
    let f = fleet(config::Config {
        token: "api".into(),
        hosts: vec![host("s1", 1), host("s2", 2)],
        ..Default::default()
    });
    let ask = |n: u8| Some(serde_json::json!({ "url": format!("http://10.0.0.{n}:7420") }));
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s1-token", ask(9)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(json(&body)["code"], "unknown_host");
    for token in ["", "api", "s2-token"] {
        let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", token, ask(1)).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "token {token:?}: {body}");
    }
    assert!(
        f.st.reg.lock().unwrap().hosts["s1"].pool_key.is_empty(),
        "nothing made for a refused ask"
    );

    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s1-token", ask(1)).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let key = json(&body)["key"].as_str().unwrap().to_string();
    assert!(
        key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()),
        "ZFS's hex format: {key}"
    );
    assert_eq!(saved(&f.st).hosts["s1"].pool_key.expose(), key, "written");
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&f.st.state_path)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "the registry is the fleet's alone");
    let (_, _, again) = call(&f.st, "POST", "/v1/hosts/key", "s1-token", ask(1)).await;
    assert_eq!(json(&again)["key"], key.as_str(), "the same key every time");
    let (_, _, other) = call(&f.st, "POST", "/v1/hosts/key", "s2-token", ask(2)).await;
    assert_ne!(json(&other)["key"], key.as_str(), "one key per host");

    let (_, _, listed) = call(&f.st, "GET", "/v1/hosts", "api", None).await;
    assert!(!listed.contains(&key), "never listed: {listed}");
    let (s, _, _) = call(&f.st, "DELETE", "/v1/hosts/s1?force=true", "api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s1-token", ask(1)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
    assert!(!body.contains(&key));
}

/// A backup's key (ADR 0035): the key of a backup's `key_id`, a live host's or a forgotten
/// one's (kept as a retired key), served to the host the fleet forwarded a restore to, for
/// that restore, once; refused with no restore open, and never made for the ask.
#[tokio::test]
async fn a_host_gets_the_key_of_a_backup_for_a_restore_it_was_given() {
    let host = |id: &str, n: u8| config::StaticHost {
        id: id.into(),
        url: format!("http://10.0.0.{n}:7420"),
        token: format!("{id}-token"),
        ..Default::default()
    };
    let f = fleet(config::Config {
        token: "api".into(),
        hosts: vec![host("s1", 1), host("s2", 2)],
        ..Default::default()
    });
    let rs = api::RestoreSpec {
        machine_id: "m_src".into(),
        backup: "b1".into(),
    };
    let ask = |n: u8, id: &str| {
        Some(serde_json::json!({
            "url": format!("http://10.0.0.{n}:7420"),
            "key_id": id,
            "restore": { "machine_id": "m_src", "backup": "b1" },
        }))
    };
    let opened = |host: &str| {
        f.st.restores.open(host, &rs, std::time::Instant::now());
    };
    let own = Some(serde_json::json!({ "url": "http://10.0.0.1:7420" }));
    let (_, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s1-token", own).await;
    let k1 = json(&body)["key"].as_str().unwrap().to_string();
    let id1 = briqyard_api::poolkey::id(&k1).unwrap();

    // Its own, by id: served without a restore, as without the id (ADR 0045).
    let mine = Some(serde_json::json!({ "url": "http://10.0.0.1:7420", "key_id": id1 }));
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s1-token", mine).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(json(&body)["key"], k1.as_str());
    // No restore forwarded to s2: refused, with or without one named.
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s2-token", ask(2, &id1)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(json(&body)["code"], "no_restore");
    let bare = Some(serde_json::json!({ "url": "http://10.0.0.2:7420", "key_id": id1 }));
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/key", "s2-token", bare).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // One forwarded to s2: served to s2 once. s1's ask for its own key leaves it open.
    opened("s2");
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s1-token", ask(1, &id1)).await;
    assert_eq!(s, StatusCode::OK, "its own: {body}");
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s2-token", ask(2, &id1)).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(
        json(&body)["key"],
        k1.as_str(),
        "s1's key, for s2's restore"
    );
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/key", "s2-token", ask(2, &id1)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "served once");
    assert!(
        f.st.reg.lock().unwrap().hosts["s2"].pool_key.is_empty(),
        "no key made for s2 by an ask for another's"
    );
    opened("s2");
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/hosts/key",
        "s2-token",
        ask(2, &"0".repeat(32)),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(json(&body)["code"], "no_key");
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/key", "api", ask(2, &id1)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "a host's token only");
    // Neither refusal took the restore: it is the last check.

    // s1 forgotten: its key stays, for its backups, and for nothing else.
    let (s, _, _) = call(&f.st, "DELETE", "/v1/hosts/s1?force=true", "api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s2-token", ask(2, &id1)).await;
    assert_eq!(
        s,
        StatusCode::OK,
        "the restore opened before the 404, still open: {body}"
    );
    assert_eq!(json(&body)["key"], k1.as_str());
    let retired = &saved(&f.st).retired_keys;
    assert_eq!(retired.len(), 1);
    assert_eq!(
        (retired[0].host.as_str(), retired[0].key.expose()),
        ("s1", k1.as_str())
    );
}

/// A restore says what the fleet will trust once started on it, never a token or a key.
#[test]
fn a_restore_says_what_the_fleet_will_trust() {
    let mut reg = Registry::default();
    let mut h = static_host(
        &config::StaticHost {
            id: "h1".into(),
            url: "https://10.0.0.1:7420".into(),
            token: "h1-token".into(),
            ..Default::default()
        },
        Utc.with_ymd_and_hms(2026, 10, 21, 12, 0, 0).unwrap(),
    );
    h.tls_fingerprint = "ab".repeat(32);
    reg.hosts.insert("h1".into(), h);
    let (key, _) = reg.pool_key("h1").unwrap();
    let out = restored(
        &reg,
        "file:///b fleet/registry.json.age",
        std::path::Path::new("/s/registry.json"),
    );
    assert!(out.starts_with("restored 1 hosts (1 pool keys, 0 retired) and 0 namespaces from file:///b fleet/registry.json.age into /s/registry.json\n"), "{out}");
    assert!(
        out.contains("newest heartbeat in it: 2026-10-21T12:00:00+00:00"),
        "{out}"
    );
    assert!(
        out.contains("  h1  https://10.0.0.1:7420  pin abababababababab…  token  pool key\n"),
        "{out}"
    );
    assert!(
        !out.contains("h1-token") && !out.contains(key.expose()),
        "{out}"
    );
}

/// With a backup, a pool key is handed out only once the store holds it (ADR 0032): a store
/// that refuses the write refuses the key, and the backup read back holds the key served.
#[tokio::test]
async fn a_pool_key_is_in_the_backup_before_it_is_served() {
    let dir = tempfile::tempdir().unwrap();
    let identity = dir.path().join("backup.key");
    let recipient = backup::keygen(&identity).unwrap();
    let store = dir.path().join("store");
    let f = fleet(config::Config {
        hosts: vec![config::StaticHost {
            id: "s1".into(),
            url: "http://10.0.0.1:7420".into(),
            token: "s1-token".into(),
            ..Default::default()
        }],
        backup: config::Backup {
            store: format!("file://{}", store.display()),
            recipient,
            ..Default::default()
        },
        ..Default::default()
    });
    let ask = Some(serde_json::json!({ "url": "http://10.0.0.1:7420" }));
    // The store's directory turned into a file: no write can make its `fleet/`, whoever runs.
    let aside = dir.path().join("store.aside");
    std::fs::rename(&store, &aside).unwrap();
    std::fs::write(&store, b"").unwrap();
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s1-token", ask.clone()).await;
    std::fs::remove_file(&store).unwrap();
    std::fs::rename(&aside, &store).unwrap();
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(json(&body)["code"], "backup");
    assert!(
        !body.contains("\"key\"") && !body.contains("store"),
        "no key, no details: {body}"
    );
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s1-token", ask).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let key = json(&body)["key"].as_str().unwrap().to_string();
    let b = f.st.backup.as_ref().unwrap();
    let back = b
        .fetch(backup::LATEST, &backup::identity(&identity).unwrap())
        .await
        .unwrap();
    assert_eq!(back.hosts["s1"].pool_key.expose(), key);
}

/// Where the fleet terminates the connection (its TLS, or plain on loopback), a host's call
/// must come from the host's address: its token alone, read off a disk that left our hands, is
/// not enough (ADR 0026). Behind `tls: off` the peer is the proxy in front: not checked.
#[tokio::test]
async fn a_host_call_must_come_from_the_host() {
    let hosts = vec![
        config::StaticHost {
            id: "s1".into(),
            url: "http://10.0.0.1:7420".into(),
            token: "s1-token".into(),
            ..Default::default()
        },
        config::StaticHost {
            id: "named".into(),
            url: "http://host.example:7420".into(),
            token: "named-token".into(),
            ..Default::default()
        },
    ];
    let f = fleet(config::Config {
        hosts: hosts.clone(),
        ..Default::default()
    });
    let ask = |u: &str| Some(serde_json::json!({ "url": u }));
    let elsewhere = std::net::IpAddr::from([203, 0, 113, 7]);
    for path in ["/v1/hosts/key", "/v1/hosts/register"] {
        let body = if path.ends_with("key") {
            ask("http://10.0.0.1:7420")
        } else {
            Some(heartbeat("http://10.0.0.1:7420", 1000, &[]))
        };
        let (s, _, text) = call_from(&f.st, elsewhere, "POST", path, "s1-token", body).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{path}: {text}");
        assert!(
            text.contains("come from 10.0.0.1, not 203.0.113.7"),
            "{text}"
        );
    }
    assert!(f.st.reg.lock().unwrap().hosts["s1"].pool_key.is_empty());
    // A host known by a name cannot be checked by address: refused, saying so.
    let (s, _, text) = call_from(
        &f.st,
        elsewhere,
        "POST",
        "/v1/hosts/key",
        "named-token",
        ask("http://host.example:7420"),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{text}");
    assert!(text.contains("its url must be one"), "{text}");
    // An IPv4 peer seen as IPv6-mapped is the same address.
    let mapped: std::net::IpAddr = "::ffff:10.0.0.1".parse().unwrap();
    let (s, _, text) = call_from(
        &f.st,
        mapped,
        "POST",
        "/v1/hosts/key",
        "s1-token",
        ask("http://10.0.0.1:7420"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{text}");

    // tls: off on a public address: whatever is in front is unknown, the token alone.
    let behind = fleet(config::Config {
        hosts: hosts.clone(),
        listen: "0.0.0.0:7430".into(),
        tls: config::Tls::Off,
        ..Default::default()
    });
    let (s, _, text) = call_from(
        &behind.st,
        elsewhere,
        "POST",
        "/v1/hosts/key",
        "s1-token",
        ask("http://10.0.0.1:7420"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "tls: off checks the token alone: {text}");

    // tls: off on loopback: a proxy of ours in front; its last X-Forwarded-For is the caller.
    let local = fleet(config::Config {
        hosts,
        listen: "127.0.0.1:7430".into(),
        tls: config::Tls::Off,
        ..Default::default()
    });
    let proxy = std::net::IpAddr::from([127, 0, 0, 1]);
    let key = |xff: &'static [(&'static str, &'static str)]| {
        let st = local.st.clone();
        async move {
            call_with(
                &st,
                proxy,
                xff,
                "POST",
                "/v1/hosts/key",
                "s1-token",
                ask("http://10.0.0.1:7420"),
            )
            .await
        }
    };
    let (s, _, text) = key(&[("x-forwarded-for", "203.0.113.7, 10.0.0.1")]).await;
    assert_eq!(s, StatusCode::OK, "the proxy's own value, the last: {text}");
    let (s, _, text) = key(&[("x-forwarded-for", "10.0.0.1, 203.0.113.7")]).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "a forged first value counts for nothing: {text}"
    );
    assert!(text.contains("not 203.0.113.7"), "{text}");
    let (s, _, text) = key(&[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "no header, no address: {text}");
    assert!(text.contains("not an unknown address"), "{text}");
}

#[tokio::test]
async fn a_heartbeat_lands_on_the_record_added_for_its_address() {
    let f = fleet(config::Config::default());
    {
        let mut reg = f.st.reg.lock().unwrap();
        let mut added = static_host(&config::StaticHost::default(), Utc::now());
        added.id = "h_srv-9".into();
        added.url = "http://10.0.0.9:7420".into();
        added.state = "provisioning".into();
        added.provider = "manual".into();
        added.token = "t0k".into();
        added.note = "bootstrapped at 2026-10-20".into();
        reg.hosts.insert(added.id.clone(), added);
    }
    // The token the bootstrap gave it is its credential; the fleet's API needs none here.
    let mut hb = heartbeat("http://10.0.0.9:7420", 64_000, &["t1"]);
    hb["conditions"] = serde_json::json!([{"type": "memory_pressure", "status": true,
        "since": "2026-10-21T10:00:00Z", "message": "63000 MB of 64000 committed (98%), over 95%"}]);
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/hosts/register",
        "other",
        Some(hb.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{body}");
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/register", "t0k", Some(hb)).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    let hs = hosts(&f.st);
    assert_eq!(hs.len(), 1);
    let h = &hs[0];
    assert_eq!(h.id, "h_srv-9", "the fleet's id for it, not the daemon's");
    assert_eq!(h.state, "ready");
    assert_eq!(h.provider, "manual");
    assert_eq!(h.region, "par");
    assert_eq!(h.capacity.memory_mb, 64_000);
    assert_eq!(h.machines, 1);
    assert_eq!(h.note, "bootstrapped at 2026-10-20");
    assert_eq!(
        (h.conditions[0].kind.as_str(), h.conditions[0].status),
        ("memory_pressure", true),
        "the heartbeat's conditions are the host's"
    );
    {
        let reg = f.st.reg.lock().unwrap();
        let rec = &reg.hosts["h_srv-9"];
        assert_eq!(rec.token, "t0k");
        assert_eq!(
            reg.namespaces.get("t1").map(String::as_str),
            Some("h_srv-9")
        );
    }
    assert!(saved(&f.st).hosts.contains_key("h_srv-9"));
    let (s, _, body) = call(&f.st, "GET", "/v1/namespaces", "", None).await;
    assert_eq!(s, StatusCode::OK);
    let ts: Vec<api::Namespace> = serde_json::from_str(&body).unwrap();
    assert_eq!(ts.len(), 1);
    assert_eq!((ts[0].id.as_str(), ts[0].host.as_str()), ("t1", "h_srv-9"));
}

#[tokio::test]
async fn status_sums_the_ready_hosts_and_hosts_are_sorted() {
    let f = fleet(config::Config::default());
    seed(&f.st, "b", 64_000, 8_000, 3, &["t1", "t2"]);
    seed(&f.st, "a", 32_000, 1_000, 1, &["t3"]);
    seed(&f.st, "c", 16_000, 0, 0, &[]);
    set_state(&f.st, "a", "down");
    set_state(&f.st, "c", "draining");
    let (s, _, body) = call(&f.st, "GET", "/v1/status", "", None).await;
    assert_eq!(s, StatusCode::OK);
    let v = json(&body);
    assert_eq!(v["host_id"], "fleet");
    assert_eq!(v["hosts"], 3);
    assert_eq!(v["ready"], 1, "only b is ready");
    assert_eq!(v["capacity"]["memory_mb"], 64_000);
    assert_eq!(v["used"]["memory_mb"], 8_000);
    assert_eq!(v["machines"], 3);
    assert_eq!(
        v["namespaces"], 3,
        "pins are counted whatever the host's state"
    );
    assert!(
        v.get("provisioner").is_none(),
        "no provisioner (ADR 0042): {v}"
    );
    let (s, _, body) = call(&f.st, "GET", "/v1/hosts", "", None).await;
    assert_eq!(s, StatusCode::OK);
    let hs: Vec<api::Host> = serde_json::from_str(&body).unwrap();
    let ids: Vec<&str> = hs.iter().map(|h| h.id.as_str()).collect();
    assert_eq!(ids, ["a", "b", "c"]);
    let states: Vec<&str> = hs.iter().map(|h| h.state.as_str()).collect();
    assert_eq!(states, ["down", "ready", "draining"]);
    assert_eq!(hs[1].namespaces, ["t1", "t2"]);
}

/// Forgetting a host that holds a pool key is refused unless forced: the key goes with the
/// record, and a static host polled back would get a key its pool does not open.
/// A create in `region`, of `memory_mb`, with a volume of `volume_gb` when not 0.
fn ask(namespace: &str, region: &str, memory_mb: u32, volume_gb: u32) -> serde_json::Value {
    let mut b = create_body(namespace, "web", memory_mb);
    b["region"] = region.into();
    if volume_gb > 0 {
        b["volume"] = serde_json::json!({"size_gb": volume_gb, "mount": "/data"});
    }
    b
}

/// The fleet's `/metrics`, checked against the format, as lines.
async fn scrape(st: &Arc<AppState>, token: &str) -> Vec<String> {
    let (s, headers, text) = call(st, "GET", "/metrics", token, None).await;
    assert_eq!(s, StatusCode::OK, "{text}");
    assert_eq!(
        headers[header::CONTENT_TYPE],
        "text/plain; version=0.0.4; charset=utf-8"
    );
    api::metrics::check_exposition(&text);
    text.lines().map(String::from).collect()
}

#[tokio::test]
async fn each_refusal_is_counted_by_what_ran_out_and_the_room_is_shown() {
    let f = fleet(config::Config::default());
    seed(&f.st, "a", 64_000, 4_000, 1, &["t0"]);
    seed(&f.st, "b", 64_000, 0, 0, &[]);
    seed(&f.st, "c", 64_000, 0, 0, &[]);
    {
        let mut reg = f.st.reg.lock().unwrap();
        for (id, disk) in [("a", 10_000), ("b", 900_000), ("c", 900_000)] {
            let h = reg.hosts.get_mut(id).unwrap();
            h.region = "gra".into();
            h.disk_free_mb = disk;
        }
    }
    set_state(&f.st, "b", "draining");
    let refused = |namespace: &'static str, region: &'static str, mb: u32, gb: u32| {
        let st = f.st.clone();
        async move {
            let body = ask(namespace, region, mb, gb);
            let (s, _, body) = call(&st, "POST", "/v1/machines", "", Some(body)).await;
            assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{namespace}: {body}");
            assert_eq!(json(&body)["code"], "capacity", "{namespace}");
        }
    };
    // No host of gra has 100 GB of memory; a and c have 512 MB, neither 1000 GB of disk.
    refused("t1", "gra", 100_000, 0).await;
    refused("t2", "gra", 512, 1000).await;
    let lines = scrape(&f.st, "").await;
    for want in [
        r#"briqyard_fleet_hosts{state="ready"} 2"#,
        r#"briqyard_fleet_hosts{state="draining"} 1"#,
        r#"briqyard_fleet_host_state{host="b",region="gra",state="draining"} 1"#,
        r#"briqyard_fleet_host_state{host="c",region="gra",state="ready"} 1"#,
        // a and c: b is drained.
        r#"briqyard_fleet_free_mb{resource="memory",region="gra"} 124000"#,
        r#"briqyard_fleet_free_mb{resource="disk",region="gra"} 910000"#,
        r#"briqyard_fleet_largest_slot_mb{resource="memory",region="gra"} 64000"#,
        r#"briqyard_fleet_largest_slot_mb{resource="disk",region="gra"} 900000"#,
        r#"briqyard_fleet_unschedulable_total{resource="memory",region="gra"} 1"#,
        r#"briqyard_fleet_unschedulable_total{resource="disk",region="gra"} 1"#,
        r#"briqyard_fleet_unschedulable_total{resource="pressure",region="gra"} 0"#,
    ] {
        assert!(lines.iter().any(|l| l == want), "{want}\n{lines:#?}");
    }
    // c has the room and memory pressure: memory, a new host fixes it. t0's host a gets a
    // condition: its own create is refused before a is asked, as pressure, which a new host
    // does not fix.
    f.st.reg
        .lock()
        .unwrap()
        .hosts
        .get_mut("c")
        .unwrap()
        .conditions = vec![pressure(api::condition::MEMORY_PRESSURE, true)];
    refused("t3", "gra", 512, 20).await;
    f.st.reg
        .lock()
        .unwrap()
        .hosts
        .get_mut("a")
        .unwrap()
        .conditions = vec![pressure(api::condition::DISK_PRESSURE, true)];
    refused("t0", "", 512, 0).await;
    // A region no host is in counts as `other`; no region asked, as none.
    refused("t5", "nowhere", 512, 0).await;
    refused("t6", "", 100_000, 0).await;
    let lines = scrape(&f.st, "").await;
    for want in [
        r#"briqyard_fleet_free_mb{resource="memory",region="gra"} 0"#,
        r#"briqyard_fleet_largest_slot_mb{resource="disk",region="gra"} 0"#,
        r#"briqyard_fleet_unschedulable_total{resource="memory",region="gra"} 2"#,
        r#"briqyard_fleet_unschedulable_total{resource="pressure",region="gra"} 1"#,
        r#"briqyard_fleet_unschedulable_total{resource="memory",region="other"} 1"#,
        r#"briqyard_fleet_unschedulable_total{resource="disk",region="other"} 0"#,
        r#"briqyard_fleet_unschedulable_total{resource="memory",region=""} 1"#,
    ] {
        assert!(lines.iter().any(|l| l == want), "{want}\n{lines:#?}");
    }
    assert!(!lines.iter().any(|l| l.contains("nowhere")), "{lines:#?}");
    // `other` and `""` have no host: their counters only, never a room of 0 that reads as a
    // full region.
    for region in ["other", ""] {
        let room = format!("region=\"{region}\"}}");
        let gauges: Vec<&String> = lines
            .iter()
            .filter(|l| l.starts_with("briqyard_fleet_") && !l.contains("unschedulable"))
            .filter(|l| l.split(' ').next().unwrap().ends_with(&room))
            .collect();
        assert!(gauges.is_empty(), "{region:?}: {gauges:#?}");
    }
    // The same in /v1/status.
    let (s, _, body) = call(&f.st, "GET", "/v1/status", "", None).await;
    assert_eq!(s, StatusCode::OK);
    let regions: Vec<api::RegionRoom> =
        serde_json::from_value(json(&body)["regions"].clone()).unwrap();
    let names: Vec<&str> = regions.iter().map(|r| r.region.as_str()).collect();
    assert_eq!(names, ["", "gra", "other"]);
    assert_eq!(
        regions[1].unschedulable,
        api::Unschedulable {
            memory: 2,
            disk: 1,
            pressure: 1,
            cpu: 0,
        }
    );
    assert_eq!(regions[1].free, Some(api::Room::default()), "gra: full");
    assert_eq!(regions[2].unschedulable.memory, 1);
    for r in [&regions[0], &regions[2]] {
        assert_eq!(
            (r.free, r.largest_slot),
            (None, None),
            "{:?}: no host",
            r.region
        );
    }
    let v = json(&body);
    assert!(v["regions"][0].get("free").is_none(), "absent, not 0: {v}");
}

#[tokio::test]
async fn metrics_take_the_metrics_token_or_the_apis() {
    let mut cfg = config::Config {
        token: "api".into(),
        tls: config::Tls::Off,
        ..Default::default()
    };
    let f = fleet(cfg.clone());
    let (s, _, _) = call(&f.st, "GET", "/metrics", "", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    scrape(&f.st, "api").await;
    // A metrics token of its own: the scraper's; the API's still opens what it reads anyway
    // (ADR 0054). The same on every path a scraper reads.
    cfg.metrics_token = "scrape".into();
    let f = fleet(cfg.clone());
    scrape(&f.st, "scrape").await;
    scrape(&f.st, "api").await;
    for path in ["/metrics", "/v1/metrics/targets", "/v1/hosts/h1/metrics"] {
        let (s, _, _) = call(&f.st, "GET", path, "", None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{path}");
        let (s, _, _) = call(&f.st, "GET", path, "other", None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{path}");
    }
    let (s, _, _) = call(&f.st, "GET", "/v1/status", "scrape", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "it opens nothing else");
    let (s, _, _) = call(&f.st, "GET", "/v1/hosts/h1/drain", "scrape", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "nor a host's other routes");
    // On loopback with nothing in front (`tls` unset), none, as the daemon's.
    cfg.tls = config::Tls::Unset;
    let f = fleet(cfg);
    let lines = scrape(&f.st, "").await;
    assert!(lines.contains(&r#"briqyard_fleet_hosts{state="ready"} 0"#.to_string()));
    let (s, _, _) = call(&f.st, "GET", "/v1/status", "", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}
