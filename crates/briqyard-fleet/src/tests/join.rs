//! Join tokens and the join call (ADR 0057).

use super::*;

pub(super) fn peer(last: u8) -> std::net::IpAddr {
    std::net::IpAddr::from([10, 0, 0, last])
}

pub(super) fn joinable() -> Fleet {
    fleet(config::Config {
        token: "api".into(),
        bootstrap: config::Bootstrap {
            enabled: true,
            release: "https://releases.example/v1".into(),
            release_token: "rel-secret".into(),
            pool_device: "/dev/nvme1n1".into(),
            allowed_clients: vec!["10.0.0.0/8".into()],
            fleet_url: "https://fleet.example".into(),
            public_tcp_ports: vec![80, 443],
            ..Default::default()
        },
        ..Default::default()
    })
}

/// A token minted through the API: the whole token and its listing.
pub(super) async fn mint(f: &Fleet, body: serde_json::Value) -> (String, serde_json::Value) {
    let (s, _, text) = call(&f.st, "POST", "/v1/hosts/tokens", "api", Some(body)).await;
    assert_eq!(s, StatusCode::CREATED, "{text}");
    let v = json(&text);
    (v["token"].as_str().unwrap().to_string(), v)
}

pub(super) fn facts(name: &str) -> serde_json::Value {
    serde_json::json!({ "name": name, "arch": "x86_64", "memory_mb": 64000, "vcpus": 16 })
}

pub(super) async fn join(
    f: &Fleet,
    from: std::net::IpAddr,
    token: &str,
    body: serde_json::Value,
) -> (StatusCode, String) {
    let (s, _, text) = call_from(&f.st, from, "POST", "/v1/hosts/join", token, Some(body)).await;
    (s, text)
}

pub(super) fn state_of(f: &Fleet, token: &str) -> String {
    let id = token.split('.').next().unwrap();
    let reg = f.st.reg.lock().unwrap();
    let rec = reg.join_tokens.iter().find(|t| t.id == id).unwrap();
    rec.state(Utc::now()).into()
}

#[tokio::test]
async fn a_join_records_the_host_and_answers_what_the_ssh_bootstrap_sends() {
    let f = joinable();
    let (token, made) = mint(
        &f,
        serde_json::json!({ "region": "gra", "labels": { "rack": "a1" } }),
    )
    .await;
    assert_eq!(made["state"], "active");
    let (s, text) = join(&f, peer(9), &token, facts("")).await;
    assert_eq!(s, StatusCode::CREATED, "{text}");
    let answer = json(&text);
    assert_eq!(answer["id"], "h_10-0-0-9");
    let env = &answer["env"];
    let host_token = env["BRIQYARD_TOKEN"].as_str().unwrap().to_string();
    assert_eq!(host_token.len(), 32, "the host's own API token");
    assert_eq!(env["ADVERTISE"], "https://10.0.0.9:7420");
    assert_eq!(env["BRIQYARD_RELEASE"], "https://releases.example/v1");
    assert_eq!(env["BRIQYARD_RELEASE_TOKEN"], "rel-secret");
    assert_eq!(env["BRIQYARD_POOL_DEVICE"], "/dev/nvme1n1");
    assert_eq!(env["ALLOWED_CLIENTS"], "10.0.0.0/8");
    assert_eq!(env["FLEET_URL"], "https://fleet.example");
    assert!(
        env.get("PRIVATE_ADDRESS").is_none(),
        "no private network here"
    );

    // The same settings the SSH path derives from the same record.
    let rec = f.st.reg.lock().unwrap().hosts["h_10-0-0-9"].clone();
    let ssh =
        bootstrap::bootstrap_env(&f.st.cfg.bootstrap, "", &rec, "https://releases.example/v1");
    for (k, v) in env.as_object().unwrap() {
        assert!(
            ssh.contains(&format!("{k}='{}'", v.as_str().unwrap())),
            "{k}: {ssh}"
        );
    }
    assert_eq!(
        (
            rec.state.as_str(),
            rec.provider.as_str(),
            rec.region.as_str()
        ),
        ("joining", "join", "gra")
    );
    assert_eq!(rec.token, host_token);
    assert_eq!(rec.labels["rack"], "a1");
    assert!(
        rec.note.contains("x86_64, 16 vCPUs, 64000 MB"),
        "{}",
        rec.note
    );
    assert!(
        bootstrap::to_install(&f.st.reg.lock().unwrap()).is_empty(),
        "no SSH bootstrap for a host that installs itself"
    );

    // The token is spent and says who spent it; nothing secret is in the listing or the file.
    assert_eq!(state_of(&f, &token), "used");
    let (_, _, listed) = call(&f.st, "GET", "/v1/hosts/tokens", "api", None).await;
    let l = json(&listed);
    assert_eq!(l[0]["state"], "used");
    assert_eq!(l[0]["used_by"]["host"], "h_10-0-0-9");
    assert_eq!(l[0]["used_by"]["peer"], "10.0.0.9");
    let secret = token.split('.').nth(1).unwrap();
    let file = std::fs::read_to_string(&f.st.state_path).unwrap();
    assert!(!listed.contains(secret) && !file.contains(secret));
    assert!(saved(&f.st).hosts.contains_key("h_10-0-0-9"), "written");

    // The host's own token opens its pool key, as for a host added by hand.
    let ask = Some(serde_json::json!({ "url": "https://10.0.0.9:7420" }));
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", &host_token, ask).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    // Its first heartbeat pins the certificate it reports and makes it ready; after that a
    // different one is refused.
    let mut hb = heartbeat("https://10.0.0.9:7420", 64_000, &[]);
    hb["tls_fingerprint"] = "ab".repeat(32).into();
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/hosts/register",
        &host_token,
        Some(hb.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    let h = &hosts(&f.st)[0];
    assert_eq!(
        (h.state.as_str(), h.tls_fingerprint.as_str()),
        ("ready", "ab".repeat(32).as_str())
    );
    hb["tls_fingerprint"] = "cd".repeat(32).into();
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/register", &host_token, Some(hb)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(json(&body)["code"], "tls_mismatch");
}

#[tokio::test]
async fn a_token_joins_one_host_and_a_second_call_gets_nothing() {
    let f = joinable();
    let (token, _) = mint(&f, serde_json::json!({})).await;
    let (s, _) = join(&f, peer(9), &token, facts("a")).await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, text) = join(&f, peer(10), &token, facts("b")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{text}");
    assert_eq!(json(&text)["code"], "invalid_token");
    assert_eq!(hosts(&f.st).len(), 1);
}

#[tokio::test]
async fn two_joins_at_once_with_one_token_make_one_host() {
    let f = joinable();
    let (token, _) = mint(&f, serde_json::json!({})).await;
    let calls = (1..=8u8).map(|n| {
        let (st, token) = (f.st.clone(), token.clone());
        tokio::spawn(async move {
            let name = format!("h{n}");
            let (s, _, _) = call_from(
                &st,
                peer(n),
                "POST",
                "/v1/hosts/join",
                &token,
                Some(facts(&name)),
            )
            .await;
            s
        })
    });
    let mut statuses = Vec::new();
    for c in calls {
        statuses.push(c.await.unwrap());
    }
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == StatusCode::CREATED)
            .count(),
        1,
        "{statuses:?}"
    );
    assert!(statuses
        .iter()
        .all(|s| *s == StatusCode::CREATED || *s == StatusCode::UNAUTHORIZED));
    assert_eq!(hosts(&f.st).len(), 1);
}

/// Every reason a token cannot be used reads the same to the caller, and a refused call spends
/// nothing.
#[tokio::test]
async fn an_unusable_token_is_one_answer_whatever_the_reason() {
    let f = joinable();
    let (good, _) = mint(&f, serde_json::json!({})).await;
    let (revoked, made) = mint(&f, serde_json::json!({})).await;
    let (s, _, _) = call(
        &f.st,
        "DELETE",
        &format!("/v1/hosts/tokens/{}", made["id"].as_str().unwrap()),
        "api",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (expired, _) = mint(&f, serde_json::json!({})).await;
    f.st.reg
        .lock()
        .unwrap()
        .join_tokens
        .last_mut()
        .unwrap()
        .expires_at = Utc::now() - Duration::seconds(1);
    let (id, secret) = good.split_once('.').unwrap();
    let flipped = format!("{id}.{}", secret.replace(&secret[..1], "z"));
    let mut bodies = Vec::new();
    for t in [
        revoked.as_str(),
        expired.as_str(),
        flipped.as_str(),
        "ffffff.00000000000000000000000000000000",
        "nonsense",
        "",
        "api",
    ] {
        let (s, text) = join(&f, peer(9), t, facts("")).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{t:?}: {text}");
        bodies.push(text);
    }
    assert!(bodies.windows(2).all(|w| w[0] == w[1]), "{bodies:?}");
    assert!(hosts(&f.st).is_empty());
    assert_eq!(
        state_of(&f, &good),
        "active",
        "a wrong secret spends nothing"
    );
}

#[tokio::test]
async fn a_join_that_is_refused_for_its_facts_leaves_the_token_whole() {
    let f = joinable();
    let (token, _) = mint(&f, serde_json::json!({})).await;
    let mut bad_arch = facts("");
    bad_arch["arch"] = "riscv64".into();
    let mut elsewhere = facts("");
    elsewhere["address"] = "10.0.0.77".into();
    let (s, text) = join(&f, peer(9), &token, bad_arch).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{text}");
    // A host cannot name an address the call did not come from, another host's included.
    let (s, text) = join(&f, peer(9), &token, elsewhere).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{text}");
    assert!(text.contains("not the one the call came from"), "{text}");
    let (s, text) = join(
        &f,
        std::net::IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 1]),
        &token,
        facts(""),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "an IPv6 caller: {text}");
    let (s, text) = join(&f, peer(9), &token, facts("Bad Name")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{text}");
    assert_eq!(state_of(&f, &token), "active");
    let (s, text) = join(&f, peer(9), &token, facts("")).await;
    assert_eq!(s, StatusCode::CREATED, "{text}");
}

#[tokio::test]
async fn a_host_cannot_join_under_a_name_or_an_address_that_is_taken() {
    let f = joinable();
    seed(&f.st, "h1", 64_000, 0, 0, &[]);
    let taken = f.st.reg.lock().unwrap().hosts["h1"].url.clone();
    let taken_ip: std::net::IpAddr = url_host(&taken).parse().unwrap();
    let (token, _) = mint(&f, serde_json::json!({})).await;
    let (s, text) = join(&f, peer(9), &token, facts("h1")).await;
    assert_eq!(s, StatusCode::CONFLICT, "{text}");
    let (s, text) = join(&f, taken_ip, &token, facts("fresh")).await;
    assert_eq!(s, StatusCode::CONFLICT, "{text}");
    assert_eq!(state_of(&f, &token), "active");
    assert_eq!(hosts(&f.st).len(), 1);
}

#[tokio::test]
async fn a_token_bound_to_a_name_joins_only_as_that_host() {
    let f = joinable();
    let (token, made) = mint(&f, serde_json::json!({ "host": "gra-1" })).await;
    assert_eq!(made["host"], "gra-1");
    let (s, text) = join(&f, peer(9), &token, facts("someone-else")).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{text}");
    assert_eq!(json(&text)["code"], "wrong_name");
    assert_eq!(state_of(&f, &token), "active");
    let (s, text) = join(&f, peer(9), &token, facts("")).await;
    assert_eq!(s, StatusCode::CREATED, "{text}");
    assert_eq!(json(&text)["id"], "gra-1");
}

/// The fleet vouches for an address only when it sees the call come from it (ADR 0026).
#[tokio::test]
async fn a_join_needs_the_fleet_to_see_where_it_comes_from() {
    let behind_a_proxy_it_cannot_see = config::Config {
        listen: "0.0.0.0:7430".into(),
        tls: config::Tls::Off,
        token: "api".into(),
        bootstrap: config::Bootstrap {
            enabled: true,
            release: "https://releases.example/v1".into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let f = fleet(behind_a_proxy_it_cannot_see);
    let (token, _) = mint(&f, serde_json::json!({})).await;
    let (s, text) = join(&f, peer(9), &token, facts("")).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{text}");
    assert!(
        text.contains("cannot tell where this call came from"),
        "{text}"
    );
    assert_eq!(state_of(&f, &token), "active");

    // Behind a loopback proxy of ours, the address is the one it writes.
    let f = fleet(config::Config {
        listen: "127.0.0.1:7430".into(),
        tls: config::Tls::Off,
        token: "api".into(),
        bootstrap: config::Bootstrap {
            enabled: true,
            release: "https://releases.example/v1".into(),
            ..Default::default()
        },
        ..Default::default()
    });
    let (token, _) = mint(&f, serde_json::json!({})).await;
    let loopback = std::net::IpAddr::from([127, 0, 0, 1]);
    let (s, _, text) = call_with(
        &f.st,
        loopback,
        &[("x-forwarded-for", "10.0.0.9")],
        "POST",
        "/v1/hosts/join",
        &token,
        Some(facts("")),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{text}");
    let (token, _) = mint(&f, serde_json::json!({})).await;
    let (s, _, text) = call_with(
        &f.st,
        loopback,
        &[],
        "POST",
        "/v1/hosts/join",
        &token,
        Some(facts("x")),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "no header, no address: {text}");
}

#[tokio::test]
async fn the_token_routes_are_the_operators_and_check_what_they_are_given() {
    let f = joinable();
    for (method, path) in [
        ("POST", "/v1/hosts/tokens"),
        ("GET", "/v1/hosts/tokens"),
        ("DELETE", "/v1/hosts/tokens/abcdef"),
    ] {
        let (s, _, _) = call(&f.st, method, path, "", Some(serde_json::json!({}))).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{method} {path}");
    }
    for body in [
        serde_json::json!({ "ttl_sec": 5 }),
        serde_json::json!({ "ttl_sec": 40 * 86400 }),
        serde_json::json!({ "region": "No Way" }),
        serde_json::json!({ "host": "Bad Host" }),
        serde_json::json!({ "labels": { "bad key": "v" } }),
    ] {
        let (s, _, text) = call(&f.st, "POST", "/v1/hosts/tokens", "api", Some(body.clone())).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}: {text}");
    }
    let (token, made) = mint(&f, serde_json::json!({ "ttl_sec": 600 })).await;
    let ttl = made["expires_at"]
        .as_str()
        .unwrap()
        .parse::<chrono::DateTime<Utc>>()
        .unwrap()
        - made["created_at"]
            .as_str()
            .unwrap()
            .parse::<chrono::DateTime<Utc>>()
            .unwrap();
    assert_eq!(ttl.num_seconds(), 600);
    assert!(made.get("secret").is_none());
    assert_eq!(
        saved(&f.st).join_tokens.len(),
        1,
        "written before it is answered"
    );

    let id = made["id"].as_str().unwrap();
    let (s, _) = join(&f, peer(9), &token, facts("")).await;
    assert_eq!(s, StatusCode::CREATED);
    let url = format!("/v1/hosts/tokens/{id}");
    let (s, _, _) = call(&f.st, "DELETE", &url, "api", None).await;
    assert_eq!(
        s,
        StatusCode::CONFLICT,
        "a used token stays as the record of who used it"
    );
    let (s, _, _) = call(&f.st, "DELETE", "/v1/hosts/tokens/ffffff", "api", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn nothing_joins_when_the_bootstrap_is_off_or_has_no_release() {
    let off = fleet(config::Config {
        token: "api".into(),
        ..Default::default()
    });
    for (method, path) in [
        ("POST", "/v1/hosts/tokens"),
        ("POST", "/v1/hosts/join"),
        ("GET", "/install.sh"),
        ("GET", "/bootstrap-host.sh?url=https://10.0.0.9:7420"),
    ] {
        let (s, _, text) = call(&off.st, method, path, "api", Some(facts(""))).await;
        assert_eq!(s, StatusCode::CONFLICT, "{path}: {text}");
        assert_eq!(json(&text)["code"], "bootstrap_off");
    }
    let no_release = fleet(config::Config {
        token: "api".into(),
        bootstrap: config::Bootstrap {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    });
    let (token, _) = mint(&no_release, serde_json::json!({})).await;
    let (s, text) = join(&no_release, peer(9), &token, facts("")).await;
    assert_eq!(s, StatusCode::CONFLICT, "{text}");
    assert!(text.contains("bootstrap.release"));
}

#[tokio::test]
async fn install_sh_is_open_and_holds_no_secret() {
    let f = joinable();
    let (s, headers, install) = call(&f.st, "GET", "/install.sh", "", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(headers["content-type"]
        .to_str()
        .unwrap()
        .starts_with("text/plain"));
    assert!(install.starts_with("#!/bin/sh"));
    assert!(!install.contains("rel-secret"), "no value of the fleet's");
}

#[tokio::test]
async fn a_join_the_registry_cannot_write_is_not_a_join() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("gone/registry.json");
    let f = fleet_at(
        config::Config {
            token: "api".into(),
            bootstrap: config::Bootstrap {
                enabled: true,
                release: "https://releases.example/v1".into(),
                ..Default::default()
            },
            ..Default::default()
        },
        dir,
        missing,
    );
    // Minted in memory only: the registry cannot be written here.
    let token =
        f.st.reg
            .lock()
            .unwrap()
            .mint_token(registry::TokenSpec::default(), Utc::now())
            .0;
    let (s, text) = join(&f, peer(9), &token, facts("")).await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{text}");
    assert!(hosts(&f.st).is_empty(), "no host the host never heard of");
    assert_eq!(state_of(&f, &token), "active", "the token is whole");
    let (s, _, _) = call(
        &f.st,
        "POST",
        "/v1/hosts/tokens",
        "api",
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        f.st.reg.lock().unwrap().join_tokens.len(),
        1,
        "the token not written is not kept"
    );
}
