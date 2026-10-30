//! What a join token and the scripts do not give away (ADR 0059): the bootstrap script only to
//! the host that joined, tokens bound to an address, a failed install that a new token mends,
//! and the writes a failed save undoes.

use super::join::{facts, join, joinable, mint, peer, state_of, uses_of};
use super::*;

const URL_9: &str = "https://10.0.0.9:7420";

fn script_path() -> String {
    format!("/bootstrap-host.sh?url={URL_9}")
}

/// A host that joined from `.9`: its own token.
async fn joined(f: &Fleet) -> String {
    let (token, _) = mint(f, serde_json::json!({})).await;
    let (s, text) = join(f, peer(9), &token, facts("")).await;
    assert_eq!(s, StatusCode::CREATED, "{text}");
    json(&text)["env"]["BRIQYARD_TOKEN"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn the_bootstrap_script_goes_to_the_host_that_joined_and_to_no_one_else() {
    let dir = tempfile::tempdir().unwrap();
    let custom = dir.path().join("bootstrap.sh");
    // What an operator's own script may hold: a login for a private registry.
    std::fs::write(&custom, "#!/bin/sh\nREGISTRY_PASSWORD=hunter2\n").unwrap();
    let mut cfg = config::Config {
        token: "api".into(),
        bootstrap: config::Bootstrap {
            enabled: true,
            release: "https://releases.example/v1".into(),
            script: custom,
            ..Default::default()
        },
        ..Default::default()
    };
    cfg.bootstrap.public_tcp_ports = vec![80, 443];
    let state = dir.path().join("registry.json");
    let f = fleet_at(cfg, dir, state);
    let host_token = joined(&f).await;
    let path = script_path();

    // Nobody: no token, a wrong one, the fleet's own, a join token, and no URL at all.
    for (from, token, uri) in [
        (peer(9), "", path.as_str()),
        (peer(9), "wrong", path.as_str()),
        (peer(9), "api", path.as_str()),
        (peer(9), host_token.as_str(), "/bootstrap-host.sh"),
        (
            peer(9),
            host_token.as_str(),
            "/bootstrap-host.sh?url=https://10.0.0.77:7420",
        ),
    ] {
        let (s, _, body) = call_from(&f.st, from, "GET", uri, token, None).await;
        assert!(
            s == StatusCode::UNAUTHORIZED || s == StatusCode::FORBIDDEN,
            "{token:?} {uri}: {s} {body}"
        );
        assert!(!body.contains("hunter2"), "{body}");
    }
    // The host's token from another address: a token on a disk that left the host's hands.
    let (s, _, body) = call_from(&f.st, peer(77), "GET", &path, &host_token, None).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
    assert!(!body.contains("hunter2"));

    // Another joined host's token does not open this host's script.
    let (other, _) = mint(&f, serde_json::json!({})).await;
    let (_, text) = join(&f, peer(10), &other, facts("")).await;
    let other_token = json(&text)["env"]["BRIQYARD_TOKEN"]
        .as_str()
        .unwrap()
        .to_string();
    let (s, _, _) = call_from(&f.st, peer(10), "GET", &path, &other_token, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // The host itself gets the script the SSH path would send.
    let (s, _, script) = call_from(&f.st, peer(9), "GET", &path, &host_token, None).await;
    assert_eq!(s, StatusCode::OK, "{script}");
    assert_eq!(script, bootstrap::script(&f.st.cfg.bootstrap).unwrap());
    assert!(script.contains("hunter2"));
}

#[tokio::test]
async fn a_token_bound_to_an_address_joins_from_that_address_only() {
    let f = joinable();
    for bad in ["host", "10.0.0", "10.0.0.0/33", "::1"] {
        let (s, _, text) = call(
            &f.st,
            "POST",
            "/v1/hosts/tokens",
            "api",
            Some(serde_json::json!({ "address": bad })),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {text}");
    }
    let (one, made) = mint(&f, serde_json::json!({ "address": "10.0.0.9" })).await;
    assert_eq!(made["address"], "10.0.0.9");
    let (net, _) = mint(&f, serde_json::json!({ "address": "10.0.0.0/28" })).await;

    // From elsewhere it is a token like any unusable one: the same answer, no use counted, and
    // the reason in the log alone.
    let (s, unbound_body) = join(&f, peer(10), &net, facts("a")).await;
    assert_eq!(s, StatusCode::CREATED, "inside the network: {unbound_body}");
    let (s, wrong) = join(&f, peer(10), &one, facts("b")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{wrong}");
    assert_eq!(json(&wrong)["code"], "invalid_token");
    let (_, unknown) = join(&f, peer(10), "ffffff.0000000000000000", facts("")).await;
    assert_eq!(wrong, unknown, "no hint of what the token is bound to");
    assert_eq!(
        state_of(&f, &one),
        "active",
        "a wrong address leaves it as it was"
    );
    assert_eq!(uses_of(&f, &one), 0, "a wrong address counts no use");
    let (s, outside) = join(&f, std::net::IpAddr::from([10, 0, 1, 1]), &net, facts("c")).await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "outside the network: {outside}"
    );

    let (s, text) = join(&f, peer(9), &one, facts("")).await;
    assert_eq!(s, StatusCode::CREATED, "{text}");
    assert_eq!(
        state_of(&f, &one),
        "active",
        "reusable: from its address, again"
    );
    assert_eq!(uses_of(&f, &one), 1);
    // Reuse keeps the binding: a second server in the network is no more welcome than before.
    let (s, _) = join(&f, peer(10), &one, facts("d")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // The same server joining again (an install that failed) replaces its record.
    let (s, text) = join(&f, peer(9), &one, facts("")).await;
    assert_eq!(s, StatusCode::CREATED, "{text}");
    assert_eq!(uses_of(&f, &one), 2);
    let (_, _, listed) = call(&f.st, "GET", "/v1/hosts/tokens", "api", None).await;
    assert!(listed.contains("10.0.0.0/28"), "{listed}");
}

#[tokio::test]
async fn a_new_token_replaces_a_host_that_joined_and_never_heartbeated() {
    let f = joinable();
    let first = joined(&f).await;
    // The install failed: the host holds its token, no daemon does. A new token from the same
    // server replaces the record and rotates the token.
    let (token, _) = mint(&f, serde_json::json!({})).await;
    let (s, text) = join(&f, peer(9), &token, facts("")).await;
    assert_eq!(s, StatusCode::CREATED, "{text}");
    let second = json(&text)["env"]["BRIQYARD_TOKEN"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(first, second);
    let all = hosts(&f.st);
    assert_eq!(all.len(), 1, "one record, not two");
    let rec = f.st.reg.lock().unwrap().hosts["h_10-0-0-9"].clone();
    assert_eq!(rec.token, second);
    assert!(rec.note.contains("replaces h_10-0-0-9"), "{}", rec.note);
    // The old token opens nothing.
    let ask = Some(serde_json::json!({ "url": URL_9 }));
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/key", &first, ask).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // By id, from another address, the holder of another token takes nothing: the record is not
    // theirs. The token that made it may (a server that came back under a new address).
    let (other, _) = mint(&f, serde_json::json!({})).await;
    let (s, text) = join(&f, peer(11), &other, facts("h_10-0-0-9")).await;
    assert_eq!(s, StatusCode::CONFLICT, "{text}");
    assert_eq!(
        f.st.reg.lock().unwrap().hosts["h_10-0-0-9"].token,
        second,
        "the record and its token are as they were"
    );
    assert_eq!(uses_of(&f, &other), 0);
    let (s, text) = join(&f, peer(11), &token, facts("h_10-0-0-9")).await;
    assert_eq!(s, StatusCode::CREATED, "{text}");
    assert!(hosts(&f.st).iter().all(|h| h.id == "h_10-0-0-9"));
    assert_eq!(hosts(&f.st).len(), 1);

    // A host that heartbeated is no one's to replace.
    let host_token = f.st.reg.lock().unwrap().hosts["h_10-0-0-9"].token.clone();
    let mut hb = heartbeat("https://10.0.0.11:7420", 64_000, &[]);
    hb["tls_fingerprint"] = "ab".repeat(32).into();
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/register", &host_token, Some(hb)).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    let (token, _) = mint(&f, serde_json::json!({})).await;
    let (s, text) = join(&f, peer(11), &token, facts("")).await;
    assert_eq!(s, StatusCode::CONFLICT, "{text}");
    assert_eq!(state_of(&f, &token), "active");
    let (s, text) = join(&f, peer(12), &token, facts("h_10-0-0-9")).await;
    assert_eq!(s, StatusCode::CONFLICT, "{text}");
}

#[tokio::test]
async fn a_replacement_the_registry_cannot_write_keeps_the_old_record() {
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
    let mint_in_memory = |f: &Fleet| {
        f.st.reg
            .lock()
            .unwrap()
            .mint_token(registry::TokenSpec::default(), Utc::now())
            .0
    };
    let first = mint_in_memory(&f);
    // Not durable here, but kept in memory: the shape of a failed second write.
    f.st.reg.lock().unwrap().hosts.insert(
        "h_10-0-0-9".into(),
        HostRec {
            id: "h_10-0-0-9".into(),
            url: URL_9.into(),
            token: "old-token".into(),
            provider: "join".into(),
            state: "joining".into(),
            last_seen: Utc::now(),
            ..Default::default()
        },
    );
    let (s, text) = join(&f, peer(9), &first, facts("")).await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{text}");
    let rec = f.st.reg.lock().unwrap().hosts["h_10-0-0-9"].clone();
    assert_eq!(rec.token, "old-token", "the record that was there is back");
    assert_eq!(state_of(&f, &first), "active");
}

#[tokio::test]
async fn a_revoke_the_registry_cannot_write_is_not_a_revoke() {
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
    let (token, rec) =
        f.st.reg
            .lock()
            .unwrap()
            .mint_token(registry::TokenSpec::default(), Utc::now());
    let (s, _, _) = call(
        &f.st,
        "DELETE",
        &format!("/v1/hosts/tokens/{}", rec.id),
        "api",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        state_of(&f, &token),
        "active",
        "what a restart would bring back is what stays"
    );
}

/// Trust on first use, made auditable: the note carries the fingerprint pinned, so it can be
/// compared with `briqyardd tls-fingerprint` on the server.
#[tokio::test]
async fn the_certificate_pinned_at_the_first_heartbeat_is_in_the_hosts_note() {
    let f = joinable();
    let host_token = joined(&f).await;
    let mut hb = heartbeat(URL_9, 64_000, &[]);
    hb["tls_fingerprint"] = "ab".repeat(32).into();
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/register", &host_token, Some(hb)).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    let note = f.st.reg.lock().unwrap().hosts["h_10-0-0-9"].note.clone();
    assert!(note.contains(&"ab".repeat(32)), "{note}");
    assert!(note.contains("pinned at its first heartbeat"), "{note}");
    assert!(
        note.contains("joined with token"),
        "what was there is kept: {note}"
    );
    // The second heartbeat adds nothing to it.
    let hb2 = heartbeat(URL_9, 64_000, &[]);
    let mut hb2 = hb2;
    hb2["tls_fingerprint"] = "ab".repeat(32).into();
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/register", &host_token, Some(hb2)).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(f.st.reg.lock().unwrap().hosts["h_10-0-0-9"].note, note);
}
