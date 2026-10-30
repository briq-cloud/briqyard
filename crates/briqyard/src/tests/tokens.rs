//! `host token` (ADR 0059): the arguments, the table, and the calls against a stub fleet.

use super::*;

fn token_cmd(args: &[&str]) -> TokenCmd {
    let mut all = vec!["host", "token"];
    all.extend(args);
    match parse(&all).cmd {
        Cmd::Host(HostCmd::Token { cmd }) => cmd,
        _ => panic!("not a host token command"),
    }
}

#[test]
fn token_commands() {
    match token_cmd(&[
        "create",
        "--ttl",
        "90m",
        "--region",
        "gra",
        "--labels",
        "rack=a1,disk=nvme",
        "--host",
        "gra-1",
        "--address",
        "10.42.0.0/24",
        "--description",
        "rack a1, gra",
    ]) {
        TokenCmd::Create {
            ttl,
            description,
            region,
            labels,
            host,
            address,
        } => {
            assert_eq!(ttl.unwrap().as_secs(), 5400);
            assert_eq!((region.as_str(), host.as_str()), ("gra", "gra-1"));
            assert_eq!(address, "10.42.0.0/24");
            assert_eq!(description, "rack a1, gra");
            assert_eq!(labels, ["rack=a1", "disk=nvme"]);
        }
        _ => panic!("not a create"),
    }
    assert!(matches!(
        token_cmd(&["create"]),
        TokenCmd::Create { ttl: None, .. }
    ));
    // 0 is kubeadm's "never expires".
    match token_cmd(&["create", "--ttl", "0"]) {
        TokenCmd::Create { ttl, .. } => assert_eq!(ttl.unwrap().as_secs(), 0),
        _ => panic!("not a create"),
    }
    assert!(matches!(token_cmd(&["ls"]), TokenCmd::Ls));
    assert!(matches!(token_cmd(&["list"]), TokenCmd::Ls));
    match token_cmd(&["revoke", "ab12cd"]) {
        TokenCmd::Revoke { id } => assert_eq!(id, "ab12cd"),
        _ => panic!("not a revoke"),
    }
    assert_eq!(
        fails(&["host", "token", "revoke"]),
        ErrorKind::MissingRequiredArgument
    );
    assert_eq!(
        fails(&["host", "token", "create", "--ttl", "soon"]),
        ErrorKind::ValueValidation
    );
}

#[test]
fn the_token_table_and_the_command_for_the_server() {
    let at = ts();
    let token = |id: &str, state: &str| api::JoinToken {
        id: id.into(),
        state: state.into(),
        created_at: at,
        expires_at: Some(at + chrono::Duration::hours(1)),
        description: String::new(),
        uses: 0,
        last_used: None,
        region: String::new(),
        labels: Default::default(),
        host: String::new(),
        address: String::new(),
        revoked_at: None,
    };
    let used = api::JoinToken {
        region: "gra".into(),
        labels: [("rack".to_string(), "a1".to_string())].into(),
        description: "gra racks".into(),
        uses: 3,
        last_used: Some(api::JoinTokenUse {
            host: "h_10-0-0-9".into(),
            at,
            peer: "10.0.0.9".into(),
        }),
        ..token("ab12cd", "active")
    };
    let never = api::JoinToken {
        expires_at: None,
        ..token("ef34ab", "active")
    };
    let both = api::JoinToken {
        host: "gra-3".into(),
        address: "10.42.0.12".into(),
        ..token("cd56ef", "active")
    };
    let out = crate::host_token::token_table(&[used, never, both, token("000001", "expired")]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines,
        [
            "ID       STATE    EXPIRES                  USES  LAST USED                                     REGION   LABELS               BOUND TO                 DESCRIPTION",
            "ab12cd   active   2026-10-19 09:30 UTC     3     h_10-0-0-9 from 10.0.0.9 2026-10-19 08:30     gra      rack=a1              -                        gra racks",
            "ef34ab   active   never                    0     -                                             -        -                    -                        -",
            "cd56ef   active   2026-10-19 09:30 UTC     0     -                                             -        -                    host gra-3, from 10.42.0.12 -",
            "000001   expired  2026-10-19 09:30 UTC     0     -                                             -        -                    -                        -",
        ]
    );
    // The command holds no token, and its fetch refuses http, redirects included.
    assert_eq!(
        crate::host_token::install_command("https://fleet.example"),
        "curl -fsSL --proto '=https' --proto-redir '=https' https://fleet.example/install.sh | FLEET_URL=https://fleet.example JOIN_TOKEN=<token> sh"
    );
    assert!(crate::host_token::install_command("http://10.0.0.1:7430")
        .contains("ALLOW_INSECURE_HTTP=1"));
}

#[tokio::test]
async fn the_commands_call_the_fleets_token_routes() {
    let made = r#"{"token":"ab12cd.0123456789abcdef0123456789abcdef","id":"ab12cd","state":"active","created_at":"2026-10-19T08:30:00Z","expires_at":"2026-10-19T09:30:00Z"}"#;
    let (url, stub) = stub(vec![
        (StatusCode::CREATED, JSON.to_vec(), made),
        (StatusCode::OK, JSON.to_vec(), "[]"),
        (StatusCode::NO_CONTENT, vec![], ""),
    ])
    .await;
    let c = client(&url, Some("api"));
    crate::host_token::run(
        &c,
        TokenCmd::Create {
            ttl: Some("1h".parse().unwrap()),
            description: "gra racks".into(),
            region: "gra".into(),
            labels: vec!["rack=a1".into()],
            host: String::new(),
            address: "10.42.0.12".into(),
        },
    )
    .await
    .unwrap();
    crate::host_token::run(&c, TokenCmd::Ls).await.unwrap();
    crate::host_token::run(
        &c,
        TokenCmd::Revoke {
            id: "ab12cd".into(),
        },
    )
    .await
    .unwrap();
    let seen = stub.seen.lock().unwrap().clone();
    assert_eq!(
        (seen[0].method.as_str(), seen[0].path.as_str()),
        ("POST", "/v1/hosts/tokens")
    );
    let body: serde_json::Value = serde_json::from_str(&seen[0].body).unwrap();
    assert_eq!(body["ttl_sec"], 3600);
    assert_eq!(body["description"], "gra racks");
    assert_eq!(body["labels"]["rack"], "a1");
    assert_eq!(body["region"], "gra");
    assert_eq!(body["address"], "10.42.0.12");
    assert_eq!(seen[0].authorization.as_deref(), Some("Bearer api"));
    assert_eq!(
        (seen[1].method.as_str(), seen[1].path.as_str()),
        ("GET", "/v1/hosts/tokens")
    );
    assert_eq!(
        (seen[2].method.as_str(), seen[2].path.as_str()),
        ("DELETE", "/v1/hosts/tokens/ab12cd")
    );
}
