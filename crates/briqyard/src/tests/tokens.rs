//! `host token` (ADR 0057): the arguments, the table, and the calls against a stub fleet.

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
    ]) {
        TokenCmd::Create {
            ttl,
            region,
            labels,
            host,
            address,
        } => {
            assert_eq!(ttl.unwrap().as_secs(), 5400);
            assert_eq!((region.as_str(), host.as_str()), ("gra", "gra-1"));
            assert_eq!(address, "10.42.0.0/24");
            assert_eq!(labels, ["rack=a1", "disk=nvme"]);
        }
        _ => panic!("not a create"),
    }
    assert!(matches!(
        token_cmd(&["create"]),
        TokenCmd::Create { ttl: None, .. }
    ));
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
        expires_at: at + chrono::Duration::hours(1),
        region: String::new(),
        labels: Default::default(),
        host: String::new(),
        address: String::new(),
        used_by: None,
        revoked_at: None,
    };
    let used = api::JoinToken {
        region: "gra".into(),
        labels: [("rack".to_string(), "a1".to_string())].into(),
        used_by: Some(api::JoinTokenUse {
            host: "h_10-0-0-9".into(),
            at,
            peer: "10.0.0.9".into(),
        }),
        ..token("ab12cd", "used")
    };
    let bound = api::JoinToken {
        host: "gra-2".into(),
        ..token("ef34ab", "active")
    };
    let both = api::JoinToken {
        host: "gra-3".into(),
        address: "10.42.0.12".into(),
        ..token("cd56ef", "active")
    };
    let out = crate::host_token::token_table(&[used, bound, both, token("000001", "expired")]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines,
        [
            "ID       STATE    EXPIRES                    REGION   LABELS                   USED BY",
            "ab12cd   used     2026-10-19 09:30:00 UTC    gra      rack=a1                  h_10-0-0-9 from 10.0.0.9 at 2026-10-19T08:30:00+00:00",
            "ef34ab   active   2026-10-19 09:30:00 UTC    -        -                        (for gra-2)",
            "cd56ef   active   2026-10-19 09:30:00 UTC    -        -                        (for gra-3, from 10.42.0.12)",
            "000001   expired  2026-10-19 09:30:00 UTC    -        -                        -",
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
