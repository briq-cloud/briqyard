use super::*;
use crate::registry::HostRec;
use briqyard_api::execution::{
    admission::{Journal, Role},
    KeyRole,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use tower::ServiceExt;

struct FixedClock(Option<Clock>);
impl ClockSource for FixedClock {
    fn qualified(&self) -> Option<QualifiedClock> {
        self.0.map(|interval| QualifiedClock {
            interval,
            valid_until: Instant::now() + std::time::Duration::from_secs(5),
        })
    }
}
struct StaleClock;
impl ClockSource for StaleClock {
    fn qualified(&self) -> Option<QualifiedClock> {
        Some(QualifiedClock {
            interval: Clock {
                now: 1000,
                uncertainty: 1,
            },
            valid_until: Instant::now() - std::time::Duration::from_secs(1),
        })
    }
}
fn fixture(clock: Arc<dyn ClockSource>) -> (Router, tempfile::TempDir) {
    let host = HostRec {
        id: "host".into(),
        url: "https://127.0.0.1:1".into(),
        token: "host-admin".into(),
        tls_fingerprint: "ab".repeat(32),
        ..Default::default()
    };
    let (app, dir, _) = fixture_with_host(clock, host);
    (app, dir)
}
fn fixture_with_host(
    clock: Arc<dyn ClockSource>,
    host: HostRec,
) -> (Router, tempfile::TempDir, String) {
    let (app, dir, epoch) = configured_fixture(clock, host, |_, _| {});
    (app.unwrap(), dir, epoch)
}
fn configured_fixture(
    clock: Arc<dyn ClockSource>,
    host: HostRec,
    configure: impl FnOnce(&mut String, &mut Credentials),
) -> (Result<Router, &'static str>, tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let journal =
        Journal::open(&dir.path().join("issuer"), Role::Authority("region".into())).unwrap();
    let key = Ed25519KeyPair::from_seed_unchecked(&[2; 32]).unwrap();
    let issuer =
        briqyard_api::execution::DurableIssuer::new(journal, key, "authority".into()).unwrap();
    let epoch = issuer.instance().to_owned();
    let transport = HostTransport::new(
        &host,
        "host-installer",
        "host-execution",
        std::time::Duration::from_secs(1),
    )
    .unwrap();
    let host_administrator = host.token.clone();
    let mut host_id = host.id;
    let mut credentials = Credentials {
        installer: "central-installer".into(),
        gateway: "gateway-only".into(),
        administrator: "fleet-admin".into(),
        host_administrator,
    };
    configure(&mut host_id, &mut credentials);
    let app = router(
        issuer,
        transport,
        host_id,
        credentials,
        "fleet-admin",
        TrustConfig {
            keys: vec![VerificationKey {
                kid: "central".into(),
                role: KeyRole::Central,
                issuer: "central".into(),
                authority: None,
                public_key: [1; 32],
            }],
            central_issuer: "central".into(),
            authority_issuer: "authority".into(),
            audience: "host".into(),
        },
        clock,
    );
    (app, dir, epoch)
}
#[test]
fn constructor_checks_actual_host_and_fleet_administrator_credentials() {
    for change in 0..5 {
        let host = HostRec {
            id: "host".into(),
            url: "https://127.0.0.1:1".into(),
            token: "host-admin".into(),
            tls_fingerprint: "ab".repeat(32),
            ..Default::default()
        };
        let (result, _dir, _) =
            configured_fixture(Arc::new(FixedClock(None)), host, |host_id, credentials| {
                if change == 0 {
                    *host_id = "another-host".into();
                } else if change < 3 {
                    credentials.host_administrator = "unrelated-placeholder".into();
                    if change == 1 {
                        credentials.installer = "host-admin".into();
                    } else {
                        credentials.gateway = "host-admin".into();
                    }
                } else {
                    credentials.administrator = "unrelated-placeholder".into();
                    if change == 3 {
                        credentials.installer = "fleet-admin".into();
                    } else {
                        credentials.gateway = "fleet-admin".into();
                    }
                }
            });
        assert!(result.is_err());
    }
}
async fn request(app: &Router, action: &str, token: &str, body: Vec<u8>) -> Response {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("/internal/authority/v1/{action}"))
        .header(header::CONTENT_TYPE, "application/json");
    if !token.is_empty() {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    app.clone()
        .oneshot(request.body(Body::from(body)).unwrap())
        .await
        .unwrap()
}
#[tokio::test]
async fn identity_reads_live_journals_only_for_the_installer() {
    let server = crate::execution_host::tests::server();
    let (app, _dir, epoch) = fixture_with_host(
        Arc::new(FixedClock(Some(Clock {
            now: 1000,
            uncertainty: 1,
        }))),
        server.host.clone(),
    );
    for token in [
        "",
        "gateway-only",
        "fleet-admin",
        server.host.token.as_str(),
    ] {
        assert_eq!(
            request(&app, "identity", token, b"{}".to_vec())
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        request(
            &app,
            "identity",
            "central-installer",
            br#"{"host":"other"}"#.to_vec()
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert!(server.calls.lock().unwrap().is_empty());
    for instance in ["first-host-instance", "replacement-host-instance"] {
        *server.instance.lock().unwrap() = instance.into();
        let response = request(&app, "identity", "central-installer", b"{}".to_vec()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            serde_json::json!({
                "authority":"region", "authority_epoch":epoch, "host":"host-one", "host_instance":instance,
            })
        );
    }
    assert_eq!(
        *server.calls.lock().unwrap(),
        vec![
            (
                "/internal/execution/v1/instance".into(),
                "Bearer host-installer".into()
            ),
            (
                "/internal/execution/v1/instance".into(),
                "Bearer host-installer".into()
            ),
        ]
    );
    let (replacement, _dir, next_epoch) = fixture_with_host(
        Arc::new(FixedClock(Some(Clock {
            now: 1000,
            uncertainty: 1,
        }))),
        server.host.clone(),
    );
    assert_ne!(epoch, next_epoch);
    let response = request(
        &replacement,
        "identity",
        "central-installer",
        b"{}".to_vec(),
    )
    .await;
    let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["authority_epoch"],
        next_epoch
    );
}

#[tokio::test]
async fn identity_refuses_untrusted_host_and_unqualified_clock() {
    let server = crate::execution_host::tests::server();
    let mut host = server.host.clone();
    host.tls_fingerprint = "ab".repeat(32);
    let (app, _dir, _) = fixture_with_host(
        Arc::new(FixedClock(Some(Clock {
            now: 1000,
            uncertainty: 1,
        }))),
        host,
    );
    assert_eq!(
        request(&app, "identity", "central-installer", b"{}".to_vec())
            .await
            .status(),
        StatusCode::BAD_GATEWAY
    );
    let (app, _dir, _) = fixture_with_host(Arc::new(StaleClock), server.host.clone());
    assert_eq!(
        request(&app, "identity", "central-installer", b"{}".to_vec())
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(server.calls.lock().unwrap().is_empty());

    struct Once(std::sync::atomic::AtomicBool);
    impl ClockSource for Once {
        fn qualified(&self) -> Option<QualifiedClock> {
            self.0
                .swap(false, std::sync::atomic::Ordering::SeqCst)
                .then_some(QualifiedClock {
                    interval: Clock {
                        now: 1000,
                        uncertainty: 1,
                    },
                    valid_until: Instant::now() + std::time::Duration::from_secs(5),
                })
        }
    }
    let (app, _dir, _) = fixture_with_host(
        Arc::new(Once(std::sync::atomic::AtomicBool::new(true))),
        server.host.clone(),
    );
    assert_eq!(
        request(&app, "identity", "central-installer", b"{}".to_vec())
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(server.calls.lock().unwrap().len(), 1);
}
#[tokio::test]
async fn roles_body_limit_and_unknown_status_are_enforced_at_router() {
    let (app, _dir) = fixture(Arc::new(FixedClock(Some(Clock {
        now: 1000,
        uncertainty: 1,
    }))));
    let status = br#"{"id":"missing"}"#.to_vec();
    for action in ["projection", "projection_lookup"] {
        for token in ["", "central-installer", "fleet-admin"] {
            assert_eq!(
                request(&app, action, token, vec![]).await.status(),
                StatusCode::UNAUTHORIZED
            );
        }
    }
    assert_eq!(
        request(
            &app,
            "projection_lookup",
            "gateway-only",
            br#"{"delegation":"missing","grant":"presented"}"#.to_vec()
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        request(
            &app,
            "projection_lookup",
            "gateway-only",
            br#"{"delegation":"missing"}"#.to_vec()
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(
            &app,
            "projection",
            "gateway-only",
            br#"{"delegation_intent":"missing"}"#.to_vec()
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(
            &app,
            "projection",
            "gateway-only",
            br#"{"delegation_intent":"missing","grant":"presented"}"#.to_vec()
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        request(&app, "operation_status", "", status.clone())
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(
            &app,
            "operation_status",
            "central-installer",
            status.clone()
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(
            &app,
            "installation_status",
            "gateway-only",
            br#"{"kind":"delegation","id":"missing"}"#.to_vec()
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(&app, "register", "fleet-admin", vec![])
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(&app, "revoke", "gateway-only", vec![])
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let response = request(&app, "operation_status", "gateway-only", status).await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        serde_json::json!({"state":"unknown","evidence":null})
    );
    assert_eq!(
        request(
            &app,
            "installation_status",
            "central-installer",
            br#"{"kind":"delegation","id":"missing"}"#.to_vec()
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        request(&app, "exec", "gateway-only", vec![b'x'; MAX_BODY_BYTES + 1])
            .await
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}
#[tokio::test]
async fn stale_or_absent_clock_refuses_mutation_before_host_call() {
    for source in [
        Arc::new(StaleClock) as Arc<dyn ClockSource>,
        Arc::new(FixedClock(None)),
    ] {
        let host = HostRec {
            id: "host".into(),
            url: "https://127.0.0.1:1".into(),
            token: "host-admin".into(),
            tls_fingerprint: "ab".repeat(32),
            ..Default::default()
        };
        let (app, _dir, epoch) = fixture_with_host(source, host);
        let record = HostRegistration {
            authority: "region".into(),
            epoch,
            key_id: "authority".into(),
            public_key: Ed25519KeyPair::from_seed_unchecked(&[2; 32])
                .unwrap()
                .public_key()
                .as_ref()
                .try_into()
                .unwrap(),
            host_instance: "instance".into(),
            generation: 1,
        };
        let body = serde_json::to_vec(&serde_json::json!({"id":"new","record":record})).unwrap();
        assert_eq!(
            request(&app, "register", "central-installer", body)
                .await
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            request(
                &app,
                "observe",
                "gateway-only",
                br#"{"id":"unknown"}"#.to_vec()
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
#[tokio::test]
async fn registration_route_returns_exact_ack_and_duplicate_is_status_only() {
    use axum::{extract::State, response::IntoResponse};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicUsize, Ordering};
    async fn endpoint(
        State(calls): State<Arc<AtomicUsize>>,
        uri: axum::http::Uri,
        body: axum::body::Bytes,
    ) -> Response {
        if uri.path().ends_with("/instance") {
            return Json(briqyard_api::execution::channel::Instance {
                host_instance: "instance".into(),
            })
            .into_response();
        }
        calls.fetch_add(1, Ordering::SeqCst);
        let record: HostRegistration = serde_json::from_slice(&body).unwrap();
        Json(briqyard_api::execution::channel::InstallationAck {
            host_instance: record.host_instance,
            generation: record.generation,
            digest: URL_SAFE_NO_PAD.encode(Sha256::digest(body)),
        })
        .into_response()
    }
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let config = briqyard_api::tls::server_config(
        cert.cert.pem().as_bytes(),
        cert.key_pair.serialize_pem().as_bytes(),
    )
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let host = HostRec {
        id: "host".into(),
        url: format!("https://{}", listener.local_addr().unwrap()),
        token: "host-admin".into(),
        tls_fingerprint: briqyard_api::tls::fingerprint(cert.cert.der()),
        ..Default::default()
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let handle = axum_server::Handle::new();
    let running = handle.clone();
    let app_host = axum::Router::new()
        .fallback(endpoint)
        .with_state(calls.clone());
    let task = tokio::spawn(async move {
        axum_server::from_tcp_rustls(
            listener,
            axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config)),
        )
        .handle(running)
        .serve(app_host.into_make_service())
        .await
    });
    let (app, _dir, epoch) = fixture_with_host(
        Arc::new(FixedClock(Some(Clock {
            now: 1000,
            uncertainty: 1,
        }))),
        host,
    );
    let record = HostRegistration {
        authority: "region".into(),
        epoch,
        key_id: "authority".into(),
        public_key: Ed25519KeyPair::from_seed_unchecked(&[2; 32])
            .unwrap()
            .public_key()
            .as_ref()
            .try_into()
            .unwrap(),
        host_instance: "instance".into(),
        generation: 1,
    };
    let body =
        serde_json::to_vec(&serde_json::json!({"id":"registration", "record":record})).unwrap();
    let first = request(&app, "register", "central-installer", body.clone()).await;
    assert_eq!(first.status(), StatusCode::OK);
    let first: serde_json::Value =
        serde_json::from_slice(&to_bytes(first.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(first["state"], "ready");
    assert_eq!(first["evidence"]["host_instance"], "instance");
    let second = request(&app, "register", "central-installer", body).await;
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        request(
            &app,
            "installation_status",
            "central-installer",
            br#"{"kind":"ownership","id":"registration"}"#.to_vec()
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    handle.shutdown();
    task.abort();
}

#[test]
fn credential_configuration_refuses_reuse_and_empty_values() {
    // Constructor validation is pure and occurs before a listener exists.
    let c = Credentials {
        installer: "i".into(),
        gateway: "g".into(),
        administrator: "a".into(),
        host_administrator: "h".into(),
    };
    assert!(valid_credentials(&c));
    for (i, g, a, h) in [
        ("", "g", "a", "h"),
        ("i", "", "a", "h"),
        ("x", "x", "a", "h"),
        ("a", "g", "a", "h"),
        ("i", "h", "a", "h"),
    ] {
        assert!(!valid_credentials(&Credentials {
            installer: i.into(),
            gateway: g.into(),
            administrator: a.into(),
            host_administrator: h.into()
        }));
    }
}

#[tokio::test]
async fn operation_renewal_routes_require_installer_and_remain_disabled_by_default() {
    let (app, _dir) = fixture(Arc::new(FixedClock(Some(Clock {
        now: 1000,
        uncertainty: 1,
    }))));
    for action in [
        "operation_active",
        "operation_protect",
        "operation_continue",
    ] {
        for (credential, expected) in [
            ("gateway-only", StatusCode::UNAUTHORIZED),
            ("central-installer", StatusCode::SERVICE_UNAVAILABLE),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/internal/authority/v1/{action}"))
                        .header(header::AUTHORIZATION, format!("Bearer {credential}"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
        }
    }
}
#[test]
fn one_live_dispatch_owner_cannot_be_reconstructed_from_retained_status() {
    let live = Arc::new(LiveOperations::default());
    let owner = live.enter("operation").unwrap();
    assert!(live.contains("operation"));
    assert!(live.enter("operation").is_err());
    drop(owner);
    assert!(!live.contains("operation"));
}

#[tokio::test]
async fn authorization_clock_is_installer_only_qualified_and_independent_of_renewable_gate() {
    let server = crate::execution_host::tests::server();
    let (app, _dir, _) = fixture_with_host(
        Arc::new(FixedClock(Some(Clock {
            now: 1000,
            uncertainty: 1,
        }))),
        server.host.clone(),
    );
    for token in [
        "",
        "gateway-only",
        "fleet-admin",
        "host-installer",
        "host-execution",
    ] {
        assert_eq!(
            request(&app, "authorization_clock", token, b"{}".to_vec())
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        request(
            &app,
            "authorization_clock",
            "central-installer",
            br#"{"host":"other"}"#.to_vec()
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    let response = request(
        &app,
        "authorization_clock",
        "central-installer",
        b"{}".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let result: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024).await.unwrap()).unwrap();
    assert_eq!(
        result,
        serde_json::json!({"authority":{"now":1000,"uncertainty":1},"host":{"now":1000,"uncertainty":1}})
    );
    assert_eq!(
        *server.calls.lock().unwrap(),
        vec![(
            "/internal/execution/v1/clock".into(),
            "Bearer host-installer".into()
        )]
    );
    for clock in [
        Arc::new(FixedClock(None)) as Arc<dyn ClockSource>,
        Arc::new(StaleClock),
    ] {
        let (app, _dir, _) = fixture_with_host(clock, server.host.clone());
        assert_eq!(
            request(
                &app,
                "authorization_clock",
                "central-installer",
                b"{}".to_vec()
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    assert_eq!(server.calls.lock().unwrap().len(), 1);
}
