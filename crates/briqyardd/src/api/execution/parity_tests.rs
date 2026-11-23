use super::*;
use crate::machine::tests::channel_manager;
use briqyard_api::execution::{
    admission::{ActivePhase, Role},
    KeyRole,
};
use std::{sync::Arc, time::Duration};

#[tokio::test]
async fn ordinary_unauthenticated_malformed_post_is_unsupported_media_type() {
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode},
    };
    use tower::ServiceExt;
    let manager = channel_manager().await;
    let dir = tempfile::tempdir().unwrap();
    let journal = Journal::open(&dir.path().join("journal"), Role::Host("h_test".into())).unwrap();
    let channel = HostExecutionChannel::new(
        manager,
        journal,
        "installer-secret".into(),
        "execution-secret".into(),
        vec![VerificationKey {
            kid: "authority-key".into(),
            role: KeyRole::Authority,
            issuer: "authority".into(),
            authority: Some("authority-1".into()),
            public_key: [7; 32],
        }],
        "central".into(),
        "authority".into(),
        "runtime".into(),
        1,
    )
    .unwrap();
    let response = router(Arc::new(channel))
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/internal/execution/v1/register")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

fn ordinary_channel(
    manager: Manager,
    journal: Journal,
    registration: &HostRegistration,
) -> HostExecutionChannel {
    HostExecutionChannel::new(
        manager,
        journal,
        "installer-secret".into(),
        "execution-secret".into(),
        vec![
            VerificationKey {
                kid: registration.key_id.clone(),
                role: KeyRole::Authority,
                issuer: "authority".into(),
                authority: Some(registration.authority.clone()),
                public_key: registration.public_key,
            },
            VerificationKey {
                kid: "central".into(),
                role: KeyRole::Central,
                issuer: "central".into(),
                authority: None,
                public_key: [1; 32],
            },
        ],
        "central".into(),
        "authority".into(),
        "runtime".into(),
        1,
    )
    .unwrap()
}

#[tokio::test]
async fn ordinary_revocation_after_ownership_failure_ends_live_lease() {
    use axum::{
        body::Body,
        http::{header, Method, Request, StatusCode},
    };
    use tower::ServiceExt;
    let manager = channel_manager().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal");
    let fixture = test_fixtures::active_operation(&path);
    let before = std::fs::read(path.join("journal.json")).unwrap();
    let channel = ordinary_channel(manager, fixture.journal, &fixture.registration);
    let (_owner, lease) = test_fixtures::reserve_ordinary(
        &channel.active,
        &fixture.permit.admission,
        &fixture.active,
    );
    assert!(lease
        .observe(&fixture.active, &test_fixtures::sample())
        .is_ok());
    std::fs::rename(path.join("writer.lock"), path.join("old.lock")).unwrap();
    std::os::unix::fs::symlink(path.join("old.lock"), path.join("writer.lock")).unwrap();
    let response = router(Arc::new(channel))
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/internal/execution/v1/revoke")
                .header(header::AUTHORIZATION, "Bearer installer-secret")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&Revoke {
                        id: "delegation".into(),
                        version: 1,
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(lease
        .observe(&fixture.active, &test_fixtures::sample())
        .is_err());
    let after = std::fs::read(path.join("journal.json")).unwrap();
    assert_eq!(after, before);
    let stored: serde_json::Value = serde_json::from_slice(&after).unwrap();
    assert_eq!(
        stored["active_operations"][&fixture.permit.admission]["phase"],
        serde_json::to_value(ActivePhase::Active).unwrap(),
    );
}

#[tokio::test]
async fn ordinary_queued_registration_reads_state_after_its_turn() {
    use axum::{
        body::Body,
        http::{header, Method, Request, StatusCode},
    };
    use tower::ServiceExt;
    let manager = channel_manager().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal");
    let fixture = test_fixtures::active_operation(&path);
    let channel = Arc::new(ordinary_channel(
        manager,
        fixture.journal,
        &fixture.registration,
    ));
    let successor = HostRegistration {
        epoch: "successor-epoch".into(),
        generation: 2,
        ..fixture.registration.clone()
    };
    let turn = channel.hold_ordinary_admission_for_test().await;
    let request = router(channel.clone()).oneshot(
        Request::builder()
            .method(Method::POST)
            .uri("/internal/execution/v1/register")
            .header(header::AUTHORIZATION, "Bearer installer-secret")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&successor).unwrap()))
            .unwrap(),
    );
    tokio::pin!(request);
    assert!(futures::poll!(&mut request).is_pending());
    {
        let mut journal = channel.journal.lock().await;
        journal
            .register_host(successor.clone(), channel.clock().unwrap())
            .unwrap();
    }
    drop(turn);
    let response = tokio::time::timeout(Duration::from_secs(2), request)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let journal = channel.journal.lock().await;
    assert_eq!(journal.registration().unwrap(), Some(&successor));
    let stored: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path.join("journal.json")).unwrap()).unwrap();
    assert_eq!(
        stored["fences"][&successor.authority].as_str(),
        Some(successor.epoch.as_str())
    );
    assert!(stored["retired"][&fixture.registration.authority]
        .as_array()
        .unwrap()
        .contains(&serde_json::Value::String(fixture.registration.epoch)));
    drop(journal);
}

#[tokio::test]
async fn ordinary_constructor_does_not_recheck_journal_ownership() {
    let manager = channel_manager().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal");
    let journal = Journal::open(&path, Role::Host("h_test".into())).unwrap();
    std::fs::rename(path.join("writer.lock"), path.join("old.lock")).unwrap();
    std::os::unix::fs::symlink(path.join("old.lock"), path.join("writer.lock")).unwrap();
    HostExecutionChannel::new(
        manager,
        journal,
        "installer-secret".into(),
        "execution-secret".into(),
        vec![VerificationKey {
            kid: "authority-key".into(),
            role: KeyRole::Authority,
            issuer: "authority".into(),
            authority: Some("authority-1".into()),
            public_key: [7; 32],
        }],
        "central".into(),
        "authority".into(),
        "runtime".into(),
        1,
    )
    .unwrap();
}
