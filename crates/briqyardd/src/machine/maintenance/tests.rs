use super::*;
use crate::machine::tests::{harness, record};

#[tokio::test]
async fn maintenance_empty_observation_is_not_a_stale_handover_permit() {
    let h = harness("10.64.0.0/22", 4096).await;
    let initial = h.m.warm_catalog_eligibility().await;
    assert!(initial.eligible);
    assert_eq!(initial.counts.unwrap().warm_machines, 0);
    let mut r = record();
    r.warm_slot = Some(warm::Slot {
        pool: "owned".into(),
        fingerprint: "f".repeat(64),
        claimed: Some("worker".into()),
    });
    r.state = state::ERROR.into();
    h.m.inner.store.put_durable("machines", &r.id, &r).unwrap();
    // A durable orphan alone blocks; claimed and failed slots are not clean absence.
    let changed = h.m.warm_catalog_eligibility().await;
    assert_eq!(
        changed.reason,
        api::WarmMaintenanceReason::OutstandingWarmState
    );
    assert_eq!(changed.counts.unwrap().warm_machines, 1);
    assert!(h
        .m
        .handover_admission(Path::new("/usr/bin/true"))
        .await
        .is_err());
    assert!(h.m.inner.warm_lock.try_write().is_ok());
    assert!(h.m.inner.namespace_lifecycle.try_write().is_ok());
    h.m.inner.store.delete_durable("machines", &r.id).unwrap();
    h.m.inner
        .machines
        .lock()
        .unwrap()
        .insert(r.id.clone(), Entry::new(r, h.m.inner.events.clone()));
    assert!(!h.m.warm_catalog_eligibility().await.eligible);
}

#[tokio::test]
async fn maintenance_unknown_or_recovery_state_never_exposes_values_or_repairs() {
    let h = harness("10.64.0.0/22", 4096).await;
    for kind in [
        "machines",
        "warm-pools",
        "launch-holds",
        "launch-transitions",
        "unbound-requests",
        "unbound-assignments",
        "assigned-runs",
        "assigned-run-intents",
        "assigned-run-readers",
        "assigned-run-updates",
    ] {
        let path = h.m.inner.store.dir(kind).join("bad.json");
        let bytes = b"not-json SECRET_SENTINEL";
        std::fs::write(&path, bytes).unwrap();
        let view = h.m.warm_catalog_eligibility().await;
        assert!(!view.eligible, "{kind}");
        assert_eq!(view.reason, api::WarmMaintenanceReason::StateUnknown);
        assert!(view.counts.is_none());
        assert!(!serde_json::to_string(&view)
            .unwrap()
            .contains("SECRET_SENTINEL"));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        std::fs::remove_file(path).unwrap();
    }
    *h.m.inner.recovery_fault.lock().unwrap() = Some("test");
    assert_eq!(
        h.m.warm_catalog_eligibility().await.reason,
        api::WarmMaintenanceReason::RecoveryUnresolved
    );
}

#[tokio::test]
async fn maintenance_retains_both_gates_and_cancellation_releases_them() {
    let h = harness("10.64.0.0/22", 4096).await;
    let held = h.m.inner.namespace_lifecycle.read().await;
    let mut pending = Box::pin(h.m.warm_catalog_eligibility());
    assert!(matches!(
        futures::poll!(&mut pending),
        std::task::Poll::Pending
    ));
    assert!(h.m.inner.warm_lock.try_read().is_err());
    drop(pending);
    assert!(h.m.inner.warm_lock.try_write().is_ok());
    drop(held);
    let guard =
        h.m.warm_maintenance_admission_until(tokio::time::Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
    assert!(h.m.inner.warm_lock.try_write().is_err());
    assert!(h.m.inner.namespace_lifecycle.try_read().is_err());
    drop(guard);
    assert!(h.m.inner.warm_lock.try_write().is_ok());
    assert!(h.m.inner.namespace_lifecycle.try_write().is_ok());
}

#[tokio::test]
async fn maintenance_http_requires_api_auth_and_exposes_only_fixed_projection() {
    use tower::ServiceExt;
    let h = harness("10.64.0.0/22", 4096).await;
    for (configured, bearer, expected) in [
        ("test-admin", None, axum::http::StatusCode::UNAUTHORIZED),
        (
            "test-admin",
            Some("metrics-only"),
            axum::http::StatusCode::UNAUTHORIZED,
        ),
        ("test-admin", Some("test-admin"), axum::http::StatusCode::OK),
        ("", None, axum::http::StatusCode::CONFLICT),
    ] {
        let router = crate::api::router(Arc::new(crate::api::AppState {
            mgr: h.m.clone(),
            token: configured.into(),
            metrics_token: "metrics-only".into(),
            loopback: true,
            openapi: "",
            tls_fingerprint: String::new(),
        }));
        let mut request = axum::http::Request::builder().uri("/v1/maintenance/warm-catalog");
        if let Some(token) = bearer {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let response = router
            .oneshot(request.body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        if expected == axum::http::StatusCode::OK {
            let body = axum::body::to_bytes(response.into_body(), 8192)
                .await
                .unwrap();
            let view: api::WarmCatalogEligibility = serde_json::from_slice(&body).unwrap();
            assert!(view.eligible);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body)
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .len(),
                4
            );
        }
    }
}
