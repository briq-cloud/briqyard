use super::*;

#[tokio::test]
async fn maintenance_zero_pool_allows_observation_but_later_desired_change_blocks_handover() {
    let (h, _, seed) = source_with_unbound(true).await;
    h.m.put_warm_pool(
        "operator",
        "owned",
        api::PutWarmPoolRequest {
            source_machine: seed.machine_id,
            snapshot: seed.snapshot,
            desired: 0,
        },
    )
    .await
    .unwrap();
    let first = h.m.warm_catalog_eligibility().await;
    assert!(first.eligible, "{:?}", first.reason);
    assert_eq!(first.counts.unwrap().pools, 1);
    let mut pool: serde_json::Value =
        h.m.inner
            .store
            .list::<serde_json::Value>("warm-pools")
            .unwrap()
            .pop()
            .unwrap();
    pool["desired"] = 1.into();
    let key = h.m.inner.store.keys("warm-pools").unwrap().pop().unwrap();
    // Store drift is unknown and cannot be repaired by a GET.
    h.m.inner
        .store
        .put_durable("warm-pools", &key, &pool)
        .unwrap();
    assert_eq!(
        h.m.warm_catalog_eligibility().await.reason,
        api::WarmMaintenanceReason::StateUnknown
    );
    assert!(h
        .m
        .handover_admission(Path::new("/usr/bin/true"))
        .await
        .is_err());
    h.m.recover_warm_names().unwrap();
    let changed = h.m.warm_catalog_eligibility().await;
    assert_eq!(changed.counts.unwrap().desired_slots, 1);
    assert!(!changed.eligible);
}

#[tokio::test]
async fn sealed_recipe_observation_uses_the_validated_artifact_without_creating_authority() {
    let (h, source, seed) = source().await;
    let before = source.snapshot();
    let readers = h.m.inner.store.keys(templates::READERS).unwrap();
    let receipt =
        h.m.sealed_sandbox_recipe(&seed.machine_id, &seed.snapshot)
            .await
            .unwrap();
    let artifact = before.snapshots[0].clone_artifact.as_ref().unwrap();
    assert_eq!(receipt.generation, seed.generation);
    assert_eq!(receipt.source_host, artifact.source_host);
    assert_eq!(receipt.namespace, before.namespace);
    assert_eq!(receipt.profile, guest::SANDBOX_READY_V1);
    assert_eq!(receipt.root_disk_gb, artifact.recipe.root_disk_gb);
    assert_eq!(receipt.size, artifact.recipe.size);
    assert_eq!(receipt.data_device, artifact.recipe.config.sandbox_device);
    assert_eq!(
        receipt.image_config_digest,
        artifact.recipe.image_config_digest
    );
    assert_eq!(receipt.init_sha256, artifact.init_sha256);
    assert_eq!(receipt.observation.host_id, h.m.host_id());
    assert_eq!(
        receipt.observation.config,
        api::LoadedConfigIdentity::Unobserved
    );
    let repeated =
        h.m.sealed_sandbox_recipe(&seed.machine_id, &seed.snapshot)
            .await
            .unwrap();
    assert_eq!(
        receipt.observation.incarnation,
        repeated.observation.incarnation
    );
    let other = harness_config(|_| {}).await;
    assert_ne!(
        receipt.observation.incarnation,
        other.m.runtime_observation().incarnation
    );
    let json = serde_json::to_value(receipt).unwrap();
    assert_eq!(json.as_object().unwrap().len(), 15);
    for forbidden in [
        "env",
        "config",
        "cmd",
        "files",
        "memory",
        "state",
        "ram_marker",
    ] {
        assert!(json.get(forbidden).is_none(), "{forbidden}");
    }
    assert_eq!(h.m.inner.store.keys(templates::READERS).unwrap(), readers);
    assert_eq!(
        serde_json::to_value(source.snapshot()).unwrap(),
        serde_json::to_value(before).unwrap()
    );
    assert!(h.m.warm_pools("operator").unwrap().is_empty());
}

#[tokio::test]
async fn sealed_recipe_requires_an_exact_snapshot_and_rejects_changed_provenance() {
    let (h, source, seed) = source().await;
    source.rec.lock().unwrap().snapshots[0].name = Some("named-template".into());
    assert!(matches!(
        h.m.sealed_sandbox_recipe(&seed.machine_id, "named-template")
            .await,
        Err(MError::NoSnapshot(_))
    ));
    let original = source.snapshot().snapshots[0]
        .clone_artifact
        .clone()
        .unwrap();
    for change in 0..4 {
        let mut altered = original.clone();
        match change {
            0 => altered.recipe.root_disk_gb += 1,
            1 => altered.init_sha256 = "0".repeat(64),
            2 => altered.source_host = "other-host".into(),
            _ => altered.recipe.config.sandbox_device = Some(guest::SandboxDevice::of_gb(3)),
        }
        source.rec.lock().unwrap().snapshots[0].clone_artifact = Some(altered);
        assert!(h
            .m
            .sealed_sandbox_recipe(&seed.machine_id, &seed.snapshot)
            .await
            .is_err());
    }
    source.rec.lock().unwrap().snapshots[0].clone_artifact = Some(original);
    assert!(h
        .m
        .sealed_sandbox_recipe(&seed.machine_id, &seed.snapshot)
        .await
        .is_ok());
    *h.m.inner.recovery_fault.lock().unwrap() = Some("recovery_unresolved");
    assert!(h
        .m
        .sealed_sandbox_recipe(&seed.machine_id, &seed.snapshot)
        .await
        .is_err());
}

#[tokio::test]
async fn sealed_recipe_http_requires_configured_api_auth_even_on_loopback() {
    use tower::ServiceExt;
    let (h, _, seed) = source().await;
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
        let mut request = axum::http::Request::builder().uri(format!(
            "/v1/machines/{}/snapshots/{}/sandbox-recipe",
            seed.machine_id, seed.snapshot,
        ));
        if let Some(token) = bearer {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let response = router
            .oneshot(request.body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
}

#[tokio::test]
async fn canceling_a_waiting_recipe_observation_releases_its_lifecycle_waiter() {
    let (h, source, seed) = source().await;
    let held = source.lock.lock().await;
    let mut request = Box::pin(h.m.sealed_sandbox_recipe(&seed.machine_id, &seed.snapshot));
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut request)
            .await
            .is_err()
    );
    drop(request);
    drop(held);
    assert!(source.lock.try_lock().is_ok());
    assert!(h
        .m
        .sealed_sandbox_recipe(&seed.machine_id, &seed.snapshot)
        .await
        .is_ok());
}

#[tokio::test]
async fn sealed_recipe_http_preserves_validator_and_recovery_error_contracts() {
    use tower::ServiceExt;
    let (h, source, seed) = source().await;
    source.rec.lock().unwrap().snapshots[0]
        .clone_artifact
        .as_mut()
        .unwrap()
        .recipe
        .config
        .sandbox_device = Some(guest::SandboxDevice::of_gb(3));
    for (recovery, status, code) in [
        (
            None,
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
        ),
        (
            Some("recovery_unresolved"),
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "capacity",
        ),
    ] {
        *h.m.inner.recovery_fault.lock().unwrap() = recovery;
        let router = crate::api::router(Arc::new(crate::api::AppState {
            mgr: h.m.clone(),
            token: "test-admin".into(),
            metrics_token: String::new(),
            loopback: true,
            openapi: "",
            tls_fingerprint: String::new(),
        }));
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .uri(format!(
                        "/v1/machines/{}/snapshots/{}/sandbox-recipe",
                        seed.machine_id, seed.snapshot
                    ))
                    .header("authorization", "Bearer test-admin")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let error: api::ApiError = serde_json::from_slice(&body).unwrap();
        assert_eq!(error.code, code);
    }
}
