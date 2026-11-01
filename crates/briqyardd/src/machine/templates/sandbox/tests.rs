use super::*;
use crate::machine::tests::{harness_config, Harness};

async fn source() -> (Harness, Arc<Entry>, api::SandboxSeed) {
    let h = harness_config(|c| {
        c.token = "test-admin".into();
        c.jailer = "/mock/jailer".into();
        c.capacity.memory_mb = 8192;
        c.capacity.vcpus = 8;
        c.network.range = "10.64.0.0/22".into();
        c.templates.enabled = true;
        c.templates.warm_pools = true;
        c.templates.sandbox_recipes = vec![crate::config::SandboxRecipe {
            image: ALPINE.into(),
            image_config_digest: ALPINE_CONFIG_DIGEST.into(),
            init_sha256: hex::encode(Sha256::digest(b"init")),
            size: api::Size {
                vcpus: 1,
                memory_mb: 256,
                cpu_millis: None,
            },
            volume_gb: 2,
        }];
    })
    .await;
    assert!(!h
        .m
        .warm_pool_profiles()
        .iter()
        .any(|profile| profile == guest::SANDBOX_READY_V1));
    h.namespace("operator");
    h.namespace("destination");
    let image =
        h.m.inner
            .images
            .seed_with_config_digest(
                ALPINE,
                ImageConfig {
                    entrypoint: vec!["/bin/sh".into()],
                    cmd: vec!["-ec".into(), "sleep infinity".into()],
                    env: BTreeMap::from([("IMAGE_DEFAULT".into(), "retained".into())]),
                    workdir: "/".into(),
                    ..Default::default()
                },
                ALPINE_CONFIG_DIGEST,
            )
            .await
            .unwrap();
    let (e, _) =
        h.m.record(
            api::CreateMachineRequest {
                namespace: "operator".into(),
                name: "pristine".into(),
                image: ALPINE.into(),
                size: image_size(),
                template_build: Some(guest::SANDBOX_READY_V1.into()),
                start: Some(true),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    {
        let mut r = e.rec.lock().unwrap();
        r.image_key = image.key.clone();
        r.root_key = image.key;
        r.image_digest = image.digest;
        r.image_config_digest = image.config_digest;
        r.image_config = image.config;
    }
    // Mocked lifecycle only: stand-in disks and VMM do not qualify native device behavior.
    h.disks(&e).await;
    h.m.start_entry(&e, true).await.unwrap();
    let snap =
        h.m.snapshot(
            &e.snapshot().id,
            api::SnapshotRequest {
                memory: true,
                template: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let seed = api::SandboxSeed {
        machine_id: e.snapshot().id,
        snapshot: snap.id,
        generation: snap.clone_generation.unwrap(),
        request_id: "create-one".into(),
    };
    (h, e, seed)
}
fn image_size() -> api::Size {
    api::Size {
        vcpus: 1,
        memory_mb: 256,
        cpu_millis: None,
    }
}
fn destination(seed: api::SandboxSeed) -> api::CreateMachineRequest {
    api::CreateMachineRequest {
        namespace: "destination".into(),
        name: "sandbox".into(),
        image: ALPINE.into(),
        size: image_size(),
        sandbox_seed: Some(seed),
        start: Some(true),
        volume: Some(api::VolumeSpec {
            size_gb: 2,
            mount: "/work".into(),
        }),
        cmd: Some(vec!["-ec".into(), "cd /work; sleep infinity".into()]),
        env: BTreeMap::from([("DESTINATION".into(), "installed".into())]),
        files: vec![api::File {
            path: "/work/start".into(),
            base64: guest::base64_encode(b"boot"),
            mode: Some("600".into()),
        }],
        ports: vec![8080],
        metadata: BTreeMap::from([
            ("team".into(), "trusted-team".into()),
            ("briq_id".into(), "bq_one".into()),
        ]),
        ..Default::default()
    }
}
#[tokio::test]
async fn ordinary_record_binds_complete_create_and_replays_exactly_across_failure_and_recovery() {
    let (h, _, seed) = source().await;
    let req = destination(seed);
    let (e, _) = h.m.record(req.clone(), None).await.unwrap();
    let id = e.snapshot().id;
    let (same, how) = h.m.record(req.clone(), None).await.unwrap();
    assert_eq!(same.snapshot().id, id);
    assert!(matches!(how, Make::Existing));
    let mut changed = req.clone();
    changed.env.insert("DESTINATION".into(), "changed".into());
    assert!(matches!(
        h.m.record(changed, None).await,
        Err(MError::Conflict(_))
    ));
    let mut changed = req.clone();
    changed.metadata.insert("team".into(), "other".into());
    assert!(matches!(
        h.m.record(changed, None).await,
        Err(MError::Conflict(_))
    ));
    e.set_state(state::ERROR, |r| {
        r.error = "interrupted bind".into();
        None
    });
    h.m.save(&e).unwrap();
    h.m.load().unwrap();
    let (same, how) = h.m.record(req.clone(), None).await.unwrap();
    assert_eq!(same.snapshot().id, id);
    assert_eq!(same.snapshot().error, "interrupted bind");
    assert!(matches!(how, Make::Existing));
    h.m.inner.machines.lock().unwrap().remove(&id);
    assert!(matches!(
        h.m.record(req, None).await,
        Err(MError::Conflict(_))
    ));
}
#[tokio::test]
async fn destination_keeps_defaults_files_volume_metadata_and_exact_ack_before_activation() {
    let (h, _, seed) = source().await;
    let req = destination(seed);
    let (e, _) = h.m.record(req.clone(), None).await.unwrap();
    h.disks(&e).await;
    h.m.start_entry(&e, true).await.unwrap();
    let record = e.snapshot();
    let origin = record.clone_origin.unwrap();
    let binding = origin.sandbox.unwrap();
    let payload = binding.bind.unwrap();
    assert_eq!(payload.config.env["IMAGE_DEFAULT"], "retained");
    assert_eq!(payload.config.env["DESTINATION"], "installed");
    assert_eq!(payload.config.mounts[0].path, "/work");
    assert_eq!(payload.files[0].data, b"boot");
    assert!(payload.config.files.is_empty());
    assert_eq!(payload.config.entrypoint, ["/bin/sh"]);
    assert_eq!(record.metadata, req.metadata);
    assert_eq!(record.ports, req.ports);
    assert_eq!(binding.ack_sha256.unwrap(), binding_hash(&payload).unwrap());
    assert_eq!(origin.stage, CloneStage::Active);
    let calls = h.host_calls();
    let bind = calls
        .iter()
        .position(|c| c.starts_with("destination_bind_v1"))
        .unwrap();
    let activate = calls
        .iter()
        .position(|c| c.starts_with("clone_activate_v1"))
        .unwrap();
    assert!(bind < activate);
}
#[tokio::test]
async fn stale_generation_and_unapproved_shapes_do_not_consume_a_destination() {
    let (h, _, mut seed) = source().await;
    seed.generation = "g_stale".into();
    assert!(h.m.record(destination(seed.clone()), None).await.is_err());
    let mut req = destination(seed);
    req.volume.as_mut().unwrap().size_gb = 3;
    assert!(h.m.record(req, None).await.is_err());
    assert_eq!(h.m.inner.machines.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn bad_or_missing_ack_never_activates_and_retry_keeps_its_machine_and_reader() {
    for response_loss in [false, true] {
        let (h, _, seed) = source().await;
        let req = destination(seed);
        let (e, _) = h.m.record(req.clone(), None).await.unwrap();
        let id = e.snapshot().id;
        h.disks(&e).await;
        h.refuse_destination(response_loss, !response_loss);
        assert!(h.m.start_entry(&e, true).await.is_err());
        let origin = e.snapshot().clone_origin.unwrap();
        assert_eq!(origin.stage, CloneStage::Configuring);
        assert!(origin.identity.is_none());
        assert!(origin.sandbox.unwrap().ack_sha256.is_none());
        assert!(!h
            .host_calls()
            .iter()
            .any(|c| c.starts_with("clone_activate_v1")));
        let (same, how) = h.m.record(req, None).await.unwrap();
        assert_eq!(same.snapshot().id, id);
        assert!(matches!(how, Make::Existing));
        assert_eq!(h.m.clone_readers().unwrap().len(), 1);
    }
}
#[tokio::test]
async fn configured_or_ordinary_sources_cannot_become_cross_namespace_seeds() {
    let (h, source, seed) = source().await;
    source.rec.lock().unwrap().template_birth = None;
    assert!(h.m.record(destination(seed), None).await.is_err());
    assert_eq!(h.m.inner.machines.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn read_only_lookup_returns_accepted_failure_without_source_and_preserves_tombstones() {
    let (h, source, seed) = source().await;
    let req = destination(seed);
    let digest = request_digest(&req).unwrap();
    let (e, _) = h.m.record(req, None).await.unwrap();
    let id = e.snapshot().id;
    h.m.inner
        .machines
        .lock()
        .unwrap()
        .remove(&source.snapshot().id);
    e.set_state(state::ERROR, |r| {
        r.error = "interrupted".into();
        None
    });
    h.m.save(&e).unwrap();
    let query = api::SandboxRequestLookup {
        namespace: "destination".into(),
        request_id: "create-one".into(),
        create_sha256: digest,
    };
    let found =
        h.m.sandbox_request_lookup(query.clone())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(found.id, id);
    assert_eq!(found.state, state::ERROR);
    assert!(h.m.delete_namespace("destination").await.is_err()); // Nonempty remains protected.
    let mut changed = query.clone();
    changed.create_sha256 = "0".repeat(64);
    assert!(matches!(
        h.m.sandbox_request_lookup(changed).await,
        Err(MError::Conflict(_))
    ));
    h.m.inner.machines.lock().unwrap().remove(&id);
    h.m.delete_namespace("destination").await.unwrap();
    assert!(h.m.namespace_of("destination").is_none());
    assert!(matches!(
        h.m.sandbox_request_lookup(query).await,
        Err(MError::Conflict(_))
    ));
}
#[tokio::test]
async fn lookup_http_returns_distinct_absence_and_requires_configured_authentication() {
    use tower::ServiceExt;
    let (h, _, _) = source().await;
    let router = |token: &str| {
        crate::api::router(Arc::new(crate::api::AppState {
            mgr: h.m.clone(),
            token: token.into(),
            metrics_token: String::new(),
            loopback: true,
            openapi: "",
            tls_fingerprint: String::new(),
        }))
    };
    let query = api::SandboxRequestLookup {
        namespace: "destination".into(),
        request_id: "unknown".into(),
        create_sha256: "a".repeat(64),
    };
    for (token, expected) in [
        ("test-admin", axum::http::StatusCode::NOT_FOUND),
        ("", axum::http::StatusCode::CONFLICT),
    ] {
        let response = router(token)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/sandbox-requests/lookup")
                    .header("authorization", "Bearer test-admin")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&query).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        if expected == axum::http::StatusCode::NOT_FOUND {
            let data = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&data).unwrap()["code"],
                "sandbox_request_unknown"
            );
        }
    }
}
