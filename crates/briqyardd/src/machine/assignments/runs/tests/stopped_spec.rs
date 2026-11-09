//! Stopped workload updates reuse the assigned run's durable authority and backing.
use super::*;

// The initial destination assignment predates the continuation journal. Establish a
// public continuation and its settled Current, as the existing resize fixtures do.
async fn settled_run(checkpoint: bool) -> (crate::machine::tests::Harness, Arc<Entry>) {
    let (h, entry) = stopped(false).await;
    let id = entry.snapshot().id;
    tokio::time::timeout(Duration::from_secs(60), h.m.start(&id, None))
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(60),
        h.m.stop(&id, Duration::from_secs(1), checkpoint, None),
    )
    .await
    .unwrap()
    .unwrap();
    let current: Current =
        h.m.inner
            .store
            .get(RUNS, &id)
            .unwrap()
            .expect("settled continuation journal");
    assert_eq!(current.reference.phase, Phase::Settled);
    assert_eq!(entry.snapshot().state, state::STOPPED);
    (h, entry)
}

fn patch(
    image: Option<String>,
    env: BTreeMap<String, String>,
    size: Option<api::Size>,
) -> api::UpdateMachineRequest {
    api::UpdateMachineRequest {
        spec: api::SpecChange {
            image,
            env: Some(env),
            size,
            ..Default::default()
        },
        ..Default::default()
    }
}

// Endpoints have separate durable records, rather than fields on the machine record.
fn seed_endpoint(h: &crate::machine::tests::Harness, record: &Record) -> EndpointRec {
    let endpoint = EndpointRec {
        id: "ep_stopped_spec".into(),
        machine_id: record.id.clone(),
        namespace: record.namespace.clone(),
        port: 8080,
        protocol: "tcp".into(),
        host_port: Some(30001),
        host: String::new(),
        created_at: Utc::now(),
    };
    h.m.inner
        .store
        .put_durable("endpoints", &endpoint.id, &endpoint)
        .unwrap();
    h.m.inner
        .endpoints
        .lock()
        .unwrap()
        .insert(endpoint.id.clone(), endpoint.clone());
    endpoint
}

fn assert_endpoint_retained(h: &crate::machine::tests::Harness, expected: &EndpointRec) {
    let expected_record = serde_json::to_value(expected).unwrap();
    let durable: EndpointRec =
        h.m.inner
            .store
            .get("endpoints", &expected.id)
            .unwrap()
            .unwrap();
    assert_eq!(serde_json::to_value(durable).unwrap(), expected_record);
    assert_eq!(
        serde_json::to_value(h.m.endpoint(&expected.id).unwrap()).unwrap(),
        expected_record
    );
    let view = h.m.endpoints_of(&expected.machine_id);
    assert_eq!(view.len(), 1);
    assert_eq!(
        serde_json::to_value(&view[0]).unwrap(),
        serde_json::to_value(h.m.endpoint_view(expected)).unwrap()
    );
}

#[tokio::test]
async fn stopped_image_env_replacement_keeps_identity_volume_and_waits_for_start() {
    for resource in 0..3 {
        let (h, entry) = settled_run(true).await;
        let before = entry.snapshot();
        let endpoint = seed_endpoint(&h, &before);
        let id = before.id.clone();
        let image = format!("alpine@sha256:{}", "3".repeat(64));
        h.m.inner
            .images
            .seed(&image, crate::image::ImageConfig::default())
            .await
            .unwrap();
        let size = match resource {
            0 => None,
            1 => Some(before.size),
            _ => Some(api::Size {
                cpu_millis: Some(before.size.vcpus * 1000),
                ..before.size
            }),
        };
        let env = if resource == 1 {
            BTreeMap::new()
        } else {
            BTreeMap::from([("REPLACEMENT".into(), "new".into())])
        };
        let data = before.data_dataset();
        let data_guid = h.pool.zfs.guid(&data).await.unwrap();
        let run: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
        let updated =
            h.m.update(
                &id,
                patch(Some(image.clone()), env.clone(), size),
                Some(before.version),
            )
            .await
            .unwrap();
        assert_eq!(updated.state, state::STOPPED);
        assert!(entry.live.lock().unwrap().is_none());
        let pending = entry.snapshot();
        assert_eq!(pending.env, before.env);
        assert_eq!(pending.image, before.image);
        assert_eq!(pending.launch_identity, before.launch_identity);
        assert_eq!(pending.volume, before.volume);
        assert_endpoint_retained(&h, &endpoint);
        assert_eq!(pending.pending.as_ref().unwrap().env, Some(env.clone()));
        let intent: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
        intent.check(&run).unwrap();
        let replay =
            h.m.update(&id, patch(Some(image.clone()), env.clone(), size), None)
                .await
                .unwrap();
        assert_eq!(replay.version, updated.version);
        // An image-only retry omits env and must preserve its pending replacement.
        let omitted = api::UpdateMachineRequest {
            spec: api::SpecChange {
                image: Some(image.clone()),
                ..Default::default()
            },
            ..Default::default()
        };
        let omitted = h.m.update(&id, omitted, None).await.unwrap();
        assert_eq!(omitted.version, updated.version);
        assert_eq!(
            entry.snapshot().pending.as_ref().unwrap().env,
            Some(env.clone())
        );
        let retained: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
        assert_eq!(retained.digest().unwrap(), intent.digest().unwrap());
        assert!(h
            .m
            .update(
                &id,
                patch(None, BTreeMap::new(), None),
                Some(before.version)
            )
            .await
            .is_err());
        restart(&h).unwrap();
        let recovered = h.m.entry(&id).unwrap();
        assert_eq!(recovered.snapshot().state, state::STOPPED);
        tokio::time::timeout(Duration::from_secs(60), h.m.start(&id, None))
            .await
            .unwrap()
            .unwrap();
        let applied = recovered.snapshot();
        assert_eq!(applied.image, image);
        assert_eq!(applied.env, env);
        assert!(!applied.env.contains_key("DESTINATION_ONLY"));
        assert!(!applied.suspended);
        assert_eq!(applied.launch_identity, before.launch_identity);
        assert_eq!(applied.volume, before.volume);
        assert_endpoint_retained(&h, &endpoint);
        assert_eq!(h.pool.zfs.guid(&data).await.unwrap(), data_guid);
    }
}

#[tokio::test]
async fn stopped_env_coalescing_clear_cancel_and_uncertain_write_recover() {
    let (h, entry) = settled_run(false).await;
    let before = entry.snapshot();
    let id = before.id.clone();
    let replacement = BTreeMap::from([("NEW".into(), "value".into())]);
    h.m.update(&id, patch(None, replacement, None), None)
        .await
        .unwrap();
    let blocked =
        h.m.inner
            .store
            .dir("machines")
            .join(format!("{id}.json.tmp"));
    std::fs::create_dir(&blocked).unwrap();
    assert!(h
        .m
        .update(&id, patch(None, BTreeMap::new(), None), None)
        .await
        .is_err());
    let outstanding: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
    assert!(h
        .m
        .update(&id, patch(None, before.env.clone(), None), None)
        .await
        .is_err());
    let retained: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
    assert_eq!(outstanding.digest().unwrap(), retained.digest().unwrap());
    std::fs::remove_dir(blocked).unwrap();
    restart(&h).unwrap();
    assert_eq!(
        h.m.entry(&id)
            .unwrap()
            .snapshot()
            .pending
            .as_ref()
            .unwrap()
            .env,
        Some(BTreeMap::new())
    );
    // Cancel back to the original environment through the same journal.
    h.m.update(&id, patch(None, before.env.clone(), None), None)
        .await
        .unwrap();
    restart(&h).unwrap();
    assert!(h.m.entry(&id).unwrap().snapshot().pending.is_none());
    h.m.start(&id, None).await.unwrap();
    assert_eq!(h.m.entry(&id).unwrap().snapshot().env, before.env);
    assert!(h
        .m
        .update(&id, patch(None, BTreeMap::new(), None), None)
        .await
        .is_err());
}

#[tokio::test]
async fn stopped_env_update_refuses_missing_creation_authority() {
    let (h, entry) = settled_run(false).await;
    let id = entry.snapshot().id;
    let before = serde_json::to_value(entry.snapshot()).unwrap();
    let run: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
    assert!(h
        .m
        .update(
            &id,
            patch(None, BTreeMap::new(), Some(api::Size::default())),
            None
        )
        .await
        .is_err());
    assert_eq!(serde_json::to_value(entry.snapshot()).unwrap(), before);
    h.m.inner
        .store
        .delete(super::super::super::REQUESTS, &run.receipt.key())
        .unwrap();
    assert!(h
        .m
        .update(&id, patch(None, BTreeMap::new(), None), None)
        .await
        .is_err());
    assert_eq!(serde_json::to_value(entry.snapshot()).unwrap(), before);
    assert!(h
        .m
        .inner
        .store
        .get::<UpdateIntent>(UPDATES, &id)
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn stopped_env_only_replacement_starts_cold_with_fresh_config_and_same_disks() {
    for env in [
        BTreeMap::from([("REPLACEMENT".into(), "fresh".into())]),
        BTreeMap::new(),
    ] {
        let (h, entry) = settled_run(true).await;
        let before = entry.snapshot();
        assert!(before.suspended);
        let id = before.id.clone();
        let root_guid = h.pool.zfs.guid(&before.root_dataset()).await.unwrap();
        let data_guid = h.pool.zfs.guid(&before.data_dataset()).await.unwrap();
        h.m.update(&id, patch(None, env.clone(), None), None)
            .await
            .unwrap();
        assert_eq!(entry.snapshot().state, state::STOPPED);
        assert!(entry.live.lock().unwrap().is_none());
        let pending = entry.snapshot().pending.unwrap();
        assert!(pending.image.is_none());
        assert!(pending.size.is_none());
        assert_eq!(pending.env, Some(env.clone()));
        restart(&h).unwrap();
        tokio::time::timeout(Duration::from_secs(60), h.m.start(&id, None))
            .await
            .unwrap()
            .unwrap();
        let applied = h.m.entry(&id).unwrap().snapshot();
        assert_eq!(applied.env, env);
        assert!(!applied.suspended);
        assert_eq!(applied.image, before.image);
        assert_eq!(applied.launch_identity, before.launch_identity);
        assert_eq!(applied.volume, before.volume);
        assert_eq!(
            h.pool.zfs.guid(&before.root_dataset()).await.unwrap(),
            root_guid
        );
        assert_eq!(
            h.pool.zfs.guid(&before.data_dataset()).await.unwrap(),
            data_guid
        );
        let current: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
        let Mode::Fresh { drive_base64, .. } = &current.mode else {
            panic!("environment changes require a fresh boot")
        };
        let (config, _) = model::parse_drive(&guest::base64_decode(drive_base64).unwrap()).unwrap();
        assert_eq!(config.env, env);
        assert!(!config.env.contains_key("DESTINATION_ONLY"));
    }
}

// This is the first stopped destination assignment, before a continuation created Current.
// It has valid immutable creation/bind authority and is an existing machine eligible for upgrade.
#[tokio::test]
async fn initial_stopped_provider_image_env_replacement_preserves_creation_authority() {
    for resource in 0..3 {
        let (h, entry) = stopped(false).await;
        let before = entry.snapshot();
        let id = before.id.clone();
        assert!(before.assigned_run.is_none());
        assert!(h.m.inner.store.get::<Current>(RUNS, &id).unwrap().is_none());
        h.m.check_assigned_bound_record(&before)
            .expect("valid immutable creation and bind authority");
        let image = format!("alpine@sha256:{}", "4".repeat(64));
        h.m.inner
            .images
            .seed(&image, crate::image::ImageConfig::default())
            .await
            .unwrap();
        let env = if resource == 1 {
            BTreeMap::new()
        } else {
            BTreeMap::from([("REPLACEMENT".into(), "new".into())])
        };
        let mut wire = serde_json::json!({ "image": image, "env": env });
        if resource > 0 {
            let mut size = before.size;
            if resource == 2 {
                size.cpu_millis = Some(size.vcpus * 1000);
            }
            wire["size"] = serde_json::to_value(size).unwrap();
        }
        let request: api::UpdateMachineRequest = serde_json::from_value(wire.clone()).unwrap();
        let data_guid = h.pool.zfs.guid(&before.data_dataset()).await.unwrap();
        let updated =
            h.m.update(&id, request, Some(before.version))
                .await
                .expect("initial stopped image/full-env replacement");
        assert_eq!(updated.state, state::STOPPED);
        assert!(entry.live.lock().unwrap().is_none());
        let update: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
        assert_eq!(update.schema, 2);
        assert!(update.source_current_sha256.is_none());
        h.m.check_update_source(&update).unwrap();
        let replay =
            h.m.update(&id, serde_json::from_value(wire.clone()).unwrap(), None)
                .await
                .unwrap();
        assert_eq!(replay.version, updated.version);
        assert!(h
            .m
            .update(
                &id,
                serde_json::from_value(wire).unwrap(),
                Some(before.version)
            )
            .await
            .is_err());
        let calls = h.m.inner.images.ensure_calls.load(Relaxed);
        full_startup(&h).await.unwrap();
        assert_eq!(
            h.m.inner.images.ensure_calls.load(Relaxed),
            calls,
            "startup must not resolve the image"
        );
        let recovered = h.m.entry(&id).unwrap();
        assert_eq!(recovered.snapshot().state, state::STOPPED);
        assert!(recovered.live.lock().unwrap().is_none());
        assert!(h.m.inner.store.get::<Current>(RUNS, &id).unwrap().is_none());
        tokio::time::timeout(Duration::from_secs(60), h.m.start(&id, None))
            .await
            .unwrap()
            .unwrap();
        let after = recovered.snapshot();
        assert_eq!(after.launch_identity, before.launch_identity);
        assert_eq!(after.volume, before.volume);
        assert_eq!(after.image, image);
        assert_eq!(after.env, env);
        assert!(!after.suspended);
        assert_eq!(
            h.pool.zfs.guid(&before.data_dataset()).await.unwrap(),
            data_guid
        );
        let current: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
        current.check().unwrap();
        assert_eq!(current.reference.sequence, 1);
        assert!(current.previous_run_sha256.is_none());
        assert!(current
            .consumed_update
            .as_ref()
            .unwrap()
            .creation_source
            .is_some());
    }
}

#[tokio::test]
async fn creation_update_refuses_mixed_tampered_and_missing_authority() {
    let (h, entry) = stopped(false).await;
    let id = entry.snapshot().id;
    h.m.update(&id, patch(None, BTreeMap::new(), None), None)
        .await
        .unwrap();
    let update: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
    let value = serde_json::to_value(&update).unwrap();
    let mutations = [
        ("schema", serde_json::json!(1)),
        ("source_current_sha256", serde_json::json!("a".repeat(64))),
        ("creation_source", serde_json::Value::Null),
    ];
    for (field, changed) in mutations {
        let mut tampered = value.clone();
        tampered[field] = changed;
        let tampered: UpdateIntent = serde_json::from_value(tampered).unwrap();
        assert!(tampered.check_shape().is_err(), "mixed source {field}");
    }
    for field in ["pid", "env", "namespace", "clone_origin"] {
        let mut tampered = value.clone();
        match field {
            "pid" => tampered["source_record"][field] = serde_json::json!(99),
            "env" => tampered["source_record"][field] = serde_json::json!({"INJECTED":"value"}),
            "namespace" => tampered["source_record"][field] = serde_json::json!("other"),
            _ => tampered["source_record"][field]["mapping_exited"] = serde_json::json!(false),
        }
        let tampered: UpdateIntent = serde_json::from_value(tampered).unwrap();
        assert!(tampered.check_shape().is_err(), "tampered original {field}");
    }
    let mut tampered = update.clone();
    tampered
        .source_record
        .clone_origin
        .as_mut()
        .unwrap()
        .sandbox
        .as_mut()
        .unwrap()
        .ack_sha256 = Some("a".repeat(64));
    assert!(tampered.check_shape().is_err());
    let mut tampered = update.clone();
    tampered.creation_source.as_mut().unwrap().reader.namespace = "other".into();
    assert!(tampered.check_shape().is_err());
    let mut tampered = update.clone();
    tampered
        .creation_source
        .as_mut()
        .unwrap()
        .receipt
        .create_sha256 = "a".repeat(64);
    assert!(tampered.check_shape().is_err());
    let mut tampered = update.clone();
    tampered.creation_source.as_mut().unwrap().root.guid += 1;
    assert!(h.m.check_creation_update_backing(&tampered).await.is_err());
    let mut tampered = update.clone();
    tampered
        .creation_source
        .as_mut()
        .unwrap()
        .data
        .as_mut()
        .unwrap()
        .guid += 1;
    assert!(h.m.check_creation_update_backing(&tampered).await.is_err());
    let creation = update.creation_source.as_ref().unwrap();
    for (kind, key) in [
        (super::super::super::REQUESTS, creation.receipt.key()),
        (templates::READERS, id.clone()),
        ("launch-holds", id.clone()),
    ] {
        let original: serde_json::Value = h.m.inner.store.get(kind, &key).unwrap().unwrap();
        h.m.inner.store.delete_durable(kind, &key).unwrap();
        assert!(h.m.check_update_source(&update).is_err(), "missing {kind}");
        h.m.inner.store.put_durable(kind, &key, &original).unwrap();
        h.m.check_update_source(&update).unwrap();
    }
}

#[tokio::test]
async fn creation_update_coalesces_clears_cancels_and_repairs_uncertain_writes() {
    let (h, entry) = stopped(false).await;
    let before = entry.snapshot();
    let id = before.id.clone();
    h.m.update(
        &id,
        patch(None, BTreeMap::from([("NEW".into(), "first".into())]), None),
        None,
    )
    .await
    .unwrap();
    let first: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
    let blocked =
        h.m.inner
            .store
            .dir("machines")
            .join(format!("{id}.json.tmp"));
    std::fs::create_dir(&blocked).unwrap();
    assert!(h
        .m
        .update(&id, patch(None, BTreeMap::new(), None), None)
        .await
        .is_err());
    let outstanding: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
    assert_eq!(
        outstanding.source_digest().unwrap(),
        first.source_digest().unwrap()
    );
    assert!(h
        .m
        .update(&id, patch(None, before.env.clone(), None), None)
        .await
        .is_err());
    let retained: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
    assert_eq!(retained.digest().unwrap(), outstanding.digest().unwrap());
    std::fs::remove_dir(blocked).unwrap();
    full_startup(&h).await.unwrap();
    assert_eq!(
        h.m.entry(&id)
            .unwrap()
            .snapshot()
            .pending
            .as_ref()
            .unwrap()
            .env,
        Some(BTreeMap::new())
    );
    h.m.update(&id, patch(None, before.env.clone(), None), None)
        .await
        .unwrap();
    full_startup(&h).await.unwrap();
    assert!(h.m.entry(&id).unwrap().snapshot().pending.is_none());
    h.m.start(&id, None).await.unwrap();
    assert_eq!(h.m.entry(&id).unwrap().snapshot().env, before.env);
    let current: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
    assert_eq!(current.reference.sequence, 1);
    assert!(current.previous_run_sha256.is_none());
}

#[tokio::test]
async fn creation_env_only_suspension_consumes_fresh_without_changing_disks() {
    for env in [
        BTreeMap::from([("NEW".into(), "fresh".into())]),
        BTreeMap::new(),
    ] {
        let (h, entry) = stopped(true).await;
        let before = entry.snapshot();
        assert!(before.suspended);
        let id = before.id.clone();
        let root = h.pool.zfs.guid(&before.root_dataset()).await.unwrap();
        let data = h.pool.zfs.guid(&before.data_dataset()).await.unwrap();
        h.m.update(&id, patch(None, env.clone(), None), None)
            .await
            .unwrap();
        full_startup(&h).await.unwrap();
        tokio::time::timeout(Duration::from_secs(60), h.m.start(&id, None))
            .await
            .unwrap()
            .unwrap();
        let applied = h.m.entry(&id).unwrap().snapshot();
        assert_eq!(applied.env, env);
        assert!(!applied.suspended);
        assert_eq!(h.pool.zfs.guid(&before.root_dataset()).await.unwrap(), root);
        assert_eq!(h.pool.zfs.guid(&before.data_dataset()).await.unwrap(), data);
        let current: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
        let Mode::Fresh { drive_base64, .. } = &current.mode else {
            panic!("fresh config required")
        };
        let (config, _) = model::parse_drive(&guest::base64_decode(drive_base64).unwrap()).unwrap();
        assert_eq!(config.env, env);
    }
}

#[tokio::test]
async fn initial_running_assignment_refuses_spec_before_writing_pending() {
    let (h, entry, request) = super::super::super::tests::fixture().await;
    let digest = templates::sandbox::request_digest(&request).unwrap();
    h.m.stage_destination_assignment(request, &entry, 2)
        .await
        .unwrap();
    h.m.start_destination_assignment("destination", "assignment-one", &digest)
        .await
        .unwrap();
    let before = entry.snapshot();
    assert_eq!(before.state, state::RUNNING);
    assert!(before.assigned_run.is_none());
    let request: api::UpdateMachineRequest =
        serde_json::from_value(serde_json::json!({"image":"alpine:replacement", "env":{}}))
            .unwrap();
    assert!(h.m.update(&before.id, request, None).await.is_err());
    assert_eq!(
        serde_json::to_value(entry.snapshot()).unwrap(),
        serde_json::to_value(&before).unwrap()
    );
    assert!(h
        .m
        .inner
        .store
        .get::<UpdateIntent>(UPDATES, &before.id)
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn legacy_settled_update_keeps_exact_field_order_bytes_and_digest() {
    // Independent declaration of the schema-1 update wire before creation authority.
    #[derive(Serialize)]
    struct LegacyUpdate<'a> {
        schema: u8,
        machine: &'a str,
        source_current_sha256: &'a str,
        source_record: &'a Record,
        change: &'a api::SpecChange,
        disk_limits: &'a Option<api::DiskLimits>,
        target: &'a Record,
        #[serde(skip_serializing_if = "Option::is_none")]
        predecessor_target: &'a Option<Box<Record>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        resolved_image: &'a Option<crate::image::Image>,
        #[serde(skip_serializing_if = "Option::is_none")]
        root_swap: &'a Option<RootSwap>,
    }
    let (h, entry) = settled_run(false).await;
    let id = entry.snapshot().id;
    h.m.update(&id, patch(None, BTreeMap::new(), None), None)
        .await
        .unwrap();
    let update: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
    assert_eq!(update.schema, 1);
    let old = LegacyUpdate {
        schema: 1,
        machine: &update.machine,
        source_current_sha256: update.source_current_sha256.as_deref().unwrap(),
        source_record: &update.source_record,
        change: &update.change,
        disk_limits: &update.disk_limits,
        target: &update.target,
        predecessor_target: &update.predecessor_target,
        resolved_image: &update.resolved_image,
        root_swap: &update.root_swap,
    };
    let old = serde_json::to_vec(&old).unwrap();
    assert_eq!(serde_json::to_vec(&update).unwrap(), old);
    assert_eq!(update.digest().unwrap(), sha(&old));
}

mod recovery_boundaries;
