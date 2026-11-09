//! Stopped workload updates reuse the assigned run's durable authority and backing.
use super::*;

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

#[tokio::test]
async fn stopped_image_env_replacement_keeps_identity_volume_and_waits_for_start() {
    for resource in 0..3 {
        let (h, entry) = stopped(true).await;
        let before = entry.snapshot();
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
        assert_eq!(
            serde_json::to_value(&pending.endpoints).unwrap(),
            serde_json::to_value(&before.endpoints).unwrap()
        );
        assert_eq!(pending.pending.as_ref().unwrap().env, Some(env.clone()));
        let intent: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
        intent.check(&run).unwrap();
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
        assert_eq!(
            serde_json::to_value(&applied.endpoints).unwrap(),
            serde_json::to_value(&before.endpoints).unwrap()
        );
        assert_eq!(h.pool.zfs.guid(&data).await.unwrap(), data_guid);
    }
}

#[tokio::test]
async fn stopped_env_coalescing_clear_cancel_and_uncertain_write_recover() {
    let (h, entry) = stopped(false).await;
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
    let (h, entry) = stopped(false).await;
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
