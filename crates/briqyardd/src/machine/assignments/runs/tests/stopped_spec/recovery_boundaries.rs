//! Durable boundary fixtures model interrupted writes; they confer no live ownership.
use super::*;

fn assert_no_launch_or_adoption(calls: &[String]) {
    assert!(!calls.iter().any(|call| [
        "boot ",
        "kill ",
        "settle-clone ",
        "assigned_resume ",
        "resume ",
        "resume-paused ",
        "activate_quarantined ",
        "exec ",
        "count ",
        "adopt ",
        "adopt-state ",
        "ping ",
    ]
    .iter()
    .any(|prefix| call.starts_with(prefix))));
}

#[tokio::test]
async fn creation_image_swap_full_startup_recovers_each_durable_boundary() {
    for boundary in 0..5 {
        let (h, entry) = stopped(false).await;
        let before = entry.snapshot();
        let id = before.id.clone();
        let data_guid = h.pool.zfs.guid(&before.data_dataset()).await.unwrap();
        let image = format!("alpine@sha256:{}", "8".repeat(64));
        h.m.inner
            .images
            .seed(&image, crate::image::ImageConfig::default())
            .await
            .unwrap();
        let env = BTreeMap::from([("REPLACEMENT".into(), "swap".into())]);
        h.m.update(&id, patch(Some(image.clone()), env.clone(), None), None)
            .await
            .unwrap();
        h.m.ensure_entry_assigned_update_backing(&entry)
            .await
            .unwrap();
        let mut update: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
        let root = before.root_dataset();
        let next = format!("{root}.next");
        let resolved = h.m.inner.images.ensure(&image).await.unwrap();
        let source_guid = h.pool.zfs.guid(&root).await.unwrap();
        assert_eq!(
            update.creation_source.as_ref().unwrap().root.guid,
            source_guid
        );
        let suffix = sha(format!(
            "{}:{}:{}",
            update.source_digest().unwrap(),
            resolved.key,
            source_guid
        )
        .as_bytes());
        let retired = format!("{}/root.u_{}", before.dataset(), &suffix[..24]);
        update.resolved_image = Some(resolved.clone());
        update.root_swap = Some(RootSwap {
            source_guid,
            target_guid: None,
            retired_dataset: retired.clone(),
        });
        h.m.check_update_source(&update).unwrap();
        h.m.inner.store.put_durable(UPDATES, &id, &update).unwrap();
        let target_guid = if boundary >= 1 {
            h.pool
                .zfs
                .clone_snapshot(&resolved.dataset(), crate::image::SNAP, &next)
                .await
                .unwrap();
            Some(h.pool.zfs.guid(&next).await.unwrap())
        } else {
            None
        };
        if boundary >= 2 {
            update.root_swap.as_mut().unwrap().target_guid = target_guid;
            h.m.inner.store.put_durable(UPDATES, &id, &update).unwrap();
        }
        if boundary >= 3 {
            h.pool.zfs.rename(&root, &retired).await.unwrap();
        }
        if boundary >= 4 {
            h.pool.zfs.rename(&next, &root).await.unwrap();
        }
        let image_calls = h.m.inner.images.ensure_calls.load(Relaxed);
        // A reboot must also preserve the pending creation authority without adoption.
        h.set_host_boot_id(Some("22222222-2222-4222-8222-222222222222"));
        h.host_calls();
        full_startup(&h).await.unwrap();
        assert_eq!(h.m.inner.images.ensure_calls.load(Relaxed), image_calls);
        assert_no_launch_or_adoption(&h.host_calls());
        let recovered = h.m.entry(&id).unwrap();
        assert_eq!(recovered.snapshot().state, state::STOPPED);
        assert_eq!(recovered.snapshot().launch_identity, before.launch_identity);
        assert!(recovered.live.lock().unwrap().is_none());
        assert!(h.m.inner.store.get::<Current>(RUNS, &id).unwrap().is_none());
        assert_eq!(
            h.pool.zfs.guid(&before.data_dataset()).await.unwrap(),
            data_guid
        );
        let pending: UpdateIntent = h.m.inner.store.get(UPDATES, &id).unwrap().unwrap();
        assert_eq!(
            pending.creation_source.as_ref().unwrap().root.guid,
            source_guid
        );
        assert_eq!(pending.root_swap.as_ref().unwrap().source_guid, source_guid);
        if boundary <= 1 {
            assert_eq!(h.pool.zfs.guid(&root).await.unwrap(), source_guid);
            assert_eq!(h.pool.zfs.exists(&next).await.unwrap(), boundary == 1);
            assert!(pending.root_swap.as_ref().unwrap().target_guid.is_none());
        } else {
            assert_eq!(h.pool.zfs.guid(&root).await.unwrap(), target_guid.unwrap());
            assert_eq!(h.pool.zfs.guid(&retired).await.unwrap(), source_guid);
            assert!(!h.pool.zfs.exists(&next).await.unwrap());
        }
        full_startup(&h).await.unwrap();
        tokio::time::timeout(Duration::from_secs(60), h.m.start(&id, None))
            .await
            .unwrap()
            .unwrap();
        let current: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
        current.check().unwrap();
        assert_eq!(current.reference.sequence, 1);
        assert!(current.previous_run_sha256.is_none());
        assert_eq!(
            before.boot_incarnation.as_ref().unwrap().host_boot_id,
            "11111111-1111-4111-8111-111111111111"
        );
        assert_eq!(
            h.m.entry(&id)
                .unwrap()
                .live
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .incarnation
                .as_ref()
                .unwrap()
                .host_boot_id,
            "22222222-2222-4222-8222-222222222222"
        );
        assert_eq!(current.host_boot_id, "22222222-2222-4222-8222-222222222222");
        assert_eq!(
            current
                .target
                .boot_incarnation
                .as_ref()
                .unwrap()
                .host_boot_id,
            current.host_boot_id
        );
        assert_eq!(
            current
                .consumed_update
                .as_ref()
                .unwrap()
                .source_record
                .boot_incarnation,
            before.boot_incarnation
        );
        assert_eq!(h.m.entry(&id).unwrap().snapshot().env, env);
        assert_eq!(
            h.pool.zfs.guid(&before.data_dataset()).await.unwrap(),
            data_guid
        );
        let installed = h.pool.zfs.guid(&root).await.unwrap();
        assert_ne!(installed, source_guid);
        if let Some(target_guid) = target_guid {
            assert_eq!(installed, target_guid);
        }
    }
}

#[tokio::test]
async fn creation_first_consumption_full_startup_repairs_each_write_and_delete_boundary() {
    for boundary in 0..6 {
        let (h, entry) = stopped(false).await;
        let before = entry.snapshot();
        let id = before.id.clone();
        let root_guid = h.pool.zfs.guid(&before.root_dataset()).await.unwrap();
        let data_guid = h.pool.zfs.guid(&before.data_dataset()).await.unwrap();
        let env = BTreeMap::from([("REPLACEMENT".into(), "consumed".into())]);
        h.m.update(&id, patch(None, env.clone(), None), None)
            .await
            .unwrap();
        let intent = h.m.plan_assigned_run(&entry, false).await.unwrap();
        assert!(intent.predecessor.is_none());
        assert_eq!(intent.current.reference.sequence, 1);
        assert!(intent.current.previous_run_sha256.is_none());
        assert!(intent
            .current
            .consumed_update
            .as_ref()
            .unwrap()
            .creation_source
            .is_some());
        h.m.inner.store.put_durable(INTENTS, &id, &intent).unwrap();
        if boundary >= 1 {
            h.m.inner
                .store
                .put_durable(RUNS, &id, &intent.current)
                .unwrap();
        }
        if boundary >= 2 {
            h.m.inner
                .store
                .put_durable("machines", &id, &intent.current.target)
                .unwrap();
        }
        if boundary >= 3 {
            h.m.inner
                .store
                .put_durable(READERS, &id, &intent.reader)
                .unwrap();
        }
        if boundary >= 4 {
            h.m.inner.store.delete_durable(UPDATES, &id).unwrap();
        }
        if boundary >= 5 {
            h.m.inner.store.delete_durable(INTENTS, &id).unwrap();
        }
        let expected_hash = intent.current.authority_sha256().unwrap();
        let image_calls = h.m.inner.images.ensure_calls.load(Relaxed);
        h.host_calls();
        for _ in 0..2 {
            full_startup(&h).await.unwrap();
            let current: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
            current.check().unwrap();
            assert_eq!(current.authority_sha256().unwrap(), expected_hash);
            let reader: Reader = h.m.inner.store.get(READERS, &id).unwrap().unwrap();
            assert_eq!(
                serde_json::to_value(reader).unwrap(),
                serde_json::to_value(&intent.reader).unwrap()
            );
            let recovered = h.m.entry(&id).unwrap();
            assert_eq!(recovered.snapshot().env, env);
            assert_eq!(recovered.snapshot().launch_identity, before.launch_identity);
            assert!(recovered.live.lock().unwrap().is_none());
            assert!(!recovered.identity_trusted.load(Relaxed));
            assert!(h.m.reserve_assigned_run(&recovered, false).await.is_err());
            assert!(h
                .m
                .inner
                .store
                .get::<UpdateIntent>(UPDATES, &id)
                .unwrap()
                .is_none());
            assert!(h
                .m
                .inner
                .store
                .get::<Intent>(INTENTS, &id)
                .unwrap()
                .is_none());
            assert_eq!(
                h.pool.zfs.guid(&before.root_dataset()).await.unwrap(),
                root_guid
            );
            assert_eq!(
                h.pool.zfs.guid(&before.data_dataset()).await.unwrap(),
                data_guid
            );
        }
        assert_eq!(h.m.inner.images.ensure_calls.load(Relaxed), image_calls);
        // Reserved recovery may quarantine forwarding; it must never adopt or launch.
        assert_no_launch_or_adoption(&h.host_calls());
    }
}
