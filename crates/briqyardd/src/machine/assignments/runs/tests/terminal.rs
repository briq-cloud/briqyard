use super::super::terminal::Disposition;
use super::*;

#[tokio::test]
async fn exact_settlement_releases_only_after_journal_and_next_sequence_reserves_again() {
    let (h, entry) = stopped(false).await;
    let identity = entry.snapshot().launch_identity;
    for sequence in 1..=3 {
        h.m.launch_assigned_run(&entry, false).await.unwrap();
        let live = entry.live.lock().unwrap().clone().unwrap();
        assert_eq!(
            entry.snapshot().assigned_run.as_ref().unwrap().sequence,
            sequence
        );
        assert!(
            h.m.settle_assigned_run(&entry, Disposition::Stopped)
                .await
                .is_err(),
            "live process cannot settle"
        );
        {
            let mut record = entry.rec.lock().unwrap();
            record.init_version = "latest guest version observation".into();
            record.version += 4;
            record.updated_at += chrono::Duration::seconds(2);
            record.state = state::RUNNING.into();
        }
        h.m.save(&entry).unwrap();
        let latest = entry.snapshot();
        h.m.inner.vmm.kill(live.pid);
        h.m.settle_assigned_run(&entry, Disposition::Stopped)
            .await
            .unwrap();
        let terminal: Current = h.m.inner.store.get(RUNS, &latest.id).unwrap().unwrap();
        terminal.check().unwrap();
        assert_eq!(terminal.reference.phase, Phase::Settled);
        assert_eq!(entry.snapshot().pid, 0);
        assert_eq!(entry.snapshot().version, latest.version);
        assert_eq!(entry.snapshot().updated_at, latest.updated_at);
        assert_eq!(entry.snapshot().init_version, latest.init_version);
        assert_eq!(entry.snapshot().launch_identity, identity);
        assert_eq!(h.m.quota("destination").unwrap().used.memory_mb, 0);
        assert_eq!(h.m.quota("destination").unwrap().used.cpu_millis(), 0);
        let next = h.m.plan_assigned_run(&entry, false).await.unwrap();
        assert_eq!(
            next.current.previous_run_sha256.as_ref(),
            Some(&terminal.authority_sha256().unwrap())
        );
        assert_eq!(next.current.reference.sequence, sequence + 1);
        assert_ne!(next.current.host_generation, terminal.host_generation);
    }
}

#[tokio::test]
async fn current_checkpoint_preserves_assigned_or_creation_lineage_across_next_sequence() {
    for creation in [false, true] {
        let (h, entry) = stopped(creation).await;
        h.m.launch_assigned_run(&entry, creation).await.unwrap();
        let observed: Current =
            h.m.inner
                .store
                .get(RUNS, &entry.snapshot().id)
                .unwrap()
                .unwrap();
        h.m.settle_assigned_run(&entry, Disposition::CheckpointAvailable)
            .await
            .unwrap();
        assert_eq!(h.m.quota("destination").unwrap().used.memory_mb, 0);
        let terminal: Current =
            h.m.inner
                .store
                .get(RUNS, &entry.snapshot().id)
                .unwrap()
                .unwrap();
        let mut changed = serde_json::to_value(&terminal).unwrap();
        changed["settlement"]["checkpoint"]["config"]["sha256"] = "f".repeat(64).into();
        assert!(
            serde_json::from_value::<Current>(changed)
                .unwrap()
                .check()
                .is_err(),
            "terminal checkpoint cannot substitute config while retaining observed lineage"
        );
        h.m.launch_assigned_run(&entry, true).await.unwrap();
        let resumed: Current =
            h.m.inner
                .store
                .get(RUNS, &entry.snapshot().id)
                .unwrap()
                .unwrap();
        assert_eq!(resumed.reference.sequence, 2);
        let Mode::Checkpoint {
            assigned_lineage,
            saved_generation,
            saved_marker,
            ..
        } = &resumed.mode
        else {
            panic!("checkpoint required")
        };
        if creation {
            assert!(assigned_lineage.is_none());
            assert_eq!(
                saved_generation,
                &observed
                    .prior
                    .clone_origin
                    .as_ref()
                    .unwrap()
                    .configure
                    .generation
            );
            assert!(resumed.observed_checkpoint.is_some());
        } else {
            let proof = observed.observed_guest.as_ref().unwrap();
            assert_eq!(assigned_lineage.as_deref(), Some(proof));
            assert_eq!(saved_generation, &proof.generation);
            assert_eq!(saved_marker, &proof.boot_marker);
            assert_eq!(resumed.observed_guest.as_ref(), Some(proof));
            assert!(resumed.observed_checkpoint.is_none());
        }
        assert_eq!(
            h.m.quota("destination").unwrap().used.memory_mb,
            resumed.target.size.memory_mb
        );
        assert!(!entry.identity_trusted.load(Relaxed));
    }
}

#[tokio::test]
async fn uncertain_terminal_write_retains_cache_charge_and_forbids_sequence_admission() {
    let (h, entry) = stopped(false).await;
    h.m.launch_assigned_run(&entry, false).await.unwrap();
    let live = entry.live.lock().unwrap().clone().unwrap();
    h.m.inner.vmm.kill(live.pid);
    let directory = h.m.inner.store.dir(INTENTS);
    std::fs::remove_dir(&directory).unwrap();
    assert!(h
        .m
        .settle_assigned_run(&entry, Disposition::Failed)
        .await
        .is_err());
    assert_eq!(
        entry.snapshot().assigned_run.unwrap().phase,
        Phase::Observed
    );
    assert_eq!(
        h.m.quota("destination").unwrap().used.memory_mb,
        entry.snapshot().size.memory_mb
    );
    assert!(h.m.plan_assigned_run(&entry, false).await.is_err());
    std::fs::create_dir(directory).unwrap();
    h.m.settle_assigned_run(&entry, Disposition::Failed)
        .await
        .unwrap();
    assert_eq!(h.m.quota("destination").unwrap().used.memory_mb, 0);
}

#[tokio::test]
async fn changed_valid_host_boot_is_exit_only_and_unknown_process_absence_is_not_exit() {
    let (h, entry) = stopped(false).await;
    h.m.launch_assigned_run(&entry, false).await.unwrap();
    *entry.live.lock().unwrap() = None;
    assert!(h
        .m
        .settle_assigned_run(&entry, Disposition::Stopped)
        .await
        .is_err());
    h.set_host_boot_id(None);
    assert!(h
        .m
        .settle_assigned_run(&entry, Disposition::Stopped)
        .await
        .is_err());
    assert!(commits_memory(&entry.snapshot()));
    h.set_host_boot_id(Some("22222222-2222-4222-8222-222222222222"));
    h.m.settle_assigned_run(&entry, Disposition::Stopped)
        .await
        .unwrap();
    assert!(!commits_memory(&entry.snapshot()));
    assert!(h.m.adopt_observed_assigned_run(&entry).await.is_err());
}

#[tokio::test]
async fn settlement_interruption_repairs_before_admission_and_preserves_latest_advisories() {
    for boundary in 0..4 {
        let (h, entry) = stopped(false).await;
        h.m.launch_assigned_run(&entry, false).await.unwrap();
        let id = entry.snapshot().id;
        let observed: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
        h.m.inner.vmm.kill(entry.snapshot().pid);
        h.m.settle_assigned_run(&entry, Disposition::Stopped)
            .await
            .unwrap();
        let settled: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
        let intent = Intent {
            schema: 3,
            reader: settled.reader().unwrap(),
            current: settled.clone(),
            predecessor: Some(observed.clone()),
        };
        intent.check().unwrap();
        let mut latest = observed.target.clone();
        latest.version += 33;
        latest.init_version = "latest post-intent advisory".into();
        h.m.inner.store.put_durable(RUNS, &id, &observed).unwrap();
        h.m.inner
            .store
            .put_durable("machines", &id, &latest)
            .unwrap();
        h.m.inner
            .store
            .put_durable(READERS, &id, &observed.reader().unwrap())
            .unwrap();
        h.m.inner.store.put_durable(INTENTS, &id, &intent).unwrap();
        if boundary >= 1 {
            h.m.inner.store.put_durable(RUNS, &id, &settled).unwrap();
        }
        if boundary >= 2 {
            h.m.inner
                .store
                .put_durable(
                    "machines",
                    &id,
                    &projection::preserve_advisory(&settled.target, &latest).unwrap(),
                )
                .unwrap();
        }
        if boundary >= 3 {
            h.m.inner
                .store
                .put_durable(READERS, &id, &intent.reader)
                .unwrap();
        }
        *entry.rec.lock().unwrap() = latest.as_ref().clone();
        assert!(
            commits_memory(&entry.snapshot()),
            "cache stays charged through uncertain terminal publication"
        );
        assert!(h.m.plan_assigned_run(&entry, false).await.is_err());
        h.host_calls();
        restart(&h).unwrap();
        let repaired = h.m.entry(&id).unwrap();
        assert_eq!(repaired.snapshot().version, latest.version);
        assert_eq!(repaired.snapshot().init_version, latest.init_version);
        assert_eq!(
            repaired.snapshot().assigned_run.unwrap().phase,
            Phase::Settled
        );
        assert_eq!(h.m.quota("destination").unwrap().used.memory_mb, 0);
        assert!(h.m.inner.store.list::<Intent>(INTENTS).unwrap().is_empty());
        h.m.plan_assigned_run(&repaired, false).await.unwrap();
        assert!(h.host_calls().is_empty());
    }
}

#[tokio::test]
async fn settled_next_sequence_rechecks_quota_pending_updates_and_current_disks() {
    let (h, entry) = stopped(false).await;
    h.m.launch_assigned_run(&entry, false).await.unwrap();
    h.m.inner.vmm.kill(entry.snapshot().pid);
    h.m.settle_assigned_run(&entry, Disposition::Stopped)
        .await
        .unwrap();
    entry.rec.lock().unwrap().pending = Some(api::SpecChange {
        cmd: Some(vec!["pending".into()]),
        ..Default::default()
    });
    assert!(h.m.reserve_assigned_run(&entry, false).await.is_err());
    assert!(entry.snapshot().pending.is_some());
    entry.rec.lock().unwrap().pending = None;
    let old_quota =
        h.m.inner
            .namespaces
            .lock()
            .unwrap()
            .get("destination")
            .unwrap()
            .rec
            .quota;
    h.m.inner
        .namespaces
        .lock()
        .unwrap()
        .get_mut("destination")
        .unwrap()
        .rec
        .quota
        .memory_mb = Some(0);
    assert!(h.m.reserve_assigned_run(&entry, false).await.is_err());
    assert_eq!(entry.snapshot().assigned_run.unwrap().phase, Phase::Settled);
    assert_eq!(h.m.quota("destination").unwrap().used.memory_mb, 0);
    h.m.inner
        .namespaces
        .lock()
        .unwrap()
        .get_mut("destination")
        .unwrap()
        .rec
        .quota = old_quota;
    let root = entry.snapshot().root_dataset();
    h.pool.zfs.destroy(&root).await.unwrap();
    h.pool.zfs.create(&root, 1 << 20).await.unwrap();
    assert!(h.m.reserve_assigned_run(&entry, false).await.is_err());
    assert_eq!(entry.snapshot().assigned_run.unwrap().phase, Phase::Settled);
}

#[tokio::test]
async fn legacy_schema1_observation_upgrades_to_terminal_without_relabeling_creation_history() {
    let (h, entry) = stopped(false).await;
    h.m.launch_assigned_run(&entry, false).await.unwrap();
    let id = entry.snapshot().id;
    let mut legacy: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
    legacy.schema = 1;
    legacy.reference.schema = 1;
    legacy.target.assigned_run = Some(legacy.reference.clone());
    legacy.prior_control_sha256 = launch_identity::record_fingerprint(&legacy.prior).unwrap();
    legacy.check().unwrap();
    h.m.inner.store.put_durable(RUNS, &id, &legacy).unwrap();
    h.m.inner
        .store
        .put_durable("machines", &id, &legacy.target)
        .unwrap();
    h.m.inner
        .store
        .put_durable(READERS, &id, &legacy.reader().unwrap())
        .unwrap();
    *entry.rec.lock().unwrap() = legacy.target.as_ref().clone();
    h.m.inner.vmm.kill(legacy.target.pid);
    h.m.settle_assigned_run(&entry, Disposition::Stopped)
        .await
        .unwrap();
    let settled: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
    settled.check().unwrap();
    assert_eq!(settled.schema, 3);
    assert_eq!(settled.reference.phase, Phase::Settled);
    assert_eq!(
        settled.target.launch_identity,
        legacy.target.launch_identity
    );
    assert_eq!(settled.receipt, legacy.receipt);
    assert_eq!(settled.creation_reader, legacy.creation_reader);
    assert_eq!(h.m.quota("destination").unwrap().used.memory_mb, 0);
}
