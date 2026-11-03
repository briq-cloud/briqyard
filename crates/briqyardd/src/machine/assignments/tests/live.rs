use super::*;

async fn second_slot(h: &crate::machine::tests::Harness, first: &Entry) -> Arc<Entry> {
    let mut record = first.snapshot();
    record.id = "m_second".into();
    record.name = "second".into();
    record.host_num = 4;
    record.ip = "10.64.1.4".into();
    record.pid = 0;
    record.boot_incarnation = None;
    record.launch_identity = None;
    record.state = state::CREATING.into();
    let origin = record.clone_origin.as_mut().unwrap();
    origin.stage = templates::CloneStage::Reserved;
    origin.configure.ip = "10.64.1.4/24".into();
    origin.configure.mac = templates::clone_mac(&record.ip).unwrap();
    let reader = templates::CloneReader {
        source_machine: origin.source_machine.clone(),
        snapshot: origin.snapshot.clone(),
        generation: origin.artifact.generation.clone(),
        destination: record.id.clone(),
        namespace: record.namespace.clone(),
        stage: templates::CloneStage::Reserved,
    };
    h.m.inner
        .store
        .put_durable(templates::READERS, &record.id, &reader)
        .unwrap();
    let entry = Entry::new(record, h.m.inner.events.clone());
    h.m.pin_launch_identity(&entry).unwrap();
    h.m.inner
        .machines
        .lock()
        .unwrap()
        .insert(entry.snapshot().id, entry.clone());
    h.disks(&entry).await;
    {
        let _turn = entry.lock.lock().await;
        h.m.start_entry(&entry, true).await.unwrap();
    }
    entry
}

fn quota_for(charge: &api::QuotaUse, dimension: u8) -> api::Quota {
    match dimension {
        0 => api::Quota {
            machines: Some(charge.machines),
            ..Default::default()
        },
        1 => api::Quota {
            memory_mb: Some(charge.memory_mb),
            ..Default::default()
        },
        2 => api::Quota {
            cpu_millis: Some(charge.cpu_millis()),
            ..Default::default()
        },
        _ => api::Quota {
            disk_gb: Some(charge.disk_gb),
            ..Default::default()
        },
    }
}

#[tokio::test]
async fn pending_assignment_blocks_every_quota_dimension_for_ordinary_admission() {
    for dimension in 0..4 {
        let (h, entry, request) = fixture().await;
        let charge = quota_need(&entry.snapshot(), true);
        h.m.set_quota("destination", quota_for(&charge, dimension))
            .await
            .unwrap();
        h.m.stage_destination_assignment(request, &entry, 2)
            .await
            .unwrap();
        let used = h.m.quota("destination").unwrap().used;
        assert_eq!(used.machines, 1);
        assert_eq!(used.memory_mb, charge.memory_mb);
        assert_eq!(used.cpu_millis(), charge.cpu_millis());
        assert_eq!(used.disk_gb, charge.disk_gb);
        assert_eq!(h.m.quota("t1").unwrap().used.disk_gb, 0);
        let mut ordinary = h.request("competing");
        ordinary.namespace = "destination".into();
        ordinary.volume = entry.snapshot().volume;
        ordinary.start = Some(true);
        assert!(
            matches!(h.m.record(ordinary, None).await, Err(MError::Quota(_))),
            "dimension {dimension}"
        );
    }
}

#[tokio::test]
async fn pending_name_address_and_namespace_remain_reserved_after_uncertain_intent_write() {
    for uncertain in [false, true] {
        let (h, entry, request) = fixture().await;
        let directory = h.m.inner.store.dir(INTENTS);
        if uncertain {
            std::fs::remove_dir(&directory).unwrap();
        }
        let result =
            h.m.stage_destination_assignment(request.clone(), &entry, 2)
                .await;
        assert_eq!(result.is_err(), uncertain);
        let mut ordinary = h.request(&request.name);
        ordinary.namespace = "destination".into();
        assert!(matches!(
            h.m.record(ordinary.clone(), None).await,
            Err(MError::Conflict(_))
        ));
        ordinary.name = "another".into();
        let (created, _) = h.m.record(ordinary, None).await.unwrap();
        assert_eq!(created.snapshot().host_num, 3);
        // With its ordinary competitor removed, the pending assignment alone prevents delete.
        h.m.inner
            .machines
            .lock()
            .unwrap()
            .remove(&created.snapshot().id);
        h.m.inner
            .store
            .delete("machines", &created.snapshot().id)
            .unwrap();
        assert!(matches!(
            h.m.delete_namespace("destination").await,
            Err(MError::NamespaceInUse)
        ));
        assert!(h
            .m
            .held_addresses(entry.snapshot().subnet_index)
            .contains(&3));
        assert!(h.m.held_addresses(2).contains(&2));
        if uncertain {
            std::fs::create_dir(directory).unwrap();
            let digest = templates::sandbox::request_digest(&request).unwrap();
            assert!(h
                .m
                .commit_destination_assignment("destination", "assignment-one", &digest)
                .await
                .is_err());
            assert!(h
                .m
                .destination_assignment_pending(&entry.snapshot().id)
                .unwrap());
        }
    }
}

#[tokio::test]
async fn concurrent_pending_assignments_cannot_share_quota_name_or_address() {
    for conflict in 0..3 {
        let (h, first, request) = fixture().await;
        let second = second_slot(&h, &first).await;
        if conflict == 0 {
            h.m.set_quota(
                "destination",
                api::Quota {
                    machines: Some(1),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        }
        let mut other = request.clone();
        other.sandbox_seed.as_mut().unwrap().request_id = "assignment-two".into();
        if conflict != 1 {
            other.name = "other".into();
        }
        let host = if conflict == 2 { 2 } else { 3 };
        let gate = h.m.inner.warm_lock.lock().await;
        let ready = Arc::new(tokio::sync::Barrier::new(3));
        let manager = h.m.clone();
        let start = ready.clone();
        let a = tokio::spawn(async move {
            start.wait().await;
            manager
                .stage_destination_assignment(request, &first, 2)
                .await
        });
        let manager = h.m.clone();
        let start = ready.clone();
        let b = tokio::spawn(async move {
            start.wait().await;
            manager
                .stage_destination_assignment(other, &second, host)
                .await
        });
        ready.wait().await;
        drop(gate);
        let (a, b) = tokio::time::timeout(Duration::from_secs(3), async {
            (a.await.unwrap(), b.await.unwrap())
        })
        .await
        .unwrap();
        assert_eq!(
            usize::from(a.is_ok()) + usize::from(b.is_ok()),
            1,
            "conflict {conflict}"
        );
        assert_eq!(
            h.m.inner
                .store
                .list::<model::Intent>(INTENTS)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(h.m.quota("destination").unwrap().used.machines, 1);
    }
}

#[tokio::test]
async fn live_transfer_preserves_entry_process_backing_and_exact_replay_at_each_durable_boundary() {
    for boundary in 0..4 {
        let (h, entry, request) = fixture().await;
        let before = entry.snapshot();
        let physical = committed(&h.m.inner.machines.lock().unwrap()).0;
        let live = entry.live.lock().unwrap().clone().unwrap();
        h.m.stage_destination_assignment(request.clone(), &entry, 2)
            .await
            .unwrap();
        let intent: model::Intent =
            h.m.inner
                .store
                .get(INTENTS, &key("destination", "assignment-one"))
                .unwrap()
                .unwrap();
        if boundary >= 1 {
            h.m.inner
                .store
                .put_durable("machines", &before.id, &intent.target)
                .unwrap();
        }
        if boundary >= 2 {
            h.m.inner
                .store
                .put_durable(templates::READERS, &before.id, &intent.target_reader)
                .unwrap();
        }
        if boundary >= 3 {
            *entry.rec.lock().unwrap() = intent.target.clone();
        }
        h.host_calls();
        let digest = templates::sandbox::request_digest(&request).unwrap();
        let assigned =
            h.m.commit_destination_assignment("destination", "assignment-one", &digest)
                .await
                .unwrap();
        assert!(Arc::ptr_eq(&entry, &assigned));
        assert_eq!(assigned.snapshot().namespace, "destination");
        assert!(!h
            .m
            .namespace_dns_names("destination")
            .contains_key(&assigned.snapshot().hostname()));
        assert_eq!(assigned.snapshot().pid, live.pid);
        assert_eq!(assigned.snapshot().launch_identity, before.launch_identity);
        assert_eq!(
            assigned.snapshot().boot_incarnation,
            before.boot_incarnation
        );
        assert_eq!(assigned.snapshot().root_dataset(), before.root_dataset());
        let after = committed(&h.m.inner.machines.lock().unwrap()).0;
        assert_eq!(after.memory_mb, physical.memory_mb);
        assert_eq!(after.cpu_millis(), physical.cpu_millis());
        assert_eq!(h.m.quota("destination").unwrap().used.machines, 1);
        assert!(!h.m.destination_assignment_pending(&before.id).unwrap());
        let replay =
            h.m.commit_destination_assignment("destination", "assignment-one", &digest)
                .await
                .unwrap();
        assert!(Arc::ptr_eq(&entry, &replay));
        assert!(h
            .m
            .commit_destination_assignment("destination", "assignment-one", &"a".repeat(64))
            .await
            .is_err());
        assert!(!h.host_calls().iter().any(|call| [
            "destination_bind",
            "clone_configure",
            "clone_activate",
            "activate_quarantined",
            "resume-paused",
            "exec "
        ]
        .iter()
        .any(|prefix| call.starts_with(prefix))));
        assert!(h.m.configure_memory_clone(&entry, &live).await.is_err());
        assert!(h.m.activate_memory_clone(&entry, &live).await.is_err());
    }
}

#[tokio::test]
async fn startup_reconstructs_all_pending_liabilities_before_any_transfer() {
    let (h, first, request) = fixture().await;
    let second = second_slot(&h, &first).await;
    let one = model::Intent::plan(&h.m, request.clone(), &first, 2).unwrap();
    let mut request_two = request;
    request_two.name = "second-destination".into();
    request_two.sandbox_seed.as_mut().unwrap().request_id = "assignment-two".into();
    let two = model::Intent::plan(&h.m, request_two, &second, 3).unwrap();
    for intent in [&one, &two] {
        h.m.inner
            .store
            .put_durable(INTENTS, &intent.receipt.key(), intent)
            .unwrap();
    }
    let mut namespace = h.m.namespace_of("destination").unwrap();
    namespace.rec.quota.machines = Some(1);
    h.m.inner
        .store
        .put_durable(crate::store::NAMESPACES, "destination", &namespace.rec)
        .unwrap();
    assert!(restart_load(&h.m).is_err());
    assert_eq!(
        h.m.inner
            .store
            .list::<model::Intent>(INTENTS)
            .unwrap()
            .len(),
        2
    );
    for source in [&one.source, &two.source] {
        let saved: Record =
            h.m.inner
                .store
                .get("machines", &source.id)
                .unwrap()
                .unwrap();
        assert_eq!(saved.namespace, source.namespace);
        assert!(h.pool.zfs.exists(&source.root_dataset()).await.unwrap());
    }
    namespace.rec.quota.machines = Some(2);
    h.m.inner
        .store
        .put_durable(crate::store::NAMESPACES, "destination", &namespace.rec)
        .unwrap();
    restart_load(&h.m).unwrap();
    assert_eq!(h.m.quota("destination").unwrap().used.machines, 2);
    assert!(h
        .m
        .inner
        .store
        .list::<model::Intent>(INTENTS)
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn missing_live_proof_retains_both_allocations_and_all_pending_charges() {
    let (h, entry, request) = fixture().await;
    let source = entry.snapshot();
    h.m.stage_destination_assignment(request.clone(), &entry, 2)
        .await
        .unwrap();
    let physical = committed(&h.m.inner.machines.lock().unwrap()).0;
    *entry.live.lock().unwrap() = None;
    let digest = templates::sandbox::request_digest(&request).unwrap();
    assert!(h
        .m
        .commit_destination_assignment("destination", "assignment-one", &digest)
        .await
        .is_err());
    assert_eq!(entry.snapshot().namespace, source.namespace);
    assert_eq!(
        committed(&h.m.inner.machines.lock().unwrap()).0.memory_mb,
        physical.memory_mb
    );
    assert_eq!(
        h.m.quota("destination").unwrap().used.memory_mb,
        source.size.memory_mb
    );
    assert!(h
        .m
        .held_addresses(source.subnet_index)
        .contains(&u32::from(source.host_num)));
    assert!(h.m.held_addresses(2).contains(&2));
    assert!(h.pool.zfs.exists(&source.root_dataset()).await.unwrap());
    assert!(h.m.destroy_machine(&source.id, None).await.is_err());
    assert!(h.m.destination_assignment_pending(&source.id).unwrap());
}

#[tokio::test]
async fn pending_liability_blocks_start_growth_and_move_admission() {
    for operation in 0..3 {
        let (h, entry, request) = fixture().await;
        h.m.stage_destination_assignment(request.clone(), &entry, 2)
            .await
            .unwrap();
        let ordinary = h.add("m_ordinary", state::STOPPED, 256);
        {
            let mut record = ordinary.rec.lock().unwrap();
            record.name = "ordinary".into();
            if operation != 2 {
                record.namespace = "destination".into();
                record.subnet_index = 2;
                record.host_num = 3;
                record.ip = "10.64.2.3".into();
            }
            if operation == 0 {
                record.state = state::CREATING.into();
                record.start = false;
            }
        }
        let charge = h.m.quota("destination").unwrap().used;
        let quota = match operation {
            0 => api::Quota {
                memory_mb: Some(charge.memory_mb),
                ..Default::default()
            },
            1 => api::Quota {
                disk_gb: Some(charge.disk_gb),
                ..Default::default()
            },
            _ => api::Quota {
                machines: Some(charge.machines),
                ..Default::default()
            },
        };
        h.m.set_quota("destination", quota).await.unwrap();
        match operation {
            0 => assert!(matches!(h.m.creating(&ordinary), Err(MError::Quota(_)))),
            1 => assert!(matches!(
                h.m.grow_volume(&ordinary, 2, 3).await,
                Err(MError::Quota(_))
            )),
            _ => assert!(matches!(
                h.m.move_machine("m_ordinary", "destination", None).await,
                Err(MError::Quota(_))
            )),
        }
        assert!(h
            .m
            .destination_assignment_pending(&entry.snapshot().id)
            .unwrap());
    }
}

#[tokio::test]
async fn reader_write_failure_publishes_target_entry_before_generic_save_can_run() {
    let (h, entry, request) = fixture().await;
    h.m.stage_destination_assignment(request.clone(), &entry, 2)
        .await
        .unwrap();
    let intent: model::Intent =
        h.m.inner
            .store
            .get(INTENTS, &key("destination", "assignment-one"))
            .unwrap()
            .unwrap();
    let blocked =
        h.m.inner
            .store
            .dir(templates::READERS)
            .join(format!("{}.json.tmp", intent.source.id));
    {
        let machines = h.m.inner.machines.lock().unwrap();
        let _writes = entry.removed.lock().unwrap();
        let records = h.m.assignment_records(&machines).unwrap();
        let result = h.m.write_destination_intent(&intent, &records, |target| {
            let saved: Record =
                h.m.inner
                    .store
                    .get("machines", &target.id)
                    .unwrap()
                    .unwrap();
            assert_eq!(saved.namespace, "destination");
            *entry.rec.lock().unwrap() = target.clone();
            // The existing source reader remains intact; only the following write fails.
            std::fs::create_dir(&blocked).unwrap();
        });
        assert!(result.is_err());
    }
    assert_eq!(entry.snapshot().namespace, "destination");
    assert!(h
        .m
        .destination_assignment_pending(&entry.snapshot().id)
        .unwrap());
    h.m.save(&entry).unwrap();
    let saved: Record =
        h.m.inner
            .store
            .get("machines", &entry.snapshot().id)
            .unwrap()
            .unwrap();
    assert_eq!(saved.namespace, "destination");
    let reader: templates::CloneReader =
        h.m.inner
            .store
            .get(templates::READERS, &saved.id)
            .unwrap()
            .unwrap();
    assert_eq!(reader, intent.source_reader);
    std::fs::remove_dir(blocked).unwrap();
    let digest = templates::sandbox::request_digest(&request).unwrap();
    let replay =
        h.m.commit_destination_assignment("destination", "assignment-one", &digest)
            .await
            .unwrap();
    assert!(Arc::ptr_eq(&replay, &entry));
    assert!(!h.m.destination_assignment_pending(&saved.id).unwrap());
}
