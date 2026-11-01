use super::*;
mod bind;
mod live;
use crate::machine::templates::tests::launch_identity::prepared;

async fn fixture() -> (
    crate::machine::tests::Harness,
    Arc<Entry>,
    api::CreateMachineRequest,
) {
    let (h, entry) = prepared().await;
    h.namespace("destination");
    for namespace in h.m.inner.namespaces.lock().unwrap().values() {
        h.m.inner
            .store
            .put_durable(crate::store::NAMESPACES, &namespace.rec.id, &namespace.rec)
            .unwrap();
    }
    let record = entry.snapshot();
    let origin = record.clone_origin.as_ref().unwrap();
    let request = api::CreateMachineRequest {
        namespace: "destination".into(),
        name: "assigned".into(),
        image: record.image,
        size: record.size,
        volume: record.volume,
        sleep: "never".into(),
        start: Some(true),
        cmd: Some(vec!["/bin/sh".into(), "-c".into(), "sleep infinity".into()]),
        env: BTreeMap::from([("DESTINATION_ONLY".into(), "value".into())]),
        metadata: BTreeMap::from([("owner".into(), "destination".into())]),
        sandbox_seed: Some(api::SandboxSeed {
            machine_id: origin.source_machine.clone(),
            snapshot: origin.snapshot.clone(),
            generation: origin.artifact.generation.clone(),
            request_id: "assignment-one".into(),
        }),
        ..Default::default()
    };
    (h, entry, request)
}
fn restart_load(manager: &Manager) -> Result<()> {
    manager.inner.machines.lock().unwrap().clear();
    manager.inner.namespaces.lock().unwrap().clear();
    manager.inner.launch_holds.lock().unwrap().clear();
    *manager.inner.assignments.lock().unwrap() = State::default();
    manager.load()
}

#[tokio::test]
async fn assignment_intent_is_not_a_miss_and_transfers_full_quota_once_on_recovery() {
    let (h, entry, request) = fixture().await;
    let before = entry.snapshot();
    let before_host = committed(&h.m.inner.machines.lock().unwrap()).0;
    h.m.stage_destination_assignment(request.clone(), &entry, 2)
        .await
        .unwrap();
    let digest = templates::sandbox::request_digest(&request).unwrap();
    assert!(h
        .m
        .resolve_destination_assignment(&request.namespace, "assignment-one", &digest)
        .is_err());
    assert!(h.m.destination_assignment_owns(&before.id).unwrap());
    assert!(h.m.destroy_machine(&before.id, None).await.is_err());
    restart_load(&h.m).unwrap();
    let assigned = h.m.entry(&before.id).unwrap().snapshot();
    assert_eq!(assigned.namespace, "destination");
    assert_eq!(assigned.pid, before.pid);
    assert_eq!(assigned.boot_incarnation, before.boot_incarnation);
    assert_eq!(assigned.launch_identity, before.launch_identity);
    assert_eq!(assigned.root_dataset(), before.root_dataset());
    let used = h.m.quota("destination").unwrap().used;
    assert_eq!(used.machines, 1);
    assert_eq!(used.memory_mb, before.size.memory_mb);
    assert_eq!(used.cpu_millis(), before.size.cpu_millis());
    assert_eq!(
        used.disk_gb,
        2 + before.clone_origin.unwrap().artifact.recipe.root_disk_gb
    );
    let after_host = committed(&h.m.inner.machines.lock().unwrap()).0;
    assert_eq!(after_host.memory_mb, before_host.memory_mb);
    assert_eq!(after_host.cpu_millis(), before_host.cpu_millis());
    assert_eq!(h.m.quota("t1").unwrap().used.disk_gb, 0);
    assert!(h
        .m
        .resolve_destination_assignment(&request.namespace, "assignment-one", &digest)
        .unwrap()
        .is_some());
    assert!(h
        .m
        .inner
        .store
        .list::<model::Intent>(INTENTS)
        .unwrap()
        .is_empty());
    h.m.destroy_machine(&assigned.id, None).await.unwrap();
    assert!(h
        .m
        .resolve_destination_assignment(&request.namespace, "assignment-one", &digest)
        .is_err());
    assert!(h
        .m
        .inner
        .store
        .get::<Receipt>(REQUESTS, &key(&request.namespace, "assignment-one"))
        .unwrap()
        .is_some());
    assert!(h
        .m
        .inner
        .store
        .get::<serde_json::Value>("launch-holds", &assigned.id)
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn intent_record_reader_index_crash_boundaries_keep_the_same_request_and_slot() {
    for boundary in 0..4 {
        let (h, entry, request) = fixture().await;
        let intent = model::Intent::plan(&h.m, request.clone(), &entry, 2).unwrap();
        h.m.inner
            .store
            .put_durable(INTENTS, &intent.receipt.key(), &intent)
            .unwrap();
        if boundary >= 1 {
            h.m.persist_destination_receipt(&intent.receipt).unwrap();
        }
        if boundary >= 2 {
            h.m.inner
                .store
                .put_durable("machines", &intent.target.id, &intent.target)
                .unwrap();
        }
        if boundary >= 3 {
            h.m.inner
                .store
                .put_durable(templates::READERS, &intent.target.id, &intent.target_reader)
                .unwrap();
        }
        restart_load(&h.m).unwrap();
        let digest = templates::sandbox::request_digest(&request).unwrap();
        let machine =
            h.m.resolve_destination_assignment(&request.namespace, "assignment-one", &digest)
                .unwrap()
                .unwrap();
        assert_eq!(machine.snapshot().id, entry.snapshot().id);
        let mut changed = request.clone();
        changed.env.insert("changed".into(), "true".into());
        assert!(h
            .m
            .resolve_destination_assignment(
                &request.namespace,
                "assignment-one",
                &templates::sandbox::request_digest(&changed).unwrap()
            )
            .is_err());
        h.m.recover_destination_assignments().unwrap();
    }
}

#[tokio::test]
async fn destination_name_address_and_logical_storage_quota_conflicts_prevent_authority() {
    for conflict in 0..3 {
        let (h, entry, request) = fixture().await;
        if conflict == 2 {
            h.m.inner
                .namespaces
                .lock()
                .unwrap()
                .get_mut("destination")
                .unwrap()
                .rec
                .quota
                .disk_gb = Some(9);
        } else {
            let mut other = entry.snapshot();
            other.id = "m_other".into();
            other.namespace = "destination".into();
            other.subnet_index = 2;
            other.host_num = if conflict == 0 { 3 } else { 2 };
            other.ip = format!("10.64.2.{}", other.host_num);
            other.name = if conflict == 0 {
                request.name.clone()
            } else {
                "other".into()
            };
            other.warm_slot = None;
            other.launch_identity = None;
            other.clone_origin = None;
            h.m.inner.machines.lock().unwrap().insert(
                other.id.clone(),
                Entry::new(other, h.m.inner.events.clone()),
            );
        }
        assert!(h
            .m
            .stage_destination_assignment(request, &entry, 2)
            .await
            .is_err());
        assert!(h
            .m
            .inner
            .store
            .list::<model::Intent>(INTENTS)
            .unwrap()
            .is_empty());
        assert!(h
            .m
            .inner
            .store
            .list::<Receipt>(REQUESTS)
            .unwrap()
            .is_empty());
    }
}

#[tokio::test]
async fn missing_record_or_reader_never_becomes_a_definitive_miss_or_releases_source() {
    for missing_record in [false, true] {
        let (h, entry, request) = fixture().await;
        h.m.stage_destination_assignment(request.clone(), &entry, 2)
            .await
            .unwrap();
        let id = entry.snapshot().id;
        h.m.inner
            .store
            .delete_durable(
                if missing_record {
                    "machines"
                } else {
                    templates::READERS
                },
                &id,
            )
            .unwrap();
        assert!(restart_load(&h.m).is_err());
        let digest = templates::sandbox::request_digest(&request).unwrap();
        assert!(h
            .m
            .resolve_destination_assignment(&request.namespace, "assignment-one", &digest)
            .is_err());
        assert!(h
            .m
            .inner
            .store
            .get::<serde_json::Value>("launch-holds", &id)
            .unwrap()
            .is_some());
        assert!(h
            .m
            .inner
            .store
            .get::<model::Intent>(INTENTS, &key(&request.namespace, "assignment-one"))
            .unwrap()
            .is_some());
    }
}

#[tokio::test]
async fn pid_absence_without_exit_proof_retains_consumed_request_and_full_backing() {
    let (h, entry, request) = fixture().await;
    h.m.stage_destination_assignment(request.clone(), &entry, 2)
        .await
        .unwrap();
    let mut record = entry.snapshot();
    record.pid = 0;
    record.state = state::ERROR.into();
    h.m.inner
        .store
        .put_durable("machines", &record.id, &record)
        .unwrap();
    assert!(restart_load(&h.m).is_err());
    assert!(h
        .m
        .resolve_destination_assignment(
            &request.namespace,
            "assignment-one",
            &templates::sandbox::request_digest(&request).unwrap()
        )
        .is_err());
    assert!(h
        .m
        .inner
        .store
        .get::<serde_json::Value>("launch-holds", &record.id)
        .unwrap()
        .is_some());
    assert!(h.pool.zfs.exists(&record.dataset()).await.unwrap());
    let charge = quota_need(&record, false);
    assert_eq!(charge.memory_mb, record.size.memory_mb);
    assert_eq!(charge.cpu_millis(), record.size.cpu_millis());
    assert_eq!(
        charge.disk_gb,
        2 + record.clone_origin.unwrap().artifact.recipe.root_disk_gb
    );
}

#[tokio::test]
async fn wrong_request_key_and_uncertain_first_intent_write_are_not_misses() {
    let (h, entry, request) = fixture().await;
    let directory = h.m.inner.store.dir(INTENTS);
    std::fs::remove_dir(&directory).unwrap();
    assert!(h
        .m
        .stage_destination_assignment(request.clone(), &entry, 2)
        .await
        .is_err());
    let digest = templates::sandbox::request_digest(&request).unwrap();
    assert!(h
        .m
        .resolve_destination_assignment(&request.namespace, "assignment-one", &digest)
        .is_err());
    assert!(h
        .m
        .destroy_machine(&entry.snapshot().id, None)
        .await
        .is_err());
    std::fs::create_dir(&directory).unwrap();
    assert!(h
        .m
        .stage_destination_assignment(request.clone(), &entry, 2)
        .await
        .is_err());
    let receipt =
        h.m.inner
            .assignments
            .lock()
            .unwrap()
            .receipts
            .values()
            .next()
            .unwrap()
            .clone();
    h.m.inner
        .store
        .put_durable(REQUESTS, &key("destination", "wrong-request"), &receipt)
        .unwrap();
    assert!(h
        .m
        .resolve_destination_assignment("destination", "wrong-request", &digest)
        .is_err());
}

#[tokio::test]
async fn confirmed_exit_during_assignment_is_not_rewritten_as_a_live_destination() {
    let (h, entry, request) = fixture().await;
    h.m.stage_destination_assignment(request, &entry, 2)
        .await
        .unwrap();
    let mut source = entry.snapshot();
    h.m.inner.vmm.kill(source.pid);
    source.pid = 0;
    source.state = state::STOPPED.into();
    source.clone_origin.as_mut().unwrap().mapping_exited = true;
    h.m.inner
        .store
        .put_durable("machines", &source.id, &source)
        .unwrap();
    restart_load(&h.m).unwrap();
    let target = h.m.entry(&source.id).unwrap().snapshot();
    assert_eq!(target.namespace, "destination");
    assert_eq!(target.pid, 0);
    assert_eq!(target.state, state::STOPPED);
    assert!(target.clone_origin.unwrap().mapping_exited);
}

fn routing_dependency(h: &crate::machine::tests::Harness, gateway: bool) -> Record {
    let mut route = crate::machine::tests::record();
    route.id = "m_route".into();
    route.name = "route".into();
    route.namespace = "destination".into();
    route.subnet_index = 2;
    route.host_num = 3;
    route.ip = "10.64.2.3".into();
    route.state = state::CREATED.into();
    route.volume = None;
    route.role = gateway.then_some(Role::Gateway);
    h.m.inner
        .store
        .put_durable("machines", &route.id, &route)
        .unwrap();
    h.m.inner.machines.lock().unwrap().insert(
        route.id.clone(),
        Entry::new(route.clone(), h.m.inner.events.clone()),
    );
    route
}

async fn interrupted_routing_assignment(gateway: bool) {
    for boundary in 0..3 {
        let (h, entry, mut request) = fixture().await;
        let route = routing_dependency(&h, gateway);
        request.egress = Some(api::Egress {
            mode: api::egress::VIA.into(),
            via: Some(if gateway {
                api::egress::GATEWAY.into()
            } else {
                route.id.clone()
            }),
            ..Default::default()
        });
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
                .put_durable("machines", &intent.target.id, &intent.target)
                .unwrap();
        }
        if boundary >= 2 {
            h.m.inner
                .store
                .put_durable(templates::READERS, &intent.target.id, &intent.target_reader)
                .unwrap();
        }
        h.host_calls();
        restart_load(&h.m).unwrap();
        assert!(
            h.host_calls().is_empty(),
            "metadata recovery must not publish a network or start a gateway"
        );
        let assigned = h.m.entry(&intent.target.id).unwrap().snapshot();
        let (_, policy) = h.m.policy_for(&assigned).unwrap().unwrap();
        assert!(matches!(policy, nft::Policy::Via { to, to_tap, .. }
            if to == route.ip && to_tap == netw::tap_name(&route.id)));
        assert!(h
            .m
            .resolve_destination_assignment(
                &request.namespace,
                "assignment-one",
                &templates::sandbox::request_digest(&request).unwrap()
            )
            .unwrap()
            .is_some());
    }
}

#[tokio::test]
async fn named_machine_egress_recovers_from_durable_dependency_at_each_assignment_interruption() {
    interrupted_routing_assignment(false).await;
}

#[tokio::test]
async fn namespace_gateway_egress_recovers_from_durable_dependency_at_each_assignment_interruption()
{
    interrupted_routing_assignment(true).await;
}

#[tokio::test]
async fn durable_policy_resolution_preserves_self_namespace_and_destroying_rejections() {
    for gateway in [false, true] {
        for invalid_namespace in [false, true] {
            let (h, entry, mut request) = fixture().await;
            let mut route = routing_dependency(&h, gateway);
            request.egress = Some(api::Egress {
                mode: api::egress::VIA.into(),
                via: Some(if gateway {
                    api::egress::GATEWAY.into()
                } else {
                    route.id.clone()
                }),
                ..Default::default()
            });
            h.m.stage_destination_assignment(request, &entry, 2)
                .await
                .unwrap();
            if invalid_namespace {
                route.namespace = "another".into();
            } else {
                route.state = state::DESTROYING.into();
            }
            h.m.inner
                .store
                .put_durable("machines", &route.id, &route)
                .unwrap();
            assert!(restart_load(&h.m).is_err());
            assert!(h
                .m
                .inner
                .store
                .get::<model::Intent>(INTENTS, &key("destination", "assignment-one"))
                .unwrap()
                .is_some());
        }
    }
    let (h, entry, _) = fixture().await;
    let mut record = entry.snapshot();
    record.egress = api::Egress {
        mode: api::egress::VIA.into(),
        via: Some(record.id.clone()),
        ..Default::default()
    };
    assert!(h.m.policy_for_records(&record, &[record.clone()]).is_err());
}
