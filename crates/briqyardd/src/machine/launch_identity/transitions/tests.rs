use super::*;
use crate::machine::templates::tests::launch_identity::reserved;

async fn planned() -> (crate::machine::tests::Harness, Transition, Record) {
    let (h, entry) = reserved().await;
    let mut target = entry.snapshot();
    let reader =
        h.m.inner
            .store
            .get(templates::READERS, &target.id)
            .unwrap()
            .unwrap();
    let origin = target.clone_origin.as_mut().unwrap();
    origin.stage = templates::CloneStage::Loading;
    origin.launch_host_boot_id = h.m.inner.vmm.host_boot_id();
    let intent = Transition::new(&h.m, &target, reader, templates::CloneStage::Loading).unwrap();
    (h, intent, target)
}

#[tokio::test]
async fn durable_evidence_reconciles_each_record_first_reader_second_crash_boundary() {
    for boundary in 0..3 {
        let (h, intent, target) = planned().await;
        intent.publish(&h.m).unwrap();
        if boundary >= 1 {
            h.m.inner
                .store
                .put_durable("machines", &target.id, &target)
                .unwrap();
        }
        if boundary >= 2 {
            h.m.inner
                .store
                .put_durable(templates::READERS, &target.id, &intent.after_reader)
                .unwrap();
        }
        h.m.recover_launch_transitions().unwrap();
        let recovered: Record =
            h.m.inner
                .store
                .get("machines", &target.id)
                .unwrap()
                .unwrap();
        h.m.validate_launch_record(&recovered).unwrap();
        assert_eq!(record_fingerprint(&recovered).unwrap(), intent.after_record);
        assert_eq!(
            h.m.inner
                .store
                .get::<templates::CloneReader>(templates::READERS, &target.id)
                .unwrap()
                .unwrap(),
            intent.after_reader
        );
        assert!(h
            .m
            .inner
            .store
            .list::<Transition>(TRANSITIONS)
            .unwrap()
            .is_empty());
        h.m.recover_launch_transitions().unwrap();
    }
}

#[tokio::test]
async fn reconciliation_preserves_terminal_exit_proof_and_error_observations() {
    for record_committed in [false, true] {
        let (h, intent, target) = planned().await;
        intent.publish(&h.m).unwrap();
        let mut current: Record = if record_committed {
            target
        } else {
            h.m.inner
                .store
                .get("machines", &intent.machine)
                .unwrap()
                .unwrap()
        };
        current.state = state::ERROR.into();
        current.error = "owned launch failed; confirmed exit".into();
        current.clone_origin.as_mut().unwrap().mapping_exited = true;
        h.m.inner
            .store
            .put_durable("machines", &current.id, &current)
            .unwrap();
        h.m.recover_launch_transitions().unwrap();
        let recovered: Record =
            h.m.inner
                .store
                .get("machines", &current.id)
                .unwrap()
                .unwrap();
        assert_eq!(recovered.state, state::ERROR);
        assert_eq!(recovered.error, current.error);
        assert!(recovered.clone_origin.as_ref().unwrap().mapping_exited);
        h.m.validate_launch_record(&recovered).unwrap();
    }
}

#[tokio::test]
async fn contradictory_owner_workload_reader_or_missing_record_retains_intent_and_hold() {
    for conflict in 0..4 {
        let (h, intent, mut target) = planned().await;
        intent.publish(&h.m).unwrap();
        match conflict {
            0 => {
                target.namespace = "other-owner".into();
                h.m.inner
                    .store
                    .put_durable("machines", &target.id, &target)
                    .unwrap();
            }
            1 => {
                target.env.insert("unexpected".into(), "value".into());
                h.m.inner
                    .store
                    .put_durable("machines", &target.id, &target)
                    .unwrap();
            }
            2 => {
                let mut reader = intent.before_reader.clone();
                reader.namespace = "other-owner".into();
                h.m.inner
                    .store
                    .put_durable(templates::READERS, &target.id, &reader)
                    .unwrap();
            }
            _ => {
                h.m.inner
                    .store
                    .delete_durable("machines", &target.id)
                    .unwrap()
            }
        }
        assert!(h.m.recover_launch_transitions().is_err());
        assert!(h
            .m
            .inner
            .store
            .get::<Transition>(TRANSITIONS, &target.id)
            .unwrap()
            .is_some());
        assert!(h
            .m
            .inner
            .store
            .get::<Hold>(HOLDS, &target.id)
            .unwrap()
            .is_some());
    }
}

#[tokio::test]
async fn reader_first_without_record_evidence_is_not_repaired_as_a_valid_transition() {
    let (h, intent, _) = planned().await;
    intent.publish(&h.m).unwrap();
    h.m.inner
        .store
        .put_durable(templates::READERS, &intent.machine, &intent.after_reader)
        .unwrap();
    assert!(h.m.recover_launch_transitions().is_err());
    assert!(h
        .m
        .inner
        .store
        .get::<Transition>(TRANSITIONS, &intent.machine)
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn startup_repairs_durable_record_first_transition_before_exact_provenance_checks() {
    let (h, intent, target) = planned().await;
    let namespace = h.m.namespace_of("t1").unwrap();
    h.m.inner
        .store
        .put_durable(crate::store::NAMESPACES, "t1", &namespace.rec)
        .unwrap();
    intent.publish(&h.m).unwrap();
    h.m.inner
        .store
        .put_durable("machines", &target.id, &target)
        .unwrap();
    // The record is Loading and the reader Reserved: exact pair validation refuses it.
    assert!(h.m.validate_launch_record(&target).is_err());
    h.m.inner.machines.lock().unwrap().clear();
    h.m.inner.namespaces.lock().unwrap().clear();
    h.m.inner.launch_holds.lock().unwrap().clear();
    h.m.load().unwrap();
    let loaded = h.m.entry(&target.id).unwrap().snapshot();
    h.m.validate_launch_record(&loaded).unwrap();
    assert_eq!(
        loaded.clone_origin.unwrap().stage,
        templates::CloneStage::Loading
    );
    assert!(h.m.held_addresses(1).contains(&3));
    assert!(h
        .m
        .inner
        .store
        .list::<Transition>(TRANSITIONS)
        .unwrap()
        .is_empty());
}
