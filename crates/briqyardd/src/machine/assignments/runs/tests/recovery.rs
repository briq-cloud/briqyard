use super::super::recovery::RunRecovery;
use super::*;

fn assert_no_launch_or_publication(calls: &[String]) {
    assert!(!calls.iter().any(|c| [
        "boot ",
        "kill ",
        "settle-clone ",
        "assigned_resume ",
        "resume ",
        "resume-paused ",
        "activate_quarantined ",
        "exec ",
        "count "
    ]
    .iter()
    .any(|prefix| c.starts_with(prefix))));
}

#[tokio::test]
async fn observed_fresh_and_consumed_checkpoint_adopt_exact_running_process_still_quarantined() {
    for checkpoint in [false, true] {
        let (h, entry) = stopped(checkpoint).await;
        h.m.launch_assigned_run(&entry, checkpoint).await.unwrap();
        let id = entry.snapshot().id;
        let current: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
        if checkpoint {
            let paths = h.m.run_checkpoint_paths(&current.prior);
            assert!(
                !paths[0].exists() && !paths[1].exists(),
                "mock must model native consumption"
            );
            assert!(paths[2].exists());
            assert!(h.m.verify_run_prelaunch_backing(&current).await.is_err());
        }
        restart(&h).unwrap();
        h.m.verify_assigned_run_backing().await.unwrap();
        assert_eq!(
            h.m.classify_run_recovery(&current).await.unwrap(),
            RunRecovery::ObservedNeedsProof
        );
        let recovered = h.m.entry(&id).unwrap();
        h.host_calls();
        let live = h.m.adopt_observed_assigned_run(&recovered).await.unwrap();
        assert_eq!(live.pid, current.target.pid);
        assert_eq!(live.incarnation, current.target.boot_incarnation);
        assert_eq!(
            live.boot_identity,
            Some(current.expected_boot_identity.clone())
        );
        assert!(!*live.exited.borrow());
        assert!(!recovered.identity_trusted.load(Relaxed));
        assert!(recovered.live.lock().unwrap().is_none());
        assert!(h.m.verified_run_publication(&recovered.snapshot()).is_ok());
        assert!(!h.m.assignment_publication_allowed(
            &recovered.snapshot(),
            recovered.identity_trusted.load(Relaxed)
        ));
        assert!(h.m.namespace_dns_names("destination").is_empty());
        assert!(h.m.ordinary_operation(&recovered.snapshot()).is_err());
        assert_eq!(
            launch_identity::record_fingerprint(&recovered.snapshot()).unwrap(),
            launch_identity::record_fingerprint(&current.target).unwrap()
        );
        assert_eq!(
            h.m.quota("destination").unwrap().used.memory_mb,
            current.target.size.memory_mb
        );
        assert!(h
            .m
            .launch_assigned_run(&recovered, checkpoint)
            .await
            .is_err());
        let calls = h.host_calls();
        assert_no_launch_or_publication(&calls);
        let quarantine = calls
            .iter()
            .position(|c| c.starts_with("quarantine "))
            .unwrap();
        let api = calls
            .iter()
            .position(|c| c.starts_with("adopt-state "))
            .unwrap();
        let ping = calls.iter().position(|c| c.starts_with("ping ")).unwrap();
        assert!(quarantine < api && api < ping);
    }
}

#[tokio::test]
async fn attempted_checkpoint_with_remaining_or_consumed_inputs_never_implies_a_handle_or_retry() {
    for fault in [0, 5, 6] {
        let (h, entry) = stopped(true).await;
        let id = entry.snapshot().id;
        if fault == 0 {
            h.m.reserve_assigned_run(&entry, true).await.unwrap();
            let prior: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
            assert_eq!(
                h.m.classify_run_recovery(&prior).await.unwrap(),
                RunRecovery::Prelaunch
            );
            let mut attempted = prior.clone();
            attempted.launch_started = true;
            h.m.persist_run_transition(&entry, prior, &attempted)
                .unwrap();
            assert!(h.m.run_checkpoint_paths(&attempted.prior)[0].exists());
        } else {
            h.assigned_run_fault(fault);
            assert!(h.m.launch_assigned_run(&entry, true).await.is_err());
        }
        let current: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
        assert_eq!(current.reference.phase, Phase::Reserved);
        assert_eq!(
            h.m.classify_run_recovery(&current).await.unwrap(),
            RunRecovery::DiscoveryNeeded
        );
        if fault != 0 {
            let paths = h.m.run_checkpoint_paths(&current.prior);
            assert!(!paths[0].exists() && !paths[1].exists());
        }
        restart(&h).unwrap();
        h.host_calls();
        h.m.verify_assigned_run_backing().await.unwrap();
        assert!(
            h.host_calls().iter().any(|c| c.starts_with("quarantine ")),
            "startup must quarantine unresolved consumption before forwarding"
        );
        h.assigned_run_fault(0);
        h.host_calls();
        let recovered = h.m.entry(&id).unwrap();
        assert!(h.m.adopt_observed_assigned_run(&recovered).await.is_err());
        assert!(h.m.launch_assigned_run(&recovered, true).await.is_err());
        assert!(!recovered.identity_trusted.load(Relaxed));
        assert!(recovered.live.lock().unwrap().is_none());
        assert_eq!(
            h.m.quota("destination").unwrap().used.memory_mb,
            current.target.size.memory_mb
        );
        assert!(h
            .pool
            .zfs
            .exists(&current.target.root_dataset())
            .await
            .unwrap());
        let calls = h.host_calls();
        assert_no_launch_or_publication(&calls);
        assert!(!calls
            .iter()
            .any(|c| c.starts_with("adopt ") || c.starts_with("ping ")));
    }
}

#[tokio::test]
async fn observed_adoption_refuses_changed_current_backing_process_api_and_guest_proof() {
    for (checkpoint, fault) in [
        (true, 0),
        (true, 1),
        (true, 2),
        (true, 3),
        (true, 4),
        (true, 5),
        (true, 7),
        (true, 8),
        (false, 10),
        (true, 11),
        (false, 1),
        (true, 12),
    ] {
        let (h, entry) = stopped(checkpoint).await;
        h.m.launch_assigned_run(&entry, checkpoint).await.unwrap();
        let id = entry.snapshot().id;
        let current: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
        restart(&h).unwrap();
        let recovered = h.m.entry(&id).unwrap();
        match fault {
            0 => {
                let root = current.prior.root_dataset();
                h.pool.zfs.destroy(&root).await.unwrap();
                h.pool.zfs.create(&root, 1 << 20).await.unwrap();
            }
            1 => std::fs::write(
                h.m.run_checkpoint_paths(&current.prior)[2].clone(),
                b"changed config",
            )
            .unwrap(),
            2 => h.m.inner.vmm.kill(current.target.pid),
            11 => h.assigned_adoption_profile(fc::UNAVAILABLE_PROFILE),
            12 => h.set_host_boot_id(Some("22222222-2222-4222-8222-222222222222")),
            _ => h.assigned_run_fault(fault),
        }
        h.host_calls();
        assert!(
            h.m.publish_observed_run(&recovered, false, None)
                .await
                .is_err(),
            "publisher fault {fault}"
        );
        assert!(!recovered.identity_trusted.load(Relaxed));
        assert!(recovered.live.lock().unwrap().is_none());
        assert!(h.m.namespace_dns_names("destination").is_empty());
        assert_no_launch_or_publication(&h.host_calls());
        // Fault 8 is one-shot; independently fault the adopter after the publisher consumed it.
        if fault == 8 {
            h.assigned_run_fault(8);
        }
        assert!(
            h.m.adopt_observed_assigned_run(&recovered).await.is_err(),
            "fault {fault}"
        );
        assert!(!recovered.identity_trusted.load(Relaxed));
        assert!(recovered.live.lock().unwrap().is_none());
        assert_eq!(
            h.m.quota("destination").unwrap().used.memory_mb,
            current.target.size.memory_mb
        );
        assert!(h
            .m
            .launch_assigned_run(&recovered, checkpoint)
            .await
            .is_err());
        assert!(h
            .pool
            .zfs
            .exists(&current.prior.data_dataset())
            .await
            .unwrap());
        assert_no_launch_or_publication(&h.host_calls());
    }
}
