//! Lifecycle barriers use the synthetic VMM's explicit death and leaf model.
use super::*;

#[tokio::test]
async fn leaf_failure_retains_destroying_disks_record_and_reservation_then_retries() {
    let h = harness("10.64.0.0/22", 4096).await;
    let e = h.add("m_retire", state::STOPPED, 512);
    h.m.save(&e).unwrap();
    let before_disks = h.pool.calls();
    assert!(!before_disks.iter().any(|c| c.starts_with("destroy ")));
    h.host.refuse_retirement.store(true, Relaxed);
    assert!(h.m.destroy("m_retire", None).await.is_err());
    assert_eq!(e.snapshot().state, state::DESTROYING);
    assert!(h
        .m
        .inner
        .store
        .get::<Record>("machines", "m_retire")
        .unwrap()
        .is_some());
    assert!(h.m.entry("m_retire").is_ok());
    assert!(!h
        .pool
        .calls()
        .iter()
        .any(|c| c.starts_with("destroy ") || c.starts_with("promote ")));
    assert_eq!(
        committed(&h.m.inner.machines.lock().unwrap()).0.memory_mb,
        768
    );
    assert!(h
        .m
        .memory_admission(&h.m.inner.machines.lock().unwrap())
        .is_err());
    assert!(!h
        .host
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|c| c.starts_with("uncount")));
    h.host.refuse_retirement.store(false, Relaxed);
    h.m.destroy("m_retire", None).await.unwrap();
    assert!(h.m.entry("m_retire").is_err());
}

#[tokio::test]
async fn original_identity_collision_refuses_before_retirement() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.add("m_owned", state::STOPPED, 512);
    h.add("m-owned", state::STOPPED, 512);
    assert!(h.m.destroy("m_owned", None).await.is_err());
    assert!(!h
        .host
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|c| c.starts_with("retire-cgroup")));
    assert!(h.m.entry("m_owned").is_ok());
    assert!(h.m.entry("m-owned").is_ok());
}

#[tokio::test]
async fn a_closed_false_exit_channel_is_not_process_death() {
    let h = harness("10.64.0.0/22", 4096).await;
    let e = h.add("m_unknown", state::RUNNING, 512);
    let (sender, exited) = tokio::sync::watch::channel(false);
    drop(sender);
    let (_report, exit) = tokio::sync::watch::channel(None);
    let live = fc::Vm {
        #[cfg(target_os = "linux")]
        identity: None,
        pid: 4242,
        api: PathBuf::new(),
        vsock: PathBuf::new(),
        dir: PathBuf::new(),
        chroot: None,
        resumed: false,
        exited,
        exit,
    };
    *e.live.lock().unwrap() = Some(live);
    assert!(h.m.destroy("m_unknown", None).await.is_err());
    assert!(e.live.lock().unwrap().is_some());
    assert_eq!(e.snapshot().state, state::DESTROYING);
    assert!(!h
        .host
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|c| c.starts_with("retire-cgroup")));
}

#[tokio::test(start_paused = true)]
async fn a_live_unsettled_process_times_out_without_releasing_ownership() {
    let h = harness("10.64.0.0/22", 4096).await;
    let e = h.add("m_deadline", state::RUNNING, 512);
    let (_sender, exited) = tokio::sync::watch::channel(false);
    let (_report, exit) = tokio::sync::watch::channel(None);
    let live = fc::Vm {
        #[cfg(target_os = "linux")]
        identity: None,
        pid: 4243,
        api: PathBuf::new(),
        vsock: PathBuf::new(),
        dir: PathBuf::new(),
        chroot: None,
        resumed: false,
        exited,
        exit,
    };
    *e.live.lock().unwrap() = Some(live);
    assert!(h.m.destroy("m_deadline", None).await.is_err());
    assert!(e.live.lock().unwrap().is_some());
    assert_eq!(e.snapshot().state, state::DESTROYING);
    assert_eq!(
        committed(&h.m.inner.machines.lock().unwrap()).0.memory_mb,
        768
    );
    assert!(!h
        .host
        .calls()
        .iter()
        .any(|c| c.starts_with("retire-cgroup")));
}

#[tokio::test]
async fn ordinary_recovered_stopped_destroy_and_empty_orphan_retirement_succeed() {
    use crate::fc::Vmm;
    let h = harness("10.64.0.0/22", 4096).await;
    let e = h.add("m_recovered", state::STOPPED, 512);
    h.disks(&e).await;
    h.m.save(&e).unwrap();
    e.meter.lock().unwrap().boot(0);
    for (id, cpu) in [("m_recovered", 42), ("m_empty_orphan", 7)] {
        h.host.cgroups.lock().unwrap().insert(
            id.into(),
            fc::CgroupUse {
                cpu_usec: cpu,
                memory_bytes: 0,
            },
        );
    }
    h.host
        .initialize_recovery(&[fc::RecoveryMachine {
            id: "m_recovered".into(),
            pid: 0,
        }])
        .await
        .unwrap();
    h.m.recover().await.unwrap();
    assert_eq!(e.snapshot().state, state::STOPPED);
    assert!(!h.host.spawning_open.load(Relaxed));
    h.m.sweep_orphans().await.unwrap();
    assert!(!h
        .host
        .cgroups
        .lock()
        .unwrap()
        .contains_key("m_empty_orphan"));
    h.host.open_recovery().unwrap();
    h.m.resume_recovery_workers();
    h.m.destroy("m_recovered", None).await.unwrap();
    assert!(h.stored("m_recovered").is_none());
    assert!(!h.pool.zfs.exists(&e.snapshot().dataset()).await.unwrap());
    let calls = h.host.calls();
    let position = |name: &str| calls.iter().position(|call| call == name).unwrap();
    assert!(position("recovery-initialized") < position("recover-stopped m_recovered"));
    assert!(position("retire-cgroup m_empty_orphan") < position("recovery-open"));
    assert_eq!(e.meter.lock().unwrap().counted().cpu_seconds, 42.0 / 1e6);
}

#[tokio::test]
async fn unresolved_supervision_keeps_recovery_closed_and_records_disks_untouched() {
    use crate::fc::Vmm;
    let h = harness("10.64.0.0/22", 4096).await;
    let e = h.add("m_unresolved", state::STOPPED, 512);
    h.disks(&e).await;
    h.m.save(&e).unwrap();
    h.host.refuse_recovery.store(true, Relaxed);
    assert!(h
        .host
        .initialize_recovery(&[fc::RecoveryMachine {
            id: "m_unresolved".into(),
            pid: 0
        }])
        .await
        .is_err());
    assert!(h.host.open_recovery().is_err());
    assert!(!h.host.spawning_open.load(Relaxed));
    assert_eq!(h.stored("m_unresolved").unwrap().state, state::STOPPED);
    assert!(h.pool.zfs.exists(&e.snapshot().dataset()).await.unwrap());
}

#[tokio::test]
async fn stale_record_pid_does_not_release_a_surviving_owned_child_or_kill_another_machine() {
    use crate::fc::Vmm;
    let h = harness("10.64.0.0/22", 4096).await;
    h.namespace("t1");
    let owned = h.add("m_owned_child", state::STOPPING, 512);
    let other = h.add("m_other_live", state::RUNNING, 512);
    let child_pid = h.host.left_running(
        "m_owned_child",
        &h.m.inner.cfg.run_dir().join("m_owned_child"),
    );
    let other_pid = h.host.left_running(
        "m_other_live",
        &h.m.inner.cfg.run_dir().join("m_other_live"),
    );
    owned.rec.lock().unwrap().pid = other_pid;
    other.rec.lock().unwrap().pid = other_pid;
    h.m.recover().await.unwrap();
    assert_eq!(owned.snapshot().state, state::STOPPED);
    assert!(!h.host.processes().iter().any(|(pid, _)| *pid == child_pid));
    assert!(h.host.processes().iter().any(|(pid, _)| *pid == other_pid));
    assert!(!h.host.calls().contains(&format!("kill {other_pid}")));
}

#[tokio::test]
async fn cut_create_recovery_dispatches_no_worker_until_the_spawn_gate_opens() {
    use crate::fc::Vmm;
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let entry = h.add("m_cut_gate", state::CREATING, 256);
    {
        let mut record = entry.rec.lock().unwrap();
        record.image = IMAGE.into();
        record.start = true;
        record.volume = None;
    }
    h.disks(&entry).await;
    h.host
        .initialize_recovery(&[fc::RecoveryMachine {
            id: "m_cut_gate".into(),
            pid: 0,
        }])
        .await
        .unwrap();
    h.m.recover().await.unwrap();
    assert_eq!(entry.snapshot().state, state::CREATING);
    assert!(!h.host.spawning_open.load(Relaxed));
    assert!(!h.host.calls().iter().any(|call| call.starts_with("boot ")));
    h.m.sweep_orphans().await.unwrap();
    h.host.open_recovery().unwrap();
    h.m.resume_recovery_workers();
    h.m.wait("m_cut_gate", Until::Running, Duration::from_secs(5))
        .await
        .unwrap();
    h.m.destroy("m_cut_gate", None).await.unwrap();
}

#[tokio::test]
async fn unavailable_final_counters_retain_leaf_disks_record_and_physical_charge() {
    let h = harness("10.64.0.0/22", 4096).await;
    let e = h.add("m_final_counter", state::STOPPED, 512);
    h.disks(&e).await;
    h.m.save(&e).unwrap();
    e.meter.lock().unwrap().boot(0);
    h.host.cgroups.lock().unwrap().insert(
        "m_final_counter".into(),
        fc::CgroupUse {
            cpu_usec: 500,
            memory_bytes: 0,
        },
    );
    h.host.refuse_final_meter.store(true, Relaxed);
    assert!(h.m.destroy("m_final_counter", None).await.is_err());
    assert_eq!(
        h.stored("m_final_counter").unwrap().state,
        state::DESTROYING
    );
    assert!(h.pool.zfs.exists(&e.snapshot().dataset()).await.unwrap());
    assert!(h
        .host
        .cgroups
        .lock()
        .unwrap()
        .contains_key("m_final_counter"));
    assert!(!h
        .host
        .calls()
        .contains(&"retire-cgroup m_final_counter".into()));
    assert_eq!(
        committed(&h.m.inner.machines.lock().unwrap()).0.memory_mb,
        768
    );
    h.host.refuse_final_meter.store(false, Relaxed);
    h.m.destroy("m_final_counter", None).await.unwrap();
    assert_eq!(e.meter.lock().unwrap().counted().cpu_seconds, 500.0 / 1e6);
    assert!(!h
        .host
        .cgroups
        .lock()
        .unwrap()
        .contains_key("m_final_counter"));
}

#[tokio::test]
async fn failed_boot_with_unproven_child_keeps_memory_and_blocks_admission_before_destroy() {
    for reason in ["lost jailer pidfile", "API readiness timeout"] {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        let e = h.add("m_failed_launch", state::CREATED, 512);
        {
            let mut r = e.rec.lock().unwrap();
            r.image = IMAGE.into();
            r.volume = None;
        }
        h.disks(&e).await;
        h.host.boots(Boots::UnsettledLaunch(reason));
        assert!(h.m.start("m_failed_launch", None).await.is_err());
        assert_eq!(e.snapshot().state, state::ERROR);
        assert_eq!(e.snapshot().pid, 0);
        assert!(e.live.lock().unwrap().is_none());
        assert_eq!(
            committed(&h.m.inner.machines.lock().unwrap()).0.memory_mb,
            768
        );
        assert!(h
            .m
            .memory_admission(&h.m.inner.machines.lock().unwrap())
            .is_err());
        let another = h.add("m_next_launch", state::STOPPED, 512);
        assert!(matches!(
            h.m.reserve(&another, None),
            Err(MError::Capacity(_))
        ));
        // Positive synthetic factory settlement can release the fence; merely ERROR/PID0
        // or dropping the boot future cannot. No native leaf is inferred from this model.
        use crate::fc::Vmm;
        h.host.recover_stopped("m_failed_launch").await.unwrap();
        let turn = e.lock.lock().await;
        h.m.refresh_launch_reservation(&e);
        drop(turn);
        assert_eq!(
            committed(&h.m.inner.machines.lock().unwrap()).0.memory_mb,
            0
        );
        h.m.destroy("m_failed_launch", None).await.unwrap();
    }
}

#[tokio::test]
async fn positively_settled_preboot_failure_does_not_charge_all_error_records() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let e = h.add("m_no_launch", state::CREATED, 512);
    {
        let mut r = e.rec.lock().unwrap();
        r.image = IMAGE.into();
        r.volume = None;
    }
    h.disks(&e).await;
    h.host.boots(Boots::RefusedLaunch);
    assert!(h.m.start("m_no_launch", None).await.is_err());
    assert_eq!(e.snapshot().state, state::ERROR);
    assert_eq!(
        committed(&h.m.inner.machines.lock().unwrap()).0.memory_mb,
        0
    );
    assert!(h
        .m
        .memory_admission(&h.m.inner.machines.lock().unwrap())
        .is_ok());
    h.m.destroy("m_no_launch", None).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn adopted_exit_during_blocked_recovery_restarts_only_after_open() {
    use crate::fc::Vmm;
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let e = h.add("m_adopted_exit", state::RUNNING, 256);
    {
        let mut r = e.rec.lock().unwrap();
        r.image = IMAGE.into();
        r.volume = None;
        r.restart.policy = "always".into();
    }
    h.disks(&e).await;
    let pid = h.host.left_running(
        "m_adopted_exit",
        &h.m.inner.cfg.run_dir().join("m_adopted_exit"),
    );
    e.rec.lock().unwrap().pid = pid;
    h.host
        .initialize_recovery(&[fc::RecoveryMachine {
            id: "m_adopted_exit".into(),
            pid,
        }])
        .await
        .unwrap();
    h.m.recover().await.unwrap();
    h.host.exit(pid, 7, false);
    tokio::time::advance(Duration::from_secs(20)).await;
    assert_eq!(e.snapshot().state, state::RUNNING);
    assert_eq!(e.snapshot().restarts, 0);
    assert!(!h.host.calls().iter().any(|call| call.starts_with("boot ")));
    let changed = e.changed.notified();
    tokio::pin!(changed);
    changed.as_mut().enable();
    h.host.open_recovery().unwrap();
    h.m.resume_recovery_workers();
    changed.await;
    assert_eq!(e.snapshot().state, state::STOPPED);
    assert!(e.snapshot().exit.as_ref().unwrap().restarting);
    let manager = h.m.clone();
    let running = tokio::spawn(async move {
        manager
            .wait("m_adopted_exit", Until::Running, Duration::from_secs(30))
            .await
    });
    tokio::time::advance(Duration::from_secs(10)).await;
    // Only the restart timer is virtual. The owned disk-helper fixture completes under
    // the real clock, so auto-advance cannot expire its event wait ahead of OS I/O.
    tokio::time::resume();
    running.await.unwrap().unwrap();
    assert_eq!(e.snapshot().state, state::RUNNING);
    assert_eq!(e.snapshot().restarts, 1);
    h.m.destroy("m_adopted_exit", None).await.unwrap();
}

#[tokio::test]
async fn pending_launch_reconciliation_cannot_use_an_old_epoch_during_an_active_start() {
    let h = harness("10.64.0.0/22", 4096).await;
    let e = h.add("m_start_window", state::STARTING, 512);
    e.launch_pending
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let turn = e.lock.lock().await;
    h.m.tick().await;
    assert!(e.launch_pending.load(std::sync::atomic::Ordering::SeqCst));
    assert!(h
        .m
        .memory_admission(&h.m.inner.machines.lock().unwrap())
        .is_err());
    e.set_state(state::ERROR, |_| None);
    drop(turn);
    // This explicit synthetic factory has no child; a quiescent subsequent tick may
    // now consume its positive no-launch result and release the conservative hold.
    h.m.tick().await;
    assert!(!e.launch_pending.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        committed(&h.m.inner.machines.lock().unwrap()).0.memory_mb,
        0
    );
}
