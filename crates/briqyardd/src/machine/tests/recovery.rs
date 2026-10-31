//! Tests of the daemon's start: loading, recovery, the sweep, forks and the hand-over.

use super::*;

#[tokio::test]
async fn a_namespace_outside_the_range_is_refused_at_load() {
    let h = harness("10.64.0.0/22", 4096).await;
    let t = NamespaceRec {
        id: "t1".into(),
        subnet_index: 4,
        created_at: Utc::now(),
        quota: api::Quota::default(),
    };
    h.m.inner
        .store
        .put(crate::store::NAMESPACES, "t1", &t)
        .unwrap();
    let err = h.m.load().unwrap_err();
    assert!(format!("{err:#}").contains("namespace t1"), "{err:#}");
    assert!(h.m.inner.namespaces.lock().unwrap().is_empty());
    // In range: loaded with its subnet.
    let t = NamespaceRec {
        subnet_index: 3,
        ..t
    };
    h.m.inner
        .store
        .put(crate::store::NAMESPACES, "t1", &t)
        .unwrap();
    h.m.load().unwrap();
    assert_eq!(h.m.namespaces()[0].router, "10.64.3.1");
}

#[tokio::test]
async fn an_endpoint_port_outside_the_range_is_refused_at_load() {
    // A port the daemon's table does not keep for allowed_clients: refused, not opened.
    let h = harness_config(|c| c.ingress.tcp_ports = "30000-32767".into()).await;
    let ep = EndpointRec {
        id: "ep_1".into(),
        machine_id: "m_1".into(),
        namespace: "t1".into(),
        port: 5432,
        protocol: "tcp".into(),
        host_port: Some(20001),
        host: String::new(),
        created_at: Utc::now(),
    };
    h.m.inner.store.put("endpoints", "ep_1", &ep).unwrap();
    let err = format!("{:#}", h.m.load().unwrap_err());
    assert_eq!(
        err,
        "endpoint ep_1 (machine m_1) holds host port 20001, outside ingress.tcp_ports \
             30000-32767: put the range back, or remove the endpoint"
    );
    assert!(h.m.inner.endpoints.lock().unwrap().is_empty());
    let ep = EndpointRec {
        host_port: Some(30001),
        ..ep
    };
    h.m.inner.store.put("endpoints", "ep_1", &ep).unwrap();
    h.m.load().unwrap();
    assert_eq!(h.m.all_endpoints().len(), 1);
}

#[tokio::test]
async fn a_namespace_id_is_checked_before_it_names_a_file() {
    let h = harness("10.64.0.0/22", 4096).await;
    for bad in ["", "../x", "a/b", "A"] {
        let req = api::CreateMachineRequest {
            namespace: bad.into(),
            name: "db".into(),
            image: "alpine".into(),
            size: api::Size {
                vcpus: 1,
                memory_mb: 256,
                cpu_millis: None,
            },
            ..Default::default()
        };
        assert!(
            matches!(h.m.create_made(req).await, Err(MError::Invalid(_))),
            "{bad}"
        );
        assert!(
            matches!(h.m.delete_namespace(bad).await, Err(MError::Invalid(_))),
            "{bad}"
        );
        assert!(
            matches!(h.m.backups(bad).await, Err(MError::Invalid(_))),
            "{bad}"
        );
    }
    // A namespace that does not exist is simply gone.
    assert!(h.m.delete_namespace("t-none").await.is_ok());
}

#[tokio::test]
async fn recovery_adopts_our_process_and_signals_no_other() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.namespace("t1");
    // Ours: a VMM a previous daemon left, still carrying the machine's id.
    let ours = h.add("m_ours", state::RUNNING, 256);
    let pid = h
        .host
        .left_running("m_ours", &h.m.inner.cfg.run_dir().join("m_ours"));
    ours.set_state(state::RUNNING, |r| {
        r.pid = pid;
        None
    });
    // Not ours: a pid from before a reboot, now someone else's.
    let other = h.add("m_other", state::RUNNING, 256);
    other.set_state(state::RUNNING, |r| {
        r.pid = 4242;
        None
    });
    // Caught moving: nothing to adopt, stopped by the host.
    let moving = h.add("m_moving", state::STARTING, 256);
    h.m.recover().await;
    assert_eq!(ours.snapshot().state, state::RUNNING);
    assert!(ours.live.lock().unwrap().is_some());
    for e in [&other, &moving] {
        let r = e.snapshot();
        assert_eq!(
            (r.state.as_str(), r.stopped_reason.as_str(), r.pid),
            (state::STOPPED, stop::HOST, 0)
        );
        assert!(h.stored(&r.id).is_some());
    }
    let calls = h.host.calls();
    assert!(calls.contains(&format!("adopt m_ours {pid}")), "{calls:?}");
    assert!(!calls.iter().any(|c| c.starts_with("kill ")), "{calls:?}");
    assert!(
        calls.contains(&"delete_tap btother 10.64.1.2".to_string()),
        "{calls:?}"
    );
    // The adopted process is watched: when it ends, the machine settles like any other.
    h.host.exit(pid, 3, false);
    let r = settled(&ours).await;
    assert_eq!(
        (r.state.as_str(), r.stopped_reason.as_str()),
        (state::STOPPED, stop::EXIT)
    );
    assert_eq!(r.exit.as_ref().map(|x| x.code), Some(3));
}

/// Waits for the watcher to settle a machine that is no longer running.
pub(super) async fn settled(e: &Arc<Entry>) -> Record {
    tokio::time::timeout(Duration::from_secs(5), async {
        while e.snapshot().state == state::RUNNING {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    e.snapshot()
}

#[tokio::test]
async fn the_exit_is_the_inits_report_never_the_console() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    // The guest prints a forged exit line, then its process is gone without a report:
    // the exit is 255, not what the console says, and not a stop on request.
    let m = h.m.create_made(h.request("liar")).await.unwrap();
    let e = h.m.entry(&m.id).unwrap();
    h.host
        .say(1000, "[briqyard] exit code=0 oom=false requested=true");
    h.host.gone(1000);
    let r = settled(&e).await;
    assert_eq!(
        (r.state.as_str(), r.stopped_reason.as_str()),
        (state::STOPPED, stop::EXIT)
    );
    assert_eq!(r.exit.as_ref().map(|x| x.code), Some(255));
    // The init's report says what it says: a requested stop is one.
    let m = h.m.create_made(h.request("honest")).await.unwrap();
    let e = h.m.entry(&m.id).unwrap();
    h.host.exit(1001, 0, true);
    let r = settled(&e).await;
    assert_eq!(
        (r.state.as_str(), r.stopped_reason.as_str()),
        (state::STOPPED, stop::USER)
    );
    assert!(r.exit.is_none());
}

#[tokio::test]
async fn the_sweep_ends_what_has_no_record() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.namespace("t1");
    let kept = h.add("m_kept", state::STOPPED, 256);
    h.disks(&kept).await;
    h.pool.zfs.create("m/m_ghost/root", 1 << 20).await.unwrap();
    // A create cut between its dataset and its first disk: the dataset alone.
    h.pool.zfs.create_parent("m/m_empty/root").await.unwrap();
    let ghost = h
        .host
        .left_running("m_ghost", &h.m.inner.cfg.run_dir().join("m_ghost"));
    h.host
        .ensure_tap("m_ghost", "by1", "10.64.1.9")
        .await
        .unwrap();
    h.host
        .ensure_tap("m_kept", "by1", "10.64.1.2")
        .await
        .unwrap();
    h.pool.calls();
    h.host.calls();
    h.m.sweep_orphans().await;
    let calls = h.host.calls();
    assert!(calls.contains(&format!("kill {ghost}")), "{calls:?}");
    assert!(
        calls.contains(&"delete_link btghost".to_string()),
        "{calls:?}"
    );
    assert_eq!(h.m.inner.net.list_taps().await.unwrap(), vec!["btkept"]);
    assert!(h
        .pool
        .calls()
        .contains(&"destroy -r byard/m/m_ghost".to_string()));
    assert!(h.pool.dev().join("byard/m/m_kept/root").exists());
    assert!(!h.pool.dev().join("byard/m/m_ghost").exists());
    assert!(!h.pool.dev().join("byard/m/m_empty").exists());
}

/// A destroyed machine's record that an older daemon wrote back after the destroy
/// (`destroying`), whose address a machine holds now: removed at load and never destroyed
/// again, which would end the counters, and the limits, of that machine's address.
#[tokio::test]
async fn a_record_written_back_after_its_destroy_is_removed_at_load() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let mut req = h.request("web");
    req.start = Some(false);
    let live = h.m.create_made(req).await.unwrap();
    let mut old = h.stored(&live.id).unwrap();
    old.id = "m_00000000000a".into();
    old.name = "old".into();
    old.state = state::DESTROYING.into();
    h.m.inner.store.put("machines", &old.id, &old).unwrap();
    // A record whose address nobody else holds is a destroy to finish, as before.
    let mut cut = old.clone();
    cut.id = "m_00000000000b".into();
    cut.ip = "10.64.1.200".into();
    h.m.inner.store.put("machines", &cut.id, &cut).unwrap();
    // The next daemon reads them.
    h.m.inner.machines.lock().unwrap().clear();
    h.m.load().unwrap();
    assert!(h.stored(&old.id).is_none());
    assert!(h.m.entry(&old.id).is_err());
    assert!(h.m.entry(&cut.id).is_ok());
    h.m.tick().await;
    assert!(h.stored(&cut.id).is_none());
    assert!(h.host.counted.lock().unwrap().contains_key(&live.ip));
    assert_eq!(h.m.get(&live.id).unwrap().state, state::CREATED);
}

// --- fork snapshots ---

impl Harness {
    /// A fork of `src`, both disks, started.
    pub(in crate::machine) async fn fork(&self, src: &str, name: &str) -> api::Machine {
        let mut req = self.request(name);
        req.image = String::new();
        req.fork = Some(api::ForkSpec {
            machine_id: src.into(),
            copy: String::new(),
        });
        self.m.create_made(req).await.unwrap()
    }

    pub(in crate::machine) fn snapshot_exists(&self, ds: &str, snap: &str) -> bool {
        self.pool.dev().join(format!("byard/{ds}@{snap}")).exists()
    }
}

#[tokio::test]
async fn a_destroyed_fork_frees_its_snapshot_on_the_source() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let src = h.m.create_made(h.request("src")).await.unwrap();
    let fork = h.fork(&src.id, "fork").await;
    let (root, snap) = (format!("m/{}/root", src.id), format!("fork-{}", fork.id));
    assert!(h.snapshot_exists(&root, &snap));
    h.pool.calls();
    h.m.destroy(&fork.id, None).await.unwrap();
    // Nothing clones the snapshot once the fork is gone: it goes with the fork.
    let calls = h.pool.calls();
    assert!(
        calls.contains(&format!("destroy byard/{root}@{snap}")),
        "{calls:?}"
    );
    assert!(!h.snapshot_exists(&root, &snap));
    assert!(h.pool.dev().join(format!("byard/{root}")).exists());
    // Two forks of one snapshot: the snapshot stays until the last one goes.
    let a = h.fork(&src.id, "a").await;
    let snap_a = format!("fork-{}", a.id);
    h.pool
        .zfs
        .clone_snapshot(&root, &snap_a, "m/other/root")
        .await
        .unwrap();
    h.m.destroy(&a.id, None).await.unwrap();
    assert!(h.snapshot_exists(&root, &snap_a));
    // A snapshot that is not a fork's (the image's base) is never touched.
    h.pool.calls();
    h.m.destroy(&src.id, None).await.unwrap();
    assert!(!h
        .pool
        .calls()
        .iter()
        .any(|c| c.starts_with("destroy byard/images/")));
}

#[tokio::test]
async fn a_destroyed_source_leaves_its_fork_whole_and_frees_what_it_took_over() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let src = h.m.create_made(h.request("src")).await.unwrap();
    let fork = h.fork(&src.id, "fork").await;
    let fork_root = format!("m/{}/root", fork.id);
    let snap = format!("fork-{}", fork.id);
    h.m.destroy(&src.id, None).await.unwrap();
    // The fork was promoted and owns the snapshot it was made from; with the source gone
    // nothing clones that snapshot, so it goes too.
    assert!(h.pool.dev().join(format!("byard/{fork_root}")).exists());
    assert!(!h.pool.dev().join(format!("byard/m/{}", src.id)).exists());
    assert!(!h.snapshot_exists(&fork_root, &snap));
    // It took its source's origin over, as ZFS's promote does: the image's.
    let origin = h.pool.zfs.origin(&fork_root).await.unwrap().unwrap();
    assert!(origin.0.starts_with("images/"), "{origin:?}");
    assert_eq!(h.m.get(&fork.id).unwrap().state, state::RUNNING);
    h.m.destroy(&fork.id, None).await.unwrap();
}

#[tokio::test]
async fn the_sweep_frees_fork_snapshots_with_no_clone() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.namespace("t1");
    let kept = h.add("m_kept", state::STOPPED, 256);
    h.disks(&kept).await;
    let child = h.add("m_child", state::STOPPED, 256);
    let z = &h.pool.zfs;
    // One snapshot a destroy failed to free, one whose clone is a machine of ours.
    z.snapshot("m/m_kept/root", "fork-gone").await.unwrap();
    z.snapshot("m/m_kept/root", "fork-m_child").await.unwrap();
    z.clone_snapshot(
        "m/m_kept/root",
        "fork-m_child",
        &child.snapshot().root_dataset(),
    )
    .await
    .unwrap();
    // One the record names, one a daemon that died before the record left (ADR 0031).
    z.snapshot("m/m_kept/root", "s_mine").await.unwrap();
    z.snapshot("m/m_kept/root", "s_lost").await.unwrap();
    kept.rec.lock().unwrap().snapshots.push(SnapshotRec {
        id: "s_mine".into(),
        name: None,
        created_at: Utc::now(),
        disks: vec!["root".into()],
        memory: None,
        vmm_version: String::new(),
    });
    h.m.sweep_orphans().await;
    assert!(!h.snapshot_exists("m/m_kept/root", "fork-gone"));
    assert!(h.snapshot_exists("m/m_kept/root", "fork-m_child"));
    assert!(h.snapshot_exists("m/m_kept/root", "s_mine"));
    assert!(!h.snapshot_exists("m/m_kept/root", "s_lost"));
}

#[tokio::test]
async fn a_snapshot_taken_under_another_vmm_is_not_resumed() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("web")).await.unwrap();
    let suspend = || h.m.stop(&m.id, Duration::from_secs(1), true, None);
    assert!(suspend().await.unwrap().suspended);
    // Firecracker (or the host kernel) changed under the suspended machine: a cold boot.
    *h.host.vmm_version.lock().unwrap() = "v1.18.0/test".into();
    h.host.calls();
    let back = h.m.start(&m.id, None).await.unwrap();
    assert!(!back.suspended);
    assert!(h.host.calls().iter().any(|c| c.ends_with(" resume=false")));
    let starting = h
        .events_of(&m.id)
        .into_iter()
        .rev()
        .find(|e| e.reason == "starting")
        .unwrap();
    assert_eq!(
        starting.message,
        "booting: its memory snapshot was taken under v1.17.0/test, the host runs v1.18.0/test"
    );
    assert_eq!(
        starting.data,
        Some(json!({"resume": false, "snapshot_vmm": "v1.17.0/test"}))
    );
    assert_eq!(back.vmm_version, "v1.18.0/test");
    // Taken and resumed under the same one: a resume.
    assert!(suspend().await.unwrap().suspended);
    h.host.calls();
    h.m.start(&m.id, None).await.unwrap();
    assert!(h.host.calls().iter().any(|c| c.ends_with(" resume=true")));
    // A snapshot from before the versions were recorded says none: cold, once.
    assert!(suspend().await.unwrap().suspended);
    h.m.entry(&m.id)
        .unwrap()
        .rec
        .lock()
        .unwrap()
        .vmm_version
        .clear();
    h.host.calls();
    h.m.start(&m.id, None).await.unwrap();
    assert!(h.host.calls().iter().any(|c| c.ends_with(" resume=false")));
}

#[tokio::test]
async fn a_hand_over_leaves_every_machine_running_for_the_next_daemon() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("web")).await.unwrap();
    h.m.touch(&m.id).unwrap();
    h.host.calls();
    let _held = h.m.hand_over().await;
    assert_eq!(
        h.host.calls(),
        Vec::<String>::new(),
        "nothing stopped, suspended or killed"
    );
    let r = h.stored(&m.id).unwrap();
    assert_eq!(
        (r.state.as_str(), r.pid),
        (state::RUNNING, m_pid(&h, &m.id))
    );
    assert!(
        r.last_used_at >= m.last_used_at,
        "the last use is on the record"
    );
    // What the next daemon's start finds: the machine, still running, adopted.
    assert_eq!(h.m.recover().await, (1, 0, 0));
}

#[tokio::test]
async fn readiness_crosses_a_hand_over() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    // A period far past the test: no probe runs, so only what was carried decides.
    let slow = api::Probe {
        http: Some(api::HttpProbe {
            port: 8080,
            path: "/".into(),
        }),
        period_sec: 3600,
        ..Default::default()
    };
    let up =
        h.m.create_made(h.probed("up", readiness(slow.clone())))
            .await
            .unwrap();
    let down =
        h.m.create_made(h.probed("down", readiness(slow)))
            .await
            .unwrap();
    for id in [&up.id, &down.id] {
        assert!(!h.m.get(id).unwrap().ready);
    }
    h.m.entry(&up.id).unwrap().probe.lock().unwrap().ready = true;
    let held = h.m.hand_over().await;
    drop(held);
    // The next daemon's adoption: its probes start over, the ready one stays ready, and
    // the one that was not has to pass its probe.
    assert_eq!(h.m.recover().await, (2, 0, 0));
    assert!(h.m.get(&up.id).unwrap().ready, "ready as handed over");
    assert!(!h.m.get(&down.id).unwrap().ready);
    // Read once: a later start (a crash's adoption) carries nothing.
    assert_eq!(h.m.recover().await, (2, 0, 0));
    assert!(!h.m.get(&up.id).unwrap().ready, "a crash carries nothing");
}

#[test]
fn a_record_keeps_what_a_newer_daemon_wrote() {
    // A record with a field this daemon does not know (a newer one's, before a rollback).
    let mut v = serde_json::to_value(record()).unwrap();
    v["checkpoint"] = json!({"name": "before-migration", "vmm": "v1.18.0/x"});
    let r: Record = serde_json::from_value(v.clone()).unwrap();
    assert_eq!(r.rest.keys().collect::<Vec<_>>(), ["checkpoint"]);
    // Rewritten as it came: the field is kept, nothing else moves.
    assert_eq!(serde_json::to_value(&r).unwrap(), v);
    // A record of this daemon's carries nothing more.
    let mine = serde_json::to_value(record()).unwrap();
    let back: Record = serde_json::from_value(mine.clone()).unwrap();
    assert!(back.rest.is_empty());
    assert_eq!(serde_json::to_value(&back).unwrap(), mine);
}

#[tokio::test]
async fn a_hand_over_waits_for_a_transition_and_lets_none_begin() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let a = h.m.create_made(h.request("a")).await.unwrap();
    let b = h.m.create_made(h.request("b")).await.unwrap();
    // A stop under way when the hand-over is asked: its guest takes a while to end.
    *h.host.stops.lock().unwrap() = Duration::from_millis(300);
    let m = h.m.clone();
    let id = a.id.clone();
    let stop = tokio::spawn(async move { m.stop(&id, Duration::from_secs(5), false, None).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let held = h.m.hand_over().await;
    // The stop finished before the hand-over wrote anything: its record says so.
    assert_eq!(h.stored(&a.id).unwrap().state, state::STOPPED);
    assert!(stop.await.unwrap().is_ok());
    // While the hand-over's locks are held, a stop asked now does not begin.
    let m = h.m.clone();
    let id = b.id.clone();
    let late = tokio::spawn(async move { m.stop(&id, Duration::from_secs(5), false, None).await });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!late.is_finished());
    assert_eq!(h.stored(&b.id).unwrap().state, state::RUNNING);
    drop(held);
    late.await.unwrap().unwrap();
}

/// The machine's process as the manager holds it.
fn m_pid(h: &Harness, id: &str) -> u32 {
    h.m.entry(id).unwrap().snapshot().pid
}

#[tokio::test]
async fn a_daemons_start_boots_again_what_the_host_stopped() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let a = h.m.create_made(h.request("a")).await.unwrap();
    let b = h.m.create_made(h.request("b")).await.unwrap();
    let c = h.m.create_made(h.request("c")).await.unwrap();
    let mut never = h.request("d");
    never.sleep = "never".into();
    let d = h.m.create_made(never).await.unwrap();
    h.m.stop(&c.id, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    // The daemon's stop: every running machine suspended, stopped by the host.
    h.m.close().await;
    for id in [&a.id, &b.id, &d.id] {
        let r = h.stored(id).unwrap();
        assert_eq!(
            (r.state.as_str(), r.stopped_reason.as_str(), r.suspended),
            ("stopped", "host", true)
        );
    }
    // b's window ran out while the host was down; d never sleeps.
    let long_ago = Utc::now() - chrono::Duration::hours(2);
    h.m.entry(&b.id).unwrap().rec.lock().unwrap().last_used_at = Some(long_ago);
    h.m.entry(&d.id).unwrap().rec.lock().unwrap().last_used_at = Some(long_ago);
    h.host.calls();
    h.m.start_stopped_by_host();
    let running = |id: &str| h.m.get(id).unwrap().state == state::RUNNING;
    eventually("a and d running again", || running(&a.id) && running(&d.id)).await;
    let calls = h.host.calls();
    let boots: Vec<&String> = calls.iter().filter(|c| c.starts_with("boot ")).collect();
    assert_eq!(boots.len(), 2, "{calls:?}");
    assert!(
        boots.iter().all(|c| c.ends_with(" resume=true")),
        "{boots:?}"
    );
    // b sleeps on, wakeable; c was stopped on purpose.
    let b = h.m.get(&b.id).unwrap();
    assert_eq!(
        (b.state.as_str(), b.stopped_reason.as_str()),
        ("stopped", "host")
    );
    let c = h.m.get(&c.id).unwrap();
    assert_eq!(
        (c.state.as_str(), c.stopped_reason.as_str()),
        ("stopped", "user")
    );
    assert!(h.m.wake(&b.id, None).await.unwrap().state == state::RUNNING);
}

/// The record with `namespace` under its former name, as a host that ran before ADR 0055 wrote it.
fn written_as_tenant(rec: &impl Serialize) -> serde_json::Value {
    let mut v = serde_json::to_value(rec).unwrap();
    let o = v.as_object_mut().unwrap();
    let ns = o.remove("namespace").expect("the record has a namespace");
    o.insert("tenant".into(), ns);
    v
}

#[tokio::test]
async fn records_written_before_the_rename_still_load() {
    let h = harness("10.64.0.0/22", 4096).await;
    let store = &h.m.inner.store;
    let r = record();
    let ep = EndpointRec {
        id: "ep_1".into(),
        machine_id: r.id.clone(),
        namespace: r.namespace.clone(),
        port: 80,
        protocol: "http".into(),
        host_port: None,
        host: String::new(),
        created_at: Utc::now(),
    };
    store
        .put("machines", &r.id, &written_as_tenant(&r))
        .unwrap();
    store
        .put("endpoints", &ep.id, &written_as_tenant(&ep))
        .unwrap();
    let back: Record = store.get("machines", &r.id).unwrap().unwrap();
    assert_eq!(back.namespace, r.namespace);
    let back: EndpointRec = store.get("endpoints", &ep.id).unwrap().unwrap();
    assert_eq!(back.namespace, ep.namespace);
    // The namespaces' records stay in the directory they were first written to.
    assert_eq!(crate::store::NAMESPACES, "tenants");
}
