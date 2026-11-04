//! A VMM's cgroup leaf goes once its VMM is gone (ADR 0099).
use super::*;

fn leaf(h: &Harness, id: &str, cpu_usec: u64) {
    h.set_cgroup(
        id,
        Some(fc::CgroupUse {
            cpu_usec,
            memory_bytes: 0,
            ..Default::default()
        }),
    );
}

fn has_leaf(h: &Harness, id: &str) -> bool {
    h.host.cgroups.lock().unwrap().contains_key(id)
}

/// The leaf goes in the watcher's task, a moment after the state settles.
async fn leaf_gone(h: &Harness, id: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while has_leaf(h, id) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_vmm_that_goes_leaves_no_leaf_and_its_last_cpu_is_counted() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    for (name, pid) in [("killed", 1000), ("exited", 1001)] {
        let m = h.m.create_made(h.request(name)).await.unwrap();
        let e = h.m.entry(&m.id).unwrap();
        leaf(&h, &m.id, 5_000_000);
        // A kill, then an exit with the init's report: both are a VMM that went.
        if name == "exited" {
            h.host.exit(pid, 0, false);
        }
        h.host.gone(pid);
        let r = settled(&e).await;
        assert_eq!(r.state, state::STOPPED);
        leaf_gone(&h, &m.id).await;
        // Counted before the leaf, the only place it is read, was removed.
        assert_eq!(e.meter.lock().unwrap().counted().cpu_seconds, 5.0);
    }
}

#[tokio::test]
async fn a_running_machine_and_a_busy_one_keep_their_leaf() {
    let h = harness("10.64.0.0/22", 4096).await;
    let running = h.add("m_run", state::RUNNING, 128);
    let stopping = h.add("m_stopping", state::STOPPING, 128);
    let stopped = h.add("m_busy", state::STOPPED, 128);
    for id in ["m_run", "m_stopping", "m_busy"] {
        leaf(&h, id, 1);
    }
    assert!(!h.m.retire_idle_leaf(&running).await.unwrap());
    assert!(!h.m.retire_idle_leaf(&stopping).await.unwrap());
    // A start, a stop or a destroy under way holds the machine's lock: its leaf is not touched.
    let turn = stopped.lock.lock().await;
    assert!(!h.m.retire_idle_leaf(&stopped).await.unwrap());
    drop(turn);
    assert!(["m_run", "m_stopping", "m_busy"]
        .iter()
        .all(|id| has_leaf(&h, id)));
    assert!(h.m.retire_idle_leaf(&stopped).await.unwrap());
    assert!(!has_leaf(&h, "m_busy"));
}

#[tokio::test]
async fn a_refused_removal_is_the_next_passes_and_counts_the_cpu_once() {
    let h = harness("10.64.0.0/22", 4096).await;
    let e = h.add("m_late", state::STOPPED, 128);
    e.meter.lock().unwrap().boot(0);
    leaf(&h, "m_late", 7_000_000);
    h.host.refuse_retirement.store(true, Relaxed);
    assert!(h.m.retire_idle_leaf(&e).await.is_err());
    h.m.sweep_leaves().await;
    assert!(has_leaf(&h, "m_late"));
    assert_eq!(h.m.inner.stats.leaves_retire_failed.load(Relaxed), 1);
    h.host.refuse_retirement.store(false, Relaxed);
    h.m.sweep_leaves().await;
    assert!(!has_leaf(&h, "m_late"));
    assert_eq!(e.meter.lock().unwrap().counted().cpu_seconds, 7.0);
}

#[tokio::test]
async fn a_pass_is_bounded_and_says_how_many_leaves_nothing_explains() {
    let h = harness("10.64.0.0/22", 4096).await;
    let stopped = 130;
    for i in 0..stopped {
        let id = format!("m_s{i}");
        h.add(&id, state::STOPPED, 64);
        leaf(&h, &id, 1);
    }
    h.add("m_up", state::RUNNING, 64);
    leaf(&h, "m_up", 1);
    // No record owns it: the start's sweep removes it, a pass only counts it.
    leaf(&h, "m_nobody", 1);
    h.m.sweep_leaves().await;
    let seen = h.m.inner.stats.leaves.lock().unwrap().unwrap();
    assert_eq!((seen.total, seen.idle), (4, 3), "128 of 130 retired");
    assert_eq!(h.m.inner.stats.leaves_retired.load(Relaxed), 128);
    h.m.sweep_leaves().await;
    let seen = h.m.inner.stats.leaves.lock().unwrap().unwrap();
    assert_eq!((seen.total, seen.idle), (2, 1));
    assert!(has_leaf(&h, "m_up") && has_leaf(&h, "m_nobody"));
    let text = h.m.metrics();
    for want in [
        "briqyard_cgroup_leaves 2",
        "briqyard_cgroup_leaves_idle 1",
        "briqyard_cgroup_leaves_retired_total 130",
        "briqyard_cgroup_leaves_retire_failed_total 0",
    ] {
        assert!(text.lines().any(|l| l == want), "{want}\n{text}");
    }
}

#[tokio::test]
async fn a_leaf_that_is_always_refused_does_not_hold_back_the_ones_behind_it() {
    let h = harness("10.64.0.0/22", 4096).await;
    // More refused leaves than a pass takes: whatever order the directory lists them in, the
    // good ones are reached once the refused have been tried and put last.
    for i in 0..150 {
        let id = format!("m_bad{i}");
        h.add(&id, state::STOPPED, 64);
        leaf(&h, &id, 1);
        h.host.refuse_retirement_of.lock().unwrap().insert(id);
    }
    for i in 0..50 {
        let id = format!("m_ok{i}");
        h.add(&id, state::STOPPED, 64);
        leaf(&h, &id, 1);
    }
    for _ in 0..3 {
        h.m.sweep_leaves().await;
    }
    let good_left = (0..50)
        .filter(|i| has_leaf(&h, &format!("m_ok{i}")))
        .count();
    assert_eq!(good_left, 0);
    assert!((0..150).all(|i| has_leaf(&h, &format!("m_bad{i}"))));
    let seen = h.m.inner.stats.leaves.lock().unwrap().unwrap();
    assert_eq!((seen.total, seen.idle), (150, 150));
    assert!(h.m.inner.stats.leaves_retire_failed.load(Relaxed) >= 150);
    assert!(h.m.metrics().lines().any(|l| l
        .starts_with("briqyard_cgroup_leaves_retire_failed_total ")
        && l != "briqyard_cgroup_leaves_retire_failed_total 0"));
}

#[tokio::test]
async fn startup_orphans_wait_for_collection_and_backlog_stays_visible() {
    let h = harness("10.64.0.0/22", 4096).await;
    for i in 0..260 {
        leaf(&h, &format!("m_orphan{i}"), 1);
    }
    h.m.sweep_orphans().await.unwrap();
    assert_eq!(h.host.cgroups.lock().unwrap().len(), 260);
    h.m.sweep_leaves().await;
    let seen = h.m.inner.stats.leaves.lock().unwrap().unwrap();
    assert_eq!((seen.total, seen.idle), (132, 132));
    h.m.sweep_leaves().await;
    assert_eq!(h.m.inner.stats.leaves.lock().unwrap().unwrap().idle, 4);
    h.m.sweep_leaves().await;
    assert_eq!(h.m.inner.stats.leaves.lock().unwrap().unwrap().idle, 0);
}
