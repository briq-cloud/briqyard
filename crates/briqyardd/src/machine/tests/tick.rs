//! Tests of the sleeper's pass.

use super::*;

#[tokio::test]
async fn the_tick_sleeps_idle_machines_and_resumes_destroys() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let idle = h.m.create_made(h.request("idle")).await.unwrap();
    let mut forever = h.request("forever");
    forever.sleep = "never".into();
    let forever = h.m.create_made(forever).await.unwrap();
    let fresh = h.m.create_made(h.request("fresh")).await.unwrap();
    let long_ago = Some(Utc::now() - chrono::Duration::hours(1));
    for id in [&idle.id, &forever.id] {
        h.m.entry(id).unwrap().rec.lock().unwrap().last_used_at = long_ago;
    }
    let gone = h.add("m_gone", state::DESTROYING, 256);
    h.disks(&gone).await;
    h.host.calls();
    h.m.tick().await;
    let idle = h.m.get(&idle.id).unwrap();
    assert_eq!(
        (idle.state.as_str(), idle.stopped_reason.as_str()),
        (state::STOPPED, stop::IDLE)
    );
    assert_eq!(h.m.get(&forever.id).unwrap().state, state::RUNNING);
    assert_eq!(h.m.get(&fresh.id).unwrap().state, state::RUNNING);
    assert!(matches!(h.m.get("m_gone"), Err(MError::NotFound)));
    assert!(!h.pool.dev().join("byard/m/m_gone").exists());
    let calls = h.host.calls();
    assert_eq!(
        calls.iter().filter(|c| c.starts_with("shutdown ")).count(),
        1
    );
    // Asleep, not stopped on request: use wakes it.
    let woken =
        h.m.exec(
            &idle.id,
            api::ExecRequest {
                cmd: vec!["true".into()],
                wake: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(woken.exit_code, 0);
    let idle = h.m.get(&idle.id).unwrap();
    assert_eq!(idle.state, state::RUNNING);
    assert!(idle.last_used_at > long_ago);
}

#[tokio::test]
async fn a_suspend_resumes_on_the_next_start() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("web")).await.unwrap();
    h.host.calls();
    let slept =
        h.m.stop(&m.id, Duration::from_secs(1), true, None)
            .await
            .unwrap();
    assert!(slept.suspended);
    assert_eq!(slept.state, state::STOPPED);
    let calls = h.host.calls();
    assert_eq!(&calls[..2], ["snapshot 1000 synced", "kill 1000"]);
    let back = h.m.start(&m.id, None).await.unwrap();
    assert!(!back.suspended);
    assert_eq!(back.state, state::RUNNING);
    let calls = h.host.calls();
    assert!(
        calls.iter().any(|c| c.ends_with(" resume=true")),
        "{calls:?}"
    );
    // A resume is not a boot.
    assert_eq!(h.stored(&m.id).unwrap().boots, 1);
    use std::sync::atomic::Ordering::Relaxed;
    assert_eq!(h.m.inner.stats.resumes.load(Relaxed), 1);
}

#[tokio::test]
async fn touches_are_written_once_by_the_tick() {
    let h = harness("10.64.0.0/22", 4096).await;
    let e = h.add("m_t", state::STOPPED, 256);
    h.m.save(&e).unwrap();
    // A write is told by content, not by the file's time (Linux stamps files with a coarse
    // clock): a mark put in the stored record only, which any write from memory removes.
    let mark = || {
        let mut r = h.stored("m_t").unwrap();
        r.metadata.insert("unwritten".into(), "yes".into());
        h.m.inner.store.put("machines", "m_t", &r).unwrap();
    };
    let unwritten = || h.stored("m_t").unwrap().metadata.contains_key("unwritten");
    let before = h.stored("m_t").unwrap();
    mark();
    for _ in 0..10 {
        h.m.touch("m_t").unwrap();
    }
    let used = e.snapshot().last_used_at;
    assert!(used.is_some());
    // Memory has the use, the API reads it there, and the disk was not written.
    assert_eq!(h.m.get("m_t").unwrap().last_used_at, used);
    assert!(unwritten());
    // The tick writes it once, as the machine is: `updated_at` stays.
    h.m.tick().await;
    let stored = h.stored("m_t").unwrap();
    assert!(!unwritten());
    assert_eq!(stored.last_used_at, used);
    assert_eq!(stored.updated_at, before.updated_at);
    // Nothing moved since: the next tick writes nothing.
    mark();
    h.m.tick().await;
    assert!(unwritten());
    // A change to the machine carries the use with it, and the tick has nothing left.
    h.m.touch("m_t").unwrap();
    e.set_state(state::STARTING, |_| None);
    h.m.save(&e).unwrap();
    assert_eq!(
        h.stored("m_t").unwrap().last_used_at,
        e.snapshot().last_used_at
    );
    mark();
    h.m.tick().await;
    assert!(unwritten());
}

#[tokio::test]
async fn a_use_never_writes_back_a_machine_that_is_gone_or_busy() {
    let h = harness("10.64.0.0/22", 4096).await;
    let e = h.add("m_u", state::STOPPED, 256);
    h.m.save(&e).unwrap();
    h.m.touch("m_u").unwrap();
    // A transition holds the machine: the flush leaves it to the transition.
    let turn = e.lock.try_lock().unwrap();
    h.m.flush_use(&e).unwrap();
    assert_eq!(h.stored("m_u").unwrap().last_used_at, None);
    assert!(e.unsaved_use.load(Relaxed));
    // The destroy that held it removed it: the flush writes nothing back.
    h.m.inner.machines.lock().unwrap().remove("m_u");
    h.m.inner.store.delete("machines", "m_u").unwrap();
    drop(turn);
    h.m.flush_use(&e).unwrap();
    assert!(h.stored("m_u").is_none());
}

#[tokio::test(start_paused = true)]
async fn idle_machines_go_to_sleep_together() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let long_ago = Some(Utc::now() - chrono::Duration::hours(1));
    for name in ["a", "b", "c"] {
        let m = h.m.create_made(h.request(name)).await.unwrap();
        h.m.entry(&m.id).unwrap().rec.lock().unwrap().last_used_at = long_ago;
    }
    // Each guest takes 3 s to stop: one after another, the tick would take 9.
    h.host.stops_take(Duration::from_secs(3));
    let t0 = tokio::time::Instant::now();
    h.m.tick().await;
    let took = t0.elapsed();
    assert!(
        took >= Duration::from_secs(3) && took < Duration::from_secs(6),
        "{took:?}"
    );
    for m in h.m.list(None, &[]) {
        assert_eq!(
            (m.state.as_str(), m.stopped_reason.as_str()),
            (state::STOPPED, stop::IDLE),
            "{}",
            m.name
        );
    }
}

#[tokio::test(start_paused = true)]
async fn the_tick_never_writes_back_the_record_of_a_machine_being_destroyed() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let p = api::Probe {
        failure_threshold: 1,
        ..http_probe(8080)
    };
    let m =
        h.m.create_made(h.probed("web", readiness(p)))
            .await
            .unwrap();
    for code in [200, 500, 200, 500] {
        h.host.http(&m.ip, 8080, code);
        eventually("flipped", || h.m.get(&m.id).unwrap().ready == (code == 200)).await;
    }
    let due = Utc::now() + chrono::Duration::minutes(11);
    // A transition holds the machine (a destroy does, from its stop to its record's
    // delete): the tick leaves it alone, to log its flips later.
    let e = h.m.entry(&m.id).unwrap();
    let held = e.lock.clone().lock_owned().await;
    let before = h.events_of(&m.id).len();
    h.m.log_folded(due);
    assert_eq!(h.events_of(&m.id).len(), before);
    drop(held);
    // The destroy logs the folded flips itself; a tick after it writes nothing back.
    h.m.destroy(&m.id, None).await.unwrap();
    h.m.log_folded(due);
    assert!(h.stored(&m.id).is_none());
    let reasons = h.reasons(&m.id);
    assert_eq!(reasons.last().map(String::as_str), Some("destroyed"));
}
