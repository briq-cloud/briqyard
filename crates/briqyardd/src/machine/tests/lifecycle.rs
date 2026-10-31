//! Tests of a machine's lifecycle: create, boot, start, stop, wake, destroy.

use super::*;

#[tokio::test]
async fn a_reservation_is_one_step() {
    // Eight starts race for the memory of two: never more than two may take it,
    // however they interleave.
    for _ in 0..20 {
        let h = harness("10.64.0.0/22", 1536).await;
        let entries: Vec<Arc<Entry>> = (0..8)
            .map(|i| h.add(&format!("m_{i}"), state::STOPPED, 512))
            .collect();
        let admitted = std::thread::scope(|s| {
            let handles: Vec<_> = entries
                .iter()
                .map(|e| s.spawn(|| h.m.reserve(e, None).is_ok()))
                .collect();
            handles
                .into_iter()
                .map(|j| j.join().unwrap())
                .filter(|ok| *ok)
                .count()
        });
        assert_eq!(admitted, 2);
        let (used, up, _) = h.m.usage();
        assert_eq!((used.memory_mb, up), (1536, 2));
    }
    // What was admitted is `starting`; what was not is untouched.
    let h = harness("10.64.0.0/22", 768).await;
    let a = h.add("m_a", state::STOPPED, 512);
    let b = h.add("m_b", state::STOPPED, 512);
    assert!(h.m.reserve(&a, None).is_ok());
    assert!(matches!(h.m.reserve(&b, None), Err(MError::Capacity(_))));
    assert_eq!(a.snapshot().state, state::STARTING);
    assert_eq!(b.snapshot().state, state::STOPPED);
    // A machine on its way down still holds its memory.
    a.set_state(state::STOPPING, |_| None);
    assert!(matches!(h.m.reserve(&b, None), Err(MError::Capacity(_))));
    assert!(admit(0, 100, 100).is_ok());
    assert!(admit(1, 100, 100).is_err());
    assert!(admit(u32::MAX, u32::MAX, 1).is_err());
}

#[tokio::test]
async fn a_machine_being_destroyed_is_not_started() {
    let h = harness("10.64.0.0/22", 4096).await;
    let e = h.add("m_d", state::DESTROYING, 512);
    for r in [
        h.m.start("m_d", None).await,
        h.m.wake("m_d", None).await,
        h.m.start_entry(&e, true)
            .await
            .map(|_| h.m.get("m_d").unwrap()),
    ] {
        match r {
            Err(MError::BadState(s)) => assert_eq!(s, state::DESTROYING),
            other => panic!("{other:?}"),
        }
    }
    // Refused before anything was touched: still destroying, no error recorded.
    let r = e.snapshot();
    assert_eq!(
        (r.state.as_str(), r.error.as_str()),
        (state::DESTROYING, "")
    );
}

#[tokio::test]
async fn wait_for_running_follows_the_state() {
    let h = harness("10.64.0.0/22", 4096).await;
    let e = h.add("m_w", state::STARTING, 512);
    let m = h.m.clone();
    let waiting =
        tokio::spawn(async move { m.wait("m_w", Until::Running, Duration::from_secs(30)).await });
    e.set_state(state::RUNNING, |_| None);
    assert_eq!(waiting.await.unwrap().unwrap().state, state::RUNNING);

    let e = h.add("m_e", state::STARTING, 512);
    let m = h.m.clone();
    let waiting =
        tokio::spawn(async move { m.wait("m_e", Until::Running, Duration::from_secs(30)).await });
    e.set_state(state::ERROR, |r| {
        r.error = "no init".into();
        None
    });
    match waiting.await.unwrap() {
        Err(MError::NotRunning(why)) => assert_eq!(why, "no init"),
        other => panic!("{other:?}"),
    }
    // Already settled: answered at once, without a change to wait for.
    assert_eq!(
        h.m.wait("m_w", Until::Running, Duration::from_secs(30))
            .await
            .unwrap()
            .state,
        state::RUNNING
    );
    assert!(matches!(
        h.m.wait("m_x", Until::Running, Duration::from_secs(1))
            .await,
        Err(MError::NotFound)
    ));
}

#[tokio::test]
async fn state_changed_at_moves_only_with_the_state() {
    let h = harness("10.64.0.0/22", 4096).await;
    let e = h.add("m_s", state::STOPPED, 512);
    let t0 = e.snapshot().state_changed_at;
    e.set_state(state::STOPPED, |r| {
        r.stopped_reason = stop::USER.into();
        None
    });
    e.touch();
    let r = e.snapshot();
    assert_eq!(r.state_changed_at, t0);
    // A use is not a change to the machine; a write of one is.
    assert_eq!(r.updated_at, t0);
    h.m.save(&e).unwrap();
    assert!(e.snapshot().updated_at > t0);
    e.set_state(state::STARTING, |_| None);
    let r = e.snapshot();
    assert!(r.state_changed_at > t0);
    assert_eq!(h.m.get("m_s").unwrap().state_changed_at, r.state_changed_at);
}

#[tokio::test]
async fn sleep_is_stored_as_the_api_says_it() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.add("m_n", state::STOPPED, 512);
    let set = |sleep: &str| api::UpdateMachineRequest {
        sleep: Some(sleep.into()),
        ..Default::default()
    };
    assert_eq!(
        h.m.update("m_n", set("never"), None).await.unwrap().sleep,
        "never"
    );
    assert_eq!(
        h.m.update("m_n", set(""), None).await.unwrap().sleep,
        "never"
    );
    assert_eq!(
        h.m.update("m_n", set("3h"), None).await.unwrap().sleep,
        "3h"
    );
    assert!(matches!(
        h.m.update("m_n", set("soon"), None).await,
        Err(MError::Invalid(_))
    ));
}

#[tokio::test]
async fn a_detached_transition_outlives_its_caller() {
    let go = Arc::new(Notify::new());
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (g, d) = (go.clone(), done.clone());
    let caller = tokio::spawn(async move {
        detached(async move {
            g.notified().await;
            d.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok::<(), MError>(())
        })
        .await
    });
    tokio::task::yield_now().await;
    // The client hangs up: the wait goes, the work does not.
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    go.notify_one();
    tokio::task::yield_now().await;
    assert!(done.load(std::sync::atomic::Ordering::SeqCst));
    // The task's own result comes back as is; a panic in it is an internal error.
    assert!(matches!(
        detached(async { Err::<(), MError>(MError::NotFound) }).await,
        Err(MError::NotFound)
    ));
    assert!(matches!(
        detached::<(), _>(async { panic!("boom") }).await,
        Err(MError::Other(_))
    ));
}

// --- transitions against the mock host ---

#[tokio::test]
async fn a_create_boots_the_machine_to_running() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let t0 = Utc::now();
    let m = h.m.create_made(h.request("web")).await.unwrap();
    assert_eq!(m.state, state::RUNNING);
    assert!(m.state_changed_at >= t0);
    assert!(m.started_at.is_some() && m.last_used_at.is_some());
    assert_eq!(
        m.sleeps_at,
        m.last_used_at.map(|t| t + chrono::Duration::minutes(30))
    );
    assert_eq!(
        (m.ip.as_str(), m.hostname.as_str()),
        ("10.64.1.2", "web.internal")
    );
    // The record on disk is the one in memory, running, with its pid.
    let stored = h.stored(&m.id).unwrap();
    assert_eq!(stored.state, state::RUNNING);
    assert_eq!(stored.pid, 1000);
    assert_eq!(stored.boots, 1);
    // The root disk is a clone of the image's snapshot; no volume, no data disk.
    let image = h.m.images().await.unwrap().remove(0);
    let zfs = h.pool.calls();
    assert!(
        zfs.contains(&format!(
            "clone byard/images/{}@base byard/m/{}/root",
            image.key, m.id
        )),
        "{zfs:?}"
    );
    assert!(!zfs.iter().any(|c| c.contains("/data")), "{zfs:?}");
    // The TAP was made on the namespace's bridge, pinned to the address, before the boot;
    // then the guest was waited for.
    let tap = netw::tap_name(&m.id);
    assert_eq!(
        h.host.calls(),
        vec![
            format!("ensure_tap {tap} by1 10.64.1.2"),
            format!("boot {} tap={tap} resume=false", m.id),
            "wait_ready 1000".to_string(),
        ]
    );
    assert_eq!(h.host.alive(), vec![1000]);
    let (used, up, total) = h.m.usage();
    assert_eq!((used.memory_mb, up, total), (512, 1, 1));
    assert_eq!(h.m.list(Some("t1"), &[])[0].id, m.id);
    // A second machine of that name is refused before anything is made.
    assert!(matches!(
        h.m.create_made(h.request("web")).await,
        Err(MError::NameTaken(x)) if x.id == m.id
    ));
    assert!(h.pool.calls().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_guest_that_never_answers_is_boot_failed() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    h.host.boots(Boots::Silent);
    let err = h.m.create_made(h.request("web")).await.unwrap_err();
    let m = match err {
        MError::BootFailed(m) => m,
        other => panic!("{other:?}"),
    };
    assert_eq!(m.state, state::ERROR);
    assert!(
        m.error.starts_with("the guest did not come up: "),
        "{}",
        m.error
    );
    // The process was ended, the TAP removed; the machine stays for the caller.
    assert!(h.host.alive().is_empty());
    let calls = h.host.calls();
    assert!(calls.contains(&"kill 1000".to_string()), "{calls:?}");
    assert_eq!(
        calls.last().unwrap(),
        &format!("delete_tap {} 10.64.1.2", netw::tap_name(&m.id))
    );
    assert_eq!(h.m.get(&m.id).unwrap().state, state::ERROR);
    assert_eq!(h.stored(&m.id).unwrap().state, state::ERROR);
    // The watcher found nothing to settle: no restart, one boot.
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(h.m.get(&m.id).unwrap().state, state::ERROR);
    assert!(!h.host.calls().iter().any(|c| c.starts_with("boot ")));
    // An errored machine holds no memory, and `/wait` answers at once with the reason.
    assert_eq!(h.m.usage().0.memory_mb, 0);
    match h
        .m
        .wait(&m.id, Until::Running, Duration::from_secs(1))
        .await
    {
        Err(MError::NotRunning(why)) => assert_eq!(why, m.error),
        other => panic!("{other:?}"),
    }
    use std::sync::atomic::Ordering::Relaxed;
    assert_eq!(h.m.inner.stats.starts_failed.load(Relaxed), 1);
}

/// A command that ends at once ends the machine at once: whichever the host sees first,
/// the init's pong or the process gone, the machine was created, then stopped with its
/// exit, as any later exit is.
#[tokio::test(start_paused = true)]
async fn a_command_that_exits_at_once_is_an_exit_in_either_order() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let once = |name: &str| {
        let mut req = h.request(name);
        req.restart = Some(api::RestartPolicy {
            policy: "no".into(),
            max_retries: 0,
        });
        req
    };
    // The pong first, then the exit.
    let a = h.m.create_made(once("pong-first")).await.unwrap();
    h.host.exit(1000, 7, false);
    // The process gone first: no pong ever came.
    h.host.boots(Boots::Runs(7));
    let b = h.m.create_made(once("exit-first")).await.unwrap();
    for m in [&a, &b] {
        let r = settled(&h.m.entry(&m.id).unwrap()).await;
        assert_eq!(
            (
                r.state.as_str(),
                r.stopped_reason.as_str(),
                r.error.as_str()
            ),
            (state::STOPPED, stop::EXIT, ""),
            "{}",
            m.name
        );
        assert_eq!(r.exit.as_ref().map(|x| x.code), Some(7), "{}", m.name);
        assert_eq!(r.init_version, "0.1.0+init", "{}", m.name);
        assert_eq!(
            h.reasons(&m.id),
            ["created", "starting", "started", "exited"],
            "{}",
            m.name
        );
    }
    // Two boots, no failed start, and nothing left running.
    use std::sync::atomic::Ordering::Relaxed;
    assert_eq!(h.m.inner.stats.boots.load(Relaxed), 2);
    assert_eq!(h.m.inner.stats.starts_failed.load(Relaxed), 0);
    assert!(h.host.alive().is_empty());
}

#[tokio::test]
async fn a_machine_that_exits_during_boot_is_boot_failed_with_its_console() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    // The init's report says its main process never started.
    // An init older than its reason: the console's tail says it.
    h.host.boots(Boots::Exits(137, ""));
    let err = h.m.create_made(h.request("web")).await.unwrap_err();
    let m = match err {
        MError::BootFailed(m) => m,
        other => panic!("{other:?}"),
    };
    assert_eq!(m.state, state::ERROR);
    assert!(
        m.error.starts_with("the machine exited during boot: "),
        "{}",
        m.error
    );
    assert!(m.error.contains("[briqyard] exit code=137"), "{}", m.error);
    // Not an exit the restart policy sees: the watcher had nothing to settle.
    assert!(m.exit.is_none());
    tokio::task::yield_now().await;
    assert_eq!(h.m.get(&m.id).unwrap().state, state::ERROR);
    assert_eq!(
        h.host
            .calls()
            .iter()
            .filter(|c| c.starts_with("boot "))
            .count(),
        1
    );
    // `create` with `start: false` leaves it `created`, and a `start` fails the same way.
    h.host.boots(Boots::Exits(1, ""));
    let mut req = h.request("db");
    req.start = Some(false);
    let created = h.m.create_made(req).await.unwrap();
    assert_eq!(created.state, state::CREATED);
    assert!(matches!(
        h.m.start(&created.id, None).await,
        Err(MError::BootFailed(_))
    ));
}

#[tokio::test]
async fn a_program_the_init_cannot_start_is_boot_failed_with_its_reason() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    // The init's own reason is the machine's error, not the console's last lines.
    let why = "start \"/run.sh\": Operation not permitted (os error 1)";
    h.host.boots(Boots::Exits(127, why));
    let m = match h.m.create_made(h.request("web")).await {
        Err(MError::BootFailed(m)) => m,
        other => panic!("{other:?}"),
    };
    assert_eq!((m.state.as_str(), m.exit.is_none()), (state::ERROR, true));
    assert_eq!(m.error, format!("the machine exited during boot: {why}"));
    let e = h.events_of(&m.id).pop().unwrap();
    assert_eq!((e.reason.as_str(), e.message), ("boot_failed", m.error));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_and_a_destroy_racing_leave_nothing_behind() {
    for round in 0..6 {
        let h = harness("10.64.0.0/22", 4096).await;
        h.namespace("t1");
        let e = h.add("m_race", state::STOPPED, 512);
        h.disks(&e).await;
        let (a, b) = (h.m.clone(), h.m.clone());
        let start = async move { a.start("m_race", None).await.map(|m| m.state) };
        let destroy = async move { b.destroy("m_race", None).await };
        let (started, destroyed) = if round % 2 == 0 {
            let s = tokio::spawn(start);
            let d = tokio::spawn(destroy);
            (s.await.unwrap(), d.await.unwrap())
        } else {
            let d = tokio::spawn(destroy);
            let s = tokio::spawn(start);
            (s.await.unwrap(), d.await.unwrap())
        };
        destroyed.unwrap();
        // The start ran first and was undone, or found the machine on its way out.
        match started {
            Ok(st) => assert_eq!(st, state::RUNNING, "round {round}"),
            Err(MError::BadState(st)) => assert_eq!(st, state::DESTROYING, "round {round}"),
            Err(MError::NotFound) => {}
            other => panic!("round {round}: {other:?}"),
        }
        // One outcome either way: no record, no process, no disks, no TAP.
        assert!(matches!(h.m.get("m_race"), Err(MError::NotFound)));
        assert!(h.stored("m_race").is_none());
        assert!(h.host.alive().is_empty(), "round {round}");
        assert!(!h.pool.dev().join("byard/m/m_race").exists());
        assert!(h.m.inner.net.list_taps().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn two_starts_past_capacity_admit_one() {
    let h = harness("10.64.0.0/22", 768).await;
    h.namespace("t1");
    for id in ["m_a", "m_b"] {
        let e = h.add(id, state::STOPPED, 512);
        h.disks(&e).await;
    }
    let (a, b) = (h.m.clone(), h.m.clone());
    let (ra, rb) = tokio::join!(a.start("m_a", None), b.start("m_b", None));
    let mut outcomes = [ra, rb];
    outcomes.sort_by_key(|r| r.is_err());
    assert_eq!(outcomes[0].as_ref().unwrap().state, state::RUNNING);
    match &outcomes[1] {
        Err(MError::Capacity(why)) => assert_eq!(why, "768 MB used of 768"),
        other => panic!("{other:?}"),
    }
    let (used, up, _) = h.m.usage();
    assert_eq!((used.memory_mb, up), (768, 1));
    // The refused one was not touched: still stopped, nothing booted for it.
    assert_eq!(
        h.host
            .calls()
            .iter()
            .filter(|c| c.starts_with("boot "))
            .count(),
        1
    );
    let states: Vec<String> = h.m.list(None, &[]).into_iter().map(|m| m.state).collect();
    assert!(states.contains(&state::STOPPED.to_string()), "{states:?}");
}

#[tokio::test]
async fn a_stop_ends_the_guest_and_the_watcher_settles_it() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("web")).await.unwrap();
    h.host.calls();
    let stopped =
        h.m.stop(&m.id, Duration::from_secs(3), false, None)
            .await
            .unwrap();
    assert_eq!(
        (stopped.state.as_str(), stopped.stopped_reason.as_str()),
        (state::STOPPED, stop::USER)
    );
    assert!(stopped.stopped_at.is_some());
    assert_eq!(h.stored(&m.id).unwrap().pid, 0);
    // The guest was asked, not killed; its TAP went with it.
    let calls = h.host.calls();
    assert_eq!(calls[0], "shutdown 1000 3s");
    assert!(!calls.iter().any(|c| c.starts_with("kill ")), "{calls:?}");
    assert!(calls.contains(&format!("delete_tap {} 10.64.1.2", netw::tap_name(&m.id))));
    assert_eq!(h.m.usage().0.memory_mb, 0);
    // Stopped on request: a wake refuses, a start boots it again.
    assert!(matches!(
        h.m.wake(&m.id, None).await,
        Err(MError::NotRunning(_))
    ));
    let again = h.m.start(&m.id, None).await.unwrap();
    assert_eq!(
        (again.state.as_str(), again.stopped_reason.as_str()),
        (state::RUNNING, "")
    );
    assert_eq!(h.stored(&m.id).unwrap().boots, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_of_a_stopping_machine_returns_when_it_settles() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("web")).await.unwrap();
    let e = h.m.entry(&m.id).unwrap();
    // A stop is in flight: the state says so, and whoever asked still holds the lock.
    let held = e.lock.lock().await;
    e.set_state(state::STOPPING, |_| None);
    let (m2, id) = (h.m.clone(), m.id.clone());
    let second = tokio::spawn(async move {
        let t0 = std::time::Instant::now();
        m2.stop(&id, Duration::from_secs(1), false, None)
            .await
            .unwrap();
        t0.elapsed()
    });
    drop(held);
    // The watcher settles the machine as soon as it can take the lock.
    let _settling = e.lock.lock().await;
    e.set_state(state::STOPPED, |r| {
        r.stopped_reason = stop::USER.into();
        None
    });
    drop(_settling);
    let waited = second.await.unwrap();
    assert!(waited < Duration::from_secs(1), "{waited:?}");
}

#[tokio::test]
async fn a_wake_during_a_sleep_waits_for_the_stop_then_starts() {
    // Found by the e2e suite: an exec waking a machine the sleeper was stopping got
    // `bad_state: stopping`.
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("db")).await.unwrap();
    let e = h.m.entry(&m.id).unwrap();
    h.host.stops_take(Duration::from_millis(300));
    let (m2, e2) = (h.m.clone(), e.clone());
    let sleep = tokio::spawn(async move {
        m2.stop_entry(&e2, stop::IDLE, Duration::from_secs(1), false, None)
            .await
            .unwrap()
    });
    while e.snapshot().state != state::STOPPING {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let woken = h.m.wake(&m.id, None).await.unwrap();
    assert_eq!(woken.state, state::RUNNING);
    sleep.await.unwrap();
    assert_eq!(h.m.get(&m.id).unwrap().state, state::RUNNING);
}

#[tokio::test]
async fn a_create_whose_caller_hangs_up_still_runs() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    h.host.boots(Boots::Ready(Duration::from_millis(50)));
    let (m, req) = (h.m.clone(), h.request("web"));
    let caller = tokio::spawn(async move { detached(async move { m.create(req).await }).await });
    // The client hangs up once the machine is registered, answered or not: its disks and
    // its boot are still to come, in a task of their own (ADR 0048).
    let id = loop {
        match h.m.list(Some("t1"), &[]).pop() {
            Some(m) => break m.id,
            None => tokio::task::yield_now().await,
        }
    };
    caller.abort();
    let _ = caller.await;
    let running =
        h.m.wait(&id, Until::Running, Duration::from_secs(5))
            .await
            .unwrap();
    assert_eq!(running.state, state::RUNNING);
    assert_eq!(h.stored(&id).unwrap().state, state::RUNNING);
    assert_eq!(h.host.alive().len(), 1);
}

/// An image on a registry at `addr`, by digest: no tag to resolve, its pull goes there.
fn image_at(addr: &str, n: u8) -> String {
    format!("{addr}/nope@sha256:{}", format!("{n:02x}").repeat(32))
}

#[tokio::test]
async fn a_create_answers_once_recorded_then_runs() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    h.host.boots(Boots::Ready(Duration::from_millis(50)));
    let m = h.m.create(h.request("web")).await.unwrap();
    // ADR 0048: recorded, on disk, its address and its memory taken; nothing booted yet.
    assert_eq!(m.state, state::CREATING);
    assert_eq!(m.ip, "10.64.1.2");
    assert_eq!(h.stored(&m.id).unwrap().state, state::CREATING);
    let running = h.m.wait(&m.id, Until::Ready, Duration::from_secs(5)).await;
    assert_eq!(running.unwrap().state, state::RUNNING);
    let (used, up, _) = h.m.usage();
    assert_eq!((used.memory_mb, up), (512, 1));
    let reasons: Vec<String> =
        h.m.events_page(0, events::Filter::default(), 100)
            .await
            .unwrap()
            .events
            .into_iter()
            .filter(|e| e.machine_id == m.id)
            .map(|e| e.reason)
            .collect();
    assert_eq!(reasons, ["created", "starting", "started"]);
}

#[tokio::test]
async fn a_create_takes_its_memory_when_recorded() {
    let h = harness("10.64.0.0/22", 768).await;
    h.ready().await;
    h.host.boots(Boots::Silent);
    let mut req = h.request("a");
    req.size.memory_mb = 384;
    // Its pull is under way: the host counts it, and refuses what no longer fits.
    let (addr, _held) = silent_registry().await;
    req.image = image_at(&addr, 1);
    let a = h.m.create(req).await.unwrap();
    assert_eq!(a.state, state::CREATING);
    assert_eq!(h.m.usage().0.memory_mb, 640);
    assert!(matches!(
        h.m.create(h.request("b")).await,
        Err(MError::Capacity(_))
    ));
    // One that does not start takes none, and a start of it while it is created takes it.
    let mut c = h.request("c");
    c.image = image_at(&addr, 2);
    c.start = Some(false);
    let c = h.m.create(c).await.unwrap();
    assert_eq!(h.m.usage().0.memory_mb, 640);
    assert!(matches!(
        h.m.start(&c.id, None).await,
        Err(MError::Capacity(_))
    ));
    h.m.destroy(&a.id, None).await.unwrap();
    let c = h.m.start(&c.id, None).await.unwrap();
    assert_eq!(
        (c.state.as_str(), h.m.usage().0.memory_mb),
        (state::CREATING, 512)
    );
    assert!(h.stored(&c.id).unwrap().start);
}

/// A registry that takes connections and never answers: a pull from it waits until the
/// task is aborted, which closes them and the listener.
async fn silent_registry() -> (String, tokio::task::JoinHandle<()>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((c, _)) = l.accept().await {
            held.push(c);
        }
    });
    (addr, task)
}

#[tokio::test]
async fn a_destroy_during_the_pull_does_not_wait_for_it() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let (addr, held) = silent_registry().await;
    let mut req = h.request("slow");
    req.image = image_at(&addr, 3);
    let m = h.m.create(req.clone()).await.unwrap();
    // A second create of the same image shares the one pull; each says it waits for it.
    let mut again = h.request("slow2");
    again.image = req.image.clone();
    let m2 = h.m.create(again).await.unwrap();
    for id in [&m.id, &m2.id] {
        let said = async {
            while !h.said(id, reason::PULLING).await {
                tokio::task::yield_now().await;
            }
        };
        tokio::time::timeout(Duration::from_secs(5), said)
            .await
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(5), h.m.destroy(&m.id, None))
        .await
        .expect("a destroy waits for no pull")
        .unwrap();
    assert!(h.stored(&m.id).is_none());
    // The registry goes: the pull fails, the machine left fails with it, the destroyed
    // one stays gone.
    held.abort();
    let failed =
        h.m.wait(&m2.id, Until::Ready, Duration::from_secs(10))
            .await;
    let Err(MError::PullFailed(f)) = failed else {
        panic!("{failed:?}")
    };
    assert_eq!(
        (f.state.as_str(), f.error_reason.as_str()),
        (state::ERROR, reason::PULL_FAILED)
    );
    assert!(
        f.error.starts_with(&format!("pull {}", req.image)),
        "{}",
        f.error
    );
    assert!(h.stored(&m.id).is_none() && h.m.get(&m.id).is_err());
}

#[tokio::test]
async fn a_pull_that_fails_leaves_the_machine_in_error_without_disks() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let mut req = h.request("bad");
    // Nothing listens there: refused at once.
    req.image = image_at("127.0.0.1:1", 4);
    let m = h.m.create(req).await.unwrap();
    for until in [Until::Running, Until::Ready] {
        let got = h.m.wait(&m.id, until, Duration::from_secs(10)).await;
        assert!(
            matches!(&got, Err(MError::PullFailed(f)) if f.id == m.id),
            "{got:?}"
        );
    }
    let r = h.stored(&m.id).unwrap();
    assert_eq!(
        (r.state.as_str(), r.error_reason.as_str()),
        (state::ERROR, reason::PULL_FAILED)
    );
    assert!(!r.has_disks() && !h.pool.zfs.exists(&r.dataset()).await.unwrap());
    assert_eq!(h.m.usage().0.memory_mb, 0);
    // Nothing is tried again: a start says what to do, a destroy cleans up.
    assert!(matches!(
        h.m.start(&m.id, None).await,
        Err(MError::BadState(_))
    ));
    let mut fork = h.request("fork");
    fork.fork = Some(api::ForkSpec {
        machine_id: m.id.clone(),
        copy: String::new(),
    });
    assert!(matches!(h.m.create(fork).await, Err(MError::Invalid(_))));
    h.m.destroy(&m.id, None).await.unwrap();
    assert!(h.m.list(Some("t1"), &[]).is_empty());
}

#[tokio::test]
async fn a_create_sent_again_answers_the_machine_the_first_made() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    h.host.boots(Boots::Silent);
    let m = h.m.create(h.request("web")).await.unwrap();
    let again = h.m.create(h.request("web")).await;
    assert!(
        matches!(&again, Err(MError::NameTaken(x)) if x.id == m.id),
        "{again:?}"
    );
    assert_eq!(h.m.list(Some("t1"), &[]).len(), 1);
}

#[tokio::test]
async fn a_create_cut_by_a_restart_is_taken_up_again_or_failed() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    h.host.boots(Boots::Ready(Duration::from_millis(10)));
    // From an image: its partial disks go and its create runs again, to the end (ADR 0048).
    let e = h.add("m_cut", state::CREATING, 256);
    {
        let mut r = e.rec.lock().unwrap();
        r.image = IMAGE.into();
        r.start = true;
        // A volume is formatted with the host's `mkfs.ext4`.
        r.volume = None;
    }
    h.disks(&e).await;
    // From a fork's source or a backup, which the record does not name: failed.
    let f = h.add("m_forked", state::CREATING, 256);
    {
        let mut r = f.rec.lock().unwrap();
        r.name = "forked".into();
        r.from_source = true;
        r.start = true;
    }
    h.disks(&f).await;
    h.m.recover().await;
    let ran =
        h.m.wait("m_cut", Until::Running, Duration::from_secs(5))
            .await;
    assert_eq!(ran.unwrap().state, state::RUNNING);
    assert_eq!(h.host.alive().len(), 1, "one boot, on new disks");
    let r = f.snapshot();
    assert_eq!(
        (r.state.as_str(), r.error_reason.as_str()),
        (state::ERROR, reason::CREATE_FAILED)
    );
    assert!(!h.pool.zfs.exists(&r.dataset()).await.unwrap());
    assert_eq!(h.m.usage().0.memory_mb, 512, "the one that runs");
    let got =
        h.m.wait("m_forked", Until::Ready, Duration::from_secs(1))
            .await;
    assert!(matches!(got, Err(MError::CreateFailed(_))), "{got:?}");
}

#[tokio::test]
async fn a_wait_that_runs_out_on_the_way_is_not_ready() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.add("m_c", state::CREATING, 256);
    for until in [Until::Running, Until::Ready] {
        let got = h.m.wait("m_c", until, Duration::from_millis(20)).await;
        let Err(MError::NotReady(m)) = got else {
            panic!("{got:?}")
        };
        assert_eq!(m.state, state::CREATING);
    }
    // Calls that change or run something wait for what the create makes.
    assert!(matches!(
        h.m.update("m_c", api::UpdateMachineRequest::default(), None)
            .await,
        Err(MError::BadState(_))
    ));
    assert!(matches!(
        h.m.stop("m_c", Duration::ZERO, false, None).await,
        Err(MError::BadState(_))
    ));
}

#[tokio::test]
async fn a_transition_that_panics_is_internal_and_frees_the_machine() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.namespace("t1");
    let e = h.add("m_p", state::STOPPED, 512);
    h.disks(&e).await;
    h.host.boots(Boots::Panics);
    let m = h.m.clone();
    let err = detached(async move { m.start("m_p", None).await })
        .await
        .unwrap_err();
    match err {
        MError::Other(err) => {
            assert!(err.to_string().starts_with("transition task: "), "{err}")
        }
        other => panic!("{other:?}"),
    }
    // The lock went with the task: the next call on the machine is served.
    h.host.boots(Boots::Ready(Duration::ZERO));
    tokio::time::timeout(Duration::from_secs(5), h.m.destroy("m_p", None))
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(h.m.get("m_p"), Err(MError::NotFound)));
}
