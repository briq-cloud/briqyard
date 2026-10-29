//! Tests of the probes and the restart policy.

use super::*;

// --- probes (ADR 0022) ---

pub(super) fn http_probe(port: u16) -> api::Probe {
    api::Probe {
        http: Some(api::HttpProbe {
            port,
            path: "/".into(),
        }),
        period_sec: 1,
        ..Default::default()
    }
}

fn exec_probe(cmd: &str) -> api::Probe {
    api::Probe {
        exec: Some(cmd.split(' ').map(String::from).collect()),
        period_sec: 1,
        ..Default::default()
    }
}

pub(in crate::machine) fn readiness(p: api::Probe) -> api::Probes {
    api::Probes {
        readiness: Some(p),
        ..Default::default()
    }
}

impl Harness {
    pub(super) fn probed(&self, name: &str, probes: api::Probes) -> api::CreateMachineRequest {
        let mut r = self.request(name);
        r.probes = Some(probes);
        r
    }

    fn last_event(&self, id: &str) -> api::Event {
        self.events_of(id).pop().expect("an event")
    }
}

/// Waits until `f` holds, a tenth of a second at a time, within ten minutes: on a paused
/// clock, a probe's periods pass at once.
pub(super) async fn eventually(what: &str, f: impl Fn() -> bool) {
    for _ in 0..6000 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("never: {what}");
}

#[tokio::test(start_paused = true)]
async fn readiness_sets_ready_and_says_when_it_changes() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    // Without probes: ready once running, as Kubernetes; never while stopped.
    let plain = h.m.create_made(h.request("plain")).await.unwrap();
    assert!(plain.ready);
    assert!(plain.probes.is_empty() && plain.probes_status.is_empty());
    let stopped =
        h.m.stop(&plain.id, Duration::from_secs(1), false, None)
            .await
            .unwrap();
    assert!(!stopped.ready);
    // A readiness probe: not ready while it fails, and never was, so no `not_ready`.
    let m =
        h.m.create_made(h.probed("web", readiness(http_probe(8080))))
            .await
            .unwrap();
    h.host.http(&m.ip, 8080, 503);
    assert_eq!((m.state.as_str(), m.ready), (state::RUNNING, false));
    let status = || h.m.get(&m.id).unwrap().probes_status.readiness;
    eventually("two failures", || status().is_some_and(|s| s.failures >= 2)).await;
    let st = status().unwrap();
    assert_eq!((st.passed, st.message.as_str()), (false, "HTTP 503"));
    assert!(!h.reasons(&m.id).contains(&"not_ready".to_string()));
    // It passes: ready, an event that moves the version.
    h.host.http(&m.ip, 8080, 200);
    eventually("ready", || h.m.get(&m.id).unwrap().ready).await;
    let ev = h.last_event(&m.id);
    assert_eq!(
        (ev.reason.as_str(), ev.kind.as_str(), ev.message.as_str()),
        ("ready", "normal", "ready: readiness passed")
    );
    assert_eq!(ev.data, Some(json!({"probe": "readiness"})));
    assert_eq!(h.m.get(&m.id).unwrap().version, ev.seq);
    assert_eq!(h.stored(&m.id).unwrap().version, ev.seq);
    // Three failures in a row: not ready, a warning that says why.
    h.host.http(&m.ip, 8080, 500);
    eventually("not ready", || !h.m.get(&m.id).unwrap().ready).await;
    let ev = h.last_event(&m.id);
    assert_eq!(
        (ev.reason.as_str(), ev.kind.as_str(), ev.message.as_str()),
        (
            "not_ready",
            "warning",
            "not ready: readiness failed 3 times in a row: HTTP 500"
        )
    );
    assert_eq!(ev.data, Some(json!({"probe": "readiness", "failures": 3})));
    // A probe is not a use: the sleep window never moved.
    let now = h.m.get(&m.id).unwrap();
    assert_eq!(now.last_used_at, m.last_used_at);
    assert!(h
        .host
        .calls()
        .contains(&format!("probe_http {}:8080/", m.ip)));
    // Stopped: not ready, and the probes stop with the process.
    h.m.stop(&m.id, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    h.host.calls();
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(!h.host.calls().iter().any(|c| c.starts_with("probe_")));
    assert!(!h.m.get(&m.id).unwrap().ready);
}

#[tokio::test(start_paused = true)]
async fn wait_follows_ready_and_says_why_it_is_not() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m =
        h.m.create_made(h.probed("web", readiness(http_probe(8080))))
            .await
            .unwrap();
    h.host.http(&m.ip, 8080, 503);
    // For running: at once, as before.
    let up = h.m.wait(&m.id, Until::Running, Duration::from_secs(30));
    assert_eq!(up.await.unwrap().state, state::RUNNING);
    // For ready: not by the timeout, answered with the machine and its probe's word.
    match h.m.wait(&m.id, Until::Ready, Duration::from_secs(5)).await {
        Err(MError::NotReady(now)) => {
            assert!(!now.ready);
            assert_eq!(now.probes_status.readiness.unwrap().message, "HTTP 503");
        }
        other => panic!("{other:?}"),
    }
    // A wait under way answers once the probe passes.
    let (mgr, id) = (h.m.clone(), m.id.clone());
    let waiting =
        tokio::spawn(async move { mgr.wait(&id, Until::Ready, Duration::from_secs(60)).await });
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(!waiting.is_finished());
    h.host.http(&m.ip, 8080, 200);
    assert!(waiting.await.unwrap().unwrap().ready);
    // A machine without probes is ready with `running`.
    let plain = h.m.create_made(h.request("plain")).await.unwrap();
    let ready = h.m.wait(&plain.id, Until::Ready, Duration::from_secs(1));
    assert!(ready.await.unwrap().ready);
}

#[tokio::test(start_paused = true)]
async fn a_startup_probe_that_fails_fails_the_boot_a_caller_waits_on() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    h.host.answers("pg_isready", 1);
    let probes = api::Probes {
        startup: Some(exec_probe("pg_isready")),
        liveness: Some(exec_probe("true")),
        ..Default::default()
    };
    let m = h.m.create_made(h.probed("pg", probes)).await.unwrap();
    // The create answers at `running`; the caller waits for `ready`.
    assert_eq!((m.state.as_str(), m.ready), (state::RUNNING, false));
    let failed = match h.m.wait(&m.id, Until::Ready, Duration::from_secs(60)).await {
        Err(MError::BootFailed(failed)) => failed,
        other => panic!("{other:?}"),
    };
    assert_eq!(failed.state, state::ERROR);
    assert!(
        failed
            .error
            .starts_with("the startup probe failed 3 times in a row: exit 1: no: "),
        "{}",
        failed.error
    );
    assert_eq!(
        h.reasons(&m.id),
        ["created", "starting", "started", "startup_failed"]
    );
    let ev = h.last_event(&m.id);
    assert_eq!(ev.kind, "warning");
    assert_eq!(ev.data, Some(json!({"failures": 3, "boot": true})));
    assert_eq!(
        ev.message,
        "startup failed 3 times in a row: exit 1: no: the boot failed"
    );
    // The guest was asked to stop; nothing restarts a boot that failed (ADR 0011), and
    // liveness never ran before startup passed.
    let calls = h.host.calls();
    assert!(
        calls.contains(&"shutdown 1000 10s".to_string()),
        "{calls:?}"
    );
    assert!(!calls.iter().any(|c| c.ends_with(" true")), "{calls:?}");
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(h.m.get(&m.id).unwrap().state, state::ERROR);
    assert_eq!(h.stored(&m.id).unwrap().boots, 1);
    assert!(h.host.alive().is_empty());
    use std::sync::atomic::Ordering::Relaxed;
    assert_eq!(h.m.inner.stats.starts_failed.load(Relaxed), 1);
    // For running, it will not run: the reason, as before.
    match h
        .m
        .wait(&m.id, Until::Running, Duration::from_secs(1))
        .await
    {
        Err(MError::NotRunning(why)) => assert_eq!(why, failed.error),
        other => panic!("{other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn a_startup_probe_failing_a_restart_is_a_crash_for_the_policy() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let probes = api::Probes {
        startup: Some(exec_probe("check")),
        ..Default::default()
    };
    let m = h.m.create_made(h.probed("app", probes)).await.unwrap();
    // Startup passed and there is no readiness probe: ready, through the startup probe.
    eventually("ready", || h.m.get(&m.id).unwrap().ready).await;
    assert_eq!(h.last_event(&m.id).message, "ready: startup passed");
    // It crashes; the restart's startup fails: a crash too, restarted by the policy.
    h.host.answers("check", 1);
    h.host.exit(h.stored(&m.id).unwrap().pid, 1, false);
    h.events_reach(&m.id, reason::STARTUP_FAILED, 1).await;
    h.events_reach(&m.id, reason::RESTARTING, 2).await;
    let evs = h.events_of(&m.id);
    let failed = evs.iter().find(|e| e.reason == "startup_failed").unwrap();
    assert_eq!(failed.data, Some(json!({"failures": 3, "boot": false})));
    assert!(
        failed.message.ends_with(": ending it"),
        "{}",
        failed.message
    );
    let exited: Vec<_> = evs.iter().filter(|e| e.reason == "exited").collect();
    assert_eq!(exited[1].data.as_ref().unwrap()["restarting"], true);
    let now = h.m.get(&m.id).unwrap();
    assert_eq!((now.state.as_str(), now.restarts), (state::STOPPED, 2));
}

#[tokio::test(start_paused = true)]
async fn liveness_restarts_under_the_policy_and_not_under_no() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let alive = "test -f /tmp/alive";
    let probes = api::Probes {
        liveness: Some(exec_probe(alive)),
        ..Default::default()
    };
    let m =
        h.m.create_made(h.probed("live", probes.clone()))
            .await
            .unwrap();
    // Liveness does not gate `ready`.
    assert!(m.ready);
    h.host.answers(alive, 1);
    h.events_reach(&m.id, reason::LIVENESS_FAILED, 1).await;
    let after: Vec<String> = h.reasons(&m.id)[3..].to_vec();
    assert_eq!(after, ["liveness_failed", "exited", "restarting"]);
    let ev = h.events_of(&m.id)[3].clone();
    assert_eq!(
        (ev.kind.as_str(), ev.message.as_str()),
        (
            "warning",
            "liveness failed 3 times in a row: exit 1: no: ending it"
        )
    );
    assert_eq!(ev.data, Some(json!({"failures": 3})));
    // Ended as a stop is (asked, then killed after 10 s), and a failure for the policy
    // whatever the code the process gave.
    assert!(h.host.calls().contains(&"shutdown 1000 10s".to_string()));
    let now = h.m.get(&m.id).unwrap();
    assert_eq!(
        (
            now.state.as_str(),
            now.stopped_reason.as_str(),
            now.restarts
        ),
        (state::STOPPED, stop::EXIT, 1)
    );
    let exit = now.exit.unwrap();
    assert!(exit.restarting);
    let at = now.restarting_at.expect("when it starts again");
    assert_eq!((at - exit.at).num_seconds(), 10);
    // It comes back, and its probes run again.
    h.host.answers(alive, 0);
    h.events_reach(&m.id, reason::STARTED, 2).await;
    let again = h.m.get(&m.id).unwrap();
    assert_eq!(again.state, state::RUNNING);
    assert_eq!(again.restarting_at, None);
    eventually("probed again", || {
        h.m.get(&m.id)
            .unwrap()
            .probes_status
            .liveness
            .is_some_and(|s| s.passed)
    })
    .await;
    // Under `restart: no` it is ended and stays stopped.
    let mut req = h.probed("once", probes);
    req.restart = Some(api::RestartPolicy {
        policy: "no".into(),
        max_retries: 0,
    });
    let once = h.m.create_made(req).await.unwrap();
    h.host.answers(alive, 1);
    h.events_reach(&once.id, reason::LIVENESS_FAILED, 1).await;
    tokio::time::sleep(Duration::from_secs(60)).await;
    let now = h.m.get(&once.id).unwrap();
    assert_eq!(
        (now.state.as_str(), now.stopped_reason.as_str()),
        (state::STOPPED, stop::EXIT)
    );
    assert!(!now.exit.unwrap().restarting);
    assert_eq!(now.restarting_at, None);
    assert!(!h.reasons(&once.id).contains(&"restarting".to_string()));
    assert_eq!(h.stored(&once.id).unwrap().boots, 1);
}

#[tokio::test(start_paused = true)]
async fn restarts_back_off_and_a_third_in_a_row_is_a_crash_loop() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let mut req = h.request("crash");
    req.restart = Some(api::RestartPolicy {
        policy: "always".into(),
        max_retries: 0,
    });
    let m = h.m.create_made(req).await.unwrap();
    for n in 1..=4 {
        h.host.exit(h.stored(&m.id).unwrap().pid, 1, false);
        h.events_reach(&m.id, reason::STARTED, n + 1).await;
    }
    let evs = h.events_of(&m.id);
    let delays: Vec<u64> = evs
        .iter()
        .filter(|e| e.reason == "restarting")
        .map(|e| e.data.as_ref().unwrap()["delay_sec"].as_u64().unwrap())
        .collect();
    assert_eq!(delays, [10, 20, 40, 80]);
    // From the third restart in a row, each is a crash loop, right after its `restarting`.
    let loops: Vec<&api::Event> = evs.iter().filter(|e| e.reason == "crash_loop").collect();
    assert_eq!(loops.len(), 2);
    assert_eq!(loops[0].data, Some(json!({"restarts": 3, "delay_sec": 40})));
    assert_eq!(
        loops[0].message,
        "restarted 3 times in a row, no run of 10 minutes between: next in 40 s"
    );
    let i = evs.iter().position(|e| e.reason == "crash_loop").unwrap();
    assert_eq!(evs[i - 1].data.as_ref().unwrap()["attempt"], 3);
    // A run of 10 minutes ends the loop: the next restart waits 10 s again. The count
    // `max_retries` reads is not reset by it.
    e_started_minutes_ago(&h, &m.id, 11);
    h.host.exit(h.stored(&m.id).unwrap().pid, 1, false);
    h.events_reach(&m.id, reason::RESTARTING, 5).await;
    let last = h.events_of(&m.id);
    let last = last
        .iter()
        .rev()
        .find(|e| e.reason == "restarting")
        .unwrap();
    assert_eq!(last.data.as_ref().unwrap()["delay_sec"], 10);
    assert_eq!(last.data.as_ref().unwrap()["attempt"], 5);
    assert_eq!(
        h.reasons(&m.id)
            .iter()
            .filter(|r| *r == "crash_loop")
            .count(),
        2
    );
    let r = h.stored(&m.id).unwrap();
    assert_eq!((r.restarts, r.recent_restarts), (5, 1));
}

#[tokio::test(start_paused = true)]
async fn probe_executions_take_turns_across_the_host() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    h.m.inner
        .probe_gate
        .forget_permits(probes::PROBES_AT_ONCE - 2);
    *h.host.exec_takes.lock().unwrap() = Duration::from_secs(2);
    let mut ids = Vec::new();
    for i in 0..5 {
        let req = h.probed(&format!("m{i}"), readiness(exec_probe("ready-check")));
        ids.push(h.m.create_made(req).await.unwrap().id);
    }
    // Each one gets its turn: all ready in the end, never more than two at once.
    eventually("all ready", || {
        ids.iter().all(|id| h.m.get(id).unwrap().ready)
    })
    .await;
    use std::sync::atomic::Ordering::SeqCst;
    assert_eq!(h.host.execs_most.load(SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn a_patch_of_the_probes_applies_at_once_to_a_running_machine() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("web")).await.unwrap();
    assert!(m.ready);
    h.host.http(&m.ip, 8080, 503);
    let set = |p: api::Probes| api::UpdateMachineRequest {
        probes: Some(p),
        ..Default::default()
    };
    let patched =
        h.m.update(&m.id, set(readiness(http_probe(8080))), None)
            .await
            .unwrap();
    assert_eq!(patched.probes, readiness(http_probe(8080)));
    assert!(!patched.ready);
    let evs = h.events_of(&m.id);
    let got: Vec<(&str, &str)> = evs[3..]
        .iter()
        .map(|e| (e.reason.as_str(), e.message.as_str()))
        .collect();
    assert_eq!(
        got,
        [
            ("updated", "probes changed"),
            ("not_ready", "not ready: its probes changed")
        ]
    );
    assert_eq!(h.stored(&m.id).unwrap().probes, readiness(http_probe(8080)));
    eventually("probed", || {
        h.m.get(&m.id)
            .unwrap()
            .probes_status
            .readiness
            .is_some_and(|s| s.failures >= 1)
    })
    .await;
    // The probes taken off: ready at once, the results gone, no probe runs any more.
    let cleared =
        h.m.update(&m.id, set(api::Probes::default()), None)
            .await
            .unwrap();
    assert!(cleared.ready && cleared.probes_status.is_empty());
    assert_eq!(h.last_event(&m.id).message, "ready: its probes changed");
    h.host.calls();
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(!h.host.calls().iter().any(|c| c.starts_with("probe_")));
    // The same probes again change nothing.
    let v = h.m.get(&m.id).unwrap().version;
    let same =
        h.m.update(&m.id, set(api::Probes::default()), None)
            .await
            .unwrap();
    assert_eq!(same.version, v);
    // Refused with the field named, on a PATCH as on a create.
    let bad = readiness(api::Probe::default());
    let want = "probes.readiness: exactly one of exec, tcp and http";
    assert_eq!(
        refused(h.m.update(&m.id, set(bad.clone()), None).await),
        want
    );
    assert_eq!(refused(h.m.create_made(h.probed("bad", bad)).await), want);
}

#[tokio::test(start_paused = true)]
async fn a_gateway_with_a_readiness_probe_is_waited_for_ready_not_its_port() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let mut spec = gateway_spec(3128);
    spec.probes = readiness(api::Probe {
        tcp: Some(3128),
        period_sec: 1,
        ..Default::default()
    });
    let gw = h.m.set_gateway("t1", spec).await.unwrap().gateway.unwrap();
    let ip: Ipv4Addr = gw.ip.parse().unwrap();
    h.host.closed.lock().unwrap().insert((ip, 3128));
    h.host.calls();
    // Not ready within the boot timeout: the consumer's start fails, the gateway errs.
    let err = h.m.create_made(h.consumer("c")).await.unwrap_err();
    let m = match err {
        MError::BootFailed(m) => m,
        other => panic!("{other:?}"),
    };
    assert!(
        m.error
            .starts_with("the tenant's gateway did not come up: not ready: "),
        "{}",
        m.error
    );
    assert_eq!(h.gateway_view().state, state::ERROR);
    let calls = h.host.calls();
    assert!(
        !calls.iter().any(|c| c.starts_with("wait_port")),
        "{calls:?}"
    );
    assert!(calls.contains(&format!("probe_tcp {ip}:3128")), "{calls:?}");
    // Its port answers: the next start runs it, ready, then the consumer.
    h.host.closed.lock().unwrap().clear();
    let c = h.m.start(&m.id, None).await.unwrap();
    assert_eq!(c.state, state::RUNNING);
    let gw = h.m.get(&gw.machine_id).unwrap();
    assert!(gw.ready);
    assert_eq!(h.last_event(&gw.id).reason, "gateway_started");
}

#[tokio::test(start_paused = true)]
async fn an_adopted_machine_runs_its_probes_again() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.tenant("t1");
    let e = h.add("m_ours", state::RUNNING, 256);
    let pid = h
        .host
        .left_running("m_ours", &h.m.inner.cfg.run_dir().join("m_ours"));
    e.set_state(state::RUNNING, |r| {
        r.pid = pid;
        r.probes = readiness(http_probe(8080));
        None
    });
    h.host.http("10.64.1.2", 8080, 503);
    assert_eq!(h.m.recover().await, (1, 0, 0));
    // Not ready until its readiness probe passes again: results are not kept.
    let m = h.m.get("m_ours").unwrap();
    assert_eq!((m.state.as_str(), m.ready), (state::RUNNING, false));
    h.host.http("10.64.1.2", 8080, 200);
    tokio::time::timeout(Duration::from_secs(10), async {
        while !h.m.get("m_ours").unwrap().ready {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_flapping_readiness_probe_is_folded_and_its_version_still_moves() {
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
    let mut versions = vec![];
    for _ in 0..4 {
        for (code, ready) in [(200, true), (500, false)] {
            h.host.http(&m.ip, 8080, code);
            eventually("flipped", || h.m.get(&m.id).unwrap().ready == ready).await;
            // A version is on disk once it can be read: a restart never gives it again.
            let version = h.m.get(&m.id).unwrap().version;
            assert!(h.stored(&m.id).unwrap().version >= version);
            versions.push(version);
        }
    }
    // Eight flips, two lines: the first of each; every flip moved the version, on disk too.
    let flips = |h: &Harness| {
        h.events_of(&m.id)
            .into_iter()
            .filter(|e| e.reason == "ready" || e.reason == "not_ready")
            .map(|e| (e.reason, e.count))
            .collect::<Vec<_>>()
    };
    assert_eq!(flips(&h), [("ready".into(), 1), ("not_ready".into(), 1)]);
    assert!(versions.windows(2).all(|v| v[0] < v[1]), "{versions:?}");
    let now = h.m.get(&m.id).unwrap();
    assert_eq!(h.stored(&m.id).unwrap().version, now.version);
    // A writer that read before the last flip is refused.
    let stale = versions[versions.len() - 2];
    let refused = h.m.stop(&m.id, Duration::from_secs(1), false, Some(stale));
    assert!(matches!(refused.await, Err(MError::Moved(_))));
    // The window over, the tick logs them: the last line says what it is, and is its version.
    h.m.log_folded(Utc::now() + chrono::Duration::minutes(11));
    assert_eq!(
        flips(&h),
        [
            ("ready".into(), 1),
            ("not_ready".into(), 1),
            ("ready".into(), 3),
            ("not_ready".into(), 3)
        ]
    );
    let last = h.events_of(&m.id).pop().unwrap();
    assert!(last.first_at.is_some_and(|t| t < last.at));
    assert_eq!(h.m.get(&m.id).unwrap().version, last.seq);
    assert_eq!(h.stored(&m.id).unwrap().version, last.seq);
}

#[tokio::test(start_paused = true)]
async fn probes_of_machines_adopted_at_a_start_are_spread_over_their_period() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.tenant("t1");
    let p = api::Probe {
        tcp: Some(80),
        ..Default::default()
    };
    for i in 0..16 {
        let id = format!("m_{i:02}");
        let e = h.add(&id, state::RUNNING, 64);
        let pid = h.host.left_running(&id, &h.m.inner.cfg.run_dir().join(&id));
        e.set_state(state::RUNNING, |r| {
            r.pid = pid;
            r.ip = format!("10.64.1.{}", 10 + i);
            r.probes = readiness(p.clone());
            None
        });
    }
    let began = tokio::time::Instant::now();
    assert_eq!(h.m.recover().await.0, 16);
    let adopted = tokio::time::Instant::now() - began;
    tokio::time::sleep(Duration::from_secs(25)).await;
    // Each machine's first probe at a point of a period from its adoption, not all at
    // once; then every 10 s from there. (A boot later than a period after the start is
    // not delayed: `first_run`'s test.)
    let probed = h.host.probed.lock().unwrap().clone();
    let mut first = BTreeMap::new();
    for (ip, at) in &probed {
        first.entry(ip.clone()).or_insert(*at - began);
    }
    assert_eq!(first.len(), 16);
    let offsets: std::collections::BTreeSet<Duration> = first.values().copied().collect();
    assert!(offsets.len() > 8, "{offsets:?}");
    let period = Duration::from_secs(10);
    assert!(offsets.iter().all(|d| *d < adopted + period), "{offsets:?}");
    let spread = *offsets.last().unwrap() - *offsets.first().unwrap();
    assert!(spread > period / 2, "{offsets:?}");
    for (ip, at0) in &first {
        let times: Vec<Duration> = probed
            .iter()
            .filter(|(i, _)| i == ip)
            .map(|(_, at)| *at - began - *at0)
            .collect();
        assert_eq!(
            times[..2],
            [Duration::ZERO, Duration::from_secs(10)],
            "{ip}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_probe_slower_than_its_period_keeps_the_period_and_skips_a_tick() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    // Past a period after the daemon's start: no spread.
    tokio::time::sleep(Duration::from_secs(20)).await;
    *h.host.exec_takes.lock().unwrap() = Duration::from_millis(1500);
    let p = api::Probe {
        period_sec: 1,
        timeout_sec: 5,
        ..exec_probe("slow-check")
    };
    h.m.create_made(h.probed("web", readiness(p)))
        .await
        .unwrap();
    let began = tokio::time::Instant::now();
    tokio::time::sleep(Duration::from_millis(6500)).await;
    let times: Vec<Duration> = h
        .host
        .probed
        .lock()
        .unwrap()
        .iter()
        .filter(|(cmd, _)| cmd == "slow-check")
        .map(|(_, at)| *at - began)
        .collect();
    // On the ticks, every other one: 0, 2, 4, 6 s, never 1.5 s after the last one ended.
    let s = Duration::from_secs;
    assert_eq!(times, [s(0), s(2), s(4), s(6)]);
}
