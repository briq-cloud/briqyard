use super::super::mock::CheckedKill;
use super::*;

#[tokio::test]
async fn failed_preclose_isolates_the_exact_gateway_before_any_new_admission() {
    let h = harness("10.64.0.0/22", 4096).await;
    let b = binding("ab");
    let id = h.with_bound_gateway(&b).await;
    let consumer =
        h.m.create_made(h.bound_consumer("existing", &b))
            .await
            .unwrap();
    let consumer_entry = h.m.entry(&consumer.id).unwrap();
    let consumer_pid = consumer_entry.snapshot().pid;
    let mut request = h.bound_consumer("next", &b);
    request.start = Some(false);
    let next = h.m.create_made(request).await.unwrap();
    let gw = h.m.entry(&id).unwrap();
    let old = gw.live.lock().unwrap().clone().unwrap();
    assert!(!h.gate_closed());
    assert!(gw.gateway_proof.lock().unwrap().is_some());
    h.host.calls();
    h.host.refuse_close_gate.store(true, Relaxed);
    assert!(matches!(
        h.m.start(&next.id, None).await,
        Err(MError::GatewayPolicy(_))
    ));
    assert!(*old.exited.borrow());
    assert!(gw.gateway_proof.lock().unwrap().is_none());
    assert_eq!(h.m.entry(&next.id).unwrap().snapshot().pid, 0);
    assert_eq!(consumer_entry.snapshot().pid, consumer_pid);
    let calls = h.host.calls();
    assert!(
        !calls.iter().any(|c| c.contains("policy-status")),
        "{calls:?}"
    );
    assert!(calls.contains(&format!("kill {}", old.pid)), "{calls:?}");
}

#[tokio::test]
async fn failed_preclose_without_positive_exit_retains_ownership_and_blocks_restart() {
    for kill in [CheckedKill::Refuse, CheckedKill::CloseWithoutExit] {
        let h = harness("10.64.0.0/22", 4096).await;
        let b = binding("ab");
        let id = h.with_bound_gateway(&b).await;
        h.m.create_made(h.bound_consumer("existing", &b))
            .await
            .unwrap();
        let gw = h.m.entry(&id).unwrap();
        let old = gw.live.lock().unwrap().clone().unwrap();
        let ip = gw.snapshot().ip;
        *h.host.checked_kill.lock().unwrap() = kill;
        h.host.refuse_close_gate.store(true, Relaxed);
        let err = h.m.ensure_gateway("t1", Some(&b)).await.unwrap_err();
        assert!(err.to_string().contains("isolation unconfirmed"), "{err}");
        assert!(!*old.exited.borrow());
        assert_eq!(gw.snapshot().pid, old.pid);
        assert_eq!(gw.snapshot().ip, ip);
        assert_eq!(gw.snapshot().state, state::RUNNING);
        assert!(gw
            .live
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .exited
            .same_channel(&old.exited));
        assert!(gw.gateway_proof.lock().unwrap().is_none());
        assert!(h.gateway_view().error.contains("isolation unconfirmed"));
        h.host.refuse_close_gate.store(false, Relaxed);
        h.host.calls();
        let err = h.m.ensure_gateway("t1", Some(&b)).await.unwrap_err();
        assert!(err.to_string().contains("isolation unconfirmed"), "{err}");
        assert!(h.host.calls().is_empty());
    }
}

#[tokio::test]
async fn cancelling_admission_drains_gate_commands_on_both_sides_of_the_effect() {
    for (phase, initially_closed) in [
        ("gate_close_before", false),
        ("gate_close_after", true),
        ("gate_open_before", true),
        ("gate_open_after", false),
    ] {
        let h = harness("10.64.0.0/22", 4096).await;
        let b = binding("ab");
        let id = h.with_bound_gateway(&b).await;
        h.m.create_made(h.bound_consumer("existing", &b))
            .await
            .unwrap();
        let gw = h.m.entry(&id).unwrap();
        let live = gw.live.lock().unwrap().clone().unwrap();
        *h.host.pause_network.lock().unwrap() = Some((phase, GW_IP.into()));
        let mut caller = Box::pin(h.m.ensure_gateway("t1", Some(&b)));
        tokio::select! {
            _ = h.host.network_started.notified() => {}
            _ = &mut caller => panic!("admission completed before {phase}"),
        }
        drop(caller);
        assert_eq!(h.gate_closed(), initially_closed, "{phase}");
        let t = h.m.namespace_of("t1").unwrap();
        assert!(
            t.lock.try_lock().is_err(),
            "{phase} lost the namespace turn"
        );
        assert!(gw.lock.try_lock().is_err(), "{phase} lost the gateway turn");
        *h.host.pause_network.lock().unwrap() = None;
        h.host.network_release.notify_one();
        let _settled = t.lock.lock().await;
        assert!(h.gate_closed(), "{phase}: the gate was left open");
        assert!(
            !*live.exited.borrow(),
            "{phase}: closing need not kill the gateway"
        );
        assert!(gw.gateway_proof.lock().unwrap().is_none(), "{phase}");
    }
}

#[tokio::test]
async fn losing_a_prepared_verification_before_delivery_rolls_back_the_gate() {
    let h = harness("10.64.0.0/22", 4096).await;
    let b = binding("ab");
    let id = h.with_bound_gateway(&b).await;
    h.m.create_made(h.bound_consumer("existing", &b))
        .await
        .unwrap();
    let gw = h.m.entry(&id).unwrap();
    *h.host.pause_network.lock().unwrap() = Some(("gate_open_after", GW_IP.into()));
    let mut caller = Box::pin(h.m.ensure_gateway("t1", Some(&b)));
    tokio::select! {
        _ = h.host.network_started.notified() => {}
        _ = &mut caller => panic!("admission completed before the open was settled"),
    }
    *h.host.pause_network.lock().unwrap() = None;
    h.host.network_release.notify_one();
    tokio::task::yield_now().await;
    assert!(!h.gate_closed());
    assert!(gw.gateway_proof.lock().unwrap().is_none());
    drop(caller);
    let t = h.m.namespace_of("t1").unwrap();
    let _settled = t.lock.lock().await;
    assert!(h.gate_closed());
    assert!(gw.gateway_proof.lock().unwrap().is_none());
}

#[tokio::test]
async fn literal_policy_gateway_requires_readback_but_literal_peers_do_not() {
    let h = harness("10.64.0.0/22", 4096).await;
    let id = h.with_bound_gateway(&binding("ab")).await;
    let peer = h.m.create_made(h.request("peer")).await.unwrap();
    h.helper(|_, _| PolicyReply::default());
    let mut through = h.consumer("through");
    through.egress.as_mut().unwrap().via = Some(peer.id);
    h.host.calls();
    assert_eq!(
        h.m.create_made(through).await.unwrap().state,
        state::RUNNING
    );
    assert!(!h
        .host
        .calls()
        .iter()
        .any(|c| c.contains("policy-status") || c.contains("gateway_gate")));
    let mut through = h.consumer("literal-gateway");
    through.egress.as_mut().unwrap().via = Some(id);
    let outcome = h.m.create_made(through).await;
    assert!(
        matches!(&outcome, Err(MError::CreateFailed(machine))
            if machine.error_reason == reason::CREATE_FAILED
                && machine.error.contains("gateway loaded policy not verified")),
        "{outcome:?}"
    );
    assert!(h.gate_closed());
    assert!(h.host.calls().iter().any(|c| c.contains("policy-status")));
}

#[tokio::test]
async fn late_open_cannot_outlive_its_gateway_turn_or_restart_the_old_process() {
    let h = harness("10.64.0.0/22", 4096).await;
    let b = binding("ab");
    let id = h.with_bound_gateway(&b).await;
    h.m.create_made(h.bound_consumer("existing", &b))
        .await
        .unwrap();
    let gw = h.m.entry(&id).unwrap();
    let mut old = gw.live.lock().unwrap().clone().unwrap();
    let t = h.m.namespace_of("t1").unwrap();
    *h.host.pause_network.lock().unwrap() = Some(("gate_open_before", GW_IP.into()));
    tokio::time::pause();
    let mut caller = Box::pin(h.m.ensure_gateway("t1", Some(&b)));
    tokio::select! {
        _ = h.host.network_started.notified() => {}
        _ = &mut caller => panic!("admission completed with an outstanding open"),
    }
    drop(caller);
    tokio::time::advance(nft::GATE_TIMEOUT).await;
    old.exited.wait_for(|gone| *gone).await.unwrap();
    assert!(
        t.lock.try_lock().is_err(),
        "late open lost address ownership"
    );
    assert!(
        gw.lock.try_lock().is_err(),
        "watcher could settle before the command"
    );
    assert_eq!(gw.snapshot().pid, old.pid);
    assert!(matches!(
        h.m.ensure_gateway("t1", Some(&b)).await,
        Err(MError::GatewayPolicy(_))
    ));
    *h.host.pause_network.lock().unwrap() = None;
    h.host.network_release.notify_one();
    drop(t.lock.lock().await);
    drop(gw.lock.lock().await);
    assert_eq!(gw.snapshot().state, state::STOPPED);
    assert_eq!(gw.snapshot().stopped_reason, stop::HOST);
    assert_eq!(gw.snapshot().restarts, 0);
    tokio::time::resume();
    drop(h.m.ensure_gateway("t1", Some(&b)).await.unwrap());
    let now = gw.live.lock().unwrap().clone().unwrap();
    assert!(!now.exited.same_channel(&old.exited));
    assert!(!*now.exited.borrow());
}

#[tokio::test]
async fn policy_gateway_put_wins_before_stopped_or_error_patch_can_change_ownership() {
    for state in [state::STOPPED, state::ERROR] {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        h.namespace("t1");
        let e = derived(&h, "m_derived", state, api::Egress::default());
        *h.host.pause_network.lock().unwrap() = Some(("count", "*".into()));
        let mut put = Box::pin(h.m.set_gateway("t1", bound_spec(&binding("ab"))));
        tokio::select! {
            _ = h.host.network_started.notified() => {}
            _ = &mut put => panic!("gateway PUT went past the barrier"),
        }
        let id = h.m.gateway_of("t1").unwrap().snapshot().id;
        let mut alias = Box::pin(h.m.update(
            "m_derived",
            api::UpdateMachineRequest {
                egress: Some(via_alias()),
                ..Default::default()
            },
            Some(e.snapshot().version),
        ));
        assert!(futures::poll!(&mut alias).is_pending());
        *h.host.pause_network.lock().unwrap() = None;
        h.host.network_release.notify_one();
        put.await.unwrap();
        let err = alias.await.unwrap_err();
        assert!(matches!(err, MError::Conflict(_)), "{err}");
        let err =
            h.m.update(
                "m_derived",
                api::UpdateMachineRequest {
                    egress: Some(api::Egress {
                        via: Some(id),
                        ..via_alias()
                    }),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, MError::Conflict(_)), "{err}");
        assert_eq!(e.snapshot().egress, api::Egress::default());
    }
}

#[tokio::test]
async fn patch_wins_namespace_turn_through_policy_effect_and_record_save() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.with_gateway().await;
    let m = h.m.create_made(h.request("derived")).await.unwrap();
    let e = h.m.entry(&m.id).unwrap();
    e.rec.lock().unwrap().from_source = true;
    *h.host.pause_network.lock().unwrap() = Some(("set_policy", e.snapshot().ip));
    let mut patch = Box::pin(h.m.update(
        &m.id,
        api::UpdateMachineRequest {
            egress: Some(via_alias()),
            ..Default::default()
        },
        None,
    ));
    tokio::select! {
        _ = h.host.network_started.notified() => {}
        _ = &mut patch => panic!("PATCH went past the barrier"),
    }
    assert!(!e.snapshot().egress.via_gateway());
    let t = h.m.namespace_of("t1").unwrap();
    assert!(
        t.lock.try_lock().is_err(),
        "PATCH lost its turn before its effects settled"
    );
    let b = binding("ab");
    let mut put = Box::pin(h.m.set_gateway("t1", bound_spec(&b)));
    assert!(futures::poll!(&mut put).is_pending());
    *h.host.pause_network.lock().unwrap() = None;
    h.host.network_release.notify_one();
    patch.await.unwrap();
    assert!(e.snapshot().egress.via_gateway());
    assert!(h.stored(&m.id).unwrap().egress.via_gateway());
    assert!(matches!(put.await, Err(MError::Invalid(_))));
    h.m.stop(&m.id, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    h.m.delete_gateway("t1").await.unwrap();
    assert!(matches!(
        h.m.set_gateway("t1", bound_spec(&b)).await,
        Err(MError::Conflict(_))
    ));
}

#[tokio::test]
async fn egress_patch_refuses_a_move_that_wins_the_entry_before_its_old_turn() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.with_gateway().await;
    let range = &h.m.inner.range;
    for i in 0..range.count() {
        h.m.inner
            .dns
            .assume_listening(range.subnet(i).unwrap().gateway());
    }
    let mut request = h.request("moving");
    request.start = Some(false);
    let m = h.m.create_made(request).await.unwrap();
    let source = h.m.namespace_of("t1").unwrap();
    let occupied = source.lock.lock().await;
    let mut patch = Box::pin(h.m.update(
        &m.id,
        api::UpdateMachineRequest {
            egress: Some(api::Egress {
                mode: api::egress::VIA.into(),
                via: Some("gateway".into()),
                ..Default::default()
            }),
            ..Default::default()
        },
        None,
    ));
    assert!(futures::poll!(&mut patch).is_pending());
    h.m.move_machine(&m.id, "t2", None).await.unwrap();
    drop(occupied);
    let error = patch.await.unwrap_err();
    assert!(
        matches!(&error, MError::Conflict(why) if why.contains("namespace changed")),
        "{error}"
    );
    let stored = h.stored(&m.id).unwrap();
    assert_eq!(stored.namespace, "t2");
    assert_eq!(stored.egress, api::Egress::default());
}

#[tokio::test]
async fn an_unbound_egress_patch_waits_for_the_entry_and_takes_no_namespace_turn() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let mut request = h.request("plain");
    request.start = Some(false);
    let m = h.m.create_made(request).await.unwrap();
    let e = h.m.entry(&m.id).unwrap();
    let patch = |mode: &str| api::UpdateMachineRequest {
        egress: Some(api::Egress {
            mode: mode.into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let namespace = h.m.namespace_of("t1").unwrap();
    let occupied = namespace.lock.lock().await;
    tokio::time::timeout(
        Duration::from_secs(30),
        h.m.update(&m.id, patch(api::egress::NONE), None),
    )
    .await
    .unwrap()
    .unwrap();
    drop(occupied);
    let held = e.lock.lock().await;
    let mut waiting = Box::pin(h.m.update(&m.id, patch(api::egress::OPEN), None));
    for _ in 0..8 {
        assert!(futures::poll!(&mut waiting).is_pending());
        tokio::task::yield_now().await;
    }
    drop(held);
    tokio::time::timeout(Duration::from_secs(30), waiting)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(h.stored(&m.id).unwrap().egress.mode, api::egress::OPEN);
}

#[tokio::test]
async fn cold_born_consumer_keeps_its_binding_through_suspend_start_wake_and_resize() {
    let h = harness("10.64.0.0/22", 4096).await;
    let b = binding("ab");
    h.with_bound_gateway(&b).await;
    let m =
        h.m.create_made(h.bound_consumer("ordinary", &b))
            .await
            .unwrap();
    let e = h.m.entry(&m.id).unwrap();
    let stopped =
        h.m.stop(&m.id, Duration::from_secs(1), true, None)
            .await
            .unwrap();
    assert!(stopped.suspended);
    h.host.calls();
    assert_eq!(h.m.start(&m.id, None).await.unwrap().state, state::RUNNING);
    let calls = h.host.calls();
    assert!(
        calls.iter().any(|call| call.contains("policy-status")),
        "{calls:?}"
    );
    assert!(
        calls.iter().any(|call| call.ends_with(" resume=true")),
        "{calls:?}"
    );
    h.m.stop_entry(&e, stop::HOST, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    assert_eq!(e.snapshot().state, state::STOPPED);
    let mut bigger = e.snapshot().size;
    bigger.memory_mb *= 2;
    h.m.update(
        &m.id,
        super::super::update::spec(|s| s.size = Some(bigger)),
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        e.snapshot().pending.as_ref().and_then(|p| p.size),
        Some(bigger)
    );
    assert_eq!(h.m.wake(&m.id, None).await.unwrap().state, state::RUNNING);
    let r = e.snapshot();
    assert_eq!(r.size, bigger);
    assert_eq!(r.egress.gateway_policy, Some(b));
    assert!(r.is_cold_born());
}
