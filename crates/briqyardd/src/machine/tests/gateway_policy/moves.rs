use super::*;
use std::{future::Future, pin::Pin};

const BOUND: Duration = Duration::from_secs(30);

fn pause_network(h: &Harness, op: &'static str, address: &str) {
    *h.host.pause_network.lock().unwrap() = Some((op, address.into()));
}

async fn at_network(h: &Harness, work: Pin<&mut impl Future>) {
    tokio::select! {
        _ = h.host.network_started.notified() => {}
        _ = work => panic!("operation finished before the network barrier"),
    }
}

fn serve_dns(h: &Harness) {
    let range = &h.m.inner.range;
    for i in 0..range.count() {
        h.m.inner
            .dns
            .assume_listening(range.subnet(i).unwrap().gateway());
    }
}

fn release_network(h: &Harness) {
    *h.host.pause_network.lock().unwrap() = None;
    h.host.network_release.notify_one();
}

async fn created(h: &Harness, namespace: &str, name: &str) -> api::Machine {
    let mut request = h.request(name);
    request.namespace = namespace.into();
    request.start = Some(false);
    h.m.create_made(request).await.unwrap()
}

fn mark_derived(h: &Harness, machine: &api::Machine) -> Arc<Entry> {
    let e = h.m.entry(&machine.id).unwrap();
    e.rec.lock().unwrap().from_source = true;
    e
}

async fn routed_source(h: &Harness, stopped: bool) -> api::Machine {
    h.with_gateway().await;
    h.namespace("t2");
    h.m.set_gateway("t2", gateway_spec(3128)).await.unwrap();
    let source = h.m.create_made(h.consumer("moving")).await.unwrap();
    mark_derived(h, &source);
    if stopped {
        let source =
            h.m.stop(&source.id, Duration::ZERO, false, None)
                .await
                .unwrap();
        assert_eq!(source.state, state::STOPPED);
        source
    } else {
        assert_eq!(source.state, state::RUNNING);
        source
    }
}

#[tokio::test]
async fn stopped_derived_move_orders_delete_and_policy_put_at_destination_count() {
    tokio::time::timeout(BOUND, async {
        let h = harness("10.64.0.0/22", 4096).await;
        let source = routed_source(&h, true).await;
        let b = binding("ab");
        pause_network(&h, "count", "10.64.2.3");
        let mut moved = Box::pin(h.m.move_machine(&source.id, "t2", None));
        at_network(&h, moved.as_mut()).await;
        assert_eq!(h.stored(&source.id).unwrap().namespace, "t1");
        let mut introduce = Box::pin(async {
            h.m.delete_gateway("t2").await.unwrap();
            h.m.set_gateway("t2", bound_spec(&b)).await
        });
        let polled = futures::poll!(&mut introduce);
        assert!(
            polled.is_pending(),
            "DELETE and policy PUT completed before the move committed: {polled:?}"
        );
        assert!(h
            .m
            .gateway_of("t2")
            .is_some_and(|g| g.snapshot().gateway_policy.is_none()));
        release_network(&h);
        let result = moved.await.unwrap();
        assert_eq!(result.machine.state, state::STOPPED);
        assert_eq!(h.stored(&source.id).unwrap().namespace, "t2");
        assert!(matches!(
            introduce.await,
            Err(MError::Conflict(why)) if why.contains("created fresh")
        ));
        assert!(h.m.gateway_of("t2").is_none());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn policy_put_first_refuses_a_derived_move_without_touching_the_source() {
    for stopped in [true, false] {
        tokio::time::timeout(BOUND, async {
            let h = harness("10.64.0.0/22", 4096).await;
            let source = routed_source(&h, stopped).await;
            h.m.delete_gateway("t2").await.unwrap();
            let was = h.stored(&source.id).unwrap();
            pause_network(&h, "count", "10.64.2.2");
            let mut put = Box::pin(h.m.set_gateway("t2", bound_spec(&binding("ab"))));
            at_network(&h, put.as_mut()).await;
            h.host.calls();
            let mut moved = Box::pin(h.m.move_machine(&source.id, "t2", Some(was.version)));
            assert!(futures::poll!(&mut moved).is_pending());
            assert!(h.host.calls().is_empty());
            release_network(&h);
            put.await.unwrap();
            h.host.calls();
            h.pool.calls();
            pause_network(&h, "counters", "*");
            assert!(matches!(
                moved.await,
                Err(MError::Conflict(why)) if why.contains("created fresh")
            ));
            assert!(h.host.calls().is_empty());
            assert!(h.pool.calls().is_empty());
            assert!(h.m.inner.address_holds.lock().unwrap().is_empty());
            let now = h.stored(&source.id).unwrap();
            assert_eq!(
                (now.namespace, now.ip, now.state, now.pid, now.version),
                (was.namespace, was.ip, was.state, was.pid, was.version)
            );
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn dropping_a_paused_derived_move_releases_both_names_and_its_address() {
    tokio::time::timeout(BOUND, async {
        let h = harness("10.64.0.0/22", 4096).await;
        let source = routed_source(&h, true).await;
        pause_network(&h, "count", "10.64.2.3");
        let mut moved = Box::pin(h.m.move_machine(&source.id, "t2", None));
        at_network(&h, moved.as_mut()).await;
        assert_eq!(h.m.inner.address_holds.lock().unwrap().len(), 2);
        assert_eq!(h.m.inner.namespace_turns.len(), 2);
        drop(moved);
        release_network(&h);
        assert!(h.m.inner.address_holds.lock().unwrap().is_empty());
        assert_eq!(h.m.inner.namespace_turns.len(), 0);
        h.m.delete_gateway("t2").await.unwrap();
        h.m.set_gateway("t2", bound_spec(&binding("ab")))
            .await
            .unwrap();
        let new = created(&h, "t2", "address-reused").await;
        assert_eq!(new.ip, "10.64.2.3");
        let rec = h.stored(&source.id).unwrap();
        assert_eq!((rec.namespace.as_str(), rec.ip), ("t1", source.ip));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn an_open_derived_move_holds_its_source_until_a_waiting_egress_patch_can_recheck() {
    tokio::time::timeout(BOUND, async {
        let h = harness("10.64.0.0/22", 4096).await;
        h.with_gateway().await;
        h.namespace("t2");
        h.m.set_gateway("t2", bound_spec(&binding("ab")))
            .await
            .unwrap();
        let source = created(&h, "t1", "open").await;
        mark_derived(&h, &source);
        pause_network(&h, "count", "10.64.2.3");
        let mut moved = Box::pin(h.m.move_machine(&source.id, "t2", None));
        at_network(&h, moved.as_mut()).await;
        let mut patch = Box::pin(h.m.update(
            &source.id,
            api::UpdateMachineRequest {
                egress: Some(via_alias()),
                ..Default::default()
            },
            None,
        ));
        assert!(futures::poll!(&mut patch).is_pending());
        release_network(&h);
        moved.await.unwrap();
        assert!(matches!(
            patch.await,
            Err(MError::Conflict(why)) if why.contains("namespace changed")
        ));
        let now = h.stored(&source.id).unwrap();
        assert_eq!(now.namespace, "t2");
        assert_eq!(now.egress, api::Egress::default());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_derived_move_rechecks_egress_after_a_source_patch_wins() {
    tokio::time::timeout(BOUND, async {
        let h = harness("10.64.0.0/22", 4096).await;
        h.with_gateway().await;
        h.namespace("t2");
        h.m.set_gateway("t2", bound_spec(&binding("ab")))
            .await
            .unwrap();
        let source = h.m.create_made(h.request("open")).await.unwrap();
        mark_derived(&h, &source);
        pause_network(&h, "set_policy", &source.ip);
        let mut patch = Box::pin(h.m.update(
            &source.id,
            api::UpdateMachineRequest {
                egress: Some(via_alias()),
                ..Default::default()
            },
            None,
        ));
        at_network(&h, patch.as_mut()).await;
        let mut moved = Box::pin(h.m.move_machine(&source.id, "t2", None));
        assert!(futures::poll!(&mut moved).is_pending());
        release_network(&h);
        patch.await.unwrap();
        h.host.calls();
        h.pool.calls();
        assert!(matches!(
            moved.await,
            Err(MError::Conflict(why)) if why.contains("created fresh")
        ));
        assert!(h.host.calls().is_empty());
        assert!(h.pool.calls().is_empty());
        let now = h.stored(&source.id).unwrap();
        assert_eq!(
            (now.namespace.as_str(), now.state.as_str(), now.ip),
            ("t1", state::RUNNING, source.ip)
        );
        assert!(now.egress.via_gateway());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn opposite_derived_moves_take_namespace_names_in_one_order() {
    tokio::time::timeout(BOUND, async {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        h.namespace("t2");
        let a = created(&h, "t1", "a").await;
        let b = created(&h, "t2", "b").await;
        mark_derived(&h, &a);
        mark_derived(&h, &b);
        pause_network(&h, "count", "10.64.2.3");
        let mut there = Box::pin(h.m.move_machine(&a.id, "t2", None));
        at_network(&h, there.as_mut()).await;
        let mut back = Box::pin(h.m.move_machine(&b.id, "t1", None));
        assert!(futures::poll!(&mut back).is_pending());
        release_network(&h);
        let (there, back) = tokio::join!(there, back);
        assert_eq!(there.unwrap().machine.namespace, "t2");
        assert_eq!(back.unwrap().machine.namespace, "t1");
        assert!(h.m.inner.address_holds.lock().unwrap().is_empty());
        assert_eq!(h.m.inner.namespace_turns.len(), 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn open_singleton_rename_and_policy_put_order_both_ways() {
    for move_first in [true, false] {
        tokio::time::timeout(BOUND, async {
            let h = harness("10.64.0.0/22", 4096).await;
            h.ready().await;
            serve_dns(&h);
            let source = created(&h, "t1", "single").await;
            let mut moved = Box::pin(h.m.move_machine(&source.id, "t2", None));
            let mut put = Box::pin(h.m.set_gateway("t1", bound_spec(&binding("ab"))));
            let result = if move_first {
                pause_network(&h, "counters", "*");
                at_network(&h, moved.as_mut()).await;
                assert!(futures::poll!(&mut put).is_pending());
                assert!(h.m.gateway_of("t1").is_none());
                assert!(h.m.namespace_of("t2").is_none());
                release_network(&h);
                let result = moved.await.unwrap();
                assert!(h.m.namespace_of("t1").is_none());
                put.await.unwrap();
                assert_eq!(result.machine.ip, source.ip);
                result
            } else {
                pause_network(&h, "count", "10.64.1.3");
                at_network(&h, put.as_mut()).await;
                assert!(futures::poll!(&mut moved).is_pending());
                assert!(h.m.namespace_of("t2").is_none());
                release_network(&h);
                put.await.unwrap();
                let result = moved.await.unwrap();
                assert_ne!(result.machine.ip, source.ip);
                result
            };
            assert!(!result.restarted);
            assert_eq!(h.stored(&source.id).unwrap().namespace, "t2");
            assert!(h
                .m
                .gateway_of("t1")
                .unwrap()
                .snapshot()
                .gateway_policy
                .is_some());
            assert!(h.m.gateway_of("t2").is_none());
        })
        .await
        .unwrap();
    }
}

fn literal_via(id: &str) -> api::Egress {
    api::Egress {
        via: Some(id.into()),
        ..via_alias()
    }
}

#[tokio::test]
async fn actual_policy_gateway_literals_are_not_peers_or_stale_gateway_ids() {
    for configured in [false, true] {
        tokio::time::timeout(BOUND, async {
            let h = harness("10.64.0.0/22", 4096).await;
            let b = binding("ab");
            let gateway = if configured {
                h.with_bound_gateway(&b).await
            } else {
                h.with_gateway().await
            };
            let peer = created(&h, "t1", "peer").await;
            let source = created(&h, "t1", "derived").await;
            mark_derived(&h, &source);
            let patch = |egress| {
                h.m.update(
                    &source.id,
                    api::UpdateMachineRequest {
                        egress: Some(egress),
                        ..Default::default()
                    },
                    None,
                )
            };
            patch(literal_via(&peer.id)).await.unwrap();
            let to_gateway = patch(literal_via(&gateway)).await;
            if configured {
                assert!(matches!(
                    to_gateway,
                    Err(MError::Conflict(why)) if why.contains("created fresh")
                ));
                assert_eq!(h.stored(&source.id).unwrap().egress, literal_via(&peer.id));
            } else {
                to_gateway.unwrap();
                {
                    let machines = h.m.inner.machines.lock().unwrap();
                    assert!(matches!(
                        h.m.check_policy_dependents(&machines, "t1", Some(&gateway)),
                        Err(MError::Conflict(_))
                    ));
                    h.m.check_policy_dependents(&machines, "t1", None).unwrap();
                }
                h.m.delete_gateway("t1").await.unwrap();
                let new =
                    h.m.set_gateway("t1", bound_spec(&b))
                        .await
                        .unwrap()
                        .gateway
                        .unwrap();
                assert_ne!(new.machine_id, gateway);
                assert_eq!(h.stored(&source.id).unwrap().egress, literal_via(&gateway));
            }
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn the_final_policy_admission_check_matches_retained_literals_by_exact_id() {
    tokio::time::timeout(BOUND, async {
        let (h, source, mut request) = crate::machine::assignments::tests::fixture().await;
        h.ready().await;
        let gateway =
            h.m.set_gateway("destination", gateway_spec(3128))
                .await
                .unwrap()
                .gateway
                .unwrap();
        request.egress = Some(literal_via(&gateway.machine_id));
        h.m.stage_destination_assignment(request, &source, 3)
            .await
            .unwrap();
        assert_eq!(h.m.assignment_targets().len(), 1);
        h.m.delete_gateway("destination").await.unwrap();
        {
            let machines = h.m.inner.machines.lock().unwrap();
            assert!(matches!(
                h.m.check_policy_dependents(&machines, "destination", Some(&gateway.machine_id)),
                Err(MError::Conflict(_))
            ));
            h.m.check_policy_dependents(&machines, "destination", Some("m_other"))
                .unwrap();
        }
        let new =
            h.m.set_gateway("destination", bound_spec(&binding("ab")))
                .await
                .unwrap()
                .gateway
                .unwrap();
        assert_ne!(new.machine_id, gateway.machine_id);
        assert_eq!(
            h.m.assignment_targets()[0].egress,
            literal_via(&gateway.machine_id)
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_same_namespace_move_answers_before_any_turn_or_lock() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = created(&h, "t1", "staying").await;
    let e = h.m.entry(&m.id).unwrap();
    let _policy =
        h.m.inner
            .namespace_turns
            .take("t1", crate::machine::gateway_policy::POLICY_ADMISSION)
            .await;
    let _creating = h.m.inner.namespace_create.lock().await;
    let _entry = e.lock.lock().await;
    tokio::time::timeout(BOUND, h.m.move_machine(&m.id, "t1", None))
        .await
        .expect("a no-op move answers without waiting")
        .unwrap();
    assert_eq!(e.snapshot().namespace, "t1");
}
