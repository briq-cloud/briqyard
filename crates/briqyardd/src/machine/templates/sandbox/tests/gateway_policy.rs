use super::*;

fn policy_spec() -> api::GatewaySpec {
    api::GatewaySpec {
        image: ALPINE.into(),
        port: 3128,
        policy: Some(api::GatewayPolicyBinding {
            policy_format: 1,
            policy_digest: format!("sha256:{}", "ab".repeat(32)),
            enforcement_version: 1,
        }),
        ..Default::default()
    }
}

fn legacy_spec() -> api::GatewaySpec {
    api::GatewaySpec {
        image: ALPINE.into(),
        port: 3128,
        ..Default::default()
    }
}

fn via_gateway() -> Option<api::Egress> {
    Some(api::Egress {
        mode: api::egress::VIA.into(),
        via: Some("gateway".into()),
        siblings: false,
        gateway_policy: None,
    })
}

#[tokio::test]
async fn warm_selector_serializes_gateway_deletion_before_policy_introduction() {
    for (put_first, uncertain) in [(true, false), (false, false), (false, true)] {
        let (h, seed, slot) = unbound::bounded(unbound::pool()).await;
        h.m.set_gateway("destination", legacy_spec()).await.unwrap();
        let mut req = destination(seed);
        req.egress = via_gateway();
        h.pause_warm_barrier("assignment_stage");
        let m = h.m.clone();
        let assigning = tokio::spawn(async move { m.record(req, None).await });
        h.wait_warm_barrier().await;
        assert!(h.m.assignment_targets().is_empty());
        let namespace = h.m.namespace_of("destination").unwrap();
        assert!(namespace.lock.try_lock().is_ok());
        if put_first {
            unbound::bounded(h.m.delete_gateway("destination"))
                .await
                .unwrap();
            unbound::bounded(h.m.set_gateway("destination", policy_spec()))
                .await
                .unwrap();
        }
        if uncertain {
            h.m.inner.store.fail_next_sync.store(true, Relaxed);
        }
        h.end_warm_barrier();
        let result = unbound::bounded(assigning).await.unwrap();
        if put_first {
            assert!(result.is_err());
            assert!(h.m.assignment_targets().is_empty());
            assert!(h.m.unsupported_policy_records().is_empty());
            assert!(h.m.gateway_of("destination").is_some());
            continue;
        }
        if uncertain {
            assert!(result.is_err());
        } else {
            let (assigned, how) = result.unwrap();
            assert!(matches!(how, Make::Assigned));
            assert_eq!(assigned.snapshot().id, slot.snapshot().id);
        }
        let deleted = h.m.delete_gateway("destination").await.is_ok();
        let put = h.m.set_gateway("destination", policy_spec()).await;
        if deleted {
            assert!(h.m.gateway_of("destination").is_none());
            assert!(matches!(put, Err(MError::Conflict(_))));
        } else {
            assert!(put.is_err());
        }
    }
}

async fn seed_create_holding_warm_never_waits_for_a_namespace_turn(exclusive: bool) {
    let (h, seed) = if exclusive {
        let (h, seed, _slot) = unbound::bounded(unbound::pool()).await;
        (h, seed)
    } else {
        let (h, _source, seed) = unbound::bounded(source()).await;
        (h, seed)
    };
    h.m.set_gateway("destination", legacy_spec()).await.unwrap();
    let mut req = destination(seed);
    req.egress = via_gateway();
    let sandbox = h.m.inner.sandbox_create_lock.write().await;
    let m = h.m.clone();
    let creating = tokio::spawn(async move { m.record(req, None).await.map(|_| ()) });
    unbound::bounded(async {
        while h.m.inner.warm_lock.try_write().is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let namespace = h.m.namespace_of("destination").unwrap();
    let gateway_turn = namespace.lock.clone().lock_owned().await;
    let m = h.m.clone();
    let reserving = tokio::spawn(async move {
        let _gateway = gateway_turn;
        let _warm = m.inner.warm_lock.write().await;
    });
    unbound::bounded(async {
        while namespace.lock.try_lock().is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    drop(sandbox);
    unbound::bounded(creating).await.unwrap().unwrap();
    unbound::bounded(reserving).await.unwrap();
}

#[tokio::test]
async fn an_exclusive_seed_create_and_an_assigned_reservation_both_finish() {
    seed_create_holding_warm_never_waits_for_a_namespace_turn(true).await;
}

#[tokio::test]
async fn a_shared_seed_create_and_an_assigned_reservation_both_finish() {
    seed_create_holding_warm_never_waits_for_a_namespace_turn(false).await;
}

#[tokio::test]
async fn warm_selector_refuses_a_request_through_a_policy_gateway() {
    let (h, seed, _slot) = unbound::bounded(unbound::pool()).await;
    h.m.set_gateway("destination", policy_spec()).await.unwrap();
    let mut req = destination(seed);
    req.egress = via_gateway();
    assert!(h.m.record(req, None).await.is_err());
    assert!(h.m.assignment_targets().is_empty());
}
