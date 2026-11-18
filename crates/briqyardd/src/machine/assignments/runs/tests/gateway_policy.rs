use super::*;
use std::future::Future;

fn binding() -> api::GatewayPolicyBinding {
    api::GatewayPolicyBinding {
        policy_format: 1,
        policy_digest: format!("sha256:{}", "ab".repeat(32)),
        enforcement_version: 1,
    }
}

fn policy_spec(h: &crate::machine::tests::Harness) -> api::GatewaySpec {
    api::GatewaySpec {
        image: h.request("gateway").image,
        port: 3128,
        policy: Some(binding()),
        ..Default::default()
    }
}

fn legacy_spec(h: &crate::machine::tests::Harness) -> api::GatewaySpec {
    api::GatewaySpec {
        image: h.request("gateway").image,
        port: 3128,
        ..Default::default()
    }
}

fn via_gateway(bound: bool) -> api::Egress {
    api::Egress {
        mode: api::egress::VIA.into(),
        via: Some("gateway".into()),
        siblings: false,
        gateway_policy: bound.then(binding),
    }
}

#[tokio::test]
async fn an_assignment_never_depends_on_a_policy_gateway() {
    let (h, entry, mut request) = crate::machine::assignments::tests::fixture().await;
    h.ready().await;
    h.gateway_policy_answers(binding(), true);
    let gateway =
        h.m.set_gateway("destination", policy_spec(&h))
            .await
            .unwrap()
            .gateway
            .unwrap()
            .machine_id;
    h.host_calls();
    for egress in [
        via_gateway(true),
        via_gateway(false),
        api::Egress {
            mode: api::egress::VIA.into(),
            via: Some(gateway),
            ..Default::default()
        },
    ] {
        request.egress = Some(egress);
        assert!(h
            .m
            .stage_destination_assignment(request.clone(), &entry, 3)
            .await
            .is_err());
        assert!(h.m.assignment_targets().is_empty());
    }
    assert!(h.host_calls().is_empty());
    request.egress = Some(api::Egress::default());
    h.m.stage_destination_assignment(request, &entry, 3)
        .await
        .unwrap();
    assert_eq!(h.m.assignment_targets().len(), 1);
}

#[tokio::test]
async fn a_staged_assignment_keeps_a_policy_gateway_out_of_its_namespace() {
    let (h, entry, mut request) = crate::machine::assignments::tests::fixture().await;
    h.ready().await;
    h.gateway_policy_answers(binding(), true);
    h.m.set_gateway("destination", legacy_spec(&h))
        .await
        .unwrap();
    request.egress = Some(via_gateway(false));
    h.m.stage_destination_assignment(request, &entry, 3)
        .await
        .unwrap();
    h.m.delete_gateway("destination").await.unwrap();
    assert!(matches!(
        h.m.set_gateway("destination", policy_spec(&h)).await,
        Err(MError::Conflict(_))
    ));
    assert!(h.m.gateway_of("destination").is_none());
}

#[tokio::test]
async fn a_committed_assignment_keeps_a_policy_gateway_out_of_its_namespace() {
    let (h, entry, mut request) = crate::machine::assignments::tests::fixture().await;
    h.ready().await;
    h.gateway_policy_answers(binding(), true);
    h.m.set_gateway("destination", legacy_spec(&h))
        .await
        .unwrap();
    request.egress = Some(via_gateway(false));
    let digest = templates::sandbox::request_digest(&request).unwrap();
    h.m.stage_destination_assignment(request, &entry, 3)
        .await
        .unwrap();
    h.m.delete_gateway("destination").await.unwrap();
    assert!(matches!(
        h.m.set_gateway("destination", policy_spec(&h)).await,
        Err(MError::Conflict(_))
    ));
    h.m.set_gateway("destination", legacy_spec(&h))
        .await
        .unwrap();
    h.m.commit_destination_assignment("destination", "assignment-one", &digest)
        .await
        .unwrap();
    assert!(h.m.assignment_targets().is_empty());
    assert_eq!(entry.snapshot().namespace, "destination");
    assert!(h.m.delete_gateway("destination").await.is_err());
    assert!(h
        .m
        .set_gateway("destination", policy_spec(&h))
        .await
        .is_err());
    assert!(h
        .m
        .gateway_of("destination")
        .unwrap()
        .snapshot()
        .gateway_policy
        .is_none());
}

#[tokio::test]
async fn paused_assignment_serializes_gateway_deletion_before_policy_introduction() {
    let (h, entry, mut request) = crate::machine::assignments::tests::fixture().await;
    h.ready().await;
    h.gateway_policy_answers(binding(), true);
    h.m.set_gateway("destination", legacy_spec(&h))
        .await
        .unwrap();
    request.egress = Some(via_gateway(false));
    let entry_turn = entry.lock.lock().await;
    let mut stage = Box::pin(h.m.stage_destination_assignment(request, &entry, 3));
    std::future::poll_fn(|cx| {
        assert!(stage.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    let namespace = h.m.namespace_of("destination").unwrap();
    assert!(namespace.lock.try_lock().is_ok());
    h.m.delete_gateway("destination").await.unwrap();
    h.m.set_gateway("destination", policy_spec(&h))
        .await
        .unwrap();
    drop(entry_turn);
    assert!(stage.await.is_err());
    assert!(h.m.assignment_targets().is_empty());
    assert!(h.m.unsupported_policy_records().is_empty());
    assert!(h.m.gateway_of("destination").is_some());
}

async fn bounded<T>(what: &str, future: impl Future<Output = T>) -> T {
    match tokio::time::timeout(Duration::from_secs(10), future).await {
        Ok(value) => value,
        Err(_) => panic!("{what} must complete"),
    }
}

async fn stopped_through_the_gateway() -> (crate::machine::tests::Harness, Arc<Entry>) {
    let (h, entry, mut request) = crate::machine::assignments::tests::fixture().await;
    h.ready().await;
    h.m.set_gateway("destination", legacy_spec(&h))
        .await
        .unwrap();
    request.egress = Some(via_gateway(false));
    let digest = templates::sandbox::request_digest(&request).unwrap();
    h.m.stage_destination_assignment(request, &entry, 3)
        .await
        .unwrap();
    h.m.start_destination_assignment("destination", "assignment-one", &digest)
        .await
        .unwrap();
    entry.rec.lock().unwrap().vmm_version = h.m.inner.vmm.version();
    h.m.save(&entry).unwrap();
    h.m.stop(&entry.snapshot().id, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    assert_eq!(entry.snapshot().state, state::STOPPED);
    (h, entry)
}

#[derive(Clone, Copy)]
enum NamespaceWaiter {
    GatewayPut,
    EgressPatch,
    ViaCreate,
}

async fn an_assigned_start_and_a_namespace_waiter_finish_beside_a_deletion(
    waiter: NamespaceWaiter,
) {
    let (h, entry) = stopped_through_the_gateway().await;
    h.namespace("spare");
    let mut ordinary = h.request("ordinary");
    ordinary.namespace = "destination".into();
    let ordinary = match waiter {
        NamespaceWaiter::EgressPatch => {
            ordinary.start = Some(false);
            Ok(h.m.create_made(ordinary).await.unwrap().id)
        }
        _ => {
            ordinary.egress = Some(via_gateway(false));
            Err(ordinary)
        }
    };
    let gateway = legacy_spec(&h);
    let warm = h.m.inner.warm_lock.read().await;
    let m = h.m.clone();
    let id = entry.snapshot().id;
    let starting = tokio::spawn(async move { m.start(&id, None).await.map(|_| ()) });
    bounded("the start's warm request", async {
        while h.m.inner.warm_lock.try_read().is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let m = h.m.clone();
    let waiting = tokio::spawn(async move {
        match (waiter, ordinary) {
            (NamespaceWaiter::GatewayPut, _) => {
                m.set_gateway("destination", gateway).await.map(|_| ())
            }
            (NamespaceWaiter::EgressPatch, Ok(id)) => m
                .update(
                    &id,
                    api::UpdateMachineRequest {
                        egress: Some(via_gateway(false)),
                        ..Default::default()
                    },
                    None,
                )
                .await
                .map(|_| ()),
            (_, Err(request)) => m.create(request).await.map(|_| ()),
            (_, Ok(_)) => unreachable!(),
        }
    });
    bounded("the waiter's admission", async {
        while h.m.inner.namespace_lifecycle.try_write().is_ok() && !waiting.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let m = h.m.clone();
    let deleting = tokio::spawn(async move { m.delete_namespace("spare").await });
    bounded("the deletion's request", async {
        while h.m.inner.namespace_lifecycle.try_read().is_ok() && !deleting.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    drop(warm);
    bounded("the namespace deletion", deleting)
        .await
        .unwrap()
        .unwrap();
    bounded("the namespace waiter", waiting)
        .await
        .unwrap()
        .unwrap();
    bounded("the assigned start", starting)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.snapshot().state, state::RUNNING);
    assert!(h.m.namespace_of("spare").is_none());
}

#[tokio::test]
async fn an_assigned_start_and_a_gateway_put_finish_beside_a_namespace_deletion() {
    an_assigned_start_and_a_namespace_waiter_finish_beside_a_deletion(NamespaceWaiter::GatewayPut)
        .await;
}

#[tokio::test]
async fn an_assigned_start_and_an_egress_patch_finish_beside_a_namespace_deletion() {
    an_assigned_start_and_a_namespace_waiter_finish_beside_a_deletion(NamespaceWaiter::EgressPatch)
        .await;
}

#[tokio::test]
async fn an_assigned_start_and_a_via_create_finish_beside_a_namespace_deletion() {
    an_assigned_start_and_a_namespace_waiter_finish_beside_a_deletion(NamespaceWaiter::ViaCreate)
        .await;
}
