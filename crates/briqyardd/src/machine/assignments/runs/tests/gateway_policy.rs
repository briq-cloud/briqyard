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
