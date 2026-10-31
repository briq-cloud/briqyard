//! Explicit namespace peer permission and address ownership across lifecycle operations.
use super::*;

fn opted(mut request: api::CreateMachineRequest, gateway: &str) -> api::CreateMachineRequest {
    request.egress = Some(api::Egress {
        mode: api::egress::VIA.into(),
        via: Some(gateway.into()),
        siblings: true,
    });
    request
}

#[tokio::test]
async fn sibling_opt_in_is_persisted_patched_atomically_and_rebuilt_only_for_live_pins() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let gateway = h.m.create_made(h.request("gateway")).await.unwrap();
    let consumer =
        h.m.create_made(opted(h.request("consumer"), &gateway.id))
            .await
            .unwrap();
    assert!(h.stored(&consumer.id).unwrap().egress.siblings);
    let (_, policy) =
        h.m.inner
            .policies
            .lock()
            .unwrap()
            .get(&consumer.id)
            .unwrap()
            .clone();
    assert!(matches!(policy, nft::Policy::Via { siblings: true, .. }));
    h.host.calls();
    let strict = api::Egress {
        siblings: false,
        ..consumer.egress.clone()
    };
    h.m.update(
        &consumer.id,
        api::UpdateMachineRequest {
            egress: Some(strict.clone()),
            ..Default::default()
        },
        None,
    )
    .await
    .unwrap();
    assert!(!h.stored(&consumer.id).unwrap().egress.siblings);
    assert!(h
        .host
        .calls()
        .iter()
        .any(|call| call.starts_with("swap_policy") && call.contains(" siblings ->")));
    h.host.refuse_policies.store(true, Relaxed);
    assert!(h
        .m
        .update(
            &consumer.id,
            api::UpdateMachineRequest {
                egress: Some(consumer.egress),
                ..Default::default()
            },
            None
        )
        .await
        .is_err());
    assert_eq!(h.stored(&consumer.id).unwrap().egress, strict);
    h.host.refuse_policies.store(false, Relaxed);
    h.m.stop(&consumer.id, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    let rules = h.m.rules().unwrap();
    assert!(!rules.members.iter().any(|(_, ip)| ip == &consumer.ip));
    assert!(rules.members.iter().any(|(_, ip)| ip == &gateway.ip));
}

#[tokio::test]
async fn same_owner_suspend_and_resume_does_not_flush_connections() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let machine = h.m.create_made(h.request("owner")).await.unwrap();
    let cleared = h.host.cleared_ips.lock().unwrap().clone();
    assert_eq!(cleared.as_slice(), std::slice::from_ref(&machine.ip));
    h.m.stop(&machine.id, Duration::from_secs(1), true, None)
        .await
        .unwrap();
    h.m.start(&machine.id, None).await.unwrap();
    assert_eq!(*h.host.cleared_ips.lock().unwrap(), cleared);
    h.m.stop(&machine.id, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    h.m.start(&machine.id, None).await.unwrap();
    assert_eq!(*h.host.cleared_ips.lock().unwrap(), cleared);
}

#[tokio::test]
async fn failed_connection_cleanup_cannot_free_an_address_for_another_owner() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let old = h.m.create_made(h.request("old")).await.unwrap();
    h.host.refuse_clear.store(true, Relaxed);
    assert!(h.m.destroy(&old.id, None).await.is_err());
    assert_eq!(
        h.m.entry(&old.id).unwrap().snapshot().state,
        state::DESTROYING
    );
    let next =
        h.m.create_made(api::CreateMachineRequest {
            start: Some(false),
            ..h.request("next")
        })
        .await
        .unwrap();
    assert_ne!(next.ip, old.ip);
    h.host.refuse_clear.store(false, Relaxed);
    h.m.destroy(&old.id, None).await.unwrap();
    let reused = h.m.create_made(h.request("reused")).await.unwrap();
    assert_eq!(reused.ip, old.ip);
    assert!(
        h.host
            .cleared_ips
            .lock()
            .unwrap()
            .iter()
            .filter(|ip| *ip == &old.ip)
            .count()
            >= 3
    );
}

#[tokio::test]
async fn membership_follows_moves_and_adoption_without_flushing_a_known_owner() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    h.namespace("t2");
    let machine = h.m.create_made(h.request("peer")).await.unwrap();
    let moved =
        h.m.move_machine(&machine.id, "t2", None)
            .await
            .unwrap()
            .machine;
    let attachments = h.host.attachments.lock().unwrap().clone();
    assert_eq!(attachments[&machine.id].0, "by2");
    assert_eq!(attachments[&machine.id].1, moved.ip);
    assert!(h.host.cleared_ips.lock().unwrap().contains(&machine.ip));
    assert!(h.host.cleared_ips.lock().unwrap().contains(&moved.ip));
    let clears = h.host.cleared_ips.lock().unwrap().clone();
    let _held = h.m.hand_over().await;
    let rules = h.m.rules().unwrap();
    assert!(rules.members.contains(&("by2".into(), moved.ip.clone())));
    assert!(!rules.members.iter().any(|(_, ip)| ip == &machine.ip));
    assert_eq!(h.m.recover().await, (1, 0, 0));
    assert_eq!(*h.host.cleared_ips.lock().unwrap(), clears);
}

#[tokio::test]
async fn a_refused_policy_transaction_never_admits_a_machine_as_a_peer() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let gateway = h.m.create_made(h.request("gateway")).await.unwrap();
    h.host.refuse_policies.store(true, Relaxed);
    assert!(h
        .m
        .create_made(opted(h.request("denied"), &gateway.id))
        .await
        .is_err());
    let rules = h.m.rules().unwrap();
    assert_eq!(rules.members, [("by1".into(), gateway.ip)]);
    assert_eq!(h.host.attachments.lock().unwrap().len(), 1);
}
