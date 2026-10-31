//! Allocation races across an asynchronous move's preparation, commit and rollback.
use super::*;

fn stopped(h: &Harness, name: &str, namespace: &str) -> api::CreateMachineRequest {
    api::CreateMachineRequest {
        namespace: namespace.into(),
        start: Some(false),
        ..h.request(name)
    }
}

async fn rollback_race(operation: &'static str) {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    h.namespace("t2");
    let machine = h.m.create_made(stopped(&h, "moving", "t1")).await.unwrap();
    let destination = "10.64.2.2";
    *h.host.pause_network.lock().unwrap() = Some((operation, destination.into()));
    if operation == "clear" {
        *h.host.refuse_clear_ip.lock().unwrap() = Some(destination.into());
    } else {
        *h.host.refuse_count_ip.lock().unwrap() = Some(destination.into());
    }
    let manager = h.m.clone();
    let id = machine.id.clone();
    let moving = tokio::spawn(async move { manager.move_machine(&id, "t2", None).await });
    tokio::time::timeout(Duration::from_secs(3), h.host.network_started.notified())
        .await
        .unwrap();
    // Both allocators race with the in-flight move while the destination command is paused.
    let source_peer =
        h.m.create_made(stopped(&h, "source-peer", "t1"))
            .await
            .unwrap();
    let target_peer =
        h.m.create_made(stopped(&h, "target-peer", "t2"))
            .await
            .unwrap();
    *h.host.pause_network.lock().unwrap() = None;
    h.host.network_release.notify_one();
    assert!(tokio::time::timeout(Duration::from_secs(3), moving)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    assert_ne!(
        source_peer.ip, machine.ip,
        "source address was exposed before rollback"
    );
    assert_ne!(
        target_peer.ip, destination,
        "destination reservation was exposed before rollback"
    );
    assert_eq!(h.m.get(&machine.id).unwrap().ip, machine.ip);
    assert_eq!(h.stored(&machine.id).unwrap().ip, machine.ip);
    let machines = h.m.inner.machines.lock().unwrap();
    let unique: std::collections::HashSet<String> =
        machines.values().map(|e| e.snapshot().ip).collect();
    assert_eq!(
        unique.len(),
        machines.len(),
        "rollback created duplicate owners"
    );
    drop(machines);
    assert!(h.m.inner.address_holds.lock().unwrap().is_empty());
    *h.host.refuse_clear_ip.lock().unwrap() = None;
    *h.host.refuse_count_ip.lock().unwrap() = None;
    let retry =
        h.m.create_made(stopped(&h, "reusable", "t2"))
            .await
            .unwrap();
    assert_eq!(
        retry.ip, destination,
        "failed move did not release its destination hold"
    );
}

#[tokio::test]
async fn failed_destination_clear_reserves_both_addresses_against_concurrent_creates() {
    rollback_race("clear").await;
}

#[tokio::test]
async fn failed_destination_count_reserves_both_addresses_against_concurrent_creates() {
    rollback_race("count").await;
}

#[tokio::test]
async fn source_address_stays_reserved_until_its_old_counters_are_removed() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    h.namespace("t2");
    let machine = h.m.create_made(stopped(&h, "moving", "t1")).await.unwrap();
    *h.host.pause_network.lock().unwrap() = Some(("uncount", machine.ip.clone()));
    let manager = h.m.clone();
    let id = machine.id.clone();
    let moving = tokio::spawn(async move { manager.move_machine(&id, "t2", None).await });
    tokio::time::timeout(Duration::from_secs(3), h.host.network_started.notified())
        .await
        .unwrap();
    let peer = h.m.create_made(stopped(&h, "peer", "t1")).await.unwrap();
    *h.host.pause_network.lock().unwrap() = None;
    h.host.network_release.notify_one();
    tokio::time::timeout(Duration::from_secs(3), moving)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_ne!(
        peer.ip, machine.ip,
        "new counter owner raced old counter removal"
    );
    let reuse = h.m.create_made(stopped(&h, "reuse", "t1")).await.unwrap();
    assert_eq!(reuse.ip, machine.ip);
    assert!(h.host.counted.lock().unwrap().contains_key(&reuse.ip));
}

#[tokio::test]
async fn a_move_rechecks_destination_quota_after_async_preparation() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    h.namespace("t2");
    h.m.set_quota(
        "t2",
        api::Quota {
            machines: Some(1),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let machine = h.m.create_made(stopped(&h, "moving", "t1")).await.unwrap();
    *h.host.pause_network.lock().unwrap() = Some(("clear", "10.64.2.2".into()));
    let manager = h.m.clone();
    let id = machine.id.clone();
    let moving = tokio::spawn(async move { manager.move_machine(&id, "t2", None).await });
    tokio::time::timeout(Duration::from_secs(3), h.host.network_started.notified())
        .await
        .unwrap();
    h.m.create_made(stopped(&h, "peer", "t2")).await.unwrap();
    *h.host.pause_network.lock().unwrap() = None;
    h.host.network_release.notify_one();
    let result = tokio::time::timeout(Duration::from_secs(3), moving)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(MError::Quota(_))), "{result:?}");
    assert_eq!(h.m.get(&machine.id).unwrap().namespace, "t1");
    assert_eq!(h.m.namespace("t2").unwrap().machines, 1);
    assert!(h.m.inner.address_holds.lock().unwrap().is_empty());
}
