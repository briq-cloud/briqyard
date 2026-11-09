//! Admission stays outside a namespace until its bridge deletion has completed.

use super::*;
use std::task::Poll;

#[tokio::test]
async fn create_waits_for_namespace_teardown() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.namespace("t1");
    h.host
        .pause_bridge_delete
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let mut tasks = tokio::task::JoinSet::new();
    let manager = h.m.clone();
    tasks.spawn(async move { manager.delete_namespace("t1").await });
    tokio::time::timeout(
        Duration::from_secs(5),
        h.host.bridge_delete_started.notified(),
    )
    .await
    .unwrap();
    let mut req = h.request("new");
    req.volume = None;
    req.start = Some(false);
    let create = h.m.record(req, None);
    tokio::pin!(create);
    // A single poll reaches the admission gate. It cannot insert a record while the old
    // bridge is still being removed, and no elapsed-time assumption is needed.
    assert!(matches!(futures::poll!(create.as_mut()), Poll::Pending));
    assert!(h.m.list(Some("t1"), &[]).is_empty());
    h.host.bridge_delete_release.notify_one();
    tokio::time::timeout(Duration::from_secs(5), tasks.join_next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .unwrap();
    // The harness seeds namespaces without a real DNS socket, as the other manager tests do.
    // Recreate the namespace after teardown; the pending admission must use this instance.
    h.namespace("t1");
    let (e, _) = tokio::time::timeout(Duration::from_secs(5), create)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(h.m.namespace("t1").unwrap().machines, 1);
    assert_eq!(e.snapshot().namespace, "t1");
    h.m.destroy_machine(&e.snapshot().id, None).await.unwrap();
}

#[tokio::test]
async fn deletion_refuses_an_admitted_machine() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.namespace("t1");
    let mut req = h.request("held");
    req.volume = None;
    req.start = Some(false);
    let (e, _) = h.m.record(req, None).await.unwrap();
    h.host_calls();
    assert!(matches!(
        h.m.delete_namespace("t1").await,
        Err(MError::NamespaceInUse)
    ));
    assert!(!h
        .host_calls()
        .iter()
        .any(|c| c.starts_with("delete_bridge ")));
    h.m.destroy_machine(&e.snapshot().id, None).await.unwrap();
}

#[tokio::test]
async fn protected_empty_namespace_retains_network_and_subnet() {
    let h = harness("10.64.0.0/22", 4096).await;
    let t = h.namespace("t1");
    let now = crate::machine::execution_mutations::execution_now_ms().unwrap();
    {
        let mut fence = h.m.inner.execution_fence.lock().unwrap();
        let generations = fence
            .snapshot(&h.m.inner.store, &["t1".into()], now)
            .unwrap();
        fence
            .protect(&h.m.inner.store, &generations, now + 30_000, now)
            .unwrap();
    }
    h.host_calls();
    assert!(h.m.delete_namespace("t1").await.is_err());
    assert!(h.m.namespace("t1").is_ok());
    assert!(!h
        .host_calls()
        .iter()
        .any(|c| c.starts_with("delete_bridge ")));
    let namespaces = h.m.inner.namespaces.lock().unwrap();
    assert_eq!(namespaces["t1"].rec.subnet_index, t.rec.subnet_index);
}

#[tokio::test]
async fn failed_namespace_record_deletion_keeps_subnet_reserved() {
    let h = harness("10.64.0.0/22", 4096).await;
    let t = h.namespace("t1");
    let dir = h.m.inner.store.dir(crate::store::NAMESPACES);
    let moved = dir.with_extension("held");
    std::fs::rename(&dir, &moved).unwrap();
    std::fs::write(&dir, b"not a directory").unwrap();
    let result = h.m.delete_namespace("t1").await;
    std::fs::remove_file(&dir).unwrap();
    std::fs::rename(&moved, &dir).unwrap();
    assert!(result.is_err());
    assert_eq!(h.m.namespace("t1").unwrap().subnet, t.subnet.cidr());
    let now = crate::machine::execution_mutations::execution_now_ms().unwrap();
    assert!(h
        .m
        .inner
        .execution_fence
        .lock()
        .unwrap()
        .snapshot(&h.m.inner.store, &["t1".into()], now,)
        .is_err());
    let namespaces = h.m.inner.namespaces.lock().unwrap();
    assert_ne!(
        h.m.free_namespace_subnet(&namespaces).unwrap(),
        t.rec.subnet_index
    );
}
