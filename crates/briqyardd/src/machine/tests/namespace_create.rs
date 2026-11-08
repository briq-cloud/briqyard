//! Namespaces are made in parallel, one namespace once (ADR 0118): the bridge and the record
//! are outside `namespace_create`, which only chooses and reserves the subnet index.

use super::*;

/// The bridge step of a create is held; the DNS socket is not needed.
fn serve_all(h: &Harness) {
    let range = &h.m.inner.range;
    for i in 0..range.count() {
        h.m.inner
            .dns
            .assume_listening(range.subnet(i).unwrap().gateway());
    }
}

async fn made(task: tokio::task::JoinHandle<Result<Namespace>>) -> Namespace {
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the namespace was made")
        .unwrap()
        .unwrap()
}

async fn settle() {
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
}

fn ensure(h: &Harness, id: &'static str) -> tokio::task::JoinHandle<Result<Namespace>> {
    let m = h.m.clone();
    tokio::spawn(async move { m.ensure_namespace(id).await })
}

async fn arrived_at_bridge(h: &Harness, n: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while h.warm_barrier_arrivals() < n {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("the creates reached the bridge");
}

fn bridges_made(h: &Harness) -> usize {
    h.host_calls()
        .iter()
        .filter(|c| c.starts_with("ensure_bridge"))
        .count()
}

#[tokio::test]
async fn two_new_namespaces_plumb_their_networks_at_the_same_time() {
    let h = harness("10.64.0.0/22", 4096).await;
    serve_all(&h);
    h.pause_warm_barrier("ensure_bridge");
    let a = ensure(&h, "a");
    let b = ensure(&h, "b");
    // Both are at the bridge together; with the lock held over it the second never gets there.
    arrived_at_bridge(&h, 2).await;
    {
        let reserved = h.m.inner.namespace_reserved.lock().unwrap();
        assert_eq!(reserved.len(), 2);
        assert_ne!(reserved["a"], reserved["b"]);
    }
    h.end_warm_barrier();
    let (a, b) = (made(a).await, made(b).await);
    assert_ne!(a.rec.subnet_index, b.rec.subnet_index);
    for t in [&a, &b] {
        let stored: NamespaceRec =
            h.m.inner
                .store
                .get(crate::store::NAMESPACES, &t.rec.id)
                .unwrap()
                .unwrap();
        assert_eq!(stored.subnet_index, t.rec.subnet_index);
    }
    assert!(h.m.inner.namespace_reserved.lock().unwrap().is_empty());
    assert_eq!(h.m.inner.namespace_turns.len(), 0);
}

#[tokio::test]
async fn two_creates_of_one_new_namespace_make_it_once() {
    let h = harness("10.64.0.0/22", 4096).await;
    serve_all(&h);
    h.pause_warm_barrier("ensure_bridge");
    let first = ensure(&h, "a");
    arrived_at_bridge(&h, 1).await;
    let second = ensure(&h, "a");
    settle().await;
    // The second waits for the first rather than reserving another index.
    assert_eq!(h.warm_barrier_arrivals(), 1);
    assert_eq!(h.m.inner.namespace_reserved.lock().unwrap().len(), 1);
    h.end_warm_barrier();
    let (first, second) = (made(first).await, made(second).await);
    assert_eq!(first.rec.subnet_index, second.rec.subnet_index);
    assert_eq!(first.rec.created_at, second.rec.created_at);
    assert_eq!(bridges_made(&h), 1);
    assert_eq!(h.m.inner.namespaces.lock().unwrap().len(), 1);
    assert!(h.m.inner.namespace_reserved.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_failed_namespace_leaves_no_reservation_and_no_record() {
    let h = harness("10.64.0.0/22", 4096).await;
    serve_all(&h);
    let all: Vec<String> = (0..h.m.inner.range.count())
        .map(netw::bridge_name)
        .collect();
    *h.host.refuse_bridge.lock().unwrap() = all;
    assert!(h.m.ensure_namespace("a").await.is_err());
    assert!(h.m.inner.namespace_reserved.lock().unwrap().is_empty());
    assert!(h.m.inner.namespaces.lock().unwrap().is_empty());
    assert_eq!(h.m.inner.namespace_turns.len(), 0);
    let stored: Option<NamespaceRec> = h.m.inner.store.get(crate::store::NAMESPACES, "a").unwrap();
    assert!(stored.is_none());
    // Nothing trusts the failed attempt: the next create makes it, on the index just freed.
    h.host.refuse_bridge.lock().unwrap().clear();
    let t = h.m.ensure_namespace("a").await.unwrap();
    assert_eq!(t.rec.subnet_index, 0);
    assert!(h.m.inner.namespace_reserved.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_delete_waits_for_a_create_that_is_making_its_namespace() {
    let h = harness("10.64.0.0/22", 4096).await;
    serve_all(&h);
    h.ready().await;
    h.pause_warm_barrier("ensure_bridge");
    let mut req = h.request("new");
    req.namespace = "t9".into();
    req.volume = None;
    req.start = Some(false);
    let m = h.m.clone();
    let create = tokio::spawn(async move { m.record(req, None).await });
    arrived_at_bridge(&h, 1).await;
    let m = h.m.clone();
    let delete = tokio::spawn(async move { m.delete_namespace("t9").await });
    settle().await;
    // The delete does not pass over a namespace whose bridge is being made.
    assert!(!delete.is_finished());
    h.end_warm_barrier();
    let (e, _) = tokio::time::timeout(Duration::from_secs(5), create)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let deleted = tokio::time::timeout(Duration::from_secs(5), delete)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(deleted, Err(MError::NamespaceInUse)));
    assert!(h.m.namespace("t9").is_ok());
    assert_eq!(e.snapshot().namespace, "t9");
    assert!(h.m.inner.namespace_reserved.lock().unwrap().is_empty());
}
