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
async fn a_failed_namespace_keeps_its_durable_subnet_and_pending_ticket() {
    let h = harness("10.64.0.0/22", 4096).await;
    serve_all(&h);
    let all: Vec<String> = (0..h.m.inner.range.count())
        .map(netw::bridge_name)
        .collect();
    *h.host.refuse_bridge.lock().unwrap() = all;
    assert!(h.m.ensure_namespace("a").await.is_err());
    assert_eq!(
        h.m.inner.namespace_reserved.lock().unwrap().get("a"),
        Some(&0)
    );
    assert!(h.m.inner.namespaces.lock().unwrap().is_empty());
    assert_eq!(h.m.inner.namespace_turns.len(), 0);
    let stored: NamespaceRec =
        h.m.inner
            .store
            .get(crate::store::NAMESPACES, "a")
            .unwrap()
            .unwrap();
    assert_eq!(stored.subnet_index, 0);
    let mut reopened = execution_fence::ExecutionFence::load(&h.m.inner.store).unwrap();
    assert!(reopened
        .snapshot(
            &h.m.inner.store,
            &["a".into()],
            crate::machine::execution_mutations::execution_now_ms().unwrap(),
        )
        .is_err());
    let now = crate::machine::execution_mutations::execution_now_ms().unwrap();
    assert!(h
        .m
        .inner
        .execution_fence
        .lock()
        .unwrap()
        .snapshot(&h.m.inner.store, &["a".into()], now,)
        .is_err());
    // The same name cannot start a second effect while the first is unresolved.
    h.host.refuse_bridge.lock().unwrap().clear();
    assert!(h.m.ensure_namespace("a").await.is_err());
    let t = h.m.ensure_namespace("b").await.unwrap();
    assert_eq!(t.rec.subnet_index, 1);
    assert_eq!(
        h.m.inner.namespace_reserved.lock().unwrap().get("a"),
        Some(&0)
    );
}

#[tokio::test]
async fn cancelled_namespace_create_keeps_its_subnet_and_ticket() {
    let h = harness("10.64.0.0/22", 4096).await;
    serve_all(&h);
    h.pause_warm_barrier("ensure_bridge");
    let create = ensure(&h, "a");
    arrived_at_bridge(&h, 1).await;
    create.abort();
    assert!(matches!(create.await, Err(error) if error.is_cancelled()));
    h.end_warm_barrier();
    assert_eq!(
        h.m.inner.namespace_reserved.lock().unwrap().get("a"),
        Some(&0)
    );
    let stored: NamespaceRec =
        h.m.inner
            .store
            .get(crate::store::NAMESPACES, "a")
            .unwrap()
            .unwrap();
    assert_eq!(stored.subnet_index, 0);
    let now = crate::machine::execution_mutations::execution_now_ms().unwrap();
    assert!(h
        .m
        .inner
        .execution_fence
        .lock()
        .unwrap()
        .snapshot(&h.m.inner.store, &["a".into()], now)
        .is_err());
    assert!(h.m.ensure_namespace("a").await.is_err());
    assert_eq!(h.m.ensure_namespace("b").await.unwrap().rec.subnet_index, 1);
}

#[tokio::test]
async fn protected_name_refuses_creation_before_bridge_setup() {
    let h = harness("10.64.0.0/22", 4096).await;
    let now = crate::machine::execution_mutations::execution_now_ms().unwrap();
    {
        let mut fence = h.m.inner.execution_fence.lock().unwrap();
        let generations = fence
            .snapshot(&h.m.inner.store, &["a".into()], now)
            .unwrap();
        fence
            .protect(&h.m.inner.store, &generations, now + 30_000, now)
            .unwrap();
    }
    assert!(h.m.ensure_namespace("a").await.is_err());
    assert!(h.host_calls().is_empty());
    assert!(h.m.inner.namespace_reserved.lock().unwrap().is_empty());
}

#[tokio::test]
async fn failed_durable_namespace_write_keeps_pending_ticket_and_subnet() {
    let h = harness("10.64.0.0/22", 4096).await;
    serve_all(&h);
    let dir = h.m.inner.store.dir(crate::store::NAMESPACES);
    let moved = dir.with_extension("held");
    std::fs::rename(&dir, &moved).unwrap();
    std::fs::write(&dir, b"not a directory").unwrap();
    let result = h.m.ensure_namespace("a").await;
    std::fs::remove_file(&dir).unwrap();
    std::fs::rename(&moved, &dir).unwrap();
    assert!(result.is_err());
    assert_eq!(
        h.m.inner.namespace_reserved.lock().unwrap().get("a"),
        Some(&0)
    );
    assert!(h.m.inner.namespaces.lock().unwrap().get("a").is_none());
    let now = crate::machine::execution_mutations::execution_now_ms().unwrap();
    assert!(h
        .m
        .inner
        .execution_fence
        .lock()
        .unwrap()
        .snapshot(&h.m.inner.store, &["a".into()], now,)
        .is_err());
    assert!(h.m.ensure_namespace("a").await.is_err());
    assert_eq!(h.m.ensure_namespace("b").await.unwrap().rec.subnet_index, 1);
}

#[tokio::test]
async fn deleted_namespace_name_can_be_created_again() {
    let h = harness("10.64.0.0/22", 4096).await;
    serve_all(&h);
    let first = h.m.ensure_namespace("a").await.unwrap();
    h.m.delete_namespace("a").await.unwrap();
    assert!(h.m.namespace("a").is_err());
    serve_all(&h);
    let second = h.m.ensure_namespace("a").await.unwrap();
    assert_eq!(second.rec.subnet_index, first.rec.subnet_index);
    let stored: NamespaceRec =
        h.m.inner
            .store
            .get(crate::store::NAMESPACES, "a")
            .unwrap()
            .unwrap();
    assert_eq!(stored.subnet_index, second.rec.subnet_index);
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
