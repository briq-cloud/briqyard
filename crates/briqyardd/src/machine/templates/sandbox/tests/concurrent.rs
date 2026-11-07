//! Seed creates record concurrently (ADR 0117): they hold `warm_lock` and `sandbox_create_lock`
//! shared, take turns per request id, and stay exclusive against writers and unbound pools.
//! A create is held at the `count` step, inside the record, after its first durable writes and
//! before the last.
use super::*;
use tokio::task::JoinHandle;

type Recorded = Result<(Arc<Entry>, Make), MError>;

fn request(seed: &api::SandboxSeed, name: &str, request_id: &str) -> api::CreateMachineRequest {
    let mut req = destination(api::SandboxSeed {
        request_id: request_id.into(),
        ..seed.clone()
    });
    req.name = name.into();
    req
}

fn record(h: &Harness, req: api::CreateMachineRequest) -> JoinHandle<Recorded> {
    let m = h.m.clone();
    tokio::spawn(async move { m.record(req, None).await })
}

fn arrived(h: &Harness) -> usize {
    h.warm_barrier_arrivals()
}

async fn wait_arrived(h: &Harness, n: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while arrived(h) < n {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("the creates reached the held step");
}

/// Lets every other task run until it waits for something.
async fn settle() {
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
}

async fn done(task: JoinHandle<Recorded>) -> Recorded {
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the create ended")
        .unwrap()
}

#[tokio::test]
async fn seed_creates_with_different_requests_record_at_the_same_time() {
    let (h, _, seed) = source().await;
    h.pause_warm_barrier("count");
    let a = record(&h, request(&seed, "one", "create-a"));
    let b = record(&h, request(&seed, "two", "create-b"));
    // Both are inside the record at once; serialized, the second would never get there.
    wait_arrived(&h, 2).await;
    // Shared with each other, closed to a writer.
    for lock in [&h.m.inner.warm_lock, &h.m.inner.sandbox_create_lock] {
        assert!(lock.try_read().is_ok());
        assert!(lock.try_write().is_err());
    }
    h.end_warm_barrier();
    let (a, b) = (done(a).await.unwrap().0, done(b).await.unwrap().0);
    assert_ne!(a.snapshot().id, b.snapshot().id);
    assert_ne!(a.snapshot().ip, b.snapshot().ip);
    assert_eq!(h.m.inner.sandbox_turns.len(), 0);
}

#[tokio::test]
async fn twins_with_one_request_make_one_machine_and_wait_for_its_durable_writes() {
    let (h, _, seed) = source().await;
    let req = request(&seed, "one", "create-a");
    h.pause_warm_barrier("count");
    let first = record(&h, req.clone());
    wait_arrived(&h, 1).await;
    let twin = record(&h, req);
    settle().await;
    // The first has not saved its machine yet: the twin is not answered with it.
    assert!(!twin.is_finished());
    assert_eq!(arrived(&h), 1);
    assert_eq!(h.m.inner.sandbox_turns.len(), 1);
    h.end_warm_barrier();
    let (e, how) = done(first).await.unwrap();
    assert!(!matches!(how, Make::Existing));
    let (same, how) = done(twin).await.unwrap();
    assert!(matches!(how, Make::Existing));
    assert_eq!(same.snapshot().id, e.snapshot().id);
    // The source and the one destination.
    assert_eq!(h.m.inner.machines.lock().unwrap().len(), 2);
    assert_eq!(h.m.inner.sandbox_turns.len(), 0);
}

#[tokio::test]
async fn the_same_request_with_another_spec_is_a_conflict_even_when_sent_together() {
    let (h, _, seed) = source().await;
    let req = request(&seed, "one", "create-a");
    let mut changed = req.clone();
    changed.env.insert("DESTINATION".into(), "changed".into());
    h.pause_warm_barrier("count");
    let first = record(&h, req);
    wait_arrived(&h, 1).await;
    let other = record(&h, changed);
    settle().await;
    assert!(!other.is_finished());
    h.end_warm_barrier();
    done(first).await.unwrap();
    assert!(matches!(done(other).await, Err(MError::Conflict(_))));
    assert_eq!(h.m.inner.machines.lock().unwrap().len(), 2);
    assert_eq!(h.m.inner.sandbox_turns.len(), 0);
}

#[tokio::test]
async fn a_lookup_waits_for_the_request_being_recorded() {
    let (h, _, seed) = source().await;
    let req = request(&seed, "one", "create-a");
    let query = api::SandboxRequestLookup {
        namespace: req.namespace.clone(),
        request_id: "create-a".into(),
        create_sha256: request_digest(&req).unwrap(),
    };
    h.pause_warm_barrier("count");
    let first = record(&h, req);
    wait_arrived(&h, 1).await;
    let m = h.m.clone();
    let lookup = tokio::spawn(async move { m.sandbox_request_lookup(query).await });
    settle().await;
    assert!(!lookup.is_finished());
    h.end_warm_barrier();
    let (e, _) = done(first).await.unwrap();
    let found = lookup.await.unwrap().unwrap().unwrap();
    assert_eq!(found.id, e.snapshot().id);
    assert_eq!(h.m.inner.sandbox_turns.len(), 0);
}

#[tokio::test]
async fn a_writer_of_either_lock_excludes_seed_creates() {
    let (h, _, seed) = source().await;
    h.pause_warm_barrier("count");
    let warm = h.m.inner.warm_lock.write().await;
    let a = record(&h, request(&seed, "one", "create-a"));
    settle().await;
    assert_eq!(arrived(&h), 0);
    assert!(!a.is_finished());
    // The writer also holds the second lock: staging takes both, warm first.
    let sandbox = h.m.inner.sandbox_create_lock.write().await;
    drop(warm);
    settle().await;
    assert_eq!(arrived(&h), 0);
    drop(sandbox);
    wait_arrived(&h, 1).await;
    h.end_warm_barrier();
    done(a).await.unwrap();
}

#[tokio::test]
async fn with_unbound_pools_available_seed_creates_stay_exclusive() {
    let (h, _, seed) = source_with_unbound(true).await;
    assert!(h.m.unbound_warm_available());
    h.pause_warm_barrier("count");
    let a = record(&h, request(&seed, "one", "create-a"));
    wait_arrived(&h, 1).await;
    let b = record(&h, request(&seed, "two", "create-b"));
    settle().await;
    // The second waits for the first, as before.
    assert_eq!(arrived(&h), 1);
    assert!(!b.is_finished());
    for lock in [&h.m.inner.warm_lock, &h.m.inner.sandbox_create_lock] {
        assert!(lock.try_read().is_err());
    }
    h.end_warm_barrier();
    done(a).await.unwrap();
    done(b).await.unwrap();
    assert_eq!(h.m.inner.sandbox_turns.len(), 0);
}

#[tokio::test]
async fn a_create_dropped_while_it_waits_leaves_no_turn_behind() {
    let (h, _, seed) = source().await;
    let req = request(&seed, "one", "create-a");
    h.pause_warm_barrier("count");
    let first = record(&h, req.clone());
    wait_arrived(&h, 1).await;
    let twin = record(&h, req);
    settle().await;
    twin.abort();
    let _ = twin.await;
    h.end_warm_barrier();
    done(first).await.unwrap();
    assert_eq!(h.m.inner.sandbox_turns.len(), 0);
}
