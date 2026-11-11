//! The boot queue (ADR 0130): boots accepted and not yet out of the boot gate.

use super::*;

/// Waits until `done` holds.
async fn until(mut done: impl FnMut() -> bool) {
    for _ in 0..500 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the condition never held");
}

/// Takes every turn at the gate, so a boot waits.
async fn hold_gate(h: &Harness) -> u32 {
    let size = h.m.boots_at_once();
    h.m.inner
        .boot_gate
        .acquire_many(size)
        .await
        .unwrap()
        .forget();
    size
}

#[tokio::test]
async fn the_queue_counts_creates_waiting_at_the_gate_from_the_record() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    assert_eq!(h.m.boots_at_once(), 2);
    assert_eq!(h.m.boot_queue(), 0);
    let size = hold_gate(&h).await;
    let a = h.m.create(h.request("a")).await.unwrap();
    assert_eq!(h.m.boot_queue(), 1, "counted when the create answers");
    let b = h.m.create(h.request("b")).await.unwrap();
    assert_eq!(h.m.boot_queue(), 2);
    h.m.inner.boot_gate.add_permits(size as usize);
    let (a, b) = (h.m.entry(&a.id).unwrap(), h.m.entry(&b.id).unwrap());
    until(|| h.m.boot_queue() == 0).await;
    assert_eq!(a.snapshot().state, state::RUNNING);
    assert_eq!(b.snapshot().state, state::RUNNING);
}

#[tokio::test]
async fn the_queue_counts_a_boot_that_holds_a_turn() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    h.host.boots(Boots::Ready(Duration::from_millis(400)));
    let m = h.m.create(h.request("slow")).await.unwrap();
    until(|| h.m.inner.boot_gate.available_permits() == 1).await;
    assert_eq!(h.m.boot_queue(), 1);
    until(|| h.m.boot_queue() == 0).await;
    assert_eq!(h.m.entry(&m.id).unwrap().snapshot().state, state::RUNNING);
}

#[tokio::test]
async fn the_queue_is_empty_after_a_create_fails_or_panics() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    h.host.boots(Boots::Exits(1, ""));
    let m = h.m.create(h.request("exits")).await.unwrap();
    assert_eq!(h.m.boot_queue(), 1);
    let e = h.m.entry(&m.id).unwrap();
    until(|| h.m.boot_queue() == 0).await;
    assert_eq!(e.snapshot().state, state::ERROR, "the boot failed");
    assert_eq!(
        h.m.inner.boot_gate.available_permits(),
        2,
        "the turn is back too"
    );
    h.host.boots(Boots::Panics);
    h.m.create(h.request("panics")).await.unwrap();
    until(|| h.m.boot_queue() == 0).await;
}

#[tokio::test(start_paused = true)]
async fn the_queue_counts_a_start_and_empties_on_success_failure_and_cancellation() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let mut request = h.request("stopped");
    request.start = Some(false);
    let m = h.m.create_made(request).await.unwrap();
    assert_eq!(
        h.m.boot_queue(),
        0,
        "a machine that is not started is not booting"
    );

    // Success: it waits for a turn, then runs.
    let size = hold_gate(&h).await;
    let manager = h.m.clone();
    let id = m.id.clone();
    let started = tokio::spawn(async move { manager.start(&id, None).await });
    until(|| h.m.boot_queue() == 1).await;
    h.m.inner.boot_gate.add_permits(size as usize);
    started.await.unwrap().unwrap();
    assert_eq!(h.m.boot_queue(), 0);

    // Cancellation: the caller gives up while the boot waits.
    h.m.stop(&m.id, Duration::from_secs(3), false, None)
        .await
        .unwrap();
    let size = hold_gate(&h).await;
    let waiting = h.m.start(&m.id, None);
    assert!(tokio::time::timeout(Duration::from_secs(1), waiting)
        .await
        .is_err());
    assert_eq!(
        h.m.boot_queue(),
        0,
        "a cancelled start gives its place back"
    );
    h.m.inner.boot_gate.add_permits(size as usize);

    // Failure: the guest never answers.
    h.host.boots(Boots::Silent);
    assert!(h.m.start(&m.id, None).await.is_err());
    assert_eq!(h.m.boot_queue(), 0);
}
