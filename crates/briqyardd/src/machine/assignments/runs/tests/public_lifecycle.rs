//! Public Manager callers must compose private run authority without duplicate launches.
use super::*;

fn bounded<T>(
    future: impl std::future::Future<Output = T>,
) -> impl std::future::Future<Output = T> {
    // Keep several large Manager futures out of this multi-operation test's stack frame.
    let future = Box::pin(future);
    async move {
        tokio::time::timeout(Duration::from_secs(10), future)
            .await
            .expect("public assigned lifecycle operation must complete")
    }
}

#[tokio::test]
async fn fresh_start_stop_start_publishes_only_current_run_and_coalesces_running_requests() {
    let (h, entry) = stopped(false).await;
    let id = entry.snapshot().id;
    let stopped_version = entry.snapshot().version;
    h.host_calls();

    let first = bounded(h.m.start(&id, Some(stopped_version)))
        .await
        .unwrap();
    assert_eq!(first.state, state::RUNNING);
    assert!(entry.identity_trusted.load(Relaxed));
    assert!(entry.live.lock().unwrap().is_some());
    assert!(h.m.ordinary_operation(&entry.snapshot()).is_ok());
    assert!(!h.m.namespace_dns_names("destination").is_empty());
    let first_run: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
    assert_eq!(first_run.reference.phase, Phase::Observed);
    assert_eq!(first_run.reference.sequence, 1);
    h.m.verified_run_publication(&entry.snapshot()).unwrap();
    let first_calls = h.host_calls();
    assert_eq!(
        first_calls
            .iter()
            .filter(|c| c.starts_with("boot "))
            .count(),
        1
    );
    assert_eq!(
        first_calls
            .iter()
            .filter(|c| c.starts_with("activate_quarantined "))
            .count(),
        1
    );

    assert!(matches!(
        bounded(h.m.start(&id, Some(stopped_version))).await,
        Err(MError::Moved(_))
    ));
    let (repeated, wake) =
        bounded(async { tokio::join!(h.m.start(&id, None), h.m.wake(&id, None)) }).await;
    assert_eq!(repeated.unwrap().state, state::RUNNING);
    assert_eq!(wake.unwrap().state, state::RUNNING);
    assert_eq!(
        entry.snapshot().assigned_run.as_ref(),
        Some(&first_run.reference)
    );
    assert!(h.host_calls().iter().all(|c| !c.starts_with("boot ")
        && !c.starts_with("activate_quarantined ")
        && !c.starts_with("count ")));

    let ended = bounded(h.m.stop(&id, Duration::from_secs(1), false, None))
        .await
        .unwrap();
    assert_eq!(ended.state, state::STOPPED);
    assert!(!entry.identity_trusted.load(Relaxed));
    assert!(entry.live.lock().unwrap().is_none());
    assert!(h.m.namespace_dns_names("destination").is_empty());
    let terminal: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
    assert_eq!(terminal.reference.phase, Phase::Settled);
    assert_eq!(terminal.reference.sequence, first_run.reference.sequence);
    h.host_calls();
    assert!(matches!(
        bounded(h.m.wake(&id, None)).await,
        Err(MError::NotRunning(_))
    ));
    assert_eq!(
        bounded(h.m.stop(&id, Duration::from_secs(1), false, None))
            .await
            .unwrap()
            .state,
        state::STOPPED
    );
    assert_eq!(
        entry.snapshot().assigned_run.as_ref(),
        Some(&terminal.reference)
    );
    assert!(h.host_calls().is_empty());

    let next = bounded(h.m.start(&id, None)).await.unwrap();
    assert_eq!(next.state, state::RUNNING);
    let next_run: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
    assert_eq!(next_run.reference.phase, Phase::Observed);
    assert_eq!(
        next_run.reference.sequence,
        first_run.reference.sequence + 1
    );
    assert_ne!(
        next_run.target.boot_incarnation,
        first_run.target.boot_incarnation
    );
    assert!(entry.identity_trusted.load(Relaxed));
    assert!(h.m.ordinary_operation(&entry.snapshot()).is_ok());
    assert!(!h.m.namespace_dns_names("destination").is_empty());
    h.m.verified_run_publication(&entry.snapshot()).unwrap();
    assert_eq!(
        h.host_calls()
            .iter()
            .filter(|c| c.starts_with("boot "))
            .count(),
        1
    );
    bounded(h.m.stop(&id, Duration::from_secs(1), false, None))
        .await
        .unwrap();
}
