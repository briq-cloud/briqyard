use super::*;

#[tokio::test]
async fn blocked_fill_reasons_count_attempts_and_scrapes_cannot_increment_them() {
    let (h, _) = pool(0).await;
    h.m.inner.warm_policy.lock().unwrap().budget.memory_mb = 255;
    desired(&h, 1).await;
    tokio::task::yield_now().await;
    {
        let _settled = h.m.inner.warm_lock.lock().await;
    }
    for _ in 0..2 {
        let metrics = h.m.metrics();
        assert!(metrics.contains("briqyard_warm_fill_blocked_total{reason=\"budget\"} 1\n"));
        assert!(metrics.contains("briqyard_warm_shortfall 1\n"));
        assert!(metrics
            .lines()
            .any(|line| line.starts_with("briqyard_warm_pool_blocked{")
                && line.contains("reason=\"budget\"")
                && line.ends_with(" 1")));
    }
}

#[tokio::test]
async fn warm_metrics_use_actual_records_and_cached_receipts_without_probing() {
    let (h, _) = pool(1).await;
    let entry = fill(&h).await;
    {
        let _complete = entry.lock.lock().await;
    }
    tokio::task::yield_now().await;
    *h.m.inner.warm_probe_override.lock().unwrap() = Some(None);
    let before = h.m.metrics();
    api::metrics::check_exposition(&before);
    assert!(before.contains("briqyard_warm_slots{state=\"ready\"} 1\n"));
    assert!(before.contains("briqyard_warm_memory_bytes{kind=\"reserved\"} 268435456\n"));
    assert!(
        before.contains("briqyard_warm_probe_available 1\n"),
        "scraping must not run the failing probe"
    );
    assert!(before
        .contains("briqyard_warm_operations_total{operation=\"prepare\",outcome=\"success\"} 1\n"));
    h.m.claim_warm_pool("t1", "tools", claim("owned", "metrics-claim"))
        .await
        .unwrap();
    assert!(matches!(
        h.m.claim_warm_pool("t1", "tools", claim("empty", "metrics-miss"))
            .await,
        Err(MError::PoolEmpty)
    ));
    assert!(h
        .m
        .claim_warm_pool("t1", "tools", claim("bad/name", "metrics-failure"))
        .await
        .is_err());
    let after = h.m.metrics();
    api::metrics::check_exposition(&after);
    for expected in [
        "briqyard_warm_slots{state=\"claimed\"} 1\n",
        "briqyard_warm_memory_bytes{kind=\"reserved\"} 0\n",
        "briqyard_warm_operations_total{operation=\"claim\",outcome=\"success\"} 1\n",
        "briqyard_warm_operations_total{operation=\"claim\",outcome=\"miss\"} 1\n",
        "briqyard_warm_operations_total{operation=\"claim\",outcome=\"failure\"} 1\n",
    ] {
        assert!(after.contains(expected), "{expected}\n{after}");
    }
    assert_eq!(h.m.quota("t1").unwrap().used.memory_mb, 512);
    let pool_key = hex::encode(sha2::Sha256::digest(b"t1\0tools"));
    let mut durable =
        h.m.inner
            .store
            .get::<serde_json::Value>("warm-pools", &pool_key)
            .unwrap()
            .unwrap();
    durable["claims"]["metrics-claim"]["name"] = json!("owned");
    h.m.inner
        .store
        .put_durable("warm-pools", &pool_key, &durable)
        .unwrap();
    entry
        .rec
        .lock()
        .unwrap()
        .warm_slot
        .as_mut()
        .unwrap()
        .claimed = None;
    *h.m.inner.warm_pool_cache.lock().unwrap() = None;
    let unavailable = h.m.metrics();
    assert!(unavailable.contains("briqyard_warm_accounting_available 0\n"));
    assert!(!unavailable.contains("briqyard_warm_memory_bytes{kind=\"reserved\"}"));
    h.m.recover_warm_names().unwrap();
    let receipt_only = h.m.metrics();
    assert!(receipt_only.contains("briqyard_warm_slots{state=\"claimed\"} 1\n"));
    assert!(receipt_only.contains("briqyard_warm_memory_bytes{kind=\"reserved\"} 0\n"));
}

#[tokio::test]
async fn draining_metrics_keep_full_reservations_until_confirmed_cleanup() {
    let (h, source) = pool(1).await;
    let entry = fill(&h).await;
    {
        let _complete = entry.lock.lock().await;
    }
    h.refuse_clone_exit(true);
    *entry.live.lock().unwrap() = None;
    h.m.delete_warm_pool("t1", "tools").await.unwrap();
    h.m.warm_step().await;
    let blocked = h.m.metrics();
    assert!(blocked.contains("briqyard_warm_slots{state=\"draining\"} 1\n"));
    assert!(blocked.contains("briqyard_warm_memory_bytes{kind=\"reserved\"} 268435456\n"));
    assert!(blocked
        .lines()
        .any(|line| line.starts_with("briqyard_warm_pool_blocked{")
            && line.contains("reason=\"cleanup\"")
            && line.ends_with(" 1")));
    assert_eq!(h.m.quota("t1").unwrap().used.memory_mb, 512);
    h.refuse_clone_exit(false);
    h.m.warm_step().await;
    let cleaned = h.m.metrics();
    assert!(cleaned.contains("briqyard_warm_slots{state=\"draining\"} 0\n"));
    assert!(cleaned.contains("briqyard_warm_memory_bytes{kind=\"reserved\"} 0\n"));
    assert!(h.m.get(&source.id).is_ok());
}
