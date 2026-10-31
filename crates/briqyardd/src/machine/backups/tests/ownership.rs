//! Real Manager callers: a request's cancellation does not end an admitted backup.
use super::*;
use std::path::PathBuf;
const LIMIT: Duration = Duration::from_secs(15);
const SHORT: Duration = Duration::from_millis(20);
struct Hold(PathBuf);
impl Hold {
    fn send(h: &Harness) -> Self {
        let path = h.pool.dev().join("hold.send");
        std::fs::write(&path, b"").unwrap();
        Self(path)
    }
    fn release(&self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
impl Drop for Hold {
    fn drop(&mut self) {
        self.release();
    }
}
async fn until(mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(LIMIT, async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("owned fake I/O reaches the observed boundary");
}
#[tokio::test]
async fn disconnected_manual_request_keeps_turn_job_and_actual_backup_until_settled() {
    let h = harness(|b| b.at_once = 1).await;
    let machine = h.machine("db", every("1h", 3), true).await;
    let entry = h.m.entry(&machine.id).unwrap();
    let hold = Hold::send(&h);
    let (manager, id) = (h.m.clone(), machine.id.clone());
    let caller = tokio::spawn(async move { manager.backup(&id).await });
    until(|| h.sends() >= 1).await;
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    assert!(
        entry.backup_turn.clone().try_lock_owned().is_err(),
        "actual generation owns its turn after waiter loss"
    );
    assert_eq!(h.m.inner.backups.jobs.pending(), 1);
    h.m.close_backup_admission();
    assert!(tokio::time::timeout(SHORT, h.m.drain_backups())
        .await
        .is_err());
    hold.release();
    tokio::time::timeout(LIMIT, h.m.drain_backups())
        .await
        .unwrap();
    assert_eq!(h.m.inner.backups.jobs.pending(), 0);
    assert!(entry.backup_turn.clone().try_lock_owned().is_ok());
    assert_eq!(h.listed(&machine.id).await.len(), 1);
    assert!(matches!(
        h.m.backup(&machine.id).await,
        Err(MError::Conflict(_))
    ));
}
#[tokio::test]
async fn manual_work_shares_the_active_gate_and_bounds_admitted_queued_jobs() {
    let h = harness(|b| b.at_once = 1).await;
    let mut machines = Vec::new();
    for name in ["a", "b", "c"] {
        machines.push(h.machine(name, None, true).await)
    }
    let hold = Hold::send(&h);
    let mut callers = Vec::new();
    for machine in &machines {
        let (manager, id) = (h.m.clone(), machine.id.clone());
        callers.push(tokio::spawn(async move { manager.backup(&id).await }));
    }
    until(|| h.sends() >= 1 && h.m.inner.backups.jobs.pending() == 2).await;
    assert_eq!(h.sends(), 1);
    assert_eq!(h.m.inner.backups.gate.available_permits(), 0);
    for caller in callers {
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
    }
    assert_eq!(h.m.inner.backups.jobs.pending(), 2);
    h.m.close_backup_admission();
    hold.release();
    tokio::time::timeout(LIMIT, h.m.drain_backups())
        .await
        .unwrap();
    let mut made = 0;
    for machine in &machines {
        made += h.listed(&machine.id).await.len();
    }
    assert_eq!(made, 2);
    assert_eq!(h.m.inner.backups.gate.available_permits(), 1);
    assert_eq!(h.m.inner.backups.jobs.pending(), 0);
}
#[tokio::test]
async fn host_close_drains_owned_jobs_before_stopping_their_guests() {
    let h = harness(|b| b.at_once = 1).await;
    let machine = h.machine("db", None, true).await;
    let hold = Hold::send(&h);
    let (manager, id) = (h.m.clone(), machine.id.clone());
    let caller = tokio::spawn(async move { manager.backup(&id).await });
    until(|| h.sends() >= 1).await;
    caller.abort();
    let _ = caller.await;
    let manager = h.m.clone();
    let closing = tokio::spawn(async move { manager.close().await });
    until(|| h.m.inner.backups.jobs.is_closed()).await;
    assert_eq!(h.m.get(&machine.id).unwrap().state, state::RUNNING);
    assert!(!closing.is_finished());
    hold.release();
    tokio::time::timeout(LIMIT, closing).await.unwrap().unwrap();
    assert_eq!(h.listed(&machine.id).await.len(), 1);
    assert_eq!(h.m.inner.backups.jobs.pending(), 0);
    assert_eq!(h.m.get(&machine.id).unwrap().state, state::STOPPED);
}

#[tokio::test]
async fn disconnected_delete_request_remains_owned_and_is_in_the_shutdown_drain() {
    let h = harness(|b| b.at_once = 1).await;
    let machine = h.machine("db", None, true).await;
    let backup = h.m.backup(&machine.id).await.unwrap();
    let entry = h.m.entry(&machine.id).unwrap();
    let reads =
        h.m.inner
            .backups
            .reads
            .acquire_many(READS_AT_ONCE as u32)
            .await
            .unwrap();
    let (manager, id, bid) = (h.m.clone(), machine.id.clone(), backup.id.clone());
    let caller = tokio::spawn(async move { manager.delete_backup(&id, &bid, false).await });
    until(|| h.m.inner.backups.jobs.pending() == 1).await;
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    assert!(entry.backup_turn.clone().try_lock_owned().is_err());
    h.m.close_backup_admission();
    assert!(tokio::time::timeout(SHORT, h.m.drain_backups())
        .await
        .is_err());
    drop(reads);
    tokio::time::timeout(LIMIT, h.m.drain_backups())
        .await
        .unwrap();
    assert!(h.listed(&machine.id).await.is_empty());
    assert_eq!(h.m.inner.backups.jobs.pending(), 0);
    assert!(entry.backup_turn.clone().try_lock_owned().is_ok());
}

#[tokio::test]
async fn cancelled_restore_waiter_retains_make_lifecycle_and_shared_io_drain() {
    let h = harness(|_| {}).await;
    let original = h.machine("source", None, false).await;
    let backup = h.m.backup(&original.id).await.unwrap();
    let hold = Hold(h.pool.dev().join("hold.receive"));
    std::fs::write(&hold.0, b"").unwrap();
    let req = api::CreateMachineRequest {
        namespace: "t1".into(),
        name: "restored".into(),
        restore: Some(api::RestoreSpec {
            machine_id: original.id,
            backup: backup.id,
        }),
        start: Some(false),
        ..Default::default()
    };
    let manager = h.m.clone();
    let caller = tokio::spawn(async move { manager.create_made(req).await });
    let calls = h.pool.dev().parent().unwrap().join("calls");
    until(|| {
        std::fs::read_to_string(&calls)
            .unwrap_or_default()
            .lines()
            .any(|line| line.starts_with("receive "))
    })
    .await;
    let entry =
        h.m.inner
            .machines
            .lock()
            .unwrap()
            .values()
            .find(|entry| entry.snapshot().name == "restored")
            .unwrap()
            .clone();
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    assert!(
        entry.lock.clone().try_lock_owned().is_err(),
        "actual make worker retains its lifecycle lock"
    );
    h.m.close_backup_admission();
    assert!(tokio::time::timeout(SHORT, h.m.drain_backups())
        .await
        .is_err());
    hold.release();
    tokio::time::timeout(LIMIT, h.m.drain_backups())
        .await
        .unwrap();
    assert_eq!(entry.snapshot().state, state::CREATED);
    assert!(entry.lock.clone().try_lock_owned().is_ok());
}

#[tokio::test]
async fn queued_create_keeps_admission_from_record_through_unpolled_make_after_close() {
    let h = harness(|_| {}).await;
    let write = h.m.inner.namespace_lifecycle.write().await;
    let hold = Hold(h.pool.dev().join("hold.clone"));
    std::fs::write(&hold.0, b"").unwrap();
    let mut req = h.request("queued");
    req.start = Some(false);
    let create = h.m.create(req);
    tokio::pin!(create);
    assert!(matches!(
        futures::poll!(create.as_mut()),
        std::task::Poll::Pending
    ));
    h.m.close_backup_admission();
    assert!(
        tokio::time::timeout(SHORT, h.m.drain_backups())
            .await
            .is_err(),
        "record admission must already belong to the drain"
    );
    drop(write);
    let made = tokio::time::timeout(LIMIT, create).await.unwrap().unwrap();
    // This single-thread test has not polled the spawned make yet: its exact reservation
    // must already have crossed the accepted-create boundary, despite closed admission.
    assert_eq!(made.state, state::CREATING);
    let calls = h.pool.dev().parent().unwrap().join("calls");
    until(|| {
        std::fs::read_to_string(&calls)
            .unwrap_or_default()
            .lines()
            .any(|line| line.starts_with("clone "))
    })
    .await;
    hold.release();
    tokio::time::timeout(LIMIT, h.m.drain_backups())
        .await
        .unwrap();
    assert_eq!(h.m.get(&made.id).unwrap().state, state::CREATED);
}

#[tokio::test]
async fn closed_create_refuses_before_machine_or_address_persistence() {
    let h = harness(|_| {}).await;
    h.m.close_backup_admission();
    assert!(h.m.create(h.request("too-late")).await.is_err());
    assert!(h.m.list(Some("t1"), &[]).is_empty());
    assert!(h
        .m
        .inner
        .store
        .list::<Record>("machines")
        .unwrap()
        .is_empty());
    assert!(h.m.inner.address_holds.lock().unwrap().is_empty());
    tokio::time::timeout(LIMIT, h.m.drain_backups())
        .await
        .unwrap();
}

#[tokio::test]
async fn failed_record_releases_only_its_positively_undispatched_reservation() {
    let h = harness(|_| {}).await;
    let mut req = h.request("invalid");
    req.name = "invalid/name".into();
    assert!(h.m.create(req).await.is_err());
    h.m.close_backup_admission();
    tokio::time::timeout(LIMIT, h.m.drain_backups())
        .await
        .unwrap();
    assert!(h
        .m
        .inner
        .store
        .list::<Record>("machines")
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn closed_recovery_cannot_destroy_partial_create_before_reserving_make() {
    let h = harness(|_| {}).await;
    let (entry, _) = h.m.record(h.request("partial"), None).await.unwrap();
    let dataset = entry.snapshot().root_dataset();
    h.pool.zfs.create(&dataset, 1 << 20).await.unwrap();
    h.m.close_backup_admission();
    h.m.recover().await;
    assert!(
        h.pool.zfs.exists(&dataset).await.unwrap(),
        "refused recovery must retain partial source"
    );
    assert_eq!(entry.snapshot().state, state::CREATING);
    tokio::time::timeout(LIMIT, h.m.drain_backups())
        .await
        .unwrap();
}

#[tokio::test]
async fn closed_new_gateway_refuses_before_machine_or_address_persistence() {
    let h = harness(|_| {}).await;
    let spec = api::GatewaySpec {
        image: h.request("image").image,
        port: 3128,
        ..Default::default()
    };
    h.m.close_backup_admission();
    assert!(h.m.set_gateway("t1", spec).await.is_err());
    assert!(h.m.namespace("t1").unwrap().gateway.is_none());
    assert!(h
        .m
        .inner
        .store
        .list::<Record>("machines")
        .unwrap()
        .is_empty());
    assert!(h.m.inner.address_holds.lock().unwrap().is_empty());
    tokio::time::timeout(LIMIT, h.m.drain_backups())
        .await
        .unwrap();
}
