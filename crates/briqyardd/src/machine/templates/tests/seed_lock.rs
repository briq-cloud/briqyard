//! Creates from one seed clone its snapshot without the seed's lock (`make_disks`): the
//! destination's durable reader holds the snapshot, and every operation that could remove or
//! replace it checks that reader under the seed's lock.
use super::*;
use std::time::Duration;

/// A sealed template with a memory snapshot, and the request for a clone of it named `name`.
async fn seed() -> (Harness, api::Machine, String) {
    let (h, builder) = reviewed_builder().await;
    let snapshot =
        h.m.snapshot(
            &builder.id,
            api::SnapshotRequest {
                memory: true,
                template: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    (h, builder, snapshot.id)
}

fn clone_of(builder: &api::Machine, snapshot: &str, name: &str) -> api::CreateMachineRequest {
    api::CreateMachineRequest {
        namespace: "t1".into(),
        name: name.into(),
        fork: Some(api::ForkSpec {
            consistency: None,
            machine_id: builder.id.clone(),
            copy: String::new(),
            snapshot: Some(snapshot.into()),
        }),
        ..Default::default()
    }
}

/// How many `zfs clone` commands the fake has at its meeting point now.
fn inside(h: &Harness) -> usize {
    std::fs::read_dir(h.pool.dev())
        .unwrap()
        .filter(|f| {
            f.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("inside.")
        })
        .count()
}

async fn wait_inside(h: &Harness, n: usize) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while inside(h) < n {
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("the clones reached the meeting point");
}

#[tokio::test]
async fn creates_from_one_seed_clone_in_parallel() {
    let (h, builder, snapshot) = seed().await;
    // Each `zfs clone` waits until two are inside: it only ends when the seed's lock is not
    // held across the clone, since the second create's reservation takes that lock.
    std::fs::write(h.pool.dev().join("barrier.clone"), "2").unwrap();
    let (a, b) = tokio::join!(
        h.m.create_made(clone_of(&builder, &snapshot, "one")),
        h.m.create_made(clone_of(&builder, &snapshot, "two")),
    );
    assert_eq!(a.unwrap().state, state::RUNNING);
    assert_eq!(b.unwrap().state, state::RUNNING);
    assert_eq!(inside(&h), 2);
    assert_eq!(h.m.clone_readers().unwrap().len(), 2);
}

#[tokio::test]
async fn a_clone_in_flight_refuses_what_would_remove_its_snapshot_without_waiting_for_it() {
    let (h, builder, snapshot) = seed().await;
    // One clone waits at the meeting point for a second that never comes, until the test
    // joins it: the clone is in flight while the seed is asked for the following.
    std::fs::write(h.pool.dev().join("barrier.clone"), "2").unwrap();
    let m = h.m.clone();
    let req = clone_of(&builder, &snapshot, "one");
    let creating = tokio::spawn(async move { m.create_made(req).await });
    wait_inside(&h, 1).await;
    let refused = async {
        assert!(matches!(
            h.m.delete_snapshot(&builder.id, &snapshot).await,
            Err(MError::Conflict(_))
        ));
        assert!(matches!(
            h.m.restore_snapshot(&builder.id, &snapshot, None).await,
            Err(MError::Conflict(_))
        ));
        assert!(matches!(
            h.m.destroy(&builder.id, None).await,
            Err(MError::Conflict(_))
        ));
        // A tidy leaves the snapshot, and the seed's lock is free.
        let seed = h.m.entry(&builder.id).unwrap();
        assert!(h.m.tidy(&seed).await.unwrap().is_empty());
        assert!(seed.lock.try_lock().is_ok());
    };
    let outcome = tokio::time::timeout(Duration::from_secs(5), refused).await;
    // Let the clone end whatever the outcome, so the task does not outlive the test.
    std::fs::write(h.pool.dev().join("inside.test"), "").unwrap();
    outcome.expect("the seed answered while a clone of it was in flight");
    assert_eq!(creating.await.unwrap().unwrap().state, state::RUNNING);
}

#[tokio::test]
async fn a_failed_clone_leaves_the_seed_free_and_its_reader_goes_with_the_machine() {
    let (h, builder, snapshot) = seed().await;
    let (e, how) =
        h.m.record(clone_of(&builder, &snapshot, "one"), None)
            .await
            .unwrap();
    // The snapshot is gone from the pool: the `zfs clone` fails.
    let gone = std::process::Command::new("find")
        .arg(h.pool.dev())
        .args(["-name", &format!("*@{snapshot}")])
        .output()
        .unwrap();
    let gone = String::from_utf8(gone.stdout).unwrap();
    assert!(!gone.is_empty(), "the seed's snapshot is in the fake pool");
    for path in gone.lines() {
        std::fs::remove_file(path).unwrap();
    }
    let scope = h.m.inner.zfs.io_scope().unwrap();
    assert!(h.m.make_admitted(scope, &e, how).await.is_err());
    assert_eq!(e.snapshot().state, state::ERROR);
    let seed = h.m.entry(&builder.id).unwrap();
    assert!(seed.lock.try_lock().is_ok());
    // The reader stays while the failed machine does: its destroy releases it.
    assert_eq!(h.m.clone_readers().unwrap().len(), 1);
    h.m.destroy(&e.snapshot().id, None).await.unwrap();
    assert!(h.m.clone_readers().unwrap().is_empty());
}

#[tokio::test]
async fn a_clone_without_its_reader_is_refused_before_any_zfs_clone() {
    let (h, builder, snapshot) = seed().await;
    let (e, how) =
        h.m.record(clone_of(&builder, &snapshot, "one"), None)
            .await
            .unwrap();
    h.m.inner
        .store
        .delete_durable(READERS, &e.snapshot().id)
        .unwrap();
    h.pool.calls();
    let scope = h.m.inner.zfs.io_scope().unwrap();
    let err = h.m.make_admitted(scope, &e, how).await.unwrap_err();
    assert!(err.to_string().contains("holds no reader"), "{err}");
    assert!(!h.pool.calls().iter().any(|c| c.starts_with("clone ")));
    assert!(h.m.entry(&builder.id).unwrap().lock.try_lock().is_ok());
}
