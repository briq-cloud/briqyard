use super::*;
use crate::zfs::fake::Fake;
use tokio::io::AsyncReadExt;

const LIMIT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn transfer_failure_reaps_the_exact_child_and_drains_large_stderr_before_release() {
    let fake = Fake::open("byard").await.unwrap();
    let mut command = Command::new("sh");
    command.args(["-c", "i=0; while [ $i -lt 9000 ]; do printf 'diagnostic-line\n' >&2; i=$((i+1)); done; printf R; read -r line"])
        .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped());
    let result = fake
        .zfs
        .owned(command, "owned transfer test".into(), true, |child| {
            let mut stdout = child.stdout.take().unwrap();
            let stdin = child.stdin.take().unwrap();
            async move {
                let mut ready = [0];
                stdout.read_exact(&mut ready).await?;
                assert_eq!(&ready, b"R");
                // The actual child is blocked on its retained stdin, not already exited.
                drop(stdin);
                Err::<(), _>(anyhow!("fixture transfer failed"))
            }
        });
    let error = tokio::time::timeout(LIMIT, result)
        .await
        .unwrap()
        .unwrap_err();
    assert!(error.to_string().contains("fixture transfer failed"));
    assert_eq!(fake.zfs.owners.pending(), 0);
    assert!(fake.zfs.stalled(Duration::ZERO).is_none());
    tokio::time::timeout(LIMIT, fake.zfs.drain_io())
        .await
        .unwrap();
}

#[tokio::test]
async fn lost_transfer_observer_cannot_drop_child_owner_or_leave_unreaped_work() {
    let fake = Fake::open("byard").await.unwrap();
    let mut command = Command::new("sh");
    command
        .args(["-c", "printf R; read -r line"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let (ready, observed) = tokio::sync::oneshot::channel();
    let z = fake.zfs.clone();
    let waiter = tokio::spawn(async move {
        z.owned(command, "cancelled transfer test".into(), true, |child| {
            let mut stdout = child.stdout.take().unwrap();
            let stdin = child.stdin.take().unwrap();
            async move {
                let mut byte = [0];
                stdout.read_exact(&mut byte).await?;
                ready.send(()).unwrap();
                std::future::pending::<()>().await;
                drop((stdin, stdout));
                Ok(())
            }
        })
        .await
    });
    tokio::time::timeout(LIMIT, observed)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fake.zfs.owners.pending(), 1);
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    tokio::time::timeout(LIMIT, fake.zfs.drain_io())
        .await
        .unwrap();
    assert_eq!(fake.zfs.owners.pending(), 0);
    assert!(fake.zfs.stalled(Duration::ZERO).is_none());
}

#[tokio::test]
async fn preadmitted_scope_survives_close_and_is_part_of_the_drain() {
    let fake = Fake::open("byard").await.unwrap();
    let scope = fake.zfs.io_scope().unwrap();
    fake.zfs.close_io_admission();
    assert!(fake.zfs.io_scope().is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), fake.zfs.drain_io())
            .await
            .is_err()
    );
    scope
        .run(async {
            let result = fake
                .zfs
                .receive_with("m/x/root", |stdin| async {
                    drop(stdin);
                    Err::<(), _>(anyhow!("fixture reader failed"))
                })
                .await;
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("fixture reader failed"));
            assert_eq!(
                fake.zfs.owners.pending(),
                1,
                "the whole admitted scope is still owned"
            );
        })
        .await;
    tokio::time::timeout(LIMIT, fake.zfs.drain_io())
        .await
        .unwrap();
    assert_eq!(fake.zfs.owners.pending(), 0);
}

#[tokio::test]
async fn failed_spawn_settles_without_claiming_a_child_exited() {
    let fake = Fake::open("byard").await.unwrap();
    let result = fake
        .zfs
        .owned(
            Command::new("/nonexistent/owned-zfs"),
            "spawn failure".into(),
            true,
            |_| async { Ok(()) },
        )
        .await;
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("run spawn failure"));
    assert_eq!(fake.zfs.owners.pending(), 0);
}

#[tokio::test]
async fn transfer_panic_is_reaped_before_error_and_drain_release() {
    let fake = Fake::open("byard").await.unwrap();
    let mut command = Command::new("sh");
    command
        .args(["-c", "read -r line"])
        .stdin(std::process::Stdio::piped());
    let result = fake
        .zfs
        .owned(command, "panic transfer test".into(), true, |child| {
            let stdin = child.stdin.take().unwrap();
            async {
                let _owned_pipe = stdin;
                panic!("fixture transfer panic");
                #[allow(unreachable_code)]
                Ok(())
            }
        })
        .await;
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("transfer panicked"));
    tokio::time::timeout(LIMIT, fake.zfs.drain_io())
        .await
        .unwrap();
    assert!(fake.zfs.stalled(Duration::ZERO).is_none());
}

#[tokio::test]
async fn abandoned_scope_is_fenced_not_a_positive_drain() {
    let fake = Fake::open("byard").await.unwrap();
    drop(fake.zfs.io_scope().unwrap());
    assert!(fake.zfs.owners.fenced());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), fake.zfs.drain_io())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn lost_wait_observation_keeps_owner_marker_and_drain_fenced() {
    let fake = Fake::open("byard").await.unwrap();
    fake.zfs.owners.lose_wait_observation();
    let mut command = Command::new("sh");
    command.args(["-c", "exit 0"]);
    let z = fake.zfs.clone();
    let waiter = tokio::spawn(async move {
        z.owned(command, "lost wait observation".into(), true, |_| async {
            Ok(())
        })
        .await
    });
    tokio::time::timeout(LIMIT, async {
        while !fake.zfs.owners.fenced() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        !waiter.is_finished(),
        "uncertain settlement cannot release the caller/lifecycle owner"
    );
    assert_eq!(fake.zfs.owners.pending(), 1);
    assert!(fake.zfs.stalled(Duration::ZERO).is_some());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), fake.zfs.drain_io())
            .await
            .is_err()
    );
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    // The injected boundary reaped the actual child before losing its observation.
    // Its protocol fence intentionally remains; no fixture process needs signalling.
}

#[tokio::test]
async fn new_transfers_cannot_spawn_after_closed_admission_has_drained() {
    let fake = Fake::open("byard").await.unwrap();
    fake.calls();
    fake.zfs.close_io_admission();
    tokio::time::timeout(LIMIT, fake.zfs.drain_io())
        .await
        .unwrap();
    let sent = fake
        .zfs
        .send_with("m/x/root", "s_1", None, |_| async { Ok(()) })
        .await;
    let received = fake
        .zfs
        .receive_with("m/x/root", |_| async { Ok(()) })
        .await;
    for result in [sent, received] {
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("admission is closed"));
    }
    assert!(
        fake.calls().is_empty(),
        "neither refused transfer reached native spawn"
    );
    assert_eq!(fake.zfs.owners.pending(), 0);
}
