//! A backup killed mid-stream leaves a marker, and the next start removes its streams (ADR 0100).

use super::*;
use crate::machine::backups::attempts::{Attempt, ATTEMPTS};

impl Harness {
    fn markers(&self) -> Vec<String> {
        self.m.inner.store.keys(ATTEMPTS).unwrap()
    }

    async fn streams(&self, id: &str) -> Vec<String> {
        self.objects(id)
            .await
            .into_iter()
            .filter(|k| k.ends_with(".zfs"))
            .collect()
    }

    /// The next start: the markers a previous process left, settled.
    async fn restart(&self) {
        let left = self.m.attempts_left();
        self.m.settle_attempts(left).await;
    }

    /// A backup of `id` begun in a task and cut once `ready` holds: the process ended there.
    async fn cut(&self, id: &str, ready: impl Fn(&Harness) -> bool) {
        let (m, rec) = (self.m.clone(), self.m.entry(id).unwrap().snapshot());
        let task = tokio::spawn(async move {
            let store = m.backup_store().unwrap().clone();
            let _ = m.send_backup(&store, &rec, None).await;
        });
        tokio::time::timeout(Duration::from_secs(10), async {
            while !ready(self) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the backup reached the step to cut at");
        task.abort();
        let _ = task.await;
    }
}

async fn machine(h: &Harness) -> String {
    with_volume(h, "m_v", state::STOPPED, 1).await;
    "m_v".into()
}

#[tokio::test]
async fn a_backup_that_finishes_leaves_no_marker() {
    let h = harness(|_| {}).await;
    let id = machine(&h).await;
    h.m.backup(&id).await.unwrap();
    assert!(h.markers().is_empty());
    assert_eq!(h.streams(&id).await.len(), 2);
}

#[tokio::test]
async fn a_kill_before_the_first_stream_leaves_a_marker_and_nothing_to_remove() {
    let h = harness(|_| {}).await;
    let id = machine(&h).await;
    let first = h.m.backup(&id).await.unwrap();
    std::fs::write(h.pool.dev().join("hold.send"), "").unwrap();
    let before = h.sends();
    h.cut(&id, |h| h.sends() > before).await;
    assert_eq!(h.markers().len(), 1);
    std::fs::remove_file(h.pool.dev().join("hold.send")).unwrap();
    h.restart().await;
    assert!(h.markers().is_empty());
    assert_eq!(h.ids(&h.listed(&id).await), vec![first.id]);
    assert_eq!(h.streams(&id).await.len(), 2, "the first backup's own");
}

#[tokio::test]
async fn a_kill_between_two_streams_removes_the_stream_that_was_written() {
    let h = harness(|_| {}).await;
    let id = machine(&h).await;
    let first = h.m.backup(&id).await.unwrap();
    std::fs::write(h.pool.dev().join("hold.send.data"), "").unwrap();
    // The root disk's stream is in the store, the data disk's send is waiting.
    h.cut(&id, |h| {
        let store = h.m.inner.cfg.data_dir.join("store");
        std::fs::read_dir(store.join(format!("backups/{id}/root")))
            .map(|d| {
                d.filter_map(|f| f.ok())
                    .filter(|f| f.file_name().to_string_lossy().ends_with(".zfs"))
                    .count()
                    == 2
            })
            .unwrap_or(false)
    })
    .await;
    assert_eq!(h.markers().len(), 1);
    assert_eq!(h.streams(&id).await.len(), 3, "an orphan beside the first");
    std::fs::remove_file(h.pool.dev().join("hold.send.data")).unwrap();
    h.restart().await;
    assert!(h.markers().is_empty());
    assert_eq!(h.ids(&h.listed(&id).await), vec![first.id.clone()]);
    let left = h.streams(&id).await;
    assert_eq!(left.len(), 2, "{left:?}");
    assert!(left.iter().all(|k| k.contains(&first.id)), "{left:?}");
}

#[tokio::test]
async fn a_kill_after_the_streams_and_before_the_record_removes_both_streams() {
    let h = harness(|_| {}).await;
    let id = machine(&h).await;
    let first = h.m.backup(&id).await.unwrap();
    let second = h.m.backup(&id).await.unwrap();
    // The state of a kill between the last stream and the record: the record is not written.
    let store = h.m.backup_store().unwrap();
    store
        .delete(&format!("backups/{id}/{}.json", second.id))
        .await
        .unwrap();
    h.m.begin_attempt(&Attempt::new(&id, &second.id, &["root", "data"]))
        .unwrap();
    h.restart().await;
    assert!(h.markers().is_empty());
    assert_eq!(h.ids(&h.listed(&id).await), vec![first.id.clone()]);
    assert!(h.streams(&id).await.iter().all(|k| k.contains(&first.id)));
}

#[tokio::test]
async fn a_kill_after_the_record_and_before_the_marker_ends_keeps_the_backup() {
    let h = harness(|_| {}).await;
    let id = machine(&h).await;
    let b = h.m.backup(&id).await.unwrap();
    h.m.begin_attempt(&Attempt::new(&id, &b.id, &["root", "data"]))
        .unwrap();
    h.restart().await;
    assert!(h.markers().is_empty());
    assert_eq!(h.ids(&h.listed(&id).await), vec![b.id.clone()]);
    assert_eq!(h.streams(&id).await.len(), 2);
}

#[tokio::test]
async fn nothing_is_removed_without_a_marker_or_on_a_marker_that_is_not_ours() {
    let h = harness(|_| {}).await;
    let id = machine(&h).await;
    let store = h.m.backup_store().unwrap();
    // A stream nobody wrote down: left alone, however it came there.
    let stray = format!("backups/{id}/root/20990101T000000.000Z.zfs");
    store.put_bytes(&stray, b"x").await.unwrap();
    h.restart().await;
    assert!(store.get_bytes_if_present(&stray).await.unwrap().is_some());
    // A marker whose names would reach another path: kept, and nothing deleted.
    let dir = h.m.inner.store.dir(ATTEMPTS);
    let evil = serde_json::json!({
        "machine_id": id,
        "id": "../../records",
        "disks": ["root"],
    });
    std::fs::write(dir.join("evil.json"), evil.to_string()).unwrap();
    let odd = serde_json::json!({
        "machine_id": id,
        "id": "20990101T000000.000Z",
        "disks": ["../root"],
    });
    std::fs::write(dir.join("odd.json"), odd.to_string()).unwrap();
    h.restart().await;
    assert_eq!(h.markers().len(), 2);
    assert!(store.get_bytes_if_present(&stray).await.unwrap().is_some());
}

#[test]
fn only_a_listing_that_shows_streams_and_no_record_gives_streams_away() {
    use crate::machine::backups::attempts::Verdict;
    let a = Attempt::new("m_v", "20261104T101010.123Z", &["root", "data"]);
    let root = "backups/m_v/root/20261104T101010.123Z.zfs".to_string();
    let data = "backups/m_v/data/20261104T101010.123Z.zfs".to_string();
    let record = "backups/m_v/20261104T101010.123Z.json".to_string();
    let other = "backups/m_v/root/20261104T090909.000Z.zfs".to_string();
    // The record is listed (whatever a GET of it says): nothing goes.
    assert_eq!(
        a.verdict(&[root.clone(), data.clone(), record.clone()]),
        Verdict::Finished
    );
    // No record: its listed streams go, and no other object.
    assert_eq!(
        a.verdict(&[root.clone(), other.clone()]),
        Verdict::Streams(vec![root])
    );
    // Nothing of it listed: nothing to remove.
    assert_eq!(a.verdict(&[other]), Verdict::Streams(vec![]));
}

#[tokio::test]
async fn a_store_that_cannot_be_listed_deletes_nothing() {
    use std::os::unix::fs::PermissionsExt;
    let h = harness(|_| {}).await;
    let id = machine(&h).await;
    let b = h.m.backup(&id).await.unwrap();
    let store = h.m.inner.cfg.data_dir.join("store");
    // The record is gone from view (a false "not found" would say the same) and the listing
    // fails or comes back empty: either way the streams stay.
    let dir = store.join(format!("backups/{id}"));
    h.m.begin_attempt(&Attempt::new(&id, &b.id, &["root", "data"]))
        .unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    h.restart().await;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(h.streams(&id).await.len(), 2);
    assert_eq!(h.ids(&h.listed(&id).await), vec![b.id]);
}
