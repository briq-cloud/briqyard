//! Tests of snapshots.

use super::super::tests::{grow_to, harness_config, with_volume, Harness};
use super::*;

const IMAGE3: &str =
    "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000003";

async fn harness() -> Harness {
    let h = harness_config(|cfg| {
        cfg.network.range = "10.64.0.0/22".into();
        cfg.capacity = crate::config::Capacity {
            memory_mb: 4096,
            vcpus: 1000,

            ..Default::default()
        };
        cfg.egress_limits = crate::config::EgressLimits {
            blocked_ports: vec![],
            new_connections_per_minute: 0,
            bandwidth_mbit: 0,
        };
        cfg.backup.store = format!("file://{}", cfg.data_dir.join("store").display());
    })
    .await;
    h.ready().await;
    h
}

fn named(name: &str) -> api::SnapshotRequest {
    api::SnapshotRequest {
        name: Some(name.into()),
        memory: false,
    }
}

fn with_memory() -> api::SnapshotRequest {
    api::SnapshotRequest {
        name: None,
        memory: true,
    }
}

impl Harness {
    /// The machine's datasets, sorted: its disks and the ones they retired.
    async fn datasets(&self, id: &str) -> Vec<String> {
        let mut v = self
            .pool
            .zfs
            .volumes_under(&format!("m/{id}"))
            .await
            .unwrap();
        v.sort();
        v
    }

    /// Its retired root disks.
    async fn retired(&self, id: &str) -> Vec<String> {
        let root = format!("m/{id}/root.");
        let all = self.datasets(id).await;
        all.into_iter().filter(|d| d.starts_with(&root)).collect()
    }

    async fn origin(&self, ds: &str) -> Option<(String, String)> {
        self.pool.zfs.origin(ds).await.unwrap()
    }

    fn snapshot_ids(&self, id: &str) -> Vec<String> {
        self.stored(id)
            .unwrap()
            .snapshots
            .iter()
            .map(|s| s.id.clone())
            .collect()
    }

    fn restored_data(&self, id: &str) -> serde_json::Value {
        self.events_of(id)
            .into_iter()
            .rev()
            .find(|e| e.reason == reason::RESTORED)
            .and_then(|e| e.data)
            .unwrap()
    }
}

/// A snapshot's delete that took the machine before its destroy, then waited on its lock
/// (the chaos run of 2026-10-28), goes on once the machine is destroyed: its write of the
/// record reaches nothing, so the next daemon does not find the record again.
#[tokio::test]
async fn a_snapshot_delete_behind_a_destroy_never_brings_the_record_back() {
    let h = harness().await;
    let e = h.add("m_s", state::STOPPED, 256);
    h.disks(&e).await;
    let s = h.m.snapshot("m_s", named("before")).await.unwrap();
    assert!(h.stored("m_s").is_some());
    // The destroy holds the lock through its `zfs destroy`; the delete waits behind it.
    let hold = h.pool.dev().join("hold.destroy");
    std::fs::write(&hold, "").unwrap();
    let m = h.m.clone();
    let destroy = tokio::spawn(async move { m.destroy("m_s", None).await });
    while h.pool.zfs.stalled(Duration::ZERO).is_none() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (m, snap) = (h.m.clone(), s.id.clone());
    let delete = tokio::spawn(async move { m.delete_snapshot("m_s", &snap).await });
    // It holds the backup turn, then waits on the lock.
    while e.backup_turn.try_lock().is_ok() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    std::fs::remove_file(&hold).unwrap();
    destroy.await.unwrap().unwrap();
    delete.await.unwrap().unwrap();
    assert!(matches!(h.m.get("m_s"), Err(MError::NotFound)));
    assert!(h.stored("m_s").is_none(), "the record came back");
}

#[tokio::test]
async fn a_snapshot_is_taken_named_listed_and_deleted() {
    let h = harness().await;
    let e = h.add("m_s", state::STOPPED, 256);
    h.disks(&e).await;
    let v0 = e.snapshot().version;
    let a = h.m.snapshot("m_s", named("before")).await.unwrap();
    // Both disks at one instant, one `zfs snapshot`.
    assert!(h.snapshot_exists("m/m_s/root", &a.id));
    assert!(h.snapshot_exists("m/m_s/data", &a.id));
    assert!(h.pool.calls().contains(&format!(
        "snapshot byard/m/m_s/root@{0} byard/m/m_s/data@{0}",
        a.id
    )));
    assert_eq!(
        (a.name.as_deref(), a.disks.clone(), a.memory),
        (
            Some("before"),
            vec!["root".to_string(), "data".to_string()],
            false
        )
    );
    assert!(e.snapshot().version > v0);
    let b =
        h.m.snapshot("m_s", api::SnapshotRequest::default())
            .await
            .unwrap();
    let listed = h.m.snapshots("m_s").await.unwrap();
    assert_eq!(
        listed.iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
        [a.id.clone(), b.id.clone()]
    );
    assert_eq!(listed[0].created_at, a.created_at);
    assert_eq!(h.reasons("m_s"), ["snapshot_taken", "snapshot_taken"]);
    // A name is the machine's once; it is not an id's shape; memory needs a process.
    assert!(matches!(
        h.m.snapshot("m_s", named("before")).await,
        Err(MError::Conflict(_))
    ));
    assert!(matches!(
        h.m.snapshot("m_s", named("s_1")).await,
        Err(MError::Invalid(_))
    ));
    assert!(matches!(
        h.m.snapshot("m_s", with_memory()).await,
        Err(MError::NotRunning(_))
    ));
    // Deleted by name: both disks' snapshots go; missing again is success.
    h.m.delete_snapshot("m_s", "before").await.unwrap();
    assert!(!h.snapshot_exists("m/m_s/root", &a.id));
    assert!(!h.snapshot_exists("m/m_s/data", &a.id));
    assert_eq!(h.snapshot_ids("m_s"), std::slice::from_ref(&b.id));
    h.m.delete_snapshot("m_s", "before").await.unwrap();
    h.m.delete_snapshot("m_s", "fork-x").await.unwrap();
    assert_eq!(h.reasons("m_s").last().unwrap(), "snapshot_deleted");
    assert!(matches!(
        h.m.snapshots("m_none").await,
        Err(MError::NotFound)
    ));
    assert!(matches!(
        h.m.restore_snapshot("m_s", "before", None).await,
        Err(MError::NoSnapshot(_))
    ));
}

#[tokio::test]
async fn a_restore_swaps_the_disk_and_keeps_newer_snapshots_and_forks() {
    let h = harness().await;
    let src = h.m.create_made(h.request("src")).await.unwrap();
    let s1 = h.m.snapshot(&src.id, named("one")).await.unwrap();
    let fork = h.fork(&src.id, "fork").await;
    let fork_snap = format!("fork-{}", fork.id);
    let s2 =
        h.m.snapshot(&src.id, api::SnapshotRequest::default())
            .await
            .unwrap();
    h.host_calls();
    let m = h.m.restore_snapshot(&src.id, "one", None).await.unwrap();
    // Running before, so stopped, swapped and booted again.
    assert_eq!(m.state, state::RUNNING);
    let calls = h.host_calls();
    assert!(
        calls
            .iter()
            .any(|c| c.starts_with(&format!("boot {} ", src.id)) && c.ends_with("resume=false")),
        "{calls:?}"
    );
    let tail: Vec<String> = h.reasons(&src.id).into_iter().rev().take(5).rev().collect();
    assert_eq!(
        tail,
        ["stopping", "stopped", "restored", "starting", "started"]
    );
    assert_eq!(h.restored_data(&src.id)["snapshot"], s1.id.as_str());
    // The disk in use is a clone of the snapshot, promoted: it holds the snapshot, and its
    // origin is the image's, as before.
    let root = format!("m/{}/root", src.id);
    assert!(h.snapshot_exists(&root, &s1.id));
    assert!(!h.snapshot_exists(&root, &s2.id));
    assert!(h.origin(&root).await.unwrap().0.starts_with("images/"));
    // The disk it replaced is retired, holding the newer snapshot and the fork's.
    let retired = h.retired(&src.id).await;
    assert_eq!(retired.len(), 1, "{retired:?}");
    assert!(h.snapshot_exists(&retired[0], &s2.id));
    assert!(h.snapshot_exists(&retired[0], &fork_snap));
    let fork_root = format!("m/{}/root", fork.id);
    assert_eq!(
        h.origin(&fork_root).await,
        Some((retired[0].clone(), fork_snap.clone()))
    );
    assert_eq!(h.snapshot_ids(&src.id), [s1.id.clone(), s2.id.clone()]);
    // Forward again, to the newer one: every snapshot back on the disk in use, the fork's
    // with it, nothing retired left.
    h.m.restore_snapshot(&src.id, &s2.id, None).await.unwrap();
    for s in [&s1.id, &s2.id, &fork_snap] {
        assert!(h.snapshot_exists(&root, s), "{s}");
    }
    assert_eq!(h.datasets(&src.id).await, std::slice::from_ref(&root));
    assert_eq!(h.origin(&fork_root).await, Some((root.clone(), fork_snap)));
    assert_eq!(h.m.get(&fork.id).unwrap().state, state::RUNNING);
}

/// The restore of RISE-M (ADR 0046): udev drops every event from the snapshot on, so the
/// link at the root disk's name still names the disk the restore retired, then destroyed.
/// The machine boots on the clone's device all the same, never on the retired disk's.
#[tokio::test(start_paused = true)]
async fn a_restore_boots_the_new_disk_whatever_udev_missed() {
    use std::os::unix::fs::MetadataExt;
    let h = harness().await;
    let m = h.m.create_made(h.request("m")).await.unwrap();
    let root = h.pool.dev().join(format!("byard/m/{}/root", m.id));
    let before = std::fs::metadata(&root).unwrap().ino();
    let s = h.m.snapshot(&m.id, named("one")).await.unwrap();
    std::fs::write(h.pool.dev().join("udev.drop"), "").unwrap();
    h.m.restore_snapshot(&m.id, &s.id, None).await.unwrap();
    assert!(h.retired(&m.id).await.is_empty(), "the retired disk went");
    let booted = h.booted_root(&m.id);
    let ino = std::fs::metadata(&booted).unwrap().ino();
    assert_ne!(ino, before, "booted on the retired disk");
    assert_eq!(ino, std::fs::metadata(&root).unwrap().ino());
}

/// A chaos run's question: after a restore with memory, the resume and every cold boot
/// after it run on the snapshot's disks, never on what the guest wrote since, with a stop
/// before the restore, after it, or none. The fake's volume file is the disk: the root's
/// holds what the guest wrote; the volume's holds its size, so it is checked by device.
#[tokio::test]
async fn a_memory_restore_and_the_cold_boots_after_it_run_on_the_snapshots_disks() {
    use std::os::unix::fs::MetadataExt;
    let h = harness().await;
    with_volume(&h, "m_v", state::STOPPED, 1).await;
    h.m.start("m_v", None).await.unwrap();
    let ino = |p: &Path| std::fs::metadata(p).unwrap().ino();
    let data = h.pool.dev().join("byard/m/m_v/data");
    let on_the_snapshot = |when: &str, written: u64| {
        let root = h.booted_root("m_v");
        assert_eq!(std::fs::read_to_string(&root).unwrap(), "5", "{when}");
        let booted = ino(&h.booted_data("m_v"));
        assert!(booted == ino(&data) && booted != written, "{when}");
    };
    let stop = || h.m.stop("m_v", Duration::ZERO, false, None);
    for racer in ["none", "before", "after"] {
        std::fs::write(h.booted_root("m_v"), "5").unwrap();
        let s = h.m.snapshot("m_v", with_memory()).await.unwrap();
        // What the guest writes after it.
        std::fs::write(h.booted_root("m_v"), "6").unwrap();
        let written = ino(&data);
        let restore = h.m.restore_snapshot("m_v", &s.id, None);
        match racer {
            "none" => drop(restore.await.unwrap()),
            "before" => drop(tokio::join!(stop(), restore).1.unwrap()),
            _ => drop(tokio::join!(restore, stop()).0.unwrap()),
        }
        // Stopped first, the restore keeps the memory for the start; stopped after, the
        // resume is over and the start is cold.
        let m = h.m.get("m_v").unwrap();
        let want = match racer {
            "none" => (state::RUNNING, false),
            "before" => (state::STOPPED, true),
            _ => (state::STOPPED, false),
        };
        assert_eq!((m.state.as_str(), m.suspended), want, "{racer}");
        if m.state == state::STOPPED {
            h.m.start("m_v", None).await.unwrap();
        }
        on_the_snapshot(&format!("{racer}: back"), written);
        h.m.restart("m_v", None).await.unwrap();
        assert_eq!(h.reasons("m_v").last().unwrap(), "started", "{racer}");
        on_the_snapshot(&format!("{racer}: cold"), written);
        h.m.delete_snapshot("m_v", &s.id).await.unwrap();
    }
}

#[tokio::test]
async fn deleted_snapshots_a_retired_disk_hangs_from_go_with_it() {
    let h = harness().await;
    let src = h.m.create_made(h.request("src")).await.unwrap();
    let root = format!("m/{}/root", src.id);
    let s1 =
        h.m.snapshot(&src.id, api::SnapshotRequest::default())
            .await
            .unwrap();
    let s2 =
        h.m.snapshot(&src.id, api::SnapshotRequest::default())
            .await
            .unwrap();
    h.m.restore_snapshot(&src.id, &s1.id, None).await.unwrap();
    // The retired disk holding s2 is a clone of s1: s1 leaves the list, its blocks stay.
    h.m.delete_snapshot(&src.id, &s1.id).await.unwrap();
    assert_eq!(h.snapshot_ids(&src.id), std::slice::from_ref(&s2.id));
    assert!(h.snapshot_exists(&root, &s1.id));
    // With s2 gone, nothing needs the retired disk, then nothing clones s1.
    h.m.delete_snapshot(&src.id, &s2.id).await.unwrap();
    assert_eq!(h.datasets(&src.id).await, std::slice::from_ref(&root));
    assert!(!h.snapshot_exists(&root, &s1.id));
}

#[tokio::test]
async fn a_fork_that_goes_frees_the_retired_disk_it_held() {
    let h = harness().await;
    let src = h.m.create_made(h.request("src")).await.unwrap();
    let s1 =
        h.m.snapshot(&src.id, api::SnapshotRequest::default())
            .await
            .unwrap();
    let fork = h.fork(&src.id, "fork").await;
    h.m.restore_snapshot(&src.id, &s1.id, None).await.unwrap();
    assert_eq!(h.retired(&src.id).await.len(), 1);
    h.m.destroy(&fork.id, None).await.unwrap();
    assert!(h.retired(&src.id).await.is_empty());
    // And the source, destroyed, leaves nothing.
    h.m.destroy(&src.id, None).await.unwrap();
    assert!(!h.pool.dev().join(format!("byard/m/{}", src.id)).exists());
}

#[tokio::test]
async fn a_destroyed_source_promotes_a_fork_of_its_retired_disk() {
    let h = harness().await;
    let src = h.m.create_made(h.request("src")).await.unwrap();
    let s1 =
        h.m.snapshot(&src.id, api::SnapshotRequest::default())
            .await
            .unwrap();
    let fork = h.fork(&src.id, "fork").await;
    h.m.restore_snapshot(&src.id, &s1.id, None).await.unwrap();
    // The fork clones the retired disk, which clones the source's: promoted twice, it
    // owns its history, and keeps none of the source's snapshots.
    h.m.destroy(&src.id, None).await.unwrap();
    let fork_root = format!("m/{}/root", fork.id);
    assert!(h.origin(&fork_root).await.unwrap().0.starts_with("images/"));
    let left = h.pool.zfs.snapshots(&fork_root).await.unwrap();
    assert!(left.is_empty(), "{left:?}");
    assert_eq!(h.m.get(&fork.id).unwrap().state, state::RUNNING);
}

#[tokio::test]
async fn a_backup_after_a_restore_continues_from_an_ancestor_or_is_whole() {
    let h = harness().await;
    let m = h.m.create_made(h.request("db")).await.unwrap();
    let b1 = h.m.backup(&m.id).await.unwrap();
    let s =
        h.m.snapshot(&m.id, api::SnapshotRequest::default())
            .await
            .unwrap();
    h.m.restore_snapshot(&m.id, &s.id, None).await.unwrap();
    // b1 was made before the snapshot: still in the disk's history, a base.
    let b2 = h.m.backup(&m.id).await.unwrap();
    assert_eq!(b2.disks[0].from.as_deref(), Some(b1.id.as_str()));
    // b2 was made after it: retired and freed by the restore, so the next is whole.
    h.m.restore_snapshot(&m.id, &s.id, None).await.unwrap();
    assert!(!h.snapshot_exists(&format!("m/{}/root", m.id), &format!("bk-{}", b2.id)));
    assert!(h.retired(&m.id).await.is_empty());
    let b3 = h.m.backup(&m.id).await.unwrap();
    assert!(!b3.incremental, "{b3:?}");
    // Both chains restore.
    for (name, b) in [("r2", &b2), ("r3", &b3)] {
        let r =
            h.m.create_made(api::CreateMachineRequest {
                namespace: "t1".into(),
                name: name.into(),
                restore: Some(api::RestoreSpec {
                    machine_id: m.id.clone(),
                    backup: b.id.clone(),
                }),
                start: Some(false),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(r.state, state::CREATED);
    }
}

#[tokio::test]
async fn a_restore_keeps_a_grown_volume_and_never_resumes_the_smaller_disks_memory() {
    let h = harness().await;
    with_volume(&h, "m_v", state::STOPPED, 2).await;
    h.m.start("m_v", None).await.unwrap();
    h.m.snapshot("m_v", named("small")).await.unwrap();
    h.m.snapshot("m_v", with_memory()).await.unwrap();
    let warm = h.snapshot_ids("m_v")[1].clone();
    h.m.update("m_v", grow_to(5), None).await.unwrap();
    // Taken while the growth waits for a boot: its memory is the smaller disk's too.
    h.m.snapshot("m_v", with_memory()).await.unwrap();
    let waiting = h.snapshot_ids("m_v")[2].clone();
    h.m.restart("m_v", None).await.unwrap();
    h.m.stop("m_v", Duration::ZERO, false, None).await.unwrap();
    assert!(h.m.get("m_v").unwrap().pending.is_none());
    // Back to a snapshot of the smaller disk: the volume keeps its size, its filesystem
    // is the snapshot's until the next boot.
    let m = h.m.restore_snapshot("m_v", "small", None).await.unwrap();
    assert_eq!(h.pool.zfs.volsize("m/m_v/data").await.unwrap(), 5 << 30);
    assert_eq!(m.volume.map(|v| v.size_gb), Some(5));
    assert_eq!(
        m.pending.and_then(|p| p.volume),
        Some(api::VolumeSize { size_gb: 5 })
    );
    h.m.start("m_v", None).await.unwrap();
    // A running machine's restore boots it, cold: that boot grows the filesystem.
    for snap in [&warm, &waiting] {
        h.host_calls();
        let m = h.m.restore_snapshot("m_v", snap, None).await.unwrap();
        assert!(m.pending.is_none(), "{snap}");
        let calls = h.host_calls();
        assert!(
            calls.iter().any(|c| c.ends_with(" resume=false")),
            "{snap}: {calls:?}"
        );
        assert_eq!(h.restored_data("m_v")["memory"], false, "{snap}");
    }
}

#[tokio::test]
async fn a_restore_cut_short_after_the_growth_still_leaves_the_filesystem_pending() {
    let h = harness().await;
    let e = with_volume(&h, "m_v", state::STOPPED, 2).await;
    let s = h.m.snapshot("m_v", named("small")).await.unwrap();
    h.m.update("m_v", grow_to(5), None).await.unwrap();
    h.m.restart("m_v", None).await.unwrap();
    h.m.stop("m_v", Duration::ZERO, false, None).await.unwrap();
    // The disks swapped and the volume grown back, then the daemon stopped before the
    // record said so: the record still has the intent, nothing pending.
    h.m.restore_snapshot("m_v", "small", None).await.unwrap();
    {
        let mut r = e.rec.lock().unwrap();
        r.pending = None;
        r.restoring = Some(s.id.clone());
    }
    h.m.finish_restore(&e).await.unwrap();
    assert_eq!(h.pool.zfs.volsize("m/m_v/data").await.unwrap(), 5 << 30);
    assert_eq!(
        h.m.get("m_v").unwrap().pending.and_then(|p| p.volume),
        Some(api::VolumeSize { size_gb: 5 })
    );
}

#[tokio::test]
async fn a_restore_checks_the_version_and_keeps_a_stopped_machine_stopped() {
    let h = harness().await;
    let m = h.m.create_made(h.request("m")).await.unwrap();
    let s =
        h.m.snapshot(&m.id, api::SnapshotRequest::default())
            .await
            .unwrap();
    let v = h.m.get(&m.id).unwrap().version;
    assert!(matches!(
        h.m.restore_snapshot(&m.id, &s.id, Some(v - 1)).await,
        Err(MError::Moved(_))
    ));
    // Suspended: the memory of the old disks is dropped, the machine stays stopped.
    h.m.stop(&m.id, Duration::ZERO, true, None).await.unwrap();
    assert!(h.stored(&m.id).unwrap().suspended);
    h.host_calls();
    let v = h.m.get(&m.id).unwrap().version;
    let r = h.m.restore_snapshot(&m.id, &s.id, Some(v)).await.unwrap();
    assert_eq!(r.state, state::STOPPED);
    assert!(!h.stored(&m.id).unwrap().suspended);
    assert!(!h.host_calls().iter().any(|c| c.starts_with("boot ")));
    assert!(r.version > v);
}

#[tokio::test]
async fn a_restore_cut_short_is_finished_by_the_daemon_or_a_start() {
    let h = harness().await;
    let m = h.m.create_made(h.request("m")).await.unwrap();
    let s =
        h.m.snapshot(&m.id, api::SnapshotRequest::default())
            .await
            .unwrap();
    h.m.stop(&m.id, Duration::ZERO, false, None).await.unwrap();
    let e = h.m.entry(&m.id).unwrap();
    let root = format!("m/{}/root", m.id);
    // Cut between the renames: the disk renamed aside, its clone beside it.
    e.rec.lock().unwrap().restoring = Some(s.id.clone());
    let z = &h.pool.zfs;
    z.rename(&root, &format!("{root}.r_cut")).await.unwrap();
    z.clone_snapshot(&format!("{root}.r_cut"), &s.id, &format!("{root}.next"))
        .await
        .unwrap();
    // Half swapped: no backup sends it, no fork copies it, no snapshot is taken of it.
    assert!(matches!(h.m.backup(&m.id).await, Err(MError::BadState(_))));
    assert!(matches!(
        h.m.snapshot(&m.id, api::SnapshotRequest::default()).await,
        Err(MError::BadState(_))
    ));
    h.m.sweep_orphans().await;
    assert_eq!(h.datasets(&m.id).await, std::slice::from_ref(&root));
    assert!(h.snapshot_exists(&root, &s.id));
    assert!(h.stored(&m.id).unwrap().restoring.is_none());
    assert_eq!(h.reasons(&m.id).last().unwrap(), "restored");
    // Cut right after its intent: the next start finishes it before it boots.
    e.rec.lock().unwrap().restoring = Some(s.id.clone());
    h.m.start(&m.id, None).await.unwrap();
    let tail: Vec<String> = h.reasons(&m.id).into_iter().rev().take(3).rev().collect();
    assert_eq!(tail, ["starting", "restored", "started"]);
    assert_eq!(h.datasets(&m.id).await, [root]);
}

#[tokio::test]
async fn a_tidy_that_fails_after_the_swap_does_not_fail_the_restore() {
    let h = harness().await;
    let m = h.m.create_made(h.request("m")).await.unwrap();
    let s =
        h.m.snapshot(&m.id, api::SnapshotRequest::default())
            .await
            .unwrap();
    // Newer than the one restored and named by nothing: the tidy tries to destroy it,
    // and this `zfs` refuses.
    let root = format!("m/{}/root", m.id);
    h.pool.zfs.snapshot(&root, "s_boom").await.unwrap();
    let r = h.m.restore_snapshot(&m.id, &s.id, None).await.unwrap();
    assert_eq!(r.state, state::RUNNING);
    assert_eq!(h.restored_data(&m.id)["snapshot"], s.id.as_str());
    assert!(h.snapshot_exists(&root, &s.id));
}

#[tokio::test]
async fn a_restore_during_a_stop_waits_for_it() {
    let h = harness().await;
    let m = h.m.create_made(h.request("m")).await.unwrap();
    let s =
        h.m.snapshot(&m.id, api::SnapshotRequest::default())
            .await
            .unwrap();
    let e = h.m.entry(&m.id).unwrap();
    h.stops_take(Duration::from_millis(300));
    let (m2, e2) = (h.m.clone(), e.clone());
    let sleep = tokio::spawn(async move {
        m2.stop_entry(&e2, stop::IDLE, Duration::from_secs(1), false, None)
            .await
            .unwrap()
    });
    while e.snapshot().state != state::STOPPING {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // Stopped by then: restored, and left stopped.
    let r = h.m.restore_snapshot(&m.id, &s.id, None).await.unwrap();
    assert_eq!(
        (r.state.as_str(), r.stopped_reason.as_str()),
        (state::STOPPED, stop::IDLE)
    );
    sleep.await.unwrap();
    assert_eq!(h.reasons(&m.id).last().unwrap(), "restored");
}

#[tokio::test]
async fn a_memory_snapshot_never_writes_through_a_link_left_in_the_jail() {
    let h = harness().await;
    let m = h.m.create_made(h.request("m")).await.unwrap();
    let s1 = h.m.snapshot(&m.id, with_memory()).await.unwrap();
    let rec = h.stored(&m.id).unwrap();
    let kept = h.m.memory_files(&rec, &s1.id)[1].clone();
    std::fs::write(&kept, b"the first one").unwrap();
    // A restore's link, where Firecracker writes the next memory snapshot.
    let dir = h.m.inner.cfg.run_dir().join(&m.id);
    std::fs::hard_link(&kept, dir.join("snap.mem")).unwrap();
    h.m.snapshot(&m.id, with_memory()).await.unwrap();
    assert_eq!(std::fs::read(&kept).unwrap(), b"the first one");
}

#[tokio::test]
async fn tidy_removes_memory_files_no_snapshot_names() {
    let h = harness().await;
    let m = h.m.create_made(h.request("m")).await.unwrap();
    let s1 = h.m.snapshot(&m.id, with_memory()).await.unwrap();
    let rec = h.stored(&m.id).unwrap();
    let kept = h.m.memory_files(&rec, &s1.id);
    // What a crash between the move of a memory snapshot's files and the record's save
    // leaves: files of a snapshot the record does not name.
    let stray = h.m.memory_files(&rec, "s_crashed");
    for f in &stray {
        std::fs::write(f, b"x").unwrap();
    }
    let other = h.m.memory_dir(&rec).join("notes");
    std::fs::write(&other, b"not ours").unwrap();
    let e = h.m.entry(&m.id).unwrap();
    h.m.tidy(&e).await.unwrap();
    assert!(stray.iter().all(|f| !f.exists()), "{stray:?}");
    assert!(kept.iter().all(|f| f.exists()), "{kept:?}");
    assert!(other.exists());
}

#[tokio::test]
async fn a_snapshots_memory_resumes_only_under_the_vmm_that_took_it() {
    let h = harness().await;
    let m = h.m.create_made(h.request("m")).await.unwrap();
    let s = h.m.snapshot(&m.id, with_memory()).await.unwrap();
    let taken = h.stored(&m.id).unwrap();
    assert_eq!(taken.snapshots[0].vmm_version, "v1.17.0/test");
    // The same Firecracker and kernel: resumed.
    h.m.restore_snapshot(&m.id, &s.id, None).await.unwrap();
    assert_eq!(h.reasons(&m.id).last().unwrap(), "resumed");
    // Another (an upgrade since): the memory is put back, then not loaded; the boot is cold
    // and says why.
    h.set_vmm_version("v1.18.0/test");
    h.m.restore_snapshot(&m.id, &s.id, None).await.unwrap();
    assert_eq!(h.reasons(&m.id).last().unwrap(), "started");
    let starting = h
        .events_of(&m.id)
        .into_iter()
        .rev()
        .find(|e| e.reason == "starting")
        .unwrap();
    assert_eq!(
        starting.data,
        Some(json!({"resume": false, "snapshot_vmm": "v1.17.0/test"}))
    );
    assert_eq!(h.m.get(&m.id).unwrap().vmm_version, "v1.18.0/test");
}

#[tokio::test]
async fn a_snapshot_with_memory_resumes_where_it_was_while_the_spec_is_the_same() {
    let h = harness().await;
    let m = h.m.create_made(h.request("m")).await.unwrap();
    let pid = h.stored(&m.id).unwrap().pid;
    h.host_calls();
    let s = h.m.snapshot(&m.id, with_memory()).await.unwrap();
    assert!(s.memory);
    // Paused for the snapshot, then running on: the same process.
    let calls = h.host_calls();
    // Unsynced while paused; the files synced by the daemon after the resume.
    assert_eq!(
        calls,
        [format!("snapshot {pid} unsynced"), format!("resume {pid}")]
    );
    assert_eq!(h.m.get(&m.id).unwrap().state, state::RUNNING);
    let rec = h.stored(&m.id).unwrap();
    let mem = h.m.memory_files(&rec, &s.id)[1].clone();
    assert!(mem.exists(), "{}", mem.display());
    // Restored: resumed from it, and the snapshot keeps it for the next restore.
    for _ in 0..2 {
        h.m.restore_snapshot(&m.id, &s.id, None).await.unwrap();
        assert_eq!(h.restored_data(&m.id)["memory"], true);
        assert_eq!(h.reasons(&m.id).last().unwrap(), "resumed");
        assert!(mem.exists());
    }
    // Another spec since: the processes it holds are not this machine's any more.
    let mut env = BTreeMap::new();
    env.insert("V".to_string(), "2".to_string());
    let patch = api::UpdateMachineRequest {
        spec: api::SpecChange {
            env: Some(env),
            ..Default::default()
        },
        ..Default::default()
    };
    h.m.update(&m.id, patch, None).await.unwrap();
    h.m.restart(&m.id, None).await.unwrap();
    h.m.restore_snapshot(&m.id, &s.id, None).await.unwrap();
    assert_eq!(h.restored_data(&m.id)["memory"], false);
    assert_eq!(h.reasons(&m.id).last().unwrap(), "started");
    h.m.delete_snapshot(&m.id, &s.id).await.unwrap();
    assert!(!mem.exists());
}

#[tokio::test]
async fn a_new_image_drops_the_root_halves_and_keeps_the_old_root_for_its_forks() {
    let h = harness().await;
    h.m.inner
        .images
        .seed(IMAGE3, ImageConfig::default())
        .await
        .unwrap();
    let m = h.m.create_made(h.request("m")).await.unwrap();
    let root = format!("m/{}/root", m.id);
    let first = h.origin(&root).await;
    let s =
        h.m.snapshot(&m.id, api::SnapshotRequest::default())
            .await
            .unwrap();
    let fork = h.fork(&m.id, "fork").await;
    let patch = api::UpdateMachineRequest {
        spec: api::SpecChange {
            image: Some(IMAGE3.into()),
            ..Default::default()
        },
        ..Default::default()
    };
    h.m.update(&m.id, patch, None).await.unwrap();
    h.m.restart(&m.id, None).await.unwrap();
    // The snapshot held the root disk only: it goes with it.
    assert!(
        h.snapshot_ids(&m.id).is_empty(),
        "{:?}",
        h.snapshot_ids(&m.id)
    );
    let now = h.origin(&root).await.unwrap();
    assert!(
        now.0.starts_with("images/") && Some(&now) != first.as_ref(),
        "{now:?}"
    );
    // The old root disk, retired, stays while the fork clones it; its other snapshots go.
    let retired = h.retired(&m.id).await;
    assert_eq!(retired.len(), 1);
    assert!(!h.snapshot_exists(&retired[0], &s.id));
    h.m.destroy(&fork.id, None).await.unwrap();
    assert!(h.retired(&m.id).await.is_empty());
}
