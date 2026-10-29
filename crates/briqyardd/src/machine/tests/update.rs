//! Tests of changing a machine: its spec, its size and its volume.

use super::*;

// --- changes at the next boot (ADR 0024) ---

/// A PATCH of what the machine runs.
pub(in crate::machine) fn spec(f: impl FnOnce(&mut api::SpecChange)) -> api::UpdateMachineRequest {
    let mut req = api::UpdateMachineRequest::default();
    f(&mut req.spec);
    req
}

pub(in crate::machine) fn env(k: &str, v: &str) -> BTreeMap<String, String> {
    BTreeMap::from([(k.to_string(), v.to_string())])
}

impl Harness {
    /// The guest config and the boot files on the config drive the machine's last start
    /// wrote.
    pub(super) fn drive(&self, id: &str) -> (guest::Config, Vec<(String, u32, Vec<u8>)>) {
        let path = self.m.inner.cfg.run_dir().join(id).join("config.tar");
        let mut all = entries(&std::fs::read(path).unwrap());
        let cfg = serde_json::from_slice(&all.remove(0).2).unwrap();
        (cfg, all)
    }
}

#[tokio::test]
async fn a_change_of_what_it_runs_waits_for_the_next_start() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    h.m.inner
        .images
        .seed(IMAGE2, ImageConfig::default())
        .await
        .unwrap();
    let mut req = h.request("web");
    req.env = env("V", "1");
    let m = h.m.create_made(req).await.unwrap();
    h.host.calls();
    let change = spec(|s| {
        s.image = Some(IMAGE2.into());
        s.env = Some(env("V", "2"));
        s.files = Some(vec![api::File {
            path: "/srv/index.html".into(),
            base64: guest::base64_encode(b"v2"),
            mode: None,
        }]);
    });
    // A stale If-Match is refused and leaves nothing pending.
    let stale = h.m.update(&m.id, change.clone(), Some(m.version - 1)).await;
    assert!(matches!(stale, Err(MError::Moved(_))), "{stale:?}");
    assert!(h.m.get(&m.id).unwrap().pending.is_none());
    let patched =
        h.m.update(&m.id, change.clone(), Some(m.version))
            .await
            .unwrap();
    // It runs on as it was: the same process, the same image; the change is pending.
    assert_eq!(
        (patched.state.as_str(), patched.image.as_str()),
        (state::RUNNING, IMAGE)
    );
    let calls = h.host.calls();
    assert!(
        !calls
            .iter()
            .any(|c| c.starts_with("boot") || c.starts_with("kill")),
        "{calls:?}"
    );
    let pending = patched.pending.clone().unwrap();
    assert_eq!(pending.fields, ["image", "env", "files"]);
    assert_eq!(pending.image.as_deref(), Some(IMAGE2));
    assert!(patched.pending_since.is_some());
    let e = h.events_of(&m.id).pop().unwrap();
    assert_eq!(
        (e.reason.as_str(), e.message.as_str()),
        ("updated", "image, env, files change at the next start")
    );
    assert_eq!(
        e.data,
        Some(json!({"fields": ["image", "env", "files"], "pending": true}))
    );
    assert_eq!(patched.version, e.seq);
    // The same change again is none: no event, the version stays.
    let same = h.m.update(&m.id, change, None).await.unwrap();
    assert_eq!(same.version, patched.version);
    // A second PATCH goes over the first; its event names what it moved.
    let cmd = vec!["sh".to_string(), "-c".into(), "echo $V".into()];
    let more =
        h.m.update(&m.id, spec(|s| s.cmd = Some(cmd.clone())), None)
            .await
            .unwrap();
    assert_eq!(
        more.pending.unwrap().fields,
        ["image", "cmd", "env", "files"]
    );
    assert_eq!(
        more.pending_since, patched.pending_since,
        "the oldest change"
    );
    assert_eq!(
        h.events_of(&m.id).pop().unwrap().data,
        Some(json!({"fields": ["cmd"], "pending": true}))
    );
    // A restart applies it, after its If-Match.
    let stale = h.m.restart(&m.id, Some(patched.version)).await;
    assert!(matches!(stale, Err(MError::Moved(_))), "{stale:?}");
    let applied = h.m.restart(&m.id, Some(more.version)).await.unwrap();
    assert_eq!(
        (applied.state.as_str(), applied.image.as_str()),
        (state::RUNNING, IMAGE2)
    );
    assert!(applied.pending.is_none() && applied.pending_since.is_none());
    let reasons = h.reasons(&m.id);
    assert_eq!(
        reasons[reasons.len() - 5..],
        ["stopping", "stopped", "applied", "starting", "started"]
    );
    let ev = h
        .events_of(&m.id)
        .into_iter()
        .find(|e| e.reason == "applied");
    assert_eq!(
        ev.map(|e| (e.message, e.data)),
        Some((
            "image, cmd, env, files applied".to_string(),
            Some(json!({"fields": ["image", "cmd", "env", "files"]}))
        ))
    );
    // The boot read the new spec: its config drive carries it.
    let (cfg, files) = h.drive(&m.id);
    assert_eq!(cfg.env.get("V").map(String::as_str), Some("2"));
    assert_eq!(cfg.cmd, cmd);
    assert_eq!(
        files,
        [("files/srv/index.html".to_string(), 0o644, b"v2".to_vec())]
    );
    assert_eq!(h.stored(&m.id).unwrap().boots, 2);
}

#[tokio::test]
async fn a_new_image_makes_the_root_disk_again_and_keeps_the_volume() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let im =
        h.m.inner
            .images
            .seed(IMAGE2, ImageConfig::default())
            .await
            .unwrap();
    let e = h.add("m_x", state::STOPPED, 256);
    h.disks(&e).await;
    let dev = h.pool.dev();
    std::fs::write(dev.join("byard/m/m_x/data"), b"the database").unwrap();
    // A fork of its root disk, as a create with `fork` makes one.
    let z = &h.pool.zfs;
    z.snapshot("m/m_x/root", "fork-m_child").await.unwrap();
    z.clone_snapshot("m/m_x/root", "fork-m_child", "m/m_child/root")
        .await
        .unwrap();
    h.m.update("m_x", spec(|s| s.image = Some(IMAGE2.into())), None)
        .await
        .unwrap();
    h.pool.calls();
    h.m.start("m_x", None).await.unwrap();
    let r = h.stored("m_x").unwrap();
    assert_eq!(
        (r.image.as_str(), r.image_key.as_str(), r.root_key.as_str()),
        (IMAGE2, im.key.as_str(), im.key.as_str())
    );
    // The root disk is a clone of the new image; the volume was never touched.
    let origin = std::fs::read_to_string(dev.join("byard/m/m_x/root.origin")).unwrap();
    assert_eq!(origin.trim(), format!("byard/images/{}@base", im.key));
    assert_eq!(
        std::fs::read(dev.join("byard/m/m_x/data")).unwrap(),
        b"the database"
    );
    // Swapped (ADR 0031): the old root disk renamed aside, a clone of the image in its
    // place.
    let calls = h.pool.calls();
    assert!(
        calls
            .iter()
            .any(|c| c.starts_with("rename byard/m/m_x/root byard/m/m_x/root.r_")),
        "{calls:?}"
    );
    assert!(
        !calls
            .iter()
            .any(|c| c.contains("m_x/data") && !c.starts_with("list ")),
        "{calls:?}"
    );
    // The fork lives on, whole, a clone of the old root disk, retired and kept for it.
    let fork_origin = std::fs::read_to_string(dev.join("byard/m/m_child/root.origin")).unwrap();
    assert!(
        fork_origin.starts_with("byard/m/m_x/root.r_")
            && fork_origin.trim().ends_with("@fork-m_child"),
        "{fork_origin}"
    );
    // The next start has nothing to make.
    h.m.stop("m_x", Duration::from_secs(1), false, None)
        .await
        .unwrap();
    h.pool.calls();
    h.m.start("m_x", None).await.unwrap();
    let calls = h.pool.calls();
    assert!(
        !calls
            .iter()
            .any(|c| c.starts_with("clone ") || c.starts_with("destroy ")),
        "{calls:?}"
    );
}

#[tokio::test]
async fn a_root_disk_is_made_from_the_image_the_cache_has_for_it_now() {
    // The build its record names is gone from the host (removed since the start resolved
    // it): the root disk comes from the image as the cache answers for its reference.
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let im = h.m.inner.images.ensure(IMAGE).await.unwrap();
    let e = h.add("m_y", state::STOPPED, 256);
    h.disks(&e).await;
    {
        let mut r = e.rec.lock().unwrap();
        r.image = IMAGE.into();
        r.root_key = "older".into();
    }
    h.m.start("m_y", None).await.unwrap();
    let r = h.stored("m_y").unwrap();
    assert_eq!((r.image_key, r.root_key), (im.key.clone(), im.key));
}

#[tokio::test]
async fn a_root_disk_is_made_again_only_once_no_backup_runs() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    h.m.inner
        .images
        .seed(IMAGE2, ImageConfig::default())
        .await
        .unwrap();
    let e = h.add("m_x", state::STOPPED, 256);
    h.disks(&e).await;
    // A backup under way holds the turn, as `backup_entry`'s callers do.
    let backup = e.backup_turn.clone().lock_owned().await;
    // A start with no root disk to make does not wait for it.
    h.m.start("m_x", None).await.unwrap();
    h.m.stop("m_x", Duration::from_secs(1), false, None)
        .await
        .unwrap();
    h.m.update("m_x", spec(|s| s.image = Some(IMAGE2.into())), None)
        .await
        .unwrap();
    h.pool.calls();
    let m = h.m.clone();
    let mut start = tokio::spawn(async move { m.start("m_x", None).await });
    let waited = tokio::time::timeout(Duration::from_millis(300), &mut start).await;
    assert!(waited.is_err(), "the start waits for the backup");
    let calls = h.pool.calls();
    assert!(
        !calls.iter().any(|c| c.starts_with("destroy ")),
        "{calls:?}"
    );
    assert_eq!(h.m.get("m_x").unwrap().state, state::STOPPED);
    drop(backup);
    let up = start.await.unwrap().unwrap();
    assert_eq!(
        (up.state.as_str(), up.image.as_str()),
        (state::RUNNING, IMAGE2)
    );
    let key = h.m.inner.images.ensure(IMAGE2).await.unwrap().key;
    assert_eq!(h.stored("m_x").unwrap().root_key, key);
}

#[tokio::test]
async fn a_new_size_is_reserved_at_the_start_and_refused_past_the_host() {
    let h = harness("10.64.0.0/22", 1024).await;
    h.ready().await;
    let a = h.m.create_made(h.request("a")).await.unwrap();
    let mut big = h.request("b");
    big.size.memory_mb = 512;
    let b = h.m.create_made(big).await.unwrap();
    let grown = api::Size {
        vcpus: 2,
        memory_mb: 768,
    };
    let patched =
        h.m.update(&a.id, spec(|s| s.size = Some(grown)), None)
            .await
            .unwrap();
    // It runs on at its size: the host holds 256 for it.
    assert_eq!(patched.size.memory_mb, 256);
    assert_eq!(h.m.usage().0.memory_mb, 768);
    h.m.stop(&a.id, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    // b holds 512: 768 more do not fit, and the change waits for a start that fits.
    let full = h.m.start(&a.id, None).await;
    assert!(matches!(full, Err(MError::Capacity(_))), "{full:?}");
    let still = h.m.get(&a.id).unwrap();
    assert_eq!(
        (still.state.as_str(), still.size.memory_mb),
        (state::STOPPED, 256)
    );
    assert_eq!(still.pending.and_then(|p| p.size), Some(grown));
    h.m.stop(&b.id, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    // A restart of a stopped machine is a start.
    let up = h.m.restart(&a.id, None).await.unwrap();
    assert_eq!((up.state.as_str(), up.size), (state::RUNNING, grown));
    assert_eq!(
        h.m.usage().0,
        api::Capacity {
            memory_mb: 768,
            vcpus: 2
        }
    );
    assert_eq!(h.host.booted.lock().unwrap().get(&a.id), Some(&grown));
}

#[tokio::test]
async fn a_change_to_what_a_memory_snapshot_holds_makes_the_next_start_cold() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("web")).await.unwrap();
    let suspend = || h.m.stop(&m.id, Duration::from_secs(1), true, None);
    assert!(suspend().await.unwrap().suspended);
    // The ports are the daemon's: a resume applies them.
    h.m.update(&m.id, spec(|s| s.ports = Some(vec![8080])), None)
        .await
        .unwrap();
    h.host.calls();
    let back = h.m.start(&m.id, None).await.unwrap();
    assert_eq!(back.ports, [8080]);
    let calls = h.host.calls();
    assert!(
        calls.iter().any(|c| c.ends_with(" resume=true")),
        "{calls:?}"
    );
    // The env is in the guest's memory: the snapshot is dropped, the boot is cold.
    assert!(suspend().await.unwrap().suspended);
    h.m.update(&m.id, spec(|s| s.env = Some(env("V", "2"))), None)
        .await
        .unwrap();
    h.host.calls();
    let cold = h.m.start(&m.id, None).await.unwrap();
    assert!(!cold.suspended);
    let calls = h.host.calls();
    assert!(
        calls.iter().any(|c| c.ends_with(" resume=false")),
        "{calls:?}"
    );
    let evs = h.events_of(&m.id);
    let starting = evs.iter().rev().find(|e| e.reason == "starting").unwrap();
    assert_eq!(starting.data, Some(json!({"resume": false})));
    assert_eq!(evs.last().map(|e| e.reason.as_str()), Some("started"));
    assert_eq!(h.drive(&m.id).0.env.get("V").map(String::as_str), Some("2"));
}

#[tokio::test]
async fn a_volume_grows_at_the_patch_and_its_filesystem_at_the_next_start_cold() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let e = with_volume(&h, "m_v", state::STOPPED, 2).await;
    // Suspended: the memory holds the guest's view of the smaller disk.
    e.rec.lock().unwrap().suspended = true;
    let m = h.m.update("m_v", grow_to(5), None).await.unwrap();
    // The disk at once, and the record with it: what the quota, usage, forks and backups
    // read.
    assert_eq!(
        h.pool.calls(),
        [
            "get -H -p -o value used,available byard",
            "set volsize=5368709120 byard/m/m_v/data"
        ]
    );
    assert_eq!(h.pool.zfs.volsize("m/m_v/data").await.unwrap(), 5 << 30);
    assert_eq!(m.volume.map(|v| v.size_gb), Some(5));
    assert_eq!(h.stored("m_v").unwrap().volume.unwrap().size_gb, 5);
    assert_eq!(h.m.quota("t1").unwrap().used.disk_gb, 5);
    let p = m.pending.unwrap();
    assert_eq!(
        (p.fields, p.volume),
        (
            vec!["volume".to_string()],
            Some(api::VolumeSize { size_gb: 5 })
        )
    );
    let ev = h.events_of("m_v").pop().unwrap();
    assert_eq!(
        (ev.reason.as_str(), ev.data),
        (
            "updated",
            Some(json!({"fields": ["volume"], "pending": true}))
        )
    );
    // The size it has is no change: nothing called, no event.
    h.pool.calls();
    let again = h.m.update("m_v", grow_to(5), None).await.unwrap();
    assert_eq!(again.version, m.version);
    let calls = h.pool.calls();
    assert!(calls.is_empty(), "{calls:?}");
    // The start applies it: the memory snapshot dropped, the boot cold, so the init grows
    // the filesystem.
    h.host_calls();
    let up = h.m.start("m_v", None).await.unwrap();
    assert!(up.pending.is_none() && !up.suspended);
    let calls = h.host_calls();
    assert!(
        calls.iter().any(|c| c.ends_with(" resume=false")),
        "{calls:?}"
    );
    let applied = h
        .events_of("m_v")
        .into_iter()
        .find(|e| e.reason == "applied");
    assert_eq!(
        applied.and_then(|e| e.data),
        Some(json!({"fields": ["volume"]}))
    );
    assert_eq!(h.drive("m_v").0.mounts[0].fstype, "ext4");
}

#[tokio::test]
async fn a_grown_volume_is_on_the_stored_record_once_its_disk_grew() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let e = with_volume(&h, "m_v", state::STOPPED, 2).await;
    h.m.grow_volume(&e, 2, 5).await.unwrap();
    // Saved with the disk: a crash before the PATCH's own save leaves no record smaller
    // than its disk.
    assert_eq!(h.stored("m_v").map(|r| r.volume.unwrap().size_gb), Some(5));
}

#[tokio::test]
async fn a_volume_never_shrinks_and_grows_within_the_quota_and_the_pool() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let e = with_volume(&h, "m_v", state::STOPPED, 2).await;
    let refused = |r: Result<api::Machine, MError>| r.unwrap_err().to_string();
    assert_eq!(
        refused(h.m.update("m_v", grow_to(1), None).await),
        "invalid request: volume: 1 GB asked, 2 GB held: a volume never shrinks"
    );
    let n = h.add("m_n", state::STOPPED, 256);
    n.rec.lock().unwrap().volume = None;
    assert_eq!(
        refused(h.m.update("m_n", grow_to(1), None).await),
        "invalid request: volume: the machine has none; a volume is made at create"
    );
    // The tenant's quota counts the growth, as a create counts a volume.
    let quota = api::Quota {
        disk_gb: Some(4),
        ..Default::default()
    };
    h.m.set_quota("t1", quota).await.unwrap();
    h.pool.calls();
    assert_eq!(
        refused(h.m.update("m_v", grow_to(5), None).await),
        "tenant t1's quota: disk_gb 2 of 4 used, 3 more asked"
    );
    let last = h.events_of("m_v").pop().unwrap();
    assert_eq!(last.reason, "quota_exceeded");
    h.m.set_quota("t1", api::Quota::default()).await.unwrap();
    // The pool's room, as at a create.
    h.pool
        .answer("used,available", &format!("0\n{}\n", 1u64 << 30));
    assert_eq!(
        refused(h.m.update("m_v", grow_to(4), None).await),
        "the host is full: the pool has 1.0 GB free, the volume asks 2 GB"
    );
    h.pool
        .answer("used,available", &format!("0\n{}\n", 1u64 << 40));
    // ZFS refuses: the record goes back.
    let data = h.pool.dev().join("byard/m/m_v/data");
    std::fs::rename(&data, data.with_extension("away")).unwrap();
    let err = refused(h.m.update("m_v", grow_to(3), None).await);
    assert!(err.contains("grow the volume to 3 GB"), "{err}");
    std::fs::rename(data.with_extension("away"), &data).unwrap();
    // A restore cut short, a destroy under way.
    e.rec.lock().unwrap().restoring = Some("s_1".into());
    assert!(refused(h.m.update("m_v", grow_to(3), None).await).contains("unfinished"));
    e.rec.lock().unwrap().restoring = None;
    let r = h.stored("m_v").unwrap();
    assert_eq!((r.volume.unwrap().size_gb, r.pending), (2, None));
    assert!(
        !h.pool
            .calls()
            .iter()
            .any(|c| c.starts_with("set volsize=") && !c.starts_with("set volsize=3221225472")),
        "only the refused one was asked"
    );
    assert_eq!(h.pool.zfs.volsize("m/m_v/data").await.unwrap(), 2 << 30);
    e.rec.lock().unwrap().state = state::DESTROYING.into();
    assert!(matches!(
        h.m.update("m_v", grow_to(3), None).await,
        Err(MError::BadState(_))
    ));
}

#[tokio::test]
async fn a_fork_takes_a_larger_volume_never_a_smaller_one() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    with_volume(&h, "m_v", state::STOPPED, 2).await;
    let fork = |gb: u32, name: &str| api::CreateMachineRequest {
        fork: Some(api::ForkSpec {
            machine_id: "m_v".into(),
            copy: String::new(),
        }),
        volume: Some(api::VolumeSpec {
            size_gb: gb,
            mount: "/data".into(),
        }),
        image: String::new(),
        start: Some(false),
        ..h.request(name)
    };
    let err = h.m.create_made(fork(1, "small")).await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "invalid request: volume: 1 GB asked, 2 GB held: a volume never shrinks"
    );
    let f = h.m.create_made(fork(6, "big")).await.unwrap();
    assert_eq!(f.volume.map(|v| v.size_gb), Some(6));
    let ds = format!("m/{}/data", f.id);
    assert_eq!(h.pool.zfs.volsize(&ds).await.unwrap(), 6 << 30);
    assert_eq!(h.pool.zfs.volsize("m/m_v/data").await.unwrap(), 2 << 30);
    // The source's own size: its clone is that size already.
    h.pool.calls();
    let same = h.m.create_made(fork(2, "same")).await.unwrap();
    assert!(!h.pool.calls().iter().any(|c| c.starts_with("set ")));
    assert_eq!(same.volume.map(|v| v.size_gb), Some(2));
}

#[tokio::test]
async fn an_image_that_cannot_be_pulled_fails_the_boot_and_stays_pending() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("web")).await.unwrap();
    h.m.stop(&m.id, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    h.host.calls();
    // No registry answers there.
    let nowhere =
        "127.0.0.1:1/nothing@sha256:0000000000000000000000000000000000000000000000000000000000000009";
    h.m.update(&m.id, spec(|s| s.image = Some(nowhere.into())), None)
        .await
        .unwrap();
    let failed = match h.m.start(&m.id, None).await {
        Err(MError::BootFailed(m)) => m,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        (failed.state.as_str(), failed.image.as_str()),
        (state::ERROR, IMAGE)
    );
    assert!(
        failed.error.starts_with(&format!("image {nowhere}: ")),
        "{}",
        failed.error
    );
    assert_eq!(failed.pending.map(|p| p.fields), Some(vec!["image".into()]));
    assert_eq!(
        h.reasons(&m.id).last().map(String::as_str),
        Some("boot_failed")
    );
    assert!(!h.host.calls().iter().any(|c| c.starts_with("boot ")));
    // A PATCH back to the image it has leaves nothing pending; the start boots that.
    let fixed =
        h.m.update(&m.id, spec(|s| s.image = Some(IMAGE.into())), None)
            .await
            .unwrap();
    assert!(fixed.pending.is_none() && fixed.pending_since.is_none());
    assert_eq!(h.m.start(&m.id, None).await.unwrap().state, state::RUNNING);
}

#[tokio::test]
async fn create_and_patch_refuse_a_bad_spec_in_the_same_words() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("web")).await.unwrap();
    let file = |path: &str, base64: &str, mode: Option<&str>| api::File {
        path: path.into(),
        base64: base64.into(),
        mode: mode.map(String::from),
    };
    let bad = [
        (
            spec(|s| {
                s.size = Some(api::Size {
                    vcpus: 0,
                    memory_mb: 256,
                })
            }),
            "size.vcpus must be 1..32",
        ),
        (
            spec(|s| s.files = Some(vec![file("etc/x", "", None)])),
            "file \"etc/x\": path must be absolute",
        ),
        (
            spec(|s| s.files = Some(vec![file("/x", "!!", None)])),
            "file \"/x\": ",
        ),
        (
            spec(|s| s.files = Some(vec![file("/x", "", Some("9"))])),
            "file \"/x\": mode \"9\": want octal digits",
        ),
        (
            spec(|s| s.env = Some(env("A=B", "1"))),
            "env \"A=B\": a name is not empty and holds no \"=\"",
        ),
        (spec(|s| s.ports = Some(vec![0])), "ports: 0 is not a port"),
        (
            spec(|s| {
                s.restart = Some(api::RestartPolicy {
                    policy: "sometimes".into(),
                    max_retries: 0,
                })
            }),
            "restart.policy must be no, on-failure or always",
        ),
    ];
    for (patch, want) in bad {
        let s = patch.spec.clone();
        let mut req = h.request("bad");
        req.size = s.size.unwrap_or(req.size);
        req.files = s.files.unwrap_or_default();
        req.env = s.env.unwrap_or_default();
        req.ports = s.ports.unwrap_or_default();
        req.restart = s.restart;
        let at_create = refused(h.m.create_made(req).await);
        let at_patch = refused(h.m.update(&m.id, patch, None).await);
        assert!(at_create.starts_with(want), "{at_create:?}, want {want:?}");
        assert_eq!(at_create, at_patch);
    }
    assert!(h.m.get(&m.id).unwrap().pending.is_none());
    let empty = refused(
        h.m.update(&m.id, spec(|s| s.image = Some("".into())), None)
            .await,
    );
    assert_eq!(empty, "image must not be empty");
}

// --- upgrades (ADR 0027) ---

#[tokio::test]
async fn a_boot_records_what_the_init_says_and_what_ran_it() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("web")).await.unwrap();
    assert_eq!(
        (m.init_version.as_str(), m.vmm_version.as_str()),
        ("0.1.0+init", "v1.17.0/test")
    );
    let r = h.stored(&m.id).unwrap();
    assert_eq!(
        (r.init_version.as_str(), r.vmm_version.as_str()),
        ("0.1.0+init", "v1.17.0/test")
    );
    // A cold boot under another init and Firecracker records them.
    h.m.stop(&m.id, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    *h.host.init_version.lock().unwrap() = "0.2.0+b".into();
    *h.host.vmm_version.lock().unwrap() = "v1.18.0/test".into();
    let m = h.m.start(&m.id, None).await.unwrap();
    assert_eq!(
        (m.init_version.as_str(), m.vmm_version.as_str()),
        ("0.2.0+b", "v1.18.0/test")
    );
}
