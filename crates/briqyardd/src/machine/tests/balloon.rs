//! Device profiles belong to incarnations, independent of the rollout switch.

use super::*;
use crate::fc::Vmm;

async fn reporting_harness() -> Harness {
    let h = harness_config(|c| {
        c.network.range = "10.64.0.0/22".into();
        c.capacity.memory_mb = 4096;
        c.balloon.enabled = true;
    })
    .await;
    h.ready().await;
    h
}

#[test]
fn old_records_and_snapshots_remain_identity_absent() {
    let mut value = serde_json::to_value(record()).unwrap();
    value.as_object_mut().unwrap().remove("boot_identity");
    let rec: Record = serde_json::from_value(value).unwrap();
    assert!(rec.boot_identity.is_none());
    let snapshot: SnapshotRec = serde_json::from_value(json!({
        "id":"s_old", "created_at":"2026-10-18T22:00:00Z", "disks":["root"],
        "memory":"old-spec", "vmm_version":"v1.17.0/test"
    }))
    .unwrap();
    assert!(snapshot.boot_identity.is_none());
}

#[tokio::test]
async fn a_new_cold_boot_persists_reporting_identity_and_keeps_full_reservation() {
    let h = reporting_harness().await;
    let machine = h.m.create_made(h.request("reporting")).await.unwrap();
    let rec = h.stored(&machine.id).unwrap();
    assert_eq!(
        rec.boot_identity.unwrap().device_profile,
        fc::REPORTING_PROFILE
    );
    assert_eq!(h.m.usage().0.memory_mb, machine.size.memory_mb);
    let stats = h.m.stats(&machine.id).await.unwrap();
    assert_eq!(stats.boot_profile.as_deref(), Some(fc::REPORTING_PROFILE));
    assert!(stats.balloon.is_none(), "no tick has sampled yet");
}

#[tokio::test]
async fn legacy_memory_resumes_after_reporting_is_enabled_without_relabeling() {
    let h = reporting_harness().await;
    let e = h.add("m_old", state::STOPPED, 256);
    h.disks(&e).await;
    {
        let mut rec = e.rec.lock().unwrap();
        rec.suspended = true;
        rec.vmm_version = h.host.version();
        rec.boot_identity = None;
    }
    let dir = h.m.inner.cfg.run_dir().join("m_old");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("snap.mem"), "legacy memory").unwrap();
    h.m.start("m_old", None).await.unwrap();
    assert!(e.live.lock().unwrap().as_ref().unwrap().resumed);
    assert!(h.stored("m_old").unwrap().boot_identity.is_none());
    h.m.measure(Utc::now()).await;
    assert!(!h.host.calls().iter().any(|s| s == "balloon-statistics"));
}

#[tokio::test]
async fn missing_legacy_memory_falls_back_with_a_durable_current_profile() {
    let h = reporting_harness().await;
    let e = h.add("m_missing", state::STOPPED, 256);
    h.disks(&e).await;
    {
        let mut rec = e.rec.lock().unwrap();
        rec.suspended = true;
        rec.vmm_version = h.host.version();
    }
    h.m.start("m_missing", None).await.unwrap();
    assert!(!e.live.lock().unwrap().as_ref().unwrap().resumed);
    assert_eq!(
        h.stored("m_missing")
            .unwrap()
            .boot_identity
            .unwrap()
            .device_profile,
        fc::REPORTING_PROFILE
    );
    assert!(h
        .events_of("m_missing")
        .iter()
        .any(|ev| ev.data.as_ref().is_some_and(|d| d["fallback"] == true)));
}

#[tokio::test]
async fn unknown_identity_refuses_memory_load_and_keeps_named_snapshot() {
    let h = reporting_harness().await;
    let e = h.add("m_future", state::STOPPED, 256);
    h.disks(&e).await;
    let mut future = h.host.boot_identity(true).unwrap();
    future.schema = 2;
    {
        let mut rec = e.rec.lock().unwrap();
        rec.suspended = true;
        rec.vmm_version = h.host.version();
        rec.boot_identity = Some(future.clone());
        rec.snapshots.push(SnapshotRec {
            id: "s_future".into(),
            name: None,
            created_at: Utc::now(),
            disks: vec!["root".into()],
            memory: Some("untouched".into()),
            vmm_version: h.host.version(),
            boot_identity: Some(future),
            clone_artifact: None,
        });
    }
    h.m.start("m_future", None).await.unwrap();
    assert!(!e.live.lock().unwrap().as_ref().unwrap().resumed);
    assert_eq!(h.stored("m_future").unwrap().snapshots.len(), 1);
}

#[tokio::test]
async fn reporting_stats_are_cached_exact_and_optional_and_stopped_gauges_disappear() {
    let h = reporting_harness().await;
    let machine = h.m.create_made(h.request("reporting")).await.unwrap();
    h.host.cgroups.lock().unwrap().insert(
        machine.id.clone(),
        fc::CgroupUse {
            memory_bytes: 99,
            memory_anon_bytes: Some(12),
            memory_file_bytes: Some(34),
            ..Default::default()
        },
    );
    h.m.measure(Utc::now()).await;
    let stats = h.m.stats(&machine.id).await.unwrap();
    assert_eq!(
        (stats.memory_anon_bytes, stats.memory_file_bytes),
        (Some(12), Some(34))
    );
    let balloon = stats.balloon.unwrap();
    assert_eq!(balloon.actual_bytes, Some(3 * 4096));
    assert_eq!(balloon.guest_available_bytes, None);
    assert!(!balloon.guest_sample_time_known);
    assert!(balloon.last_stats_update_observed_at.is_none());
    h.host.calls();
    let first = h.m.metrics();
    assert!(first.contains("briqyard_machine_balloon_actual_bytes{"));
    assert!(first.contains(" 12288\n"));
    let machine_samples = |text: &str| {
        text.lines()
            .filter(|line| line.starts_with("briqyard_machine_"))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    assert_eq!(machine_samples(&first), machine_samples(&h.m.metrics()));
    assert!(!h.host.calls().iter().any(|s| s == "balloon-statistics"));
    let e = h.m.entry(&machine.id).unwrap();
    e.rec.lock().unwrap().state = state::STOPPED.into();
    assert!(!h
        .m
        .metrics()
        .lines()
        .any(|l| l.starts_with("briqyard_machine_balloon_actual_bytes{")));
    assert!(!h
        .m
        .metrics()
        .lines()
        .any(|l| l.starts_with("briqyard_machine_memory_bytes{")));
}

#[tokio::test]
async fn telemetry_failure_keeps_lifecycle_and_profile_and_omits_false_samples() {
    let h = reporting_harness().await;
    let machine = h.m.create_made(h.request("reporting")).await.unwrap();
    h.host.refuse_balloon_stats.store(true, Relaxed);
    h.m.measure(Utc::now()).await;
    let stats = h.m.stats(&machine.id).await.unwrap();
    assert_eq!(stats.state, state::RUNNING);
    assert_eq!(stats.boot_profile.as_deref(), Some(fc::REPORTING_PROFILE));
    let balloon = stats.balloon.unwrap();
    assert_eq!(balloon.status, "error");
    assert!(balloon.actual_bytes.is_none());
    assert!(!h
        .m
        .metrics()
        .lines()
        .any(|line| line.starts_with("briqyard_machine_balloon_actual_bytes{")));
    h.m.stop(&machine.id, Duration::ZERO, true, None)
        .await
        .unwrap();
    h.m.start(&machine.id, None).await.unwrap();
    assert_eq!(h.reasons(&machine.id).last().unwrap(), "resumed");
    assert_eq!(
        h.stored(&machine.id)
            .unwrap()
            .boot_identity
            .unwrap()
            .device_profile,
        fc::REPORTING_PROFILE
    );
}

#[tokio::test]
async fn named_memory_restore_copies_identity_and_disk_fork_chooses_cold_profile() {
    let h = reporting_harness().await;
    let machine = h.m.create_made(h.request("source")).await.unwrap();
    let identity = h.stored(&machine.id).unwrap().boot_identity;
    let snapshot =
        h.m.snapshot(
            &machine.id,
            api::SnapshotRequest {
                template: false,
                name: None,
                memory: true,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        h.stored(&machine.id).unwrap().snapshots[0].boot_identity,
        identity
    );
    h.m.restore_snapshot(&machine.id, &snapshot.id, None)
        .await
        .unwrap();
    assert_eq!(h.reasons(&machine.id).last().unwrap(), "resumed");
    assert_eq!(h.stored(&machine.id).unwrap().boot_identity, identity);
    let fork = h.fork(&machine.id, "fork").await;
    let entry = h.m.entry(&fork.id).unwrap();
    assert!(!entry.live.lock().unwrap().as_ref().unwrap().resumed);
    assert_eq!(
        h.stored(&fork.id)
            .unwrap()
            .boot_identity
            .unwrap()
            .device_profile,
        fc::REPORTING_PROFILE
    );
}

#[tokio::test]
async fn adoption_keeps_known_identity_and_missing_provenance_never_becomes_legacy() {
    let h = reporting_harness().await;
    let machine = h.m.create_made(h.request("reporting")).await.unwrap();
    let e = h.m.entry(&machine.id).unwrap();
    let before = e.snapshot();
    assert!(h.m.adopt(&e, before.pid, true).await);
    assert_eq!(e.snapshot().boot_identity, before.boot_identity);
    e.rec.lock().unwrap().boot_identity = None;
    h.host.calls();
    assert!(h.m.adopt(&e, before.pid, true).await);
    let observed = e.snapshot().boot_identity.unwrap();
    assert_eq!(observed.device_profile, fc::REPORTING_PROFILE);
    assert_eq!(
        observed.schema, 0,
        "current artifacts cannot prove historical provenance"
    );
    assert!(!h.m.resume_compatible(&e.snapshot()));
    assert!(!h.host.calls().iter().any(|c| c.starts_with("kill ")));
}

#[test]
fn rollout_switch_is_default_off_and_rejects_unknown_controls() {
    let cfg: Config = serde_yaml::from_str("balloon:\n  enabled: true\n").unwrap();
    assert!(cfg.balloon.enabled);
    assert!(!Config::default().balloon.enabled);
    assert!(serde_yaml::from_str::<Config>("balloon:\n  amount_mib: 128\n").is_err());
}

#[tokio::test]
async fn adoption_detects_stale_reporting_metadata_from_an_older_cold_boot() {
    let h = reporting_harness().await;
    let machine = h.m.create_made(h.request("reporting")).await.unwrap();
    let e = h.m.entry(&machine.id).unwrap();
    let pid = e.snapshot().pid;
    // An old daemon preserved unknown metadata but cold-booted without the device.
    h.host
        .procs
        .lock()
        .unwrap()
        .iter_mut()
        .find(|p| p.pid == pid)
        .unwrap()
        .boot_identity = None;
    h.host.calls();
    assert!(h.m.adopt(&e, pid, true).await);
    let identity = h.stored(&machine.id).unwrap().boot_identity.unwrap();
    assert_eq!(
        (identity.schema, identity.device_profile.as_str()),
        (0, fc::LEGACY_PROFILE)
    );
    assert!(!h.m.resume_compatible(&e.snapshot()));
    assert!(!h.host.calls().iter().any(|c| c.starts_with("kill ")));
}

#[tokio::test]
async fn adoption_missing_or_changed_binding_cannot_recertify_matching_devices() {
    for reporting in [false, true] {
        let h = harness_config(|c| {
            c.network.range = "10.64.0.0/22".into();
            c.capacity.memory_mb = 4096;
            c.balloon.enabled = reporting;
        })
        .await;
        h.ready().await;
        let machine = h.m.create_made(h.request("bound")).await.unwrap();
        let e = h.m.entry(&machine.id).unwrap();
        let pid = e.snapshot().pid;
        let original = e.snapshot().boot_identity.unwrap();
        assert!(e.snapshot().boot_incarnation.is_some());
        for missing in [false, true] {
            {
                let mut rec = e.rec.lock().unwrap();
                rec.boot_identity = Some(original.clone());
                if missing {
                    rec.boot_incarnation = None;
                } else {
                    rec.boot_incarnation.as_mut().unwrap().start_ticks += 1;
                }
            }
            assert!(h.m.adopt(&e, pid, true).await);
            let identity = h.stored(&machine.id).unwrap().boot_identity.unwrap();
            assert_eq!(identity.schema, 0);
            assert_eq!(identity.device_profile, original.device_profile);
            assert!(!e.identity_trusted.load(Relaxed));
        }
    }
}

#[tokio::test]
async fn failed_observation_retains_metadata_but_unbound_memory_is_ambiguous_and_stop_works() {
    let h = reporting_harness().await;
    let machine = h.m.create_made(h.request("reporting")).await.unwrap();
    let e = h.m.entry(&machine.id).unwrap();
    let pid = e.snapshot().pid;
    let original = e.snapshot().boot_identity;
    e.rec.lock().unwrap().boot_incarnation = None;
    h.host
        .procs
        .lock()
        .unwrap()
        .iter_mut()
        .find(|p| p.pid == pid)
        .unwrap()
        .boot_identity = Some(fc::BootIdentity::ambiguous(fc::UNAVAILABLE_PROFILE));
    assert!(h.m.adopt(&e, pid, true).await);
    assert_eq!(e.snapshot().boot_identity, original);
    assert!(!e.identity_trusted.load(Relaxed));
    let snapshot =
        h.m.snapshot(
            &machine.id,
            api::SnapshotRequest {
                template: false,
                name: None,
                memory: true,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        h.stored(&machine.id)
            .unwrap()
            .snapshots
            .iter()
            .find(|s| s.id == snapshot.id)
            .unwrap()
            .boot_identity
            .as_ref()
            .unwrap()
            .schema,
        0
    );
    h.m.stop(&machine.id, Duration::ZERO, true, None)
        .await
        .unwrap();
    assert_eq!(e.snapshot().boot_identity.as_ref().unwrap().schema, 0);
    h.m.start(&machine.id, None).await.unwrap();
    assert_eq!(h.reasons(&machine.id).last().unwrap(), "started");
    assert!(h
        .events_of(&machine.id)
        .iter()
        .any(|ev| ev.message.contains("boot identity incompatible")));
    h.m.stop(&machine.id, Duration::ZERO, false, None)
        .await
        .unwrap();
    assert_eq!(h.m.get(&machine.id).unwrap().state, state::STOPPED);
}
