//! Tests of egress policies and limits, and disk limits.

use super::*;

// --- egress (ADR 0015) ---

pub(super) fn egress(mode: &str, via: Option<&str>) -> api::Egress {
    api::Egress {
        mode: mode.into(),
        via: via.map(String::from),
    }
}

pub(super) fn set_egress(mode: &str, via: Option<&str>) -> api::UpdateMachineRequest {
    api::UpdateMachineRequest {
        egress: Some(egress(mode, via)),
        ..Default::default()
    }
}

/// The message of an `invalid` refusal.
pub(in crate::machine) fn refused<T: std::fmt::Debug>(r: Result<T, MError>) -> String {
    match r {
        Err(MError::Invalid(msg)) => msg,
        other => panic!("not refused: {other:?}"),
    }
}

impl Harness {
    pub(super) fn request_egress(
        &self,
        name: &str,
        mode: &str,
        via: Option<&str>,
    ) -> api::CreateMachineRequest {
        api::CreateMachineRequest {
            egress: Some(egress(mode, via)),
            ..self.request(name)
        }
    }

    /// Whether tenant `t1`'s resolver answers `ip` from the tenant's names alone.
    fn dns_kept(&self, ip: &str) -> bool {
        let gateway = Ipv4Addr::new(10, 64, 1, 1);
        self.m
            .inner
            .dns
            .is_internal_only(gateway, ip.parse().unwrap())
    }
}

pub(super) const VIA: &str = "via 10.64.1.3 to 10.64.1.2 host 10.64.1.1";

#[tokio::test]
async fn a_via_machine_is_kept_to_its_gateway_while_it_runs() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let gw = h.m.create_made(h.request("gw")).await.unwrap();
    h.host.calls();
    let m =
        h.m.create_made(h.request_egress("sbx", "via", Some(&gw.id)))
            .await
            .unwrap();
    assert_eq!(m.egress, egress("via", Some(&gw.id)));
    assert_eq!(h.stored(&m.id).unwrap().egress, m.egress);
    // The TAP and its pin, then the policy, then the boot.
    let tap = netw::tap_name(&m.id);
    assert_eq!(
        h.host.calls(),
        vec![
            format!("ensure_tap {tap} by1 10.64.1.3"),
            format!("set_policy {VIA}"),
            format!("boot {} tap={tap} resume=false", m.id),
            "wait_ready 1001".to_string(),
        ]
    );
    assert!(h.dns_kept("10.64.1.3"));
    assert!(!h.dns_kept("10.64.1.2"), "the gateway machine is open");
    // A stop takes it out right after the pin.
    h.m.stop(&m.id, Duration::from_secs(3), false, None)
        .await
        .unwrap();
    let calls = h.host.calls();
    let at = |line: String| calls.iter().position(|c| *c == line);
    let unpinned = at(format!("delete_tap {tap} 10.64.1.3")).expect("unpinned");
    assert_eq!(
        at(format!("unset_policy {VIA}")),
        Some(unpinned + 1),
        "{calls:?}"
    );
    assert!(!h.dns_kept("10.64.1.3"));
    assert!(h.m.inner.policies.lock().unwrap().is_empty());
    // Every start sets it again.
    h.m.start(&m.id, None).await.unwrap();
    assert!(h.host.calls().contains(&format!("set_policy {VIA}")));
}

#[tokio::test]
async fn a_policy_changes_at_once_on_a_running_machine() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let gw = h.m.create_made(h.request("gw")).await.unwrap();
    let m =
        h.m.create_made(h.request_egress("sbx", "via", Some(&gw.id)))
            .await
            .unwrap();
    h.host.calls();
    let changed =
        h.m.update(&m.id, set_egress("none", None), None)
            .await
            .unwrap();
    assert_eq!(changed.egress, egress("none", None));
    assert_eq!(
        h.host.calls(),
        [format!("swap_policy {VIA} -> none 10.64.1.3")],
        "one call, one transaction"
    );
    assert!(h.dns_kept("10.64.1.3"));
    // The same policy again: nothing to change.
    h.m.update(&m.id, set_egress("none", None), None)
        .await
        .unwrap();
    assert!(h.host.calls().is_empty());
    // Open: nothing in the tables, outside names forwarded again.
    h.m.update(&m.id, set_egress("open", None), None)
        .await
        .unwrap();
    assert_eq!(h.host.calls(), ["unset_policy none 10.64.1.3"]);
    assert!(!h.dns_kept("10.64.1.3"));
    // Stopped: the record changes, the next start applies it.
    h.m.stop(&m.id, Duration::from_secs(3), false, None)
        .await
        .unwrap();
    h.host.calls();
    h.m.update(&m.id, set_egress("none", None), None)
        .await
        .unwrap();
    assert!(h.host.calls().is_empty());
    assert_eq!(h.stored(&m.id).unwrap().egress, egress("none", None));
    h.m.start(&m.id, None).await.unwrap();
    assert!(h
        .host
        .calls()
        .contains(&"set_policy none 10.64.1.3".to_string()));
}

#[tokio::test]
async fn a_via_names_another_machine_of_the_tenant() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    h.tenant("t2");
    let gw = h.m.create_made(h.request("gw")).await.unwrap();
    let other =
        h.m.create_made(api::CreateMachineRequest {
            tenant: "t2".into(),
            ..h.request("other")
        })
        .await
        .unwrap();
    let m = h.m.create_made(h.request("sbx")).await.unwrap();
    h.host.calls();
    h.pool.calls();
    let missing = "m_000000000000";
    for (via, want) in [
        (
            other.id.as_str(),
            format!("egress.via {}: a machine of another tenant", other.id),
        ),
        (missing, format!("egress.via {missing}: no such machine")),
    ] {
        let create =
            h.m.create_made(h.request_egress("sbx2", "via", Some(via)))
                .await;
        assert_eq!(refused(create), want);
        let update = h.m.update(&m.id, set_egress("via", Some(via)), None).await;
        assert_eq!(refused(update), want);
    }
    assert_eq!(
        refused(
            h.m.update(&m.id, set_egress("via", Some(&m.id)), None)
                .await
        ),
        "egress.via names the machine itself"
    );
    assert_eq!(
        refused(h.m.create_made(h.request_egress("sbx2", "via", None)).await),
        "egress.via must name a machine of the tenant"
    );
    // Nothing applied, made or changed.
    assert!(h.host.calls().is_empty());
    let zfs = h.pool.calls();
    assert!(zfs.is_empty(), "{zfs:?}");
    assert!(h.m.list(None, &[]).iter().all(|x| x.name != "sbx2"));
    assert_eq!(h.stored(&m.id).unwrap().egress, api::Egress::default());
    // Its own tenant's machine is a gateway.
    h.m.update(&m.id, set_egress("via", Some(&gw.id)), None)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_gateway_destroyed_under_a_via_machine_leaves_it_reaching_nothing() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let gw = h.m.create_made(h.request("gw")).await.unwrap();
    let m =
        h.m.create_made(h.request_egress("sbx", "via", Some(&gw.id)))
            .await
            .unwrap();
    h.m.destroy(&gw.id, None).await.unwrap();
    // The policy stays, and so does the address it names: a new machine gets another.
    assert_eq!(
        h.m.create_made(h.request("next")).await.unwrap().ip,
        "10.64.1.4"
    );
    h.host.calls();
    // A stop takes out what was set, gateway or not.
    h.m.stop(&m.id, Duration::from_secs(3), false, None)
        .await
        .unwrap();
    assert!(h.host.calls().contains(&format!("unset_policy {VIA}")));
    // A start is refused until the policy names a machine that is there; nothing moves.
    assert_eq!(
        refused(h.m.start(&m.id, None).await),
        format!("egress.via {}: no such machine", gw.id)
    );
    assert!(h.host.calls().is_empty());
    assert_eq!(h.stored(&m.id).unwrap().state, state::STOPPED);
    // Named by no policy, the address is free again.
    assert_eq!(
        h.m.create_made(h.request("last")).await.unwrap().ip,
        "10.64.1.2"
    );
}

#[tokio::test]
async fn the_tables_at_start_hold_the_running_policies() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.tenant("t1");
    let add = |id: &str, st: &str, n: u8, eg: api::Egress| {
        let e = h.add(id, st, 256);
        let mut r = e.rec.lock().unwrap();
        r.name = id.trim_start_matches("m_").into();
        (r.host_num, r.ip, r.egress) = (n, format!("10.64.1.{n}"), eg);
    };
    add("m_gw", state::RUNNING, 2, api::Egress::default());
    add("m_via", state::RUNNING, 3, egress("via", Some("m_gw")));
    add("m_none", state::RUNNING, 4, egress("none", None));
    // Its gateway is gone: no pin, so nothing it sends leaves its TAP.
    add("m_lost", state::RUNNING, 5, egress("via", Some("m_gone")));
    add("m_off", state::STOPPED, 6, egress("none", None));
    let r = h.m.rules().unwrap();
    let pin = |tap: &str, ip: &str| (tap.to_string(), ip.to_string());
    assert_eq!(
        r.pins,
        [
            pin("btgw", "10.64.1.2"),
            pin("btnone", "10.64.1.4"),
            pin("btvia", "10.64.1.3")
        ]
    );
    assert_eq!(
        r.policies,
        [
            nft::Policy::Via {
                ip: "10.64.1.3".into(),
                to: "10.64.1.2".into(),
                host: "10.64.1.1".into()
            },
            nft::Policy::None {
                ip: "10.64.1.4".into()
            }
        ]
    );
    assert!(r
        .render()
        .contains("elements = { 10.64.1.3 . 10.64.1.2, 10.64.1.3 . 10.64.1.1 }"));
    // Every machine's internet traffic is counted, a stopped one's too: its element lives
    // as long as it does.
    assert_eq!(
        r.counted,
        [
            "10.64.1.2",
            "10.64.1.3",
            "10.64.1.4",
            "10.64.1.5",
            "10.64.1.6"
        ]
    );
    // Held as if set: the resolver keeps them in, and a stop takes them out.
    assert!(h.dns_kept("10.64.1.3") && h.dns_kept("10.64.1.4"));
    assert!(!h.dns_kept("10.64.1.5") && !h.dns_kept("10.64.1.6"));
    assert_eq!(h.m.inner.policies.lock().unwrap().len(), 2);
    // None of them is adopted (no process): each is unplugged, policy included.
    h.host.calls();
    h.m.recover().await;
    let calls = h.host.calls();
    assert!(calls.contains(&format!("unset_policy {VIA}")), "{calls:?}");
    assert!(calls.contains(&"unset_policy none 10.64.1.4".to_string()));
    assert!(h.m.inner.policies.lock().unwrap().is_empty());
    assert!(!h.dns_kept("10.64.1.3") && !h.dns_kept("10.64.1.4"));
}

#[tokio::test]
async fn a_refused_swap_keeps_the_old_policy_and_the_record() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let gw = h.m.create_made(h.request("gw")).await.unwrap();
    let m =
        h.m.create_made(h.request_egress("sbx", "via", Some(&gw.id)))
            .await
            .unwrap();
    h.host.calls();
    h.host.refuse_policies.store(true, Relaxed);
    let err =
        h.m.update(&m.id, set_egress("none", None), None)
            .await
            .unwrap_err();
    assert!(matches!(err, MError::Other(_)), "{err:?}");
    // One transaction tried, nothing taken out before it.
    assert_eq!(
        h.host.calls(),
        [format!("swap_policy {VIA} -> none 10.64.1.3")]
    );
    let via = egress("via", Some(&gw.id));
    assert_eq!(h.m.get(&m.id).unwrap().egress, via);
    assert_eq!(h.stored(&m.id).unwrap().egress, via);
    let held = h.m.inner.policies.lock().unwrap().get(&m.id).cloned();
    assert!(
        matches!(held, Some((_, nft::Policy::Via { .. }))),
        "{held:?}"
    );
    assert!(h.dns_kept("10.64.1.3"));
    // Accepted, it lands.
    h.host.refuse_policies.store(false, Relaxed);
    let changed =
        h.m.update(&m.id, set_egress("none", None), None)
            .await
            .unwrap();
    assert_eq!(changed.egress, egress("none", None));
}

// --- disk limits (ADR 0030) ---

pub(in crate::machine) fn disk(bandwidth_mb: u32, iops: u32, burst_sec: u32) -> fc::DiskRate {
    fc::DiskRate {
        bandwidth_mb,
        iops,
        burst_sec,
    }
}

fn set_disk(l: api::DiskLimits) -> api::UpdateMachineRequest {
    api::UpdateMachineRequest {
        disk_limits: Some(l),
        ..Default::default()
    }
}

#[tokio::test]
async fn disks_boot_with_the_host_s_limits_for_the_size_under_the_machine_s_own() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("web")).await.unwrap();
    // The host's default for 1 vCPU, on the root disk only: it has no volume.
    assert_eq!(m.disk_limits, disk(32, 4000, 10).view());
    let disks = |id: &str| h.host.disks.lock().unwrap().get(id).copied();
    assert_eq!(disks(&m.id), Some((disk(32, 4000, 10), false)));
    let mut req = h.request("db");
    req.size.vcpus = 2;
    req.disk_limits = Some(api::DiskLimits {
        iops: Some(500),
        ..Default::default()
    });
    let db = h.m.create_made(req).await.unwrap();
    // Its own value over the host's; the rest scale with its 2 vCPUs.
    assert_eq!(db.disk_limits, disk(64, 500, 10).view());
    assert_eq!(disks(&db.id), Some((disk(64, 500, 10), false)));
    assert_eq!(
        h.stored(&db.id).unwrap().disk_limits,
        api::DiskLimits {
            iops: Some(500),
            ..Default::default()
        },
        "the record keeps its own values, not the host's"
    );
    // A new size is the next boot's, and so are the limits it brings.
    let grown = api::Size {
        vcpus: 4,
        memory_mb: 256,
    };
    let patched =
        h.m.update(&m.id, spec(|s| s.size = Some(grown)), None)
            .await
            .unwrap();
    assert_eq!(patched.disk_limits, disk(32, 4000, 10).view());
    let up = h.m.restart(&m.id, None).await.unwrap();
    assert_eq!(up.disk_limits, disk(128, 16000, 10).view());
    assert_eq!(disks(&m.id), Some((disk(128, 16000, 10), false)));
    // Refused before anything is made, with the field named.
    let mut bad = h.request("bad");
    bad.disk_limits = Some(api::DiskLimits {
        burst_sec: Some(4000),
        ..Default::default()
    });
    assert_eq!(
        refused(h.m.create_made(bad).await),
        "disk_limits.burst_sec: at most 3600"
    );
}

#[tokio::test]
async fn disk_limits_change_at_once_on_a_running_machine_and_at_the_boot_otherwise() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("web")).await.unwrap();
    h.host.calls();
    let disks = |id: &str| h.host.disks.lock().unwrap().get(id).copied();
    let slow = api::DiskLimits {
        bandwidth_mb: Some(2),
        ..Default::default()
    };
    let changed =
        h.m.update(&m.id, set_disk(slow.clone()), None)
            .await
            .unwrap();
    assert_eq!(changed.disk_limits, disk(2, 4000, 10).view());
    assert_eq!(disks(&m.id), Some((disk(2, 4000, 10), false)));
    let pid = h.stored(&m.id).unwrap().pid;
    assert_eq!(h.host.calls(), [format!("disk-rate {pid} 2mb 4000iops")]);
    // A machine with a volume: both disks take it (a unit test has no `mkfs.ext4` to
    // make one, so the record says it has one).
    h.m.entry(&m.id).unwrap().rec.lock().unwrap().volume = Some(api::VolumeSpec {
        size_gb: 1,
        mount: "/data".into(),
    });
    let iops = api::DiskLimits {
        iops: Some(100),
        ..Default::default()
    };
    h.m.update(&m.id, set_disk(iops), None).await.unwrap();
    assert_eq!(disks(&m.id), Some((disk(2, 100, 10), true)));
    h.m.entry(&m.id).unwrap().rec.lock().unwrap().volume = None;
    let back = api::DiskLimits {
        iops: Some(4000),
        ..Default::default()
    };
    let changed = h.m.update(&m.id, set_disk(back), None).await.unwrap();
    h.host.calls();
    let ev = h.events_of(&m.id).pop().unwrap();
    assert_eq!(
        (ev.reason.as_str(), ev.message.as_str()),
        ("updated", "disk_limits changed")
    );
    // The same again changes nothing: no call, no event.
    let version = changed.version;
    let same = h.m.update(&m.id, set_disk(slow), None).await.unwrap();
    assert!(h.host.calls().is_empty());
    assert_eq!(same.version, version);
    // Refused by Firecracker: the disks and the record keep what they had.
    h.host.refuse_disk_rate.store(true, Relaxed);
    let lift = api::DiskLimits {
        bandwidth_mb: Some(0),
        ..Default::default()
    };
    let err = h.m.update(&m.id, set_disk(lift.clone()), None).await;
    assert!(matches!(err, Err(MError::Other(_))), "{err:?}");
    assert_eq!(
        h.m.get(&m.id).unwrap().disk_limits,
        disk(2, 4000, 10).view()
    );
    assert_eq!(h.stored(&m.id).unwrap().disk_limits.bandwidth_mb, Some(2));
    h.host.refuse_disk_rate.store(false, Relaxed);
    // Stopped: only the record, and the next boot is given it.
    h.m.stop(&m.id, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    h.host.calls();
    h.m.update(&m.id, set_disk(lift), None).await.unwrap();
    assert!(!h.host.calls().iter().any(|c| c.starts_with("disk-rate")));
    h.m.start(&m.id, None).await.unwrap();
    assert_eq!(disks(&m.id), Some((disk(0, 4000, 10), false)));
    // Out of bounds: refused, named.
    let bad = api::DiskLimits {
        bandwidth_mb: Some(100_001),
        ..Default::default()
    };
    assert_eq!(
        refused(h.m.update(&m.id, set_disk(bad), None).await),
        "disk_limits.bandwidth_mb: at most 100000"
    );
}

#[tokio::test]
async fn disk_metrics_add_up_per_machine_across_its_boots() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("web")).await.unwrap();
    let io = h.m.entry(&m.id).unwrap().disk_io.clone();
    let line = |w: u64, t: u64| {
        json!({"block": {"write_bytes": w, "rate_limiter_throttled_events": t}}).to_string()
    };
    io.add(&line(1 << 20, 3));
    h.m.restart(&m.id, None).await.unwrap();
    // A new process starts its counters at zero; the machine's go on.
    io.add(&line(1 << 20, 4));
    let text = h.m.metrics();
    briqyard_api::metrics::check_exposition(&text);
    let l = format!(r#"machine="{}",tenant="t1",name="web""#, m.id);
    for want in [
        format!("briqyard_machine_disk_write_bytes_total{{{l}}} 2097152"),
        format!("briqyard_machine_disk_throttled_total{{{l}}} 7"),
        format!("briqyard_machine_disk_read_bytes_total{{{l}}} 0"),
    ] {
        assert!(text.lines().any(|x| x == want), "{want}\n{text}");
    }
}

// --- egress limits (ADR 0018) ---

/// The host's limits in these tests: port 25, 600 connections a minute, no cap.
fn host_limits() -> crate::config::EgressLimits {
    crate::config::EgressLimits {
        blocked_ports: vec![25],
        new_connections_per_minute: 600,
        bandwidth_mbit: 0,
    }
}

fn set_limits(l: api::EgressLimits) -> api::UpdateMachineRequest {
    api::UpdateMachineRequest {
        limits: Some(l),
        ..Default::default()
    }
}

fn view_limits(ports: &[u16], conn: u32, mbit: u32) -> api::EgressLimits {
    api::EgressLimits {
        blocked_ports: Some(ports.to_vec()),
        new_connections_per_minute: Some(conn),
        bandwidth_mbit: Some(mbit),
    }
}

#[tokio::test]
async fn an_open_machine_runs_with_the_host_s_limits_under_its_own() {
    let h = harness_with("10.64.0.0/22", 4096, host_limits()).await;
    h.ready().await;
    let m =
        h.m.create_made(api::CreateMachineRequest {
            limits: Some(api::EgressLimits {
                bandwidth_mbit: Some(100),
                ..Default::default()
            }),
            ..h.request("web")
        })
        .await
        .unwrap();
    // Its own field over the host's two; shown whole, stored as it was asked.
    assert_eq!(m.limits, view_limits(&[25], 600, 100));
    assert_eq!(h.stored(&m.id).unwrap().limits.bandwidth_mbit, Some(100));
    assert_eq!(h.stored(&m.id).unwrap().limits.blocked_ports, None);
    // Set where the policy is: after the pin, before the boot. The resolver forwards
    // outside names as for any open machine.
    let (tap, open) = (
        netw::tap_name(&m.id),
        "open 10.64.1.2 ports [25] conn 600 mbit 100",
    );
    assert_eq!(
        h.host.calls(),
        vec![
            format!("ensure_tap {tap} by1 10.64.1.2"),
            format!("set_policy {open}"),
            format!("boot {} tap={tap} resume=false", m.id),
            "wait_ready 1000".to_string(),
        ]
    );
    assert!(!h.dns_kept("10.64.1.2"));
    // A stop withdraws them right after the pin, a start sets them again.
    h.m.stop(&m.id, Duration::from_secs(3), false, None)
        .await
        .unwrap();
    let calls = h.host.calls();
    let at = |line: String| calls.iter().position(|c| *c == line);
    let unpinned = at(format!("delete_tap {tap} 10.64.1.2")).expect("unpinned");
    assert_eq!(
        at(format!("unset_policy {open}")),
        Some(unpinned + 1),
        "{calls:?}"
    );
    assert!(h.m.inner.policies.lock().unwrap().is_empty());
    h.m.start(&m.id, None).await.unwrap();
    assert!(h.host.calls().contains(&format!("set_policy {open}")));
    // A destroy withdraws them too, and the drop counters with the others.
    h.m.destroy(&m.id, None).await.unwrap();
    assert!(h.host.calls().contains(&format!("unset_policy {open}")));
    assert!(h.m.inner.policies.lock().unwrap().is_empty());
    assert!(!h.host.counted.lock().unwrap().contains_key("10.64.1.2"));
}

#[tokio::test]
async fn limits_change_at_once_on_a_running_machine() {
    let h = harness_with("10.64.0.0/22", 4096, host_limits()).await;
    h.ready().await;
    let m = h.m.create_made(h.request("web")).await.unwrap();
    assert_eq!(m.limits, view_limits(&[25], 600, 0));
    h.host.calls();
    // The fields it names, in one transaction; the others stay.
    let lift = api::EgressLimits {
        new_connections_per_minute: Some(0),
        ..Default::default()
    };
    let changed = h.m.update(&m.id, set_limits(lift), None).await.unwrap();
    assert_eq!(changed.limits, view_limits(&[25], 0, 0));
    assert_eq!(
        h.host.calls(),
        ["swap_policy open 10.64.1.2 ports [25] conn 600 mbit 0 -> open 10.64.1.2 ports [25] conn 0 mbit 0"]
    );
    let ports = api::EgressLimits {
        blocked_ports: Some(vec![465, 25]),
        bandwidth_mbit: Some(2),
        ..Default::default()
    };
    let changed = h.m.update(&m.id, set_limits(ports), None).await.unwrap();
    assert_eq!(changed.limits, view_limits(&[25, 465], 0, 2));
    assert_eq!(
        h.stored(&m.id).unwrap().limits,
        api::EgressLimits {
            blocked_ports: Some(vec![465, 25]),
            new_connections_per_minute: Some(0),
            bandwidth_mbit: Some(2),
        }
    );
    h.host.calls();
    // The same again: nothing to change.
    let same = api::EgressLimits {
        bandwidth_mbit: Some(2),
        ..Default::default()
    };
    h.m.update(&m.id, set_limits(same), None).await.unwrap();
    assert!(h.host.calls().is_empty());
    // Nothing left to limit: nothing in the tables.
    let none = view_limits(&[], 0, 0);
    h.m.update(&m.id, set_limits(none), None).await.unwrap();
    assert_eq!(
        h.host.calls(),
        ["unset_policy open 10.64.1.2 ports [25, 465] conn 0 mbit 2"]
    );
    assert!(h.m.inner.policies.lock().unwrap().is_empty());
    // Refused: named, nothing applied or stored.
    let bad = api::EgressLimits {
        blocked_ports: Some(vec![0]),
        ..Default::default()
    };
    assert_eq!(
        refused(h.m.update(&m.id, set_limits(bad.clone()), None).await),
        "limits.blocked_ports: 0 is not a port"
    );
    assert_eq!(
        refused(
            h.m.create_made(api::CreateMachineRequest {
                limits: Some(bad),
                ..h.request("web2")
            })
            .await
        ),
        "limits.blocked_ports: 0 is not a port"
    );
    assert!(h.host.calls().is_empty());
    assert_eq!(h.stored(&m.id).unwrap().limits.blocked_ports, Some(vec![]));
    // Stopped: the record changes, the next start applies it.
    h.m.stop(&m.id, Duration::from_secs(3), false, None)
        .await
        .unwrap();
    h.host.calls();
    let conn = api::EgressLimits {
        new_connections_per_minute: Some(6),
        ..Default::default()
    };
    assert_eq!(
        h.m.update(&m.id, set_limits(conn), None)
            .await
            .unwrap()
            .limits,
        view_limits(&[], 6, 0)
    );
    assert!(h.host.calls().is_empty());
    h.m.start(&m.id, None).await.unwrap();
    assert!(h
        .host
        .calls()
        .contains(&"set_policy open 10.64.1.2 ports [] conn 6 mbit 0".to_string()));
}

#[tokio::test]
async fn via_and_none_machines_get_no_limits() {
    let h = harness_with("10.64.0.0/22", 4096, host_limits()).await;
    h.ready().await;
    let gw = h.m.create_made(h.request("gw")).await.unwrap();
    h.host.calls();
    // They never reach the NAT: their policy is the one they would have without limits.
    let m =
        h.m.create_made(h.request_egress("sbx", "via", Some(&gw.id)))
            .await
            .unwrap();
    assert!(h.host.calls().contains(&format!("set_policy {VIA}")));
    let n =
        h.m.create_made(h.request_egress("off", "none", None))
            .await
            .unwrap();
    assert!(h
        .host
        .calls()
        .contains(&"set_policy none 10.64.1.4".to_string()));
    // The limits are shown and stored all the same, ready for an open policy.
    assert_eq!(n.limits, view_limits(&[25], 600, 0));
    let own = api::EgressLimits {
        bandwidth_mbit: Some(10),
        ..Default::default()
    };
    h.m.update(&m.id, set_limits(own), None).await.unwrap();
    assert!(h.host.calls().is_empty(), "nothing to change in the tables");
    // Open: the policy becomes its limits, in one transaction, and the resolver lets
    // it go once the tables have changed.
    assert!(h.dns_kept("10.64.1.3"));
    h.m.update(&m.id, set_egress("open", None), None)
        .await
        .unwrap();
    assert_eq!(
        h.host.calls(),
        [format!(
            "swap_policy {VIA} -> open 10.64.1.3 ports [25] conn 600 mbit 10"
        )]
    );
    assert!(!h.dns_kept("10.64.1.3"));
    // And back: the resolver takes it in before.
    h.m.update(&m.id, set_egress("none", None), None)
        .await
        .unwrap();
    assert_eq!(
        h.host.calls(),
        ["swap_policy open 10.64.1.3 ports [25] conn 600 mbit 10 -> none 10.64.1.3"]
    );
    assert!(h.dns_kept("10.64.1.3"));
    // Refused, a swap to open keeps the machine in the resolver with its old policy.
    h.host.refuse_policies.store(true, Relaxed);
    assert!(h
        .m
        .update(&m.id, set_egress("open", None), None)
        .await
        .is_err());
    assert!(h.dns_kept("10.64.1.3"));
    // Refused, a swap from open takes nothing into the resolver.
    h.host.refuse_policies.store(false, Relaxed);
    h.m.update(&gw.id, set_limits(view_limits(&[25], 600, 1)), None)
        .await
        .unwrap();
    h.host.refuse_policies.store(true, Relaxed);
    assert!(h
        .m
        .update(&gw.id, set_egress("none", None), None)
        .await
        .is_err());
    assert!(!h.dns_kept("10.64.1.2"));
}

#[tokio::test]
async fn the_tables_at_start_hold_the_running_machines_limits() {
    let h = harness_with("10.64.0.0/22", 4096, host_limits()).await;
    h.tenant("t1");
    let add = |id: &str, st: &str, n: u8, eg: api::Egress, own: api::EgressLimits| {
        let e = h.add(id, st, 256);
        let mut r = e.rec.lock().unwrap();
        r.name = id.trim_start_matches("m_").into();
        (r.host_num, r.ip, r.egress, r.limits) = (n, format!("10.64.1.{n}"), eg, own);
    };
    let own = api::EgressLimits {
        new_connections_per_minute: Some(6),
        ..Default::default()
    };
    add(
        "m_web",
        state::RUNNING,
        2,
        api::Egress::default(),
        own.clone(),
    );
    add(
        "m_free",
        state::RUNNING,
        3,
        api::Egress::default(),
        view_limits(&[], 0, 0),
    );
    add(
        "m_none",
        state::RUNNING,
        4,
        egress("none", None),
        own.clone(),
    );
    add("m_off", state::STOPPED, 5, api::Egress::default(), own);
    let r = h.m.rules().unwrap();
    // The running open machine with something to limit, merged; the one with nothing
    // has no policy; `none` has its own; a stopped machine has nothing.
    assert_eq!(
        r.policies,
        [
            nft::Policy::Open {
                ip: "10.64.1.2".into(),
                limits: crate::config::EgressLimits {
                    new_connections_per_minute: 6,
                    ..host_limits()
                }
            },
            nft::Policy::None {
                ip: "10.64.1.4".into()
            }
        ]
    );
    assert!(r
        .render()
        .contains("\tlimit conn_10_64_1_2 {\n\t\trate over 6/minute burst 6 packets\n\t}\n"));
    // Held as if set, and only `none` in the resolver.
    assert_eq!(h.m.inner.policies.lock().unwrap().len(), 2);
    assert!(!h.dns_kept("10.64.1.2") && h.dns_kept("10.64.1.4"));
}

#[tokio::test]
async fn drops_land_in_the_view_and_the_usage() {
    let h = harness("10.64.0.0/22", 4096).await;
    let e = h.metered("m_a", state::RUNNING, "2026-10-20T14:00:00Z");
    h.m.inner.net.count("10.64.1.2").await.unwrap();
    h.host.dropped("10.64.1.2", 2, 5, 0);
    h.m.measure(at("2026-10-20T14:00:15Z")).await;
    h.host.dropped("10.64.1.2", 1, 0, 10);
    h.m.measure(at("2026-10-20T14:00:30Z")).await;
    let u = h.bucket("m_a", "2026-10-20T14:00:00Z").await;
    assert_eq!(u.usage.egress_dropped_packets, 18);
    assert_eq!(
        h.m.get("m_a").unwrap().egress_drops,
        api::EgressDrops {
            blocked_port: 3,
            rate: 5,
            bandwidth: 10
        }
    );
    // Since the machine started: a boot counts the view from none, not the usage.
    e.meter.lock().unwrap().boot(0);
    h.host.dropped("10.64.1.2", 1, 0, 0);
    h.m.measure(at("2026-10-20T14:00:45Z")).await;
    assert_eq!(h.m.get("m_a").unwrap().egress_drops.total(), 1);
    let u = h.bucket("m_a", "2026-10-20T14:00:00Z").await;
    assert_eq!(u.usage.egress_dropped_packets, 19);
}

#[tokio::test(start_paused = true)]
async fn a_patch_waiting_on_a_destroy_finds_nothing() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("web")).await.unwrap();
    // The guest takes a while to stop: the destroy holds the lock meanwhile.
    h.host.stops_take(Duration::from_secs(3));
    let d = h.m.clone();
    let id = m.id.clone();
    let destroy = tokio::spawn(async move { d.destroy(&id, None).await });
    while h.m.get(&m.id).unwrap().state != state::DESTROYING {
        tokio::task::yield_now().await;
    }
    let set = api::UpdateMachineRequest {
        sleep: Some("3h".into()),
        ..Default::default()
    };
    let patched = h.m.update(&m.id, set, None).await;
    destroy.await.unwrap().unwrap();
    assert!(matches!(patched, Err(MError::NotFound)), "{patched:?}");
    assert!(h.stored(&m.id).is_none(), "the record is not written back");
    assert!(matches!(h.m.get(&m.id), Err(MError::NotFound)));
}
