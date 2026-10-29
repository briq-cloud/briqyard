//! Tests of the pure functions and the record's own rules.

use super::super::exec::parse_log_line;
use super::super::shutdown::{restart_delay, restarts_after_exit};
use super::super::start::{boot_args, config_drive, jail_uid, write_drive};
use super::*;

#[test]
fn log_lines() {
    let l = parse_log_line("2026-10-18T22:00:00.123456Z hello world\n");
    assert_eq!(l.line, "hello world");
    assert_eq!(l.ts.timestamp(), 1_792_360_800);
    assert_eq!(parse_log_line("no timestamp\n").line, "no timestamp");
}

#[test]
fn port_ranges() {
    assert_eq!(port_range("20000-29999").unwrap(), (20000, 29999));
    assert!(port_range("29999-20000").is_err());
    assert!(port_range("x").is_err());
    assert!(port_range("0-10").is_err());
}

#[test]
fn endpoint_ports() {
    assert_eq!(free_tcp_port("20000-29999", vec![]).unwrap(), 20000);
    assert_eq!(
        free_tcp_port("20000-29999", vec![20001, 20000, 20003]).unwrap(),
        20002
    );
    // A port outside the range (a stale record) does not get in the way.
    assert_eq!(
        free_tcp_port("20000-29999", vec![80, 30000]).unwrap(),
        20000
    );
    match free_tcp_port("20000-20001", vec![20000, 20001]) {
        Err(MError::Capacity(msg)) => assert_eq!(msg, "no tcp endpoint port left"),
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        free_tcp_port("nonsense", vec![]),
        Err(MError::Invalid(_))
    ));
}

pub(in crate::machine) fn policy(policy: &str, max_retries: u32) -> api::RestartPolicy {
    api::RestartPolicy {
        policy: policy.into(),
        max_retries,
    }
}

#[test]
fn restart_decisions() {
    // on-failure: a failure restarts until the retries run out; a clean exit never.
    let p = policy("on-failure", 3);
    assert!(restarts_after_exit(&p, true, 0));
    assert!(restarts_after_exit(&p, true, 2));
    assert!(!restarts_after_exit(&p, true, 3));
    assert!(!restarts_after_exit(&p, false, 0));
    assert!(!restarts_after_exit(&policy("on-failure", 0), true, 0));
    // always: every time, whatever the code and however many times before.
    let p = policy("always", 0);
    assert!(restarts_after_exit(&p, false, 0));
    assert!(restarts_after_exit(&p, true, 1000));
    // no: never.
    assert!(!restarts_after_exit(&policy("no", 3), true, 0));
    // The default policy is on-failure with three retries.
    let d = api::RestartPolicy::default();
    assert!(restarts_after_exit(&d, true, 2));
    assert!(!restarts_after_exit(&d, true, 3));
}

#[test]
fn the_backoff_doubles_to_five_minutes() {
    let secs: Vec<u64> = (1..=9).map(|n| restart_delay(n).as_secs()).collect();
    assert_eq!(secs, [10, 20, 40, 80, 160, 300, 300, 300, 300]);
    // Past any count: the cap, never an overflow.
    assert_eq!(restart_delay(u32::MAX), Duration::from_secs(300));
    assert_eq!(restart_delay(0), Duration::from_secs(10));
}

#[test]
fn sleep_deadlines() {
    let t = Utc.with_ymd_and_hms(2026, 10, 18, 22, 0, 0).unwrap();
    let w = Some(Duration::from_secs(30 * 60));
    assert_eq!(
        sleeps_at(Some(t), w),
        Some(t + chrono::Duration::minutes(30))
    );
    // Never used, or never sleeps: no deadline.
    assert_eq!(sleeps_at(None, w), None);
    assert_eq!(sleeps_at(Some(t), None), None);
    // A window past every date never comes, and does not panic the view.
    let huge = api::parse_sleep("99999999d").unwrap();
    assert_eq!(sleeps_at(Some(t), huge), None);
    assert!(!idle_past(
        Some(t),
        huge,
        t + chrono::Duration::days(365 * 1000)
    ));

    let secs = |n: i64| t + chrono::Duration::seconds(n);
    assert!(!idle_past(Some(t), w, secs(0)));
    assert!(!idle_past(Some(t), w, secs(30 * 60)));
    assert!(idle_past(Some(t), w, secs(30 * 60 + 1)));
    assert!(!idle_past(None, w, secs(3600)));
    assert!(!idle_past(Some(t), None, secs(3600)));
    // A last use in the future (the clock went backwards) is not idle.
    assert!(!idle_past(Some(t), w, secs(-3600)));
}

#[test]
fn a_record_knows_its_sleep_window() {
    let mut r = record();
    assert_eq!(r.sleep_window(), Some(Duration::from_secs(1800)));
    r.sleep = String::new();
    assert_eq!(r.sleep_window(), None);
    r.sleep = "never".into();
    assert_eq!(r.sleep_window(), None);
    r.sleep = "3h".into();
    assert_eq!(r.sleep_window(), Some(Duration::from_secs(3 * 3600)));
    // A value that does not parse reads as never: the API refused it at the edge.
    r.sleep = "soon".into();
    assert_eq!(r.sleep_window(), None);
}

#[test]
fn jail_uids() {
    assert_eq!(jail_uid(100_000, 0, 2), 100_002);
    assert_eq!(jail_uid(100_000, 3, 254), 100_000 + 3 * 256 + 254);
    // Two machines differ in subnet or host number, never share a uid.
    assert_ne!(jail_uid(100_000, 0, 255), jail_uid(100_000, 1, 0));
}

#[test]
fn kernel_command_line() {
    let a = boot_args(false, "");
    assert!(
        a.starts_with("console=ttyS0 reboot=k panic=1 root=/dev/vda rw"),
        "{a}"
    );
    assert!(a.contains(&format!("init={}", image::INIT_PATH)), "{a}");
    assert!(a.contains(" rootfstype=ext4 rootflags=discard "), "{a}");
    assert!(a.ends_with(" pci=off"), "{a}");
    let b = boot_args(true, "loglevel=3 quiet");
    assert!(!b.contains("pci=off"), "{b}");
    assert!(b.ends_with(" loglevel=3 quiet"), "{b}");
}

#[test]
fn host_facts() {
    let meminfo = "MemTotal:       16318192 kB\nMemFree:         1234 kB\n";
    assert_eq!(meminfo_total_mb(meminfo), Some(15935));
    assert_eq!(meminfo_total_mb("MemFree: 1 kB\n"), None);
    assert_eq!(meminfo_total_mb(""), None);
    // 64 GB, the ARC capped at 6 GB: 56 GB for machines; no cap, 2 GB kept only.
    assert_eq!(default_memory_mb(65536, 2048, 6144), 57344);
    assert_eq!(default_memory_mb(65536, 2048, 0), 63488);
    assert_eq!(
        default_memory_mb(65536, 3072, 6144),
        56320,
        "an edge beside it"
    );
    assert_eq!(default_memory_mb(3072, 2048, 1024), 1024, "at least 1 GB");
    assert_eq!(default_vcpus(16, 0), 64);
    assert_eq!(default_vcpus(16, 2), 56);
    assert_eq!(default_vcpus(2, 4), 4, "at least one thread's");

    let addr = "2: eth0    inet 192.168.64.3/24 brd 192.168.64.255 scope global dynamic eth0\\       valid_lft 86000sec preferred_lft 86000sec\n";
    assert_eq!(inet_of(addr), Some(Ipv4Addr::new(192, 168, 64, 3)));
    assert_eq!(inet_of(""), None);
    assert_eq!(inet_of("2: eth0 inet6 fe80::1/64 scope link\n"), None);
}

#[test]
fn wait_decisions() {
    let m = |state: &str, reason: &str, restarting: bool| api::Machine {
        state: state.into(),
        stopped_reason: reason.into(),
        error: "why".into(),
        exit: Some(api::Exit {
            code: 1,
            oom_killed: false,
            at: Utc::now(),
            restarting,
        }),
        ..Default::default()
    };
    assert_eq!(will_run(&m(state::RUNNING, "", false)), Some(Ok(())));
    assert_eq!(
        will_run(&m(state::ERROR, "", false)),
        Some(Err("why".into()))
    );
    assert_eq!(
        will_run(&m(state::DESTROYING, "", false)),
        Some(Err("destroying".into()))
    );
    assert_eq!(
        will_run(&m(state::STOPPED, stop::USER, false)),
        Some(Err("stopped (user)".into()))
    );
    assert_eq!(
        will_run(&m(state::STOPPED, stop::EXIT, false)),
        Some(Err("stopped (exit)".into()))
    );
    // A process that exited and is being restarted will run: keep waiting.
    assert_eq!(will_run(&m(state::STOPPED, stop::EXIT, true)), None);
    assert_eq!(will_run(&m(state::STARTING, "", false)), None);
    assert_eq!(will_run(&m(state::STOPPING, "", false)), None);
}

#[test]
fn wait_for_ready_decisions() {
    let m = |state: &str, ready: bool| api::Machine {
        id: "m_1".into(),
        state: state.into(),
        ready,
        error: "why".into(),
        ..Default::default()
    };
    let verdict = |m: &api::Machine, until| match wait_verdict(m, until) {
        None => "wait".to_string(),
        Some(Ok(())) => "ok".to_string(),
        Some(Err(MError::BootFailed(_))) => "boot_failed".to_string(),
        Some(Err(MError::NotRunning(why))) => format!("not_running: {why}"),
        Some(Err(other)) => format!("{other:?}"),
    };
    // Running is enough for `running`; `ready` waits for the probes.
    assert_eq!(verdict(&m(state::RUNNING, false), Until::Running), "ok");
    assert_eq!(verdict(&m(state::RUNNING, false), Until::Ready), "wait");
    assert_eq!(verdict(&m(state::RUNNING, true), Until::Ready), "ok");
    // In `error`, a wait for ready answers as the boot did; for running, as before.
    assert_eq!(
        verdict(&m(state::ERROR, false), Until::Ready),
        "boot_failed"
    );
    assert_eq!(
        verdict(&m(state::ERROR, false), Until::Running),
        "not_running: why"
    );
    assert_eq!(verdict(&m(state::STARTING, false), Until::Ready), "wait");
    assert_eq!(
        verdict(&m(state::DESTROYING, false), Until::Ready),
        "not_running: destroying"
    );
    // Why it is not ready: the probes that have not passed, else that none has run.
    let mut r = m(state::RUNNING, false);
    assert_eq!(not_ready_why(&r), "its probes have not passed yet");
    let st = |passed, message: &str| api::ProbeStatus {
        passed,
        message: message.into(),
        failures: 1,
        at: Utc::now(),
    };
    r.probes_status.startup = Some(st(true, "exit 0"));
    r.probes_status.readiness = Some(st(false, "HTTP 503"));
    assert_eq!(not_ready_why(&r), "readiness: HTTP 503");
}

#[test]
fn records_from_before_are_migrated() {
    let mut r = record();
    r.sleep = String::new();
    r.state_changed_at = DateTime::<Utc>::default();
    r.root_key.clear();
    r.migrate();
    assert_eq!(r.sleep, "never");
    assert_eq!(r.state_changed_at, r.updated_at);
    assert_eq!(
        r.root_key, r.image_key,
        "the root disk was made from its image"
    );
    // A current record is left alone.
    let mut r = record();
    r.state_changed_at = r.updated_at + chrono::Duration::seconds(5);
    r.root_key = "older".into();
    let before = r.clone();
    r.migrate();
    assert_eq!(r.sleep, before.sleep);
    assert_eq!(r.state_changed_at, before.state_changed_at);
    assert_eq!(r.root_key, "older");
    // One representation of "never", whatever the API was sent.
    assert_eq!(sleep_setting(""), "never");
    assert_eq!(sleep_setting("  "), "never");
    assert_eq!(sleep_setting("never"), "never");
    assert_eq!(sleep_setting(" 30m "), "30m");
}

#[test]
fn the_advertised_address() {
    let ip = Some(Ipv4Addr::new(192, 168, 64, 3));
    assert_eq!(advertise_address("10.0.0.5", "0.0.0.0", ip), "10.0.0.5");
    assert_eq!(advertise_address("", "10.0.0.5", ip), "10.0.0.5");
    assert_eq!(advertise_address("", "0.0.0.0", ip), "192.168.64.3");
    assert_eq!(advertise_address("", "", ip), "192.168.64.3");
    assert_eq!(advertise_address("", "0.0.0.0", None), "0.0.0.0");
}

/// Reads the drive back: every entry's path, mode and content.
pub(in crate::machine) fn entries(drive: &[u8]) -> Vec<(String, u32, Vec<u8>)> {
    use std::io::Read;
    let mut a = tar::Archive::new(drive);
    a.entries()
        .unwrap()
        .map(|e| {
            let mut e = e.unwrap();
            let path = e.path().unwrap().to_string_lossy().into_owned();
            let mode = e.header().mode().unwrap();
            let mut data = Vec::new();
            e.read_to_end(&mut data).unwrap();
            (path, mode, data)
        })
        .collect()
}

#[test]
fn config_drive_carries_the_guest_config() {
    let r = record();
    let gw = Ipv4Addr::new(10, 64, 1, 1);
    let drive = config_drive(&r, gw).unwrap();
    assert_eq!(drive.len() % 512, 0, "{}", drive.len());
    let es = entries(&drive);
    assert_eq!(es.len(), 1);
    let (path, mode, data) = &es[0];
    assert_eq!(path, guest::CONFIG_NAME);
    assert_eq!(*mode, 0o600);
    let cfg: guest::Config = serde_json::from_slice(data).unwrap();
    assert_eq!(cfg.hostname, "db");
    assert_eq!(cfg.ip, "10.64.1.2/24");
    assert_eq!(cfg.gateway, "10.64.1.1");
    assert_eq!(cfg.dns, vec!["10.64.1.1"]);
    assert_eq!(cfg.hosts["db.internal"], "10.64.1.2");
    assert_eq!(cfg.hosts["m_abc123.vm.internal"], "10.64.1.2");
    // The image's entrypoint and cmd, since the machine gives neither.
    assert_eq!(cfg.entrypoint, vec!["docker-entrypoint.sh"]);
    assert_eq!(cfg.cmd, vec!["postgres"]);
    // The machine's env over the image's.
    assert_eq!(cfg.env["PATH"], "/usr/bin");
    assert_eq!(cfg.env["PGDATA"], "/data/pg");
    assert_eq!(cfg.workdir, "/");
    assert_eq!(cfg.user, "postgres");
    assert_eq!(cfg.mounts.len(), 1);
    assert_eq!(cfg.mounts[0].device, "/dev/vdc");
    assert_eq!(cfg.mounts[0].path, "/data");
    assert_eq!(cfg.mounts[0].fstype, "ext4");
    assert!(cfg.files.is_empty());
    assert_eq!(cfg.stop_timeout_sec, 10);

    // No volume: no mount.
    let mut r = record();
    r.volume = None;
    let cfg: guest::Config =
        serde_json::from_slice(&entries(&config_drive(&r, gw).unwrap())[0].2).unwrap();
    assert!(cfg.mounts.is_empty());
}

#[test]
fn config_drive_follows_docker_for_entrypoint_and_cmd() {
    let gw = Ipv4Addr::new(10, 64, 1, 1);
    let cfg_of = |r: &Record| -> guest::Config {
        serde_json::from_slice(&entries(&config_drive(r, gw).unwrap())[0].2).unwrap()
    };
    // A cmd alone keeps the image's entrypoint.
    let mut r = record();
    r.cmd = Some(vec![
        "postgres".into(),
        "-c".into(),
        "log_min_messages=debug".into(),
    ]);
    let c = cfg_of(&r);
    assert_eq!(c.entrypoint, vec!["docker-entrypoint.sh"]);
    assert_eq!(c.cmd, vec!["postgres", "-c", "log_min_messages=debug"]);
    // An entrypoint alone replaces the image's and drops its cmd.
    let mut r = record();
    r.entrypoint = Some(vec!["/bin/sh".into()]);
    let c = cfg_of(&r);
    assert_eq!(c.entrypoint, vec!["/bin/sh"]);
    assert!(c.cmd.is_empty());
    // Both given: both used.
    let mut r = record();
    r.entrypoint = Some(vec!["/bin/sh".into()]);
    r.cmd = Some(vec!["-c".into(), "true".into()]);
    let c = cfg_of(&r);
    assert_eq!(c.entrypoint, vec!["/bin/sh"]);
    assert_eq!(c.cmd, vec!["-c", "true"]);
}

#[test]
fn config_drive_carries_the_boot_files() {
    let gw = Ipv4Addr::new(10, 64, 1, 1);
    let mut r = record();
    r.files = vec![
        api::File {
            path: "/etc/app/app.conf".into(),
            base64: guest::base64_encode(b"k=v\n"),
            mode: None,
        },
        api::File {
            path: "/usr/local/bin/run".into(),
            base64: guest::base64_encode(b"#!/bin/sh\n"),
            mode: Some("0755".into()),
        },
        api::File {
            path: "/empty".into(),
            base64: String::new(),
            mode: Some(String::new()),
        },
    ];
    let drive = config_drive(&r, gw).unwrap();
    assert_eq!(drive.len() % 512, 0);
    let es = entries(&drive);
    assert_eq!(es.len(), 4);
    let cfg: guest::Config = serde_json::from_slice(&es[0].2).unwrap();
    assert_eq!(cfg.files.len(), 3);
    assert_eq!(
        (cfg.files[0].path.as_str(), cfg.files[0].mode),
        ("/etc/app/app.conf", 0o644)
    );
    assert_eq!(
        (cfg.files[1].path.as_str(), cfg.files[1].mode),
        ("/usr/local/bin/run", 0o755)
    );
    assert_eq!(
        (cfg.files[2].path.as_str(), cfg.files[2].mode),
        ("/empty", 0o644)
    );
    // Under files/, by guest path without the leading slash.
    assert_eq!(es[1].0, "files/etc/app/app.conf");
    assert_eq!(es[1].1, 0o644);
    assert_eq!(es[1].2, b"k=v\n");
    assert_eq!(es[2].0, "files/usr/local/bin/run");
    assert_eq!(es[2].1, 0o755);
    assert_eq!(es[2].2, b"#!/bin/sh\n");
    assert_eq!(es[3].0, "files/empty");
    assert!(es[3].2.is_empty());
}

#[test]
fn config_drive_refuses_a_bad_file() {
    let gw = Ipv4Addr::new(10, 64, 1, 1);
    let mut r = record();
    r.files = vec![api::File {
        path: "/x".into(),
        base64: "not base64!".into(),
        mode: None,
    }];
    let err = config_drive(&r, gw).unwrap_err();
    assert!(err.to_string().starts_with("file /x: "), "{err}");

    r.files = vec![api::File {
        path: "/x".into(),
        base64: guest::base64_encode(b"ok"),
        mode: Some("rw-r--r--".into()),
    }];
    let err = config_drive(&r, gw).unwrap_err();
    assert_eq!(err.to_string(), "file /x: mode \"rw-r--r--\"");
}

#[test]
fn a_drive_is_written_whole_then_renamed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.tar");
    let data = config_drive(&record(), Ipv4Addr::new(10, 64, 1, 1)).unwrap();
    write_drive(&path, &data).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), data);
    assert!(!path.with_extension("tar.tmp").exists());
    // A second write replaces the first.
    write_drive(&path, b"x").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"x");
    // A directory that does not exist is an error, not a panic.
    assert!(write_drive(&dir.path().join("nope/config.tar"), b"x").is_err());
}

#[test]
fn record_names() {
    let r = record();
    assert_eq!(r.hostname(), "db.internal");
    assert_eq!(r.machine_host(), "m_abc123.vm.internal");
    assert_eq!(r.dataset(), "m/m_abc123");
    assert_eq!(r.root_dataset(), "m/m_abc123/root");
    assert_eq!(r.data_dataset(), "m/m_abc123/data");
}

#[test]
fn ids_have_a_prefix_and_twelve_hex_digits() {
    let id = new_id("m");
    let (p, hex) = id.split_once('_').unwrap();
    assert_eq!(p, "m");
    assert_eq!(hex.len(), 12);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()), "{id}");
    assert_ne!(new_id("m"), new_id("m"));
}
