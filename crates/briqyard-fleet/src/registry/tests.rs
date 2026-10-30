//! The registry's decisions, tested without a network.

use super::*;

fn host(id: &str, cap: u32, used: u32, machines: usize) -> HostRec {
    HostRec {
        id: id.into(),
        url: format!("http://{id}:7420"),
        ssh: String::new(),
        token: String::new(),
        tls_fingerprint: String::new(),
        region: "fsn".into(),
        provider: "static".into(),
        state: "ready".into(),
        capacity: Capacity {
            memory_mb: cap,
            vcpus: 32,
        },
        used: Capacity {
            memory_mb: used,
            vcpus: 0,
        },
        machines,
        namespaces: vec![],
        last_seen: Utc::now(),
        version: "0.1".into(),
        disk_free_mb: 0,
        note: String::new(),
        bootstrap_attempts: 0,
        public_tcp_ports: None,
        conditions: vec![],
        started: Default::default(),
        pool_key: PoolKey::default(),
        labels: Default::default(),
        unknown: Unknown::new(),
        holds: Vec::new(),
    }
}

/// None yet is empty; a file that does not parse is an error, never an empty registry;
/// what this fleet does not know is kept and written back, so a rollback loses nothing.
#[test]
fn a_registry_keeps_what_it_does_not_know_and_refuses_what_does_not_parse() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.json");
    assert!(Registry::load(&path).unwrap().hosts.is_empty());
    let mut reg = Registry::default();
    reg.hosts.insert("h1".into(), host("h1", 1000, 0, 0));
    let (key, made) = reg.pool_key("h1").unwrap();
    assert!(made);
    assert_eq!(reg.pool_key("h1").unwrap(), (key.clone(), false));
    assert_eq!(format!("{key:?}"), "PoolKey(..)", "never printed");
    assert!(!format!("{:?}", reg.hosts["h1"]).contains(key.expose()));
    let mut v = serde_json::to_value(&reg).unwrap();
    v["hosts"]["h1"]["later"] = 1.into();
    v["later_too"] = serde_json::json!({"a": [1]});
    std::fs::write(&path, v.to_string()).unwrap();
    let back = Registry::load(&path).unwrap();
    assert_eq!(back.hosts["h1"].pool_key, key);
    let written = serde_json::to_value(&back).unwrap();
    assert_eq!(
        written["hosts"]["h1"]["later"], 1,
        "written back: {written}"
    );
    assert_eq!(written["later_too"], serde_json::json!({"a": [1]}));
    std::fs::write(&path, "{").unwrap();
    let err = Registry::load(&path).unwrap_err();
    assert!(format!("{err:#}").contains("read the registry"), "{err:#}");
}

/// A condition of the host's, true or not.
fn condition(kind: &str, status: bool) -> Condition {
    Condition {
        kind: kind.into(),
        status,
        since: Utc::now(),
        message: "pool 4.0 GB free of 100.0 (4%), under 10%".into(),
    }
}

#[test]
fn a_host_under_pressure_takes_no_new_namespace() {
    let now = Utc::now();
    let mut reg = Registry::default();
    let mut full = host("a", 100_000, 0, 1);
    full.conditions = vec![
        condition(api::condition::MEMORY_PRESSURE, false),
        condition(api::condition::DISK_PRESSURE, true),
    ];
    reg.heartbeat(full, now);
    reg.heartbeat(host("b", 100_000, 50_000, 5), now);
    let p = Policy::default();
    // The emptiest host is under pressure: the new namespace goes to the other one.
    assert_eq!(placed(&mut reg, "t1", 512, 0).unwrap().0, "b");
    assert_eq!(
        reg.hosts["a"].pressure().as_deref(),
        Some("host a is under disk_pressure: pool 4.0 GB free of 100.0 (4%), under 10%")
    );
    assert_eq!(reg.hosts["b"].pressure(), None);
    // Nor do the capacity signals count its memory as free.
    let (free, largest) = reg.room(&p)["fsn"];
    assert_eq!((free.memory_mb, largest.memory_mb), (49_488, 49_488));
    // The heartbeat that clears it lets it take namespaces again.
    let mut cleared = host("a", 100_000, 0, 1);
    cleared.conditions = vec![condition(api::condition::DISK_PRESSURE, false)];
    reg.heartbeat(cleared, now);
    assert_eq!(reg.place("t2", "", 512, 0, &p).as_deref(), Some("a"));
}

/// A host of `region` with `free` MB of memory and `disk` MB of disk free.
fn roomy(id: &str, region: &str, free: u32, disk: u64) -> HostRec {
    let mut h = host(id, 100_000, 100_000 - free, 1);
    h.region = region.into();
    h.disk_free_mb = disk;
    h
}

#[test]
fn room_counts_the_hosts_that_take_a_new_namespace() {
    let mut reg = Registry::default();
    let mut hosts = vec![
        roomy("a", "gra", 40_000, 500_000),
        roomy("b", "gra", 30_000, 900_000),
        // Its memory is free, it is not placed on: none of it counts.
        roomy("drained", "gra", 90_000, 900_000),
        roomy("down", "gra", 90_000, 900_000),
        roomy("pressed", "gra", 90_000, 900_000),
        roomy("full", "gra", 10_000, 900_000),
        // Reports no disk figure: its memory counts, no disk.
        roomy("v", "vin", 20_000, 0),
        roomy("gone", "sgp", 90_000, 900_000),
    ];
    hosts[2].state = "draining".into();
    hosts[3].state = "down".into();
    hosts[4].conditions = vec![condition(api::condition::DISK_PRESSURE, true)];
    hosts[7].state = "retiring".into();
    for h in hosts {
        reg.hosts.insert(h.id.clone(), h);
    }
    let room = reg.room(&Policy::default());
    let r = |memory_mb, disk_mb| api::Room { memory_mb, disk_mb };
    assert_eq!(room["gra"], (r(70_000, 1_400_000), r(40_000, 900_000)));
    assert_eq!(room["vin"], (r(20_000, 0), r(20_000, 0)));
    assert_eq!(
        room["sgp"],
        (r(0, 0), r(0, 0)),
        "a region whose hosts take nothing is listed, with nothing"
    );
    assert_eq!(room.len(), 3);
}

#[test]
fn a_shortage_names_what_ran_out() {
    let mut reg = Registry::default();
    let mut pressed = roomy("pressed", "gra", 60_000, 900_000);
    pressed.conditions = vec![condition(api::condition::MEMORY_PRESSURE, true)];
    for h in [
        roomy("a", "gra", 40_000, 5_000),
        pressed,
        roomy("v", "vin", 20_000, 0),
    ] {
        reg.hosts.insert(h.id.clone(), h);
    }
    let p = Policy::default();
    let short = |region, mb, disk| reg.shortage(region, mb, disk, &p);
    // No host of gra under its ceiling has 70 GB.
    assert_eq!(short("gra", 70_000, 0), Resource::Memory);
    assert_eq!(short("sgp", 512, 0), Resource::Memory, "no host there");
    // a has the memory, not the disk; pressed has both, under memory pressure: memory.
    assert_eq!(short("gra", 50_000, 10_000), Resource::Memory);
    assert_eq!(short("gra", 30_000, 1_000_000), Resource::Disk);
    // Under disk pressure: disk.
    reg.hosts.get_mut("pressed").unwrap().conditions =
        vec![condition(api::condition::DISK_PRESSURE, true)];
    let short = |region, mb, disk| reg.shortage(region, mb, disk, &p);
    assert_eq!(short("gra", 50_000, 10_000), Resource::Disk);
    // No region asked: every region's hosts, and none has 1 TB.
    assert_eq!(short("", 30_000, 1_000_000), Resource::Disk);
    // What place refuses, shortage names; what it takes, it would not be asked about.
    assert_eq!(reg.place("t1", "gra", 30_000, 10_000, &p), None);
    assert_eq!(
        reg.place("t2", "gra", 30_000, 2_000, &p).as_deref(),
        Some("a")
    );
}

#[test]
fn a_new_namespace_is_placed_in_its_region_and_its_region_is_its_hosts() {
    let now = Utc::now();
    let mut reg = Registry::default();
    let mut gra = host("gra1", 100_000, 50_000, 1);
    gra.region = "gra".into();
    let mut vin = host("vin1", 100_000, 0, 0);
    vin.region = "vin".into();
    reg.heartbeat(gra, now);
    reg.heartbeat(vin.clone(), now);
    let p = Policy::default();
    // vin1 is the emptiest; t1 asks for gra.
    assert_eq!(reg.place("t1", "gra", 512, 0, &p).as_deref(), Some("gra1"));
    assert_eq!(reg.region_of("t1"), Some("gra"));
    assert_eq!(
        reg.place("t2", "", 512, 0, &p).as_deref(),
        Some("vin1"),
        "any"
    );
    assert_eq!(reg.place("t3", "sgp", 512, 0, &p), None, "no host there");
    assert_eq!(
        reg.place("t4", "gra", 60_000, 0, &p),
        None,
        "the region is full, whatever the others have"
    );
    assert_eq!(reg.region_of("t4"), None, "nothing pinned");
    // Pinned, a namespace's machines go to its host whatever is asked: the caller refuses
    // another region.
    assert_eq!(reg.place("t1", "vin", 512, 0, &p).as_deref(), Some("gra1"));
    let h = reg.host_of_namespace("t1").unwrap();
    assert_eq!(h.outside("t1", "gra"), None);
    assert_eq!(h.outside("t1", ""), None, "no region asked");
    assert_eq!(
        h.outside("t1", "vin").as_deref(),
        Some("namespace t1 is in region \"gra\" (host gra1), not \"vin\": a namespace never spans regions")
    );
    // A namespace a heartbeat pins is in its host's region.
    vin.namespaces = vec!["t9".into()];
    reg.heartbeat(vin, now);
    assert_eq!(reg.region_of("t9"), Some("vin"));
}

#[test]
fn a_heartbeat_lands_on_the_record_at_its_address() {
    let now = Utc::now();
    let mut reg = Registry::default();
    let mut added = host("h_srv-9", 0, 0, 0);
    added.url = "http://10.0.0.9:7420".into();
    added.state = "bootstrapped".into();
    added.provider = "manual".into();
    added.token = "t0k".into();
    added.tls_fingerprint = "ab".repeat(32);
    reg.hosts.insert(added.id.clone(), added);
    assert_eq!(
        reg.expecting("http://10.0.0.9:7421/")
            .map(|h| h.id.as_str()),
        Some("h_srv-9"),
        "the address, whatever the port"
    );
    assert_eq!(reg.expecting("http://10.0.0.8:7420").map(|h| &h.id), None);
    // The daemon reports under its own id; the fleet applies it to the record it added.
    let mut hb = host("h_srv-9", 64_000, 0, 0);
    hb.url = "http://10.0.0.9:7420".into();
    hb.token.clear();
    hb.provider.clear();
    reg.heartbeat(hb, now);
    assert_eq!(reg.hosts.len(), 1);
    let h = &reg.hosts["h_srv-9"];
    assert_eq!(
        h.state, "ready",
        "an added host is ready at its first heartbeat"
    );
    assert_eq!(h.provider, "manual", "a heartbeat does not touch it");
    assert_eq!(h.token, "t0k", "nor the token");
    assert_eq!(h.tls_fingerprint, "ab".repeat(32), "nor the pin");
    assert_eq!(h.capacity.memory_mb, 64_000);
    assert_eq!(url_host("http://[::1]:7420/x"), "[::1]");
    assert_eq!(url_host("10.0.0.5"), "10.0.0.5");
}

#[test]
fn a_heartbeat_must_report_the_pinned_certificate() {
    let (a, b) = ("aa".repeat(32), "bb".repeat(32));
    let https = "https://10.0.0.9:7420";
    let http = "http://10.0.0.9:7420";
    assert_eq!(tls_matches(&a, &a, https), Ok(()));
    assert_eq!(tls_matches("", "", http), Ok(()), "a host on plain HTTP");
    let err = tls_matches(&a, &b, https).unwrap_err();
    assert!(
        err.starts_with(&format!("certificate {b} is not the one pinned ({a})")),
        "{err}"
    );
    // No trust on first use: TLS with nothing pinned is refused.
    let err = tls_matches("", &b, https).unwrap_err();
    assert!(err.contains("no fingerprint is pinned"), "{err}");
    let err = tls_matches(&a, "", http).unwrap_err();
    assert!(err.contains("serves plain HTTP"), "{err}");
    // The URL the fleet dials follows the pin.
    assert!(tls_matches(&a, &a, http)
        .unwrap_err()
        .contains("must advertise https://"));
    assert!(tls_matches("", "", https)
        .unwrap_err()
        .contains("must advertise http://"));
}

#[test]
fn a_heartbeat_drops_pins_the_host_no_longer_has() {
    let now = Utc::now();
    let mut reg = Registry::default();
    let mut a = host("a", 1000, 0, 1);
    a.namespaces = vec!["t1".into(), "t2".into()];
    reg.heartbeat(a, now);
    reg.heartbeat(host("b", 1000, 500, 0), now);
    reg.namespaces.insert("tb".into(), "b".into());
    // A placement just pinned t3 to a (the emptier host); a does not list it yet: the pin stays.
    assert_eq!(
        reg.place("t3", "", 10, 0, &Policy::default()).as_deref(),
        Some("a")
    );
    let mut a = host("a", 1000, 0, 1);
    a.namespaces = vec!["t2".into()];
    reg.heartbeat(a.clone(), now);
    assert_eq!(reg.namespaces.get("t1"), None, "t1 left host a");
    assert_eq!(
        reg.namespaces.get("t3").map(String::as_str),
        Some("a"),
        "a fresh pin stays"
    );
    reg.pinned_at
        .insert("t3".into(), now - Duration::minutes(11));
    reg.heartbeat(a, now);
    assert_eq!(
        reg.namespaces.get("t3"),
        None,
        "an old pin the host never confirmed goes"
    );
    assert_eq!(reg.namespaces.get("t2").map(String::as_str), Some("a"));
    assert_eq!(
        reg.namespaces.get("tb").map(String::as_str),
        Some("b"),
        "another host's pin stays"
    );
}

#[test]
fn retire_waits_for_the_host_to_empty() {
    let now = Utc::now();
    let mut reg = Registry::default();
    let mut busy = host("a", 1000, 100, 1);
    busy.namespaces = vec!["t".into()];
    reg.heartbeat(busy, now);
    reg.hosts.get_mut("a").unwrap().state = "retiring".into();
    assert!(reg.retirable().is_empty());
    let mut empty = host("a", 1000, 0, 0);
    empty.namespaces.clear();
    reg.heartbeat(empty, now);
    reg.namespaces.clear();
    assert_eq!(
        reg.hosts["a"].state, "retiring",
        "a heartbeat keeps a retire"
    );
    assert_eq!(reg.retirable().len(), 1);
    // A drained host stays drained, empty or not: only a retire forgets.
    let mut fixed = host("s", 1000, 0, 0);
    fixed.namespaces.clear();
    reg.heartbeat(fixed, now);
    reg.hosts.get_mut("s").unwrap().state = "draining".into();
    assert_eq!(
        reg.retirable()
            .iter()
            .map(|h| h.id.as_str())
            .collect::<Vec<_>>(),
        ["a"]
    );
    assert_eq!(
        reg.place("t2", "", 10, 0, &Policy::default()),
        None,
        "no placement on a retiring host"
    );
    // A drain, an upgrade: kept by a heartbeat, never forgotten, nothing placed.
    for state in ["draining", "upgrading"] {
        reg.hosts.get_mut("a").unwrap().state = state.into();
        reg.heartbeat(host("a", 1000, 0, 0), now);
        assert_eq!(reg.hosts["a"].state, state);
        assert!(reg.retirable().is_empty(), "{state}");
        assert_eq!(
            reg.place("t2", "", 10, 0, &Policy::default()),
            None,
            "{state}"
        );
        assert!(
            reg.listed().iter().any(|h| h.id == "a"),
            "a listing asks a host {state}"
        );
    }
}

#[test]
fn placement_pins_namespaces_and_picks_the_emptiest_host() {
    let now = Utc::now();
    let mut reg = Registry::default();
    reg.heartbeat(host("a", 100_000, 90_000, 10), now);
    reg.heartbeat(host("b", 100_000, 20_000, 2), now);
    reg.heartbeat(host("c", 100_000, 50_000, 5), now);
    let p = Policy::default();
    assert_eq!(reg.place("t1", "", 512, 0, &p).as_deref(), Some("b"));
    assert_eq!(
        reg.place("t1", "", 512, 0, &p).as_deref(),
        Some("b"),
        "a namespace stays where it is"
    );
    // c is next; a is over the ceiling.
    reg.hosts.get_mut("b").unwrap().used.memory_mb = 99_000;
    assert_eq!(reg.place("t2", "", 512, 0, &p).as_deref(), Some("c"));
    assert_eq!(reg.place("t3", "", 60_000, 0, &p), None, "nothing has room");
    reg.hosts.get_mut("c").unwrap().disk_free_mb = 1000;
    assert_eq!(
        reg.place("t4", "", 512, 5000, &p),
        None,
        "c has memory but no disk"
    );
    assert_eq!(reg.place("t5", "", 512, 500, &p).as_deref(), Some("c"));
}

/// `place` and `hold`, as a create does them.
fn placed(reg: &mut Registry, namespace: &str, mb: u32, disk: u64) -> Option<(String, u64)> {
    let host = reg.place(namespace, "", mb, disk, &Policy::default())?;
    let hold = reg.hold(&host, mb, disk);
    Some((host, hold))
}

#[test]
fn a_hold_counts_until_a_report_after_the_create_or_its_failure() {
    let t0 = Utc::now();
    let mut reg = Registry::default();
    reg.heartbeat(host("a", 100_000, 0, 0), t0);
    reg.heartbeat(host("b", 100_000, 10_000, 1), t0);
    let p = Policy::default();
    // A burst: the second namespace sees the first one's memory taken on a.
    let (a, t1) = placed(&mut reg, "t1", 60_000, 3000).unwrap();
    assert_eq!(a, "a");
    assert_eq!(reg.hosts["a"].used.memory_mb, 60_000);
    assert_eq!(placed(&mut reg, "t2", 50_000, 0).unwrap().0, "b");
    // A pinned namespace's machine holds too, memory and disk.
    reg.hosts.get_mut("a").unwrap().disk_free_mb = 10_000;
    let (_, t1b) = placed(&mut reg, "t1", 10_000, 4000).unwrap();
    assert_eq!(reg.hosts["a"].used.memory_mb, 70_000);
    assert_eq!(reg.hosts["a"].disk_free_mb, 6000);
    let (free, largest) = reg.room(&p)["fsn"];
    assert_eq!(
        (free.memory_mb, largest.memory_mb),
        (70_000, 40_000),
        "the capacity signals see the holds too"
    );
    assert_eq!(reg.hold("nobody", 5000, 0), 0, "no host, nothing held");
    // A report while both creates are under way: they still count, on its figures.
    let t2 = t0 + Duration::seconds(15);
    let mut report = host("a", 100_000, 1000, 0);
    report.disk_free_mb = 20_000;
    reg.heartbeat(report, t2);
    assert_eq!(reg.hosts["a"].used.memory_mb, 71_000);
    assert_eq!(reg.hosts["a"].disk_free_mb, 13_000);
    // The first failed: what it held is back at once, not at the next report.
    reg.release("a", t1);
    reg.release("a", t1);
    assert_eq!(reg.hosts["a"].used.memory_mb, 11_000, "released once");
    assert_eq!(reg.hosts["a"].disk_free_mb, 16_000);
    // The second was made: counted until a report received after it, then the host's.
    reg.made("a", t1b, t2 + Duration::seconds(1));
    let mut report = host("a", 100_000, 1000, 0);
    report.disk_free_mb = 20_000;
    reg.heartbeat(report.clone(), t2 + Duration::milliseconds(500));
    assert_eq!(
        reg.hosts["a"].used.memory_mb, 11_000,
        "a report from before"
    );
    report.used.memory_mb = 11_000;
    report.disk_free_mb = 16_000;
    reg.heartbeat(report, t2 + Duration::seconds(2));
    assert_eq!(
        reg.hosts["a"].used.memory_mb, 11_000,
        "the host's figure, once"
    );
    assert_eq!(reg.hosts["a"].disk_free_mb, 16_000);
    assert!(reg.hosts["a"].holds.is_empty());
    // A hold never takes disk a host does not report, nor gives back more than it took.
    let t3 = reg.hold("b", 1000, 50_000);
    assert_eq!(reg.hosts["b"].disk_free_mb, 0, "b reports no disk figure");
    reg.release("b", t3);
    assert_eq!(reg.hosts["b"].disk_free_mb, 0);
}

#[test]
fn unpin_releases_a_namespace_for_a_new_placement() {
    let now = Utc::now();
    let mut reg = Registry::default();
    reg.heartbeat(host("a", 100_000, 0, 0), now);
    reg.heartbeat(host("b", 100_000, 0, 0), now);
    let first = placed(&mut reg, "t1", 60_000, 0).unwrap().0;
    assert!(reg.pinned_at.contains_key("t1"));
    reg.unpin("t1");
    assert_eq!(reg.namespaces.get("t1"), None);
    assert!(!reg.pinned_at.contains_key("t1"));
    assert_ne!(
        placed(&mut reg, "t1", 10_000, 0).unwrap().0,
        first,
        "placed afresh, on the host with the most room"
    );
    reg.unpin("never-pinned");
}

#[test]
fn forget_drops_the_host_and_its_index() {
    let now = Utc::now();
    let mut reg = Registry::default();
    let mut a = host("a", 1000, 0, 1);
    a.namespaces = vec!["t1".into()];
    reg.heartbeat(a, now);
    reg.heartbeat(host("b", 1000, 0, 0), now);
    reg.machines.insert("m1".into(), "a".into());
    reg.machines.insert("m2".into(), "b".into());
    reg.endpoints.insert("e1".into(), "a".into());
    reg.namespaces.insert("t2".into(), "b".into());
    reg.forget("a");
    assert!(!reg.hosts.contains_key("a"));
    assert_eq!(reg.namespaces.get("t1"), None);
    assert_eq!(reg.namespaces.get("t2").map(String::as_str), Some("b"));
    assert_eq!(reg.machines.get("m1"), None);
    assert_eq!(reg.machines.get("m2").map(String::as_str), Some("b"));
    assert_eq!(reg.endpoints.get("e1"), None);
    assert_eq!(reg.listed().len(), 1);
    reg.forget("a");
    assert!(
        reg.retired_keys.is_empty(),
        "a host with no key leaves none"
    );
}

/// A forgotten host's pool key stays, found by its id beside the live hosts' (ADR 0035).
#[test]
fn a_forgotten_hosts_key_is_kept_for_its_backups() {
    let now = Utc::now();
    let mut reg = Registry::default();
    reg.heartbeat(host("a", 1000, 0, 0), now);
    reg.heartbeat(host("b", 1000, 0, 0), now);
    let (ka, _) = reg.pool_key("a").unwrap();
    let (kb, _) = reg.pool_key("b").unwrap();
    let id = |k: &PoolKey| briqyard_api::poolkey::id(k.expose()).unwrap();
    assert_eq!(reg.key_by_id(&id(&kb)), Some(("b".into(), kb.clone())));
    reg.forget("a");
    assert_eq!(reg.key_by_id(&id(&ka)), Some(("a".into(), ka.clone())));
    assert_eq!(reg.key_by_id(&"0".repeat(32)), None);
    let back: Registry = serde_json::from_slice(&serde_json::to_vec(&reg).unwrap()).unwrap();
    assert_eq!(back.key_by_id(&id(&ka)), Some(("a".into(), ka)));
}

#[test]
fn silent_hosts_go_down_and_come_back() {
    let now = Utc::now();
    let mut reg = Registry::default();
    reg.heartbeat(host("a", 1000, 0, 0), now - Duration::seconds(120));
    reg.sweep(&Policy::default(), now);
    assert_eq!(reg.hosts["a"].state, "down");
    reg.heartbeat(host("a", 1000, 0, 0), now);
    assert_eq!(reg.hosts["a"].state, "ready");
}
