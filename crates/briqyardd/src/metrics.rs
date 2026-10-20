//! `/metrics` (ADR 0021): the Prometheus text exposition (0.0.4) of the host and of each
//! machine, from what the tick last measured. Rendering only: the manager gathers the figures.

use crate::zfs::Pool;
use briqyard_api as api;
use std::collections::BTreeMap;

/// The host's figures.
#[derive(Default)]
pub struct Host {
    pub by_state: BTreeMap<String, usize>,
    pub suspended: usize,
    pub tenants: usize,
    pub endpoints: usize,
    /// Committed to running machines, and what the host hands out.
    pub memory_mb: (u32, u32),
    pub vcpus: (u32, u32),
    /// None until the tick has read the pool.
    pub pool: Option<Pool>,
    pub conditions: Vec<api::Condition>,
    /// Events since the daemon started, by type and reason.
    pub events: BTreeMap<(&'static str, &'static str), u64>,
    /// The daemon's own counters: name, help, value.
    pub counters: Vec<(&'static str, &'static str, u64)>,
}

/// One machine's figures, as the tick last measured them.
pub struct Machine {
    pub id: String,
    pub tenant: String,
    pub name: String,
    /// `gateway` for a tenant's gateway.
    pub role: Option<String>,
    pub state: String,
    /// What its counters added up to since the daemon started.
    pub counted: api::Usage,
    pub memory_bytes: u64,
    pub memory_limit_bytes: u64,
    pub disk_used_bytes: u64,
    pub restarts: u64,
    pub boot_seconds: Option<f64>,
}

impl Machine {
    /// `machine`, `tenant`, `name`, and `role` where it applies.
    fn labels(&self) -> String {
        let mut l = format!(
            "machine=\"{}\",tenant=\"{}\",name=\"{}\"",
            label_value(&self.id),
            label_value(&self.tenant),
            label_value(&self.name)
        );
        if let Some(role) = &self.role {
            l.push_str(&format!(",role=\"{}\"", label_value(role)));
        }
        l
    }
}

/// A label value as the format writes it: `\\`, `\"` and `\n` escaped.
fn label_value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// One family: its HELP and TYPE, then its samples, `(labels, value)`.
fn family(out: &mut String, name: &str, kind: &str, help: &str, samples: Vec<(String, String)>) {
    out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {kind}\n"));
    for (labels, v) in samples {
        match labels.is_empty() {
            true => out.push_str(&format!("{name} {v}\n")),
            false => out.push_str(&format!("{name}{{{labels}}} {v}\n")),
        }
    }
}

fn one(v: impl ToString) -> Vec<(String, String)> {
    vec![(String::new(), v.to_string())]
}

fn kinds(pairs: &[(&str, u64)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| (format!("kind=\"{k}\""), v.to_string()))
        .collect()
}

/// A per-machine series: name, type, help, and its value of a machine (none: no sample).
type Series = (
    &'static str,
    &'static str,
    &'static str,
    fn(&Machine) -> Option<String>,
);

/// The per-machine series, but the state.
const MACHINE_SERIES: [Series; 11] = [
    (
        "briqyard_machine_cpu_seconds_total",
        "counter",
        "CPU time its cgroup used, since the daemon started.",
        |m| Some(m.counted.cpu_seconds.to_string()),
    ),
    (
        "briqyard_machine_memory_bytes",
        "gauge",
        "Memory its process holds, from its cgroup.",
        |m| Some(m.memory_bytes.to_string()),
    ),
    (
        "briqyard_machine_memory_limit_bytes",
        "gauge",
        "Its size's memory.",
        |m| Some(m.memory_limit_bytes.to_string()),
    ),
    (
        "briqyard_machine_disk_used_bytes",
        "gauge",
        "What its disks, their snapshots and its memory snapshot take on the pool.",
        |m| Some(m.disk_used_bytes.to_string()),
    ),
    (
        "briqyard_machine_internet_in_bytes_total",
        "counter",
        "Bytes from the internet, through the host's NAT.",
        |m| Some(m.counted.internet_in_bytes.to_string()),
    ),
    (
        "briqyard_machine_internet_out_bytes_total",
        "counter",
        "Bytes to the internet, through the host's NAT.",
        |m| Some(m.counted.internet_out_bytes.to_string()),
    ),
    (
        "briqyard_machine_ingress_in_bytes_total",
        "counter",
        "Bytes from clients of its endpoints.",
        |m| Some(m.counted.ingress_in_bytes.to_string()),
    ),
    (
        "briqyard_machine_ingress_out_bytes_total",
        "counter",
        "Bytes to clients of its endpoints.",
        |m| Some(m.counted.ingress_out_bytes.to_string()),
    ),
    (
        "briqyard_machine_egress_dropped_packets_total",
        "counter",
        "Packets its egress limits dropped.",
        |m| Some(m.counted.egress_dropped_packets.to_string()),
    ),
    (
        "briqyard_machine_restarts_total",
        "counter",
        "Restarts by its restart policy, since the daemon started.",
        |m| Some(m.restarts.to_string()),
    ),
    (
        "briqyard_machine_boot_seconds",
        "gauge",
        "How long its last start took, starting to running.",
        |m| m.boot_seconds.map(|s| s.to_string()),
    ),
];

/// The exposition: the host's families, then the machines'.
pub fn render(h: &Host, machines: &[Machine]) -> String {
    let mut out = String::new();
    let o = &mut out;
    let states = h
        .by_state
        .iter()
        .map(|(s, n)| (format!("state=\"{s}\""), n.to_string()))
        .collect();
    family(
        o,
        "briqyard_machines",
        "gauge",
        "Machines on this host, by state.",
        states,
    );
    let total: usize = h.by_state.values().sum();
    family(
        o,
        "briqyard_machines_total",
        "gauge",
        "Machines on this host.",
        one(total),
    );
    family(
        o,
        "briqyard_machines_suspended",
        "gauge",
        "Machines stopped with a memory snapshot.",
        one(h.suspended),
    );
    family(
        o,
        "briqyard_tenants",
        "gauge",
        "Tenants on this host.",
        one(h.tenants),
    );
    family(
        o,
        "briqyard_endpoints",
        "gauge",
        "Endpoints on this host.",
        one(h.endpoints),
    );
    let (used, cap) = h.memory_mb;
    family(
        o,
        "briqyard_memory_mb",
        "gauge",
        "Memory committed to running machines, and what the host hands out.",
        kinds(&[("used", used as u64), ("capacity", cap as u64)]),
    );
    let (used, cap) = h.vcpus;
    family(
        o,
        "briqyard_vcpus",
        "gauge",
        "vCPUs of running machines, and what the host hands out.",
        kinds(&[("used", used as u64), ("capacity", cap as u64)]),
    );
    if let Some(p) = h.pool {
        family(
            o,
            "briqyard_disk_free_mb",
            "gauge",
            "Free space in the pool, in MB.",
            one(p.free >> 20),
        );
        family(
            o,
            "briqyard_pool_bytes",
            "gauge",
            "The pool's size, what its datasets take, and what is free.",
            kinds(&[("size", p.size()), ("used", p.used), ("free", p.free)]),
        );
    }
    let conditions = h
        .conditions
        .iter()
        .map(|c| {
            (
                format!("condition=\"{}\"", c.kind),
                (c.status as u8).to_string(),
            )
        })
        .collect();
    family(
        o,
        "briqyard_host_condition",
        "gauge",
        "1 while a host condition is true.",
        conditions,
    );
    let events = h
        .events
        .iter()
        .map(|((t, r), n)| (format!("type=\"{t}\",reason=\"{r}\""), n.to_string()))
        .collect();
    family(
        o,
        "briqyard_events_total",
        "counter",
        "Events logged since the daemon started, by type and reason.",
        events,
    );
    for (name, help, n) in &h.counters {
        family(o, name, "counter", help, one(n));
    }
    for (name, kind, help, value) in MACHINE_SERIES {
        let samples = machines
            .iter()
            .filter_map(|m| value(m).map(|v| (m.labels(), v)))
            .collect();
        family(o, name, kind, help, samples);
    }
    let states = machines
        .iter()
        .map(|m| (format!("{},state=\"{}\"", m.labels(), m.state), "1".into()))
        .collect();
    family(
        o,
        "briqyard_machine_state",
        "gauge",
        "1 for the state it is in: one series per machine.",
        states,
    );
    out
}

/// Checks text against the exposition format (0.0.4): every line a `# HELP`, a `# TYPE` or a
/// sample; a family's HELP and TYPE once, before its samples, which are together; label names
/// and values well formed; values numbers; no series twice.
#[cfg(test)]
pub fn check_exposition(text: &str) {
    use std::collections::HashSet;
    let name_ok = |n: &str| {
        let mut c = n.chars();
        c.next()
            .is_some_and(|f| f.is_ascii_alphabetic() || f == '_' || f == ':')
            && c.all(|x| x.is_ascii_alphanumeric() || x == '_' || x == ':')
    };
    let (mut typed, mut helped, mut done, mut series) = (
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
    );
    let mut current = String::new();
    // A family begins: the one before it is done.
    let enter = |name: &str, current: &mut String, done: &mut HashSet<String>| {
        assert!(!done.contains(name), "{name} again, apart from its samples");
        if current != name {
            done.insert(std::mem::replace(current, name.to_string()));
        }
    };
    assert!(text.ends_with('\n'), "ends with a newline");
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("# ") {
            let (kw, rest) = rest.split_once(' ').expect(line);
            let (name, arg) = rest.split_once(' ').expect(line);
            assert!(name_ok(name), "{line}");
            enter(name, &mut current, &mut done);
            match kw {
                "HELP" => assert!(helped.insert(name.to_string()), "HELP twice: {line}"),
                "TYPE" => {
                    assert!(["counter", "gauge", "untyped"].contains(&arg), "{line}");
                    assert!(typed.insert(name.to_string()), "TYPE twice: {line}");
                }
                _ => panic!("not a comment of the format: {line}"),
            }
            continue;
        }
        let (head, value) = line.rsplit_once(' ').expect(line);
        assert!(
            value.parse::<f64>().is_ok() || ["+Inf", "-Inf", "NaN"].contains(&value),
            "value: {line}"
        );
        let (name, labels) = match head.split_once('{') {
            Some((n, l)) => (n, l.strip_suffix('}').expect(line)),
            None => (head, ""),
        };
        assert!(name_ok(name), "{line}");
        assert!(typed.contains(name), "a sample before its TYPE: {line}");
        enter(name, &mut current, &mut done);
        let mut names = HashSet::new();
        let mut rest = labels;
        while !rest.is_empty() {
            let (l, after) = rest.split_once("=\"").expect(line);
            assert!(name_ok(l) && !l.contains(':'), "label {l}: {line}");
            assert!(names.insert(l), "label {l} twice: {line}");
            let mut chars = after.char_indices();
            let end = loop {
                match chars.next().expect(line) {
                    (_, '\\') => {
                        let (_, e) = chars.next().expect(line);
                        assert!(['\\', '"', 'n'].contains(&e), "escape: {line}");
                    }
                    (i, '"') => break i,
                    _ => {}
                }
            };
            rest = &after[end + 1..];
            rest = rest.strip_prefix(',').unwrap_or(rest);
        }
        assert!(series.insert(head.to_string()), "series twice: {line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine(id: &str, state: &str) -> Machine {
        Machine {
            id: id.into(),
            tenant: "t1".into(),
            name: "db".into(),
            role: None,
            state: state.into(),
            counted: api::Usage {
                cpu_seconds: 2.5,
                internet_in_bytes: 1000,
                ..Default::default()
            },
            memory_bytes: 1 << 20,
            memory_limit_bytes: 512 << 20,
            disk_used_bytes: 4096,
            restarts: 1,
            boot_seconds: None,
        }
    }

    #[test]
    fn the_exposition_is_the_format_with_a_family_per_series() {
        let mut gw = machine("m_2", "stopped");
        gw.role = Some("gateway".into());
        gw.name = "gate\"way\\".into();
        let mut run = machine("m_1", "running");
        run.boot_seconds = Some(1.25);
        let h = Host {
            by_state: BTreeMap::from([("running".into(), 1), ("stopped".into(), 1)]),
            memory_mb: (512, 4096),
            pool: Some(Pool {
                used: 300,
                free: 700,
            }),
            counters: vec![("briqyard_boots_total", "Cold boots.", 3)],
            ..Default::default()
        };
        let text = render(&h, &[run, gw]);
        check_exposition(&text);
        let lines: Vec<&str> = text.lines().collect();
        for want in [
            r#"briqyard_machines{state="running"} 1"#,
            "briqyard_machines_total 2",
            r#"briqyard_memory_mb{kind="capacity"} 4096"#,
            r#"briqyard_pool_bytes{kind="size"} 1000"#,
            "briqyard_boots_total 3",
            r#"briqyard_machine_cpu_seconds_total{machine="m_1",tenant="t1",name="db"} 2.5"#,
            r#"briqyard_machine_boot_seconds{machine="m_1",tenant="t1",name="db"} 1.25"#,
            r#"briqyard_machine_restarts_total{machine="m_2",tenant="t1",name="gate\"way\\",role="gateway"} 1"#,
            r#"briqyard_machine_state{machine="m_2",tenant="t1",name="gate\"way\\",role="gateway",state="stopped"} 1"#,
        ] {
            assert!(lines.contains(&want), "{want}\n{text}");
        }
        // No boot measured: no sample. Families are there with no machine.
        assert_eq!(text.matches("briqyard_machine_boot_seconds{").count(), 1);
        let empty = render(&Host::default(), &[]);
        check_exposition(&empty);
        assert!(empty.contains("# TYPE briqyard_machine_state gauge\n"));
        assert!(!empty.contains("briqyard_pool_bytes"), "no pool read yet");
    }

    #[test]
    fn the_check_refuses_what_is_not_the_format() {
        check_exposition("# HELP a A.\n# TYPE a gauge\na{x=\"1\\\"\"} 1\na 2\n");
        for bad in [
            "a 1\n",
            "# TYPE a gauge\na{x=\"1\"} one\n",
            "# TYPE a gauge\na{x=1} 1\n",
            "# TYPE a gauge\na 1\n# TYPE b gauge\nb 1\na 2\n",
            "# TYPE a gauge\na 1\na 1\n",
            "# TYPE a gauge\na{x=\"\\t\"} 1\n",
        ] {
            assert!(
                std::panic::catch_unwind(|| check_exposition(bad)).is_err(),
                "{bad:?}"
            );
        }
        assert_eq!(label_value("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }
}
