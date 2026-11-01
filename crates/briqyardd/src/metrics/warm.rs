//! Warm reservations and host lifecycle observations; no guest or request labels.
use super::*;
use std::time::Duration;

pub const REASONS: [&str; 7] = [
    "catalog", "quota", "budget", "headroom", "pressure", "capacity", "cleanup",
];
pub const STATES: [&str; 5] = ["creating", "ready", "claimed", "draining", "failed"];

#[derive(Clone)]
pub struct Pool {
    pub namespace: String,
    pub name: String,
    pub catalog: String,
    pub kind: String,
    pub size: api::Size,
    pub desired: u16,
    pub ceiling: u16,
    pub slots: [u64; 5],
    pub charged: api::WarmResources,
    pub blocked: Option<String>,
}

impl Pool {
    fn labels(&self) -> String {
        format!("namespace=\"{}\",pool=\"{}\",catalog=\"{}\",type=\"{}\",memory_mb=\"{}\",vcpus=\"{}\",cpu_millis=\"{}\"",
            label_value(&self.namespace), label_value(&self.name), label_value(&self.catalog), label_value(&self.kind),
            self.size.memory_mb, self.size.vcpus, self.size.cpu_millis())
    }
}

#[derive(Clone)]
pub struct Probe {
    pub age: Duration,
    pub memory_mb: u32,
    pub disk_free_bytes: u64,
    pub valid: bool,
}

#[derive(Default)]
pub struct Snapshot {
    pub available: bool,
    pub pools: Vec<Pool>,
    pub charged: api::WarmResources,
    pub budget: api::WarmResources,
    pub headroom: api::WarmResources,
    pub memory_floor_mb: u32,
    pub max_fills: u16,
    pub fills: usize,
    pub probe: Option<Probe>,
}

#[derive(Clone, Copy)]
pub enum Operation {
    Prepare,
    Claim,
}
#[derive(Clone, Copy)]
pub enum Outcome {
    Success,
    Miss,
    Failure,
}

#[derive(Clone, Copy, Default)]
struct Observation {
    count: u64,
    seconds: f64,
    last: Option<f64>,
}

#[derive(Clone, Default)]
pub struct Operations {
    observations: [[Observation; 3]; 2],
    blocked: [u64; 7],
}

impl Operations {
    pub fn observe(&mut self, operation: Operation, outcome: Outcome, elapsed: Duration) {
        let value = &mut self.observations[operation as usize][outcome as usize];
        value.count = value.count.saturating_add(1);
        value.seconds += elapsed.as_secs_f64();
        value.last = Some(elapsed.as_secs_f64());
    }

    pub fn blocked(&mut self, reason: &str) {
        let index = REASONS.iter().position(|r| *r == reason).unwrap_or(5);
        self.blocked[index] = self.blocked[index].saturating_add(1);
    }
}

pub fn render(out: &mut String, snapshot: &Snapshot, operations: &Operations) {
    family(out, "briqyard_warm_accounting_available", "gauge", "Whether warm accounting was reconstructed from current records and cached durable pool receipts.", one(u8::from(snapshot.available)));
    if snapshot.available {
        family(
            out,
            "briqyard_warm_pools",
            "gauge",
            "Durable pool records on this host, including closed pools.",
            one(snapshot.pools.len()),
        );
        for (name, help, select) in [
            (
                "briqyard_warm_pool_desired",
                "Upper target for paused host slots; not a readiness promise.",
                0,
            ),
            (
                "briqyard_warm_pool_max_ready",
                "Configured entry ceiling shared across its pools.",
                1,
            ),
            (
                "briqyard_warm_pool_shortfall",
                "Desired minus currently paused ready slots, floored at zero.",
                2,
            ),
        ] {
            family(
                out,
                name,
                "gauge",
                help,
                snapshot
                    .pools
                    .iter()
                    .map(|p| {
                        let value = match select {
                            0 => u64::from(p.desired),
                            1 => u64::from(p.ceiling),
                            _ => u64::from(p.desired).saturating_sub(p.slots[1]),
                        };
                        (p.labels(), value.to_string())
                    })
                    .collect(),
            );
        }
        let mut slots = Vec::new();
        let mut blocked = Vec::new();
        let mut totals = [0u64; 5];
        for pool in &snapshot.pools {
            for (index, state) in STATES.iter().enumerate() {
                totals[index] = totals[index].saturating_add(pool.slots[index]);
                slots.push((
                    format!("{},state=\"{state}\"", pool.labels()),
                    pool.slots[index].to_string(),
                ));
            }
            for reason in REASONS {
                blocked.push((
                    format!("{},reason=\"{reason}\"", pool.labels()),
                    u8::from(
                        (pool.desired > 0 || pool.slots[3] > 0)
                            && pool.blocked.as_deref() == Some(reason),
                    )
                    .to_string(),
                ));
            }
        }
        family(out, "briqyard_warm_pool_slots", "gauge", "Actual host pool records; ready means paused host preparation, not public API readiness.", slots);
        family(
            out,
            "briqyard_warm_slots",
            "gauge",
            "Actual pool records summed over this host, by state.",
            STATES
                .iter()
                .zip(totals)
                .map(|(state, n)| (format!("state=\"{state}\""), n.to_string()))
                .collect(),
        );
        family(
            out,
            "briqyard_warm_desired",
            "gauge",
            "Upper targets summed over this host.",
            one(snapshot
                .pools
                .iter()
                .map(|p| u64::from(p.desired))
                .sum::<u64>()),
        );
        family(
            out,
            "briqyard_warm_shortfall",
            "gauge",
            "Sum of per-pool desired minus paused ready slots.",
            one(snapshot
                .pools
                .iter()
                .map(|p| u64::from(p.desired).saturating_sub(p.slots[1]))
                .sum::<u64>()),
        );
        family(
            out,
            "briqyard_warm_pool_blocked",
            "gauge",
            "Last persisted pool blockage, with bounded reason labels; zero when no demand or draining slots.",
            blocked,
        );
        for (name, help, field) in [
            ("briqyard_warm_pool_reserved_memory_bytes", "Full recipe RAM reservation, including failed or unreleased slots; not resident usage.", 0),
            ("briqyard_warm_pool_reserved_cpu_millis", "Full CPU millis reserved by unclaimed slots.", 1),
            ("briqyard_warm_pool_reserved_root_disk_bytes", "Full logical root reservation without a copy-on-write discount; not physical usage.", 2),
        ] {
            family(out, name, "gauge", help, snapshot.pools.iter().map(|p| (p.labels(), resource(p.charged, field).to_string())).collect());
        }
    }
    for (name, help, field) in [
        ("briqyard_warm_memory_bytes", "Full RAM reservations and configured budget/headroom, distinct from measured availability.", 0),
        ("briqyard_warm_cpu_millis", "Full CPU millis reservations and configured budget/headroom.", 1),
        ("briqyard_warm_root_disk_bytes", "Full logical root reservations and budget; headroom is the absolute free-space floor.", 2),
    ] {
        let mut values = vec![("kind=\"budget\"".into(), resource(snapshot.budget, field).to_string()), ("kind=\"headroom\"".into(), resource(snapshot.headroom, field).to_string())];
        if snapshot.available { values.push(("kind=\"reserved\"".into(), resource(snapshot.charged, field).to_string())); }
        family(out, name, "gauge", help, values);
    }
    family(
        out,
        "briqyard_warm_fills",
        "gauge",
        "Current unfinished fills, including recovery, and configured maximum.",
        {
            let mut values = vec![("kind=\"maximum\"".into(), snapshot.max_fills.to_string())];
            if snapshot.available {
                values.push(("kind=\"current\"".into(), snapshot.fills.to_string()));
            }
            values
        },
    );
    family(
        out,
        "briqyard_warm_probe_available",
        "gauge",
        "Whether a cached warm availability measurement exists.",
        one(u8::from(snapshot.probe.is_some())),
    );
    family(
        out,
        "briqyard_warm_probe_valid",
        "gauge",
        "Whether the cached warm availability measurement remains within its admission age bound.",
        one(u8::from(snapshot.probe.as_ref().is_some_and(|p| p.valid))),
    );
    if let Some(probe) = &snapshot.probe {
        family(
            out,
            "briqyard_warm_probe_age_seconds",
            "gauge",
            "Age of the cached availability sample; a scrape performs no probe.",
            one(probe.age.as_secs_f64()),
        );
        family(
            out,
            "briqyard_warm_memory_available_bytes",
            "gauge",
            "Cached MemAvailable; measured availability, not a reservation.",
            one(u64::from(probe.memory_mb) << 20),
        );
        family(
            out,
            "briqyard_warm_disk_free_bytes",
            "gauge",
            "Cached physical pool free space.",
            one(probe.disk_free_bytes),
        );
    }
    family(
        out,
        "briqyard_warm_memory_floor_bytes",
        "gauge",
        "Configured minimum MemAvailable after conservative fill liabilities.",
        one(u64::from(snapshot.memory_floor_mb) << 20),
    );
    for (name, help, value) in [
        ("briqyard_warm_operations_total", "Host warm prepare workers and claims by outcome, since daemon start.", 0),
        ("briqyard_warm_operation_seconds_total", "Cumulative host prepare-worker or claim-to-host-readiness seconds; excludes fleet and public API transport.", 1),
        ("briqyard_warm_operation_last_seconds", "Most recent host operation duration by outcome; absent until observed.", 2),
    ] {
        let mut samples = Vec::new();
        for (i, operation) in ["prepare", "claim"].iter().enumerate() {
            for (j, outcome) in ["success", "miss", "failure"].iter().enumerate() {
                let observation = operations.observations[i][j];
                let n = match value { 0 => Some(observation.count.to_string()), 1 => Some(observation.seconds.to_string()), _ => observation.last.map(|n| n.to_string()) };
                if let Some(n) = n { samples.push((format!("operation=\"{operation}\",outcome=\"{outcome}\""), n)); }
            }
        }
        family(out, name, if value == 2 { "gauge" } else { "counter" }, help, samples);
    }
    family(
        out,
        "briqyard_warm_fill_blocked_total",
        "counter",
        "Refill attempts refused, by a bounded reason, since daemon start.",
        REASONS
            .iter()
            .enumerate()
            .map(|(i, reason)| {
                (
                    format!("reason=\"{reason}\""),
                    operations.blocked[i].to_string(),
                )
            })
            .collect(),
    );
}

fn resource(value: api::WarmResources, field: usize) -> u64 {
    match field {
        0 => u64::from(value.memory_mb) << 20,
        1 => u64::from(value.cpu_millis),
        _ => u64::from(value.root_disk_gb) << 30,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservations_probe_values_and_bounded_operations_have_distinct_series() {
        let resources = api::WarmResources {
            memory_mb: 768,
            cpu_millis: 1500,
            root_disk_gb: 24,
        };
        let snapshot = Snapshot {
            available: true,
            pools: vec![Pool {
                namespace: "team".into(),
                name: "tools".into(),
                catalog: "shell-small".into(),
                kind: "shell".into(),
                size: api::Size {
                    memory_mb: 256,
                    vcpus: 1,
                    cpu_millis: Some(500),
                },
                desired: 3,
                ceiling: 4,
                slots: [1, 1, 1, 1, 0],
                charged: resources,
                blocked: Some("pressure".into()),
            }],
            charged: resources,
            budget: api::WarmResources {
                memory_mb: 2048,
                cpu_millis: 3000,
                root_disk_gb: 64,
            },
            headroom: api::WarmResources {
                memory_mb: 512,
                cpu_millis: 1000,
                root_disk_gb: 16,
            },
            memory_floor_mb: 1024,
            max_fills: 2,
            fills: 1,
            probe: Some(Probe {
                age: Duration::ZERO,
                memory_mb: 3072,
                disk_free_bytes: 128 << 30,
                valid: true,
            }),
        };
        let mut operations = Operations::default();
        operations.observe(
            Operation::Prepare,
            Outcome::Success,
            Duration::from_millis(250),
        );
        operations.observe(
            Operation::Claim,
            Outcome::Success,
            Duration::from_millis(80),
        );
        operations.observe(Operation::Claim, Outcome::Miss, Duration::from_millis(5));
        operations.observe(
            Operation::Claim,
            Outcome::Failure,
            Duration::from_millis(10),
        );
        operations.blocked("pressure");
        operations.blocked("private-error-details");
        let mut text = String::new();
        render(&mut text, &snapshot, &operations);
        api::metrics::check_exposition(&text);
        let labels = "namespace=\"team\",pool=\"tools\",catalog=\"shell-small\",type=\"shell\",memory_mb=\"256\",vcpus=\"1\",cpu_millis=\"500\"";
        for expected in [
            format!("briqyard_warm_pool_shortfall{{{labels}}} 2\n"),
            format!("briqyard_warm_pool_slots{{{labels},state=\"draining\"}} 1\n"),
            format!("briqyard_warm_pool_blocked{{{labels},reason=\"pressure\"}} 1\n"),
            "briqyard_warm_memory_bytes{kind=\"reserved\"} 805306368\n".into(),
            "briqyard_warm_memory_available_bytes 3221225472\n".into(),
            "briqyard_warm_root_disk_bytes{kind=\"reserved\"} 25769803776\n".into(),
            "briqyard_warm_operations_total{operation=\"claim\",outcome=\"miss\"} 1\n".into(),
            "briqyard_warm_operation_seconds_total{operation=\"claim\",outcome=\"success\"} 0.08\n"
                .into(),
            "briqyard_warm_fill_blocked_total{reason=\"capacity\"} 1\n".into(),
        ] {
            assert!(text.contains(&expected), "{expected}\n{text}");
        }
        for excluded in [
            "private-error-details",
            "machine=",
            "request_id",
            "generation=",
            "snapshot=",
            "fingerprint=",
        ] {
            assert!(!text.contains(excluded));
        }
        let mut empty = String::new();
        render(&mut empty, &Snapshot::default(), &Operations::default());
        api::metrics::check_exposition(&empty);
        assert!(!empty
            .lines()
            .any(|line| line.starts_with("briqyard_warm_operation_last_seconds{")));
        assert!(!empty.contains("briqyard_warm_probe_age_seconds"));
        assert!(
            !empty.contains("kind=\"reserved\""),
            "unknown accounting is not a zero reservation"
        );
    }

    #[test]
    fn host_dashboard_warm_queries_keep_host_selection_units_and_known_metric_names() {
        let dashboard: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../hack/monitoring/dashboards/host.json"
        ))
        .unwrap();
        assert_eq!(dashboard["uid"], "briqyard-host");
        let mut text = String::new();
        render(
            &mut text,
            &Snapshot {
                available: true,
                probe: Some(Probe {
                    age: Duration::ZERO,
                    memory_mb: 1024,
                    disk_free_bytes: 1 << 30,
                    valid: true,
                }),
                ..Default::default()
            },
            &Operations::default(),
        );
        let names = text
            .lines()
            .filter_map(|line| line.strip_prefix("# TYPE "))
            .map(|line| line.split_whitespace().next().unwrap())
            .collect::<std::collections::HashSet<_>>();
        let mut ids = std::collections::HashSet::new();
        let mut queries = 0;
        for panel in dashboard["panels"].as_array().unwrap() {
            assert!(ids.insert(panel["id"].as_u64().unwrap()));
            let Some(targets) = panel["targets"].as_array() else {
                continue;
            };
            let mut refs = std::collections::HashSet::new();
            for target in targets {
                assert!(refs.insert(target["refId"].as_str().unwrap()));
                let expr = target["expr"].as_str().unwrap();
                if !expr.contains("briqyard_warm_") {
                    continue;
                }
                queries += 1;
                assert!(expr.contains("host=\"$host\""), "{expr}");
                assert!(
                    !expr.contains("or vector(0)"),
                    "missing telemetry must stay absent"
                );
                assert_eq!(target["datasource"]["uid"], "briqyard-prometheus");
                for name in expr
                    .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .filter(|name| name.starts_with("briqyard_warm_"))
                {
                    assert!(names.contains(name), "unknown metric: {name}");
                }
                if expr.contains("briqyard_warm_probe_age_seconds")
                    || expr.contains("briqyard_warm_operation_seconds_total")
                {
                    assert_eq!(panel["fieldConfig"]["defaults"]["unit"], "s");
                }
                if expr.contains("briqyard_warm_pool_reserved_memory_bytes")
                    || expr.contains("briqyard_warm_root_disk_bytes")
                {
                    assert_eq!(panel["fieldConfig"]["defaults"]["unit"], "bytes");
                }
            }
        }
        assert!(queries >= 15);
    }

    #[test]
    fn monitoring_only_accepts_absence_with_explicit_warm_host_evidence() {
        let source = include_str!("../../../../hack/monitoring-check.sh");
        let function = source
            .split("warm_optional() {")
            .nth(1)
            .unwrap()
            .split("\n}\n")
            .next()
            .unwrap();
        let script = format!("host=h_test\nup() {{ case \"$1\" in *accounting_available*) printf '%s' \"$WARM_ACCOUNTING\";; *warm_pools*) printf '%s' \"$WARM_POOLS\";; *probe_available*) printf '%s' \"$WARM_PROBE\";; *operations_total*) printf '%s' \"$WARM_OPERATIONS\";; *warm_desired*) printf '%s' \"$WARM_DESIRED\";; esac; }}\nwarm_optional() {{{function}\n}}\nwarm_optional \"$1\"\n");
        for (query, accounting, pools, probe, operations, desired, optional) in [
            ("briqyard_warm_pool_slots", "1", "0", "0", "0", "0", true),
            ("briqyard_warm_pool_slots", "1", "1", "0", "0", "0", false),
            ("briqyard_warm_pool_slots", "0", "0", "0", "0", "0", false),
            ("briqyard_warm_pool_slots", "", "0", "0", "0", "0", false),
            (
                "briqyard_warm_probe_age_seconds",
                "1",
                "0",
                "0",
                "0",
                "0",
                true,
            ),
            (
                "briqyard_warm_probe_age_seconds",
                "1",
                "1",
                "0",
                "0",
                "1",
                false,
            ),
            (
                "briqyard_warm_probe_age_seconds",
                "1",
                "0",
                "1",
                "0",
                "0",
                false,
            ),
            (
                "rate(briqyard_warm_operation_seconds_total)",
                "1",
                "0",
                "0",
                "0",
                "0",
                true,
            ),
            (
                "rate(briqyard_warm_operation_seconds_total)",
                "1",
                "0",
                "0",
                "1",
                "0",
                false,
            ),
            ("briqyard_warm_memory_bytes", "1", "0", "0", "0", "0", false),
            ("briqyard_machines_total", "1", "0", "0", "0", "0", false),
        ] {
            let status = std::process::Command::new("bash")
                .args(["-c", &script, "warm-query-check", query])
                .env("WARM_ACCOUNTING", accounting)
                .env("WARM_POOLS", pools)
                .env("WARM_PROBE", probe)
                .env("WARM_OPERATIONS", operations)
                .env("WARM_DESIRED", desired)
                .status()
                .unwrap();
            assert_eq!(status.success(), optional, "{query} accounting={accounting} pools={pools} probe={probe} operations={operations}");
        }
    }
}
