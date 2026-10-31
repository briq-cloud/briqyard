//! The tables and descriptions the commands print.

use super::*;

// --- tables ---

/// `machine ls`.
/// Why a machine is in its state: stopped, or in `error`.
pub(super) fn reason_of(m: &api::Machine) -> &str {
    match m.state.as_str() {
        api::state::ERROR => &m.error_reason,
        _ => &m.stopped_reason,
    }
}

pub(super) fn machine_table(ms: &[api::Machine]) -> String {
    let mut out = format!(
        "{:<16} {:<12} {:<14} {:<24} {:<18} {:<5} {:<12} {:<9} {:<7} {:<6} {:<18} {:<24} {:<16} {:<8} {:<12} HOST\n",
        "ID",
        "NAMESPACE",
        "NAME",
        "IMAGE",
        "STATE",
        "READY",
        "IP",
        "SIZE",
        "CPU m",
        "SLEEP",
        "EGRESS",
        "LIMITS",
        "DISK",
        "BACKUP",
        "PENDING"
    );
    for m in ms {
        let state = match reason_of(m) {
            "" => m.state.clone(),
            why => format!("{} ({why})", m.state),
        };
        let pending = match &m.pending {
            Some(p) => p.fields.join(","),
            None => "-".into(),
        };
        out.push_str(&format!(
            "{:<16} {:<12} {:<14} {:<24} {:<18} {:<5} {:<12} {:<9} {:<7} {:<6} {:<18} {:<24} {:<16} {:<8} {:<12} {}\n",
            m.id,
            m.namespace,
            m.name,
            m.image,
            state,
            if m.ready { "yes" } else { "no" },
            m.ip,
            format!("{}c/{}M", m.size.vcpus, m.size.memory_mb),
            m.size.cpu_millis(),
            m.sleep,
            egress_label(&m.egress),
            limits_label(&m.limits),
            disk_label(&m.disk_limits),
            backup_label(m.backup.as_ref()),
            pending,
            m.host
        ));
    }
    out
}

/// `machine snapshot ls`.
pub(super) fn snapshot_table(ss: &[api::Snapshot]) -> String {
    let mut out = format!(
        "{:<16} {:<20} {:<21} {:<10} MEMORY\n",
        "ID", "NAME", "CREATED", "DISKS"
    );
    for s in ss {
        out.push_str(&format!(
            "{:<16} {:<20} {:<21} {:<10} {}\n",
            s.id,
            s.name.as_deref().unwrap_or("-"),
            s.created_at.format("%Y-%m-%d %H:%M:%S"),
            s.disks.join(","),
            if s.memory { "yes" } else { "no" }
        ));
    }
    out
}

/// `endpoint ls`.
pub(super) fn endpoint_table(eps: &[api::Endpoint]) -> String {
    let mut out = format!(
        "{:<18} {:<16} {:<6} {:<9} ADDRESS\n",
        "ID", "MACHINE", "PORT", "PROTOCOL"
    );
    for e in eps {
        out.push_str(&format!(
            "{:<18} {:<16} {:<6} {:<9} {}\n",
            e.id, e.machine_id, e.port, e.protocol, e.address
        ));
    }
    out
}

/// `image ls`.
pub(super) fn image_table(ims: &[api::Image]) -> String {
    let mut out = format!(
        "{:<22} {:<40} {:<9} {:<21} DIGEST\n",
        "KEY", "REF", "MACHINES", "BUILT"
    );
    for i in ims {
        out.push_str(&format!(
            "{:<22} {:<40} {:<9} {:<21} {}\n",
            i.key,
            i.reference,
            i.machines,
            i.built_at.format("%Y-%m-%d %H:%M:%S"),
            &i.digest[..i.digest.len().min(19)]
        ));
    }
    out
}

/// `--public-tcp-ports`: `80,443,5432`, or `none` for no port.
pub(super) fn port_list(s: &str) -> Result<Vec<u16>> {
    if s == "none" {
        return Ok(vec![]);
    }
    s.split(',')
        .map(|p| {
            p.trim()
                .parse::<u16>()
                .ok()
                .filter(|&p| p > 0)
                .ok_or_else(|| {
                    anyhow!("--public-tcp-ports {s:?}: want ports, comma-separated, or none")
                })
        })
        .collect()
}

/// What `host upgrade --all` upgrades, in order: the ready and draining hosts by id; and the
/// others, with their state, which it leaves.
pub(super) fn upgrade_order(hs: &[api::Host]) -> (Vec<String>, Vec<(String, String)>) {
    let mut hs: Vec<&api::Host> = hs.iter().collect();
    hs.sort_by(|a, b| a.id.cmp(&b.id));
    let (up, left): (Vec<&api::Host>, Vec<&api::Host>) = hs
        .into_iter()
        .partition(|h| matches!(h.state.as_str(), "ready" | "draining"));
    (
        up.into_iter().map(|h| h.id.clone()).collect(),
        left.into_iter()
            .map(|h| (h.id.clone(), h.state.clone()))
            .collect(),
    )
}

/// `host ls`: a line per host, and under it its SSH address when it is not the API's, its pin,
/// each condition that is true and its note when the bootstrap or an upgrade left one.
pub(super) fn host_table(hs: &[api::Host]) -> String {
    let mut out = format!(
        "{:<16} {:<28} {:<12} {:<8} {:<14} {:<10} {:<9} {:<10} {:<20} {:<18} LAST SEEN\n",
        "ID",
        "URL",
        "STATE",
        "REGION",
        "MEMORY MB",
        "CPU m",
        "MACHINES",
        "NAMESPACES",
        "VERSION",
        "MEM POLICY"
    );
    for h in hs {
        out.push_str(&format!(
            "{:<16} {:<28} {:<12} {:<8} {:<14} {:<10} {:<9} {:<10} {:<20} {:<18} {}\n",
            h.id,
            if h.url.is_empty() { "-" } else { &h.url },
            h.state,
            if h.region.is_empty() { "-" } else { &h.region },
            format!("{}/{}", h.used.memory_mb, h.capacity.memory_mb),
            format!("{}/{}", h.used.cpu_millis(), h.capacity.cpu_millis()),
            h.machines,
            h.namespaces.len(),
            if h.version.is_empty() {
                "-"
            } else {
                &h.version
            },
            h.memory_policy.map_or_else(
                || "legacy".to_string(),
                |p| format!("v{}:+{}MB", p.version, p.vmm_overhead_mb)
            ),
            h.last_seen.to_rfc3339()
        ));
        if !h.ssh.is_empty() {
            out.push_str(&format!("{:<16} ssh: {}\n", "", h.ssh));
        }
        if !h.tls_fingerprint.is_empty() {
            out.push_str(&format!("{:<16} tls: {}\n", "", h.tls_fingerprint));
        }
        if !h.labels.is_empty() {
            let labels: Vec<String> = h.labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
            out.push_str(&format!("{:<16} labels: {}\n", "", labels.join(",")));
        }
        if !h.public_tcp_ports.is_empty() {
            let ports: Vec<String> = h.public_tcp_ports.iter().map(u16::to_string).collect();
            out.push_str(&format!("{:<16} public tcp: {}\n", "", ports.join(",")));
        }
        for c in h.conditions.iter().filter(|c| c.status) {
            out.push_str(&format!(
                "{:<16} {} since {}: {}\n",
                "",
                c.kind,
                c.since.format("%Y-%m-%d %H:%M:%S"),
                c.message
            ));
        }
        if !h.note.is_empty() {
            out.push_str(&format!("{:<16} note: {}\n", "", h.note));
        }
    }
    out
}

/// `host ls`'s summary: each region's room and the creates refused for want of it (ADR 0042).
/// A region no host is in has refusals only: `-` for its room.
pub(super) fn region_table(rs: &[api::RegionRoom]) -> String {
    let room = |r: Option<api::Room>| match r {
        Some(r) => format!("{}/{}", r.memory_mb, r.disk_mb),
        None => "-".into(),
    };
    if rs.is_empty() {
        return String::new();
    }
    let mut out = format!(
        "\n{:<8} {:<20} {:<20} UNSCHEDULABLE MEM/DISK/PRESSURE\n",
        "REGION", "FREE MB MEM/DISK", "LARGEST MB MEM/DISK"
    );
    for r in rs {
        let u = r.unschedulable;
        out.push_str(&format!(
            "{:<8} {:<20} {:<20} {}/{}/{}\n",
            if r.region.is_empty() { "-" } else { &r.region },
            room(r.free),
            room(r.largest_slot),
            u.memory,
            u.disk,
            u.pressure
        ));
    }
    out
}

/// `usage`: a line per machine and hour. Disk is the allocated root and volume; `--json` has
/// every measure.
pub(super) fn usage_table(bs: &[api::UsageBucket]) -> String {
    let mut out = format!(
        "{:<17} {:<16} {:<12} {:>7} {:>8} {:>9} {:>10} {:>12} {:>21} {:>21} HOST\n",
        "HOUR",
        "MACHINE",
        "NAMESPACE",
        "RUN H",
        "CPU S",
        "MEM GB·H",
        "DISK GB·H",
        "BACKUP GB·H",
        "INTERNET OUT/IN",
        "INGRESS OUT/IN"
    );
    for b in bs {
        let u = &b.usage;
        out.push_str(&format!(
            "{:<17} {:<16} {:<12} {:>7.2} {:>8.1} {:>9.2} {:>10.2} {:>12.2} {:>21} {:>21} {}\n",
            b.hour.format("%Y-%m-%d %H:00"),
            b.machine_id,
            b.namespace,
            u.running_seconds / 3600.0,
            u.cpu_seconds,
            u.memory_mb_seconds / 1024.0 / 3600.0,
            u.root_gb_hours + u.volume_gb_hours,
            u.backup_gb_hours,
            format!("{}/{}", u.internet_out_bytes, u.internet_in_bytes),
            format!("{}/{}", u.ingress_out_bytes, u.ingress_in_bytes),
            b.host
        ));
    }
    out
}

/// `top`: the busiest first. Memory is used/limit in MB, disk in MB, network in KB/s.
pub(super) fn top_table(mut ms: Vec<api::TopMachine>) -> String {
    ms.sort_by(|a, b| {
        b.cpu_percent
            .total_cmp(&a.cpu_percent)
            .then_with(|| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)))
    });
    let mb = |b: u64| b >> 20;
    let kb = |r: f64| r / 1024.0;
    let mut out = format!(
        "{:<16} {:<12} {:<14} {:>6} {:>13} {:>9} {:>17} {:>17} HOST\n",
        "MACHINE",
        "NAMESPACE",
        "NAME",
        "CPU %",
        "MEMORY MB",
        "DISK MB",
        "INTERNET IN/OUT",
        "INGRESS IN/OUT"
    );
    for m in &ms {
        out.push_str(&format!(
            "{:<16} {:<12} {:<14} {:>6.1} {:>13} {:>9} {:>17} {:>17} {}\n",
            m.machine_id,
            m.namespace,
            m.name,
            m.cpu_percent,
            format!("{}/{}", mb(m.memory_bytes), mb(m.memory_limit_bytes)),
            mb(m.disk_used_bytes),
            format!(
                "{:.1}/{:.1}",
                kb(m.internet_in_bytes_per_sec),
                kb(m.internet_out_bytes_per_sec)
            ),
            format!(
                "{:.1}/{:.1}",
                kb(m.ingress_in_bytes_per_sec),
                kb(m.ingress_out_bytes_per_sec)
            ),
            m.host
        ));
    }
    out
}

/// `events`: the header, then `event_row` per event.
pub(super) fn events_table(evs: &[api::Event]) -> String {
    let mut out = format!(
        "{:<19}  {:<7}  {:<15}  {:<14}  {:>5}  MESSAGE\n",
        "TIME", "TYPE", "REASON", "MACHINE", "COUNT"
    );
    for e in evs {
        out.push_str(&event_row(e));
    }
    out
}

/// An event's line; `TIME` is the last time of a line that folds repeats, the first in the
/// message.
pub(super) fn event_row(e: &api::Event) -> String {
    format!(
        "{:<19}  {:<7}  {:<15}  {:<14}  {:>5}  {}{}\n",
        e.at.format("%Y-%m-%d %H:%M:%S"),
        e.kind,
        e.reason,
        if e.machine_id.is_empty() {
            "-"
        } else {
            &e.machine_id
        },
        e.count,
        e.message,
        since_first(e)
    )
}

/// ` (x4 since 10:02:11)` for a line that folds repeats, as `kubectl describe` says it.
pub(super) fn since_first(e: &api::Event) -> String {
    match e.first_at {
        Some(t) => format!(" (x{} since {})", e.count, t.format("%H:%M:%S")),
        None => String::new(),
    }
}

/// `machine describe`: the machine as `kubectl describe` shows a pod, then its events.
pub(super) fn describe(m: &api::Machine, evs: &[api::Event]) -> String {
    let mut lines: Vec<(&str, String)> = vec![
        ("Name", m.name.clone()),
        ("ID", m.id.clone()),
        ("Namespace", m.namespace.clone()),
    ];
    if !m.host.is_empty() {
        lines.push(("Host", m.host.clone()));
    }
    lines.push(("Image", m.image.clone()));
    lines.push(("State", m.state.clone()));
    lines.push(("Ready", if m.ready { "yes" } else { "no" }.into()));
    if !reason_of(m).is_empty() {
        lines.push(("Reason", reason_of(m).into()));
    }
    if let Some(x) = &m.exit {
        let mut exit = format!("code {} at {}", x.code, x.at.format("%Y-%m-%d %H:%M:%S"));
        if x.oom_killed {
            exit.push_str(", out of memory");
        }
        if x.restarting {
            exit.push_str(", restarting");
        }
        lines.push(("Exit", exit));
    }
    if m.restarts > 0 || m.restarting_at.is_some() {
        let mut restarts = m.restarts.to_string();
        if let Some(t) = m.restarting_at {
            restarts.push_str(&format!(", next at {}", t.format("%Y-%m-%d %H:%M:%S")));
        }
        lines.push(("Restarts", restarts));
    }
    if !m.error.is_empty() {
        lines.push(("Error", m.error.clone()));
    }
    let probes: Vec<String> = [
        ("startup", &m.probes.startup, &m.probes_status.startup),
        ("readiness", &m.probes.readiness, &m.probes_status.readiness),
        ("liveness", &m.probes.liveness, &m.probes_status.liveness),
    ]
    .into_iter()
    .filter_map(|(name, p, st)| p.as_ref().map(|p| probe_line(name, p, st.as_ref())))
    .collect();
    if !probes.is_empty() {
        lines.push(("Probes", probes.join(&format!("\n{:15}", ""))));
    }
    lines.push(("IP", m.ip.clone()));
    lines.push((
        "Size",
        format!("{} vCPU, {} MB", m.size.vcpus, m.size.memory_mb),
    ));
    lines.push(("CPU limit", format!("{}m", m.size.cpu_millis())));
    if let Some(v) = &m.volume {
        lines.push(("Volume", format!("{} GB at {}", v.size_gb, v.mount)));
    }
    let d = &m.disk_limits;
    let disk = match disk_label(d).as_str() {
        "-" => "none".to_string(),
        l => format!("{l} each, {}s burst", d.burst_sec.unwrap_or(0)),
    };
    lines.push(("Disk limits", disk));
    lines.push(("Egress", egress_label(&m.egress)));
    // What runs it (ADR 0027): the init its root disk carries, the VMM of its last boot.
    if !m.init_version.is_empty() || !m.vmm_version.is_empty() {
        let or_unknown = |v: &str| {
            if v.is_empty() {
                "unknown".to_string()
            } else {
                v.to_string()
            }
        };
        lines.push((
            "Runs on",
            format!(
                "init {}, vmm {}",
                or_unknown(&m.init_version),
                or_unknown(&m.vmm_version)
            ),
        ));
    }
    let endpoints: Vec<String> = m
        .endpoints
        .iter()
        .map(|e| format!("{} {} {} -> {}", e.id, e.protocol, e.port, e.address))
        .collect();
    lines.push((
        "Endpoints",
        match endpoints.is_empty() {
            true => "none".into(),
            false => endpoints.join(&format!("\n{:15}", "")),
        },
    ));
    let sleep = match m.sleeps_at {
        Some(t) => format!("{}, sleeps at {}", m.sleep, t.format("%Y-%m-%d %H:%M:%S")),
        None => m.sleep.clone(),
    };
    lines.push(("Sleep", sleep));
    let at = |t: Option<chrono::DateTime<chrono::Utc>>| match t {
        Some(t) => t.format("%Y-%m-%d %H:%M:%S").to_string(),
        None => "none".into(),
    };
    let backup = match (&m.backup, m.last_backup_at) {
        (Some(p), last) => format!(
            "every {}, keep {}; last {}, next {}",
            p.every,
            p.keep,
            at(last),
            at(m.next_backup_at)
        ),
        (None, Some(last)) => format!("none; last {}", at(Some(last))),
        (None, None) => "none".into(),
    };
    lines.push(("Backup", backup));
    if let Some(p) = &m.pending {
        // Each field, with its new value when the view shows one.
        let changes: Vec<String> = p
            .fields
            .iter()
            .map(|f| match (f.as_str(), &p.image, p.size, p.volume) {
                ("image", Some(image), _, _) => format!("image {image}"),
                ("size", _, Some(s), _) => format!("size {} vCPU, {} MB", s.vcpus, s.memory_mb),
                ("volume", _, _, Some(v)) => format!("volume's filesystem to {} GB", v.size_gb),
                _ => f.clone(),
            })
            .collect();
        let mut pending = format!("{}, at the next start", changes.join(", "));
        if let Some(t) = m.pending_since {
            pending.push_str(&format!(" (since {})", t.format("%Y-%m-%d %H:%M:%S")));
        }
        lines.push(("Pending", pending));
    }
    lines.push(("Version", m.version.to_string()));
    lines.push((
        "Created",
        m.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
    ));
    let mut out = String::new();
    for (k, v) in lines {
        out.push_str(&format!("{:<15}{v}\n", format!("{k}:")));
    }
    out.push_str("Events:\n");
    if evs.is_empty() {
        out.push_str("  none\n");
    }
    for e in evs {
        out.push_str(&format!(
            "  {}  {:<7}  {:<15}  {}{}\n",
            e.at.format("%Y-%m-%d %H:%M:%S"),
            e.kind,
            e.reason,
            e.message,
            since_first(e)
        ));
    }
    out
}

/// A probe as `describe` shows it: what it checks, how often, and its last result.
pub(super) fn probe_line(name: &str, p: &api::Probe, st: Option<&api::ProbeStatus>) -> String {
    let last = match st {
        None => "not run yet".to_string(),
        Some(s) if s.passed => format!("passed ({})", s.message),
        Some(s) => format!("failed {} in a row ({})", s.failures, s.message),
    };
    format!("{name} {}, every {} s: {last}", p.target(), p.period_sec)
}
