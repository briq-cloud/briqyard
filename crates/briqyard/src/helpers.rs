//! Argument parsers, request paths and the labels the tables print.

use super::*;

/// `backup rm`'s request.
pub(super) fn backup_rm_path(
    machine: &str,
    backup: &str,
    chain: bool,
    namespace: Option<&str>,
) -> String {
    let mut q = Vec::new();
    if chain {
        q.push("chain=true".to_string());
    }
    if let Some(t) = namespace {
        q.push(format!("namespace={t}"));
    }
    let path = format!("/v1/machines/{machine}/backups/{backup}");
    match q.is_empty() {
        true => path,
        false => format!("{path}?{}", q.join("&")),
    }
}

/// `-e K=V` flags as an env map; a value may hold `=`.
pub(super) fn env_args(kvs: &[String]) -> Result<BTreeMap<String, String>> {
    let mut env = BTreeMap::new();
    for kv in kvs {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| anyhow!("--env {kv:?}: want K=V"))?;
        env.insert(k.to_string(), v.to_string());
    }
    Ok(env)
}

/// `--label K=V`: metadata that `machine ls -l` selects on, so checked as a label is.
pub(super) fn label_args(kvs: &[String]) -> Result<BTreeMap<String, String>> {
    kvs.iter()
        .map(|kv| match api::Label::parse(kv) {
            Ok(api::Label {
                key,
                value: Some(v),
            }) => Ok((key, v)),
            Ok(_) => bail!("--label {kv:?}: want K=V"),
            Err(e) => bail!("--label: {e}"),
        })
        .collect()
}

/// `--file /guest/path=local/path` flags as boot files, read now.
pub(super) fn file_args(specs: &[String]) -> Result<Vec<api::File>> {
    let mut files = Vec::new();
    for f in specs {
        let (guest_path, local) = f
            .split_once('=')
            .ok_or_else(|| anyhow!("--file {f:?}: want /guest/path=local/path"))?;
        let data = std::fs::read(local).with_context(|| local.to_string())?;
        files.push(api::File {
            path: guest_path.to_string(),
            base64: api::guest::base64_encode(&data),
            mode: None,
        });
    }
    Ok(files)
}

/// A restart policy, Docker's way: `no`, `always`, `on-failure`, `on-failure:N` (3 retries
/// when no N is given, as the API's default).
pub(super) fn restart_arg(s: &str) -> Result<api::RestartPolicy, String> {
    let (policy, retries) = match s.split_once(':') {
        Some(("on-failure", n)) => (
            "on-failure",
            n.parse()
                .map_err(|_| format!("{s:?}: want on-failure:MAX_RETRIES"))?,
        ),
        Some(_) => return Err(format!("{s:?}: only on-failure takes :MAX_RETRIES")),
        None => (s, api::RestartPolicy::default().max_retries),
    };
    if !["no", "on-failure", "always"].contains(&policy) {
        return Err(format!(
            "{s:?}: want no, always, on-failure or on-failure:N"
        ));
    }
    Ok(api::RestartPolicy {
        policy: policy.into(),
        max_retries: retries,
    })
}

/// A sleep window as the daemon reads it, refused here before the request leaves.
pub(super) fn sleep_arg(s: &str) -> Result<String, String> {
    api::parse_sleep(s)?;
    Ok(s.to_string())
}

/// A probe with the API's timings: `http:PORT[/PATH]`, `tcp:PORT` or `exec:CMD ARGS` (the
/// command split on spaces), checked as the daemon checks it.
pub(super) fn probe_arg(s: &str) -> Result<api::Probe, String> {
    let bad = || format!("{s:?}: want http:PORT[/PATH], tcp:PORT or exec:CMD ARGS");
    let port = |p: &str| p.parse::<u16>().map_err(|_| bad());
    let mut p = api::Probe::default();
    match s.split_once(':').ok_or_else(bad)? {
        ("exec", cmd) => p.exec = Some(cmd.split_whitespace().map(String::from).collect()),
        ("tcp", at) => p.tcp = Some(port(at)?),
        ("http", at) => {
            let (at, path) = match at.find('/') {
                Some(i) => at.split_at(i),
                None => (at, "/"),
            };
            p.http = Some(api::HttpProbe {
                port: port(at)?,
                path: path.into(),
            });
        }
        _ => return Err(bad()),
    }
    p.check("probe", false)?;
    Ok(p)
}

/// An egress policy, `open`, `none` or `via:MACHINE_ID` (`via:gateway`), checked as the daemon
/// checks it.
pub(super) fn egress_arg(s: &str) -> Result<api::Egress, String> {
    let (s, siblings) = s
        .strip_suffix("+siblings")
        .map_or((s, false), |s| (s, true));
    let e = match s.split_once(':') {
        Some((api::egress::VIA, id)) => api::Egress {
            mode: api::egress::VIA.into(),
            via: Some(id.into()),
            siblings,
        },
        _ => api::Egress {
            mode: s.into(),
            via: None,
            siblings,
        },
    };
    e.check()?;
    Ok(e)
}

/// A moment in RFC 3339, as UTC; whether it is on the hour is the server's to say.
pub(super) fn hour_arg(s: &str) -> Result<chrono::DateTime<chrono::Utc>, String> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&chrono::Utc))
        .map_err(|_| format!("{s:?}: want RFC 3339, like 2026-10-20T14:00:00Z"))
}

/// `GET /v1/usage` for a range, in UTC so the query needs no escaping.
pub(super) fn usage_path(
    from: chrono::DateTime<chrono::Utc>,
    to: chrono::DateTime<chrono::Utc>,
    namespace: Option<&str>,
) -> String {
    let utc = |t: chrono::DateTime<chrono::Utc>| t.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let mut p = format!("/v1/usage?from={}&to={}", utc(from), utc(to));
    if let Some(t) = namespace {
        p.push_str(&format!("&namespace={t}"));
    }
    p
}

/// `GET /v1/events` for a namespace, a machine, both or neither.
/// `/v1/backups`, of a namespace, of a machine, or of every one.
pub(super) fn backups_path(namespace: Option<&str>, machine: Option<&str>) -> String {
    let q: Vec<String> = [("namespace", namespace), ("machine", machine)]
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| format!("{k}={v}")))
        .collect();
    match q.is_empty() {
        true => "/v1/backups".into(),
        false => format!("/v1/backups?{}", q.join("&")),
    }
}

pub(super) fn events_path(namespace: Option<&str>, machine: Option<&str>, watch: bool) -> String {
    let mut q = Vec::new();
    if let Some(t) = namespace {
        q.push(format!("namespace={t}"));
    }
    if let Some(m) = machine {
        q.push(format!("machine={m}"));
    }
    if watch {
        q.push("watch=true".into());
    }
    match q.is_empty() {
        true => "/v1/events".into(),
        false => format!("/v1/events?{}", q.join("&")),
    }
}

/// A path with `since` added; none when the cursor is empty.
pub(super) fn with_since(path: &str, since: &str) -> String {
    match (since.is_empty(), path.contains('?')) {
        (true, _) => path.into(),
        (false, true) => format!("{path}&since={since}"),
        (false, false) => format!("{path}?since={since}"),
    }
}

/// An egress policy as `egress_arg` reads it.
pub(super) fn egress_label(e: &api::Egress) -> String {
    e.label()
}

/// The limits in force, short: the blocked ports, the rate, the cap (`25,465 600/min
/// 100Mbit`); `-` when nothing is limited.
pub(super) fn limits_label(l: &api::EgressLimits) -> String {
    let mut parts = Vec::new();
    let ports = l.blocked_ports.as_deref().unwrap_or_default();
    if !ports.is_empty() {
        let ports: Vec<String> = ports.iter().map(u16::to_string).collect();
        parts.push(ports.join(","));
    }
    if let Some(n) = l.new_connections_per_minute.filter(|n| *n > 0) {
        parts.push(format!("{n}/min"));
    }
    if let Some(n) = l.bandwidth_mbit.filter(|n| *n > 0) {
        parts.push(format!("{n}Mbit"));
    }
    if parts.is_empty() {
        "-".into()
    } else {
        parts.join(" ")
    }
}

/// The disk limits in force, short: `32MB/s 4000io` (the burst in `describe`); `-` when
/// nothing is limited.
pub(super) fn disk_label(l: &api::DiskLimits) -> String {
    let mut parts = Vec::new();
    if let Some(n) = l.bandwidth_mb.filter(|n| *n > 0) {
        parts.push(format!("{n}MB/s"));
    }
    if let Some(n) = l.iops.filter(|n| *n > 0) {
        parts.push(format!("{n}io"));
    }
    if parts.is_empty() {
        "-".into()
    } else {
        parts.join(" ")
    }
}

/// A backup schedule in a table: `6h/4` (every, keep), `-` for none.
pub(super) fn backup_label(p: Option<&api::BackupPolicy>) -> String {
    match p {
        Some(p) => format!("{}/{}", p.every, p.keep),
        None => "-".into(),
    }
}

pub(super) fn suffix() -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:04}", n % 10000)
}
