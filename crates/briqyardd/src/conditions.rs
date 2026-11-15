//! The host's conditions (ADR 0021): memory and disk pressure, decided by the tick on what it
//! measured, and a stalled pool (ADR 0046). Each is a pressure: true is trouble. A probe of a
//! local service (ADR 0133) is a condition too, with the effect `avoid`: not a refusal.

use crate::config;
use crate::zfs::Pool;
use briqyard_api::{self as api, condition};
use chrono::{DateTime, Utc};

const GB: f64 = (1u64 << 30) as f64;

/// The conditions as the tick last decided them.
#[derive(Clone, Debug)]
pub struct Conditions {
    list: Vec<api::Condition>,
}

impl Conditions {
    /// Every condition false since `now`: the daemon's start, until a tick says otherwise.
    /// A probe's condition is listed from the start, as `avoid`.
    pub fn new(now: DateTime<Utc>, probes: &[config::Probe]) -> Self {
        let probed = probes.iter().map(|p| api::Condition {
            kind: p.name.clone(),
            status: false,
            since: now,
            message: "not measured yet".into(),
            effect: Some(api::ConditionEffect::Avoid),
        });
        Self {
            list: condition::ALL
                .iter()
                // Live process protection and fleet holds are derived separately.
                .filter(|k| {
                    ![condition::MEMORY_PROTECTION, condition::MEMORY_ACCOUNTING].contains(k)
                })
                .map(|k| api::Condition {
                    kind: k.to_string(),
                    status: false,
                    since: now,
                    message: "not measured yet".into(),
                    effect: None,
                })
                .chain(probed)
                .collect(),
        }
    }

    pub fn list(&self) -> Vec<api::Condition> {
        self.list.clone()
    }

    /// Sets a condition to what the tick found: the message always, `since` when the status
    /// changed. Returns the condition when it did.
    pub fn set(
        &mut self,
        kind: &str,
        (status, message): (bool, String),
        now: DateTime<Utc>,
    ) -> Option<api::Condition> {
        let c = self.list.iter_mut().find(|c| c.kind == kind)?;
        c.message = message;
        if c.status == status {
            return None;
        }
        c.status = status;
        c.since = now;
        Some(c.clone())
    }
}

/// `memory_pressure`: what running machines reserved over `memory_pct` of capacity.
pub fn memory(committed_mb: u32, capacity_mb: u32, t: &config::Conditions) -> (bool, String) {
    let (used, cap) = (committed_mb as u64, capacity_mb.max(1) as u64);
    let pct = used * 100 / cap;
    let over = used * 100 > t.memory_pct as u64 * cap;
    let mut msg = format!("{used} MB of {cap} committed ({pct}%)");
    if over {
        msg.push_str(&format!(", over {}%", t.memory_pct));
    }
    (over, msg)
}

/// What the pool lacks to be back at `disk_free_pct` free, in bytes; 0 when it is there.
pub fn disk_short(pool: Pool, t: &config::Conditions) -> u64 {
    (pool.size() * t.disk_free_pct as u64)
        .div_ceil(100)
        .saturating_sub(pool.free)
}

/// `disk_pressure`: the pool's free space under `disk_free_pct` of its size.
pub fn disk(pool: Pool, t: &config::Conditions) -> (bool, String) {
    let under = disk_short(pool, t) > 0;
    let pct = pool.free * 100 / pool.size().max(1);
    let mut msg = format!(
        "pool {:.1} GB free of {:.1} ({pct}%)",
        pool.free as f64 / GB,
        pool.size() as f64 / GB
    );
    if under {
        msg.push_str(&format!(", under {}%", t.disk_free_pct));
    }
    (under, msg)
}

/// `storage_stalled`: a `zfs` command has run past `zfs::STALL_AFTER` (ADR 0046), the oldest.
pub fn storage(stalled: Option<(std::time::Duration, String)>) -> (bool, String) {
    match stalled {
        Some((ran, what)) => (true, format!("{what} running for {} s", ran.as_secs())),
        None => (
            false,
            format!(
                "no zfs command running for over {} s",
                crate::zfs::STALL_AFTER.as_secs()
            ),
        ),
    }
}

/// What a probe has seen: its misses in a row.
#[derive(Debug, Default)]
pub struct ProbeRun {
    misses: u32,
}

impl ProbeRun {
    /// Takes one answer: true after `failures` misses in a row, false on the first success. The
    /// message says what was asked and what went wrong, never what came back.
    pub fn observe(&mut self, p: &config::Probe, answer: Result<(), String>) -> (bool, String) {
        match answer {
            Ok(()) => {
                self.misses = 0;
                (false, format!("GET {} answered 200", p.http))
            }
            Err(why) => {
                self.misses = self.misses.saturating_add(1);
                let msg = format!(
                    "GET {}: {why}, {} of {} misses",
                    p.http,
                    self.misses.min(p.failures),
                    p.failures
                );
                (self.misses >= p.failures, msg)
            }
        }
    }
}

/// The client of the probes: a redirect is a miss, and one probe waits `timeout_sec` at most.
pub fn probe_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("http client")
}

/// Asks the service once: a 200 is up, anything else says why not.
pub async fn probe_once(client: &reqwest::Client, p: &config::Probe) -> Result<(), String> {
    let sent = client
        .get(&p.http)
        .timeout(std::time::Duration::from_secs(p.timeout_sec))
        .send()
        .await;
    match sent {
        Ok(r) if r.status() == reqwest::StatusCode::OK => Ok(()),
        Ok(r) => Err(format!("answered {}", r.status().as_u16())),
        Err(e) if e.is_timeout() => Err(format!("no answer in {} s", p.timeout_sec)),
        Err(e) if e.is_connect() => Err("connection failed".into()),
        Err(_) => Err("request failed".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    const DEFAULT: config::Conditions = config::Conditions {
        memory_pct: 95,
        disk_free_pct: 10,
        probes: Vec::new(),
    };

    #[test]
    fn memory_is_under_pressure_over_its_share() {
        assert_eq!(
            memory(950, 1000, &DEFAULT),
            (false, "950 MB of 1000 committed (95%)".into())
        );
        assert_eq!(
            memory(951, 1000, &DEFAULT),
            (true, "951 MB of 1000 committed (95%), over 95%".into())
        );
        // A host with no capacity is never divided by zero.
        assert!(memory(1, 0, &DEFAULT).0);
    }

    #[test]
    fn disk_is_under_pressure_under_its_free_share() {
        let gb = 1u64 << 30;
        let pool = |used: u64, free: u64| Pool {
            used: used * gb,
            free: free * gb,
        };
        assert_eq!(
            disk(pool(90, 10), &DEFAULT),
            (false, "pool 10.0 GB free of 100.0 (10%)".into())
        );
        assert_eq!(disk_short(pool(90, 10), &DEFAULT), 0);
        assert_eq!(
            disk(pool(92, 8), &DEFAULT),
            (true, "pool 8.0 GB free of 100.0 (8%), under 10%".into())
        );
        // What image removal has to free: back to 10 GB.
        assert_eq!(disk_short(pool(92, 8), &DEFAULT), 2 * gb);
        // A byte short is short.
        let p = Pool {
            used: 90 * gb + 1,
            free: 10 * gb - 1,
        };
        assert_eq!(disk_short(p, &DEFAULT), 1);
        // 0% never presses.
        let none = config::Conditions {
            disk_free_pct: 0,
            ..DEFAULT
        };
        assert!(!disk(pool(100, 0), &none).0);
    }

    #[test]
    fn storage_is_stalled_by_its_oldest_command() {
        let ran = std::time::Duration::from_secs(75);
        assert_eq!(
            storage(Some((ran, "zfs snapshot byard/m/m_1/root@fork-x".into()))),
            (
                true,
                "zfs snapshot byard/m/m_1/root@fork-x running for 75 s".into()
            )
        );
        assert_eq!(
            storage(None),
            (false, "no zfs command running for over 60 s".into())
        );
    }

    #[test]
    fn a_condition_changes_once_and_keeps_its_message_fresh() {
        let mut c = Conditions::new(t("2026-10-21T10:00:00Z"), &[]);
        assert_eq!(api::under_pressure(&c.list()), None);
        assert_eq!(c.list().len(), 3);
        // The same status: no change, the message follows the figures.
        let same = c.set(
            condition::DISK_PRESSURE,
            (false, "pool 50% free".into()),
            t("2026-10-21T10:00:15Z"),
        );
        assert_eq!(same, None);
        assert_eq!(c.list()[1].message, "pool 50% free");
        assert_eq!(c.list()[1].since, t("2026-10-21T10:00:00Z"));
        let on = c
            .set(
                condition::DISK_PRESSURE,
                (true, "pool 5% free".into()),
                t("2026-10-21T10:00:30Z"),
            )
            .unwrap();
        assert_eq!(
            (on.kind.as_str(), on.status, on.since),
            ("disk_pressure", true, t("2026-10-21T10:00:30Z"))
        );
        assert_eq!(
            api::under_pressure(&c.list()).map(|c| c.kind.as_str()),
            Some(condition::DISK_PRESSURE)
        );
        assert!(!c.list()[0].status, "memory as it was");
        let off = c
            .set(
                condition::DISK_PRESSURE,
                (false, "pool 20% free".into()),
                t("2026-10-21T10:01:00Z"),
            )
            .unwrap();
        assert!(!off.status);
        assert_eq!(
            c.set("pid_pressure", (true, String::new()), Utc::now()),
            None
        );
    }

    fn probe(failures: u32) -> config::Probe {
        config::Probe {
            name: "registry".into(),
            http: "http://127.0.0.1:5000/v2/".into(),
            failures,
            ..Default::default()
        }
    }

    #[test]
    fn a_probe_is_true_after_its_misses_in_a_row_and_false_on_one_success() {
        let p = probe(3);
        let mut run = ProbeRun::default();
        let miss = || Err("connection failed".to_string());
        assert!(!run.observe(&p, miss()).0);
        let (on, msg) = run.observe(&p, miss());
        assert!(!on);
        assert_eq!(
            msg,
            "GET http://127.0.0.1:5000/v2/: connection failed, 2 of 3 misses"
        );
        // A success in between starts the count again.
        assert!(!run.observe(&p, Ok(())).0);
        assert!(!run.observe(&p, miss()).0);
        assert!(!run.observe(&p, miss()).0);
        assert!(run.observe(&p, miss()).0);
        assert!(run.observe(&p, Err("answered 503".into())).0);
        let (on, msg) = run.observe(&p, Ok(()));
        assert!(!on);
        assert_eq!(msg, "GET http://127.0.0.1:5000/v2/ answered 200");
    }

    #[test]
    fn a_probe_condition_is_listed_as_avoid_and_is_not_a_pressure() {
        let mut c = Conditions::new(t("2026-11-15T10:00:00Z"), &[probe(1)]);
        let listed = c.list();
        assert_eq!(listed.len(), 4);
        let mine = listed.iter().find(|c| c.kind == "registry").unwrap();
        assert_eq!(mine.effect, Some(api::ConditionEffect::Avoid));
        let on = c
            .set("registry", (true, "down".into()), t("2026-11-15T10:00:15Z"))
            .unwrap();
        assert!(on.status);
        assert_eq!(api::under_pressure(&c.list()), None);
        assert!(api::avoided(&c.list()));
    }

    /// Answers each connection with the next canned reply, or none to hang up.
    async fn serve(replies: Vec<Option<&'static str>>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/health", listener.local_addr().unwrap());
        tokio::spawn(async move {
            for reply in replies {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf).await;
                if let Some(r) = reply {
                    let _ = s.write_all(r.as_bytes()).await;
                }
            }
        });
        url
    }

    #[tokio::test]
    async fn the_probe_asks_over_http_and_reports_what_failed() {
        let ok = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok";
        let down = "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 6\r\nconnection: close\r\n\r\nsecret";
        let moved = "HTTP/1.1 302 Found\r\nlocation: http://127.0.0.1:1/\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
        let url = serve(vec![Some(ok), Some(down), Some(moved), None]).await;
        let p = config::Probe {
            http: url,
            timeout_sec: 2,
            ..probe(2)
        };
        let client = probe_client();
        assert_eq!(probe_once(&client, &p).await, Ok(()));
        assert_eq!(
            probe_once(&client, &p).await,
            Err("answered 503".to_string())
        );
        assert_eq!(
            probe_once(&client, &p).await,
            Err("answered 302".to_string())
        );
        assert_eq!(
            probe_once(&client, &p).await,
            Err("request failed".to_string())
        );
        // Nothing listens: the connection fails.
        let gone = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}/", l.local_addr().unwrap())
        };
        let p = config::Probe { http: gone, ..p };
        assert_eq!(
            probe_once(&client, &p).await,
            Err("connection failed".to_string())
        );
    }
}
