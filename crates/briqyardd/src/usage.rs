//! Usage (ADR 0017): what each machine used, per UTC hour, measured by the sleeper's tick and
//! kept on the host. Measures only, never a price.
//!
//! A machine's `Meter` accrues time in its state up to now (at every state change and every
//! tick) and adds what its counters grew by; the tick drains it into the `Ledger`, which holds
//! the hours not closed yet, writes them once a minute and closes each hour once it is over.

use crate::netw::nft::Counters;
use crate::store::Store;
use anyhow::Result;
use briqyard_api::{EgressDrops, Usage, UsageBucket};
use chrono::{DateTime, Duration, DurationRound, Utc};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// A GB, as disk sizes count it.
const GB: f64 = (1u64 << 30) as f64;
/// The store kind: one file per hour, holding that hour's buckets.
const KIND: &str = "usage";
/// The open hours are written this often.
const WRITE_EVERY: Duration = Duration::seconds(60);
/// The longest range one read covers.
const MAX_RANGE: Duration = Duration::days(31);

/// The UTC hour a moment falls in.
pub fn hour_of(t: DateTime<Utc>) -> DateTime<Utc> {
    t.duration_trunc(Duration::hours(1)).unwrap_or(t)
}

/// An hour's store key; keys sort as their hours do.
fn key(hour: DateTime<Utc>) -> String {
    hour.format("%Y-%m-%dT%H").to_string()
}

/// What a machine holds while its state stays as it is.
#[derive(Clone, Copy, Debug, Default)]
pub struct Held {
    /// It has a process, which holds its memory.
    pub running: bool,
    /// Stopped with a memory snapshot.
    pub suspended: bool,
    pub memory_mb: u32,
}

/// What a machine's disks take, in bytes, as last measured: what disk hours accrue at until
/// the next measure.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Disks {
    /// Allocated sizes.
    pub root: u64,
    pub volume: u64,
    /// What the datasets' blocks take.
    pub used: u64,
    /// Local snapshots and the memory snapshot.
    pub snapshots: u64,
    /// The machine's backups in the object store.
    pub backups: u64,
}

/// Bytes through the host's endpoints, added by the proxy as they pass and taken by the tick:
/// a long connection lands in the hours it ran, and one cut short still counts.
#[derive(Debug, Default)]
pub struct Traffic {
    from_client: AtomicU64,
    to_client: AtomicU64,
}

impl Traffic {
    pub fn received(&self, n: u64) {
        self.from_client.fetch_add(n, Relaxed);
    }
    pub fn sent(&self, n: u64) {
        self.to_client.fetch_add(n, Relaxed);
    }
    /// `(in, out)` since the last take.
    pub fn take(&self) -> (u64, u64) {
        (
            self.from_client.swap(0, Relaxed),
            self.to_client.swap(0, Relaxed),
        )
    }
}

/// One machine's measure since the tick last drained it, and its readings as of the last
/// tick: what `/metrics` and `top` show (ADR 0021).
#[derive(Debug)]
pub struct Meter {
    /// Time is accrued up to here.
    pub at: DateTime<Utc>,
    pub disks: Disks,
    /// The cgroup's CPU time when last read; none until the first read after the daemon
    /// starts, which is where an adopted machine's count starts.
    cpu_usec: Option<u64>,
    /// The host's counters when last read. They start at zero with the meter: the daemon
    /// renders them afresh at start, and a create adds them.
    net: Counters,
    /// Packets its egress limits dropped since it booted, as last read.
    drops: EgressDrops,
    /// What it used since the last drain, by hour.
    pending: BTreeMap<DateTime<Utc>, Usage>,
    /// What `counters` added since the meter was made (the counter fields only): the totals
    /// of `/metrics`, counting from the daemon's start as the counters do.
    counted: Usage,
    /// `counted` at the last two ticks, the newest second: the window of `top`'s rates.
    readings: [Option<(DateTime<Utc>, Usage)>; 2],
    /// Memory its cgroup held at the last tick; 0 without one.
    pub memory_bytes: u64,
    /// How long its last start took, `starting` to `running`.
    pub boot_seconds: Option<f64>,
    /// Restarts by its policy since the daemon started.
    pub restarts: u64,
}

/// What a machine's counters grew by per second between the last two ticks. All zero until
/// there are two.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Rates {
    pub window_sec: f64,
    /// Of one CPU.
    pub cpu_percent: f64,
    pub internet_in: f64,
    pub internet_out: f64,
    pub ingress_in: f64,
    pub ingress_out: f64,
}

impl Meter {
    pub fn new(at: DateTime<Utc>) -> Self {
        Self {
            at,
            disks: Disks::default(),
            cpu_usec: None,
            net: Counters::default(),
            drops: EgressDrops::default(),
            pending: BTreeMap::new(),
            counted: Usage::default(),
            readings: [None, None],
            memory_bytes: 0,
            boot_seconds: None,
            restarts: 0,
        }
    }

    /// What its counters added up to since the daemon started, as of the last tick.
    pub fn counted(&self) -> Usage {
        self.counted
    }

    /// The rates between the last two ticks.
    pub fn rates(&self) -> Rates {
        let [Some((t0, a)), Some((t1, b))] = self.readings else {
            return Rates::default();
        };
        let secs = (t1 - t0).num_microseconds().unwrap_or(0) as f64 / 1e6;
        if secs <= 0.0 {
            return Rates::default();
        }
        let per = |x: u64, y: u64| y.saturating_sub(x) as f64 / secs;
        Rates {
            window_sec: secs,
            cpu_percent: (b.cpu_seconds - a.cpu_seconds) * 100.0 / secs,
            internet_in: per(a.internet_in_bytes, b.internet_in_bytes),
            internet_out: per(a.internet_out_bytes, b.internet_out_bytes),
            ingress_in: per(a.ingress_in_bytes, b.ingress_in_bytes),
            ingress_out: per(a.ingress_out_bytes, b.ingress_out_bytes),
        }
    }

    /// Accrues the time from `at` to `now`, held as `h`, to the hours each second fell in.
    pub fn advance(&mut self, now: DateTime<Utc>, h: Held) {
        let mut t = self.at;
        while t < now {
            let hour = hour_of(t);
            let end = (hour + Duration::hours(1)).min(now);
            let secs = (end - t).num_microseconds().unwrap_or(0) as f64 / 1e6;
            let u = self.pending.entry(hour).or_default();
            if h.running {
                u.running_seconds += secs;
                u.memory_mb_seconds += h.memory_mb as f64 * secs;
            }
            if h.suspended {
                u.suspended_seconds += secs;
            }
            let gb_hours = |bytes: u64| bytes as f64 / GB * secs / 3600.0;
            u.root_gb_hours += gb_hours(self.disks.root);
            u.volume_gb_hours += gb_hours(self.disks.volume);
            u.disk_used_gb_hours += gb_hours(self.disks.used);
            u.snapshot_gb_hours += gb_hours(self.disks.snapshots);
            u.backup_gb_hours += gb_hours(self.disks.backups);
            t = end;
        }
        self.at = self.at.max(now);
    }

    /// A process is about to start: its CPU time counts from what the cgroup holds now (0
    /// when it has none yet), its drops from none.
    pub fn boot(&mut self, cpu_usec: u64) {
        self.cpu_usec = Some(cpu_usec);
        self.drops = EgressDrops::default();
    }

    /// Packets its egress limits dropped since it booted (or the daemon started), as of the
    /// last reading.
    pub fn drops(&self) -> EgressDrops {
        self.drops
    }

    /// Adds what the counters grew by since they were last read to the hour of `now` and to
    /// the totals, and takes a reading: the cgroup's CPU time and the host's counters when
    /// they could be read, and the endpoints' bytes, `(in, out)`.
    pub fn counters(
        &mut self,
        now: DateTime<Utc>,
        cpu_usec: Option<u64>,
        net: Option<Counters>,
        ingress: (u64, u64),
    ) {
        let mut u = Usage::default();
        if let Some(c) = cpu_usec {
            if let Some(last) = self.cpu_usec {
                u.cpu_seconds += grown(last, c) as f64 / 1e6;
            }
            self.cpu_usec = Some(c);
        }
        if let Some(n) = net {
            let (last, d) = (self.net.dropped, n.dropped);
            let dropped = EgressDrops {
                blocked_port: grown(last.blocked_port, d.blocked_port),
                rate: grown(last.rate, d.rate),
                bandwidth: grown(last.bandwidth, d.bandwidth),
            };
            u.internet_in_bytes += grown(self.net.internet_in, n.internet_in);
            u.internet_out_bytes += grown(self.net.internet_out, n.internet_out);
            u.egress_dropped_packets += dropped.total();
            self.drops.blocked_port += dropped.blocked_port;
            self.drops.rate += dropped.rate;
            self.drops.bandwidth += dropped.bandwidth;
            self.net = n;
        }
        u.ingress_in_bytes += ingress.0;
        u.ingress_out_bytes += ingress.1;
        self.pending.entry(hour_of(now)).or_default().add(&u);
        self.counted.add(&u);
        self.readings = [self.readings[1], Some((now, self.counted))];
    }

    /// What it used since the last drain, by hour.
    pub fn drain(&mut self) -> BTreeMap<DateTime<Utc>, Usage> {
        std::mem::take(&mut self.pending)
    }
}

/// What a counter added since it read `last`: a smaller value is a counter that began again
/// (a new cgroup, a table rendered afresh), and all of it is new.
fn grown(last: u64, now: u64) -> u64 {
    if now >= last {
        now - last
    } else {
        now
    }
}

/// The bytes files take on their filesystem; a missing one takes none.
pub fn file_bytes(paths: &[PathBuf]) -> u64 {
    use std::os::unix::fs::MetadataExt;
    paths
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.blocks() * 512)
        .sum()
}

/// The hours not closed yet, each with its machines' buckets: what the tick adds to, the API
/// reads first and the store holds once a minute.
#[derive(Debug, Default)]
pub struct Ledger {
    hours: BTreeMap<DateTime<Utc>, BTreeMap<String, UsageBucket>>,
    /// The first hour still open: use measured for an earlier one lands here, so a closed
    /// hour never changes.
    open: DateTime<Utc>,
    written: Option<DateTime<Utc>>,
    /// The hour retention last ran in.
    pruned: Option<DateTime<Utc>>,
}

impl Ledger {
    /// Reads back what a previous daemon left: the hour of `now` goes on from its file, and
    /// an earlier hour it left open is closed now.
    pub fn load(store: &Store, now: DateTime<Utc>) -> Result<Self> {
        let open = hour_of(now);
        let mut l = Ledger {
            open,
            ..Default::default()
        };
        let mut keys = store.keys(KIND)?;
        keys.reverse();
        for k in keys {
            let mut buckets: Vec<UsageBucket> = store.get(KIND, &k)?.unwrap_or_default();
            if buckets.iter().all(|b| b.closed) {
                break;
            }
            let Some(hour) = buckets.first().map(|b| b.hour) else {
                continue;
            };
            if hour >= open {
                l.hours.insert(
                    hour,
                    buckets
                        .into_iter()
                        .map(|b| (b.machine_id.clone(), b))
                        .collect(),
                );
            } else {
                for b in &mut buckets {
                    b.closed = true;
                }
                store.put(KIND, &k, &buckets)?;
            }
        }
        Ok(l)
    }

    /// Adds what a machine used, by hour, under `who` (its identity as it is now).
    pub fn add(&mut self, who: &UsageBucket, used: BTreeMap<DateTime<Utc>, Usage>) {
        for (hour, u) in used {
            let hour = hour.max(self.open);
            let b = self
                .hours
                .entry(hour)
                .or_default()
                .entry(who.machine_id.clone())
                .or_insert_with(|| UsageBucket {
                    hour,
                    ..Default::default()
                });
            b.machine_id.clone_from(&who.machine_id);
            b.tenant.clone_from(&who.tenant);
            b.role.clone_from(&who.role);
            b.metadata.clone_from(&who.metadata);
            b.size = who.size;
            b.usage.add(&u);
        }
    }

    /// The tick's last step: closes the hours before `now`'s (written once, closed, never
    /// again), writes the open ones once a minute, and once an hour removes the hours older
    /// than `keep_days`. A write that fails leaves the hour open, for the next tick.
    pub fn settle(&mut self, store: &Store, now: DateTime<Utc>, keep_days: u32) -> Result<()> {
        let current = hour_of(now);
        let over: Vec<DateTime<Utc>> = self.hours.range(..current).map(|(h, _)| *h).collect();
        for h in over {
            let buckets: Vec<UsageBucket> = self.hours[&h]
                .values()
                .map(|b| UsageBucket {
                    closed: true,
                    ..b.clone()
                })
                .collect();
            store.put(KIND, &key(h), &buckets)?;
            self.hours.remove(&h);
        }
        self.open = self.open.max(current);
        if self.written.is_none_or(|w| now - w >= WRITE_EVERY) {
            self.write(store, now)?;
        }
        if self.pruned != Some(current) {
            let cut = key(hour_of(now - Duration::days(keep_days as i64)));
            for k in store.keys(KIND)? {
                if k < cut {
                    store.delete(KIND, &k)?;
                }
            }
            self.pruned = Some(current);
        }
        Ok(())
    }

    /// Writes the open hours as they are now.
    pub fn write(&mut self, store: &Store, now: DateTime<Utc>) -> Result<()> {
        for (h, buckets) in &self.hours {
            store.put(KIND, &key(*h), &buckets.values().collect::<Vec<_>>())?;
        }
        self.written = Some(now);
        Ok(())
    }

    /// The open hours' buckets in `[from, to)`, and every hour the ledger holds: those are
    /// read here, fresher than their file.
    pub fn open_buckets(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        tenant: Option<&str>,
    ) -> (Vec<UsageBucket>, BTreeSet<DateTime<Utc>>) {
        let buckets = self
            .hours
            .range(from..to)
            .flat_map(|(_, bs)| bs.values())
            .filter(|b| tenant.is_none_or(|t| b.tenant == t))
            .cloned()
            .collect();
        (buckets, self.hours.keys().copied().collect())
    }
}

/// The stored buckets of the hours in `[from, to)` but those in `skip`.
pub fn stored(
    store: &Store,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    tenant: Option<&str>,
    skip: &BTreeSet<DateTime<Utc>>,
) -> Result<Vec<UsageBucket>> {
    let mut out = Vec::new();
    let mut h = from;
    while h < to {
        if !skip.contains(&h) {
            let buckets: Vec<UsageBucket> = store.get(KIND, &key(h))?.unwrap_or_default();
            out.extend(
                buckets
                    .into_iter()
                    .filter(|b| tenant.is_none_or(|t| b.tenant == t)),
            );
        }
        h += Duration::hours(1);
    }
    Ok(out)
}

/// A read's range: two hours in RFC 3339, `from` included, `to` excluded, at most 31 days.
pub fn range(
    from: Option<&str>,
    to: Option<&str>,
) -> Result<(DateTime<Utc>, DateTime<Utc>), String> {
    let hour = |name: &str, v: Option<&str>| -> Result<DateTime<Utc>, String> {
        let v = v.ok_or_else(|| format!("{name} is required: an hour, 2026-10-20T14:00:00Z"))?;
        let t = DateTime::parse_from_rfc3339(v)
            .map_err(|_| format!("{name} {v:?}: want RFC 3339, 2026-10-20T14:00:00Z"))?
            .with_timezone(&Utc);
        if hour_of(t) != t {
            return Err(format!("{name} {v:?}: not on the hour"));
        }
        Ok(t)
    };
    let (from, to) = (hour("from", from)?, hour("to", to)?);
    if to <= from {
        return Err("to must be after from".into());
    }
    if to - from > MAX_RANGE {
        return Err("at most 31 days at once".into());
    }
    Ok((from, to))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    fn running(memory_mb: u32) -> Held {
        Held {
            running: true,
            suspended: false,
            memory_mb,
        }
    }

    #[test]
    fn hours_and_keys() {
        assert_eq!(
            hour_of(t("2026-10-20T14:59:59.9Z")),
            t("2026-10-20T14:00:00Z")
        );
        assert_eq!(
            hour_of(t("2026-10-20T15:00:00Z")),
            t("2026-10-20T15:00:00Z")
        );
        assert_eq!(key(t("2026-10-20T09:00:00Z")), "2026-10-20T09");
    }

    #[test]
    fn time_is_split_at_the_hour_and_disks_accrue_in_every_state() {
        let mut m = Meter::new(t("2026-10-20T13:59:50Z"));
        m.disks = Disks {
            root: 8 << 30,
            volume: 0,
            used: 1 << 30,
            snapshots: 0,
            backups: 2 << 30,
        };
        m.advance(t("2026-10-20T14:00:20Z"), running(512));
        let used = m.drain();
        let (a, b) = (
            used[&t("2026-10-20T13:00:00Z")],
            used[&t("2026-10-20T14:00:00Z")],
        );
        assert_eq!((a.running_seconds, b.running_seconds), (10.0, 20.0));
        assert_eq!(b.memory_mb_seconds, 512.0 * 20.0);
        assert_eq!(a.root_gb_hours, 8.0 * 10.0 / 3600.0);
        assert_eq!(b.backup_gb_hours, 2.0 * 20.0 / 3600.0);
        // Stopped: disk hours, no compute.
        m.advance(t("2026-10-20T14:01:20Z"), Held::default());
        let s = m.drain()[&t("2026-10-20T14:00:00Z")];
        assert_eq!((s.running_seconds, s.memory_mb_seconds), (0.0, 0.0));
        assert_eq!(s.disk_used_gb_hours, 60.0 / 3600.0);
        // Time that went backwards accrues nothing and moves nothing.
        m.advance(t("2026-10-20T14:00:00Z"), running(512));
        assert!(m.drain().is_empty());
        assert_eq!(m.at, t("2026-10-20T14:01:20Z"));
    }

    #[test]
    fn counters_add_what_they_grew_by_and_a_reset_adds_all() {
        let now = t("2026-10-20T14:30:00Z");
        let mut m = Meter::new(now);
        // The first CPU reading after a start is where the count starts: an adopted
        // machine's earlier CPU time is not this daemon's to report.
        m.counters(now, Some(5_000_000), Some(net(100, 10)), (7, 70));
        let u = m.drain()[&hour_of(now)];
        assert_eq!(u.cpu_seconds, 0.0);
        // The internet counters start at zero with the meter, the endpoints' bytes are added.
        assert_eq!((u.internet_in_bytes, u.internet_out_bytes), (100, 10));
        assert_eq!((u.ingress_in_bytes, u.ingress_out_bytes), (7, 70));
        m.counters(now, Some(6_500_000), Some(net(150, 10)), (0, 0));
        let u = m.drain()[&hour_of(now)];
        assert_eq!(u.cpu_seconds, 1.5);
        assert_eq!((u.internet_in_bytes, u.internet_out_bytes), (50, 0));
        // Smaller than last time: the counter began again, all of it is new.
        m.counters(now, Some(2_000_000), Some(net(30, 5)), (0, 0));
        let u = m.drain()[&hour_of(now)];
        assert_eq!(u.cpu_seconds, 2.0);
        assert_eq!((u.internet_in_bytes, u.internet_out_bytes), (30, 5));
        // Unreadable this time: nothing added, the next reading covers it.
        m.counters(now, None, None, (0, 0));
        m.counters(now, Some(3_000_000), Some(net(40, 5)), (0, 0));
        let u = m.drain()[&hour_of(now)];
        assert_eq!((u.cpu_seconds, u.internet_in_bytes), (1.0, 10));
        // A boot counts from what the cgroup holds before it.
        m.boot(10_000_000);
        m.counters(now, Some(10_250_000), None, (0, 0));
        assert_eq!(m.drain()[&hour_of(now)].cpu_seconds, 0.25);
    }

    /// The host's counters with these internet bytes and no drops.
    fn net(inb: u64, out: u64) -> Counters {
        Counters {
            internet_in: inb,
            internet_out: out,
            ..Default::default()
        }
    }

    #[test]
    fn drops_add_up_in_usage_and_count_from_the_boot_in_the_view() {
        let now = t("2026-10-20T14:30:00Z");
        let mut m = Meter::new(now);
        let dropped = |blocked_port, rate, bandwidth| Counters {
            dropped: EgressDrops {
                blocked_port,
                rate,
                bandwidth,
            },
            ..Default::default()
        };
        m.counters(now, None, Some(dropped(2, 5, 0)), (0, 0));
        assert_eq!(m.drain()[&hour_of(now)].egress_dropped_packets, 7);
        m.counters(now, None, Some(dropped(3, 5, 10)), (0, 0));
        assert_eq!(m.drain()[&hour_of(now)].egress_dropped_packets, 11);
        assert_eq!(
            m.drops(),
            EgressDrops {
                blocked_port: 3,
                rate: 5,
                bandwidth: 10
            }
        );
        // A boot: the view counts from none, the counters go on where they were.
        m.boot(0);
        assert_eq!(m.drops(), EgressDrops::default());
        m.counters(now, None, Some(dropped(4, 5, 10)), (0, 0));
        assert_eq!(m.drain()[&hour_of(now)].egress_dropped_packets, 1);
        assert_eq!(m.drops().total(), 1);
        // Counters begun again (a daemon start): all of it is new.
        m.counters(now, None, Some(dropped(0, 2, 0)), (0, 0));
        assert_eq!(m.drain()[&hour_of(now)].egress_dropped_packets, 2);
        assert_eq!(m.drops().rate, 2);
    }

    #[test]
    fn totals_add_up_and_rates_come_from_the_last_two_readings() {
        let t0 = t("2026-10-20T14:30:00Z");
        let mut m = Meter::new(t0);
        m.counters(t0, Some(1_000_000), Some(net(100, 10)), (0, 0));
        // One reading: no window yet.
        assert_eq!(m.rates(), Rates::default());
        let t1 = t0 + Duration::seconds(15);
        m.counters(t1, Some(4_000_000), Some(net(1600, 40)), (30, 300));
        // The totals keep what was drained into the hours.
        m.drain();
        let c = m.counted();
        assert_eq!((c.cpu_seconds, c.internet_in_bytes), (3.0, 1600));
        assert_eq!((c.ingress_in_bytes, c.ingress_out_bytes), (30, 300));
        assert_eq!(
            m.rates(),
            Rates {
                window_sec: 15.0,
                cpu_percent: 20.0,
                internet_in: 100.0,
                internet_out: 2.0,
                ingress_in: 2.0,
                ingress_out: 20.0,
            }
        );
        // The window moves on with each tick; a boot does not take the totals back.
        m.boot(0);
        let t2 = t1 + Duration::seconds(10);
        m.counters(t2, Some(500_000), Some(net(1600, 40)), (0, 0));
        assert_eq!(m.counted().cpu_seconds, 3.5);
        let r = m.rates();
        assert_eq!(
            (r.window_sec, r.cpu_percent, r.internet_in),
            (10.0, 5.0, 0.0)
        );
    }

    #[test]
    fn traffic_is_taken_once() {
        let tr = Traffic::default();
        tr.received(10);
        tr.sent(300);
        tr.sent(1);
        assert_eq!(tr.take(), (10, 301));
        assert_eq!(tr.take(), (0, 0));
    }

    #[test]
    fn files_count_what_they_take() {
        let dir = tempfile::tempdir().unwrap();
        let mem = dir.path().join("snap.mem");
        std::fs::write(&mem, vec![7u8; 1 << 20]).unwrap();
        let n = file_bytes(&[dir.path().join("snap.state"), mem]);
        assert!(n >= 1 << 20, "{n}");
        assert_eq!(file_bytes(&[dir.path().join("nothing")]), 0);
    }

    #[test]
    fn a_range_is_two_hours_at_most_31_days_apart() {
        let r = |f: &str, to: &str| range(Some(f), Some(to));
        assert_eq!(
            r("2026-10-20T14:00:00Z", "2026-10-20T15:00:00Z"),
            Ok((t("2026-10-20T14:00:00Z"), t("2026-10-20T15:00:00Z")))
        );
        // Another offset is the same moment.
        assert_eq!(
            r("2026-10-20T16:00:00+02:00", "2026-11-20T14:00:00Z").map(|(f, _)| f),
            Ok(t("2026-10-20T14:00:00Z"))
        );
        assert_eq!(
            range(None, Some("2026-10-20T15:00:00Z")),
            Err("from is required: an hour, 2026-10-20T14:00:00Z".into())
        );
        assert_eq!(
            range(Some("2026-10-20T14:00:00Z"), None),
            Err("to is required: an hour, 2026-10-20T14:00:00Z".into())
        );
        assert_eq!(
            r("yesterday", "2026-10-20T15:00:00Z"),
            Err("from \"yesterday\": want RFC 3339, 2026-10-20T14:00:00Z".into())
        );
        assert_eq!(
            r("2026-10-20T14:30:00Z", "2026-10-20T15:00:00Z"),
            Err("from \"2026-10-20T14:30:00Z\": not on the hour".into())
        );
        assert_eq!(
            r("2026-10-20T14:00:00Z", "2026-10-20T14:00:00Z"),
            Err("to must be after from".into())
        );
        assert_eq!(
            r("2026-10-20T14:00:00Z", "2026-11-20T15:00:00Z"),
            Err("at most 31 days at once".into())
        );
    }
}
