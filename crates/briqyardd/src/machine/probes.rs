//! Probes (ADR 0022): one task per running machine that has some. Its startup probe runs
//! first, then its readiness and liveness probes, each on its own fixed period, the first run
//! spread over a period just after a daemon start. What they find is the
//! machine's `ready` and `probes_status`; a startup or liveness failure ends the boot or the run.

use super::{Entry, Manager};
use crate::events::Ev;
use crate::fc;
use briqyard_api::{self as api, guest, reason, state};
use chrono::Utc;
use serde_json::json;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

/// Probe executions a host runs at once (ADR 0022).
pub(super) const PROBES_AT_ONCE: usize = 32;

/// What a liveness or startup failure gives the guest to stop before a kill: a stop's default.
const END_GRACE: Duration = Duration::from_secs(10);

/// The longest message a probe's status keeps.
const MAX_MESSAGE: usize = 300;

/// What a machine's probes found in the current run, in memory; reset at each boot.
#[derive(Default)]
pub(super) struct Run {
    /// One more at each reset: a task of an earlier run changes nothing.
    generation: u64,
    pub(super) ready: bool,
    pub(super) status: api::ProbesStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Startup,
    Readiness,
    Liveness,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Startup => "startup",
            Kind::Readiness => "readiness",
            Kind::Liveness => "liveness",
        }
    }

    fn slot(self, s: &mut api::ProbesStatus) -> &mut Option<api::ProbeStatus> {
        match self {
            Kind::Startup => &mut s.startup,
            Kind::Readiness => &mut s.readiness,
            Kind::Liveness => &mut s.liveness,
        }
    }
}

/// Passes and failures in a row.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Tally {
    pub(super) passes: u32,
    pub(super) failures: u32,
}

impl Tally {
    pub(super) fn add(&mut self, passed: bool) {
        if passed {
            self.passes = self.passes.saturating_add(1);
            self.failures = 0;
        } else {
            self.failures = self.failures.saturating_add(1);
            self.passes = 0;
        }
    }
}

/// What the readiness probe's tally makes of `ready`: a change, or none.
pub(super) fn readiness_verdict(p: &api::Probe, t: &Tally, ready: bool) -> Option<bool> {
    match ready {
        false if t.passes >= p.success_threshold => Some(true),
        true if t.failures >= p.failure_threshold => Some(false),
        _ => None,
    }
}

/// Whether `ready` is true at a boot: without a startup or a readiness probe, at once.
pub(super) fn ready_at_boot(p: &api::Probes) -> bool {
    p.startup.is_none() && p.readiness.is_none()
}

/// When a probe first runs: after its initial delay and, while the daemon is younger than the
/// probe's period, at a random point (`spread`, 0 to 1) of one more period, as the kubelet
/// does, so a daemon start that adopts or starts every machine does not probe them all at
/// once. Later runs (a boot, a wake) are not delayed.
pub(super) fn first_run(now: Instant, began: Instant, p: &api::Probe, spread: f64) -> Instant {
    let period = secs(p.period_sec);
    let jitter = match now.duration_since(began) < period {
        true => period.mul_f64(spread.clamp(0.0, 1.0)),
        false => Duration::ZERO,
    };
    now + secs(p.initial_delay_sec) + jitter
}

/// The tick after `last` on its period that is not past at `now`: a probe slower than its
/// period skips the ticks it ran over, rather than running again at once.
pub(super) fn next_tick(last: Instant, period: Duration, now: Instant) -> Instant {
    let mut next = last + period;
    if next < now {
        let behind = (now - next).as_nanos().div_ceil(period.as_nanos().max(1));
        next += period * behind as u32;
    }
    next
}

fn secs(n: u32) -> Duration {
    Duration::from_secs(n.into())
}

/// A message as a status keeps it: at most `MAX_MESSAGE` bytes, cut on a character.
fn bounded(s: &str) -> String {
    let s = s.trim();
    if s.len() <= MAX_MESSAGE {
        return s.to_string();
    }
    let mut start = s.len() - MAX_MESSAGE;
    while !s.is_char_boundary(start) {
        start += 1;
    }
    format!("…{}", &s[start..])
}

/// What an exec probe answered: the code, and the end of what it printed.
fn exec_message(out: &crate::guestc::ExecOutput) -> String {
    let said = if out.stderr.is_empty() {
        &out.stdout
    } else {
        &out.stderr
    };
    let said = String::from_utf8_lossy(said);
    match said.trim() {
        "" => format!("exit {}", out.code),
        text => bounded(&format!("exit {}: {text}", out.code)),
    }
}

impl Manager {
    /// The probes of a new run, as a boot has them: statuses cleared, `ready` true at once
    /// only without a startup or readiness probe. Done before the machine is `running`, so no
    /// reader sees the last run's `ready` on this one. What `ready` was and is, and the run.
    pub(super) fn reset_probes(&self, e: &Entry) -> (bool, bool, u64) {
        let now = ready_at_boot(&e.snapshot().probes);
        let mut run = e.probe.lock().unwrap();
        let was = run.ready;
        run.generation += 1;
        run.ready = now;
        run.status = Default::default();
        (was, now, run.generation)
    }

    /// Runs the probes of run `generation` on `live`, once it is `running`; the task of an
    /// earlier run is ended. `asked`: a run a caller asked for, whose startup failing is a
    /// failed boot.
    pub(super) fn spawn_probes(&self, e: &Arc<Entry>, live: &fc::Vm, generation: u64, asked: bool) {
        let probes = e.snapshot().probes;
        let task = (!probes.is_empty()).then(|| {
            tokio::spawn(self.clone().probe_machine(
                e.clone(),
                live.clone(),
                probes,
                generation,
                asked,
            ))
            .abort_handle()
        });
        if let Some(old) = std::mem::replace(&mut *e.prober.lock().unwrap(), task) {
            old.abort();
        }
    }

    /// A PATCH changed the probes of a running machine: they start over at once, and a change
    /// of `ready` that makes is an event.
    pub(super) fn restart_probes(&self, e: &Arc<Entry>) {
        let live = e.live.lock().unwrap().clone();
        let Some(live) = live else { return };
        let (was, now, generation) = self.reset_probes(e);
        self.spawn_probes(e, &live, generation, false);
        if was != now {
            let ev = match now {
                true => Ev::normal(reason::READY, "ready: its probes changed")
                    .data(json!({ "probe": null })),
                false => Ev::warning(reason::NOT_READY, "not ready: its probes changed")
                    .data(json!({ "probe": null, "failures": 0 })),
            };
            self.note_flip(e, ev);
            e.changed.notify_waiters();
        }
    }

    /// Logs a readiness flip and writes the record with its version before that version can
    /// be read: a folded flip's seq is in no line (ADR 0047), so the record is what keeps it
    /// past a crash; a restart then never hands it out again. Never on a destroy under way,
    /// whose record is about to go.
    fn note_flip(&self, e: &Entry, ev: Ev) {
        let written = self.save_edit(e, |r| {
            if r.state == state::DESTROYING {
                return false;
            }
            e.note_locked(r, ev);
            true
        });
        if let Err(err) = written {
            let r = e.snapshot();
            tracing::warn!(
                machine = r.id,
                version = r.version,
                err = %err,
                "record not written: a restart may give its version out again"
            );
        }
    }

    /// The probes of one run, until its process is gone or a probe ends it.
    async fn probe_machine(
        self,
        e: Arc<Entry>,
        live: fc::Vm,
        probes: api::Probes,
        generation: u64,
        asked: bool,
    ) {
        let Ok(ip) = e.snapshot().ip.parse::<Ipv4Addr>() else {
            return;
        };
        let at = Target {
            e: &e,
            live: &live,
            ip,
            generation,
        };
        let run = async {
            if let Some(p) = &probes.startup {
                let t = self
                    .probe_until(&at, Kind::Startup, p, |t| {
                        (t.passes >= 1 || t.failures >= p.failure_threshold).then_some(*t)
                    })
                    .await?;
                if t.passes == 0 {
                    return Some((Kind::Startup, t.failures));
                }
                if probes.readiness.is_none() {
                    self.set_ready(&at, true, Kind::Startup, 0);
                }
            }
            let readiness = async {
                match &probes.readiness {
                    Some(p) => {
                        self.probe_until(&at, Kind::Readiness, p, |t| {
                            let ready = at.e.probe.lock().unwrap().ready;
                            if let Some(now) = readiness_verdict(p, t, ready) {
                                self.set_ready(&at, now, Kind::Readiness, t.failures);
                            }
                            None::<()>
                        })
                        .await
                    }
                    None => std::future::pending().await,
                }
            };
            let liveness = async {
                match &probes.liveness {
                    Some(p) => {
                        self.probe_until(&at, Kind::Liveness, p, |t| {
                            (t.failures >= p.failure_threshold).then_some(t.failures)
                        })
                        .await
                    }
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = readiness => None,
                failed = liveness => failed.map(|n| (Kind::Liveness, n)),
            }
        };
        let mut exited = live.exited.clone();
        let failed = tokio::select! {
            failed = run => failed,
            _ = exited.wait_for(|gone| *gone) => None,
        };
        if let Some((kind, failures)) = failed {
            // A task of its own: a PATCH that ends this one must not cut the machine's end.
            let (m, last) = (self.clone(), self.last_message(&e, kind));
            tokio::spawn(async move {
                m.probe_failed(&e, live.pid, kind, asked, failures, last)
                    .await
            });
        }
    }

    /// Runs `p` on a fixed period from its first run (`first_run`) and records each result,
    /// until `decide` makes something of the tally. A probe slower than its period skips the
    /// ticks it ran over (`next_tick`). None: the run is over (a newer one began).
    async fn probe_until<T>(
        &self,
        at: &Target<'_>,
        kind: Kind,
        p: &api::Probe,
        mut decide: impl FnMut(&Tally) -> Option<T>,
    ) -> Option<T> {
        let mut next = first_run(Instant::now(), self.inner.began, p, rand::random());
        let mut tally = Tally::default();
        loop {
            tokio::time::sleep_until(next).await;
            let (passed, message) = self.probe_once(at, p).await;
            next = next_tick(next, secs(p.period_sec), Instant::now());
            tally.add(passed);
            {
                let mut run = at.e.probe.lock().unwrap();
                if run.generation != at.generation {
                    return None;
                }
                *kind.slot(&mut run.status) = Some(api::ProbeStatus {
                    passed,
                    message,
                    failures: tally.failures,
                    at: Utc::now(),
                });
            }
            if let Some(t) = decide(&tally) {
                return Some(t);
            }
        }
    }

    /// One execution, in its turn: whether it passed, and what it answered. Not a use: the
    /// machine's sleep window does not move.
    async fn probe_once(&self, at: &Target<'_>, p: &api::Probe) -> (bool, String) {
        let Ok(_turn) = self.inner.probe_gate.acquire().await else {
            return (false, "the host is closing".into());
        };
        let timeout = secs(p.timeout_sec);
        match (&p.exec, p.tcp, &p.http) {
            (Some(cmd), _, _) => {
                let req = guest::Request {
                    op: "exec".into(),
                    cmd: cmd.clone(),
                    timeout_ms: u64::from(p.timeout_sec) * 1000,
                    ..Default::default()
                };
                // The init ends the command at its timeout; the margin is for the init itself.
                let answer = tokio::time::timeout(timeout + Duration::from_secs(5), async {
                    let mut conn = self.inner.guest.session(&at.live.vsock, req).await?;
                    crate::guestc::collect(&mut conn).await
                })
                .await;
                match answer {
                    Err(_) => (false, format!("no answer within {timeout:?}")),
                    Ok(Err(err)) => (false, bounded(&format!("{err:#}"))),
                    Ok(Ok(out)) if out.timed_out => {
                        (false, format!("timed out after {} s", p.timeout_sec))
                    }
                    Ok(Ok(out)) => (out.code == 0, exec_message(&out)),
                }
            }
            (_, Some(port), _) => match self.inner.net.probe_tcp(at.ip, port, timeout).await {
                Ok(()) => (true, format!("{}:{port} accepted", at.ip)),
                Err(err) => (false, bounded(&format!("{err:#}"))),
            },
            (_, _, Some(h)) => {
                let answer = self
                    .inner
                    .net
                    .probe_http(at.ip, h.port, &h.path, timeout)
                    .await;
                match answer {
                    Ok(code) => ((200..400).contains(&code), format!("HTTP {code}")),
                    Err(err) => (false, bounded(&format!("{err:#}"))),
                }
            }
            _ => (false, "no action".into()),
        }
    }

    /// Sets `ready` for this run while the machine runs; a change is an event, written with
    /// the record, and wakes whoever waits on the machine.
    fn set_ready(&self, at: &Target<'_>, ready: bool, kind: Kind, failures: u32) {
        let e = at.e;
        {
            let mut run = e.probe.lock().unwrap();
            if run.generation != at.generation
                || run.ready == ready
                || e.snapshot().state != state::RUNNING
            {
                return;
            }
            run.ready = ready;
            let name = kind.name();
            let ev = match ready {
                true => Ev::normal(reason::READY, format!("ready: {name} passed"))
                    .data(json!({ "probe": name })),
                false => {
                    let last = kind
                        .slot(&mut run.status)
                        .as_ref()
                        .map(|s| s.message.clone());
                    let last = last.unwrap_or_default();
                    Ev::warning(
                        reason::NOT_READY,
                        format!("not ready: {name} failed {failures} times in a row: {last}"),
                    )
                    .data(json!({ "probe": name, "failures": failures }))
                }
            };
            // Under the run's lock: a reset waits for it, so the event is of this run.
            self.note_flip(e, ev);
        }
        e.changed.notify_waiters();
    }

    fn last_message(&self, e: &Entry, kind: Kind) -> String {
        let mut run = e.probe.lock().unwrap();
        kind.slot(&mut run.status)
            .as_ref()
            .map(|s| s.message.clone())
            .unwrap_or_default()
    }

    /// A startup or liveness probe failed `failures` times in a row on the run of `pid`. Under
    /// the machine's lock, and only while that run is the machine's and it runs: the process
    /// is ended; a run a caller asked for whose startup failed is a failed boot (`error`, no
    /// restart, ADR 0011), anything else an exit the restart policy decides on as a failure.
    async fn probe_failed(
        &self,
        e: &Arc<Entry>,
        pid: u32,
        kind: Kind,
        asked: bool,
        failures: u32,
        last: String,
    ) {
        let _guard = e.lock.lock().await;
        let live = e.live.lock().unwrap().clone();
        let Some(live) = live.filter(|l| l.pid == pid) else {
            return;
        };
        if e.snapshot().state != state::RUNNING {
            return;
        }
        let boot = kind == Kind::Startup && asked;
        let what = format!("{} failed {failures} times in a row: {last}", kind.name());
        let r = e.snapshot();
        tracing::warn!(
            machine = r.id,
            probe = kind.name(),
            failures,
            last,
            "probe failed"
        );
        e.note(match kind {
            Kind::Startup => Ev::warning(
                reason::STARTUP_FAILED,
                match boot {
                    true => format!("{what}: the boot failed"),
                    false => format!("{what}: ending it"),
                },
            )
            .data(json!({ "failures": failures, "boot": boot })),
            _ => Ev::warning(reason::LIVENESS_FAILED, format!("{what}: ending it"))
                .data(json!({ "failures": failures })),
        });
        self.end_process(e, &live, END_GRACE).await;
        if boot {
            self.inner
                .stats
                .starts_failed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let tail = self.last_console_lines(&r, 5);
            e.set_state(state::ERROR, |r| {
                r.error =
                    format!("the startup probe failed {failures} times in a row: {last}: {tail}");
                r.stopped_at = Some(Utc::now());
                r.pid = 0;
                None
            });
            let _ = self.save(e);
            return;
        }
        // The init's report when it sent one before the end; none reads as 255, as an exit.
        let mut exit = live.exit.clone();
        let _ = exit.wait_for(|r| r.is_some()).await;
        let report = exit.borrow().clone();
        let (code, oom) = report.map_or((255, false), |r| (r.code, r.oom));
        self.exited(e, code, oom, true);
    }
}

/// The run a probe task works for.
struct Target<'a> {
    e: &'a Arc<Entry>,
    live: &'a fc::Vm,
    ip: Ipv4Addr,
    generation: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(success: u32, failure: u32) -> api::Probe {
        api::Probe {
            tcp: Some(80),
            success_threshold: success,
            failure_threshold: failure,
            ..Default::default()
        }
    }

    #[test]
    fn the_first_run_is_spread_only_just_after_a_daemon_start() {
        let began = Instant::now();
        let s = Duration::from_secs;
        let p = api::Probe {
            period_sec: 10,
            initial_delay_sec: 5,
            ..probe(1, 3)
        };
        // Within a period of the start: the initial delay, then a point of one period.
        assert_eq!(first_run(began, began, &p, 0.0), began + s(5));
        assert_eq!(first_run(began, began, &p, 0.5), began + s(10));
        assert_eq!(
            first_run(began + s(9), began, &p, 0.99),
            began + s(9) + s(5) + s(10).mul_f64(0.99)
        );
        // A period or more after it: the initial delay alone.
        assert_eq!(first_run(began + s(10), began, &p, 0.5), began + s(15));
    }

    #[test]
    fn the_next_tick_keeps_the_period_and_skips_what_a_slow_probe_ran_over() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let period = ms(1000);
        // On time: one period after the last tick, whenever the probe ended.
        assert_eq!(next_tick(t0, period, t0 + ms(300)), t0 + ms(1000));
        assert_eq!(next_tick(t0, period, t0 + ms(1000)), t0 + ms(1000));
        // Ran over one tick, or three: the next one not past.
        assert_eq!(next_tick(t0, period, t0 + ms(1500)), t0 + ms(2000));
        assert_eq!(next_tick(t0, period, t0 + ms(3200)), t0 + ms(4000));
    }

    #[test]
    fn a_tally_counts_in_a_row() {
        let mut t = Tally::default();
        for passed in [true, true, false, false, false] {
            t.add(passed);
        }
        assert_eq!(
            t,
            Tally {
                passes: 0,
                failures: 3
            }
        );
        t.add(true);
        assert_eq!(
            t,
            Tally {
                passes: 1,
                failures: 0
            }
        );
    }

    #[test]
    fn readiness_moves_at_its_thresholds() {
        let p = probe(2, 3);
        let t = |passes, failures| Tally { passes, failures };
        // Not ready: two passes in a row make it ready, failures change nothing.
        assert_eq!(readiness_verdict(&p, &t(1, 0), false), None);
        assert_eq!(readiness_verdict(&p, &t(2, 0), false), Some(true));
        assert_eq!(readiness_verdict(&p, &t(0, 9), false), None);
        // Ready: three failures in a row make it not ready, passes change nothing.
        assert_eq!(readiness_verdict(&p, &t(0, 2), true), None);
        assert_eq!(readiness_verdict(&p, &t(0, 3), true), Some(false));
        assert_eq!(readiness_verdict(&p, &t(5, 0), true), None);
    }

    #[test]
    fn ready_at_boot_only_without_startup_or_readiness() {
        let some = Some(probe(1, 3));
        assert!(ready_at_boot(&api::Probes::default()));
        assert!(ready_at_boot(&api::Probes {
            liveness: some.clone(),
            ..Default::default()
        }));
        for p in [
            api::Probes {
                startup: some.clone(),
                ..Default::default()
            },
            api::Probes {
                readiness: some,
                ..Default::default()
            },
        ] {
            assert!(!ready_at_boot(&p));
        }
    }

    #[test]
    fn messages_are_bounded_from_their_end() {
        assert_eq!(bounded("  short \n"), "short");
        let long = format!("{}é{}", "a".repeat(400), "z".repeat(10));
        let b = bounded(&long);
        assert!(b.starts_with('…') && b.ends_with("zzzzzzzzzz"), "{b}");
        assert!(b.len() <= MAX_MESSAGE + '…'.len_utf8());
        let out = |code, stdout: &str, stderr: &str| crate::guestc::ExecOutput {
            stdout: stdout.into(),
            stderr: stderr.into(),
            code,
            timed_out: false,
        };
        assert_eq!(exec_message(&out(0, "", "")), "exit 0");
        assert_eq!(exec_message(&out(1, "out\n", "")), "exit 1: out");
        assert_eq!(
            exec_message(&out(2, "out", "no such file\n")),
            "exit 2: no such file"
        );
    }
}
