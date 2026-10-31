//! What the manager reports: images, stats, metrics, conditions, usage, events, and what a caller waits on.

use super::*;

impl Manager {
    /// The images on the host.
    pub async fn images(&self) -> Result<Vec<api::Image>, MError> {
        Ok(self
            .inner
            .images
            .list()
            .await?
            .into_iter()
            .map(|(im, machines)| api::Image {
                key: im.key,
                reference: im.r#ref,
                digest: im.digest,
                size_gb: im.size_gb,
                built_at: im.built_at,
                machines,
            })
            .collect())
    }

    /// Removes an image no machine clones.
    pub async fn delete_image(&self, key: &str) -> Result<(), MError> {
        if !key.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(MError::NotFound);
        }
        match self.inner.images.remove(key, Removal::Request).await? {
            true => Ok(()),
            false => Err(MError::Conflict("machines still use this image".into())),
        }
    }

    /// Removes images unused for `keep`; runs hourly from the daemon.
    pub async fn gc_images(&self, keep: chrono::Duration) -> usize {
        self.inner.images.gc(keep).await.unwrap_or_else(|e| {
            tracing::warn!(err = %e, "image gc");
            0
        })
    }

    /// What the machine uses now: CPU and memory from its cgroup when jailed, disk from ZFS.
    pub async fn stats(&self, id: &str) -> Result<api::MachineStats, MError> {
        let e = self.entry(id)?;
        let r = e.snapshot();
        let mut st = api::MachineStats {
            state: r.state.clone(),
            memory_status: if r.state == state::RUNNING {
                "unavailable"
            } else {
                "stopped"
            }
            .into(),
            boot_profile: r.boot_identity.as_ref().map(|i| i.device_profile.clone()),
            ..Default::default()
        };
        if r.state == state::RUNNING {
            if let Some(t) = r.started_at {
                st.uptime_sec = (Utc::now() - t).num_seconds().max(0) as u64;
            }
            if let Some(cg) = self.inner.vmm.cgroup(&r.id).await {
                st.cpu_usec = cg.cpu_usec;
                st.memory_bytes = cg.memory_bytes;
                st.memory_anon_bytes = cg.memory_anon_bytes;
                st.memory_file_bytes = cg.memory_file_bytes;
                st.memory_status = "available".into();
                st.memory_read_at = Some(Utc::now());
            }
            st.balloon = e.meter.lock().unwrap().balloon.clone();
        }
        st.disk_bytes = self.inner.zfs.used(&r.dataset()).await.unwrap_or(0);
        let current = e.snapshot();
        if current.pid != r.pid || current.state != state::RUNNING {
            st.state = current.state.clone();
            st.memory_status = if current.state == state::RUNNING {
                "unavailable"
            } else {
                "stopped"
            }
            .into();
            st.memory_read_at = None;
            st.memory_anon_bytes = None;
            st.memory_file_bytes = None;
            st.balloon = None;
        }
        Ok(st)
    }

    /// `/metrics` (ADR 0021): the host's figures and each machine's from the tick's last
    /// measure. Nothing is probed here: a scrape costs the same however often it comes.
    pub fn metrics(&self) -> String {
        use std::sync::atomic::Ordering::Relaxed;
        let mut entries: Vec<Arc<Entry>> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        entries.sort_by_key(|e| e.snapshot().id);
        let mut host = metrics::Host::default();
        let machines: Vec<metrics::Machine> = entries
            .iter()
            .map(|e| {
                let r = e.rec.lock().unwrap();
                let m = e.meter.lock().unwrap();
                *host.by_state.entry(r.state.clone()).or_default() += 1;
                if r.state == state::STOPPED {
                    *host.stopped.entry(r.stopped_reason.clone()).or_default() += 1;
                }
                host.suspended += r.suspended as usize;
                metrics::Machine {
                    id: r.id.clone(),
                    namespace: r.namespace.clone(),
                    name: r.name.clone(),
                    role: role_name(r.role),
                    state: r.state.clone(),
                    counted: m.counted(),
                    memory_bytes: m.memory_bytes,
                    memory_available: r.state == state::RUNNING && m.memory_available,
                    memory_anon_bytes: m.memory_anon_bytes.filter(|_| r.state == state::RUNNING),
                    memory_file_bytes: m.memory_file_bytes.filter(|_| r.state == state::RUNNING),
                    balloon: m.balloon.clone().filter(|_| r.state == state::RUNNING),
                    memory_limit_bytes: (r.size.memory_mb as u64) << 20,
                    disk_used_bytes: m.disks.used + m.disks.snapshots,
                    restarts: m.restarts,
                    boot_seconds: m.boot_seconds,
                    disk_read_bytes: e.disk_io.read_bytes.load(Relaxed),
                    disk_write_bytes: e.disk_io.write_bytes.load(Relaxed),
                    disk_throttled: e.disk_io.throttled.load(Relaxed),
                }
            })
            .collect();
        let (used, _, _) = self.usage();
        let cap = self.capacity();
        let st = &self.inner.stats;
        host.namespaces = self.inner.namespaces.lock().unwrap().len();
        host.endpoints = self.inner.endpoints.lock().unwrap().len();
        host.memory_mb = (used.memory_mb, cap.memory_mb);
        host.cpu_millis = (used.cpu_millis(), cap.cpu_millis());
        host.pool = *self.inner.pool.lock().unwrap();
        host.conditions = self.conditions();
        host.events = self.inner.events.emitted();
        host.resident_bytes = metrics::resident_bytes();
        host.counters = vec![
            (
                "briqyard_boots_total",
                "Cold boots since the daemon started.",
                st.boots.load(Relaxed),
            ),
            (
                "briqyard_resumes_total",
                "Resumes from a memory snapshot.",
                st.resumes.load(Relaxed),
            ),
            (
                "briqyard_suspends_total",
                "Stops with a memory snapshot.",
                st.suspends.load(Relaxed),
            ),
            (
                "briqyard_execs_total",
                "Commands run in machines.",
                st.execs.load(Relaxed),
            ),
            (
                "briqyard_starts_failed_total",
                "Starts that failed.",
                st.starts_failed.load(Relaxed),
            ),
            (
                "briqyard_backups_total",
                "Backups sent to the store.",
                st.backups.load(Relaxed),
            ),
        ];
        metrics::render(&host, &machines)
    }

    /// The host's conditions as the tick last decided them.
    pub fn conditions(&self) -> Vec<api::Condition> {
        self.inner.conditions.lock().unwrap().list()
    }

    /// This daemon's start (ADR 0027).
    pub fn started(&self) -> api::DaemonStart {
        *self.inner.started.lock().unwrap()
    }

    /// What a machine booted now runs under (ADR 0027).
    pub fn vmm_version(&self) -> String {
        self.inner.vmm.version()
    }

    /// The running machines' use over the tick's last window (ADR 0021), of one namespace or
    /// all, gateways included, by namespace then name.
    pub fn top(&self, namespace: Option<&str>) -> Vec<api::TopMachine> {
        let entries: Vec<Arc<Entry>> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        let mut out: Vec<api::TopMachine> = entries
            .iter()
            .filter_map(|e| {
                let r = e.rec.lock().unwrap();
                if r.state != state::RUNNING || namespace.is_some_and(|t| r.namespace != t) {
                    return None;
                }
                let m = e.meter.lock().unwrap();
                let rates = m.rates();
                Some(api::TopMachine {
                    machine_id: r.id.clone(),
                    namespace: r.namespace.clone(),
                    name: r.name.clone(),
                    role: role_name(r.role),
                    cpu_percent: rates.cpu_percent,
                    memory_bytes: m.memory_bytes,
                    memory_limit_bytes: (r.size.memory_mb as u64) << 20,
                    disk_used_bytes: m.disks.used + m.disks.snapshots,
                    internet_in_bytes_per_sec: rates.internet_in,
                    internet_out_bytes_per_sec: rates.internet_out,
                    ingress_in_bytes_per_sec: rates.ingress_in,
                    ingress_out_bytes_per_sec: rates.ingress_out,
                    window_sec: rates.window_sec,
                    host: String::new(),
                })
            })
            .collect();
        out.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
        out
    }

    /// Free space in the pool, in MB.
    pub async fn disk_free_mb(&self) -> u64 {
        self.inner.zfs.free().await.unwrap_or(0) >> 20
    }

    pub fn capacity(&self) -> api::Capacity {
        let c = self.inner.cfg.capacity;
        let mut cap = api::Capacity {
            cpu_millis: None,
            memory_mb: if c.memory_mb > 0 {
                c.memory_mb
            } else {
                default_memory_mb(host_memory_mb(), c.reserved_memory_mb, arc_max_mb())
            },
            vcpus: if c.vcpus > 0 {
                c.vcpus
            } else {
                let threads = std::thread::available_parallelism().map_or(2, |n| n.get());
                default_vcpus(threads as u32, c.reserved_threads)
            },
        };
        cap.cpu_millis = Some(cap.cpu_millis());
        cap
    }

    /// Where the ingress adds the bytes it passes to and from a machine's endpoints.
    pub fn traffic(&self, id: &str) -> Option<Arc<Traffic>> {
        self.entry(id).ok().map(|e| e.traffic.clone())
    }

    /// The buckets of the hours in `[from, to)`, of one namespace or all, by hour then machine:
    /// the open hours from memory, the others from their files.
    pub async fn usage_buckets(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        namespace: Option<String>,
    ) -> Result<Vec<api::UsageBucket>, MError> {
        let (mut out, open) =
            self.inner
                .usage
                .lock()
                .unwrap()
                .open_buckets(from, to, namespace.as_deref());
        let store = self.inner.store.clone();
        let stored = tokio::task::spawn_blocking(move || {
            usage::stored(&store, from, to, namespace.as_deref(), &open)
        })
        .await
        .map_err(|e| anyhow!(e))??;
        out.extend(stored);
        out.sort_by(|a, b| (a.hour, &a.machine_id).cmp(&(b.hour, &b.machine_id)));
        Ok(out)
    }

    // --- events (ADR 0019) ---

    pub fn events(&self) -> &Events {
        &self.inner.events
    }

    /// A page of events after `since`, oldest first.
    pub async fn events_page(
        &self,
        since: u64,
        f: events::Filter,
        limit: usize,
    ) -> Result<api::EventsPage, MError> {
        let log = self.inner.events.clone();
        let page = tokio::task::spawn_blocking(move || log.read(since, &f, limit))
            .await
            .map_err(|e| anyhow!(e))?
            .map_err(gone)?;
        Ok(api::EventsPage {
            events: page.events,
            next: page.next.to_string(),
        })
    }

    /// Blocks until the machine runs (`Until::Running`) or is ready (`Until::Ready`, ADR 0022),
    /// or until it is clear it will not, within `timeout`. A timeout while it is still on its
    /// way (creating, starting, running not ready, a restart waiting) is `not_ready`, with the
    /// machine: a caller waits again (ADR 0048).
    pub async fn wait(
        &self,
        id: &str,
        until: Until,
        timeout: Duration,
    ) -> Result<api::Machine, MError> {
        let e = self.entry(id)?;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            // Registered before the state is read, so a change in between is not missed.
            let changed = e.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let m = self.view(&e);
            if let Some(answer) = wait_verdict(&m, until) {
                return answer.map(|()| m);
            }
            if tokio::time::timeout_at(deadline, changed).await.is_err() {
                let m = self.view(&e);
                return match wait_verdict(&m, until) {
                    Some(answer) => answer.map(|()| m),
                    None => Err(MError::NotReady(Box::new(m))),
                };
            }
        }
    }

    /// The address a proxy connects to once the machine is ready, woken when it sleeps:
    /// readiness gates traffic (ADR 0022).
    pub async fn ready_addr(&self, id: &str, timeout: Duration) -> Result<Ipv4Addr, MError> {
        let ip = self.machine_addr(id, true).await?;
        self.wait(id, Until::Ready, timeout).await?;
        Ok(ip)
    }
}

/// What `/wait` waits for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Until {
    Running,
    Ready,
}

/// What a `/wait` answers now, or None to keep waiting. A machine whose create failed answers
/// that (`pull_failed`, `create_failed`, ADR 0048). For `Ready`, another machine in `error`
/// failed its boot (the guest or its startup probe): `boot_failed`, as its start would answer.
pub(super) fn wait_verdict(m: &api::Machine, until: Until) -> Option<Result<(), MError>> {
    if m.state == state::ERROR {
        match m.error_reason.as_str() {
            reason::PULL_FAILED => return Some(Err(MError::PullFailed(Box::new(m.clone())))),
            reason::CREATE_FAILED => return Some(Err(MError::CreateFailed(Box::new(m.clone())))),
            _ => {}
        }
    }
    match (will_run(m), until) {
        (Some(Ok(())), Until::Ready) if !m.ready => None,
        (Some(Err(_)), Until::Ready) if m.state == state::ERROR => {
            Some(Err(MError::BootFailed(Box::new(m.clone()))))
        }
        (verdict, _) => verdict.map(|v| v.map_err(MError::NotRunning)),
    }
}

/// Where a machine that is not ready is: still on its way, or running and why it is not ready.
pub(super) fn not_ready_state(m: &api::Machine) -> String {
    match m.state.as_str() {
        state::RUNNING => format!("running, not ready: {}", not_ready_why(m)),
        other => format!("still {other}"),
    }
}

/// Why a running machine is not ready: its probes' last results.
pub(super) fn not_ready_why(m: &api::Machine) -> String {
    let s = &m.probes_status;
    let said: Vec<String> = [("startup", &s.startup), ("readiness", &s.readiness)]
        .into_iter()
        .filter_map(|(name, st)| st.as_ref().map(|st| (name, st)))
        .filter(|(_, st)| !st.passed)
        .map(|(name, st)| format!("{name}: {}", st.message))
        .collect();
    match said.is_empty() {
        true => "its probes have not passed yet".into(),
        false => said.join("; "),
    }
}

/// What `/wait` answers: running, will not run (why), or still moving.
pub(super) fn will_run(m: &api::Machine) -> Option<Result<(), String>> {
    match m.state.as_str() {
        state::RUNNING => Some(Ok(())),
        state::ERROR => Some(Err(m.error.clone())),
        state::DESTROYING => Some(Err("destroying".into())),
        state::STOPPED
            if !(m.stopped_reason == stop::EXIT
                && m.exit.as_ref().map(|e| e.restarting).unwrap_or(false)) =>
        {
            Some(Err(format!("stopped ({})", m.stopped_reason)))
        }
        _ => None,
    }
}
