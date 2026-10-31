//! Starting a machine: the checks, the boot, and what the boot is made of (kernel arguments, jail, config drive).

use super::*;

impl Manager {
    pub async fn start(&self, id: &str, at: Option<u64>) -> Result<api::Machine, MError> {
        let e = self.own_entry(id)?;
        let _turns = e.lock_once_stopped(false).await;
        self.check_version(&e, at)?;
        match e.snapshot() {
            r if r.state == state::CREATING => return self.creating(&e),
            r if r.state != state::RUNNING => self.start_entry(&e, true).await?,
            _ => {}
        }
        Ok(self.view(&e))
    }

    /// A start or a wake of a machine whose create is pulling its image (its lock is held
    /// from then on, so it is never seen here later): its create starts it once made, its
    /// memory taken now as a create's is (ADR 0048). The machine as it is, `creating`.
    pub(super) fn creating(&self, e: &Entry) -> Result<api::Machine, MError> {
        let r = e.snapshot();
        if r.start {
            return Ok(self.view(e));
        }
        let quota = self
            .namespace_of(&r.namespace)
            .map(|t| t.rec.quota)
            .unwrap_or_default();
        // The machine and its volume are counted already: its size is what it adds.
        let need = api::QuotaUse {
            memory_mb: r.size.memory_mb,
            vcpus: r.size.vcpus,
            cpu_millis: Some(r.size.cpu_millis()),
            ..Default::default()
        };
        {
            let machines = self.inner.machines.lock().unwrap();
            let held = namespace_use(&machines, &r.namespace);
            if let Some(x) = over_quota(&r.namespace, &quota, &held, &need) {
                drop(machines);
                e.note(x.event(format!("start refused: {x}")));
                return Err(MError::Quota(x.to_string()));
            }
            let (used, _) = committed(&machines);
            self.memory_admission(&machines)?;
            admit(
                used.memory_mb,
                self.capacity().memory_mb,
                host_memory(r.size.memory_mb)?,
            )?;
            admit_cpu(
                used.cpu_millis(),
                self.capacity().cpu_millis(),
                r.size.cpu_millis(),
            )?;
            e.rec.lock().unwrap().start = true;
        }
        self.save(e)?;
        Ok(self.view(e))
    }

    /// Starts a machine that went to sleep, that the host stopped or whose process ended;
    /// one stopped on purpose stays stopped.
    pub async fn wake(&self, id: &str, at: Option<u64>) -> Result<api::Machine, MError> {
        let e = self.own_entry(id)?;
        let _turns = e.lock_once_stopped(false).await;
        self.check_version(&e, at)?;
        let r = e.snapshot();
        match r.state.as_str() {
            state::RUNNING => {
                e.touch();
                return Ok(self.view(&e));
            }
            state::CREATING => return self.creating(&e),
            state::STOPPED if r.stopped_reason == stop::USER => {
                return Err(MError::NotRunning("stopped on request".into()))
            }
            state::ERROR => return Err(MError::BadState(r.state)),
            _ => {}
        }
        self.start_entry(&e, true).await?;
        Ok(self.view(&e))
    }

    /// `start_entry` behind a boxed future: the restart path recurses through a spawned task,
    /// and the compiler needs the cycle broken somewhere.
    pub(super) fn start_boxed<'a>(
        &'a self,
        e: &'a Arc<Entry>,
        asked: bool,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), MError>> + Send + 'a>> {
        Box::pin(self.start_entry(e, asked))
    }

    /// Boots the machine. Called with the entry's lock held, on a machine that is not up:
    /// one being destroyed is refused here, whoever asks (a start, a wake, a restart).
    /// `asked`: a caller asked for this run (a create, a start, a wake), not the restart
    /// policy; its startup probe failing is a failed boot (ADR 0022).
    pub(super) async fn start_entry(&self, e: &Arc<Entry>, asked: bool) -> Result<(), MError> {
        let cfg = &self.inner.cfg;
        let rec = e.snapshot();
        match rec.state.as_str() {
            // `creating`: the create's own start (`make`), its lock held throughout.
            state::CREATING | state::CREATED | state::STOPPED | state::ERROR => {}
            other => return Err(MError::BadState(other.into())),
        }
        if rec.state == state::ERROR && !rec.has_disks() {
            return Err(made_never(&rec));
        }
        self.check_host_size(
            rec.pending
                .as_ref()
                .and_then(|p| p.size.as_ref())
                .unwrap_or(&rec.size),
        )?;
        // A pending change's image is pulled and built before anything moves (ADR 0024): a
        // failure is the boot's, and the change waits for the next start.
        let image = match rec.pending.as_ref().and_then(|p| p.image.clone()) {
            Some(reference) => match self.inner.images.ensure(&reference).await {
                Ok(im) => Some(im),
                Err(err) => {
                    self.inner.stats.starts_failed.fetch_add(1, Relaxed);
                    return Err(self.boot_failed(e, format!("image {reference}: {err:#}")));
                }
            },
            None => None,
        };
        // Resolved before anything moves: a `via` whose machine is gone refuses the start.
        let policy = self.policy_for(&rec)?;
        // Through the namespace's gateway: it runs first, and the namespace's lock is kept until
        // this machine is `starting`, which is what the sleeper looks for.
        let gateway_turn = match rec.egress.via_gateway() {
            true => Some(
                self.ensure_gateway(&rec.namespace)
                    .await
                    .map_err(|err| self.gateway_failed(e, err))?,
            ),
            false => None,
        };
        self.reserve(e, image)?;
        drop(gateway_turn);
        let _ = self.save(e);
        // The host's fault (a network, disk or Firecracker error): the machine ends in
        // `error` and the caller gets a 500.
        let fail = |err: anyhow::Error| -> MError {
            self.inner
                .stats
                .starts_failed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            e.set_state(state::ERROR, |r| {
                r.error = format!("{err:#}");
                r.error_reason = reason::START_FAILED.into();
                r.stopped_at = Some(Utc::now());
                r.pid = 0;
                Some(Ev::warning(reason::START_FAILED, r.error.clone()))
            });
            let _ = self.save(e);
            MError::Other(err)
        };
        // A restore cut short first (ADR 0031), then a new image's root disk (ADR 0024).
        let rec = e.snapshot();
        // The machines they free a snapshot of are tidied apart, once the caller's lock
        // is released (ADR 0031): never another machine's lock under this one's.
        if rec.restoring.is_some() {
            let parents = self
                .finish_restore(e)
                .await
                .map_err(|err| fail(anyhow!("{err:#}")))?;
            self.tidy_later(parents);
        }
        let rec = e.snapshot();
        if rec.root_key != rec.image_key {
            let parents = self.remake_root(e).await.map_err(fail)?;
            self.tidy_later(parents);
        }
        // What this boot runs: the record, the change it applied on it.
        let rec = e.snapshot();
        let t = match self.namespace_of(&rec.namespace) {
            Some(t) => t,
            None => return Err(fail(anyhow!("namespace network is gone"))),
        };
        let tap = self
            .inner
            .net
            .ensure_tap(&rec.id, &netw::bridge_name(t.rec.subnet_index), &rec.ip)
            .await
            .map_err(fail)?;
        self.set_policy(&rec.id, policy).await.map_err(fail)?;
        let dir = cfg.run_dir().join(&rec.id);
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| fail(e.into()))?;
        let config_drive = dir.join("config.tar");
        self.write_config_drive(&config_drive, &rec, &t)
            .map_err(fail)?;
        let root_dev = self
            .inner
            .zfs
            .device(&rec.root_dataset())
            .await
            .context("root disk")
            .map_err(fail)?;
        let data_dev = match &rec.volume {
            Some(_) => Some(
                self.inner
                    .zfs
                    .device(&rec.data_dataset())
                    .await
                    .context("data volume")
                    .map_err(fail)?,
            ),
            None => None,
        };
        // Where this boot's lines start in the console (the writer rotates it by size).
        let console_offset = console::end(&dir).unwrap_or(0);
        e.rec.lock().unwrap().console_offset = console_offset;
        let ip: Ipv4Addr = rec.ip.parse().unwrap();
        let boot = fc::Boot {
            id: rec.id.clone(),
            dir,
            jail: self.jail_for(&rec),
            oom_class: rec.oom_class(),
            vcpus: rec.size.vcpus,
            memory_mb: rec.size.memory_mb,
            kernel: cfg.kernel.clone(),
            boot_args: self.boot_args(),
            config_drive,
            root: root_dev,
            data: data_dev,
            tap,
            mac: netw::mac_for(ip),
            resume: rec.suspended,
            disk: self.disk_rate(&rec),
            disk_io: e.disk_io.clone(),
        };
        // Boots take their turn: a host asked for many at once boots a few at a time, each
        // with the whole timeout, instead of all of them crawling past it together.
        let _boot_turn = self
            .inner
            .boot_gate
            .acquire()
            .await
            .map_err(|e| fail(anyhow!(e)))?;
        // CPU time counts from what the machine's cgroup holds before this boot.
        let cpu = self
            .inner
            .vmm
            .cgroup(&rec.id)
            .await
            .map_or(0, |c| c.cpu_usec);
        e.meter.lock().unwrap().boot(cpu);
        let live = self.inner.vmm.boot(&boot).await.map_err(fail)?;
        {
            self.retain_memory_policy(e, &live);
            *e.live.lock().unwrap() = Some(live.clone());
            *e.stop_req.lock().unwrap() = None;
            let mut r = e.rec.lock().unwrap();
            r.pid = live.pid;
            r.suspended = false;
            if !live.resumed {
                r.boots += 1;
                r.vmm_version = self.inner.vmm.version();
            }
        }
        let _ = self.save(e);
        self.watch(e, &live);

        let ready = self.inner.guest.wait_ready(
            &live.vsock,
            Duration::from_secs(cfg.boot_timeout_sec.max(10)),
        );
        let mut exited = live.exited.clone();
        let outcome = tokio::select! {
            r = ready => r.map_err(|err| (format!("the guest did not come up: {err}"), false)),
            // `exited` is sent once the console is fully written, so the tail is complete.
            _ = exited.changed() => self.ran_before_ready(&live).await,
        };
        if let Ok(init) = &outcome {
            e.rec.lock().unwrap().init_version = init.clone();
        }
        if let Err((why, said)) = outcome {
            // The image's fault: the process is ended here, under the lock, so the watcher
            // finds nothing to settle and no restart policy applies. The machine stays in
            // `error`, with the init's reason or else the console's last lines, for the
            // caller to read and destroy.
            self.end_process(e, &live, Duration::ZERO).await;
            self.inner.stats.starts_failed.fetch_add(1, Relaxed);
            let why = match said {
                true => why,
                false => format!("{why}: {}", self.last_console_lines(&rec, 5)),
            };
            return Err(self.boot_failed(e, why));
        }
        let (_, _, generation) = self.reset_probes(e);
        e.set_state(state::RUNNING, |r| {
            let now = Utc::now();
            r.started_at = Some(now);
            r.last_used_at = Some(now);
            r.stopped_reason.clear();
            let pid = live.pid;
            let ev = match live.resumed {
                true => Ev::normal(
                    reason::RESUMED,
                    format!("resumed from its memory snapshot, pid {pid}"),
                ),
                false => Ev::normal(reason::STARTED, format!("running, pid {pid}")),
            };
            Some(ev.data(json!({ "pid": pid })))
        });
        self.spawn_probes(e, &live, generation, asked);
        let _ = self.save(e);
        tracing::info!(
            machine = rec.id,
            namespace = rec.namespace,
            name = rec.name,
            ip = rec.ip,
            pid = live.pid,
            resumed = live.resumed,
            "machine running"
        );
        use std::sync::atomic::Ordering::Relaxed;
        if live.resumed {
            self.inner.stats.resumes.fetch_add(1, Relaxed);
        } else {
            self.inner.stats.boots.fetch_add(1, Relaxed);
        }
        Ok(())
    }

    /// A boot whose process ended before the init's pong: a main process that ran and exited
    /// at once is a boot that came up (the watcher then settles its exit, as any later one),
    /// with the version its init reported; one the init never started is a failed boot, with
    /// the init's reason when it said one (true). The report is already in or never comes:
    /// its channel closes with the process.
    async fn ran_before_ready(&self, live: &fc::Vm) -> Result<String, (String, bool)> {
        let mut exit = live.exit.clone();
        let _ = exit.wait_for(|r| r.is_some()).await;
        let report = exit.borrow().clone();
        let why = "the machine exited during boot";
        match report {
            Some(r) if r.started => Ok(r.version),
            Some(r) if !r.error.is_empty() => Err((format!("{why}: {}", r.error), true)),
            _ => Err((why.to_string(), false)),
        }
    }

    /// A boot the machine's spec fails (ADR 0011): the machine left in `error` with why, a
    /// `boot_failed` event, and the 409 that carries the machine. Its process is already gone.
    pub(super) fn boot_failed(&self, e: &Entry, why: String) -> MError {
        e.set_state(state::ERROR, |r| {
            r.error = why;
            r.error_reason = reason::BOOT_FAILED.into();
            r.stopped_at = Some(Utc::now());
            r.pid = 0;
            Some(Ev::warning(reason::BOOT_FAILED, r.error.clone()))
        });
        let _ = self.save(e);
        MError::BootFailed(Box::new(self.view(e)))
    }

    /// Makes the root disk again from the record's image, before a boot (ADR 0024): the root
    /// disk is swapped for a clone of the image (ADR 0031), the old one retired and kept only
    /// while forks clone it; the snapshots' root halves and memory go, since the root disk
    /// follows the image; the data volume is not touched. The image comes from the cache,
    /// pulled again when the host removed it since the start resolved it. Returns the
    /// machines whose snapshots the old root disk was cloned from, to tidy.
    async fn remake_root(&self, e: &Entry) -> Result<Vec<String>> {
        let im = self.inner.images.ensure(&e.snapshot().image).await?;
        let base = im.dataset();
        {
            let mut r = e.rec.lock().unwrap();
            r.image_key = im.key;
            r.image_digest = im.digest;
            r.image_config = im.config;
        }
        let r = e.snapshot();
        self.finish_swap(&r, "root")
            .await
            .context("the root disk")?;
        self.swap(&r, "root", &base, image::SNAP)
            .await
            .context("the root disk")?;
        let dropped = {
            let mut rec = e.rec.lock().unwrap();
            rec.root_key = rec.image_key.clone();
            let dropped: Vec<String> = rec
                .snapshots
                .iter()
                .filter(|s| s.memory.is_some())
                .map(|s| s.id.clone())
                .collect();
            for s in rec.snapshots.iter_mut() {
                s.disks.retain(|d| d != "root");
                s.memory = None;
            }
            rec.snapshots.retain(|s| !s.disks.is_empty());
            dropped
        };
        for snap in dropped {
            self.remove_memory(&r, &snap);
        }
        self.save(e)?;
        Ok(self.tidy_or_warn(e).await)
    }

    /// The jail of a machine, when the daemon runs Firecracker under the jailer: one uid per
    /// machine, from its place in the namespace's network.
    pub(super) fn jail_for(&self, rec: &Record) -> Option<fc::Jail> {
        let cfg = &self.inner.cfg;
        if cfg.jailer.as_os_str().is_empty() {
            return None;
        }
        let uid = jail_uid(cfg.jail_uid_base, rec.subnet_index, rec.host_num);
        Some(fc::Jail {
            jailer: cfg.jailer.clone(),
            base: cfg.jail_base(),
            uid,
            gid: uid,
            cpu_millis: rec.size.cpu_millis(),
            // Guest memory, plus what Firecracker itself needs around it.
            memory_mb: api::vmm_memory_mb(rec.size.memory_mb).unwrap_or(u32::MAX),
        })
    }

    /// The limits on each of its disks: its own over the host's for its size (ADR 0030).
    pub(super) fn disk_rate(&self, rec: &Record) -> fc::DiskRate {
        self.inner
            .cfg
            .disk_limits
            .with(rec.size.vcpus, &rec.disk_limits)
    }

    pub(super) fn boot_args(&self) -> String {
        boot_args(self.inner.cfg.pci, &self.inner.cfg.kernel_args)
    }

    // --- config drive ---

    fn write_config_drive(&self, path: &Path, r: &Record, t: &Namespace) -> Result<()> {
        write_drive(path, &config_drive(r, t.subnet.gateway())?)
    }
}

/// The uid (and gid) a jailed machine runs as: one per machine, from its place in the
/// namespace's network, so no two machines on the host share one.
pub(super) fn jail_uid(base: u32, subnet_index: u32, host_num: u8) -> u32 {
    base + subnet_index * 256 + host_num as u32
}

/// The guest kernel's command line. The root disk is mounted with `discard`: what the guest
/// deletes goes back to the pool (ADR 0037).
pub(super) fn boot_args(pci: bool, extra: &str) -> String {
    let mut args = format!(
        "console=ttyS0 reboot=k panic=1 root=/dev/vda rw rootfstype=ext4 rootflags=discard i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd random.trust_cpu=on init={}",
        image::INIT_PATH
    );
    if !pci {
        args.push_str(" pci=off");
    }
    if !extra.is_empty() {
        args.push(' ');
        args.push_str(extra);
    }
    args
}

/// The config drive: a tar archive the init reads raw, `config.json` first and the boot
/// files under `files/`, padded to a multiple of 512 bytes since Firecracker wants a drive
/// that size.
pub(super) fn config_drive(r: &Record, gateway: Ipv4Addr) -> Result<Vec<u8>> {
    let mut env = r.image_config.env.clone();
    env.extend(r.env.iter().map(|(k, v)| (k.clone(), v.clone())));
    // Docker semantics: an entrypoint given replaces the image's and drops its cmd.
    let (entrypoint, cmd) = match (&r.entrypoint, &r.cmd) {
        (Some(ep), Some(c)) => (ep.clone(), c.clone()),
        (Some(ep), None) => (ep.clone(), vec![]),
        (None, Some(c)) => (r.image_config.entrypoint.clone(), c.clone()),
        (None, None) => (
            r.image_config.entrypoint.clone(),
            r.image_config.cmd.clone(),
        ),
    };
    let mut hosts = BTreeMap::new();
    hosts.insert(r.hostname(), r.ip.clone());
    hosts.insert(r.machine_host(), r.ip.clone());
    let mut cfg = guest::Config {
        hostname: r.name.clone(),
        ip: format!("{}/24", r.ip),
        gateway: gateway.to_string(),
        dns: vec![gateway.to_string()],
        hosts,
        entrypoint,
        cmd,
        env,
        workdir: r.image_config.workdir.clone(),
        user: r.image_config.user.clone(),
        mounts: vec![],
        files: vec![],
        stop_timeout_sec: 10,
    };
    if let Some(v) = &r.volume {
        cfg.mounts.push(guest::Mount {
            device: "/dev/vdc".into(),
            path: v.mount.clone(),
            fstype: "ext4".into(),
        });
    }
    let mut files: Vec<(String, u32, Vec<u8>)> = Vec::new();
    for f in &r.files {
        let data = guest::base64_decode(&f.base64).map_err(|e| anyhow!("file {}: {e}", f.path))?;
        let mode = match &f.mode {
            Some(m) if !m.is_empty() => {
                u32::from_str_radix(m, 8).map_err(|_| anyhow!("file {}: mode {m:?}", f.path))?
            }
            _ => 0o644,
        };
        cfg.files.push(guest::FileMeta {
            path: f.path.clone(),
            mode,
        });
        files.push((f.path.clone(), mode, data));
    }
    let mut b = tar::Builder::new(Vec::new());
    let cfg_json = serde_json::to_vec(&cfg)?;
    let mut h = tar::Header::new_gnu();
    h.set_mode(0o600);
    h.set_size(cfg_json.len() as u64);
    h.set_mtime(Utc::now().timestamp() as u64);
    b.append_data(&mut h, guest::CONFIG_NAME, &cfg_json[..])?;
    for (p, mode, data) in &files {
        let mut h = tar::Header::new_gnu();
        h.set_mode(*mode);
        h.set_size(data.len() as u64);
        h.set_mtime(Utc::now().timestamp() as u64);
        b.append_data(
            &mut h,
            format!("{}{}", guest::FILES_PREFIX, p.trim_start_matches('/')),
            &data[..],
        )?;
    }
    let mut out = b.into_inner()?;
    let pad = (512 - out.len() % 512) % 512;
    out.resize(out.len() + pad, 0);
    Ok(out)
}

/// Writes a drive whole and for the daemon alone (it holds the machine's secrets): through a
/// temp file next to it, so a crash leaves the previous drive or none, never half of one.
pub(super) fn write_drive(path: &Path, data: &[u8]) -> Result<()> {
    crate::store::write_private(path, data)
}
