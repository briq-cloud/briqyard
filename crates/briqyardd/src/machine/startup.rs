//! Starting the manager: loading the records, recovering what a previous daemon left, and the host facts the defaults come from.

use super::*;

impl Manager {
    /// Loads the state and prepares the host: forwarding, nftables, the namespaces' bridges and
    /// DNS, and reaps machines left over from a previous daemon.
    pub async fn new(
        cfg: Config,
        store: Store,
        zfs: Zfs,
        mut images: Builder,
        dns: Resolver,
    ) -> Result<Self> {
        let range = Range::parse(&cfg.network.range).context("network.range")?;
        let host_id = match store.get_meta("host_id")? {
            Some(id) => id,
            None => {
                let id = new_id("h");
                store.put_meta("host_id", &id)?;
                id
            }
        };
        let egress = if cfg.network.egress.is_empty() {
            host::default_egress_interface()
                .await
                .context("network.egress")?
        } else {
            cfg.network.egress.clone()
        };
        tokio::fs::create_dir_all(cfg.run_dir()).await?;
        let boots_at_once = if cfg.boots_at_once > 0 {
            cfg.boots_at_once
        } else {
            (std::thread::available_parallelism()
                .map(|n| n.get() as u32)
                .unwrap_or(4)
                / 2)
            .max(2)
        };
        let backups = Backups::open(&cfg.backup, &store)?;
        let (endpoint_events, _) = broadcast::channel(64);
        let ledger = Ledger::load(&store, Utc::now()).context("usage")?;
        let events = Events::open(&store.dir("events")).context("events")?;
        images.events = Some(events.clone());
        let advertise = advertise_address(
            &cfg.ingress.advertise,
            &cfg.ingress.bind,
            host_ip(&egress).await,
        );
        let inner = Arc::new(Inner {
            stats: Stats::default(),
            verified_templates: Mutex::new(std::collections::HashSet::new()),
            vmm: Arc::new(fc::Firecracker {
                binary: cfg.firecracker.clone(),
                pci: cfg.pci,
                console_max: (cfg.console_max_mb as u64) << 20,
                version: fc::vmm_version(&cfg.firecracker)?,
                identity: fc::BootIdentity::read(&cfg.kernel, &cfg.firecracker, cfg.pci)?,
            }),
            guest: Arc::new(guestc::Vsock),
            net: Arc::new(host::HostNet::new().await?),
            cfg,
            store,
            zfs,
            images,
            dns,
            range,
            egress,
            host_id,
            advertise,
            machines: Mutex::new(HashMap::new()),
            address_holds: Mutex::new(std::collections::HashSet::new()),
            namespaces: Mutex::new(HashMap::new()),
            endpoints: Mutex::new(HashMap::new()),
            endpoint_events,
            policies: Mutex::new(HashMap::new()),
            namespace_create: tokio::sync::Mutex::new(()),
            namespace_lifecycle: tokio::sync::RwLock::new(()),
            backups,
            boot_gate: tokio::sync::Semaphore::new(boots_at_once as usize),
            probe_gate: tokio::sync::Semaphore::new(probes::PROBES_AT_ONCE),
            began: tokio::time::Instant::now(),
            probe_spread: Box::new(rand::random::<f64>),
            usage: Mutex::new(ledger),
            events,
            pool: Mutex::new(None),
            conditions: Mutex::new(Conditions::new(Utc::now())),
            started: Mutex::new(api::DaemonStart::default()),
        });
        let m = Self { inner };
        m.load()?;
        m.verify_clone_artifacts();
        host::enable_forwarding()?;
        let namespaces: Vec<Namespace> = m
            .inner
            .namespaces
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        for t in &namespaces {
            m.plumb_namespace(t).await?;
            m.refresh_dns(t);
        }
        m.apply_rules().await?;
        let (adopted, stopped, gone) = m.recover().await;
        let swept = m.sweep_orphans().await;
        let machines = m.inner.machines.lock().unwrap().len();
        *m.inner.started.lock().unwrap() = api::DaemonStart {
            at: Utc::now(),
            adopted,
            stopped,
            gone,
        };
        m.inner.events.emit(
            Ev::normal(
                reason::HOST_STARTED,
                format!("daemon started: {adopted} machines adopted, {stopped} not handed over and {gone} gone marked stopped, {swept} leftovers swept"),
            )
            .data(json!({
                "version": api::VERSION, "vmm_version": m.inner.vmm.version(),
                "machines": machines, "adopted": adopted, "stopped": stopped, "gone": gone,
                "swept": swept,
            })),
        );
        m.start_stopped_by_host();
        let sleeper = m.clone();
        tokio::spawn(async move { sleeper.sleeper().await });
        let watch = m.clone();
        tokio::spawn(async move { watch.storage_watch().await });
        Ok(m)
    }

    pub fn host_id(&self) -> &str {
        &self.inner.host_id
    }

    /// Reads the records. A namespace whose subnet index is outside `network.range`, or an
    /// endpoint whose port is outside `ingress.tcp_ports`, is refused here, with the fix, rather than found by the first request that needs its subnet. The
    /// event log goes on past every machine's version.
    pub(super) fn load(&self) -> Result<()> {
        let st = &self.inner.store;
        for rec in st.list::<NamespaceRec>(crate::store::NAMESPACES)? {
            let subnet = self.inner.range.subnet(rec.subnet_index).with_context(|| {
                format!(
                    "namespace {}: widen network.range back, or remove the namespace",
                    rec.id
                )
            })?;
            self.inner
                .namespaces
                .lock()
                .unwrap()
                .insert(rec.id.clone(), Namespace::new(rec, subnet));
        }
        let records = st.list::<Record>("machines")?;
        // An address is one record's at a time: a `destroying` record whose address another
        // holds is a destroyed machine's, written back after its destroy by an older daemon.
        // Its destroy ran; another would take the address's counters, and its limits, from
        // the machine that holds it now. Removed, nothing else done.
        let held: std::collections::HashSet<String> = records
            .iter()
            .filter(|r| r.state != state::DESTROYING && !r.ip.is_empty())
            .map(|r| r.ip.clone())
            .collect();
        let (records, stale): (Vec<Record>, Vec<Record>) = records
            .into_iter()
            .partition(|r| r.state != state::DESTROYING || !held.contains(&r.ip));
        for r in stale {
            st.delete("machines", &r.id)?;
            tracing::warn!(
                machine = r.id,
                ip = r.ip,
                "record of a destroyed machine, written back after its destroy: removed"
            );
        }
        for mut r in records {
            r.migrate();
            self.inner.events.floor(r.version);
            let id = r.id.clone();
            self.inner
                .machines
                .lock()
                .unwrap()
                .insert(id, Entry::new(r, self.inner.events.clone()));
        }
        self.drop_renamed_leftovers()?;
        // An endpoint port outside the range would listen where the daemon's table does not
        // hold it for `allowed_clients`: refused, like a namespace outside `network.range`.
        let spec = &self.inner.cfg.ingress.tcp_ports;
        let (lo, hi) = port_range(spec).map_err(|e| anyhow!("{e}"))?;
        for ep in st.list::<EndpointRec>("endpoints")? {
            if let Some(p) = ep.host_port.filter(|p| !(lo..=hi).contains(p)) {
                bail!(
                    "endpoint {} (machine {}) holds host port {p}, outside ingress.tcp_ports \
                     {spec}: put the range back, or remove the endpoint",
                    ep.id,
                    ep.machine_id
                );
            }
            self.inner
                .endpoints
                .lock()
                .unwrap()
                .insert(ep.id.clone(), ep);
        }
        Ok(())
    }

    /// Machines a previous daemon left running: adopted when their Firecracker is still up
    /// and answering, else ended (only a process that still carries the machine's id is
    /// killed: after a reboot the pid is someone else's) and marked stopped by the host, so
    /// the next use wakes them. A create it left is failed (ADR 0048). Destroys cut short are
    /// resumed by the sleeper's tick. How many were adopted, and how many marked stopped.
    pub(super) async fn recover(&self) -> (usize, usize, usize) {
        let entries: Vec<Arc<Entry>> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        let (mut adopted, mut stopped, mut gone) = (0, 0, 0);
        let ready = self.take_handed_ready();
        for e in entries {
            let rec = e.snapshot();
            // Its create's task went with the previous daemon. One from an image is taken up
            // again, its partial disks gone first: the record holds what it needs. What a fork
            // or a restore was made from is not on the record: failed, for the caller to create
            // again, and nothing a person must look at (ADR 0048).
            if rec
                .clone_origin
                .as_ref()
                .is_some_and(|o| o.stage != templates::CloneStage::Active)
            {
                tracing::warn!(
                    machine = rec.id,
                    "incomplete memory clone retained under quarantine; explicit destroy required"
                );
                continue;
            }
            if rec.state == state::CREATING {
                self.recover_create(&e).await;
                continue;
            }
            if !matches!(
                rec.state.as_str(),
                state::RUNNING | state::STARTING | state::STOPPING
            ) {
                continue;
            }
            if rec.state == state::RUNNING
                && rec.pid > 0
                && self.adopt(&e, rec.pid, ready.contains(&rec.id)).await
            {
                adopted += 1;
                continue;
            }
            // Its process still there but not answering for it (not handed over), or gone: it
            // exited while no daemon ran.
            let alive =
                rec.pid > 0 && self.inner.vmm.machine_of(rec.pid).as_deref() == Some(&rec.id);
            let why = match alive {
                true => {
                    stopped += 1;
                    self.inner.vmm.kill(rec.pid);
                    "left running by a previous daemon that could not hand it over: stopped"
                }
                false => {
                    gone += 1;
                    "its process ended while no daemon ran: stopped"
                }
            };
            let _ = self.unplug(&rec.id, &rec.ip).await;
            e.set_state(state::STOPPED, |r| {
                r.stopped_reason = stop::HOST.into();
                r.pid = 0;
                r.stopped_at = Some(Utc::now());
                Some(Ev::warning(reason::STOPPED, why).data(json!({"reason": stop::HOST})))
            });
            tracing::warn!(
                machine = rec.id,
                "machine left running by a previous daemon, marked stopped"
            );
            let _ = self.save(&e);
        }
        // An adopted machine that sends through its namespace's gateway needs it, and the
        // gateway's own process may not have survived: it starts as a start would start it.
        for gw in self.gateways_out_of_step(false) {
            let (m, namespace) = (self.clone(), gw.snapshot().namespace);
            tokio::spawn(async move {
                if let Err(err) = m.ensure_gateway(&namespace).await {
                    tracing::warn!(namespace, err = %err, "gateway an adopted machine needs");
                }
            });
        }
        (adopted, stopped, gone)
    }

    /// Admission precedes partial-disk cleanup; closed startup work leaves its source alone.
    async fn recover_create(&self, e: &Arc<Entry>) {
        let scope = match self.inner.zfs.io_scope() {
            Ok(scope) => scope,
            Err(error) => {
                tracing::warn!(err = %error, "create recovery admission closed");
                return;
            }
        };
        scope
            .run(async {
                let rec = e.snapshot();
                match self.clone_readers() {
                    Ok(readers) if readers.iter().any(|r| r.destination == rec.id || r.source_machine == rec.id) => {
                        tracing::warn!(machine = rec.id, "incomplete clone with memory reference retained for reconciliation");
                        return;
                    }
                    Err(error) => {
                        tracing::error!(err = %error, "clone references unreadable: create recovery deferred");
                        return;
                    }
                    _ => {}
                }
                if !rec.from_source {
                    let child_scope = match self.inner.zfs.io_scope() {
                        Ok(scope) => scope,
                        Err(error) => {
                            tracing::warn!(err = %error, "create recovery reservation failed");
                            return;
                        }
                    };
                    let z = &self.inner.zfs;
                    if z.exists(&rec.dataset()).await.unwrap_or(false) {
                        if let Err(err) = z.destroy(&rec.dataset()).await {
                            tracing::warn!(machine = rec.id, err = %err, "disks of a cut create");
                        }
                    }
                    tracing::info!(machine = rec.id, "create cut by a restart, taken up again");
                    self.spawn_make_admitted(child_scope, e.clone(), Make::Image);
                } else {
                    let why = "its create was cut short by a restart of the host's daemon";
                    tracing::warn!(machine = rec.id, "{why}");
                    self.create_failed(e, reason::CREATE_FAILED, why.into())
                        .await;
                }
            })
            .await;
    }

    /// Resources a previous daemon left with no record to own them: a crash between a resource
    /// and its record, or a destroy cut short. A Firecracker nobody knows is ended; its run
    /// directory, jail, TAP and disks go. Done once at start, so nothing leaks for good. How
    /// many it found.
    pub(super) async fn sweep_orphans(&self) -> usize {
        let mut known: std::collections::HashSet<String> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        // Read intents predate staging/load. Retain both sides on ambiguous recovery;
        // even a recordless VMM may still fault its private artifact mapping.
        match self.clone_readers() {
            Ok(readers) => {
                for reader in readers {
                    known.insert(reader.source_machine);
                    known.insert(reader.destination);
                }
            }
            Err(error) => {
                tracing::error!(err = %error, "clone references unreadable: orphan cleanup deferred");
                return 0;
            }
        }
        let mut swept = 0;
        for (pid, id) in self.inner.vmm.processes() {
            if !known.contains(&id) {
                self.inner.vmm.kill(pid);
                tracing::warn!(machine = id, pid, "firecracker with no record, ended");
                swept += 1;
            }
        }
        if let Ok(mut rd) = tokio::fs::read_dir(self.inner.cfg.run_dir()).await {
            while let Ok(Some(e)) = rd.next_entry().await {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.starts_with("m_") && !known.contains(&name) {
                    let _ = tokio::fs::remove_dir_all(e.path()).await;
                    tracing::warn!(machine = name, "run directory with no record, removed");
                    swept += 1;
                }
            }
        }
        let jails = self.inner.cfg.jail_base().join("firecracker");
        if let Ok(mut rd) = tokio::fs::read_dir(&jails).await {
            while let Ok(Some(e)) = rd.next_entry().await {
                let name = e.file_name().to_string_lossy().into_owned();
                let id = name.replacen("m-", "m_", 1);
                if name.starts_with("m-") && !known.contains(&id) {
                    let _ = tokio::fs::remove_dir_all(e.path()).await;
                    tracing::warn!(machine = id, "jail with no record, removed");
                    swept += 1;
                }
            }
        }
        if let Ok(taps) = self.inner.net.list_taps().await {
            let owned: std::collections::HashSet<String> =
                known.iter().map(|id| netw::tap_name(id)).collect();
            for t in taps {
                if !owned.contains(&t) {
                    let _ = self.inner.net.delete_link(&t).await;
                    tracing::warn!(tap = t, "tap with no record, removed");
                    swept += 1;
                }
            }
        }
        // Every `m/<id>`, with its disks or none: a create cut between its dataset and its
        // first disk leaves it empty.
        if let Ok(children) = self.inner.zfs.children("m").await {
            for id in children.iter().filter_map(|c| c.strip_prefix("m/")) {
                if !known.contains(id) {
                    match self.inner.zfs.destroy(&format!("m/{id}")).await {
                        Ok(()) => {
                            tracing::warn!(machine = id, "dataset with no record, destroyed");
                            swept += 1;
                        }
                        Err(err) => {
                            tracing::warn!(machine = id, err = %err, "dataset with no record")
                        }
                    }
                }
            }
        }
        // A restore cut short goes on; a snapshot or a retired disk nothing needs goes: a
        // fork's that outlived the fork, one taken when the daemon died before its record.
        swept += self.tidy_at_start().await;
        if swept > 0 {
            tracing::info!(swept, "orphans swept at start");
        }
        swept
    }

    /// Takes over a VMM a previous daemon left running (it crashed; a shutdown suspends
    /// them instead), when the VMM still answers for the machine.
    ///
    /// `ready`: the previous daemon handed it over ready (ADR 0051). Its probes still start
    /// over, and failing them as often as a failure threshold takes that back.
    pub(super) async fn adopt(&self, e: &Arc<Entry>, pid: u32, ready: bool) -> bool {
        let rec = e.snapshot();
        let dir = self.inner.cfg.run_dir().join(&rec.id);
        let jail = self.jail_for(&rec);
        let Some(vm) = self
            .inner
            .vmm
            .adopt(&rec.id, &dir, jail.as_ref(), pid, e.disk_io.clone())
            .await
        else {
            return false;
        };
        let bound = rec
            .boot_incarnation
            .as_ref()
            .zip(vm.incarnation.as_ref())
            .is_some_and(|(saved, actual)| saved == actual);
        e.identity_trusted.store(bound, Relaxed);
        let identity = fc::BootIdentity::after_adoption(
            rec.boot_identity.as_ref(),
            vm.boot_identity.as_ref(),
            bound,
        );
        if identity != rec.boot_identity {
            e.rec.lock().unwrap().boot_identity = identity;
            if let Err(err) = self.save(e) {
                tracing::warn!(machine = rec.id, err = %err, "adopted boot identity not saved");
            }
        }
        *e.live.lock().unwrap() = Some(vm.clone());
        *e.stop_req.lock().unwrap() = None;
        self.watch(e, &vm);
        // Its probes run again from the top; nobody waits on this run, so a startup that
        // fails is a crash for the restart policy, not a failed boot.
        let (_, _, generation) = self.reset_probes(e);
        if ready {
            e.probe.lock().unwrap().ready = true;
        }
        self.spawn_probes(e, &vm, generation, false);
        e.note(
            Ev::normal(
                reason::ADOPTED,
                format!("pid {pid}, left running by a previous daemon, taken over"),
            )
            .data(json!({"pid": pid})),
        );
        let _ = self.save(e);
        tracing::info!(
            machine = rec.id,
            pid,
            "adopted a machine left running by a previous daemon"
        );
        true
    }

    /// Settles the machine's state once its process is gone.
    pub(super) fn watch(&self, e: &Arc<Entry>, vm: &fc::Vm) {
        let (m, e, pid, mut exited) = (self.clone(), e.clone(), vm.pid, vm.exited.clone());
        tokio::spawn(async move {
            let _ = exited.wait_for(|gone| *gone).await;
            m.settle_exit(&e, pid).await;
        });
    }

    /// Starts again the machines the host stopped (the last shutdown suspended them, or a
    /// previous daemon could not hand them over) whose sleep window has not run out: what ran
    /// before the daemon went down runs once it is back, used or not (ADR 0027). Detached,
    /// through the boot gate; a gateway is started by what needs it.
    pub(super) fn start_stopped_by_host(&self) {
        let now = Utc::now();
        let left: Vec<Arc<Entry>> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .filter(|e| {
                let r = e.rec.lock().unwrap();
                stopped_by_host(&r) && !idle_past(r.last_used_at, r.sleep_window(), now)
            })
            .cloned()
            .collect();
        for e in left {
            let m = self.clone();
            tokio::spawn(async move {
                let _turns = e.lock_for_start().await;
                // A call may have moved it meanwhile (a wake, a stop, a destroy).
                if !stopped_by_host(&e.snapshot()) {
                    return;
                }
                if let Err(err) = m.start_entry(&e, false).await {
                    tracing::warn!(machine = e.snapshot().id, err = %err, "start again after the daemon's start");
                }
            });
        }
    }
}

/// The address TCP endpoints are reported at: `ingress.advertise`, else a bind address that
/// names one, else the egress interface's.
pub(super) fn advertise_address(advertise: &str, bind: &str, host_ip: Option<Ipv4Addr>) -> String {
    if !advertise.is_empty() {
        return advertise.into();
    }
    if !bind.is_empty() && bind != "0.0.0.0" {
        return bind.into();
    }
    host_ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| bind.into())
}

/// The first IPv4 address of an interface.
async fn host_ip(interface: &str) -> Option<Ipv4Addr> {
    let out = tokio::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show", "dev", interface])
        .output()
        .await
        .ok()?;
    inet_of(&String::from_utf8_lossy(&out.stdout))
}

pub(super) fn host_memory_mb() -> u32 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| meminfo_total_mb(&s))
        .unwrap_or(4096)
}

/// MemTotal from `/proc/meminfo`, in MB.
pub(super) fn meminfo_total_mb(text: &str) -> Option<u32> {
    text.lines()
        .find(|l| l.starts_with("MemTotal:"))
        .and_then(|l| {
            l.split_whitespace()
                .nth(1)
                .and_then(|kb| kb.parse::<u64>().ok())
        })
        .map(|kb| (kb / 1024) as u32)
}

/// What the host hands out when the configuration does not say: its memory less what it
/// keeps for itself and its other services (`capacity.reserved_memory_mb`, 2 GB) and less the
/// ZFS cache's ceiling when one is set (ADR 0028), at least 1 GB.
pub(super) fn default_memory_mb(host_mb: u32, reserved_mb: u32, arc_max_mb: u32) -> u32 {
    host_mb
        .saturating_sub(reserved_mb)
        .saturating_sub(arc_max_mb)
        .max(1024)
}

/// Four shared vCPUs a hardware thread, less the threads kept for the host's other services
/// (`capacity.reserved_threads`), at least one thread's.
pub(super) fn default_vcpus(threads: u32, reserved: u32) -> u32 {
    threads.saturating_sub(reserved).max(1) * 4
}

/// The ZFS cache's ceiling (`zfs_arc_max`, the bootstrap sets it), in MB; 0 when it is the
/// module's default, which the cache gives back under pressure.
pub(super) fn arc_max_mb() -> u32 {
    std::fs::read_to_string("/sys/module/zfs/parameters/zfs_arc_max")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|b| (b >> 20) as u32)
        .unwrap_or(0)
}

/// The first IPv4 address in `ip -4 -o addr show` output.
pub(super) fn inet_of(text: &str) -> Option<Ipv4Addr> {
    let f: Vec<&str> = text.split_whitespace().collect();
    let i = f.iter().position(|w| *w == "inet")?;
    f.get(i + 1)?.split('/').next()?.parse().ok()
}
