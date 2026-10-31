//! Creating a machine: the record, the disks, and the make that boots it.

use super::*;

impl Manager {
    // --- create ---

    /// The API's create (ADR 0048): answers once the machine is recorded, in `creating`; its
    /// image, disks and start follow in a task of its own, which leaves it running (or
    /// `created`), or in `error` with the reason. The caller waits with `/wait` or reads it.
    pub async fn create(&self, req: api::CreateMachineRequest) -> Result<api::Machine, MError> {
        let (e, how) = self.record(req, None).await?;
        let made = self.view(&e);
        self.spawn_make(e, how);
        Ok(made)
    }

    /// `make` in a task of its own: a create's background, from `create` or taken up again by
    /// `recover`.
    pub(super) fn spawn_make(&self, e: Arc<Entry>, how: Make) {
        let m = self.clone();
        tokio::spawn(async move {
            // Its outcome is on the machine, for a `/wait` or a read; logged once, here or
            // where the create failed (`create_failed`).
            match m.make(&e, how).await {
                Ok(())
                | Err(MError::NotFound | MError::PullFailed(_) | MError::CreateFailed(_)) => {}
                Err(MError::BootFailed(v)) => {
                    tracing::warn!(machine = v.id, err = v.error, "boot failed")
                }
                Err(err) => {
                    tracing::error!(machine = e.snapshot().id, err = %err, "create's start failed")
                }
            }
        });
    }

    /// The create's first half, what it answers on: the spec checked, the source found (a
    /// fork's machine, a restore's backup), the name, an address, the namespace's quota and, when
    /// it starts, the host's memory taken, the record written in `creating`.
    pub(super) async fn record(
        &self,
        req: api::CreateMachineRequest,
        role: Option<Role>,
    ) -> Result<(Arc<Entry>, Make), MError> {
        let _admission = self.inner.namespace_lifecycle.read().await;
        self.record_admitted(req, role).await
    }

    /// The caller already holds namespace admission (a gateway put keeps it through boot).
    pub(super) async fn record_admitted(
        &self,
        req: api::CreateMachineRequest,
        role: Option<Role>,
    ) -> Result<(Arc<Entry>, Make), MError> {
        check_namespace_id(&req.namespace)?;
        if let Some(rs) = &req.restore {
            if !api::valid_id(&rs.machine_id) {
                return Err(invalid("restore.machine_id is not a machine id"));
            }
        }
        if !api::valid_name(&req.name) {
            return Err(invalid("name must be a DNS label (a-z, 0-9, -)"));
        }
        if req.image.is_empty() && req.fork.is_none() && req.restore.is_none() {
            return Err(invalid("image is required"));
        }
        if req.fork.is_some() && req.restore.is_some() {
            return Err(invalid("fork and restore are one or the other"));
        }
        // A restore with no size takes the backup's; everything else says its size.
        let size_from_backup = req.restore.is_some() && req.size == api::Size::default();
        // What it runs, checked as a PATCH of it is (ADR 0024).
        let mut spec = req.spec();
        if size_from_backup {
            spec.size = None;
        }
        spec.check().map_err(invalid)?;
        if let Some(v) = &req.volume {
            if v.size_gb < 1 || !v.mount.starts_with('/') {
                return Err(invalid("volume needs size_gb >= 1 and an absolute mount"));
            }
        }
        api::parse_sleep(&req.sleep).map_err(invalid)?;
        check_limits(req.limits.as_ref())?;
        check_disk_limits(req.disk_limits.as_ref())?;
        if let Some(p) = &req.probes {
            p.check().map_err(invalid)?;
        }
        let restart = req.restart.clone().unwrap_or_default();
        // A cheap early answer, before a fork's or a restore's lookups; `add_machine` checks
        // again under the map's lock, where it counts.
        if let Some(e) = self.named(&req.namespace, &req.name) {
            return Err(MError::NameTaken(Box::new(self.view(&e))));
        }
        let now = Utc::now();
        let mut rec = Record {
            id: new_id("m"),
            namespace: req.namespace.clone(),
            role,
            name: req.name.clone(),
            image: String::new(),
            image_key: String::new(),
            image_digest: String::new(),
            image_config: ImageConfig::default(),
            root_key: String::new(),
            entrypoint: req.entrypoint.clone(),
            cmd: req.cmd.clone(),
            env: req.env.clone(),
            files: req.files.clone(),
            size: req.size,
            volume: req.volume.clone(),
            ports: req.ports.clone(),
            sleep: sleep_setting(&req.sleep),
            restart,
            probes: req.probes.clone().unwrap_or_default(),
            egress: req.egress.clone().unwrap_or_default(),
            limits: req.limits.clone().unwrap_or_default(),
            disk_limits: req.disk_limits.clone().unwrap_or_default(),
            metadata: req.metadata.clone(),
            state: state::CREATING.into(),
            stopped_reason: String::new(),
            exit: None,
            error: String::new(),
            error_reason: String::new(),
            start: req.start.unwrap_or(true),
            from_source: req.fork.is_some() || req.restore.is_some(),
            subnet_index: 0,
            host_num: 0,
            ip: String::new(),
            pid: 0,
            restarts: 0,
            recent_restarts: 0,
            restarting_at: None,
            boots: 0,
            created_at: now,
            updated_at: now,
            state_changed_at: now,
            started_at: None,
            stopped_at: None,
            last_used_at: None,
            console_offset: 0,
            suspended: false,
            backup_bytes: 0,
            backup: backups::schedule_of(&req.backup, &self.inner.cfg.backup, now)?,
            version: 0,
            pending: None,
            pending_since: None,
            init_version: String::new(),
            vmm_version: String::new(),
            rest: Default::default(),
            snapshots: Vec::new(),
            restoring: None,
        };
        self.check_egress(&rec.egress, &rec.namespace, &rec.id)?;
        let mut src: Option<(Arc<Entry>, api::ForkSpec)> = None;
        let mut restore_from: Option<(api::Backup, Option<String>)> = None;
        if let Some(rs) = &req.restore {
            let b = self.find_backup(&rs.machine_id, &rs.backup).await?;
            // The key its streams and its record are under (ADR 0035); none in a backup in clear.
            let key = self.backup_key(&b, rs).await?;
            let was: Record = serde_json::from_value(backups::spec_of(&b, key.as_deref())?)
                .map_err(|e| invalid(format!("backup {}: machine record: {e}", b.id)))?;
            // The request says what it says; the backup fills the rest.
            rec.image = was.image;
            rec.image_key = was.image_key;
            rec.image_digest = was.image_digest;
            rec.image_config = was.image_config;
            // The root disk comes from the backup: made from what it was made from.
            rec.root_key = was.root_key;
            if rec.entrypoint.is_none() {
                rec.entrypoint = was.entrypoint;
            }
            if rec.cmd.is_none() {
                rec.cmd = was.cmd;
            }
            let mut env = was.env;
            env.extend(rec.env.clone());
            rec.env = env;
            if rec.files.is_empty() {
                rec.files = was.files;
            }
            if req.ports.is_empty() {
                rec.ports = was.ports;
            }
            if req.egress.is_none() {
                rec.egress = was.egress;
                self.check_egress(&rec.egress, &rec.namespace, &rec.id)?;
            }
            if req.limits.is_none() {
                rec.limits = was.limits;
            }
            if req.disk_limits.is_none() {
                rec.disk_limits = was.disk_limits;
            }
            if req.probes.is_none() {
                rec.probes = was.probes;
            }
            if rec.size == api::Size::default() {
                rec.size = was.size;
            }
            match (&rec.volume, &was.volume) {
                (None, Some(v)) => rec.volume = Some(v.clone()),
                (Some(a), Some(b)) if a.mount != b.mount => {
                    return Err(invalid("a restore keeps the backup's volume mount"))
                }
                (Some(a), Some(b)) if a.size_gb < b.size_gb => {
                    return Err(never_shrinks(a.size_gb, b.size_gb))
                }
                (Some(_), None) => return Err(invalid("the backup has no volume to restore")),
                _ => {}
            }
            if b.disks.iter().any(|d| d.disk == "data") != rec.volume.is_some() {
                return Err(invalid("the backup's disks and the volume do not match"));
            }
            check_size(&rec.size)?;
            restore_from = Some((b, key));
        } else if let Some(fork) = &req.fork {
            let s = self.own_entry(&fork.machine_id).map_err(|e| match e {
                MError::NotFound => invalid("fork source not found"),
                other => other,
            })?;
            let sr = s.snapshot();
            if !sr.has_disks() {
                return Err(invalid(format!(
                    "fork source has no disks: it is {} {}",
                    sr.state, sr.error_reason
                )));
            }
            if !req.image.is_empty() && req.image != sr.image {
                return Err(invalid("a fork keeps its source's image"));
            }
            rec.image = sr.image.clone();
            rec.image_key = sr.image_key.clone();
            rec.image_digest = sr.image_digest.clone();
            rec.image_config = sr.image_config.clone();
            match (&req.volume, &sr.volume) {
                (None, v) => rec.volume = v.clone(),
                (Some(a), Some(b)) if a.mount != b.mount => {
                    return Err(invalid("a fork keeps its source's volume mount"))
                }
                (Some(a), Some(b)) if a.size_gb < b.size_gb => {
                    return Err(never_shrinks(a.size_gb, b.size_gb))
                }
                _ => {}
            }
            src = Some((s, fork.clone()));
        } else {
            rec.image = req.image.clone();
        }
        if rec.root_key.is_empty() {
            rec.root_key = rec.image_key.clone();
        }
        if let Some(v) = &rec.volume {
            self.room_on_pool(v.size_gb).await?;
        }
        let t = self.ensure_namespace(&req.namespace).await?;
        let e = self.add_machine(rec, &t)?;
        let ip = e.snapshot().ip;
        let counted = self.inner.net.count(&ip).await.context("usage counters");
        // Written before the answer: a machine the caller was told of survives a restart, and
        // a restart finds it `creating` and fails it (`recover`).
        if let Err(err) = counted.and_then(|()| self.save(&e)) {
            self.remove_machine(&e);
            let _ = self.inner.net.uncount(&ip).await;
            let _ = self.inner.store.delete("machines", &e.snapshot().id);
            return Err(err.into());
        }
        let how = match (restore_from, src) {
            (Some((b, key)), _) => Make::Restore(Box::new(b), key),
            (None, Some((s, fork))) => Make::Fork(s, fork),
            (None, None) => Make::Image,
        };
        Ok((e, how))
    }

    /// The create's second half (ADR 0048): the image pulled, without the machine's lock (a
    /// pull may take minutes, and a destroy meanwhile must not wait for it), then the disks
    /// made and the start done under it. A failure leaves the machine in `error` with the
    /// reason (`pull_failed`, `create_failed`, or the start's), its disks gone, for the caller
    /// to read and destroy; nothing is tried again. A machine destroyed meanwhile is left be.
    pub(super) async fn make(&self, e: &Arc<Entry>, how: Make) -> Result<(), MError> {
        let reference = e.snapshot().image;
        let image = match how {
            Make::Image => {
                let pulling = || {
                    e.note(
                        Ev::normal(reason::PULLING, format!("pulling {reference}"))
                            .data(json!({ "image": reference })),
                    )
                };
                match self.inner.images.ensure_noting(&reference, pulling).await {
                    Ok(im) => Some(im),
                    Err(err) => {
                        let why = format!("pull {reference}: {err:#}");
                        // The image's, or its registry's: not a person's to fix here.
                        tracing::warn!(machine = e.snapshot().id, err = why, "pull failed");
                        return Err(self.create_failed(e, reason::PULL_FAILED, why).await);
                    }
                }
            }
            _ => None,
        };
        let _guard = e.lock.lock().await;
        let id = e.snapshot().id;
        if !self.inner.machines.lock().unwrap().contains_key(&id)
            || e.snapshot().state != state::CREATING
        {
            return Err(MError::NotFound);
        }
        if let Some(im) = image {
            let mut r = e.rec.lock().unwrap();
            r.image_key = im.key.clone();
            r.root_key = im.key;
            r.image_digest = im.digest;
            r.image_config = im.config;
        }
        let made = match &how {
            Make::Restore(b, key) => self.receive_disks(e, b, key.as_deref()).await,
            Make::Fork(src, fork) => self.make_disks(e, Some(src.as_ref()), Some(fork)).await,
            Make::Image => self.make_disks(e, None, None).await,
        };
        // A fork's or a restore's volume larger than its source's: its disk grows to it (ADR
        // 0040). A new volume is made at its size.
        let made = match made {
            Ok(()) if !matches!(how, Make::Image) => self.fit_volume(&e.snapshot()).await.map(drop),
            other => other,
        };
        if let Err(err) = made {
            let why = format!("disks: {err:#}");
            tracing::error!(machine = e.snapshot().id, err = why, "create failed");
            return Err(self
                .create_failed_locked(e, reason::CREATE_FAILED, why)
                .await);
        }
        let r = e.snapshot();
        let ev = match &how {
            Make::Restore(b, _) => Ev::normal(
                reason::RESTORED,
                format!("restored from backup {} of {}", b.id, b.machine_id),
            )
            .data(json!({ "from": b.machine_id, "backup": b.id })),
            Make::Fork(src, _) => {
                let from = src.snapshot().id;
                Ev::normal(reason::FORKED, format!("forked from {from}"))
                    .data(json!({ "from": from }))
            }
            Make::Image => Ev::normal(reason::CREATED, format!("created from {}", r.image))
                .data(json!({ "image": r.image, "digest": r.image_digest })),
        };
        if !r.start {
            e.set_state(state::CREATED, |_| Some(ev));
            self.save(e)?;
            return Ok(());
        }
        e.note(ev);
        self.save(e)?;
        match self.start_entry(e, true).await {
            // Refused before anything moved, so no state says it yet: its namespace's gateway did
            // not come up (`boot_failed`, its disks kept for a start), its quota, its `via`.
            Err(err) if e.snapshot().state == state::CREATING => {
                let (reason, why) = match &err {
                    MError::BootFailed(m) => (reason::BOOT_FAILED, m.error.clone()),
                    other => (reason::CREATE_FAILED, format!("start: {other}")),
                };
                if reason == reason::CREATE_FAILED {
                    tracing::error!(machine = e.snapshot().id, err = why, "create failed");
                }
                Err(self.create_failed_locked(e, reason, why).await)
            }
            // Its start failed and said so on the machine (`boot_failed`, `start_failed`).
            other => other,
        }
    }

    /// A create that did not get its machine made and started: the machine stays in `error`
    /// with `why` and the event `reason`. `pull_failed` and `create_failed` leave no disks
    /// (`has_disks`): the caller destroys it and creates again; `boot_failed` keeps them, for
    /// a start. The caller logs it, by whose it is.
    pub(super) async fn create_failed(
        &self,
        e: &Arc<Entry>,
        reason: &'static str,
        why: String,
    ) -> MError {
        let _guard = e.lock.lock().await;
        self.create_failed_locked(e, reason, why).await
    }

    async fn create_failed_locked(
        &self,
        e: &Arc<Entry>,
        reason: &'static str,
        why: String,
    ) -> MError {
        let r = e.snapshot();
        if !self.inner.machines.lock().unwrap().contains_key(&r.id) || r.state != state::CREATING {
            return MError::NotFound;
        }
        let z = &self.inner.zfs;
        if reason != reason::BOOT_FAILED && z.exists(&r.dataset()).await.unwrap_or(true) {
            if let Err(err) = z.destroy(&r.dataset()).await {
                tracing::warn!(machine = r.id, err = %err, "disks of a failed create");
            }
        }
        e.set_state(state::ERROR, |r| {
            r.error = why;
            r.error_reason = reason.into();
            r.start = false;
            r.stopped_at = Some(Utc::now());
            Some(Ev::warning(reason, r.error.clone()))
        });
        let _ = self.save(e);
        let m = Box::new(self.view(e));
        match reason {
            reason::PULL_FAILED => MError::PullFailed(m),
            reason::BOOT_FAILED => MError::BootFailed(m),
            _ => MError::CreateFailed(m),
        }
    }

    /// The namespace's machine of this name: what a create of the name answers, so a create sent
    /// again after no answer finds the one the first made (ADR 0048).
    pub(super) fn named(&self, namespace: &str, name: &str) -> Option<Arc<Entry>> {
        let machines = self.inner.machines.lock().unwrap();
        let found = machines.values().find(|e| {
            let r = e.rec.lock().unwrap();
            r.namespace == namespace && r.name == name && r.state != state::DESTROYING
        });
        found.cloned()
    }

    /// Gives the machine an address and registers it, within its namespace's quota (ADR 0025):
    /// a machine and its volume, and when its create starts it its size, which the host's
    /// memory must hold too (ADR 0048). Nothing on disk yet.
    fn add_machine(&self, mut rec: Record, t: &Namespace) -> Result<Arc<Entry>, MError> {
        self.check_host_size(&rec.size)?;
        let mut machines = self.inner.machines.lock().unwrap();
        // A rename of the namespace (ADR 0056) swaps it under this lock: a create that read
        // the old name is repeated, not recorded in a namespace that is gone.
        if !self
            .inner
            .namespaces
            .lock()
            .unwrap()
            .contains_key(&t.rec.id)
        {
            return Err(MError::Conflict(format!(
                "namespace {} was renamed meanwhile: repeat the request",
                t.rec.id
            )));
        }
        let taken = machines.values().find(|e| {
            let r = e.rec.lock().unwrap();
            r.namespace == rec.namespace && r.name == rec.name && r.state != state::DESTROYING
        });
        if let Some(e) = taken.cloned() {
            drop(machines);
            return Err(MError::NameTaken(Box::new(self.view(&e))));
        }
        let mut used = Vec::new();
        for e in machines.values() {
            let r = e.rec.lock().unwrap();
            if r.namespace == t.rec.id {
                used.push(r.host_num as u32);
            }
        }
        let held = namespace_use(&machines, &rec.namespace);
        if let Some(x) = over_quota(
            &rec.namespace,
            &t.rec.quota,
            &held,
            &quota_need(&rec, false),
        ) {
            drop(machines);
            let ev = x.event(format!("create of {} refused: {x}", rec.name));
            self.inner.events.emit(ev.namespace(&rec.namespace));
            return Err(MError::Quota(x.to_string()));
        }
        if rec.start {
            self.memory_admission(&machines)?;
            let (used, _) = committed(&machines);
            admit(
                used.memory_mb,
                self.capacity().memory_mb,
                host_memory(rec.size.memory_mb)?,
            )?;
            admit_cpu(
                used.cpu_millis(),
                self.capacity().cpu_millis(),
                rec.size.cpu_millis(),
            )?;
        }
        // The address a `via` policy in the tables names stays its gateway's, even once that
        // machine is gone: given to a new machine, it would be reachable through the policy.
        for (_, p) in self.inner.policies.lock().unwrap().values() {
            if let nft::Policy::Via { to, .. } = p {
                if let Ok(to) = to.parse::<Ipv4Addr>() {
                    if to.octets()[..3] == t.subnet.network.octets()[..3] {
                        used.push(to.octets()[3] as u32);
                    }
                }
            }
        }
        let n = netw::first_free(used, 2, 254).ok_or_else(|| {
            MError::Capacity(format!("namespace {} has no address left", t.rec.id))
        })?;
        rec.subnet_index = t.rec.subnet_index;
        rec.host_num = n as u8;
        rec.ip = t.subnet.host(n as u8)?.to_string();
        let id = rec.id.clone();
        if machines
            .keys()
            .any(|other| fc::fc_id(other) == fc::fc_id(&id))
        {
            return Err(MError::Conflict(
                "machine cgroup identity is already owned".into(),
            ));
        }
        self.inner.vmm.register_new(&id)?;
        let e = Entry::new(rec, self.inner.events.clone());
        machines.insert(id, e.clone());
        drop(machines);
        self.refresh_dns(t);
        Ok(e)
    }

    pub(super) fn remove_machine(&self, e: &Entry) {
        *e.removed.lock().unwrap() = true;
        let rec = e.snapshot();
        self.inner.machines.lock().unwrap().remove(&rec.id);
        if let Some(t) = self.namespace_of(&rec.namespace) {
            self.refresh_dns(&t);
        }
    }

    /// Clones the root disk and makes the data volume; for a fork, both from snapshots of the
    /// source taken now.
    async fn make_disks(
        &self,
        e: &Entry,
        src: Option<&Entry>,
        fork: Option<&api::ForkSpec>,
    ) -> Result<()> {
        let r = e.snapshot();
        let z = &self.inner.zfs;
        let copy_disks = src.is_some()
            && fork
                .map(|f| f.copy.is_empty() || f.copy == "disk")
                .unwrap_or(false);
        if copy_disks {
            // Under the source's lock: a restore swaps its disks under that lock (ADR 0031),
            // and a tidy removes a fork snapshot nothing clones yet.
            let src = src.unwrap();
            let _src_lock = src.lock.lock().await;
            let s = src.snapshot();
            if s.state == state::DESTROYING {
                return Err(anyhow!("fork source {} is being destroyed", s.id));
            }
            if let Some(snap) = &s.restoring {
                return Err(anyhow!(
                    "fork source {}: a restore to {snap} is unfinished",
                    s.id
                ));
            }
            let snap = format!("fork-{}", r.id);
            z.snapshot(&s.root_dataset(), &snap).await?;
            z.clone_snapshot(&s.root_dataset(), &snap, &r.root_dataset())
                .await?;
            if r.volume.is_some() && z.exists(&s.data_dataset()).await? {
                z.snapshot(&s.data_dataset(), &snap).await?;
                z.clone_snapshot(&s.data_dataset(), &snap, &r.data_dataset())
                    .await?;
                return Ok(());
            }
        } else {
            z.clone_snapshot(
                &format!("images/{}", r.image_key),
                image::SNAP,
                &r.root_dataset(),
            )
            .await?;
        }
        if let Some(v) = &r.volume {
            let dev = z
                .create(&r.data_dataset(), (v.size_gb as u64) << 30)
                .await?;
            let out = crate::host_process::command("mkfs.ext4")
                .args([
                    "-q",
                    "-F",
                    "-L",
                    "data",
                    "-E",
                    "lazy_itable_init=0,lazy_journal_init=0",
                ])
                .arg(&dev)
                .output()
                .await
                .context("run mkfs.ext4")?;
            if !out.status.success() {
                return Err(anyhow!(
                    "mkfs.ext4 {}: {}",
                    dev.display(),
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
        }
        Ok(())
    }

    pub(super) fn check_host_size(&self, size: &api::Size) -> Result<(), MError> {
        check_size(size)?;
        host_memory(size.memory_mb)?;
        if size.cpu_millis() < size.vcpus.saturating_mul(1000)
            && self.inner.cfg.jailer.as_os_str().is_empty()
        {
            return Err(invalid(
                "fractional cpu_millis requires the jailer and cgroup v2",
            ));
        }
        Ok(())
    }

    // --- start ---

    /// `If-Match` (ADR 0019): the version the caller read, compared under the machine's lock,
    /// so nothing moves it between the check and the change. None: no condition.
    pub(super) fn check_version(&self, e: &Entry, at: Option<u64>) -> Result<(), MError> {
        match at {
            Some(v) if v != e.snapshot().version => Err(MError::Moved(Box::new(self.view(e)))),
            _ => Ok(()),
        }
    }
}

pub(super) fn check_size(size: &api::Size) -> Result<(), MError> {
    size.check().map_err(invalid)
}

/// Limits a request may set (ADR 0018); none is fine.
pub(super) fn check_limits(l: Option<&api::EgressLimits>) -> Result<(), MError> {
    match l.map(|l| l.check()) {
        Some(Err(e)) => Err(invalid(format!("limits.{e}"))),
        _ => Ok(()),
    }
}

/// Disk limits a request may set (ADR 0030); none is fine.
pub(super) fn check_disk_limits(l: Option<&api::DiskLimits>) -> Result<(), MError> {
    match l.map(|l| l.check()) {
        Some(Err(e)) => Err(invalid(format!("disk_limits.{e}"))),
        _ => Ok(()),
    }
}
