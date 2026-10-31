//! Looking a machine up and presenting it, and the reservation of a host's memory and cpus for it.

use super::*;

impl Manager {
    // --- lookup and views ---

    pub(super) fn entry(&self, id: &str) -> Result<Arc<Entry>, MError> {
        self.inner
            .machines
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or(MError::NotFound)
    }

    /// The machine a call that changes or runs something in it acts on: every such call of
    /// the API resolves its machine here. A namespace's gateway is read through the machine
    /// routes (get, logs, stats) and changed only through its namespace's.
    pub(super) fn own_entry(&self, id: &str) -> Result<Arc<Entry>, MError> {
        let e = self.entry(id)?;
        let r = e.rec.lock().unwrap();
        if r.is_gateway() {
            return Err(MError::Gateway(r.namespace.clone()));
        }
        drop(r);
        Ok(e)
    }

    pub(super) fn view(&self, e: &Entry) -> api::Machine {
        let r = e.snapshot();
        let running = r.state == state::RUNNING;
        let sleeps_at = if running && e.in_flight.load(Relaxed) == 0 {
            sleeps_at(r.last_used_at, r.sleep_window())
        } else {
            None
        };
        let (ready, probes_status) = {
            let run = e.probe.lock().unwrap();
            (
                running && run.ready && r.template_birth.is_none(),
                run.status.clone(),
            )
        };
        let waiting_restart = r.state == state::STOPPED && r.stopped_reason == stop::EXIT;
        api::Machine {
            template_profile: r.template_birth.as_ref().map(|b| b.profile.clone()),
            memory_origin: r.clone_origin.as_ref().map(|o| api::MemoryOrigin {
                source_machine: o.source_machine.clone(),
                snapshot: o.snapshot.clone(),
                source_host: o.artifact.source_host.clone(),
                ram_marker: o.artifact.ram_marker.clone(),
                generation: o.artifact.generation.clone(),
                stage: o.stage.as_str().into(),
                identity: o.identity.clone(),
            }),
            id: r.id.clone(),
            namespace: r.namespace.clone(),
            name: r.name.clone(),
            image: r.image.clone(),
            image_digest: r.image_digest.clone(),
            state: r.state.clone(),
            stopped_reason: r.stopped_reason.clone(),
            exit: r.exit.clone(),
            error: r.error.clone(),
            error_reason: r.error_reason.clone(),
            ip: r.ip.clone(),
            hostname: r.hostname(),
            machine_host: r.machine_host(),
            size: r.size,
            volume: r.volume.clone(),
            ports: r.ports.clone(),
            sleep: r.sleep.clone(),
            restart: r.restart.clone(),
            restarts: r.restarts,
            restarting_at: r.restarting_at.filter(|_| waiting_restart),
            ready,
            probes: r.probes.clone(),
            probes_status,
            egress: r.egress.clone(),
            limits: self.inner.cfg.egress_limits.with(&r.limits).view(),
            egress_drops: e.meter.lock().unwrap().drops(),
            disk_limits: self.disk_rate(&r).view(),
            metadata: r.metadata.clone(),
            endpoints: self.endpoints_of(&r.id),
            created_at: r.created_at,
            updated_at: r.updated_at,
            state_changed_at: r.state_changed_at,
            started_at: r.started_at,
            stopped_at: r.stopped_at,
            last_used_at: r.last_used_at,
            sleeps_at,
            suspended: r.suspended,
            backup: r.backup.policy.clone(),
            last_backup_at: r.backup.last_at,
            next_backup_at: r.backup.next_at,
            version: r.version,
            pending: r.pending.as_ref().map(|p| p.view()),
            pending_since: r.pending_since,
            init_version: r.init_version.clone(),
            vmm_version: r.vmm_version.clone(),
            host: String::new(),
        }
    }

    pub fn get(&self, id: &str) -> Result<api::Machine, MError> {
        let e = self.entry(id)?;
        Ok(self.view(&e))
    }

    /// The namespace's machines, or every namespace's, those whose labels (`metadata`) match every
    /// selector (ADR 0025).
    pub fn list(&self, namespace: Option<&str>, labels: &[api::Label]) -> Vec<api::Machine> {
        let entries: Vec<Arc<Entry>> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        let mut out: Vec<api::Machine> = entries
            .iter()
            .filter(|e| {
                let r = e.rec.lock().unwrap();
                r.is_namespaces()
                    && namespace.map(|t| r.namespace == t).unwrap_or(true)
                    && labels.iter().all(|l| l.matches(&r.metadata))
            })
            .map(|e| self.view(e))
            .collect();
        out.sort_by_key(|a| a.created_at);
        out
    }

    /// What running machines take (gateways included), how many run, and how many machines
    /// namespaces have (gateways not counted).
    pub fn usage(&self) -> (api::Capacity, usize, usize) {
        let machines = self.inner.machines.lock().unwrap();
        let (used, running) = committed(&machines);
        let total = machines
            .values()
            .filter(|e| e.rec.lock().unwrap().is_namespaces())
            .count();
        (used, running, total)
    }

    /// Takes the machine's memory from the host and moves it to `starting`, as one step
    /// under the map's lock: two starts that read the same free memory cannot both take it,
    /// nor pass their namespace's quota together (ADR 0025). A pending change goes onto the record
    /// in that step (ADR 0024), its size the one reserved and counted, with `image` its new
    /// image, resolved. Its events are logged once that lock is let go: the log syncs to disk,
    /// and the map is every request's. Nothing else moves the machine meanwhile: its own lock
    /// is held.
    pub(super) fn reserve(&self, e: &Entry, image: Option<image::Image>) -> Result<(), MError> {
        let namespace = e.rec.lock().unwrap().namespace.clone();
        let quota = self
            .namespace_of(&namespace)
            .map(|t| t.rec.quota)
            .unwrap_or_default();
        let mut applied = None;
        // A memory snapshot taken under another Firecracker or host kernel is not loaded
        // (ADR 0027): this start is cold.
        let vmm = self.inner.vmm.version();
        let mut dropped = None;
        let over = {
            let machines = self.inner.machines.lock().unwrap();
            // A create's start: its memory is counted since it was recorded, and taken again
            // here, the count without it (ADR 0048).
            let (size, own) = {
                let r = e.rec.lock().unwrap();
                let own = match commits_memory(&r) {
                    true => r.size,
                    false => api::Size::default(),
                };
                (
                    r.pending.as_ref().and_then(|p| p.size).unwrap_or(r.size),
                    own,
                )
            };
            let need = api::QuotaUse {
                memory_mb: size.memory_mb,
                vcpus: size.vcpus,
                cpu_millis: Some(size.cpu_millis()),
                ..Default::default()
            };
            let mut held = namespace_use(&machines, &namespace);
            held.memory_mb = held.memory_mb.saturating_sub(own.memory_mb);
            held.cpu_millis = Some(held.cpu_millis().saturating_sub(own.cpu_millis()));
            held.vcpus = held.vcpus.saturating_sub(own.vcpus);
            match over_quota(&namespace, &quota, &held, &need) {
                Some(x) => Some(x),
                None => {
                    let (used, _) = committed(&machines);
                    admit_cpu(
                        used.cpu_millis().saturating_sub(own.cpu_millis()),
                        self.capacity().cpu_millis(),
                        size.cpu_millis(),
                    )?;
                    let used = used.memory_mb.saturating_sub(own.memory_mb);
                    admit(used, self.capacity().memory_mb, size.memory_mb)?;
                    e.set_state(state::STARTING, |r| {
                        r.error.clear();
                        r.error_reason.clear();
                        r.start = false;
                        r.pid = 0;
                        r.restarting_at = None;
                        applied = apply_pending(r, image);
                        let compatible =
                            match (&r.boot_identity, self.inner.vmm.boot_identity(false)) {
                                (Some(saved), Some(host)) => {
                                    r.vmm_version == vmm && saved.compatible(&host)
                                }
                                (Some(_), None) => false,
                                (None, _) => r.vmm_version == vmm,
                            };
                        if r.suspended && !compatible {
                            r.suspended = false;
                            dropped = Some(if r.vmm_version != vmm {
                                r.vmm_version.clone()
                            } else {
                                format!("{} (boot identity incompatible)", r.vmm_version)
                            });
                        }
                        None
                    });
                    None
                }
            }
        };
        if let Some(x) = over {
            e.note(x.event(format!("start refused: {x}")));
            let _ = self.save(e);
            return Err(MError::Quota(x.to_string()));
        }
        if let Some(fields) = applied {
            e.note(
                Ev::normal(reason::APPLIED, format!("{} applied", fields.join(", ")))
                    .data(json!({ "fields": fields })),
            );
        }
        let resume = e.snapshot().suspended;
        let ev = match (resume, dropped) {
            (true, _) => Ev::normal(reason::STARTING, "resuming from its memory snapshot")
                .data(json!({ "resume": true })),
            (false, None) => {
                Ev::normal(reason::STARTING, "booting").data(json!({ "resume": false }))
            }
            (false, Some(was)) => Ev::normal(
                reason::STARTING,
                format!("booting: its memory snapshot was taken under {was}, the host runs {vmm}"),
            )
            .data(json!({ "resume": false, "snapshot_vmm": was })),
        };
        e.note(ev);
        Ok(())
    }
}
