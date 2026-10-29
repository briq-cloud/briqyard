//! Changing a machine: what it runs, its size and its volume.

use super::*;

impl Manager {
    // --- use and sleep ---

    /// Changes the sleep window, the metadata, the egress policy, the limits or the probes of a
    /// machine, in any state; a running machine's policy changes in the tables at once, and its
    /// probes start over. What it runs (`spec`) changes at its next start (ADR 0024): kept as
    /// `pending` meanwhile, a running machine running on as it was. A change is an event
    /// (`egress_changed` for the policy or the limits, `updated` for the rest, one with
    /// `pending` for the spec); a request that changes nothing is none.
    pub async fn update(
        &self,
        id: &str,
        mut req: api::UpdateMachineRequest,
        at: Option<u64>,
    ) -> Result<api::Machine, MError> {
        let e = self.own_entry(id)?;
        if let Some(sl) = &req.sleep {
            api::parse_sleep(sl).map_err(invalid)?;
        }
        check_limits(req.limits.as_ref())?;
        check_disk_limits(req.disk_limits.as_ref())?;
        backups::check_update(&req.backup)?;
        if let Some(p) = &req.probes {
            p.check().map_err(invalid)?;
        }
        req.spec.check().map_err(invalid)?;
        // Under the entry's lock, like every transition: no start or stop runs in between,
        // and a destroy that ran first has removed the machine, whose record is not written
        // back.
        let _guard = e.lock.lock().await;
        if !self.inner.machines.lock().unwrap().contains_key(id) {
            return Err(MError::NotFound);
        }
        self.check_version(&e, at)?;
        // What a create pulls, makes and starts is what it was asked (ADR 0048).
        if e.snapshot().state == state::CREATING {
            return Err(made_never(&e.snapshot()));
        }
        // A larger volume grows below, once nothing else can refuse the request (ADR 0040).
        let grow = match req.spec.volume {
            Some(v) => volume_growth(&e.snapshot(), v.size_gb)?,
            None => None,
        };
        if grow.is_none() {
            // The size it has: no change.
            req.spec.volume = None;
        }
        // Held until the record says `via: gateway`, as a start holds it.
        let mut gateway_turn = None;
        let reprobe;
        if req.egress.is_some() || req.limits.is_some() {
            let mut r = e.snapshot();
            if let Some(eg) = &req.egress {
                self.check_egress(eg, &r.tenant, &r.id)?;
                r.egress = eg.clone();
            }
            if let Some(l) = &req.limits {
                r.limits = l.over(&r.limits);
            }
            // The tables first: refused, the old policy stays and so does the record.
            if r.state == state::RUNNING {
                let policy = self.policy_for(&r)?;
                if req.egress.as_ref().is_some_and(|eg| eg.via_gateway()) {
                    gateway_turn = Some(
                        self.ensure_gateway(&r.tenant)
                            .await
                            .map_err(|err| self.gateway_failed(&e, err))?,
                    );
                }
                self.replace_policy(&r.id, policy).await?;
            }
        }
        if let Some(l) = &req.disk_limits {
            // Firecracker first: refused, the disks keep their limits and the record its own.
            let mut r = e.snapshot();
            let was = self.disk_rate(&r);
            r.disk_limits = l.over(&r.disk_limits);
            let now = self.disk_rate(&r);
            let live = e.live.lock().unwrap().clone();
            if let (Some(vm), true) = (live, now != was && r.state == state::RUNNING) {
                self.inner
                    .vmm
                    .disk_rate(&vm, &now, r.volume.is_some())
                    .await
                    .context("disk limits")?;
            }
        }
        if let Some((from, to)) = grow {
            self.grow_volume(&e, from, to).await?;
        }
        {
            let mut r = e.rec.lock().unwrap();
            let was = r.clone();
            if let Some(sl) = req.sleep {
                r.sleep = sleep_setting(&sl);
            }
            if let Some(m) = req.metadata {
                r.metadata = m;
            }
            if let Some(eg) = req.egress {
                r.egress = eg;
            }
            if let Some(l) = req.limits {
                r.limits = l.over(&r.limits);
            }
            if let Some(l) = req.disk_limits {
                r.disk_limits = l.over(&r.disk_limits);
            }
            backups::update(&mut r, req.backup)?;
            if let Some(p) = req.probes {
                r.probes = p;
            }
            if let Some(ev) = change_event(&was, &r) {
                e.note_locked(&mut r, ev);
            }
            let pending = pending_after(&r, req.spec);
            if pending != r.pending {
                r.pending_since = match pending {
                    Some(_) => r.pending_since.or(Some(Utc::now())),
                    None => None,
                };
                let fields = pending
                    .clone()
                    .unwrap_or_default()
                    .changed_from(&r.pending.take().unwrap_or_default());
                r.pending = pending;
                let ev = Ev::normal(
                    reason::UPDATED,
                    format!("{} change at the next start", fields.join(", ")),
                );
                e.note_locked(
                    &mut r,
                    ev.data(json!({ "fields": fields, "pending": true })),
                );
            }
            reprobe = r.probes != was.probes && r.state == state::RUNNING;
        }
        self.save(&e)?;
        drop(gateway_turn);
        if reprobe {
            self.restart_probes(&e);
        }
        Ok(self.view(&e))
    }

    /// Stops the machine and starts it again: what a PATCH left pending applies now (ADR 0024).
    /// One that is not running is started. `at` is the caller's `If-Match`, checked by the
    /// stop, whose events move the version.
    pub async fn restart(&self, id: &str, at: Option<u64>) -> Result<api::Machine, MError> {
        let e = self.own_entry(id)?;
        self.stop_entry(&e, stop::USER, Duration::ZERO, false, at)
            .await?;
        let _turns = e.lock_for_start().await;
        if e.snapshot().state != state::RUNNING {
            self.start_entry(&e, true).await?;
        }
        Ok(self.view(&e))
    }

    pub fn touch(&self, id: &str) -> Result<(), MError> {
        self.own_entry(id)?.touch();
        Ok(())
    }

    /// Grows the machine's volume from `from` to `to` GB now, its lock held (ADR 0040): the
    /// pool's room checked as a create's, then the growth checked against the tenant's quota
    /// and the size taken on the record in one step under the map's lock, as a start takes its
    /// memory (two grows cannot pass the quota together), then the disk grown and the record
    /// saved; refused there, the record goes back. The guest's filesystem follows at its next
    /// start.
    pub(super) async fn grow_volume(&self, e: &Entry, from: u32, to: u32) -> Result<(), MError> {
        self.room_on_pool(to - from).await?;
        let tenant = e.rec.lock().unwrap().tenant.clone();
        let quota = self
            .tenant_of(&tenant)
            .map(|t| t.rec.quota)
            .unwrap_or_default();
        let resize = |r: &mut Record, gb: u32| {
            if let Some(v) = r.volume.as_mut() {
                v.size_gb = gb;
            }
        };
        let over = {
            let machines = self.inner.machines.lock().unwrap();
            let need = api::QuotaUse {
                disk_gb: to - from,
                ..Default::default()
            };
            let over = over_quota(&tenant, &quota, &tenant_use(&machines, &tenant), &need);
            if over.is_none() {
                resize(&mut e.rec.lock().unwrap(), to);
            }
            over
        };
        if let Some(x) = over {
            e.note(x.event(format!("volume growth refused: {x}")));
            let _ = self.save(e);
            return Err(MError::Quota(x.to_string()));
        }
        let ds = e.snapshot().data_dataset();
        if let Err(err) = self.inner.zfs.grow(&ds, (to as u64) << 30).await {
            resize(&mut e.rec.lock().unwrap(), from);
            return Err(err.context(format!("grow the volume to {to} GB")).into());
        }
        // On disk with the disk: the stored record is never smaller than the volume.
        self.save(e)?;
        Ok(())
    }

    /// Whether the pool has `gb` free for a volume, a create's or a grow's (ADR 0040): 503
    /// `capacity` when not. Volumes are thin, so this admits, as the fleet's placement does;
    /// it reserves nothing.
    pub(super) async fn room_on_pool(&self, gb: u32) -> Result<(), MError> {
        let pool = self
            .inner
            .zfs
            .pool()
            .await
            .context("the pool's free space")?;
        if pool.free < (gb as u64) << 30 {
            let free = pool.free as f64 / (1u64 << 30) as f64;
            return Err(MError::Capacity(format!(
                "the pool has {free:.1} GB free, the volume asks {gb} GB"
            )));
        }
        Ok(())
    }

    /// Grows the data disk to the record's size when it is smaller (ADR 0040): a disk cloned
    /// from an older snapshot or received from a backup is never smaller than its record says.
    /// Whether it grew.
    pub(super) async fn fit_volume(&self, r: &Record) -> Result<bool> {
        let Some(v) = &r.volume else {
            return Ok(false);
        };
        let (ds, want) = (r.data_dataset(), (v.size_gb as u64) << 30);
        if self.inner.zfs.volsize(&ds).await? >= want {
            return Ok(false);
        }
        self.inner.zfs.grow(&ds, want).await?;
        Ok(true)
    }
}

/// The event of a PATCH: `egress_changed` when the policy or the limits moved (both are what
/// the tables hold for its internet traffic), else `updated`; each with the fields that did.
/// None when nothing changed.
fn change_event(was: &Record, now: &Record) -> Option<Ev> {
    let changed = |pairs: &[(&'static str, bool)]| -> Vec<&'static str> {
        pairs.iter().filter(|(_, c)| *c).map(|(f, _)| *f).collect()
    };
    let egress = changed(&[
        ("egress", was.egress != now.egress),
        ("limits", was.limits != now.limits),
    ]);
    if !egress.is_empty() {
        let label = |e: &api::Egress| match &e.via {
            Some(via) => format!("{}:{via}", e.mode),
            None => e.mode.clone(),
        };
        let (from, to) = (label(&was.egress), label(&now.egress));
        let message = match was.egress != now.egress {
            true => format!("egress {from} -> {to}"),
            false => "egress limits changed".to_string(),
        };
        return Some(Ev::normal(reason::EGRESS_CHANGED, message).data(json!({
            "fields": egress, "from": from, "to": to, "limits": now.limits,
        })));
    }
    let fields = changed(&[
        ("sleep", was.sleep != now.sleep),
        ("metadata", was.metadata != now.metadata),
        ("backup", was.backup.policy != now.backup.policy),
        ("probes", was.probes != now.probes),
        ("disk_limits", was.disk_limits != now.disk_limits),
    ]);
    if fields.is_empty() {
        return None;
    }
    let ev = Ev::normal(reason::UPDATED, format!("{} changed", fields.join(", ")));
    Some(ev.data(json!({ "fields": fields })))
}

/// What the next start applies after a PATCH of `change` (ADR 0024): the pending change with
/// `change` over it, less what the record already has; None when nothing is left.
fn pending_after(r: &Record, change: api::SpecChange) -> Option<api::SpecChange> {
    let p = r.pending.clone().unwrap_or_default();
    let next = api::SpecChange {
        image: change.image.or(p.image).filter(|v| *v != r.image),
        entrypoint: (change.entrypoint.or(p.entrypoint))
            .filter(|v| Some(v) != r.entrypoint.as_ref()),
        cmd: change.cmd.or(p.cmd).filter(|v| Some(v) != r.cmd.as_ref()),
        env: change.env.or(p.env).filter(|v| *v != r.env),
        files: change.files.or(p.files).filter(|v| *v != r.files),
        size: change.size.or(p.size).filter(|v| *v != r.size),
        ports: change.ports.or(p.ports).filter(|v| *v != r.ports),
        restart: change.restart.or(p.restart).filter(|v| *v != r.restart),
        // The record has the new size already, the disk grown at the PATCH (ADR 0040): it
        // waits for the guest's filesystem, not for the record.
        volume: change.volume.or(p.volume),
    };
    (!next.is_empty()).then_some(next)
}

/// What a PATCH of the volume to `gb` grows (ADR 0040): from and to, in GB; None for the
/// size it has. A machine without a volume, a smaller size, a restore cut short or a destroy
/// refuse it.
fn volume_growth(r: &Record, gb: u32) -> Result<Option<(u32, u32)>, MError> {
    let held = r
        .volume
        .as_ref()
        .ok_or_else(|| invalid("volume: the machine has none; a volume is made at create"))?
        .size_gb;
    if gb < held {
        return Err(never_shrinks(gb, held));
    }
    if let Some(snap) = &r.restoring {
        return Err(snapshots::unfinished(snap));
    }
    if r.state == state::DESTROYING {
        return Err(MError::BadState(r.state.clone()));
    }
    Ok((gb > held).then_some((held, gb)))
}

/// Puts the pending change on the record, in the step that starts the machine (ADR 0024);
/// `image` is its new image, resolved. A change to what a memory snapshot holds drops the
/// snapshot: that start is cold. The fields applied; None when nothing was pending.
pub(super) fn apply_pending(
    r: &mut Record,
    image: Option<image::Image>,
) -> Option<Vec<&'static str>> {
    let p = r.pending.take()?;
    r.pending_since = None;
    let fields = p.fields();
    if p.touches_snapshot() {
        r.suspended = false;
    }
    if let (Some(reference), Some(im)) = (p.image, image) {
        r.image = reference;
        r.image_key = im.key;
        r.image_digest = im.digest;
        r.image_config = im.config;
    }
    if let Some(v) = p.entrypoint {
        r.entrypoint = Some(v);
    }
    if let Some(v) = p.cmd {
        r.cmd = Some(v);
    }
    if let Some(v) = p.env {
        r.env = v;
    }
    if let Some(v) = p.files {
        r.files = v;
    }
    if let Some(v) = p.size {
        r.size = v;
    }
    if let Some(v) = p.ports {
        r.ports = v;
    }
    if let Some(v) = p.restart {
        r.restart = v;
    }
    // A volume is on the record already: this cold boot's init grows its filesystem.
    Some(fields)
}
