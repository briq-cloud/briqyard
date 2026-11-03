use super::*;

fn matches_update_image(actual: &Record, expected: &Record) -> bool {
    match (
        projection::authority(actual),
        projection::authority(expected),
    ) {
        (Ok(actual), Ok(expected)) => actual == expected,
        _ => false,
    }
}

pub(super) fn matches_update_target(actual: &Record, expected: &Record) -> bool {
    matches_update_image(actual, expected) && actual.pending == expected.pending
}

pub(super) fn matches_authorized_update_target(
    actual: &Record,
    current: &Current,
    update: &UpdateIntent,
) -> Result<bool> {
    if matches_update_target(actual, &update.target) {
        return Ok(true);
    }
    let digest = update.digest()?;
    let settled_authority = current.settlement.as_deref().is_some_and(|settlement| {
        settlement.update_sha256.as_deref() == Some(digest.as_str())
            && settlement
                .update
                .as_deref()
                .is_some_and(|settled| settled.digest().ok().as_ref() == Some(&digest))
    });
    Ok(settled_authority && matches_current_target(actual, current, update)?)
}

pub(super) fn matches_current_target(
    actual: &Record,
    current: &Current,
    update: &UpdateIntent,
) -> Result<bool> {
    Ok(current.reference.phase == Phase::Settled
        && current.record_fingerprint(actual)? == current.record_fingerprint(&current.target)?
        && actual.pending == update.target.pending
        && actual.volume == update.target.volume
        && actual.disk_limits == update.target.disk_limits)
}

pub(super) fn matches_settled_update_target(actual: &Record, expected: &Record) -> Result<bool> {
    if !actual
        .assigned_run
        .as_ref()
        .is_some_and(|run| run.phase == Phase::Settled)
        || !expected.assigned_run.as_ref().is_some_and(|run| {
            run.phase == Phase::Observed
                && actual.assigned_run.as_ref().is_some_and(|settled| {
                    settled.schema == run.schema && settled.sequence == run.sequence
                })
        })
    {
        return Ok(false);
    }
    let mut projected = expected.clone();
    projected.assigned_run = actual.assigned_run.clone();
    projected.pid = actual.pid;
    projected.suspended = actual.suspended;
    if let (Some(projected_origin), Some(actual_origin)) = (
        projected.clone_origin.as_mut(),
        actual.clone_origin.as_ref(),
    ) {
        projected_origin.mapping_exited = actual_origin.mapping_exited;
    }
    Ok(projection::authority(actual)? == projection::authority(&projected)?)
}

pub(super) fn apply_consumed_update(
    update: &UpdateIntent,
    record: &mut Record,
) -> Result<Vec<String>> {
    record.disk_limits = update.target.disk_limits.clone();
    if update.change.image.is_some() {
        let image = update
            .resolved_image
            .as_ref()
            .context("assigned image update was not resolved")?;
        let swap = update
            .root_swap
            .as_ref()
            .context("assigned image update lacks root-swap authority")?;
        anyhow::ensure!(
            swap.target_guid.is_some() && record.root_dataset() == update.target.root_dataset(),
            "assigned image root swap is incomplete"
        );
        let dropped_memory = record
            .snapshots
            .iter()
            .filter(|snapshot| snapshot.memory.is_some())
            .map(|snapshot| snapshot.id.clone())
            .collect();
        crate::machine::update::apply_pending(record, Some(image.clone()));
        record.root_key = image.key.clone();
        for snapshot in &mut record.snapshots {
            snapshot.disks.retain(|disk| disk != "root");
            snapshot.memory = None;
        }
        record
            .snapshots
            .retain(|snapshot| !snapshot.disks.is_empty());
        Ok(dropped_memory)
    } else {
        crate::machine::update::apply_pending(record, None);
        Ok(Vec::new())
    }
}

impl Manager {
    pub(super) fn persist_assigned_update(
        &self,
        entry: &Arc<Entry>,
        target: &Record,
        intent: &UpdateIntent,
        disk_growth_gb: Option<u32>,
    ) -> Result<(), MError> {
        let namespace = target.namespace.clone();
        let quota = self
            .namespace_of(&namespace)
            .map(|tenant| tenant.rec.quota)
            .unwrap_or_default();
        let machines = self.inner.machines.lock().unwrap();
        if !machines
            .get(&target.id)
            .is_some_and(|current| Arc::ptr_eq(current, entry))
        {
            return Err(MError::NotFound);
        }
        let removed = entry.removed.lock().unwrap();
        if *removed {
            return Err(MError::NotFound);
        }
        if let Some(disk_growth_gb) = disk_growth_gb.filter(|growth| *growth > 0) {
            let need = api::QuotaUse {
                disk_gb: disk_growth_gb,
                ..Default::default()
            };
            if let Some(exceeded) = over_quota(
                &namespace,
                &quota,
                &self.namespace_use(&machines, &namespace),
                &need,
            ) {
                return Err(MError::Quota(exceeded.to_string()));
            }
        }

        // The map lock makes this durable target the quota reservation seen by every other
        // create, start, or growth admission. Persist authority before exposing the new use.
        // Memory may hold the previous target after its machine write failed. Make that
        // target durable before discarding its predecessor, using startup's exact validation.
        // On any failure the old journal and its capacity reservation remain authoritative.
        self.repair_outstanding_update_record(&target.id)?;
        self.inner.store.put_durable(UPDATES, &target.id, intent)?;
        *entry.rec.lock().unwrap() = target.clone();
        self.inner
            .store
            .put_durable("machines", &target.id, target)?;
        Ok(())
    }

    pub(super) async fn ensure_entry_assigned_update_backing(&self, entry: &Entry) -> Result<()> {
        let record = entry.snapshot();
        let Some(update) = self.inner.store.get::<UpdateIntent>(UPDATES, &record.id)? else {
            return Ok(());
        };
        let current: Current = self
            .inner
            .store
            .get(RUNS, &record.id)?
            .context("assigned update current run missing")?;
        update.check(&current)?;
        anyhow::ensure!(
            matches_authorized_update_target(&record, &current, &update)?,
            "assigned update machine record differs from its target"
        );
        self.ensure_assigned_volume_update(&update).await?;
        // Prefetch image bytes before the admission locks, but do not persist a resolved image
        // from this unlocked snapshot. A concurrent provider PATCH may replace the durable
        // intent while the image is being fetched. The authoritative image/root-swap journal is
        // written later by ensure_assigned_root_update under the entry lock.
        if update.resolved_image.is_none() {
            if let Some(reference) = update.change.image.as_deref() {
                self.inner.images.ensure(reference).await?;
            }
        }
        Ok(())
    }

    pub(in crate::machine) async fn update_assigned_volume(
        &self,
        entry: &Arc<Entry>,
        req: api::UpdateMachineRequest,
        at: Option<u64>,
    ) -> Result<api::Machine, MError> {
        let volume = req.spec.volume;
        if volume.is_none()
            || req.spec.size.is_some()
            || req.spec.image.is_some()
            || req.spec.entrypoint.is_some()
            || req.spec.cmd.is_some()
            || req.spec.env.is_some()
            || req.spec.files.is_some()
            || req.spec.ports.is_some()
            || req.spec.restart.is_some()
            || req.sleep.is_some()
            || req.metadata.is_some()
            || req.egress.is_some()
            || req.limits.is_some()
            || req.disk_limits.is_some()
            || req.backup.is_some()
            || req.probes.is_some()
        {
            return Err(MError::Conflict(
                "assigned volume updates currently accept a volume-only patch".into(),
            ));
        }
        req.spec.check().map_err(invalid)?;

        let _backup = entry.backup_turn.clone().lock_owned().await;
        let _namespace = self.inner.namespace_lifecycle.read().await;
        let _entry = entry.lock.lock().await;
        self.check_version(entry, at)?;
        let record = entry.snapshot();
        if !self.assigned_lifecycle(&record)
            || !matches!(record.state.as_str(), state::RUNNING | state::STOPPED)
        {
            return Err(MError::BadState(
                "assigned volume update requires a running or stopped assigned machine".into(),
            ));
        }
        let current: Current = self
            .inner
            .store
            .get(RUNS, &record.id)?
            .context("assigned current-run journal missing")?;
        let phase_matches = match record.state.as_str() {
            state::RUNNING => current.reference.phase == Phase::Observed,
            state::STOPPED => current.reference.phase == Phase::Settled,
            _ => false,
        };
        if !phase_matches {
            return Err(MError::Conflict(
                "assigned volume update requires the exact live or settled run".into(),
            ));
        }
        self.check_run_creation_authority(&current)
            .map_err(|error| MError::Conflict(format!("assigned update authority: {error:#}")))?;

        let requested = volume.unwrap();
        let Some((from, to)) = crate::machine::update::volume_growth(&record, requested.size_gb)?
        else {
            if let Some(existing) = self.inner.store.get::<UpdateIntent>(UPDATES, &record.id)? {
                existing
                    .check(&current)
                    .map_err(|error| MError::Conflict(format!("assigned update: {error:#}")))?;
                if existing.change.volume.as_ref() == Some(&requested)
                    && matches_update_target(&record, &existing.target)
                {
                    self.ensure_assigned_volume_update(&existing)
                        .await
                        .map_err(MError::Other)?;
                    return Ok(self.view(entry));
                }
            }
            return Ok(self.view(entry));
        };
        self.room_on_pool(to - from).await?;

        let existing = self.inner.store.get::<UpdateIntent>(UPDATES, &record.id)?;
        let (source_record, mut change, disk_limits, mut target, source_sha256, predecessor_target) =
            if let Some(existing) = existing {
                existing
                    .check(&current)
                    .map_err(|error| MError::Conflict(format!("assigned update: {error:#}")))?;
                if !matches_update_target(&record, &existing.target) {
                    return Err(MError::Conflict(
                        "assigned machine differs from its pending update".into(),
                    ));
                }
                if existing.change.volume.is_some() {
                    self.ensure_assigned_volume_update(&existing)
                        .await
                        .map_err(MError::Other)?;
                }
                (
                    existing.source_record,
                    existing.change,
                    existing.disk_limits,
                    existing.target.clone(),
                    existing.source_current_sha256,
                    Some(existing.target),
                )
            } else {
                (
                    Box::new(record.clone()),
                    api::SpecChange::default(),
                    None,
                    Box::new(record.clone()),
                    current.authority_sha256()?,
                    None,
                )
            };

        change.volume = Some(requested);
        target.volume.as_mut().unwrap().size_gb = to;
        target.pending = crate::machine::update::pending_after(&record, change.clone());
        target.pending_since = target
            .pending
            .as_ref()
            .map(|_| record.pending_since.unwrap_or_else(Utc::now));
        let fields = vec!["volume"];
        entry.note_locked(
            &mut target,
            Ev::normal(reason::UPDATED, "volume change applied to the data disk")
                .data(json!({ "fields": fields, "volume_gb": to })),
        );
        let intent = UpdateIntent {
            schema: 1,
            machine: record.id.clone(),
            source_current_sha256: source_sha256,
            source_record,
            change,
            disk_limits,
            target: target.clone(),
            predecessor_target,
            resolved_image: None,
            root_swap: None,
        };
        intent
            .check(&current)
            .map_err(|error| MError::Conflict(format!("assigned update intent: {error:#}")))?;
        // Reserve tenant quota durably before the non-transactional ZFS grow. Recovery repeats
        // the idempotent grow from this exact target if the command outcome is lost.
        self.persist_assigned_update(entry, &target, &intent, Some(to - from))?;
        self.ensure_assigned_volume_update(&intent)
            .await
            .map_err(MError::Other)?;
        Ok(self.view(entry))
    }

    pub(in crate::machine) async fn update_assigned_stopped_size(
        &self,
        entry: &Arc<Entry>,
        req: api::UpdateMachineRequest,
        at: Option<u64>,
    ) -> Result<api::Machine, MError> {
        let size = req.spec.size;
        let image = req.spec.image.clone();
        let requested_volume = req.spec.volume;
        let disk_limits = req.disk_limits.clone();
        if size.is_none() && image.is_none() && requested_volume.is_none()
            || req.spec.entrypoint.is_some()
            || req.spec.cmd.is_some()
            || req.spec.env.is_some()
            || req.spec.files.is_some()
            || req.spec.ports.is_some()
            || req.spec.restart.is_some()
            || req.sleep.is_some()
            || req.metadata.is_some()
            || req.egress.is_some()
            || req.limits.is_some()
            || (disk_limits.is_some() && size.is_none())
            || req.backup.is_some()
            || req.probes.is_some()
        {
            return Err(MError::Conflict(
                "assigned updates currently journal stopped size changes only".into(),
            ));
        }
        req.spec.check().map_err(invalid)?;
        if let Some(size) = &size {
            self.check_host_size(size)?;
        }
        crate::machine::create::check_disk_limits(disk_limits.as_ref())?;

        let _backup = entry.backup_turn.clone().lock_owned().await;
        let _namespace = self.inner.namespace_lifecycle.read().await;
        let _entry = entry.lock.lock().await;
        self.check_version(entry, at)?;
        let record = entry.snapshot();
        if !(self.assigned_lifecycle(&record)
            && record.state == state::STOPPED
            && record.assigned_run.is_some())
        {
            return Err(MError::BadState(
                "assigned size update requires a stopped assigned machine".into(),
            ));
        }
        let current: Current = self
            .inner
            .store
            .get(RUNS, &record.id)?
            .context("assigned current-run journal missing")?;
        let existing = self.inner.store.get::<UpdateIntent>(UPDATES, &record.id)?;
        let existing_is_settlement = existing.as_ref().is_some_and(|update| {
            current
                .settlement
                .as_deref()
                .and_then(|settlement| settlement.update_sha256.as_deref())
                == update.digest().ok().as_deref()
        });
        if current.reference.phase != Phase::Settled
            || (record.pending.is_none()
                && current.record_fingerprint(&record)?
                    != current.record_fingerprint(&current.target)?
                && existing.is_none())
        {
            return Err(MError::Conflict(
                "assigned size update requires the exact settled run".into(),
            ));
        }
        self.check_run_creation_authority(&current)
            .map_err(|error| MError::Conflict(format!("assigned update authority: {error:#}")))?;

        let growth = match requested_volume {
            Some(volume) => crate::machine::update::volume_growth(&record, volume.size_gb)?,
            None => None,
        };
        if let Some((from, to)) = growth {
            self.room_on_pool(to - from).await?;
        }
        let settlement_update = current
            .settlement
            .as_deref()
            .and_then(|settlement| settlement.update.as_deref());
        if let Some(update) = &existing {
            update
                .check(&current)
                .map_err(|error| MError::Conflict(format!("assigned pending update: {error:#}")))?;
            let matches = matches_update_target(&record, &update.target)
                || matches_current_target(&record, &current, update).map_err(MError::Other)?;
            if !matches {
                return Err(MError::Conflict(
                    "assigned pending update differs from its durable authority".into(),
                ));
            }
            if update.resolved_image.is_some() {
                return Err(MError::Conflict(
                    "assigned image root update is already in recovery; start it before another resize".into(),
                ));
            }
        } else if record.pending.is_some()
            && settlement_update.is_none_or(|update| update.target.pending != record.pending)
        {
            return Err(MError::Conflict(
                "assigned pending update lacks settled authority".into(),
            ));
        }

        let mut source_record = record.clone();
        let mut source_current_sha256 = current.authority_sha256()?;
        let mut change = api::SpecChange {
            image: image
                .clone()
                .or_else(|| record.pending.as_ref().and_then(|p| p.image.clone())),
            size: size.or_else(|| record.pending.as_ref().and_then(|p| p.size)),
            volume: growth.map(|(_, to)| api::VolumeSize { size_gb: to }),
            ..Default::default()
        };
        let mut intent_disk_limits = disk_limits.clone();
        let mut resolved_image = None;
        let mut root_swap = None;
        let mut predecessor_target = None;
        if let Some(existing) = &existing {
            if !existing_is_settlement {
                predecessor_target = Some(existing.target.clone());
                source_record = existing.source_record.as_ref().clone();
                source_current_sha256 = existing.source_current_sha256.clone();
                change.image = image.or(existing.change.image.clone());
                change.size = size.or(existing.change.size);
                change.volume = growth
                    .map(|(_, to)| api::VolumeSize { size_gb: to })
                    .or(existing.change.volume);
                if let Some(limits) = &disk_limits {
                    intent_disk_limits = Some(limits.over(&record.disk_limits));
                } else {
                    intent_disk_limits = existing.disk_limits.clone();
                }
                resolved_image = existing.resolved_image.clone();
                root_swap = existing.root_swap.clone();
            }
        }
        // An image equal to the current one changes nothing, so it is not a change of the
        // intent, unless a pending image has to be canceled by it.
        if change.image.as_ref() == Some(&source_record.image)
            && source_record
                .pending
                .as_ref()
                .is_none_or(|pending| pending.image.is_none())
        {
            change.image = None;
        }
        let pending = crate::machine::update::pending_after(&source_record, change.clone());
        let target_disk_limits = intent_disk_limits.as_ref().map_or_else(
            || source_record.disk_limits.clone(),
            |limits| limits.over(&source_record.disk_limits),
        );
        if intent_disk_limits.is_some() {
            // Coalesced partial limit patches are stored as their complete effective target,
            // still relative to the original update source rather than the latest record.
            intent_disk_limits = Some(target_disk_limits.clone());
        }
        if pending == record.pending && target_disk_limits == record.disk_limits {
            // The same request again: its target is reserved, but the growth may not have
            // finished before the first one failed.
            if let Some(existing) = existing.as_ref().filter(|_| !existing_is_settlement) {
                self.ensure_assigned_volume_update(existing)
                    .await
                    .map_err(MError::Other)?;
            }
            return Ok(self.view(entry));
        }
        let mut target = record.clone();
        if let Some((_, to)) = growth {
            target.volume.as_mut().unwrap().size_gb = to;
        }
        target.disk_limits = target_disk_limits;
        target.pending = pending.clone();
        target.pending_since = pending
            .as_ref()
            .map(|_| record.pending_since.unwrap_or_else(Utc::now));
        if target.disk_limits != record.disk_limits {
            let fields = vec!["disk_limits"];
            entry.note_locked(
                &mut target,
                Ev::normal(reason::UPDATED, "disk_limits changed")
                    .data(json!({ "fields": fields })),
            );
        }
        if target.pending != record.pending {
            let fields = target
                .pending
                .clone()
                .unwrap_or_default()
                .changed_from(&record.pending.clone().unwrap_or_default());
            let pending_after = target.pending.is_some();
            entry.note_locked(
                &mut target,
                Ev::normal(
                    reason::UPDATED,
                    format!("{} change at the next start", fields.join(", ")),
                )
                .data(json!({ "fields": fields, "pending": pending_after })),
            );
        }
        let intent = UpdateIntent {
            schema: 1,
            machine: record.id.clone(),
            source_current_sha256,
            source_record: Box::new(source_record),
            change,
            disk_limits: intent_disk_limits,
            target: Box::new(target.clone()),
            predecessor_target,
            resolved_image,
            root_swap,
        };
        intent
            .check(&current)
            .map_err(|error| MError::Conflict(format!("assigned update intent: {error:#}")))?;
        // Record the target volume in the quota map under the same lock as admission. The
        // intent still precedes this record transition so startup can finish an interrupted grow.
        self.persist_assigned_update(entry, &target, &intent, growth.map(|(from, to)| to - from))?;
        if let Some((from, to)) = growth {
            self.ensure_assigned_volume_update(&intent)
                .await
                .map_err(MError::Other)?;
            debug_assert!(to > from);
        }
        Ok(self.view(entry))
    }

    /// Make the machine file match the outstanding update, if there is one. A failed machine
    /// write leaves memory and the journal at the newest target and the file at its predecessor;
    /// startup repairs that, so every durable journal write that startup then checks against the
    /// file (a newer update, a run reservation, a run transition) repairs it first, under the
    /// entry lock. On failure the existing journal is kept.
    pub(super) fn repair_outstanding_update_record(&self, machine: &str) -> Result<()> {
        let Some(update) = self.inner.store.get::<UpdateIntent>(UPDATES, machine)? else {
            return Ok(());
        };
        self.recover_assigned_update(&update)?;
        // Matching bytes can come from a rename whose directory sync failed. The
        // store syncs file contents before rename; complete that durable boundary too.
        std::fs::File::open(self.inner.store.dir("machines"))
            .and_then(|directory| directory.sync_all())
            .context("sync reconciled assigned machine directory")?;
        Ok(())
    }

    pub(super) fn recover_assigned_update(&self, update: &UpdateIntent) -> Result<()> {
        let current: Current = self
            .inner
            .store
            .get(RUNS, &update.machine)?
            .context("assigned update current run missing")?;
        if let Some(settlement) = current.settlement.as_deref() {
            if settlement.update_sha256.as_deref() == Some(update.digest()?.as_str()) {
                anyhow::ensure!(
                    settlement.update.as_deref().is_some_and(|settled| {
                        settled.digest().ok().as_ref() == update.digest().ok().as_ref()
                    }),
                    "settled update journal differs"
                );
                let machine: Record = self
                    .inner
                    .store
                    .get("machines", &update.machine)?
                    .context("settled update machine missing")?;
                anyhow::ensure!(
                    machine.assigned_run.as_ref() == Some(&current.reference)
                        && projection::authority(&machine)?
                            == projection::authority(&current.target)?,
                    "settled update machine differs from its terminal authority"
                );
                return Ok(());
            }
        }
        update.check(&current)?;
        let machine: Record = self
            .inner
            .store
            .get("machines", &update.machine)?
            .context("assigned update machine record missing")?;
        if matches_update_target(&machine, &update.target) {
            let mut repaired = update.target.as_ref().clone();
            repaired.version = machine.version;
            repaired.updated_at = machine.updated_at;
            repaired.last_used_at = machine.last_used_at;
            if serde_json::to_value(&machine)? != serde_json::to_value(&repaired)? {
                self.inner
                    .store
                    .put_durable("machines", &update.machine, &repaired)?;
            }
        } else if (matches_update_image(&machine, &update.source_record)
            && machine.pending == update.source_record.pending)
            || update
                .predecessor_target
                .as_deref()
                .is_some_and(|earlier| matches_update_target(&machine, earlier))
        {
            self.inner
                .store
                .put_durable("machines", &update.machine, &*update.target)?;
        } else {
            anyhow::bail!("assigned update machine record conflicts with source and target");
        }
        Ok(())
    }

    pub(super) async fn ensure_assigned_volume_update(&self, update: &UpdateIntent) -> Result<()> {
        let Some(volume) = update.change.volume.as_ref() else {
            return Ok(());
        };
        let data = update.target.data_dataset();
        let wanted = u64::from(volume.size_gb)
            .checked_mul(1 << 30)
            .context("assigned volume size overflow")?;
        let actual = self.inner.zfs.volsize(&data).await?;
        anyhow::ensure!(
            actual <= wanted,
            "assigned data volume exceeds its durable update target"
        );
        if actual < wanted {
            self.inner.zfs.grow(&data, wanted).await?;
        }
        anyhow::ensure!(
            self.inner.zfs.volsize(&data).await? == wanted,
            "assigned data volume did not reach its durable update target"
        );
        Ok(())
    }

    pub(super) fn cleanup_consumed_image_update(&self, entry: &Arc<Entry>, update: &UpdateIntent) {
        if update.change.image.is_none() {
            return;
        }
        let source = update.source_record.clone();
        let snapshots: Vec<_> = source
            .snapshots
            .iter()
            .filter(|snapshot| snapshot.memory.is_some())
            .map(|snapshot| snapshot.id.clone())
            .collect();
        let manager = self.clone();
        let entry = Arc::clone(entry);
        tokio::spawn(async move {
            // `tidy` requires the machine's lock. The start that consumed the update does not
            // hold it here, so it is taken like any other lifecycle step.
            let _lock = entry.lock.lock().await;
            if !manager.holds(&entry) {
                return;
            }
            for snapshot in snapshots {
                manager.remove_memory(&source, &snapshot);
            }
            let parents = manager.tidy_or_warn(&entry).await;
            manager.tidy_later(parents);
        });
    }

    pub(in crate::machine) async fn recover_assigned_update_backing(&self) -> Result<()> {
        for update in self.inner.store.list::<UpdateIntent>(UPDATES)? {
            let current: Current = self
                .inner
                .store
                .get(RUNS, &update.machine)?
                .context("assigned update current run missing")?;
            update.check(&current)?;
            self.ensure_assigned_volume_update(&update).await?;
            // Startup only completes an externally started swap with durable target identity.
            // Resolving an image or creating/adopting .next belongs to the next assigned start.
            if update
                .root_swap
                .as_ref()
                .and_then(|swap| swap.target_guid)
                .is_some()
            {
                self.apply_assigned_root_update(update).await?;
            }
        }
        Ok(())
    }

    /// Pending journals retain the machine's entire backing until run consumption is durable.
    /// Unreadable authority must refuse cleanup, never imply that there are no references.
    pub(in crate::machine) fn assigned_update_machines(
        &self,
    ) -> Result<std::collections::HashSet<String>> {
        Ok(self
            .inner
            .store
            .list::<UpdateIntent>(UPDATES)?
            .into_iter()
            .map(|update| update.machine)
            .collect())
    }

    pub(in crate::machine) fn assigned_update_images(
        &self,
    ) -> Result<std::collections::HashSet<String>> {
        Ok(self
            .inner
            .store
            .list::<UpdateIntent>(UPDATES)?
            .into_iter()
            .filter_map(|update| update.resolved_image.map(|image| image.key))
            .collect())
    }

    pub(super) async fn ensure_assigned_root_update(&self, update: &UpdateIntent) -> Result<()> {
        if update.change.image.is_none() {
            anyhow::ensure!(
                update.resolved_image.is_none() && update.root_swap.is_none(),
                "image update authority exists without an image change"
            );
            return Ok(());
        }
        self.resolve_assigned_image_update(update).await?;
        let resolved: UpdateIntent = self
            .inner
            .store
            .get(UPDATES, &update.machine)?
            .context("resolved assigned image update missing")?;
        self.apply_assigned_root_update(resolved).await
    }

    async fn apply_assigned_root_update(&self, mut resolved: UpdateIntent) -> Result<()> {
        let reference = resolved
            .change
            .image
            .as_deref()
            .context("assigned root update image missing")?;
        let current: Current = self
            .inner
            .store
            .get(RUNS, &resolved.machine)?
            .context("assigned image update current run missing")?;
        resolved.check(&current)?;
        anyhow::ensure!(
            current.reference.phase == Phase::Settled,
            "assigned image update requires a settled run"
        );

        let image = resolved
            .resolved_image
            .as_ref()
            .context("resolved assigned image missing")?;
        let mut swap = resolved
            .root_swap
            .clone()
            .context("resolved assigned root swap missing")?;
        resolved.check(&current)?;
        let base = image.dataset();
        anyhow::ensure!(
            image.r#ref == reference
                && self.inner.zfs.exists(&base).await?
                && self
                    .inner
                    .zfs
                    .snapshots(&base)
                    .await?
                    .iter()
                    .any(|snap| snap == crate::image::SNAP),
            "assigned image root snapshot is unavailable"
        );
        self.check_clone_readers(&resolved.machine, None)?;

        let zfs = &self.inner.zfs;
        let live = resolved.target.root_dataset();
        let next = format!("{live}.next");
        if swap.target_guid.is_none() {
            if zfs.exists(&next).await? {
                anyhow::ensure!(
                    zfs.origin(&next).await?.as_ref()
                        == Some(&(base.clone(), crate::image::SNAP.to_string())),
                    "assigned root .next belongs to another operation"
                );
                swap.target_guid = Some(zfs.guid(&next).await?);
            } else {
                anyhow::ensure!(
                    zfs.exists(&live).await? && zfs.guid(&live).await? == swap.source_guid,
                    "assigned root source changed before clone"
                );
                zfs.clone_snapshot(&base, crate::image::SNAP, &next).await?;
                anyhow::ensure!(
                    zfs.origin(&next).await?.as_ref()
                        == Some(&(base.clone(), crate::image::SNAP.to_string())),
                    "assigned root clone origin differs"
                );
                swap.target_guid = Some(zfs.guid(&next).await?);
            }
            resolved.root_swap = Some(swap.clone());
            resolved.check(&current)?;
            self.inner
                .store
                .put_durable(UPDATES, &resolved.machine, &resolved)?;
        }
        let target_guid = swap
            .target_guid
            .context("assigned root target GUID missing")?;
        anyhow::ensure!(
            target_guid != swap.source_guid,
            "assigned root clone reused source GUID"
        );

        let live_exists = zfs.exists(&live).await?;
        let next_exists = zfs.exists(&next).await?;
        let retired_exists = zfs.exists(&swap.retired_dataset).await?;
        let live_guid = if live_exists {
            Some(zfs.guid(&live).await?)
        } else {
            None
        };
        let next_guid = if next_exists {
            anyhow::ensure!(
                zfs.origin(&next).await?.as_ref()
                    == Some(&(base.clone(), crate::image::SNAP.to_string())),
                "assigned root .next origin differs"
            );
            Some(zfs.guid(&next).await?)
        } else {
            None
        };
        let retired_guid = if retired_exists {
            Some(zfs.guid(&swap.retired_dataset).await?)
        } else {
            None
        };
        if live_guid == Some(target_guid) {
            anyhow::ensure!(
                !next_exists
                    && retired_guid == Some(swap.source_guid)
                    && zfs.origin(&live).await?.as_ref()
                        == Some(&(base.clone(), crate::image::SNAP.to_string())),
                "installed assigned root conflicts with its durable update"
            );
            return Ok(());
        }
        anyhow::ensure!(
            next_guid == Some(target_guid),
            "assigned root target clone is missing or changed"
        );
        match live_guid {
            Some(guid) if guid == swap.source_guid => {
                anyhow::ensure!(
                    retired_guid.is_none(),
                    "assigned retired root conflicts with the live source"
                );
                zfs.rename(&live, &swap.retired_dataset).await?;
                anyhow::ensure!(
                    zfs.guid(&swap.retired_dataset).await? == swap.source_guid,
                    "assigned retired root identity differs after rename"
                );
            }
            None => anyhow::ensure!(
                retired_guid == Some(swap.source_guid),
                "assigned image update lost its source root"
            ),
            Some(_) => anyhow::bail!("assigned live root conflicts with update authority"),
        }
        anyhow::ensure!(
            !zfs.exists(&live).await?,
            "assigned root destination is unexpectedly occupied"
        );
        zfs.rename(&next, &live).await?;
        anyhow::ensure!(
            zfs.guid(&live).await? == target_guid
                && zfs.origin(&live).await?.as_ref()
                    == Some(&(base, crate::image::SNAP.to_string())),
            "assigned root installation differs from durable target"
        );
        Ok(())
    }

    async fn resolve_assigned_image_update(&self, update: &UpdateIntent) -> Result<()> {
        let Some(reference) = update.change.image.as_deref() else {
            anyhow::ensure!(
                update.resolved_image.is_none() && update.root_swap.is_none(),
                "image update authority exists without an image change"
            );
            return Ok(());
        };
        if update.resolved_image.is_some() {
            let current: Current = self
                .inner
                .store
                .get(RUNS, &update.machine)?
                .context("assigned image update current run missing")?;
            return update.check(&current);
        }
        let current: Current = self
            .inner
            .store
            .get(RUNS, &update.machine)?
            .context("assigned image update current run missing")?;
        update.check(&current)?;
        anyhow::ensure!(
            current.reference.phase == Phase::Settled,
            "assigned image update requires a settled run"
        );
        let image = self.inner.images.ensure(reference).await?;
        let source_guid = self.inner.zfs.guid(&update.target.root_dataset()).await?;
        anyhow::ensure!(
            source_guid == current.root.guid,
            "assigned image update source root differs from settled backing"
        );
        let suffix = sha(format!(
            "{}:{}:{}",
            update.source_current_sha256, image.key, source_guid
        )
        .as_bytes());
        let mut resolved = update.clone();
        resolved.resolved_image = Some(image);
        resolved.root_swap = Some(RootSwap {
            source_guid,
            target_guid: None,
            retired_dataset: format!(
                "{}/root.u_{}",
                update.source_record.dataset(),
                &suffix[..24]
            ),
        });
        resolved.check(&current)?;
        self.inner
            .store
            .put_durable(UPDATES, &resolved.machine, &resolved)?;
        Ok(())
    }
}
