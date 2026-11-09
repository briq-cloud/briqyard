//! Initial assigned process updates retain immutable creation authority through exit.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreationSettlement {
    incarnation: fc::Incarnation,
    /// Absent only for an exit observed through the exact owned process handle.
    changed_host_boot_id: Option<String>,
    stopped_baseline_sha256: String,
}

fn stopped_projection(record: &Record) -> Record {
    let mut record = record.clone();
    record.pid = 0;
    record.suspended = false;
    record.suspend_synced = false;
    record.clone_origin.as_mut().unwrap().mapping_exited = true;
    record
}

impl UpdateIntent {
    pub(super) fn check_creation_settlement(&self) -> Result<()> {
        let Some(settlement) = &self.creation_settlement else {
            return Ok(());
        };
        anyhow::ensure!(
            self.schema == 3
                && self.live_creation_source.is_some()
                && self.source_record.boot_incarnation.as_ref() == Some(&settlement.incarnation)
                && settlement
                    .changed_host_boot_id
                    .as_ref()
                    .is_none_or(|host| fc::valid_host_boot_id(host)
                        && *host != settlement.incarnation.host_boot_id)
                && settlement.stopped_baseline_sha256
                    == projection::fingerprint(&stopped_projection(&self.source_record))?
                && self.target.pid == 0
                && !self.target.suspended
                && !self.target.suspend_synced
                && self
                    .target
                    .clone_origin
                    .as_ref()
                    .is_some_and(|origin| origin.mapping_exited),
            "creation settlement differs from exact original process and stopped projection"
        );
        Ok(())
    }

    pub(super) fn normalize_creation_settlement(&self, projected: &mut Record) -> Result<()> {
        if self.creation_settlement.is_some() && projected.pid == 0 {
            anyhow::ensure!(
                !projected.suspended
                    && !projected.suspend_synced
                    && projected
                        .clone_origin
                        .as_ref()
                        .is_some_and(|origin| origin.mapping_exited),
                "creation settlement projection is not cold and exited"
            );
            projected.pid = self.source_record.pid;
            projected.suspended = self.source_record.suspended;
            projected.suspend_synced = self.source_record.suspend_synced;
            projected.clone_origin.as_mut().unwrap().mapping_exited = false;
            // State is an observation, but source bytes remain immutable.
            projected.state = self.source_record.state.clone();
        }
        Ok(())
    }
}

impl Manager {
    pub(in crate::machine) fn creation_update_source_record(
        &self,
        record: &Record,
    ) -> Result<Option<Record>> {
        let Some(update) = self.inner.store.get::<UpdateIntent>(UPDATES, &record.id)? else {
            anyhow::ensure!(
                record.assigned_run.is_some() || record.pending.is_none(),
                "initial assigned pending change lacks durable update authority"
            );
            return Ok(None);
        };
        if update.creation_authority().is_none() {
            return Ok(None);
        }
        self.check_update_source(&update)?;
        anyhow::ensure!(
            updates::matches_update_target(record, &update.target),
            "creation update record differs"
        );
        Ok(Some(*update.source_record))
    }

    pub(super) async fn update_live_creation_volume(
        &self,
        entry: &Arc<Entry>,
        record: &Record,
        requested: api::VolumeSize,
    ) -> Result<api::Machine> {
        anyhow::ensure!(
            record.state == state::RUNNING && record.assigned_run.is_none(),
            "live creation growth requires the initial running assignment"
        );
        let existing = self.inner.store.get::<UpdateIntent>(UPDATES, &record.id)?;
        let source = existing
            .as_ref()
            .map_or(record, |update| &update.source_record);
        let origin = self.settled_assigned_origin(source)?;
        Self::check_assigned_binding(source, &origin)?;
        anyhow::ensure!(
            origin.stage == templates::CloneStage::Active
                && !origin.mapping_exited
                && origin.artifact.source_host == self.inner.host_id
                && entry.identity_trusted.load(Relaxed),
            "initial assigned process is not trusted and active"
        );
        let live = entry
            .live
            .lock()
            .unwrap()
            .clone()
            .context("initial assigned handle missing")?;
        self.verify_live_launch(entry, &live)?;
        self.assigned_process_proof(record)?;
        anyhow::ensure!(
            !*live.exited.borrow()
                && live.pid == source.pid
                && live.incarnation == source.boot_incarnation
                && live.boot_identity == source.boot_identity,
            "initial assigned handle differs from original process"
        );
        anyhow::ensure!(
            self.inner
                .store
                .get::<serde_json::Value>(INTENTS, &record.id)?
                .is_none()
                && self
                    .inner
                    .store
                    .get::<serde_json::Value>(READERS, &record.id)?
                    .is_none(),
            "initial assignment has unresolved continuation authority"
        );
        if let Some(update) = &existing {
            self.check_update_source(update)?;
            anyhow::ensure!(
                update.live_creation_source.is_some()
                    && update.creation_settlement.is_none()
                    && updates::matches_update_target(record, &update.target),
                "initial assigned update target differs"
            );
            self.check_creation_update_backing(update).await?;
            self.ensure_assigned_volume_update(update).await?;
        } else {
            anyhow::ensure!(
                record.pending.is_none(),
                "initial assignment has unjournaled pending changes"
            );
        }
        let growth = crate::machine::update::volume_growth(record, requested.size_gb)?;
        let Some((from, to)) = growth else {
            return Ok(self.view(entry));
        };
        self.room_on_pool(to - from).await?;
        let creation = if let Some(update) = &existing {
            update.live_creation_source.clone().unwrap()
        } else {
            let binding = origin.sandbox.as_ref().unwrap();
            let receipt = self
                .inner
                .store
                .get(
                    super::super::REQUESTS,
                    &key(&source.namespace, &binding.request_id),
                )?
                .context("live creation receipt missing")?;
            let reader = self
                .inner
                .store
                .get(templates::READERS, &source.id)?
                .context("live creation reader missing")?;
            let (root, data) = self.current_run_disks(source).await?;
            anyhow::ensure!(
                self.inner.zfs.volsize(&source.root_dataset()).await?
                    == (u64::from(origin.artifact.recipe.root_disk_gb) << 30)
                    && self.inner.zfs.volsize(&source.data_dataset()).await?
                        == (u64::from(from) << 30),
                "live creation backing geometry differs"
            );
            update_authority::CreationSource {
                receipt,
                reader,
                root,
                data,
            }
        };
        let mut target = record.clone();
        target.volume.as_mut().unwrap().size_gb = to;
        let change = api::SpecChange {
            volume: Some(requested),
            ..Default::default()
        };
        target.pending = crate::machine::update::pending_after(source, change.clone());
        target.pending_since = Some(record.pending_since.unwrap_or_else(Utc::now));
        entry.note_locked(
            &mut target,
            Ev::normal(reason::UPDATED, "volume change applied to the data disk")
                .data(json!({"fields": ["volume"], "volume_gb": to})),
        );
        let intent = UpdateIntent {
            schema: 3,
            machine: record.id.clone(),
            source_current_sha256: None,
            source_record: Box::new(source.clone()),
            change,
            disk_limits: None,
            target: Box::new(target.clone()),
            predecessor_target: existing.as_ref().map(|update| update.target.clone()),
            resolved_image: None,
            root_swap: None,
            creation_source: None,
            live_creation_source: Some(creation),
            creation_settlement: None,
        };
        self.check_update_source(&intent)?;
        self.check_creation_update_backing(&intent).await?;
        self.persist_assigned_update(entry, &target, &intent, Some(to - from))?;
        self.ensure_assigned_volume_update(&intent).await?;
        self.assigned_process_proof(&entry.snapshot())?;
        Ok(self.view(entry))
    }

    /// Entry lock held. Write exit authority before any writer clears PID or mapping evidence.
    pub(in crate::machine) async fn settle_creation_update(&self, entry: &Entry) -> Result<()> {
        let record = entry.snapshot();
        let Some(mut update) = self.inner.store.get::<UpdateIntent>(UPDATES, &record.id)? else {
            return Ok(());
        };
        if update.live_creation_source.is_none() {
            return Ok(());
        }
        self.check_update_source(&update)?;
        if update.creation_settlement.is_some() {
            self.repair_outstanding_update_record(&record.id)?;
            *entry.rec.lock().unwrap() = projection::preserve_advisory(&update.target, &record)?;
            return Ok(());
        }
        self.check_creation_update_backing(&update).await?;
        self.ensure_assigned_volume_update(&update).await?;
        let incarnation = update.source_record.boot_incarnation.as_ref().unwrap();
        let host = self
            .inner
            .vmm
            .host_boot_id()
            .filter(|host| fc::valid_host_boot_id(host));
        let changed = host.filter(|host| *host != incarnation.host_boot_id);
        let owned_exit = entry.live.lock().unwrap().as_ref().is_some_and(|live| {
            live.pid == incarnation.pid
                && live.incarnation.as_ref() == Some(incarnation)
                && live.boot_identity == update.source_record.boot_identity
                && *live.exited.borrow()
        });
        anyhow::ensure!(
            changed.is_some() || owned_exit,
            "creation update process exit is unconfirmed"
        );
        self.repair_outstanding_update_record(&record.id)?;
        update.predecessor_target = Some(update.target.clone());
        *update.target = stopped_projection(&update.target);
        update.target.state = state::STOPPED.into();
        update.creation_settlement = Some(CreationSettlement {
            incarnation: incarnation.clone(),
            changed_host_boot_id: changed,
            stopped_baseline_sha256: projection::fingerprint(&stopped_projection(
                &update.source_record,
            ))?,
        });
        self.check_update_source(&update)?;
        self.inner.store.put_durable(UPDATES, &record.id, &update)?;
        self.inner
            .store
            .put_durable("machines", &record.id, &update.target)?;
        *entry.rec.lock().unwrap() = *update.target;
        Ok(())
    }
}
