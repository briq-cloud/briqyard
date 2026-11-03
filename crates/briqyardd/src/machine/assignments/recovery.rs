use super::*;
use model::Intent;

impl Manager {
    pub(super) fn check_assignment_destination(&self, target: &Record) -> Result<()> {
        let machines = self.inner.machines.lock().unwrap();
        self.check_assignment_destination_records(target, &self.assignment_records(&machines)?)
    }

    pub(super) fn assignment_records(
        &self,
        machines: &HashMap<String, Arc<Entry>>,
    ) -> Result<Vec<Record>> {
        let mut records: BTreeMap<_, _> = self
            .inner
            .store
            .list::<Record>("machines")?
            .into_iter()
            .map(|record| (record.id.clone(), record))
            .collect();
        for entry in machines.values() {
            let record = entry.snapshot();
            records.insert(record.id.clone(), record);
        }
        for target in self.assignment_targets() {
            records.insert(target.id.clone(), target);
        }
        Ok(records.into_values().collect())
    }

    pub(super) fn check_assignment_destination_records(
        &self,
        target: &Record,
        records: &[Record],
    ) -> Result<()> {
        let namespace = self
            .namespace_of(&target.namespace)
            .context("assignment destination namespace missing")?;
        anyhow::ensure!(
            target.role.is_none()
                && (2..=254).contains(&target.host_num)
                && target.subnet_index == namespace.rec.subnet_index
                && target.ip == namespace.subnet.host(target.host_num)?.to_string(),
            "assignment destination address is invalid"
        );
        anyhow::ensure!(
            !self
                .held_addresses_except_assignment(target.subnet_index, &target.id)
                .contains(&u32::from(target.host_num)),
            "assignment destination address is held"
        );
        anyhow::ensure!(
            !self
                .durable_launch_addresses()?
                .contains(&(target.subnet_index, target.host_num)),
            "assignment destination overlaps a durable launch allocation"
        );
        anyhow::ensure!(
            !self.assignment_name_held(&target.namespace, &target.name, &target.id)
                && self
                    .inner
                    .warm_names
                    .lock()
                    .unwrap()
                    .get(&(target.namespace.clone(), target.name.clone()))
                    .is_none_or(|id| id == &target.id),
            "assignment destination name is reserved"
        );
        for record in records
            .iter()
            .filter(|record| record.id != target.id && record.namespace == target.namespace)
        {
            anyhow::ensure!(
                record.host_num != target.host_num
                    && (record.name != target.name || record.state == state::DESTROYING),
                "assignment destination name or address is already taken"
            );
        }
        anyhow::ensure!(
            !self.inner.policies.lock().unwrap().values().any(
                |(_, policy)| matches!(policy, nft::Policy::Via { to, .. } if to == &target.ip)
            ),
            "assignment destination address is retained by a network policy"
        );
        let root = target
            .clone_origin
            .as_ref()
            .context("assignment origin missing")?
            .artifact
            .recipe
            .root_disk_gb;
        root.checked_add(target.volume.as_ref().map_or(0, |volume| volume.size_gb))
            .context("assignment logical storage charge overflow")?;
        let machines: HashMap<_, _> = records
            .iter()
            .filter(|record| record.id != target.id)
            .map(|record| {
                (
                    record.id.clone(),
                    Entry::new(record.clone(), self.inner.events.clone()),
                )
            })
            .collect();
        let used = namespace_use(&machines, &target.namespace);
        if let Some(exceeded) = over_quota(
            &target.namespace,
            &namespace.rec.quota,
            &used,
            &quota_need(target, true),
        ) {
            return Err(MError::Quota(exceeded.to_string()).into());
        }
        let _ = self.policy_for_records(target, records)?;
        Ok(())
    }

    /// Startup-only metadata reconciliation. This grants no permission to bind or resume.
    pub(in crate::machine) fn recover_destination_assignments(&self) -> Result<()> {
        let receipts = self.inner.store.list::<Receipt>(REQUESTS)?;
        let intents = self.inner.store.list::<Intent>(INTENTS)?;
        {
            let mut state = self.inner.assignments.lock().unwrap();
            let mut receipt_keys = std::collections::HashSet::new();
            let mut intent_keys = std::collections::HashSet::new();
            for receipt in &receipts {
                anyhow::ensure!(
                    receipt_keys.insert(receipt.key())
                        && self
                            .inner
                            .store
                            .get::<Receipt>(REQUESTS, &receipt.key())?
                            .as_ref()
                            == Some(receipt),
                    "destination receipt key or duplicate conflict"
                );
                state.remember(receipt, false)?;
            }
            for intent in &intents {
                let stored = self
                    .inner
                    .store
                    .get::<Intent>(INTENTS, &intent.receipt.key())?;
                anyhow::ensure!(
                    intent_keys.insert(intent.receipt.key())
                        && stored
                            .as_ref()
                            .is_some_and(|stored| serde_json::to_value(stored).ok()
                                == serde_json::to_value(intent).ok()),
                    "destination intent key or duplicate conflict"
                );
                intent.check()?;
                state.reserve(intent)?;
            }
        }
        if !intents.is_empty() {
            anyhow::ensure!(
                self.inner.machines.lock().unwrap().is_empty(),
                "destination reconciliation requires closed startup admission"
            );
        }
        for intent in intents {
            let records = self.assignment_records(&HashMap::new())?;
            self.write_destination_intent(&intent, &records, |_| {})?;
            self.finish_destination_intent(&intent)?;
        }
        Ok(())
    }

    pub(super) fn write_destination_intent(
        &self,
        intent: &Intent,
        records: &[Record],
        publish_record: impl FnOnce(&Record),
    ) -> Result<()> {
        intent.check()?;
        anyhow::ensure!(
            intent
                .source
                .clone_origin
                .as_ref()
                .unwrap()
                .artifact
                .source_host
                == self.inner.host_id,
            "destination assignment is intrinsic to its original host"
        );
        let id = &intent.receipt.machine;
        self.check_durable_launch_hold(id, intent.source.launch_identity.as_ref().unwrap())?;
        let mut current = self
            .inner
            .store
            .get::<Record>("machines", id)?
            .context("assignment record missing; request remains consumed")?;
        let reader = self
            .inner
            .store
            .get::<templates::CloneReader>(templates::READERS, id)?
            .context("assignment reader missing; backing retained")?;
        let current_hash = launch_identity::record_fingerprint(&current)?;
        let source_hash = launch_identity::record_fingerprint(&intent.source)?;
        let target_hash = launch_identity::record_fingerprint(&intent.target)?;
        anyhow::ensure!(
            current_hash == source_hash || current_hash == target_hash,
            "assignment record differs from exact durable control evidence"
        );
        anyhow::ensure!(
            reader == intent.source_reader || reader == intent.target_reader,
            "assignment reader conflicts with durable evidence"
        );
        if current_hash == source_hash {
            anyhow::ensure!(
                reader == intent.source_reader,
                "assignment reader advanced before ownership record"
            );
            launch_identity::check_launch_pair(&current, Some(&intent.source_reader))?;
        } else {
            launch_identity::check_launch_pair(&current, Some(&intent.target_reader))?;
        }
        self.check_assignment_destination_records(&intent.target, records)?;
        self.persist_destination_receipt(&intent.receipt)?;
        if current_hash == source_hash {
            let previous = current;
            current = intent.target.clone();
            if previous.state != state::STARTING
                || previous.clone_origin.as_ref().unwrap().mapping_exited
            {
                current.state = previous.state;
                current.error = previous.error;
                current.error_reason = previous.error_reason;
                current.exit = previous.exit;
                current.pid = previous.pid;
                current.stopped_at = previous.stopped_at;
            }
            current.clone_origin.as_mut().unwrap().mapping_exited |=
                previous.clone_origin.as_ref().unwrap().mapping_exited;
            anyhow::ensure!(
                launch_identity::record_fingerprint(&current)? == target_hash,
                "assignment terminal observations changed frozen control data"
            );
            launch_identity::check_launch_pair(&current, Some(&intent.target_reader))?;
            self.inner.store.put_durable("machines", id, &current)?;
        }
        // Publish the same Entry before any uncertain reader write. A later generic
        // save must preserve target ownership, never recreate source + target-reader.
        publish_record(&current);
        self.inner
            .store
            .put_durable(templates::READERS, id, &intent.target_reader)?;
        Ok(())
    }

    pub(super) fn finish_destination_intent(&self, intent: &Intent) -> Result<()> {
        self.inner
            .store
            .delete_durable(INTENTS, &intent.receipt.key())?;
        let mut state = self.inner.assignments.lock().unwrap();
        state.pending.remove(&intent.receipt.machine);
        state.targets.remove(&intent.receipt.machine);
        Ok(())
    }
}
