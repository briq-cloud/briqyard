//! Private admission/ownership primitives; no selector, binding or activation caller.
use super::*;
use model::Intent;

impl Manager {
    #[allow(dead_code)]
    pub(in crate::machine) async fn stage_destination_assignment(
        &self,
        request: api::CreateMachineRequest,
        entry: &Arc<Entry>,
        host: u8,
    ) -> Result<()> {
        let _warm = self.inner.warm_lock.lock().await;
        let _namespace = self.inner.namespace_lifecycle.read().await;
        let _sandbox = self.inner.sandbox_create_lock.lock().await;
        let _entry = entry.lock.lock().await;
        let intent = Intent::plan(self, request, entry, host)?;
        let machines = self.inner.machines.lock().unwrap();
        anyhow::ensure!(
            machines
                .get(&intent.source.id)
                .is_some_and(|e| Arc::ptr_eq(e, entry)),
            "assignment source left the live map"
        );
        anyhow::ensure!(
            launch_identity::record_fingerprint(&entry.snapshot())?
                == launch_identity::record_fingerprint(&intent.source)?,
            "assignment source changed during preparation"
        );
        let live = entry
            .live
            .lock()
            .unwrap()
            .clone()
            .context("owned paused process missing")?;
        self.verify_live_launch(entry, &live)?;
        self.check_assignment_destination_records(
            &intent.target,
            &self.assignment_records(&machines)?,
        )?;
        // The reservation is installed at the ordinary allocator's commit boundary before
        // uncertain I/O. Failure keeps name/address/quota and exact request/slot consumed.
        self.inner.assignments.lock().unwrap().reserve(&intent)?;
        anyhow::ensure!(
            self.inner
                .store
                .get::<Intent>(INTENTS, &intent.receipt.key())?
                .is_none(),
            "destination assignment intent already exists"
        );
        self.inner
            .store
            .put_durable(INTENTS, &intent.receipt.key(), &intent)?;
        self.persist_destination_receipt(&intent.receipt)
    }

    // The journal authorizes both exact reader ownership states. Process proof remains
    // immutable source proof even after a reader write whose result was uncertain.
    fn verify_assignment_process(&self, intent: &Intent, live: &fc::Vm) -> Result<()> {
        intent.check()?;
        let source = &intent.source;
        let identity = source
            .launch_identity
            .as_ref()
            .context("source identity missing")?;
        self.check_durable_launch_hold(&source.id, identity)?;
        anyhow::ensure!(
            self.inner.launch_holds.lock().unwrap().get(&source.id) == Some(identity),
            "source launch allocation is not held"
        );
        let saved = source
            .boot_incarnation
            .as_ref()
            .context("source incarnation missing")?;
        anyhow::ensure!(
            !*live.exited.borrow()
                && live.pid == source.pid
                && live.incarnation.as_ref() == Some(saved)
                && live.boot_identity == source.boot_identity
                && self
                    .inner
                    .vmm
                    .verify_process(&source.id, saved, identity.uid, identity.gid),
            "actual assignment process, incarnation or credentials are unconfirmed"
        );
        Ok(())
    }

    #[allow(dead_code)]
    pub(in crate::machine) async fn commit_destination_assignment(
        &self,
        namespace: &str,
        request: &str,
        digest: &str,
    ) -> Result<Arc<Entry>> {
        let _warm = self.inner.warm_lock.lock().await;
        let _namespace = self.inner.namespace_lifecycle.read().await;
        let _sandbox = self.inner.sandbox_create_lock.lock().await;
        let receipt = self
            .destination_receipt(namespace, request)?
            .context("assignment absent")?;
        anyhow::ensure!(
            receipt.create_sha256 == digest,
            "assignment request identity conflict"
        );
        if !self.destination_assignment_pending(&receipt.machine)? {
            return self
                .resolve_destination_assignment(namespace, request, digest)?
                .context("consumed assignment is unavailable");
        }
        let intent = self
            .inner
            .store
            .get::<Intent>(INTENTS, &receipt.key())?
            .context("pending assignment has no durable intent; reservation retained")?;
        intent.check()?;
        anyhow::ensure!(
            intent.receipt == receipt,
            "durable assignment receipt differs"
        );
        let entry = self.entry(&receipt.machine)?;
        let _entry = entry.lock.lock().await;
        let before = entry.snapshot();
        let fingerprint = launch_identity::record_fingerprint(&before)?;
        anyhow::ensure!(
            fingerprint == launch_identity::record_fingerprint(&intent.source)?
                || fingerprint == launch_identity::record_fingerprint(&intent.target)?,
            "live entry differs from exact assignment evidence"
        );
        // No inferred PID absence, replacement Entry, VMM resume, guest frame or network
        // publication is allowed here. Unknown exit retains the source and reservation.
        let live = entry
            .live
            .lock()
            .unwrap()
            .clone()
            .context("owned paused process missing")?;
        self.verify_assignment_process(&intent, &live)?;
        self.meter(std::slice::from_ref(&entry), Utc::now()).await;
        {
            let machines = self.inner.machines.lock().unwrap();
            anyhow::ensure!(
                machines
                    .get(&receipt.machine)
                    .is_some_and(|e| Arc::ptr_eq(e, &entry)),
                "assignment source left the live map"
            );
            // Generic save/save_edit also take removed. Keep a stale source snapshot
            // from landing after the destination record/reader publication.
            let removed = entry.removed.lock().unwrap();
            anyhow::ensure!(!*removed, "assignment entry was removed");
            self.verify_assignment_process(&intent, &live)?;
            let records = self.assignment_records(&machines)?;
            self.write_destination_intent(&intent, &records, |current| {
                // Holding machines + rec makes quota/name/address transfer one admission
                // step. Publish before reader I/O so a failed reader write cannot let a
                // later generic save restore source ownership with an advanced reader.
                let mut record = entry.rec.lock().unwrap();
                let mut meter = entry.meter.lock().unwrap();
                let now = Utc::now();
                meter.advance(now, held(&record));
                self.inner
                    .usage
                    .lock()
                    .unwrap()
                    .add(&usage_identity(&record), meter.drain());
                if record.namespace != current.namespace || record.ip != current.ip {
                    meter.rehome(now);
                    entry.traffic.take();
                }
                *record = current.clone();
            })?;
            // Delete last: failures leave the same Entry/intent reserved for exact retry.
            self.finish_destination_intent(&intent)?;
        }
        entry.changed.notify_waiters();
        drop(_entry);
        Ok(entry)
    }
}
