//! Private binding of a settled assignment on its original owned VMM.
//! Selection, assignment-aware adoption and public consumption remain unavailable.
use super::*;

impl Manager {
    fn assigned_origin(&self, entry: &Entry, live: &fc::Vm) -> Result<templates::CloneOrigin> {
        let record = entry.snapshot();
        anyhow::ensure!(
            record.launch_identity.is_some()
                && matches!(record.state.as_str(), state::STARTING | state::RUNNING),
            "assignment requires its original starting process"
        );
        anyhow::ensure!(
            entry.identity_trusted.load(Relaxed),
            "assigned handle is not trusted"
        );
        let owned = entry
            .live
            .lock()
            .unwrap()
            .clone()
            .context("assigned owned handle missing")?;
        anyhow::ensure!(
            owned.pid == live.pid
                && owned.api == live.api
                && owned.vsock == live.vsock
                && owned.incarnation == live.incarnation
                && owned.boot_identity == live.boot_identity,
            "assignment handle differs from the original owned VMM"
        );
        self.verify_live_launch(entry, live)?;
        self.settled_assigned_origin(&record)
    }

    pub(super) fn settled_assigned_origin(
        &self,
        record: &Record,
    ) -> Result<templates::CloneOrigin> {
        self.validate_launch_record(record)?;
        self.settled_assigned_origin_durable(record)
    }

    pub(in crate::machine) fn settled_assigned_origin_durable(
        &self,
        record: &Record,
    ) -> Result<templates::CloneOrigin> {
        anyhow::ensure!(
            record.assigned_run.is_none(),
            "run continuation requires separate lifecycle/guest proof"
        );
        anyhow::ensure!(
            record.launch_identity.is_some(),
            "assigned launch identity missing"
        );
        self.check_durable_launch_hold(&record.id, record.launch_identity.as_ref().unwrap())?;
        let reader = self
            .inner
            .store
            .get::<templates::CloneReader>(templates::READERS, &record.id)?;
        launch_identity::check_launch_pair(record, reader.as_ref())?;
        anyhow::ensure!(
            self.inner
                .store
                .get::<serde_json::Value>("launch-transitions", &record.id)?
                .is_none(),
            "unsettled assignment stage requires journal recovery"
        );
        let origin = record
            .clone_origin
            .as_ref()
            .context("assignment origin missing")?;
        let binding = origin
            .sandbox
            .as_ref()
            .context("assignment binding missing")?;
        // Cache-only consumption authority prevents fallback, but cannot authorize
        // binding, adoption or publication when permanent evidence disappeared.
        let durable = self
            .inner
            .store
            .get::<Receipt>(REQUESTS, &key(&record.namespace, &binding.request_id))?
            .context("durable permanent assignment receipt missing")?;
        durable.check()?;
        anyhow::ensure!(
            durable.namespace == record.namespace && durable.request_id == binding.request_id,
            "durable assignment receipt key differs"
        );
        let receipt = self
            .destination_receipt(&record.namespace, &binding.request_id)?
            .context("permanent assignment receipt missing")?;
        anyhow::ensure!(
            receipt == durable,
            "durable assignment receipt differs from consumed authority"
        );
        anyhow::ensure!(
            receipt.machine == record.id
                && receipt.create_sha256 == binding.create_sha256
                && !self.destination_assignment_pending(&record.id)?
                && record
                    .warm_slot
                    .as_ref()
                    .and_then(|slot| slot.claimed.as_deref())
                    == Some(binding.request_id.as_str()),
            "assignment ownership differs from its settled receipt"
        );
        anyhow::ensure!(
            matches!(
                origin.stage,
                templates::CloneStage::UnboundPaused
                    | templates::CloneStage::Configuring
                    | templates::CloneStage::IdentityDone
                    | templates::CloneStage::Active
            ),
            "assignment is not at its binding or activation barrier"
        );
        Ok(origin.clone())
    }

    pub(super) fn freeze_assigned_configuration(
        &self,
        entry: &Entry,
        mut origin: templates::CloneOrigin,
    ) -> Result<()> {
        if origin.stage == templates::CloneStage::UnboundPaused {
            anyhow::ensure!(
                origin.identity.is_none()
                    && origin.sandbox.as_ref().is_some_and(
                        |binding| binding.bind.is_none() && binding.ack_sha256.is_none()
                    ),
                "assignment was already configured"
            );
            origin.configure.realtime_sec = Utc::now().timestamp().try_into()?;
            let bind = templates::sandbox::destination_bind(&entry.snapshot(), &origin)?;
            origin.sandbox.as_mut().unwrap().bind = Some(bind);
            entry.rec.lock().unwrap().clone_origin = Some(origin);
            // Full payload/entropy/clock and Configuring are durable before resume or send.
            self.clone_stage(entry, templates::CloneStage::Configuring)?;
        }
        Ok(())
    }

    async fn configure_assigned_destination(&self, entry: &Entry, live: &fc::Vm) -> Result<()> {
        let origin = self.assigned_origin(entry, live)?;
        if matches!(
            origin.stage,
            templates::CloneStage::IdentityDone | templates::CloneStage::Active
        ) {
            return self.check_assigned_activation(entry, live);
        }
        self.freeze_assigned_configuration(entry, origin)?;
        let frozen = self.assigned_origin(entry, live)?;
        anyhow::ensure!(
            frozen.stage == templates::CloneStage::Configuring,
            "assignment resume requires durable Configuring"
        );
        let bind = frozen
            .sandbox
            .as_ref()
            .and_then(|binding| binding.bind.as_ref())
            .context("frozen assigned payload missing")?;
        let resolved = templates::sandbox::destination_bind(&entry.snapshot(), &frozen)?;
        anyhow::ensure!(
            bind.fingerprint_bytes()? == resolved.fingerprint_bytes()?,
            "assigned payload differs from frozen destination"
        );
        // A journal never proves Running. The assignment-only backend operation queries
        // the established API, permits Paused -> Running or already Running, and refuses
        // unknown state. Fresh immutable process proof brackets that API operation.
        self.verify_live_launch(entry, live)?;
        self.inner.vmm.resume_assigned(live).await?;
        self.verify_live_launch(entry, live)?;
        let pong = self.inner.guest.ping(&live.vsock).await?;
        let status = pong
            .clone_status
            .as_ref()
            .context("assigned guest omitted its barrier")?;
        anyhow::ensure!(
            pong.main_pid == 0
                && pong.init_sha256 == frozen.artifact.init_sha256
                && status.protocol == 1
                && status.profile == guest::SANDBOX_READY_V1
                && status.ram_marker == frozen.artifact.ram_marker,
            "assigned guest is not at its exact pre-main barrier"
        );
        match status.stage.as_str() {
            "builder" => anyhow::ensure!(
                status.identity.is_none(),
                "builder already has destination identity"
            ),
            "destination_done" => {
                templates::sandbox::check_ack(&frozen, &pong, &["destination_done"])?
            }
            _ => anyhow::bail!("Configuring cannot authorize an activated guest"),
        }
        self.configure_sandbox_destination(entry, live, frozen)
            .await?;
        self.check_assigned_activation(entry, live)
    }

    pub(in crate::machine) fn check_assigned_activation(
        &self,
        entry: &Entry,
        live: &fc::Vm,
    ) -> Result<()> {
        self.assigned_origin(entry, live)?;
        self.check_assigned_bound_record(&entry.snapshot())
    }

    pub(in crate::machine) fn check_assigned_bound_record(&self, record: &Record) -> Result<()> {
        if let Some(source) = self.creation_update_source_record(record)? {
            let origin = self.settled_assigned_origin(&source)?;
            return Self::check_assigned_binding(&source, &origin);
        }
        let origin = self.settled_assigned_origin(record)?;
        Self::check_assigned_binding(record, &origin)
    }

    pub(in crate::machine) fn check_assigned_binding(
        record: &Record,
        origin: &templates::CloneOrigin,
    ) -> Result<()> {
        anyhow::ensure!(
            matches!(
                origin.stage,
                templates::CloneStage::IdentityDone | templates::CloneStage::Active
            ) && origin.identity.is_some(),
            "assignment has no durable complete bind acknowledgment"
        );
        let binding = origin.sandbox.as_ref().unwrap();
        let bind = binding.bind.as_ref().context("assigned payload missing")?;
        let resolved = templates::sandbox::destination_bind(record, origin)?;
        anyhow::ensure!(
            binding.ack_sha256.as_ref() == Some(&templates::sandbox::binding_hash(bind)?)
                && bind.fingerprint_bytes()? == resolved.fingerprint_bytes()?,
            "assignment acknowledgment or complete payload differs"
        );
        Ok(())
    }

    /// Startup Entries begin untrusted. Metadata alone cannot publish an assigned VM.
    pub(in crate::machine) fn assignment_publication_allowed(
        &self,
        record: &Record,
        trusted: bool,
    ) -> bool {
        if record.launch_identity.is_none() {
            return true;
        }
        if record.assigned_run.is_some() {
            return trusted && self.verified_run_publication(record).is_ok();
        }
        trusted
            && record
                .clone_origin
                .as_ref()
                .is_some_and(|origin| origin.stage == templates::CloneStage::Active)
            && self.check_assigned_bound_record(record).is_ok()
    }

    /// Private end-to-end caller. No ordinary create/selector reaches this function.
    #[allow(dead_code)]
    pub(in crate::machine) async fn start_destination_assignment(
        &self,
        namespace: &str,
        request: &str,
        digest: &str,
    ) -> Result<api::Machine> {
        let entry = self
            .commit_destination_assignment(namespace, request, digest)
            .await?;
        let _namespace = self.inner.namespace_lifecycle.read().await;
        let _entry = entry.lock.lock().await;
        let record = entry.snapshot();
        let live = entry
            .live
            .lock()
            .unwrap()
            .clone()
            .context("original assigned handle unavailable")?;
        if record.state == state::RUNNING
            && record
                .clone_origin
                .as_ref()
                .is_some_and(|origin| origin.stage == templates::CloneStage::Active)
        {
            self.check_assigned_activation(&entry, &live)?;
            let ticket = self.begin_execution_mutation(
                std::slice::from_ref(&record.namespace),
                crate::machine::execution_fence::MutationMode::Broaden,
            )?;
            // A previous final save may have failed after Active became durable.
            self.save_execution_publication(&entry)?;
            if entry.prober.lock().unwrap().is_none() && !record.probes.is_empty() {
                let (_, _, generation) = self.reset_probes(&entry);
                self.spawn_probes(&entry, &live, generation, true);
            }
            if let Some(namespace) = self.namespace_of(namespace) {
                self.refresh_dns(&namespace);
            }
            self.finish_execution_mutation(&ticket)?;
            return Ok(self.view(&entry));
        }
        self.configure_assigned_destination(&entry, &live).await?;
        self.check_assigned_activation(&entry, &live)?;
        let ticket = self.begin_execution_mutation(
            std::slice::from_ref(&record.namespace),
            crate::machine::execution_fence::MutationMode::Broaden,
        )?;
        let version = if entry.snapshot().clone_origin.as_ref().unwrap().stage
            == templates::CloneStage::Active
        {
            record.init_version
        } else {
            // Full ACK is durable before target traffic counters or bridge visibility.
            self.inner.net.count(&entry.snapshot().ip).await?;
            self.activate_configured_clone(
                &entry,
                &live,
                false,
                "unbound_claim",
                std::time::Instant::now(),
            )
            .await?
        };
        let (_, _, generation) = self.reset_probes(&entry);
        entry.set_state(state::RUNNING, |record| {
            record.init_version = version;
            record.started_at = Some(Utc::now());
            record.last_used_at = record.started_at;
            None
        });
        self.save_execution_publication(&entry)?;
        self.spawn_probes(&entry, &live, generation, true);
        if let Some(namespace) = self.namespace_of(namespace) {
            self.refresh_dns(&namespace);
        }
        self.finish_execution_mutation(&ticket)?;
        Ok(self.view(&entry))
    }
}
