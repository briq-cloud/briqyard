//! Distinct internal pristine factory; public named clones retain their sealed recipe rules.
use super::*;

impl Manager {
    pub(in crate::machine) fn unbound_warm_available(&self) -> bool {
        self.inner.cfg.templates.unbound_warm_pools
            && self.inner.cfg.templates.warm_pools
            && self.sandbox_available()
            && self.inner.vmm.paused_slots_supported()
            && self
                .inner
                .vmm
                .host_boot_id()
                .is_some_and(|id| fc::valid_host_boot_id(&id))
    }

    pub(super) async fn record_unbound_warm_slot(
        &self,
        pool: &Pool,
        name: String,
        slot: Slot,
    ) -> Result<(Arc<Entry>, Make), MError> {
        if !self.unbound_warm_available() {
            return Err(invalid("unbound warm pools disabled"));
        }
        let recipe = self.sandbox_recipe(
            &pool.artifact.recipe.image,
            pool.artifact.recipe.size,
            pool.artifact
                .recipe
                .config
                .sandbox_device
                .as_ref()
                .map(|d| d.gb()),
        )?;
        let request = api::CreateMachineRequest {
            namespace: pool.namespace.clone(),
            name,
            image: recipe.image.clone(),
            size: recipe.size,
            volume: recipe.volume().map(|size_gb| api::VolumeSpec {
                size_gb,
                mount: "/work".into(),
            }),
            sleep: "never".into(),
            fork: Some(api::ForkSpec {
                machine_id: pool.source_machine.clone(),
                snapshot: Some(pool.snapshot.clone()),
                copy: "disk".into(),
            }),
            ..Default::default()
        };
        let _namespace = self.inner.namespace_lifecycle.read().await;
        self.record_with_warm_slot(request, None, Some(slot), true)
            .await
    }

    pub(in crate::machine) fn unbound_warm_clone_spec(
        &self,
        request: &api::CreateMachineRequest,
        record: &mut Record,
        source: &Record,
        fork: &api::ForkSpec,
    ) -> Result<(), MError> {
        if !self.unbound_warm_available()
            || request.namespace != source.namespace
            || request.sandbox_seed.is_some()
            || request.template_build.is_some()
            || !request.env.is_empty()
            || !request.files.is_empty()
            || !request.ports.is_empty()
            || request.entrypoint.is_some()
            || request.cmd.is_some()
            || request.probes.is_some()
            || request.egress.is_some()
            || request.restart.is_some()
            || request.backup.is_some()
            || request.limits.is_some()
            || request.disk_limits.is_some()
        {
            return Err(invalid(
                "unbound factory requires an empty operator-owned pristine recipe",
            ));
        }
        let snapshot = source
            .snapshots
            .iter()
            .find(|s| Some(&s.id) == fork.snapshot.as_ref())
            .ok_or_else(|| invalid("unbound factory snapshot missing"))?;
        let artifact = snapshot
            .clone_artifact
            .as_ref()
            .ok_or_else(|| invalid("unbound factory artifact missing"))?;
        // Reuse full artifact/recipe/device validation and metadata construction, but never
        // persist or send the synthetic preview's destination binding.
        let mut preview = request.clone();
        preview.fork = None;
        preview.start = Some(true);
        preview.sandbox_seed = Some(api::SandboxSeed {
            machine_id: source.id.clone(),
            snapshot: snapshot.id.clone(),
            generation: artifact.generation.clone(),
            request_id: "unbound-factory-preview".into(),
        });
        self.sandbox_clone_spec(&preview, record, source)?;
        record.clone_origin.as_mut().unwrap().sandbox = None;
        record.egress = api::Egress {
            mode: api::egress::NONE.into(),
            ..Default::default()
        };
        Ok(())
    }
}
