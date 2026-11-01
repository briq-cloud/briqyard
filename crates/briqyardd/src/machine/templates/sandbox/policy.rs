use super::*;
impl Manager {
    pub(in crate::machine) fn sandbox_available(&self) -> bool {
        let cfg = &self.inner.cfg;
        cfg.templates.enabled
            && !cfg.token.is_empty()
            && !cfg.templates.sandbox_recipes.is_empty()
            && !cfg.jailer.as_os_str().is_empty()
            && cfg.kernel_args.is_empty()
            && self.inner.vmm.cpu_fingerprint().is_some()
            && self
                .inner
                .vmm
                .boot_identity(false)
                .is_some_and(|i| i.schema == 1 && i.compatible(&i))
            && cfg
                .templates
                .sandbox_recipes
                .iter()
                .any(|r| r.init_sha256 == self.inner.images.init_sha256())
    }
    pub(in crate::machine) fn sandbox_recipe(
        &self,
        image: &str,
        size: api::Size,
    ) -> Result<&crate::config::SandboxRecipe, MError> {
        if !self.sandbox_available() {
            return Err(invalid("operator sandbox seed profile unavailable"));
        }
        self.inner
            .cfg
            .templates
            .sandbox_recipes
            .iter()
            .find(|r| {
                r.image == image
                    && r.size.matches_sandbox_resources(&size)
                    && r.init_sha256 == self.inner.images.init_sha256()
            })
            .ok_or_else(|| invalid("sandbox image/size/init is not operator approved"))
    }
    pub(in crate::machine) fn sandbox_birth(
        &self,
        req: &api::CreateMachineRequest,
        role: Option<Role>,
    ) -> Result<TemplateBirth, MError> {
        let recipe = self.sandbox_recipe(&req.image, req.size)?;
        if role.is_some()
            || req.fork.is_some()
            || req.restore.is_some()
            || req.sandbox_seed.is_some()
            || req.volume.is_some()
            || req.entrypoint.is_some()
            || req.cmd.is_some()
            || !req.env.is_empty()
            || !req.files.is_empty()
            || !req.ports.is_empty()
            || req.limits.is_some()
            || req.disk_limits.is_some()
            || req.restart.is_some()
            || req.probes.is_some()
            || req.backup.is_some()
            || req.start != Some(true)
            || !req.metadata.is_empty()
            || !matches!(req.sleep.as_str(), "" | "never")
            || req
                .egress
                .as_ref()
                .is_some_and(|e| e.mode != api::egress::NONE || e.via.is_some() || e.siblings)
        {
            return Err(invalid("sandbox builder permits only the operator recipe without caller preparation or data"));
        }
        Ok(TemplateBirth {
            schema: 1,
            profile: guest::SANDBOX_READY_V1.into(),
            namespace: req.namespace.clone(),
            image: req.image.clone(),
            init_sha256: recipe.init_sha256.clone(),
        })
    }
    pub(in crate::machine) fn check_sandbox_builder(&self, r: &Record) -> Result<()> {
        let recipe = self.sandbox_recipe(&r.image, r.size)?;
        let birth = r.template_birth.as_ref().context("sandbox birth missing")?;
        anyhow::ensure!(
            r.clone_origin.is_none()
                && r.warm_slot.is_none()
                && r.role.is_none()
                && birth.schema == 1
                && birth.profile == guest::SANDBOX_READY_V1
                && birth.namespace == r.namespace
                && birth.image == recipe.image
                && birth.init_sha256 == recipe.init_sha256
                && r.image_digest == recipe.image.split('@').nth(1).unwrap_or("")
                && r.image_config_digest == recipe.image_config_digest
                && r.image_key == self.inner.images.key(&r.image_digest)
                && r.root_key == r.image_key
                && r.image_config.volumes.is_empty()
                && r.pending.is_none()
                && r.backup.policy.is_none()
                && r.egress.mode == api::egress::NONE
                && !r.egress.siblings
                && r.egress.via.is_none()
                && r.entrypoint.as_ref().is_some_and(Vec::is_empty)
                && r.cmd.as_ref().is_some_and(Vec::is_empty)
                && r.env.is_empty()
                && r.files.is_empty()
                && r.ports.is_empty()
                && r.metadata.is_empty()
                && r.volume
                    .as_ref()
                    .is_some_and(|v| v.mount == "/work" && v.size_gb == recipe.volume_gb),
            "sandbox builder provenance/configuration mismatch"
        );
        Ok(())
    }
    pub(in crate::machine) fn check_sandbox_artifact(
        &self,
        r: &Record,
        a: &CloneArtifact,
    ) -> Result<()> {
        self.check_sandbox_builder(r)?;
        let recipe = self.sandbox_recipe(&a.recipe.image, a.recipe.size)?;
        anyhow::ensure!(
            a.profile == guest::SANDBOX_READY_V1
                && a.recipe.image == r.image
                && a.recipe.size.matches_sandbox_resources(&r.size)
                && a.recipe.image_digest == r.image_digest
                && a.recipe.image_config_digest == recipe.image_config_digest
                && a.recipe.image_key == r.image_key
                && a.namespace == r.namespace
                && a.init_sha256 == recipe.init_sha256
                && a.recipe.config.sandbox_device.as_ref() == Some(&recipe.device())
                && crate::machine::templates::sandbox::pristine_config(&a.recipe.config),
            "sandbox artifact recipe/device differs from operator provenance"
        );
        Ok(())
    }
}
pub(in crate::machine) fn pristine_config(c: &guest::Config) -> bool {
    c.template_profile.as_deref() == Some(guest::SANDBOX_READY_V1)
        && c.hostname.is_empty()
        && c.ip.is_empty()
        && c.gateway.is_empty()
        && c.dns.is_empty()
        && c.hosts.is_empty()
        && c.entrypoint.is_empty()
        && c.cmd.is_empty()
        && c.env.is_empty()
        && c.mounts.is_empty()
        && c.files.is_empty()
        && c.user.is_empty()
        && c.workdir.is_empty()
}
