//! One reviewed public pre-main recipe. No caller-selected preparation shell or promotion.
use super::*;

const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
#[cfg(target_arch = "x86_64")]
pub(super) const ALPINE: &str = "docker.io/library/alpine@sha256:85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f";
#[cfg(target_arch = "aarch64")]
pub(super) const ALPINE: &str = "docker.io/library/alpine@sha256:24bb3511a0db7b5114a4aee033c65a8a4148f39b7b80a398e548546db967a36f";

#[cfg(target_arch = "x86_64")]
pub(super) const ALPINE_CONFIG_DIGEST: &str =
    "sha256:706db57fb2063f39f69632c5b5c9c439633fda35110e65587c5d85553fd1cc38";
#[cfg(target_arch = "aarch64")]
pub(super) const ALPINE_CONFIG_DIGEST: &str =
    "sha256:171e65262c8018f8f09a360006af2acbb2c0c494cb2be933025b466ea3d672dc";

/// Immutable provenance written before the builder's first image pull or boot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TemplateBirth {
    pub schema: u32,
    pub profile: String,
    pub namespace: String,
    pub image: String,
    pub init_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CloneOrigin {
    pub source_machine: String,
    pub snapshot: String,
    pub artifact: CloneArtifact,
    pub configure: guest::CloneConfigure,
    pub identity: Option<guest::CloneIdentity>,
    pub stage: CloneStage,
    #[serde(default)]
    pub mapping_exited: bool,
    /// Persisted before a VMM launch can begin, even before a PID is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_host_boot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<sandbox::Binding>,
}

impl Manager {
    /// Availability describes implemented, configured profiles. Hardware correctness and
    /// performance still require native evidence; no qualification checkbox bypasses checks.
    pub fn named_memory_profiles(&self) -> Vec<String> {
        let cfg = &self.inner.cfg;
        let boot = self.inner.vmm.boot_identity(false);
        let available = cfg.templates.enabled
            && cfg.templates.init_ready_init_sha256.len() == 64
            && cfg.templates.init_ready_init_sha256 == self.inner.images.init_sha256()
            && !cfg.jailer.as_os_str().is_empty()
            && cfg.kernel_args.is_empty()
            && boot
                .as_ref()
                .is_some_and(|i| i.schema == 1 && i.compatible(i))
            && self.inner.vmm.cpu_fingerprint().is_some()
            && !self.inner.images.registries.iter().any(|(host, _, _)| {
                matches!(
                    host.as_str(),
                    "docker.io" | "index.docker.io" | "registry-1.docker.io"
                )
            });
        let mut profiles = if available {
            vec![guest::INIT_READY_V1.into()]
        } else {
            vec![]
        };
        if self.sandbox_available() {
            profiles.push(guest::SANDBOX_READY_V1.into());
        }
        profiles
    }

    pub(in crate::machine) fn template_birth(
        &self,
        req: &api::CreateMachineRequest,
        role: Option<Role>,
    ) -> Result<Option<TemplateBirth>, MError> {
        let Some(profile) = &req.template_build else {
            return Ok(None);
        };
        if profile == guest::SANDBOX_READY_V1 {
            return self.sandbox_birth(req, role).map(Some);
        }
        let bound = &self.inner.cfg.templates.init_ready_init_sha256;
        if !self
            .named_memory_profiles()
            .iter()
            .any(|supported| supported == profile)
        {
            return Err(invalid(
                "reviewed init-ready recipe/init/jailer is unavailable",
            ));
        }
        if req.image != ALPINE
            || req.size.vcpus != 1
            || req.size.memory_mb != 256
            || req.size.cpu_millis.is_some()
            || role.is_some()
            || req.fork.is_some()
            || req.restore.is_some()
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
            || req.start == Some(false)
            || !matches!(req.sleep.as_str(), "" | "never")
            || req
                .egress
                .as_ref()
                .is_some_and(|e| e.mode != api::egress::NONE || e.via.is_some() || e.siblings)
            || self.inner.images.registries.iter().any(|(host, _, _)| {
                matches!(
                    host.as_str(),
                    "docker.io" | "index.docker.io" | "registry-1.docker.io"
                )
            })
        {
            return Err(invalid("template build requires the fixed public Alpine recipe without overrides, private registry credentials, or ingress"));
        }
        Ok(Some(TemplateBirth {
            schema: 1,
            profile: profile.clone(),
            namespace: req.namespace.clone(),
            image: req.image.clone(),
            init_sha256: bound.clone(),
        }))
    }

    pub(in crate::machine) fn check_template_image(&self, r: &Record) -> Result<()> {
        let Some(birth) = &r.template_birth else {
            return Ok(());
        };
        if birth.profile == guest::SANDBOX_READY_V1 {
            return self.check_sandbox_builder(r);
        }
        let cfg = &r.image_config;
        anyhow::ensure!(
            birth.schema == 1
                && birth.profile == guest::INIT_READY_V1
                && birth.namespace == r.namespace
                && birth.image == ALPINE
                && r.image == ALPINE
                && r.image_digest == ALPINE.split('@').nth(1).unwrap_or("")
                && r.image_config_digest == ALPINE_CONFIG_DIGEST
                && birth.init_sha256 == self.inner.images.init_sha256()
                && r.image_key == self.inner.images.key(&r.image_digest)
                && cfg.entrypoint.is_empty()
                && cfg.cmd == ["/bin/sh"]
                && cfg.env == BTreeMap::from([("PATH".into(), PATH.into())])
                && cfg.workdir == "/"
                && cfg.user.is_empty()
                && cfg.volumes.is_empty()
                && cfg.exposed_ports.is_empty()
                && r.size.vcpus == 1
                && r.size.memory_mb == 256
                && r.size.cpu_millis.is_none()
                && r.entrypoint.as_ref().is_some_and(|v| v.is_empty())
                && r.cmd.as_ref() == Some(&builder_config().cmd)
                && r.pending.is_none()
                && r.root_key == r.image_key
                && r.backup.policy.is_none()
                && r.egress.mode == api::egress::NONE
                && r.volume.is_none()
                && r.env.is_empty()
                && r.files.is_empty()
                && r.ports.is_empty(),
            "reviewed template image/config/provenance mismatch"
        );
        Ok(())
    }

    pub(in crate::machine) fn ordinary_operation(&self, r: &Record) -> Result<(), MError> {
        if r.template_birth.is_some() {
            return Err(MError::Conflict(
                "sealed template builder permits status, memory seal and destroy only".into(),
            ));
        }
        if r.clone_origin
            .as_ref()
            .is_some_and(|o| o.stage != CloneStage::Active)
        {
            return Err(MError::Conflict(
                "memory clone has not crossed its activation barrier".into(),
            ));
        }
        Ok(())
    }
}

pub(in crate::machine) fn builder_config() -> guest::Config {
    guest::Config {
        template_profile: Some(guest::INIT_READY_V1.into()),
        cmd: vec!["/bin/sleep".into(), "2147483647".into()],
        env: BTreeMap::from([("PATH".into(), PATH.into())]),
        workdir: "/".into(),
        stop_timeout_sec: 10,
        ..Default::default()
    }
}
