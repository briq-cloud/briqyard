use super::*;

impl Manager {
    pub(in crate::machine) fn named_clone_spec(
        &self,
        req: &api::CreateMachineRequest,
        rec: &mut Record,
        source: &Record,
        fork: &api::ForkSpec,
    ) -> Result<(), MError> {
        let selector = fork
            .snapshot
            .as_deref()
            .ok_or_else(|| invalid("named memory snapshot is required"))?;
        if source.namespace != req.namespace {
            return Err(invalid("memory clone requires the same namespace owner"));
        }
        let snapshot = source
            .snapshots
            .iter()
            .find(|s| s.id == selector || s.name.as_deref() == Some(selector))
            .ok_or_else(|| MError::NoSnapshot(selector.into()))?;
        let artifact = snapshot
            .clone_artifact
            .as_ref()
            .ok_or_else(|| invalid("snapshot is not a sealed memory template"))?;
        if !req.image.is_empty()
            || req.entrypoint.is_some()
            || req.cmd.is_some()
            || !req.env.is_empty()
            || !req.files.is_empty()
            || req.volume.is_some()
            || !req.ports.is_empty()
            || req.probes.is_some()
            || req.limits.is_some()
            || req.disk_limits.is_some()
            || req.restart.is_some()
            || req.backup.is_some()
            || req.egress.is_some()
            || req.start == Some(false)
            || req.template_build.is_some()
            || !matches!(req.sleep.as_str(), "" | "never")
            || !matches!(fork.copy.as_str(), "" | "disk")
            || (req.size != api::Size::default() && req.size != artifact.recipe.size)
        {
            return Err(invalid(
                "named memory clone keeps the sealed recipe: overrides/config copy are unsupported",
            ));
        }
        let cfg = &artifact.recipe.config;
        rec.image = artifact.recipe.image.clone();
        rec.image_key = artifact.recipe.image_key.clone();
        rec.root_key = artifact.recipe.image_key.clone();
        rec.image_digest = artifact.recipe.image_digest.clone();
        rec.image_config_digest = artifact.recipe.image_config_digest.clone();
        rec.image_config = ImageConfig {
            entrypoint: cfg.entrypoint.clone(),
            cmd: cfg.cmd.clone(),
            env: cfg.env.clone(),
            workdir: cfg.workdir.clone(),
            user: cfg.user.clone(),
            ..Default::default()
        };
        rec.size = artifact.recipe.size;
        rec.volume = None;
        rec.sleep = "never".into();
        rec.restart = api::RestartPolicy::default();
        rec.backup = Schedule::default();
        rec.egress = api::Egress {
            mode: api::egress::NONE.into(),
            ..Default::default()
        };
        rec.boot_identity = Some(artifact.boot_identity.clone());
        rec.vmm_version = snapshot.vmm_version.clone();
        let mut entropy = [0; 32];
        use rand::RngCore;
        rand::rngs::OsRng
            .try_fill_bytes(&mut entropy)
            .map_err(|e| anyhow!("clone host entropy: {e}"))?;
        rec.clone_origin = Some(CloneOrigin {
            source_machine: source.id.clone(),
            snapshot: snapshot.id.clone(),
            artifact: artifact.clone(),
            configure: guest::CloneConfigure {
                generation: format!("clone-{}", rec.id.replace('_', "-")),
                hostname: req.name.clone(),
                ip: String::new(),
                gateway: String::new(),
                dns: vec![],
                mac: [0; 6],
                entropy,
                realtime_sec: Utc::now()
                    .timestamp()
                    .try_into()
                    .map_err(|_| invalid("host clock predates epoch"))?,
            },
            identity: None,
            stage: CloneStage::Reserved,
            mapping_exited: false,
        });
        Ok(())
    }
}

pub(in crate::machine) fn clone_mac(ip: &str) -> Result<[u8; 6], MError> {
    let ip: Ipv4Addr = ip.parse().map_err(|_| invalid("invalid clone address"))?;
    let [a, b, c, d] = ip.octets();
    Ok([6, 0xb1, a, b, c, d])
}
