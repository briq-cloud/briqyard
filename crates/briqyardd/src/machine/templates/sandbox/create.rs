use super::*;
impl Manager {
    pub(in crate::machine) fn sandbox_clone_spec(
        &self,
        req: &api::CreateMachineRequest,
        rec: &mut Record,
        source: &Record,
    ) -> Result<api::ForkSpec, MError> {
        req.check_sandbox_seed().map_err(invalid)?;
        let seed = req
            .sandbox_seed
            .as_ref()
            .ok_or_else(|| invalid("sandbox selector missing"))?;
        let recipe = self.sandbox_recipe(&req.image, req.size)?;
        if req
            .volume
            .as_ref()
            .is_none_or(|v| v.size_gb != recipe.volume_gb || v.mount != "/work")
        {
            return Err(invalid(
                "sandbox destination volume must match the sealed device capacity",
            ));
        }
        let snapshot = source
            .snapshots
            .iter()
            .find(|s| s.id == seed.snapshot)
            .ok_or_else(|| MError::NoSnapshot(seed.snapshot.clone()))?;
        let (artifact, _) = self.checked_clone_artifact(source, snapshot, &req.namespace)?;
        self.check_sandbox_artifact(source, &artifact)?;
        if artifact.generation != seed.generation
            || artifact.recipe.size != req.size
            || artifact.recipe.image != req.image
        {
            return Err(invalid("sandbox seed generation/image/size mismatch"));
        }
        let fork = api::ForkSpec {
            machine_id: source.id.clone(),
            copy: "disk".into(),
            snapshot: Some(snapshot.id.clone()),
        };
        rec.image = artifact.recipe.image.clone();
        rec.image_key = artifact.recipe.image_key.clone();
        rec.root_key = rec.image_key.clone();
        rec.image_digest = artifact.recipe.image_digest.clone();
        rec.image_config_digest = artifact.recipe.image_config_digest.clone();
        rec.image_config = source.image_config.clone();
        rec.boot_identity = Some(artifact.boot_identity.clone());
        rec.vmm_version = snapshot.vmm_version.clone();
        let mut entropy = [0; 32];
        use rand::RngCore;
        rand::rngs::OsRng
            .try_fill_bytes(&mut entropy)
            .map_err(|_| anyhow!("sandbox entropy unavailable"))?;
        let digest = request_digest(req)?;
        let receipt = hex::encode(Sha256::digest(
            serde_json::to_vec(&json!({
                "protocol": 1, "machine": rec.id, "namespace": rec.namespace, "spec_sha256": digest,
                "source": source.id, "snapshot": snapshot.id, "generation": artifact.generation,
                "image": rec.image, "size": rec.size, "volume": rec.volume, "backup": rec.backup,
                "metadata": rec.metadata, "probes": rec.probes, "egress": rec.egress,
            }))
            .context("serialize sandbox assignment")?,
        ));
        // Validate the complete resolved guest shape before any destination admission,
        // disk allocation or reader consumption. Synthetic network values carry no authority.
        let mut preview = rec.clone();
        preview.ip = "10.64.0.2".into();
        let (mut config, files) =
            crate::machine::start::resolved_guest_config(&preview, Ipv4Addr::new(10, 64, 0, 1))?;
        config.files.clear();
        config.sandbox_device = Some(recipe.device());
        let preview_bind = guest::DestinationBind {
            config,
            files: files
                .into_iter()
                .map(|(path, mode, data)| guest::DestinationFile { path, mode, data })
                .collect(),
            identity: guest::CloneConfigure {
                generation: "preview".into(),
                hostname: req.name.clone(),
                ip: "10.64.0.2/24".into(),
                gateway: "10.64.0.1".into(),
                dns: vec!["10.64.0.1".into()],
                mac: [2, 0, 0, 0, 0, 1],
                entropy,
                realtime_sec: 1_793_404_800,
            },
            receipt: "a".repeat(64),
        };
        preview_bind.validate().map_err(invalid)?;
        guest::encode_frame(&guest::Request {
            op: "destination_bind_v1".into(),
            destination_bind: Some(preview_bind),
            ..Default::default()
        })
        .context("sandbox destination exceeds the guest frame contract")?;
        rec.clone_origin = Some(CloneOrigin {
            source_machine: source.id.clone(),
            snapshot: snapshot.id.clone(),
            artifact,
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
                    .context("host clock predates epoch")?,
            },
            identity: None,
            stage: CloneStage::Reserved,
            mapping_exited: false,
            launch_host_boot_id: None,
            sandbox: Some(Binding {
                request_id: seed.request_id.clone(),
                create_sha256: digest,
                receipt,
                device: recipe.device(),
                bind: None,
                ack_sha256: None,
            }),
        });
        Ok(fork)
    }
}
