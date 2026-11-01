use super::*;
impl Manager {
    pub(in crate::machine) async fn configure_sandbox_destination(
        &self,
        e: &Entry,
        live: &fc::Vm,
        mut origin: CloneOrigin,
    ) -> Result<()> {
        if origin.stage == CloneStage::Loading {
            origin.configure.realtime_sec = Utc::now()
                .timestamp()
                .try_into()
                .context("host clock predates epoch")?;
            let r = e.snapshot();
            let (mut config, files) = crate::machine::start::resolved_guest_config(
                &r,
                origin.configure.gateway.parse()?,
            )?;
            let binding = origin.sandbox.as_mut().context("sandbox binding missing")?;
            config.files.clear();
            config.sandbox_device = Some(binding.device.clone());
            let bind = guest::DestinationBind {
                identity: origin.configure.clone(),
                config,
                receipt: binding.receipt.clone(),
                files: files
                    .into_iter()
                    .map(|(path, mode, data)| guest::DestinationFile { path, mode, data })
                    .collect(),
            };
            bind.validate().map_err(|e| anyhow!(e))?;
            binding.bind = Some(bind);
            e.rec.lock().unwrap().clone_origin = Some(origin.clone());
            // clone_stage fsyncs record and reader before the first bind can be sent.
            self.clone_stage(e, CloneStage::Configuring)?;
        }
        let bind = origin
            .sandbox
            .as_ref()
            .and_then(|b| b.bind.clone())
            .context("frozen sandbox destination missing")?;
        let response = self
            .inner
            .guest
            .destination_control(
                &live.vsock,
                guest::Request {
                    op: "destination_bind_v1".into(),
                    destination_bind: Some(bind),
                    ..Default::default()
                },
            )
            .await?;
        check_ack(&origin, &response, &["destination_done"])?;
        let acknowledged = response
            .clone_status
            .as_ref()
            .and_then(|s| s.identity.clone())
            .context("sandbox ACK identity missing")?;
        if let Some(old) = &origin.identity {
            anyhow::ensure!(old == &acknowledged, "sandbox identity changed on replay");
        }
        {
            let mut record = e.rec.lock().unwrap();
            let saved = record.clone_origin.as_mut().unwrap();
            saved.identity = Some(acknowledged);
            saved.sandbox.as_mut().unwrap().ack_sha256 = Some(response.sha256);
        }
        self.clone_stage(e, CloneStage::IdentityDone)?;
        Ok(())
    }
}
pub(in crate::machine) fn binding_hash(bind: &guest::DestinationBind) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(bind.fingerprint_bytes()?);
    Ok(hex::encode(hash.finalize()))
}
pub(in crate::machine) fn check_ack(
    origin: &CloneOrigin,
    response: &guest::Response,
    stages: &[&str],
) -> Result<()> {
    let binding = origin.sandbox.as_ref().context("sandbox binding missing")?;
    let bind = binding.bind.as_ref().context("sandbox payload missing")?;
    let expected = binding_hash(bind)?;
    let status = response
        .clone_status
        .as_ref()
        .context("sandbox ACK status missing")?;
    let identity = status
        .identity
        .as_ref()
        .context("sandbox ACK identity missing")?;
    let c = &origin.configure;
    anyhow::ensure!(
        matches!(response.kind.as_str(), "ok" | "pong")
            && response.sha256 == expected
            && binding.ack_sha256.as_ref().is_none_or(|a| a == &expected)
            && status.protocol == 1
            && status.profile == guest::SANDBOX_READY_V1
            && stages.contains(&status.stage.as_str())
            && status.ram_marker == origin.artifact.ram_marker
            && identity.generation == c.generation
            && identity.hostname == c.hostname
            && identity.ip == c.ip
            && identity.mac == c.mac
            && identity.machine_id.len() == 32
            && identity.machine_id.bytes().all(|b| b.is_ascii_hexdigit())
            && origin.identity.as_ref().is_none_or(|old| old == identity),
        "sandbox destination acknowledgment mismatch"
    );
    Ok(())
}
