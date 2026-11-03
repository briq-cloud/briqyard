//! Internal preparation only. Public profile selection and activation stay disabled.
use super::*;

impl Manager {
    pub(super) async fn prepare_unbound_warm_slot(
        &self,
        entry: &Entry,
        live: &fc::Vm,
    ) -> Result<String> {
        let record = entry.snapshot();
        let origin = record
            .clone_origin
            .as_ref()
            .context("unbound clone origin missing")?;
        anyhow::ensure!(
            live.resumed
                && record.launch_identity.is_some()
                && origin.stage == templates::CloneStage::Loading
                && origin.artifact.profile == guest::SANDBOX_READY_V1
                && origin.sandbox.is_none()
                && origin.identity.is_none()
                && record
                    .warm_slot
                    .as_ref()
                    .is_some_and(|slot| slot.claimed.is_none())
                && record.env.is_empty()
                && record.files.is_empty()
                && record.ports.is_empty()
                && record.entrypoint.as_ref().is_none_or(Vec::is_empty)
                && record.cmd.as_ref().is_none_or(Vec::is_empty),
            "unbound preparation requires an unassigned slot without destination workload"
        );
        let device = origin
            .artifact
            .recipe
            .config
            .sandbox_device
            .as_ref()
            .context("unbound artifact omitted sealed work-device geometry")?;
        anyhow::ensure!(
            device.drive_id == "data"
                && device.logical_sector_bytes == 512
                && record
                    .volume
                    .as_ref()
                    .is_some_and(|volume| volume.mount == "/work"
                        && u64::from(volume.size_gb).checked_mul(1 << 30) == Some(device.bytes)),
            "unbound work volume differs from the sealed device"
        );
        self.verify_live_launch(entry, live)?;
        self.inner
            .vmm
            .resume(live)
            .await
            .context("resume unbound builder barrier")?;
        let version = self
            .template_builder_ready(
                live,
                Some(&origin.artifact.ram_marker),
                guest::SANDBOX_READY_V1,
            )
            .await?;
        // No configure, destination-bind, main, exec, probes or network publication.
        self.inner
            .vmm
            .pause(live)
            .await
            .context("park unbound slot")?;
        self.clone_stage(entry, templates::CloneStage::UnboundPaused)?;
        Ok(version)
    }
}
