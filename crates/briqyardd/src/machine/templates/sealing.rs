use super::*;

impl Manager {
    /// Caller holds the builder's lifecycle lock throughout Full snapshot and publication.
    pub(in crate::machine) async fn check_template_seal(
        &self,
        e: &Entry,
        memory: bool,
        seal: bool,
    ) -> Result<Option<String>, MError> {
        let r = e.snapshot();
        if !seal && r.template_birth.is_none() {
            return Ok(None);
        }
        if !seal || !memory || r.template_birth.is_none() || r.clone_origin.is_some() {
            return Err(invalid(
                "template seal requires a reviewed builder and a full memory snapshot",
            ));
        }
        self.check_template_image(&r)?;
        let identity = self
            .memory_identity(e, &r)
            .ok_or_else(|| invalid("template requires strong boot provenance"))?;
        if identity.schema != 1 || !e.identity_trusted.load(Relaxed) || r.boot_incarnation.is_none()
        {
            return Err(invalid("template boot provenance is unconfirmed"));
        }
        let live = e
            .live
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| MError::NotRunning(r.state.clone()))?;
        if live.incarnation != r.boot_incarnation {
            return Err(invalid("template VMM incarnation changed"));
        }
        let report = self.inner.guest.ping(&live.vsock).await?;
        if report.init_sha256 != self.inner.images.init_sha256() {
            return Err(invalid(
                "actual guest init executable differs from reviewed recipe",
            ));
        }
        let status = report
            .clone_status
            .ok_or_else(|| invalid("template init lacks clone barrier protocol"))?;
        if report.main_pid != 0
            || status.protocol != 1
            || status.profile != guest::INIT_READY_V1
            || status.stage != "builder"
        {
            return Err(invalid(
                "template init is not parked before its first workload exec",
            ));
        }
        if status.ram_marker.len() != 32 {
            return Err(invalid("template init RAM marker unavailable"));
        }
        Ok(Some(status.ram_marker))
    }

    pub(in crate::machine) fn seal_named_artifact(
        &self,
        e: &Entry,
        snapshot: &mut SnapshotRec,
        ram_marker: String,
    ) -> Result<()> {
        let r = e.snapshot();
        let birth = r
            .template_birth
            .as_ref()
            .ok_or_else(|| invalid("ordinary machines cannot be promoted to templates"))?;
        let generation = new_id("g");
        let from = self.memory_files(&r, &snapshot.id);
        let files = self.artifact_files(&r.id, &snapshot.id, &generation)?;
        let base = self.inner.cfg.jail_base().join("memory-artifacts");
        for dir in [
            base.clone(),
            base.join(&r.id),
            base.join(&r.id).join(&snapshot.id),
        ] {
            crate::store::private_dir(&dir)?;
            std::fs::File::open(
                dir.parent()
                    .ok_or_else(|| anyhow!("artifact directory has no parent"))?,
            )?
            .sync_all()?;
        }
        for (old, new) in from.iter().zip(&files) {
            anyhow::ensure!(!new.exists(), "immutable artifact file already exists");
            // Same-pool rename only. A cross-device error is a failure, never a copy.
            std::fs::rename(old, new).context("publish fresh private memory artifact")?;
            std::os::unix::fs::chown(
                new,
                Some(unsafe { libc::geteuid() }),
                Some(unsafe { libc::getegid() }),
            )?;
            std::fs::set_permissions(new, std::fs::Permissions::from_mode(0o444))?;
            std::fs::File::open(new)?.sync_all()?;
        }
        std::fs::File::open(files[0].parent().unwrap())?.sync_all()?;
        let identity = snapshot
            .boot_identity
            .clone()
            .filter(|i| i.schema == 1)
            .ok_or_else(|| invalid("template snapshot lacks strong boot identity"))?;
        snapshot.clone_artifact = Some(CloneArtifact {
            schema: 1,
            generation: generation.clone(),
            profile: birth.profile.clone(),
            ram_marker,
            namespace: birth.namespace.clone(),
            source_host: self.inner.host_id.clone(),
            init_sha256: birth.init_sha256.clone(),
            init_protocol: 1,
            cpu_fingerprint: self
                .inner
                .vmm
                .cpu_fingerprint()
                .ok_or_else(|| invalid("CPU fingerprint unavailable"))?,
            boot_identity: identity,
            recipe: CloneRecipe {
                image: r.image.clone(),
                image_digest: r.image_digest.clone(),
                image_key: r.image_key.clone(),
                size: r.size,
                root_disk_gb: self.inner.cfg.root_disk_gb,
                config: builder_config(),
            },
            state: fingerprint(&files[0])?,
            memory: fingerprint(&files[1])?,
        });
        // The existing source record is the manifest. Publish it only after durable bytes.
        {
            let mut r = e.rec.lock().unwrap();
            let saved = r
                .snapshots
                .iter_mut()
                .find(|s| s.id == snapshot.id)
                .ok_or_else(|| invalid("snapshot disappeared before publication"))?;
            *saved = snapshot.clone();
        }
        self.save(e)?;
        std::fs::File::open(self.inner.store.dir("machines"))?.sync_all()?;
        self.inner.verified_templates.lock().unwrap().insert((
            r.id,
            snapshot.id.clone(),
            generation,
        ));
        Ok(())
    }
}
