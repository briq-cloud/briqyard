use super::*;

impl Manager {
    /// Caller holds the builder's lifecycle lock throughout Full snapshot and publication.
    pub(in crate::machine) async fn check_template_seal(
        &self,
        e: &Arc<Entry>,
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
        let profile = &r.template_birth.as_ref().unwrap().profile;
        if !self.named_memory_profiles().iter().any(|p| p == profile) {
            return Err(invalid(
                "reviewed named memory profile is disabled or unavailable",
            ));
        }
        self.check_template_image(&r)?;
        let identity = self
            .memory_identity(e, &r)
            .ok_or_else(|| invalid("template requires strong boot provenance"))?;
        if identity.schema != fc::BootIdentity::SCHEMA
            || !e.identity_trusted.load(Relaxed)
            || r.boot_incarnation.is_none()
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
        if r.template_birth.as_ref().is_some_and(|b| b.is_service()) {
            return self.park_service(e, &r, &live, report).await.map(Some);
        }
        let status = report
            .clone_status
            .ok_or_else(|| invalid("template init lacks clone barrier protocol"))?;
        if report.main_pid != 0
            || status.protocol != 1
            || &status.profile != profile
            || status.stage != "builder"
        {
            return Err(invalid(
                "template init is not parked before its first workload exec",
            ));
        }
        if status.ram_marker.len() != 32 {
            return Err(invalid("template init RAM marker unavailable"));
        }
        // A seal is reused for a whole generation: no crash-consistent fallback.
        tokio::time::timeout(
            crate::guestc::CONTROL_TIMEOUT,
            self.inner.guest.fs_sync(&live.vsock),
        )
        .await
        .context("template seal fs_sync timeout")?
        .context("template seal fs_sync")?;
        Ok(Some(status.ram_marker))
    }

    /// Parks a running service for its seal: the hook, the socket check and the freeze all run
    /// in the guest. A refusal there restored the service, which keeps running. Anything
    /// after a park leaves the source parked, so it is stopped: a parked source never
    /// serves again.
    async fn park_service(
        &self,
        e: &Arc<Entry>,
        r: &Record,
        live: &fc::Vm,
        report: guest::Response,
    ) -> Result<String, MError> {
        let hooks = r
            .template_birth
            .as_ref()
            .and_then(|b| b.hooks.clone())
            .ok_or_else(|| invalid("service template lacks its hooks"))?;
        let status = report
            .clone_status
            .ok_or_else(|| invalid("service init lacks clone barrier protocol"))?;
        if report.main_pid == 0
            || status.protocol != 1
            || status.profile != guest::SERVICE_READY_V1
            || status.stage != "running"
        {
            return Err(invalid("service is not running unparked"));
        }
        let limit = Duration::from_secs(u64::from(hooks.park_timeout_s) + 15);
        let request = guest::Request {
            op: guest::SERVICE_PARK_OP.into(),
            ..Default::default()
        };
        let answer = self
            .inner
            .guest
            .control_within(&live.vsock, request, limit)
            .await;
        let parked = match answer {
            Ok(a) if a.kind == "error" => {
                return Err(MError::Conflict(format!(
                    "service park refused ({}): {}",
                    if a.error_code.is_empty() {
                        "error"
                    } else {
                        &a.error_code
                    },
                    a.message
                )));
            }
            Ok(a) => a
                .clone_status
                .filter(|s| s.stage == "parked" && s.ram_marker.len() == 32),
            Err(_) => None,
        };
        let Some(parked) = parked else {
            // The guest's state is unknown: it may be parked.
            self.stop_parked(e).await;
            return Err(invalid("service park was not acknowledged"));
        };
        let synced = tokio::time::timeout(
            crate::guestc::CONTROL_TIMEOUT,
            self.inner.guest.fs_sync(&live.vsock),
        )
        .await;
        if !matches!(synced, Ok(Ok(()))) {
            self.stop_parked(e).await;
            return Err(invalid("service seal fs_sync failed"));
        }
        Ok(parked.ram_marker)
    }

    /// Ends a parked source under its held lifecycle lock.
    pub(in crate::machine) async fn stop_parked(&self, e: &Arc<Entry>) {
        if let Err(err) = self.stop_locked(e, "service template sealed".into()).await {
            tracing::warn!(machine = %e.snapshot().id, "stopping parked service source: {err:#}");
        }
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
            .filter(|i| i.schema == fc::BootIdentity::SCHEMA)
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
                image_config_digest: r.image_config_digest.clone(),
                image_key: r.image_key.clone(),
                size: r.size,
                root_disk_gb: self.inner.cfg.root_disk_gb,
                config: if birth.is_service() {
                    let (mut cfg, _) =
                        crate::machine::start::resolved_guest_config(&r, Ipv4Addr::UNSPECIFIED)?;
                    // Identity is the clone's own: it comes with the configure step.
                    cfg.hostname.clear();
                    cfg.ip.clear();
                    cfg.gateway.clear();
                    cfg.dns.clear();
                    cfg.hosts.clear();
                    cfg.files.clear();
                    cfg.template_profile = Some(birth.profile.clone());
                    cfg.clone_hooks = birth.hooks.clone();
                    cfg
                } else if birth.profile == guest::SANDBOX_READY_V1 {
                    sandbox::builder_config(
                        self.sandbox_recipe(
                            &r.image,
                            r.size,
                            r.volume.as_ref().map(|v| v.size_gb),
                        )?
                        .device(),
                    )
                } else {
                    builder_config()
                },
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
