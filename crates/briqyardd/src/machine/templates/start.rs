use super::*;

impl Manager {
    pub(in crate::machine) fn initial_memory_clone(&self, r: &Record) -> bool {
        r.clone_origin
            .as_ref()
            .is_some_and(|o| o.stage != CloneStage::Active)
    }

    pub(in crate::machine) fn clone_backing(&self, r: &Record) -> Result<Option<fc::MemoryClone>> {
        let Some(o) = r
            .clone_origin
            .as_ref()
            .filter(|o| o.stage != CloneStage::Active)
        else {
            return Ok(None);
        };
        let files = self.artifact_files(&o.source_machine, &o.snapshot, &o.artifact.generation)?;
        check_inode(&files[0], &o.artifact.state)?;
        check_inode(&files[1], &o.artifact.memory)?;
        Ok(Some(fc::MemoryClone {
            state: files[0].clone(),
            memory: files[1].clone(),
        }))
    }

    pub(in crate::machine) fn clone_stage(&self, e: &Entry, next: CloneStage) -> Result<()> {
        let mut reader: CloneReader = self
            .inner
            .store
            .get(READERS, &e.snapshot().id)?
            .ok_or_else(|| anyhow!("clone memory reader is missing"))?;
        {
            let mut r = e.rec.lock().unwrap();
            let origin = r
                .clone_origin
                .as_mut()
                .ok_or_else(|| anyhow!("clone origin is missing"))?;
            anyhow::ensure!(
                reader.generation == origin.artifact.generation
                    && reader.snapshot == origin.snapshot,
                "clone reader generation differs from origin"
            );
            let allowed = origin.stage == next
                || matches!(
                    (&origin.stage, &next),
                    (CloneStage::Reserved, CloneStage::Loading)
                        | (CloneStage::Loading, CloneStage::Configuring)
                        | (CloneStage::Configuring, CloneStage::IdentityDone)
                        | (CloneStage::IdentityDone, CloneStage::Active)
                        | (CloneStage::IdentityDone, CloneStage::Paused)
                        | (CloneStage::Paused, CloneStage::Active)
                );
            anyhow::ensure!(allowed, "invalid clone stage transition");
            if next == CloneStage::Loading && origin.stage == CloneStage::Reserved {
                let boot = self
                    .inner
                    .vmm
                    .host_boot_id()
                    .filter(|id| fc::valid_host_boot_id(id))
                    .ok_or_else(|| {
                        anyhow!("host boot identity is unavailable; clone launch refused")
                    })?;
                origin.launch_host_boot_id = Some(boot);
            }
            origin.stage = next.clone();
        }
        self.save(e)?;
        std::fs::File::open(self.inner.store.dir("machines"))?.sync_all()?;
        reader.stage = next;
        self.inner
            .store
            .put_durable(READERS, &reader.destination, &reader)
    }

    pub(in crate::machine) async fn template_builder_ready(
        &self,
        live: &fc::Vm,
        expected_marker: Option<&str>,
    ) -> Result<String> {
        let timeout = Duration::from_secs(self.inner.cfg.boot_timeout_sec.max(10));
        self.inner.guest.wait_ready(&live.vsock, timeout).await?;
        let pong = self.inner.guest.ping(&live.vsock).await?;
        anyhow::ensure!(
            pong.init_sha256 == self.inner.images.init_sha256(),
            "actual guest init executable differs from reviewed recipe"
        );
        let status = pong
            .clone_status
            .ok_or_else(|| anyhow!("template init omitted clone protocol"))?;
        anyhow::ensure!(
            pong.main_pid == 0
                && status.protocol == 1
                && status.profile == guest::INIT_READY_V1
                && status.stage == "builder"
                && status.identity.is_none(),
            "template init is not at its pre-main barrier"
        );
        anyhow::ensure!(
            status.ram_marker.len() == 32 && expected_marker.is_none_or(|m| m == status.ram_marker),
            "restored init RAM marker differs from sealed artifact"
        );
        Ok(pong.version)
    }

    pub(in crate::machine) async fn activate_memory_clone(
        &self,
        e: &Entry,
        live: &fc::Vm,
    ) -> Result<String> {
        let entire = std::time::Instant::now();
        let machine = e.snapshot().id;
        let mut origin = e
            .snapshot()
            .clone_origin
            .ok_or_else(|| anyhow!("clone origin missing"))?;
        anyhow::ensure!(
            live.resumed
                && live.incarnation.is_some()
                && e.identity_trusted.load(Relaxed)
                && live.boot_identity.as_ref() == Some(&origin.artifact.boot_identity),
            "memory clone load/provenance is unconfirmed"
        );
        let started = std::time::Instant::now();
        self.inner
            .vmm
            .resume(live)
            .await
            .context("resume into clone barrier")?;
        crate::profile::stage(
            "named_memory_clone",
            "resume_into_init",
            &machine,
            live.pid,
            started,
            true,
        );
        self.template_builder_ready(live, Some(&origin.artifact.ram_marker))
            .await?;
        // Queueing/disk load can take time. Freeze current wall time durably immediately
        // before the first configure, so delayed admission cannot start with a stale clock.
        if origin.stage == CloneStage::Loading {
            origin.configure.realtime_sec = Utc::now()
                .timestamp()
                .try_into()
                .context("host clock predates epoch")?;
            e.rec
                .lock()
                .unwrap()
                .clone_origin
                .as_mut()
                .unwrap()
                .configure = origin.configure.clone();
            self.clone_stage(e, CloneStage::Configuring)?;
        }
        let started = std::time::Instant::now();
        let configured = self
            .inner
            .guest
            .clone_control(
                &live.vsock,
                guest::Request {
                    op: "clone_configure_v1".into(),
                    clone_configure: Some(origin.configure.clone()),
                    ..Default::default()
                },
            )
            .await?;
        let identity = configured
            .identity
            .ok_or_else(|| anyhow!("clone identity acknowledgment missing"))?;
        let c = &origin.configure;
        anyhow::ensure!(
            configured.protocol == 1
                && configured.profile == guest::INIT_READY_V1
                && configured.stage == "identity_done"
                && identity.generation == c.generation
                && identity.hostname == c.hostname
                && identity.ip == c.ip
                && identity.mac == c.mac
                && identity.machine_id.len() == 32
                && identity.machine_id.bytes().all(|v| v.is_ascii_hexdigit()),
            "clone acknowledged a different or incomplete identity"
        );
        if let Some(old) = origin.identity {
            anyhow::ensure!(
                old == identity,
                "clone identity changed after acknowledgment"
            );
        }
        e.rec
            .lock()
            .unwrap()
            .clone_origin
            .as_mut()
            .unwrap()
            .identity = Some(identity);
        // Durable identity before any unquarantine or activation request.
        self.clone_stage(e, CloneStage::IdentityDone)?;
        crate::profile::stage(
            "named_memory_clone",
            "identity_durable",
            &machine,
            live.pid,
            started,
            true,
        );
        let started = std::time::Instant::now();
        self.activate_clone_network(&e.snapshot()).await?;
        crate::profile::stage(
            "named_memory_clone",
            "network_activate",
            &machine,
            live.pid,
            started,
            true,
        );
        let started = std::time::Instant::now();
        let activated = self
            .inner
            .guest
            .clone_control(
                &live.vsock,
                guest::Request {
                    op: "clone_activate_v1".into(),
                    clone_generation: c.generation.clone(),
                    ..Default::default()
                },
            )
            .await?;
        anyhow::ensure!(
            activated
                .identity
                .as_ref()
                .is_some_and(|i| i.generation == c.generation)
                && matches!(activated.stage.as_str(), "activating" | "active"),
            "clone activation generation mismatch"
        );
        let wait = async {
            loop {
                let pong = self.inner.guest.ping(&live.vsock).await?;
                let ready = pong.clone_status.as_ref().is_some_and(|s| {
                    s.protocol == 1
                        && s.profile == guest::INIT_READY_V1
                        && s.stage == "active"
                        && s.identity
                            .as_ref()
                            .is_some_and(|i| i.generation == c.generation)
                });
                if ready && pong.main_pid > 0 {
                    return Ok::<_, anyhow::Error>(pong.version);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        let version = tokio::time::timeout(
            Duration::from_secs(self.inner.cfg.boot_timeout_sec.max(10)),
            wait,
        )
        .await
        .context("clone main-start barrier timeout")??;
        crate::profile::stage(
            "named_memory_clone",
            "main_started",
            &machine,
            live.pid,
            started,
            true,
        );
        let started = std::time::Instant::now();
        let mut session = self
            .inner
            .guest
            .session(
                &live.vsock,
                guest::Request {
                    op: "exec".into(),
                    cmd: vec!["/bin/true".into()],
                    timeout_ms: 5000,
                    ..Default::default()
                },
            )
            .await?;
        let result = tokio::time::timeout(Duration::from_secs(10), guestc::collect(&mut session))
            .await
            .context("clone first command timeout")??;
        anyhow::ensure!(
            result.code == 0 && !result.timed_out,
            "clone first command failed"
        );
        self.clone_stage(e, CloneStage::Active)?;
        crate::profile::stage(
            "named_memory_clone",
            "first_exec_ready",
            &machine,
            live.pid,
            started,
            true,
        );
        crate::profile::stage(
            "named_memory_clone",
            "identity_activation_ready",
            &machine,
            live.pid,
            entire,
            true,
        );
        Ok(version)
    }
}
