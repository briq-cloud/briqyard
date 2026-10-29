//! A tenant's gateway: the machine the daemon runs for its `via-gateway` machines.

use super::*;

impl Manager {
    // --- the tenant's gateway (ADR 0016) ---

    /// Puts the tenant's gateway: made, not started, when the tenant has none (the tenant
    /// too, when it has nothing yet); else given the new spec, a running one restarted. With
    /// `start`, it then runs as a start that needs it would run it.
    pub async fn set_gateway(
        &self,
        tenant: &str,
        spec: api::GatewaySpec,
    ) -> Result<api::Tenant, MError> {
        check_tenant_id(tenant)?;
        if spec.image.is_empty() || spec.port == 0 {
            return Err(invalid("a gateway needs an image and a port (1..65535)"));
        }
        spec.probes.check().map_err(invalid)?;
        // A machine of the daemon: no window of its own, it runs while something needs it,
        // and comes back whenever its program ends on its own.
        let req = api::CreateMachineRequest {
            tenant: tenant.into(),
            name: GATEWAY_NAME.into(),
            size: spec.size(),
            image: spec.image,
            cmd: spec.cmd,
            env: spec.env,
            files: spec.files,
            volume: spec.volume_gb.map(|size_gb| api::VolumeSpec {
                size_gb,
                mount: "/data".into(),
            }),
            ports: vec![spec.port],
            probes: Some(spec.probes),
            sleep: "never".into(),
            restart: Some(api::RestartPolicy {
                policy: "always".into(),
                max_retries: 0,
            }),
            start: Some(false),
            ..Default::default()
        };
        // A machine's own check, so a replacement is refused in the words a create would be.
        req.spec().check().map_err(invalid)?;
        check_size(&req.size)?;
        // Pulled before the tenant's lock: a pull may take minutes.
        let im = self.inner.images.ensure(&req.image).await?;
        let t = self.ensure_tenant(tenant).await?;
        let _turn = t.lock.lock().await;
        match self.gateway_of(tenant) {
            None => {
                // Made before the answer: the tenant's lock orders its gateway's changes.
                let (gw, how) = self.record(req, Some(Role::Gateway)).await?;
                self.make(&gw, how).await?;
            }
            Some(gw) => self.replace_gateway(&gw, req, im).await?,
        }
        if spec.start {
            let gw = self.gateway_of(tenant).ok_or_else(|| no_gateway(tenant))?;
            self.run_gateway(&gw).await?;
        }
        self.tenant(tenant)
    }

    /// A new spec on the same machine, address and volume: stopped if it runs, started again
    /// (a new image's root disk is made by the next start, ADR 0024). The spec it has already
    /// changes nothing, so a control plane may put it again. Under the tenant's lock.
    async fn replace_gateway(
        &self,
        gw: &Arc<Entry>,
        req: api::CreateMachineRequest,
        im: image::Image,
    ) -> Result<(), MError> {
        let was = gw.snapshot();
        let size_gb = |v: &Option<api::VolumeSpec>| v.as_ref().map(|v| v.size_gb);
        if size_gb(&req.volume) != size_gb(&was.volume) {
            return Err(invalid(
                "volume_gb is fixed for the gateway's life: DELETE the gateway to change it",
            ));
        }
        let probes = req.probes.clone().unwrap_or_default();
        if im.key == was.image_key
            && req.cmd == was.cmd
            && req.env == was.env
            && req.files == was.files
            && req.size == was.size
            && req.ports == was.ports
            && probes == was.probes
        {
            return Ok(());
        }
        let running = was.state == state::RUNNING;
        if running {
            self.stop_entry(gw, stop::HOST, Duration::from_secs(10), false, None)
                .await?;
        }
        {
            let _turn = gw.lock.lock().await;
            let r = gw.snapshot();
            if !matches!(
                r.state.as_str(),
                state::CREATED | state::STOPPED | state::ERROR
            ) {
                return Err(MError::BadState(r.state));
            }
            {
                let mut r = gw.rec.lock().unwrap();
                let fields: Vec<&str> = [
                    ("image", im.key != r.image_key),
                    ("cmd", req.cmd != r.cmd),
                    ("env", req.env != r.env),
                    ("files", req.files != r.files),
                    ("size", req.size != r.size),
                    ("ports", req.ports != r.ports),
                    ("probes", probes != r.probes),
                ]
                .into_iter()
                .filter_map(|(f, changed)| changed.then_some(f))
                .collect();
                r.image = req.image;
                r.image_key = im.key;
                r.image_digest = im.digest;
                r.image_config = im.config;
                r.cmd = req.cmd;
                r.env = req.env;
                r.files = req.files;
                r.size = req.size;
                r.ports = req.ports;
                r.probes = probes;
                // A memory snapshot is of the old program on the old disk: boot cold.
                r.suspended = false;
                let ev = Ev::normal(
                    reason::UPDATED,
                    format!("the gateway's {} replaced", fields.join(", ")),
                );
                gw.note_locked(&mut r, ev.data(json!({ "fields": fields })));
            }
            self.save(gw)?;
        }
        if running {
            self.run_gateway(gw).await?;
        }
        Ok(())
    }

    /// Stops and destroys the tenant's gateway; refused while a machine runs through it.
    /// None is success.
    pub async fn delete_gateway(&self, tenant: &str) -> Result<(), MError> {
        check_tenant_id(tenant)?;
        let Some(t) = self.tenant_of(tenant) else {
            return Ok(());
        };
        let _turn = t.lock.lock().await;
        let Some(gw) = self.gateway_of(tenant) else {
            return Ok(());
        };
        if gateway_needed(&self.inner.machines.lock().unwrap(), tenant) {
            return Err(MError::GatewayInUse);
        }
        self.destroy_machine(&gw.snapshot().id, None).await
    }

    /// The tenant's gateway machine, unless it is being destroyed.
    pub(super) fn gateway_of(&self, tenant: &str) -> Option<Arc<Entry>> {
        self.inner
            .machines
            .lock()
            .unwrap()
            .values()
            .find(|e| {
                let r = e.rec.lock().unwrap();
                r.tenant == tenant && r.is_gateway() && r.state != state::DESTROYING
            })
            .cloned()
    }

    /// Makes sure the tenant's gateway runs and its port answers, and returns the tenant's
    /// lock held: two starts that need the gateway boot it once.
    pub(super) async fn ensure_gateway(
        &self,
        tenant: &str,
    ) -> Result<tokio::sync::OwnedMutexGuard<()>, MError> {
        let t = self
            .tenant_of(tenant)
            .ok_or_else(|| anyhow!("tenant network is gone"))?;
        let turn = t.lock.clone().lock_owned().await;
        let gw = self.gateway_of(tenant).ok_or_else(|| no_gateway(tenant))?;
        self.run_gateway(&gw).await?;
        Ok(turn)
    }

    /// Starts the gateway unless it runs, then waits for it to serve within the boot timeout:
    /// its `ready` when it has a startup or readiness probe (ADR 0022), else its port. A
    /// gateway that does not serve in time is ended and left in `error` with its console's
    /// last lines, as a boot that fails is. Under the tenant's lock; the gateway's own lock is
    /// let go while it is waited for, since its probes take it to end a failed boot.
    async fn run_gateway(&self, gw: &Arc<Entry>) -> Result<(), MError> {
        let (started, live) = {
            let _turns = gw.lock_for_start().await;
            let started = gw.snapshot().state != state::RUNNING;
            if started {
                self.start_boxed(gw, true).await?;
            }
            (started, gw.live.lock().unwrap().clone())
        };
        let Some(live) = live else {
            return Err(MError::NotRunning("the gateway has no process".into()));
        };
        let r = gw.snapshot();
        let port = r.ports.first().copied().unwrap_or(0);
        let ip: Ipv4Addr = r.ip.parse().map_err(anyhow::Error::from)?;
        let timeout = Duration::from_secs(self.inner.cfg.boot_timeout_sec.max(10));
        let mut exited = live.exited.clone();
        let answered = match probes::ready_at_boot(&r.probes) {
            true => tokio::select! {
                r = self.inner.net.wait_port(ip, port, timeout) => {
                    r.map_err(|err| format!("port {port} did not answer: {err:#}"))
                }
                _ = exited.wait_for(|gone| *gone) => Err("the gateway exited".to_string()),
            },
            false => match self.wait(&r.id, Until::Ready, timeout).await {
                Ok(_) => Ok(()),
                // Its startup probe failed it already: the machine says why.
                Err(MError::BootFailed(m)) => return Err(MError::BootFailed(m)),
                Err(err) => Err(format!("not ready: {err}")),
            },
        };
        let _turn = gw.lock.lock().await;
        let Err(why) = answered else {
            if started {
                gw.note(
                    Ev::normal(
                        reason::GATEWAY_STARTED,
                        format!("the tenant's gateway answers on {ip}:{port}"),
                    )
                    .data(json!({ "port": port })),
                );
                let _ = self.save(gw);
            }
            return Ok(());
        };
        if gw.live.lock().unwrap().as_ref().map(|l| l.pid) == Some(live.pid) {
            self.end_process(gw, &live, Duration::ZERO).await;
        }
        let tail = self.last_console_lines(&r, 5);
        Err(self.boot_failed(gw, format!("{why}: {tail}")))
    }

    /// What a machine that needs the gateway answers when the gateway did not come up:
    /// `boot_failed` with the machine as it is (not moved), the gateway's reason in `error`.
    pub(super) fn gateway_failed(&self, e: &Entry, err: MError) -> MError {
        match err {
            MError::BootFailed(gw) => {
                let mut m = self.view(e);
                m.error = format!("the tenant's gateway did not come up: {}", gw.error);
                MError::BootFailed(Box::new(m))
            }
            other => other,
        }
    }

    /// The gateways whose state is not what their tenant needs: running while no machine
    /// needs them (`running`), or not running while one does (not `running`).
    pub(super) fn gateways_out_of_step(&self, running: bool) -> Vec<Arc<Entry>> {
        let machines = self.inner.machines.lock().unwrap();
        machines
            .values()
            .filter(|e| {
                let tenant = {
                    let r = e.rec.lock().unwrap();
                    if !r.is_gateway() || (r.state == state::RUNNING) != running {
                        return false;
                    }
                    r.tenant.clone()
                };
                gateway_needed(&machines, &tenant) != running
            })
            .cloned()
            .collect()
    }

    /// Stops a gateway nothing needs, under its tenant's lock. A lock someone holds is a start
    /// or a change of the gateway under way: the next tick looks again.
    pub(super) async fn sleep_gateway(&self, gw: &Arc<Entry>) {
        let r = gw.snapshot();
        let Some(t) = self.tenant_of(&r.tenant) else {
            return;
        };
        let Ok(_turn) = t.lock.try_lock() else {
            return;
        };
        if gateway_needed(&self.inner.machines.lock().unwrap(), &r.tenant) {
            return;
        }
        tracing::info!(
            machine = r.id,
            tenant = r.tenant,
            "gateway unused, going to sleep"
        );
        let suspend = self.inner.cfg.suspend_on_sleep;
        if let Err(err) = self
            .stop_entry(gw, stop::IDLE, Duration::from_secs(10), suspend, None)
            .await
        {
            tracing::warn!(machine = r.id, err = %err, "gateway sleep");
            return;
        }
        let _turn = gw.lock.lock().await;
        if self.holds(gw) && gw.snapshot().state == state::STOPPED {
            gw.note(Ev::normal(
                reason::GATEWAY_STOPPED,
                "nothing sends through the tenant's gateway: stopped",
            ));
            let _ = self.save(gw);
        }
    }
}

/// Whether a machine of `tenant` that sends through its gateway is running or starting: what
/// keeps the gateway up.
fn gateway_needed(machines: &HashMap<String, Arc<Entry>>, tenant: &str) -> bool {
    machines.values().any(|e| {
        let r = e.rec.lock().unwrap();
        r.tenant == tenant
            && r.egress.via_gateway()
            && matches!(r.state.as_str(), state::STARTING | state::RUNNING)
    })
}
