//! A namespace's gateway: the machine the daemon runs for its `via-gateway` machines.

use super::*;

impl Manager {
    // --- the namespace's gateway (ADR 0016) ---

    /// Puts the namespace's gateway: made, not started, when the namespace has none (the namespace
    /// too, when it has nothing yet); else given the new spec, a running one restarted. With
    /// `start`, it then runs as a start that needs it would run it.
    pub async fn set_gateway(
        &self,
        namespace: &str,
        spec: api::GatewaySpec,
    ) -> Result<api::Namespace, MError> {
        check_namespace_id(namespace)?;
        if spec.image.is_empty() || spec.port == 0 {
            return Err(invalid("a gateway needs an image and a port (1..65535)"));
        }
        spec.probes.check().map_err(invalid)?;
        if let Some(policy) = &spec.policy {
            policy
                .check()
                .map_err(|why| invalid(format!("policy: {why}")))?;
        }
        // A machine of the daemon: no window of its own, it runs while something needs it,
        // and comes back whenever its program ends on its own.
        let req = api::CreateMachineRequest {
            namespace: namespace.into(),
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
            gateway_policy: spec.policy.clone(),
            ..Default::default()
        };
        // A machine's own check, so a replacement is refused in the words a create would be.
        req.spec().check().map_err(invalid)?;
        self.check_host_size(&req.size)?;
        // Pulled before the namespace's lock: a pull may take minutes.
        let im = self.inner.images.ensure(&req.image).await?;
        let _admission = self.inner.namespace_lifecycle.read().await;
        let _policy_turn = self
            .inner
            .namespace_turns
            .take(namespace, gateway_policy::POLICY_ADMISSION)
            .await;
        let t = self.ensure_namespace(namespace).await?;
        let turn = Arc::new(t.lock.clone().lock_owned().await);
        match self.gateway_of(namespace) {
            None => {
                if req.gateway_policy.is_some() {
                    self.check_policy_dependents(
                        &self.inner.machines.lock().unwrap(),
                        namespace,
                        None,
                    )?;
                }
                // Made before the answer: the namespace's lock orders its gateway's changes.
                let scope = self.inner.zfs.io_scope()?;
                let (gw, how, child_scope) = scope
                    .run(async {
                        let (gw, how) = self.record_admitted(req, Some(Role::Gateway)).await?;
                        let child_scope = self.inner.zfs.io_scope()?;
                        Ok::<_, MError>((gw, how, child_scope))
                    })
                    .await?;
                self.make_admitted(child_scope, &gw, how).await?;
            }
            Some(gw) => self.replace_gateway(&gw, req, im, &turn).await?,
        }
        if spec.start {
            let gw = self
                .gateway_of(namespace)
                .ok_or_else(|| no_gateway(namespace))?;
            self.run_gateway(&gw, true, &turn).await?;
        }
        self.namespace(namespace)
    }

    /// A new spec on the same machine, address and volume: stopped if it runs, started again
    /// (a new image's root disk is made by the next start, ADR 0024). The spec it has already
    /// changes nothing, so a control plane may put it again. Under the namespace's lock.
    async fn replace_gateway(
        &self,
        gw: &Arc<Entry>,
        req: api::CreateMachineRequest,
        im: image::Image,
        turn: &GatewayTurn,
    ) -> Result<(), MError> {
        let was = gw.snapshot();
        let size_gb = |v: &Option<api::VolumeSpec>| v.as_ref().map(|v| v.size_gb);
        if size_gb(&req.volume) != size_gb(&was.volume) {
            return Err(invalid(
                "volume_gb is fixed for the gateway's life: DELETE the gateway to change it",
            ));
        }
        if req.gateway_policy != was.gateway_policy {
            return Err(invalid(
                "policy is fixed for the gateway's life: DELETE the gateway to change it",
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
        self.check_gateway_isolation(gw)?;
        if self.has_bound_consumer(&was.namespace) {
            return Err(MError::Conflict(
                "a machine bound to the gateway's loaded policy exists: the gateway is not replaced until it is destroyed".into(),
            ));
        }
        let publication = self.begin_execution_mutation(
            std::slice::from_ref(&was.namespace),
            execution_fence::MutationMode::Broaden,
        )?;
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
                r.image_config_digest = im.config_digest;
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
            self.save_execution_publication(gw)?;
        }
        if running {
            self.run_gateway(gw, true, turn).await?;
        }
        self.save_execution_publication(gw)?;
        self.finish_execution_mutation(&publication)?;
        Ok(())
    }

    /// Stops and destroys the namespace's gateway; refused while a machine runs through it.
    /// None is success.
    pub async fn delete_gateway(&self, namespace: &str) -> Result<(), MError> {
        check_namespace_id(namespace)?;
        let _admission = self.inner.namespace_lifecycle.read().await;
        let _policy_turn = self
            .inner
            .namespace_turns
            .take(namespace, gateway_policy::POLICY_ADMISSION)
            .await;
        let Some(t) = self.namespace_of(namespace) else {
            return Ok(());
        };
        let _turn = t.lock.lock().await;
        let Some(gw) = self.gateway_of(namespace) else {
            return Ok(());
        };
        self.check_gateway_isolation(&gw)?;
        if self.has_bound_consumer(namespace) {
            return Err(MError::Conflict(
                "a machine bound to the gateway's loaded policy exists: the gateway is not deleted until it is destroyed".into(),
            ));
        }
        let policy_gateway = {
            let g = gw.rec.lock().unwrap();
            g.gateway_policy.is_some().then(|| g.id.clone())
        };
        if gateway_needed(
            &self.inner.machines.lock().unwrap(),
            namespace,
            policy_gateway.as_deref(),
        ) {
            return Err(MError::GatewayInUse);
        }
        self.destroy_machine(&gw.snapshot().id, None).await
    }

    /// The namespace's gateway machine, unless it is being destroyed.
    pub(super) fn gateway_of(&self, namespace: &str) -> Option<Arc<Entry>> {
        self.inner
            .machines
            .lock()
            .unwrap()
            .values()
            .find(|e| {
                let r = e.rec.lock().unwrap();
                r.namespace == namespace && r.is_gateway() && r.state != state::DESTROYING
            })
            .cloned()
    }

    /// Makes sure the namespace's gateway runs and its port answers, and returns the namespace's
    /// lock held: two starts that need the gateway boot it once.
    ///
    /// A gateway with a loaded policy is read back from its running process on every call
    /// before its bridge gate opens (ADR 0143); `required` is the binding the caller needs it to
    /// carry, and a gateway with another is refused.
    pub(super) async fn ensure_gateway(
        &self,
        namespace: &str,
        required: Option<&api::GatewayPolicyBinding>,
    ) -> Result<GatewayTurn, MError> {
        let t = self
            .namespace_of(namespace)
            .ok_or_else(|| anyhow!("namespace network is gone"))?;
        if let Some(gw) = self.gateway_of(namespace) {
            self.check_gateway_isolation(&gw)?;
        }
        let turn = Arc::new(t.lock.clone().lock_owned().await);
        self.ensure_gateway_held(namespace, required, &turn).await?;
        Ok(turn)
    }

    pub(super) async fn ensure_gateway_held(
        &self,
        namespace: &str,
        required: Option<&api::GatewayPolicyBinding>,
        turn: &GatewayTurn,
    ) -> Result<(), MError> {
        let gw = self
            .gateway_of(namespace)
            .ok_or_else(|| no_gateway(namespace))?;
        if required.is_some() && required != gw.snapshot().gateway_policy.as_ref() {
            return Err(MError::GatewayPolicy(
                "the namespace's gateway does not carry the loaded policy this machine requires"
                    .into(),
            ));
        }
        self.run_gateway(&gw, true, turn).await
    }

    /// Starts the gateway unless it runs, then waits for it to serve within the boot timeout:
    /// its `ready` when it has a startup or readiness probe (ADR 0022), else its port. A
    /// gateway that does not serve in time is ended and left in `error` with its console's
    /// last lines, as a boot that fails is. Under the namespace's lock; the gateway's own lock is
    /// let go while it is waited for, since its probes take it to end a failed boot.
    pub(super) async fn run_gateway(
        &self,
        gw: &Arc<Entry>,
        asked: bool,
        turn: &GatewayTurn,
    ) -> Result<(), MError> {
        if gw.rec.lock().unwrap().gateway_policy.is_some() {
            return Box::pin(self.verify_gateway(gw, asked, turn)).await;
        }
        let (_entry, live, answered) = Box::pin(self.gateway_serving(gw, asked)).await?;
        let Err(why) = answered else {
            return Ok(());
        };
        let r = gw.snapshot();
        let unended = if gw.live.lock().unwrap().as_ref().map(|l| l.pid) == Some(live.pid) {
            self.end_process(gw, &live, Duration::ZERO).await.err()
        } else {
            None
        };
        let tail = self.last_console_lines(&r, 5);
        Err(self.boot_failed(
            gw,
            match unended {
                None => format!("{why}: {tail}"),
                Some(err) => format!("{why}: {tail} (its process could not be ended: {err:#})"),
            },
        ))
    }

    pub(super) async fn gateway_serving(
        &self,
        gw: &Arc<Entry>,
        asked: bool,
    ) -> Result<(tokio::sync::OwnedMutexGuard<()>, fc::Vm, Result<(), String>), MError> {
        let (started, live) = {
            let _turns = gw.lock_for_start().await;
            self.check_gateway_isolation(gw)?;
            let started = gw.snapshot().state != state::RUNNING;
            if started {
                self.start_boxed(gw, asked).await?;
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
        let entry_turn = gw.lock.clone().lock_owned().await;
        if started && answered.is_ok() {
            gw.note(
                Ev::normal(
                    reason::GATEWAY_STARTED,
                    format!("the namespace's gateway answers on {ip}:{port}"),
                )
                .data(json!({ "port": port })),
            );
            let _ = self.save(gw);
        }
        Ok((entry_turn, live, answered))
    }

    /// What a machine that needs the gateway answers when the gateway did not come up:
    /// `boot_failed` with the machine as it is (not moved), the gateway's reason in `error`.
    pub(super) fn gateway_failed(&self, e: &Entry, err: MError) -> MError {
        match err {
            MError::BootFailed(gw) => {
                let mut m = self.view(e);
                m.error = format!("the namespace's gateway did not come up: {}", gw.error);
                MError::BootFailed(Box::new(m))
            }
            other => other,
        }
    }

    /// The gateways whose state is not what their namespace needs: running while no machine
    /// needs them (`running`), or not running while one does (not `running`).
    pub(super) fn gateways_out_of_step(&self, running: bool) -> Vec<Arc<Entry>> {
        let machines = self.inner.machines.lock().unwrap();
        machines
            .values()
            .filter(|e| {
                let (namespace, policy_gateway) = {
                    let r = e.rec.lock().unwrap();
                    if !r.is_gateway() || (r.state == state::RUNNING) != running {
                        return false;
                    }
                    (
                        r.namespace.clone(),
                        r.gateway_policy.is_some().then(|| r.id.clone()),
                    )
                };
                gateway_needed(&machines, &namespace, policy_gateway.as_deref()) != running
            })
            .cloned()
            .collect()
    }

    /// Stops a gateway nothing needs, under its namespace's lock. A lock someone holds is a start
    /// or a change of the gateway under way: the next tick looks again.
    pub(super) async fn sleep_gateway(&self, gw: &Arc<Entry>) {
        let r = gw.snapshot();
        let Some(t) = self.namespace_of(&r.namespace) else {
            return;
        };
        let Ok(_turn) = t.lock.try_lock() else {
            return;
        };
        let policy_gateway = r.gateway_policy.is_some().then_some(r.id.as_str());
        if gateway_needed(
            &self.inner.machines.lock().unwrap(),
            &r.namespace,
            policy_gateway,
        ) {
            return;
        }
        if !self.idle_stop_allowed(&r, Utc::now()) {
            return;
        }
        tracing::info!(
            machine = r.id,
            namespace = r.namespace,
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
                "nothing sends through the namespace's gateway: stopped",
            ));
            let _ = self.save(gw);
        }
    }
}

/// Whether a machine of `namespace` that sends through its gateway is running or starting: what
/// keeps the gateway up.
fn gateway_needed(
    machines: &HashMap<String, Arc<Entry>>,
    namespace: &str,
    policy_gateway: Option<&str>,
) -> bool {
    machines.values().any(|e| {
        let r = e.rec.lock().unwrap();
        r.namespace == namespace
            && (r.egress.via_gateway()
                || (r.egress.mode == api::egress::VIA
                    && policy_gateway.is_some()
                    && r.egress.via.as_deref() == policy_gateway))
            && matches!(r.state.as_str(), state::STARTING | state::RUNNING)
    })
}
