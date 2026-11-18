//! The loaded-policy fence of a namespace's gateway (ADR 0143).
//!
//! A gateway made with a policy binding is unverified until the daemon has read that policy
//! back from its current process. Until then a bridge gate keeps the namespace's machines and
//! the gateway from exchanging ARP or IP (the gateway's own route to the host stays, so it can
//! register its CA and fetch its configuration). The gate opens only after a readback whose
//! outer identity (namespace, machine, process incarnation) is the daemon's own and the same
//! before and after the question.

use super::*;
use rand::RngCore;
use tokio::sync::{oneshot, watch};

/// The helper the gateway image carries; nothing else in the guest is asked.
const HELPER: &str = "/credential-gateway";
/// The guest's own deadline for the command, and the one deadline for everything the daemon
/// does for it: the lock, the session and the reading of its output.
const GUEST_TIMEOUT_MS: u64 = 2_000;
const OUTER: Duration = Duration::from_secs(3);
/// A report is a few hundred bytes. More is a refusal, never a prefix.
const REPORT_LIMIT: u64 = 4096;
const ISOLATION_UNCONFIRMED: &str = "gateway isolation unconfirmed: process and address retained";
pub(super) const POLICY_ADMISSION: &str = "gateway-policy";

impl Record {
    /// Born by an ordinary fresh create: no source, backup, template, warm slot or assigned run.
    /// A gateway loaded policy serves only such machines (ADR 0143).
    pub(super) fn is_cold_born(&self) -> bool {
        !self.from_source
            && self.fork.is_none()
            && self.template_birth.is_none()
            && self.clone_origin.is_none()
            && self.warm_slot.is_none()
            && self.launch_identity.is_none()
            && self.assigned_run.is_none()
    }
}

fn depends_on_policy_gateway(egress: &api::Egress, namespace: &str, records: &[Record]) -> bool {
    records.iter().any(|g| {
        g.is_gateway()
            && g.gateway_policy.is_some()
            && g.namespace == namespace
            && routes_through_gateway(egress, Some(&g.id))
    })
}

fn routes_through_gateway(egress: &api::Egress, gateway_id: Option<&str>) -> bool {
    egress.mode == api::egress::VIA
        && (egress.via_gateway() || gateway_id.is_some_and(|id| egress.via.as_deref() == Some(id)))
}

fn not_cold_born(what: &str) -> MError {
    invalid(format!(
        "a gateway loaded policy serves only machines created fresh: {what}"
    ))
}

impl Manager {
    pub(super) fn uses_gateway(&self, namespace: &str, egress: &api::Egress) -> bool {
        egress.via_gateway()
            || (egress.mode == api::egress::VIA
                && egress
                    .via
                    .as_deref()
                    .and_then(|id| self.entry(id).ok())
                    .is_some_and(|target| {
                        let r = target.rec.lock().unwrap();
                        r.namespace == namespace && r.is_gateway() && r.gateway_policy.is_some()
                    }))
    }

    /// Refuses a machine that is not cold-born and depends on a gateway loaded policy: its own
    /// binding, or a route through its namespace's policy gateway (by `gateway` or by its machine
    /// id). Nothing is claimed, stopped or moved by the caller before this answers.
    pub(super) fn check_policy_ownership(
        &self,
        cold_born: bool,
        egress: &api::Egress,
        namespace: &str,
    ) -> Result<(), MError> {
        self.check_policy_ownership_in(
            &self.inner.machines.lock().unwrap(),
            cold_born,
            egress,
            namespace,
        )
    }

    /// The same check over the machines map its caller holds, so that the answer and what the
    /// caller then admits are one step a policy gateway's introduction cannot fall between.
    pub(super) fn check_policy_ownership_in(
        &self,
        machines: &HashMap<String, Arc<Entry>>,
        cold_born: bool,
        egress: &api::Egress,
        namespace: &str,
    ) -> Result<(), MError> {
        if cold_born {
            return Ok(());
        }
        if egress.gateway_policy.is_some() {
            return Err(not_cold_born(
                "no fork, restore, seed, template, warm slot or assigned run is bound to it",
            ));
        }
        let gateways: Vec<Record> = machines
            .values()
            .map(|e| e.snapshot())
            .filter(Record::is_gateway)
            .collect();
        if depends_on_policy_gateway(egress, namespace, &gateways) {
            return Err(MError::Conflict(
                "the namespace's gateway enforces a loaded policy: only machines created fresh route through it"
                    .into(),
            ));
        }
        Ok(())
    }

    /// A source or backup bound to a gateway loaded policy is never derived from, whatever the
    /// request says its egress is: checked before any override is applied.
    pub(super) fn check_policy_source(&self, source: &Record) -> Result<(), MError> {
        match source.egress.gateway_policy.is_some() {
            true => Err(not_cold_born(
                "a machine bound to it is not forked, restored or seeded",
            )),
            false => Ok(()),
        }
    }

    /// What the raw request already says, before any replay, lock or claim: a request for a derived
    /// machine carries no binding and does not route through a policy gateway.
    pub(super) fn check_cold_born_request(
        &self,
        req: &api::CreateMachineRequest,
        internal: bool,
    ) -> Result<(), MError> {
        let derived = internal
            || req.fork.is_some()
            || req.restore.is_some()
            || req.sandbox_seed.is_some()
            || req.template_build.is_some()
            || req.clone_hooks.is_some();
        match &req.egress {
            Some(egress) => self.check_policy_ownership(!derived, egress, &req.namespace),
            None => Ok(()),
        }
    }

    /// A gateway with a loaded policy is refused while the namespace holds a machine, or a retained
    /// assignment target, that is not cold-born and routes through its gateway.
    pub(super) fn check_policy_dependents(
        &self,
        machines: &HashMap<String, Arc<Entry>>,
        namespace: &str,
        gateway_id: Option<&str>,
    ) -> Result<(), MError> {
        let depends = |r: &Record| {
            r.namespace == namespace
                && !r.is_gateway()
                && !r.is_cold_born()
                && routes_through_gateway(&r.egress, gateway_id)
        };
        match machines.values().any(|e| depends(&e.rec.lock().unwrap()))
            || self.assignment_targets().iter().any(depends)
        {
            true => Err(MError::Conflict(
                "a machine that was not created fresh routes through the namespace's gateway: a loaded policy is not set until it is gone"
                    .into(),
            )),
            false => Ok(()),
        }
    }

    /// Stored records (and retained assignment targets) that are not cold-born yet carry a
    /// binding or route through a policy gateway. Recovery withholds them and everything of theirs.
    pub(super) fn unsupported_policy_records(&self) -> Vec<String> {
        let held: Vec<Record> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .map(|e| e.snapshot())
            .chain(self.assignment_targets())
            .collect();
        let mut ids: Vec<String> = held
            .iter()
            .filter(|r| {
                !r.is_cold_born()
                    && (r.egress.gateway_policy.is_some()
                        || depends_on_policy_gateway(&r.egress, &r.namespace, &held))
            })
            .map(|r| r.id.clone())
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }
}

/// A gateway's process and binding as the last readback proved them.
pub(super) struct GatewayProof {
    incarnation: fc::Incarnation,
    binding: api::GatewayPolicyBinding,
    exited: watch::Receiver<bool>,
    namespace: String,
    id: String,
    ip: String,
    version: u64,
}

impl GatewayProof {
    fn matches(&self, gw: &Entry) -> bool {
        let r = gw.rec.lock().unwrap();
        r.is_gateway()
            && r.state == state::RUNNING
            && r.namespace == self.namespace
            && r.id == self.id
            && r.ip == self.ip
            && r.version == self.version
            && r.pid == self.incarnation.pid
            && r.boot_incarnation.as_ref() == Some(&self.incarnation)
            && r.gateway_policy.as_ref() == Some(&self.binding)
            && gw.identity_trusted.load(Relaxed)
            && !gw.gateway_isolating.load(Relaxed)
            && gw.live.lock().unwrap().as_ref().is_some_and(|vm| {
                vm.pid == self.incarnation.pid
                    && vm.incarnation.as_ref() == Some(&self.incarnation)
                    && vm.exited.same_channel(&self.exited)
            })
    }
}

fn unverified(why: &str) -> MError {
    MError::GatewayPolicy(format!("gateway loaded policy not verified: {why}"))
}

impl Manager {
    /// `POST /v1/namespaces/{id}/gateway/policy-status`: asks the namespace's running gateway
    /// for its loaded policy. Never starts, wakes or creates anything.
    pub async fn gateway_policy_status(
        &self,
        namespace: &str,
        request: api::GatewayPolicyStatusRequest,
    ) -> Result<api::GatewayPolicyStatus, MError> {
        check_namespace_id(namespace)?;
        request.check().map_err(invalid)?;
        let t = self.namespace_of(namespace).ok_or(MError::NotFound)?;
        let read = async {
            // Namespace before gateway: no replacement or restart runs under the question.
            let _turn = t.lock.lock().await;
            let gw = self
                .gateway_of(namespace)
                .ok_or_else(|| no_gateway(namespace))?;
            Box::pin(self.read_gateway_policy(&gw, &request.challenge)).await
        };
        tokio::time::timeout(OUTER, read)
            .await
            .map_err(|_| unverified("the readback did not finish in time"))?
    }

    /// The gateway's record, handle and process incarnation, when all three are the same
    /// running process this daemon booted or adopted with proof.
    fn gateway_identity(
        &self,
        gw: &Arc<Entry>,
    ) -> Result<(Record, fc::Vm, fc::Incarnation), MError> {
        let rec = gw.snapshot();
        if !rec.is_gateway() || rec.state != state::RUNNING || *gw.removed.lock().unwrap() {
            return Err(unverified("the gateway is not running"));
        }
        let live = gw
            .live
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| unverified("the gateway has no process"))?;
        let incarnation = live
            .incarnation
            .clone()
            .filter(|i| rec.boot_incarnation.as_ref() == Some(i))
            .filter(|_| gw.identity_trusted.load(Relaxed) && !*live.exited.borrow())
            .ok_or_else(|| unverified("the gateway's process identity is not confirmed"))?;
        Ok((rec, live, incarnation))
    }

    /// One readback, the namespace's turn held by the caller.
    async fn read_gateway_policy(
        &self,
        gw: &Arc<Entry>,
        challenge: &str,
    ) -> Result<api::GatewayPolicyStatus, MError> {
        let (rec, live, incarnation) = self.gateway_identity(gw)?;
        let binding = rec
            .gateway_policy
            .clone()
            .ok_or_else(|| unverified("the gateway carries no loaded policy"))?;
        let request = guest::Request {
            op: "exec".into(),
            cmd: vec![HELPER.into(), "policy-status".into(), challenge.into()],
            cwd: "/".into(),
            timeout_ms: GUEST_TIMEOUT_MS,
            ..Default::default()
        };
        let answer = async {
            let mut conn = self.inner.guest.session(&live.vsock, request).await?;
            guestc::collect_limited(&mut conn, REPORT_LIMIT).await
        };
        let out = tokio::time::timeout(OUTER, answer)
            .await
            .map_err(|_| unverified("the helper did not answer in time"))?
            .map_err(|_| unverified("the helper could not be run or answered too much"))?;
        if out.timed_out || out.code != 0 || !out.stderr.is_empty() {
            return Err(unverified("the helper did not exit cleanly"));
        }
        let report: api::GatewayPolicyReport = serde_json::from_slice(&out.stdout)
            .map_err(|_| unverified("the helper's answer is not exactly one report"))?;
        if report.challenge != challenge || !report.ready {
            return Err(unverified("the report does not answer this challenge"));
        }
        if report.policy_format != binding.policy_format
            || report.policy_digest != binding.policy_digest
            || report.enforcement_version != binding.enforcement_version
        {
            return Err(unverified("the loaded policy is not the gateway's binding"));
        }
        let (after, _, again) = self.gateway_identity(gw)?;
        if again != incarnation || after.id != rec.id || after.gateway_policy != rec.gateway_policy
        {
            return Err(unverified(
                "the gateway's process changed during the readback",
            ));
        }
        Ok(api::GatewayPolicyStatus {
            namespace: rec.namespace,
            machine_id: rec.id,
            native_incarnation: api::NativeIncarnation {
                pid: incarnation.pid,
                start_ticks: incarnation.start_ticks,
                host_boot_id: incarnation.host_boot_id,
            },
            report,
        })
    }

    pub(super) async fn verify_gateway(
        &self,
        gw: &Arc<Entry>,
        asked: bool,
        turn: &GatewayTurn,
    ) -> Result<(), MError> {
        let (reply, result) = oneshot::channel();
        let (manager, gateway, turn) = (self.clone(), gw.clone(), turn.clone());
        tokio::spawn(async move {
            let _turn = turn;
            let (_entry, live, ready) =
                match Box::pin(manager.gateway_serving(&gateway, asked)).await {
                    Ok(serving) => serving,
                    Err(error) => {
                        let _ = reply.send(Err(error));
                        return;
                    }
                };
            let ip = gateway.rec.lock().unwrap().ip.clone();
            *gateway.gateway_proof.lock().unwrap() = None;
            let prepared = async {
                manager
                    .change_gateway_gate(&gateway, &live, &ip, true)
                    .await?;
                if ready.is_err() {
                    return Err(unverified("the gateway did not become ready"));
                }
                if reply.is_closed() {
                    return Err(unverified("admission was cancelled"));
                }
                let proof = Box::pin(manager.read_gateway_proof(&gateway, &live)).await?;
                if reply.is_closed() {
                    return Err(unverified("admission was cancelled"));
                }
                if let Err(error) = manager
                    .change_gateway_gate(&gateway, &live, &ip, false)
                    .await
                {
                    if !*live.exited.borrow() {
                        manager
                            .change_gateway_gate(&gateway, &live, &ip, true)
                            .await?;
                    }
                    return Err(error);
                }
                Ok(proof)
            }
            .await;
            match prepared {
                Err(error) => {
                    let _ = reply.send(Err(error));
                }
                Ok(proof) => {
                    let (commit, committed) = oneshot::channel();
                    if reply.send(Ok((proof, commit))).is_err() || committed.await.is_err() {
                        let _ = manager
                            .change_gateway_gate(&gateway, &live, &ip, true)
                            .await;
                    }
                }
            }
        });
        let (proof, commit) = result
            .await
            .map_err(|_| unverified("verification owner lost"))??;
        let exited = proof.exited.clone();
        if exited.has_changed().is_err() {
            return Err(unverified("the gateway's exit proof is unavailable"));
        }
        let exit = exited.borrow();
        if *exit || !proof.matches(gw) {
            return Err(unverified(
                "the gateway's record or process changed before admission",
            ));
        }
        let mut stored = gw.gateway_proof.lock().unwrap();
        *stored = Some(proof);
        if commit.send(()).is_err() {
            *stored = None;
            return Err(unverified("verification owner lost"));
        }
        Ok(())
    }

    async fn read_gateway_proof(
        &self,
        gw: &Arc<Entry>,
        expected: &fc::Vm,
    ) -> Result<GatewayProof, MError> {
        let (rec, live, incarnation) = self.gateway_identity(gw)?;
        if !same_gateway_process(&live, expected) {
            return Err(unverified(
                "the gateway's process changed before the readback",
            ));
        }
        let proof = GatewayProof {
            incarnation,
            binding: rec
                .gateway_policy
                .ok_or_else(|| unverified("the gateway carries no loaded policy"))?,
            exited: live.exited,
            namespace: rec.namespace,
            id: rec.id,
            ip: rec.ip,
            version: rec.version,
        };
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let status = Box::pin(self.read_gateway_policy(gw, &hex::encode(nonce))).await?;
        if proof.incarnation.pid != status.native_incarnation.pid
            || proof.incarnation.start_ticks != status.native_incarnation.start_ticks
            || proof.incarnation.host_boot_id != status.native_incarnation.host_boot_id
            || proof.exited.has_changed().is_err()
            || *proof.exited.borrow()
            || !proof.matches(gw)
        {
            return Err(unverified(
                "the gateway's process changed during the readback",
            ));
        }
        Ok(proof)
    }

    async fn change_gateway_gate(
        &self,
        gw: &Arc<Entry>,
        live: &fc::Vm,
        ip: &str,
        closed: bool,
    ) -> Result<(), MError> {
        let command = self.inner.net.gateway_gate(ip, closed);
        tokio::pin!(command);
        tokio::select! {
            biased;
            result = &mut command => match result {
                Ok(()) => Ok(()),
                Err(_) if !closed => Err(unverified("the bridge gate did not open")),
                Err(_) => Err(self.isolate_gateway(gw, live).await),
            },
            _ = tokio::time::sleep(nft::GATE_TIMEOUT) => {
                let (failure, _) = tokio::join!(self.isolate_gateway(gw, live), command);
                Err(failure)
            }
        }
    }

    async fn isolate_gateway(&self, gw: &Arc<Entry>, live: &fc::Vm) -> MError {
        if !gw.gateway_isolating.swap(true, Relaxed) {
            *gw.stop_req.lock().unwrap() = Some(stop::HOST.into());
            gw.rec.lock().unwrap().error = ISOLATION_UNCONFIRMED.into();
            let _ = self.save(gw);
            let held = gw
                .live
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|vm| same_gateway_process(vm, live));
            if held
                && self
                    .confirm_process_exit(gw, live, Duration::ZERO)
                    .await
                    .is_ok()
            {
                return unverified("the bridge gate failed; the gateway process exited");
            }
            tracing::error!(
                machine = gw.rec.lock().unwrap().id.as_str(),
                "{ISOLATION_UNCONFIRMED}"
            );
        }
        MError::GatewayPolicy(ISOLATION_UNCONFIRMED.into())
    }

    pub(super) fn check_gateway_isolation(&self, gw: &Entry) -> Result<(), MError> {
        if gw.gateway_isolating.load(Relaxed) {
            return Err(MError::GatewayPolicy(ISOLATION_UNCONFIRMED.into()));
        }
        Ok(())
    }

    /// Whether the namespace's gateway still has the proof of its current process and carries
    /// what `required` names: checked just before a machine is reserved or published, with the
    /// namespace's turn held.
    pub(super) fn gateway_still_verified(
        &self,
        namespace: &str,
        required: Option<&api::GatewayPolicyBinding>,
    ) -> Result<(), MError> {
        let gw = self
            .gateway_of(namespace)
            .ok_or_else(|| no_gateway(namespace))?;
        self.check_gateway_isolation(&gw)?;
        let rec = gw.snapshot();
        if required.is_some() && required != rec.gateway_policy.as_ref() {
            return Err(unverified("the gateway does not carry the required policy"));
        }
        let Some(binding) = rec.gateway_policy else {
            return Ok(());
        };
        let proved = gw.gateway_proof.lock().unwrap();
        match proved.as_ref() {
            Some(p)
                if p.binding == binding
                    && p.exited.has_changed().is_ok()
                    && !*p.exited.borrow()
                    && p.matches(&gw) =>
            {
                Ok(())
            }
            _ => Err(unverified("no readback of the gateway's current process")),
        }
    }

    /// Closes the gate before a bound gateway is attached or booted, and drops its proof.
    pub(super) async fn close_gateway_gate(&self, gw: &Arc<Entry>) -> Result<()> {
        let ip = {
            let rec = gw.rec.lock().unwrap();
            if !rec.is_gateway() || rec.gateway_policy.is_none() {
                return Ok(());
            }
            rec.ip.clone()
        };
        *gw.gateway_proof.lock().unwrap() = None;
        self.inner.net.gateway_gate(&ip, true).await
    }

    /// A machine of the namespace, in any state, bound to a gateway's loaded policy: the
    /// gateway outlives it.
    pub(super) fn has_bound_consumer(&self, namespace: &str) -> bool {
        self.inner.machines.lock().unwrap().values().any(|e| {
            let r = e.rec.lock().unwrap();
            r.namespace == namespace && r.egress.gateway_policy.is_some()
        }) || self
            .assignment_targets()
            .iter()
            .any(|r| r.namespace == namespace && r.egress.gateway_policy.is_some())
    }

    /// The restart policy brings a bound gateway back through the same fence a start has:
    /// the namespace's turn, then the gateway's, then a readback before the gate opens.
    pub(super) async fn restart_bound_gateway(&self, gw: &Arc<Entry>) {
        let namespace = gw.snapshot().namespace;
        let Some(t) = self.namespace_of(&namespace) else {
            return;
        };
        let turn = Arc::new(t.lock.clone().lock_owned().await);
        {
            let _turns = gw.lock_for_start().await;
            let r = gw.snapshot();
            if r.state != state::STOPPED || r.stopped_reason != stop::EXIT {
                return;
            }
        }
        match self.run_gateway(gw, false, &turn).await {
            Ok(()) => {}
            Err(err @ (MError::BootFailed(_) | MError::GatewayPolicy(_))) => {
                tracing::warn!(machine = gw.snapshot().id, err = %err, "restart")
            }
            Err(err) => tracing::error!(machine = gw.snapshot().id, err = %err, "restart"),
        }
    }

    /// The bound gateways a daemon found running when it started: their gate was rendered
    /// closed, and opens only once their process is read back.
    pub(super) fn adopted_bound_gateways(&self) -> Vec<Arc<Entry>> {
        self.inner
            .machines
            .lock()
            .unwrap()
            .values()
            .filter(|e| {
                let r = e.rec.lock().unwrap();
                r.is_gateway() && r.gateway_policy.is_some() && r.state == state::RUNNING
            })
            .cloned()
            .collect()
    }
}

pub(super) fn same_gateway_process(a: &fc::Vm, b: &fc::Vm) -> bool {
    a.pid == b.pid && a.incarnation == b.incarnation && a.exited.same_channel(&b.exited)
}
