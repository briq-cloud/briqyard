use super::*;
use admission::{AuthorityTransitionView, Error, PreparedWitness};
use ring::rand::{SecureRandom, SystemRandom};
use sealed::{
    objects::{Bind, ProjectionAction, ProofQuery, Q},
    prim::Nonce,
    sig::{Signer, Tag},
    transition::{self as t, ApiState, ApiView, OwnerCap, Packet},
};
use std::sync::Arc;

const FRESH: Duration = Duration::from_secs(5);

/// The same verifier can issue independent challenges without holding the journal turn.
/// It belongs to one live issuer and carries no writer or signing key.
pub struct AuthorityVerifier {
    scope: Arc<GuardedKeys>,
    reader: admission::JournalReader,
}

/// One bounded exchange. Only this value can verify the replies to its two queries.
pub struct AuthorityChallenge<'a> {
    scope: Arc<GuardedKeys>,
    packet: &'a Packet,
    view: AuthorityTransitionView,
    host: ProofQuery,
    api: ProofQuery,
    issued: Instant,
    deadline: Instant,
}

/// A consumed exchange for exactly one action, packet, issuer, and original snapshot.
pub struct AuthorityActionProof<'a> {
    scope: Arc<GuardedKeys>,
    permit: &'a SealedPermit,
    view: AuthorityTransitionView,
    host: HRead,
    sample: clock::ClockSample,
    deadline: Instant,
}

fn binding(_: impl std::fmt::Debug) -> Error {
    Error::Binding
}

impl AuthorityVerifier {
    pub fn sample(&self) -> Result<clock::ClockSample, Error> {
        (self.scope.clock)().ok_or(Error::Persistence)
    }

    pub fn snapshot(&self) -> Result<AuthorityTransitionView, Error> {
        let view = self.reader.view().authority_transition()?;
        view.verify_origin(&self.scope.bk, &self.scope.ak)?;
        Ok(view)
    }

    pub fn challenge<'a>(
        &self,
        action: ClaimKind,
        packet: &'a Packet,
        received: Instant,
    ) -> Result<AuthorityChallenge<'a>, Error> {
        let deadline = received.checked_add(FRESH).ok_or(Error::Binding)?;
        let now = Instant::now();
        if now < received
            || now >= deadline
            || !matches!(
                action,
                ClaimKind::Adopt | ClaimKind::Register | ClaimKind::RecordAck
            )
        {
            return Err(Error::Binding);
        }
        let view = self.snapshot()?;
        let scope = &self.scope;
        let ticket = &packet.p.body;
        let bind = &ticket.bind;
        let guard = view.guard();
        if ticket.action != action
            || ticket.authority_proc != guard.proc
            || ticket.daemon_proc != scope.host_proc
            || ticket.retired != scope.retirement
            || guard.plan != scope.plan_hash
            || ticket.auth_guard.as_ref() != Some(&guard.hash().map_err(binding)?)
            || bind.record.authority != scope.plan.pre_record.authority
            || bind.record.epoch == scope.plan.pre.epoch
            || bind.record.host_instance != scope.host_instance
            || bind.intent == scope.plan.pre_intent
        {
            return Err(Error::Binding);
        }
        t::check_bind_plan(bind, &scope.plan_hash, &scope.plan).map_err(binding)?;
        packet.validate().map_err(binding)?;
        packet
            .verify_decision(&scope.bk, &scope.rk)
            .map_err(binding)?;
        let mut nonces = [
            packet.bh.body.q.nonce,
            packet.rh.body.q.nonce,
            packet.ba.body.q.nonce,
            packet.ra.body.q.nonce,
        ];
        nonces.sort_unstable();
        if nonces.windows(2).any(|p| p[0] == p[1]) {
            return Err(Error::Binding);
        }
        for read in [&packet.bh, &packet.rh] {
            scope.verify_host(read, &read.body.q)?;
        }
        for read in [&packet.ba, &packet.ra] {
            let body = read
                .verify(Tag::AuthorityRead, &scope.ak)
                .map_err(binding)?;
            body.host_clock
                .verify(Tag::HostClock, &scope.hk)
                .map_err(binding)?;
            body.check_host(&scope.host_proc, &scope.host_instance)
                .map_err(binding)?;
            body.check_selection(Some(bind)).map_err(binding)?;
        }
        let query = || {
            let mut raw = [0; 32];
            SystemRandom::new().fill(&mut raw).map_err(binding)?;
            let nonce = Nonce::from_array(raw);
            if nonces.contains(&nonce) {
                return Err(Error::Binding);
            }
            Ok(ProofQuery {
                q: Q {
                    x: scope.plan.x.clone(),
                    nonce,
                },
                plan: scope.plan_hash.clone(),
                preview: None,
            })
        };
        let issued = Instant::now();
        let host = query()?;
        let api = query()?;
        if host.q.nonce == api.q.nonce || Instant::now() >= deadline {
            return Err(Error::Binding);
        }
        Ok(AuthorityChallenge {
            scope: scope.clone(),
            packet,
            view,
            host,
            api,
            issued,
            deadline,
        })
    }
}

impl GuardedKeys {
    fn verify_host(&self, read: &HRead, query: &Q) -> Result<(), Error> {
        let host = read.verify(Tag::HostRead, &self.hk).map_err(binding)?;
        let receipt = host.gate.receipt.as_ref().ok_or(Error::Binding)?;
        t::verify_receipt(receipt, &self.hk).map_err(binding)?;
        if host.q != *query
            || host.q.x != self.plan.x
            || host.plan != self.plan_hash
            || host.proc != self.host_proc
            || host.gate.instance != self.host_instance
            || h(receipt).map_err(binding)? != self.retirement
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
}

impl<'a> AuthorityChallenge<'a> {
    pub fn host_query(&self) -> &ProofQuery {
        &self.host
    }

    pub fn api_query(&self) -> &ProofQuery {
        &self.api
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    pub fn finish(self, host: HRead, api: &ApiView) -> Result<AuthorityActionProof<'a>, Error> {
        if Instant::now() >= self.deadline {
            return Err(Error::Binding);
        }
        self.scope.verify_host(&host, &self.host.q)?;
        let api = api.verify(Tag::ApiRead, &self.scope.bk).map_err(binding)?;
        let packet = self.packet;
        let ticket = &packet.p.body;
        let bind = &ticket.bind;
        let permit_hash = h(&packet.p).map_err(binding)?;
        if host.body.gate != packet.bh.body.gate
            || host.body.water != packet.bh.body.water
            || host.body.cap.actual != packet.bh.body.cap.actual
            || host.body.cap.actual != packet.rh.body.cap.actual
            || api.q != self.api.q
            || api.plan != self.scope.plan_hash
        {
            return Err(Error::Binding);
        }
        let sample = (self.scope.clock)().ok_or(Error::Persistence)?;
        if sample.monotonic < self.issued {
            return Err(Error::Binding);
        }
        let clock = sample.interval().ok_or(Error::Binding)?;
        let state = self.view.registration_state(Some(bind), clock)?;
        let action = ticket.action;
        let observing = action == ClaimKind::RecordAck && state.ready;
        if observing && api.state == ApiState::Observed {
            api.check_release_ready(bind, &ticket.claim)
                .map_err(binding)?;
            if api.permit.as_ref() != Some(&permit_hash) {
                return Err(Error::Binding);
            }
        } else {
            api.check_crossing(bind, action, &ticket.claim, &permit_hash)
                .map_err(binding)?;
        }
        let capacity = self
            .view
            .capacity(Some(bind), &self.scope.host_proc, clock)?;
        let (row, host_row) = match action {
            ClaimKind::Adopt | ClaimKind::Register => (
                ProjectionAction::AuthorityIntent,
                Some(ProjectionAction::HostRegister),
            ),
            ClaimKind::RecordAck => (ProjectionAction::AuthorityAck, None),
            _ => return Err(Error::Binding),
        };
        if state.uncertain {
            return Err(Error::Binding);
        }
        if !observing {
            require_capacity(&capacity, row, bind)?;
        }
        let archived_intent = if observing {
            self.view.origin()
        } else {
            state.intent.as_ref()
        };
        for archived in [&packet.ba.body, &packet.ra.body] {
            if archived.guard != *self.view.guard()
                || archived.native_water.get() != state.water
                || archived.ready
                || archived.uncertain != state.uncertain
                || archived.intent.as_ref() != archived_intent
                || (!observing && archived.cap.actual != capacity.actual)
            {
                return Err(Error::Binding);
            }
            require_capacity(&archived.cap, row, bind)?;
        }
        if let Some(row) = host_row {
            for observed in [&host.body, &packet.bh.body, &packet.rh.body] {
                require_capacity(&observed.cap, row, bind)?;
            }
        }
        let proof = AuthorityActionProof {
            scope: self.scope,
            permit: &packet.p,
            view: self.view,
            host,
            sample,
            deadline: self.deadline,
        };
        proof.time().check((!observing).then_some(&packet.p))?;
        Ok(proof)
    }
}

fn require_capacity(cap: &OwnerCap, action: ProjectionAction, bind: &Bind) -> Result<(), Error> {
    t::require_fit(cap, &[action]).map_err(binding)?;
    let row = cap
        .projections
        .iter()
        .find(|r| r.action == action)
        .ok_or(Error::Binding)?;
    if row.target.as_ref() != Some(&admission::transition_projection_target(action, bind)?)
        || row.expected_ack.as_ref() != Some(&bind.record.ack())
    {
        return Err(Error::Binding);
    }
    Ok(())
}

impl AuthorityActionProof<'_> {
    fn time(&self) -> GuardedTime<'_> {
        GuardedTime {
            sample: &self.sample,
            request_deadline: self.deadline,
        }
    }

    fn qualified_after_write(&self, before: Clock, deadline: Instant) -> Option<Instant> {
        let committed = Instant::now();
        let after = (self.scope.clock)()?;
        if after.monotonic < committed || !after.follows(&self.sample) {
            return None;
        }
        let (current, deadline) = GuardedTime {
            sample: &after,
            request_deadline: deadline,
        }
        .check(Some(self.permit))
        .ok()?;
        (current.now >= before.now).then_some(deadline)
    }

    pub fn prepare_witness(&self, signer: &dyn Signer) -> Result<PreparedWitness, Error> {
        if self.permit.body.action != ClaimKind::Register
            || signer.public_key() != *self.scope.ak.raw()
        {
            return Err(Error::Binding);
        }
        self.time().check(Some(self.permit))?;
        self.view.prepare_witness(self.permit, signer)
    }
}

impl DurableIssuer {
    pub fn authority_verifier(&self) -> Result<AuthorityVerifier, Error> {
        Ok(AuthorityVerifier {
            scope: self.guarded.as_ref().ok_or(Error::Binding)?.clone(),
            reader: self.reader(),
        })
    }

    pub fn adopt_guard(&mut self, proof: AuthorityActionProof<'_>) -> Result<(), Error> {
        self.check_action(&proof, ClaimKind::Adopt)?;
        let (clock, deadline) = proof.time().check(Some(proof.permit))?;
        self.journal.adopt_guard(&proof.view, proof.permit, clock)?;
        self.check_commit_deadline(deadline)
    }

    pub fn begin_original_registration(
        &mut self,
        proof: AuthorityActionProof<'_>,
        prepared: PreparedWitness,
    ) -> Result<(Witness, Instant), Error> {
        self.check_action(&proof, ClaimKind::Register)?;
        let (clock, deadline) = proof.time().check(Some(proof.permit))?;
        let witness = self.journal.begin_origin(
            &proof.view,
            proof.permit,
            prepared,
            &proof.scope.ak,
            clock,
        )?;
        self.check_commit_deadline(deadline)?;
        let deadline = proof
            .qualified_after_write(clock, deadline)
            .ok_or(Error::Persistence)?;
        Ok((witness, deadline))
    }

    pub fn record_original_ack(&mut self, proof: AuthorityActionProof<'_>) -> Result<bool, Error> {
        self.check_action(&proof, ClaimKind::RecordAck)?;
        let (clock, _) = proof.time().check(None)?;
        let observing = proof.view.registration_state(None, clock)?.ready;
        let (clock, deadline) = proof.time().check((!observing).then_some(proof.permit))?;
        let done = proof.host.body.gate.done.as_ref().ok_or(Error::Binding)?;
        let mut armed = proof.host.body.gate.clone();
        armed.phase = GatePhase::Armed;
        armed.done = None;
        if proof.view.guard().armed_gate.as_ref() != Some(&armed.hash().map_err(binding)?) {
            return Err(Error::Binding);
        }
        let changed = self.journal.record_origin_ack(&proof.view, done, clock)?;
        if changed && proof.qualified_after_write(clock, deadline).is_none() {
            self.journal.refuse_transition_readiness()?;
            return Err(Error::Persistence);
        }
        Ok(changed)
    }

    fn check_action(
        &self,
        proof: &AuthorityActionProof<'_>,
        action: ClaimKind,
    ) -> Result<(), Error> {
        let scope = self.guarded.as_ref().ok_or(Error::Binding)?;
        if !Arc::ptr_eq(scope, &proof.scope) || proof.permit.body.action != action {
            return Err(Error::Binding);
        }
        Ok(())
    }
}
