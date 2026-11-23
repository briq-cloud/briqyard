use super::capacity::dimensions;
use super::*;
use crate::execution::channel::InstallationAck;
use sealed::{
    canonical::{encode, h, Wire},
    objects::{Ack, Bind, ClaimKind, Plan, Proc, Projection, ProjectionAction, Reg},
    prim::{HexDigest, Nonce, PosInt, SigBytes, Uint},
    sig::{PinnedKey, Signer, Tag},
    transition::{
        self as t, Guard, GuardPhase, Intent, IntentPhase, OwnerCap, RegDone, Ticket, Witness,
        WitnessBody,
    },
};

#[cfg(test)]
mod tests;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SealedAuthority {
    guard: Guard,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    origin: Option<OriginIntent>,
}

impl SealedAuthority {
    pub(super) fn started(guard: Guard) -> Self {
        Self {
            guard,
            origin: None,
        }
    }
}

/// The crossing evidence is immutable, including the original *pending* phase.
/// Readiness lives in the matching native authority row, not a second registration.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginIntent {
    original: Intent,
    permit: String,
    witness: String,
    send_consumed: sealed::prim::LitBool<true>,
}

impl OriginIntent {
    fn permit_bytes(&self) -> &[u8] {
        self.permit.as_bytes()
    }

    fn witness_bytes(&self) -> &[u8] {
        self.witness.as_bytes()
    }

    fn decode(&self) -> Result<(t::Permit, Witness), Error> {
        Ok((
            t::Permit::decode(self.permit_bytes(), Tag::Decision).map_err(binding)?,
            Witness::decode(self.witness_bytes(), Tag::Intent).map_err(binding)?,
        ))
    }

    fn verify(&self, bk: &PinnedKey, ak: &PinnedKey) -> Result<(), Error> {
        let (permit, witness) = self.decode()?;
        permit.verify(Tag::Decision, bk).map_err(binding)?;
        witness.verify(Tag::Intent, ak).map_err(binding)?;
        Ok(())
    }

    fn matches_done(&self, done: &RegDone, bind: &Bind) -> bool {
        done.bind == *bind
            && done.claim == self.original.claim
            && done.permit == self.original.permit
            && done.witness == self.original.witness
            && done.ack == self.original.record.ack()
            && done.host_water == self.original.record.generation
    }
}

fn binding(_: impl std::fmt::Debug) -> Error {
    Error::Binding
}

fn registration_key(guard: &Guard) -> String {
    format!("registration:{}", guard.x.host)
}

fn water(state: &State, guard: &Guard) -> u64 {
    state
        .authority_highwater
        .get(&registration_key(guard))
        .copied()
        .unwrap_or(0)
}

fn native_ack(ack: &Ack) -> InstallationAck {
    InstallationAck {
        host_instance: ack.host_instance.to_string(),
        generation: ack.generation.get(),
        digest: ack.digest.to_text(),
    }
}

fn native_record(bind: &Bind) -> HostRegistration {
    let r = &bind.record;
    HostRegistration {
        authority: r.authority.to_string(),
        epoch: r.epoch.to_string(),
        key_id: r.key_id.to_string(),
        public_key: r.public_key,
        host_instance: r.host_instance.to_string(),
        generation: r.generation.get(),
    }
}

pub(super) fn validate_predecessor(state: &State, plan: &Plan) -> Result<(), Error> {
    let key = format!("registration:{}", plan.x.host);
    let id = plan.pre_intent.as_str();
    let row = state.authority_intents.get(id).ok_or(Error::Binding)?;
    let AuthorityPayload::Registration(record) = &row.payload else {
        return Err(Error::Binding);
    };
    let ack = plan.pre_record.ack();
    if state.instance != plan.pre_record.epoch.as_str()
        || row.authority_epoch != state.instance
        || row.host != plan.x.host.as_str()
        || row.host_instance != plan.pre_record.host_instance.as_str()
        || Reg::from_native(record).map_err(binding)? != plan.pre_record
        || state.authority_highwater.get(&key) != Some(&plan.pre_record.generation.get())
        || state
            .uncertain_installations
            .contains(&format!("authority:{id}"))
        || !row
            .acknowledgement
            .as_ref()
            .is_some_and(|a| ack_matches(a, &ack))
    {
        return Err(Error::Binding);
    }
    Ok(())
}

fn ack_matches(native: &InstallationAck, expected: &Ack) -> bool {
    native.host_instance == expected.host_instance.as_str()
        && native.generation == expected.generation.get()
        && native.digest == expected.digest.to_text()
}

pub(super) fn validate_state(state: &State) -> Result<(), Error> {
    let Some(sealed) = &state.sealed_authority else {
        return Ok(());
    };
    let Role::Authority(authority) = &state.role else {
        return Err(Error::Binding);
    };
    let guard = &sealed.guard;
    guard.validate().map_err(binding)?;
    encode(guard).map_err(binding)?;
    if !valid_id(authority)
        || state.instance != guard.epoch.as_str()
        || state.registration.is_some()
        || state.registration_highwater != 0
        || state.clock_floor > MAX_SAFE_INTEGER
        || water(state, guard) > MAX_SAFE_INTEGER
        || guard
            .bind
            .as_ref()
            .is_some_and(|b| b.record.authority.as_str() != authority)
    {
        return Err(Error::Binding);
    }
    let Some(bind) = &guard.bind else {
        return if sealed.origin.is_none() {
            Ok(())
        } else {
            Err(Error::Binding)
        };
    };
    let row = state.authority_intents.get(bind.intent.as_str());
    let Some(origin) = &sealed.origin else {
        return if row.is_none() && water(state, guard) == bind.prior.get() {
            Ok(())
        } else {
            Err(Error::Binding)
        };
    };
    let row = row.ok_or(Error::Binding)?;
    let (p, w) = origin.decode()?;
    let original = &origin.original;
    original.validate().map_err(binding)?;
    if original.phase != IntentPhase::Pending
        || original.id != bind.intent
        || original.record != bind.record
        || original.guard != guard.hash().map_err(binding)?
        || original.witness != HexDigest::of(origin.witness_bytes())
        || original.permit != HexDigest::of(origin.permit_bytes())
        || p.body.action != ClaimKind::Register
        || p.body.bind != *bind
        || p.body.claim != original.claim
        || p.body.auth_guard.as_ref() != Some(&original.guard)
        || Some(&p.body.prior_gate) != guard.armed_gate.as_ref()
        || p.body.authority_proc != guard.proc
        || w.body != witness_body(guard, bind, original.claim, original.permit.clone())?
        || row.host != bind.x.host.as_str()
        || row.host_instance != bind.record.host_instance.as_str()
        || row.authority_epoch != guard.epoch.as_str()
        || row.payload != AuthorityPayload::Registration(native_record(bind))
        || row.registration_dependency.is_some()
        || row.discovery_dependency.is_some()
        || row.instance_confirmed
        || row
            .acknowledgement
            .as_ref()
            .is_some_and(|a| !ack_matches(a, &bind.record.ack()))
        || water(state, guard) != bind.record.generation.get()
    {
        return Err(Error::Binding);
    }
    Ok(())
}

fn witness_body(
    guard: &Guard,
    bind: &Bind,
    claim: Nonce,
    permit: HexDigest,
) -> Result<WitnessBody, Error> {
    Ok(WitnessBody {
        x: guard.x.clone(),
        plan: guard.plan.clone(),
        bind: bind.clone(),
        claim,
        permit,
        guard: guard.hash().map_err(binding)?,
        proc: guard.proc.clone(),
        authority_water: bind.record.generation,
        intent: bind.intent.clone(),
    })
}

fn make_origin(permit: &t::Permit, witness: &Witness) -> Result<OriginIntent, Error> {
    let bytes = |value: Vec<u8>| String::from_utf8(value).map_err(binding);
    let p = bytes(encode(permit).map_err(binding)?)?;
    let w = bytes(encode(witness).map_err(binding)?)?;
    Ok(OriginIntent {
        original: Intent {
            id: witness.body.intent.clone(),
            record: witness.body.bind.record.clone(),
            claim: witness.body.claim,
            permit: HexDigest::of(p.as_bytes()),
            guard: witness.body.guard.clone(),
            witness: HexDigest::of(w.as_bytes()),
            phase: IntentPhase::Pending,
            ack: None,
        },
        permit: p,
        witness: w,
        send_consumed: sealed::prim::LitBool,
    })
}

fn put_origin(state: &mut State, bind: &Bind, origin: OriginIntent) -> Result<(), Error> {
    let sealed = state.sealed_authority.as_mut().ok_or(Error::Binding)?;
    if sealed.origin.is_some() || state.authority_intents.contains_key(bind.intent.as_str()) {
        return Err(Error::AlreadyAdmitted);
    }
    state.authority_highwater.insert(
        registration_key(&sealed.guard),
        bind.record.generation.get(),
    );
    state.authority_intents.insert(
        bind.intent.to_string(),
        AuthorityIntent {
            host: bind.x.host.to_string(),
            host_instance: bind.record.host_instance.to_string(),
            authority_epoch: bind.record.epoch.to_string(),
            registration_dependency: None,
            discovery_dependency: None,
            payload: AuthorityPayload::Registration(native_record(bind)),
            acknowledgement: None,
            instance_confirmed: false,
        },
    );
    sealed.origin = Some(origin);
    Ok(())
}

fn ack_candidate(next: &mut State, bind: &Bind) -> Result<(), Error> {
    next.authority_intents
        .get_mut(bind.intent.as_str())
        .ok_or(Error::Binding)?
        .acknowledgement = Some(native_ack(&bind.record.ack()));
    Ok(())
}

fn reserve_ack(mut next: State, bind: &Bind) -> Result<State, Error> {
    ack_candidate(&mut next, bind)?;
    next.uncertain_installations
        .insert(format!("authority:{}", bind.intent));
    next.clock_floor = MAX_SAFE_INTEGER;
    Ok(next)
}

/// An immutable snapshot from the owned journal, never a router/cohort pointer.
pub struct AuthorityTransitionView(JournalView);

/// Inert outside the issuer: the signature is never exposed before the journal commits.
pub struct PreparedWitness(Witness);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationState {
    pub water: u64,
    pub intent: Option<Intent>,
    pub uncertain: bool,
    pub ready: bool,
}

impl JournalView {
    pub fn is_guarded_authority(&self) -> bool {
        self.state.sealed_authority.is_some()
    }

    pub fn authority_transition(&self) -> Result<AuthorityTransitionView, Error> {
        self.owned()?;
        storage::guarded_clean(&self.fence.root)?;
        validate_state(&self.state)?;
        if !self.is_guarded_authority() {
            return Err(Error::Binding);
        }
        Ok(AuthorityTransitionView(self.clone()))
    }
}

impl AuthorityTransitionView {
    fn sealed(&self) -> &SealedAuthority {
        self.0
            .state
            .sealed_authority
            .as_ref()
            .expect("checked guarded snapshot")
    }

    pub fn guard(&self) -> &Guard {
        &self.sealed().guard
    }

    /// The original pending intent exposes commitments only, never the archived envelopes.
    pub fn origin(&self) -> Option<&Intent> {
        self.sealed().origin.as_ref().map(|origin| &origin.original)
    }

    pub(in crate::execution) fn verify_origin(
        &self,
        bk: &PinnedKey,
        ak: &PinnedKey,
    ) -> Result<(), Error> {
        if let Some(origin) = &self.sealed().origin {
            origin.verify(bk, ak)?;
        }
        Ok(())
    }

    pub fn same_snapshot(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0.state, &other.0.state) && Arc::ptr_eq(&self.0.fence, &other.0.fence)
    }

    pub(in crate::execution) fn prepare_witness(
        &self,
        permit: &t::Permit,
        signer: &dyn Signer,
    ) -> Result<PreparedWitness, Error> {
        self.0.owned()?;
        let guard = self.guard();
        let bind = guard.bind.as_ref().ok_or(Error::Binding)?;
        if self.origin().is_some() {
            return Err(Error::AlreadyAdmitted);
        }
        let ticket = &permit.body;
        if ticket.action != ClaimKind::Register
            || ticket.bind != *bind
            || ticket.auth_guard.as_ref() != Some(&guard.hash().map_err(binding)?)
            || Some(&ticket.prior_gate) != guard.armed_gate.as_ref()
            || ticket.authority_proc != guard.proc
        {
            return Err(Error::Binding);
        }
        let body = witness_body(guard, bind, ticket.claim, h(permit).map_err(binding)?)?;
        Witness::sign(Tag::Intent, body, signer)
            .map(PreparedWitness)
            .map_err(binding)
    }

    fn check_bind(&self, bind: &Bind) -> Result<(), Error> {
        let guard = self.guard();
        t::check_bind(bind).map_err(binding)?;
        let Role::Authority(authority) = self.0.role() else {
            return Err(Error::Binding);
        };
        if bind.x != guard.x
            || bind.plan != guard.plan
            || bind.set != guard.set
            || bind.record.authority.as_str() != authority
            || bind.record.epoch != guard.epoch
            || bind.record.key_id != guard.ordinary_kid
            || bind.record.public_key != *guard.ordinary_key.as_array()
            || guard.bind.as_ref().is_some_and(|b| b != bind)
        {
            return Err(Error::Binding);
        }
        Ok(())
    }

    pub fn registration_state(
        &self,
        selected: Option<&Bind>,
        clock: Clock,
    ) -> Result<RegistrationState, Error> {
        self.0.check(clock)?;
        if clock.uncertainty > 5 {
            return Err(Error::Binding);
        }
        if let Some(bind) = selected {
            self.check_bind(bind)?;
        }
        let selected = self.guard().bind.as_ref().or(selected);
        let water = water(&self.0.state, self.guard());
        let mut result = RegistrationState {
            water,
            intent: None,
            uncertain: false,
            ready: false,
        };
        if let Some(bind) = selected {
            let id = bind.intent.as_str();
            result.uncertain = self.0.installation_uncertain("authority", id);
            if let Some(origin) = self.origin() {
                let mut intent = origin.clone();
                result.ready = !result.uncertain && self.0.authority_intent_ready(id)?;
                if result.ready {
                    intent.phase = IntentPhase::Ready;
                    intent.ack = Some(bind.record.ack());
                }
                result.intent = Some(intent);
            } else if water != bind.prior.get() || self.0.authority_intent(id)?.is_some() {
                return Err(Error::Binding);
            }
        }
        Ok(result)
    }

    pub fn capacity(
        &self,
        selected: Option<&Bind>,
        host: &Proc,
        clock: Clock,
    ) -> Result<OwnerCap, Error> {
        let state = self.registration_state(selected, clock)?;
        let guard = self.guard();
        let basis = guard.hash().map_err(binding)?;
        let mut projections = [
            ProjectionAction::AuthorityIntent,
            ProjectionAction::AuthorityAck,
        ]
        .map(|action| Projection {
            action,
            basis: basis.clone(),
            target: None,
            next: None,
            reserve: None,
            expected_ack: None,
        });
        if let Some(bind) = guard
            .bind
            .as_ref()
            .or(selected)
            .filter(|_| !state.uncertain)
        {
            let mut next = State::clone(&self.0.state);
            next.clock_floor = clock.now;
            let i = match state.intent.as_ref().map(|i| i.phase) {
                None => {
                    put_reserved_origin(&mut next, bind, host)?;
                    Some(0)
                }
                Some(IntentPhase::Pending) => {
                    ack_candidate(&mut next, bind)?;
                    Some(1)
                }
                Some(IntentPhase::Ready) => None,
            };
            if let Some(i) = i {
                let reserve = reserve_ack(next.clone(), bind)?;
                let (next, reserve) = capacity::qualified_candidates(next, reserve, clock)?;
                let action = projections[i].action;
                projections[i].target = Some(transition_projection_target(action, bind)?);
                projections[i].next = if i == 1 {
                    Some(dimensions(&next)?)
                } else {
                    None
                };
                projections[i].reserve = Some(dimensions(&reserve)?);
                projections[i].expected_ack = Some(bind.record.ack());
            }
        }
        Ok(OwnerCap {
            actual: dimensions(&self.0.state)?,
            projections: projections.into(),
        })
    }
}

fn put_reserved_origin(next: &mut State, bind: &Bind, host: &Proc) -> Result<(), Error> {
    let hash = HexDigest::of(b"");
    let nonce = Nonce::from_array([0; 32]);
    let sig = SigBytes::from_array([0; 64]);
    let guard = &mut next.sealed_authority.as_mut().ok_or(Error::Binding)?.guard;
    if guard.phase == GuardPhase::Started {
        guard.phase = GuardPhase::Adopted;
        guard.bind = Some(bind.clone());
        guard.armed_gate = Some(hash.clone());
        guard.adoption = Some(hash.clone());
    }
    let ticket = Ticket {
        x: bind.x.clone(),
        plan: bind.plan.clone(),
        action: ClaimKind::Register,
        claim: nonce,
        owner: nonce,
        challenge: nonce,
        bind: bind.clone(),
        prior_gate: guard.armed_gate.clone().ok_or(Error::Binding)?,
        auth_guard: Some(guard.hash().map_err(binding)?),
        retired: hash.clone(),
        authority_proc: guard.proc.clone(),
        daemon_proc: host.clone(),
        host_proof: hash.clone(),
        authority_proof: hash.clone(),
        receiver_ok: hash.clone(),
        not_before: Uint::new(MAX_SAFE_INTEGER - 1).map_err(binding)?,
        expires: PosInt::new(MAX_SAFE_INTEGER).map_err(binding)?,
    };
    let p = t::Permit {
        tag: Tag::Decision,
        kid: hash.clone(),
        body: ticket,
        sig,
    };
    let w = Witness {
        tag: Tag::Intent,
        kid: hash,
        body: witness_body(guard, bind, nonce, h(&p).map_err(binding)?)?,
        sig,
    };
    put_origin(next, bind, make_origin(&p, &w)?)
}

impl Journal {
    fn check_transition(
        &self,
        expected: &AuthorityTransitionView,
        clock: Clock,
    ) -> Result<AuthorityTransitionView, Error> {
        self.check(clock)?;
        let current = self.authority_transition()?;
        if clock.uncertainty > 5 || !current.same_snapshot(expected) {
            return Err(Error::Binding);
        }
        Ok(current)
    }

    pub(in crate::execution) fn adopt_guard(
        &mut self,
        expected: &AuthorityTransitionView,
        permit: &t::Permit,
        clock: Clock,
    ) -> Result<(), Error> {
        let old = self.check_transition(expected, clock)?;
        let guard = old.guard();
        let ticket = &permit.body;
        let state = old.registration_state(Some(&ticket.bind), clock)?;
        if guard.phase != GuardPhase::Started
            || ticket.action != ClaimKind::Adopt
            || ticket.auth_guard.as_ref() != Some(&guard.hash().map_err(binding)?)
            || ticket.authority_proc != guard.proc
            || state.uncertain
            || state.intent.is_some()
        {
            return Err(Error::Binding);
        }
        let mut next = State::clone(&self.state);
        let guarded = next.sealed_authority.as_mut().ok_or(Error::Binding)?;
        guarded.guard.phase = GuardPhase::Adopted;
        guarded.guard.bind = Some(ticket.bind.clone());
        guarded.guard.armed_gate = Some(ticket.prior_gate.clone());
        guarded.guard.adoption = Some(h(permit).map_err(binding)?);
        next.clock_floor = clock.now;
        validate_state(&next)?;
        let mut reserve = next.clone();
        put_reserved_origin(&mut reserve, &ticket.bind, &ticket.daemon_proc)?;
        let reserve = reserve_ack(reserve, &ticket.bind)?;
        self.commit_guarded(next, clock, reserve)
    }

    pub(in crate::execution) fn begin_origin(
        &mut self,
        expected: &AuthorityTransitionView,
        permit: &t::Permit,
        prepared: PreparedWitness,
        ak: &PinnedKey,
        clock: Clock,
    ) -> Result<Witness, Error> {
        let old = self.check_transition(expected, clock)?;
        let guard = old.guard();
        let bind = guard.bind.as_ref().ok_or(Error::Binding)?;
        if old.origin().is_some() {
            return Err(Error::AlreadyAdmitted);
        }
        let state = old.registration_state(Some(bind), clock)?;
        let ticket = &permit.body;
        if ticket.action != ClaimKind::Register
            || ticket.bind != *bind
            || ticket.auth_guard.as_ref() != Some(&guard.hash().map_err(binding)?)
            || Some(&ticket.prior_gate) != guard.armed_gate.as_ref()
            || ticket.authority_proc != guard.proc
            || state.uncertain
        {
            return Err(Error::Binding);
        }
        let witness = prepared.0;
        if witness.body != witness_body(guard, bind, ticket.claim, h(permit).map_err(binding)?)? {
            return Err(Error::Binding);
        }
        witness.verify(Tag::Intent, ak).map_err(binding)?;
        let mut next = State::clone(&self.state);
        put_origin(&mut next, bind, make_origin(permit, &witness)?)?;
        next.clock_floor = clock.now;
        validate_state(&next)?;
        let reserve = reserve_ack(next.clone(), bind)?;
        self.commit_guarded(next, clock, reserve)?;
        Ok(witness)
    }

    pub(in crate::execution) fn record_origin_ack(
        &mut self,
        expected: &AuthorityTransitionView,
        done: &RegDone,
        clock: Clock,
    ) -> Result<bool, Error> {
        let old = self.check_transition(expected, clock)?;
        let bind = old.guard().bind.as_ref().ok_or(Error::Binding)?;
        let state = old.registration_state(Some(bind), clock)?;
        let origin = old.sealed().origin.as_ref().ok_or(Error::Binding)?;
        if state.uncertain || !origin.matches_done(done, bind) {
            return Err(Error::Binding);
        }
        if state.ready {
            return Ok(false);
        }
        let mut next = State::clone(&self.state);
        ack_candidate(&mut next, bind)?;
        next.clock_floor = clock.now;
        let reserve = reserve_ack(next.clone(), bind)?;
        self.commit_guarded(next, clock, reserve)?;
        Ok(true)
    }

    pub(in crate::execution) fn refuse_transition_readiness(&mut self) -> Result<(), Error> {
        let result = (|| {
            let current = self.authority_transition()?;
            let id = &current.guard().bind.as_ref().ok_or(Error::Binding)?.intent;
            let mut next = State::clone(&self.state);
            next.uncertain_installations
                .insert(format!("authority:{id}"));
            self.persist(next)
        })();
        if result.is_err() {
            self.fence.poisoned.store(true, Ordering::SeqCst);
        }
        result
    }

    fn commit_guarded(&mut self, next: State, clock: Clock, reserve: State) -> Result<(), Error> {
        let (next, reserve) = capacity::qualified_candidates(next, reserve, clock)?;
        if over_capacity(&reserve) {
            return Err(Error::Full);
        }
        self.persist(next)
    }
}
