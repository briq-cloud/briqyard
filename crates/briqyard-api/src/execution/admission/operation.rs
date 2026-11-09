//! One-shot regional operation evidence in the issuer's exclusive journal.
//! Every retained ID is status-only after its first intent, including a crash
//! before quota debit. No state transition grants permission to resend a host RPC.
use super::*;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationPhase {
    Intent,
    Reserved,
    Prepared,
    Dispatched,
    Consumed,
    Finished,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationIntent {
    pub id: String,
    pub delegation: String,
    pub authority_epoch: String,
    pub host: String,
    pub host_instance: String,
    pub request_digest: String,
    pub permit: Permit,
    pub phase: OperationPhase,
    /// The token is kept only to bind the exact issued permit to the host ACK.
    pub permit_digest: Option<String>,
    pub prepared: Option<PreparedAdmission>,
    pub outcome_digest: Option<String>,
    /// A missing or failed RPC reply is never proof of non-execution.
    pub unconfirmed: bool,
}

impl Journal {
    pub fn operation_intent(&self, id: &str) -> Result<Option<&OperationIntent>, Error> {
        self.ownership()?;
        Ok(self.state.operation_intents.get(id))
    }

    pub fn begin_operation(&mut self, intent: OperationIntent, clock: Clock) -> Result<(), Error> {
        self.check(clock)?;
        if !matches!(self.role(), Role::Authority(_))
            || !valid_id(&intent.id)
            || !valid_id(&intent.delegation)
            || !valid_id(&intent.host)
            || !valid_id(&intent.host_instance)
            || intent.phase != OperationPhase::Intent
            || intent.permit_digest.is_some()
            || intent.prepared.is_some()
            || intent.outcome_digest.is_some()
            || intent.unconfirmed
            || intent.authority_epoch != self.instance()
            || intent.permit.admission != intent.id
            || intent.permit.authority_epoch != intent.authority_epoch
            || intent.permit.request_digest != intent.request_digest
            || intent.permit.operation != Operation::Exec
            || intent.permit.exp <= clock.now.saturating_add(clock.uncertainty)
        {
            return Err(Error::Binding);
        }
        if self.state.operation_intents.contains_key(&intent.id)
            || self.state.admissions.contains_key(&intent.id)
        {
            return Err(Error::AlreadyAdmitted);
        }
        let delegation = self
            .state
            .delegation_intents
            .get(&intent.delegation)
            .ok_or(Error::Binding)?;
        let registration = self
            .authority_intent(&delegation.registration)?
            .ok_or(Error::Binding)?;
        let ownership = self
            .authority_intent(&delegation.ownership)?
            .ok_or(Error::Binding)?;
        let (AuthorityPayload::Registration(reg), AuthorityPayload::Ownership(owner)) =
            (&registration.payload, &ownership.payload)
        else {
            return Err(Error::Binding);
        };
        if !self.delegation_intent_ready(&intent.delegation)?
            || self.delegation_revoked(&delegation.request.id)?
            || delegation.host != intent.host
            || delegation.authority_epoch != intent.authority_epoch
            || reg.host_instance != intent.host_instance
            || owner.host_instance != intent.host_instance
            || intent.permit.authority != reg.authority
            || intent.permit.target != owner.primary
            || intent.permit.metadata_revision != owner.metadata_revision
            || intent.permit.grant_digest != delegation.expected.grant_digest
            || intent.permit.exp > delegation.expected.expires_at
        {
            return Err(Error::Binding);
        }
        if self.state.operation_intents.len() >= MAX_RECORDS {
            return Err(Error::Full);
        }
        let mut next = self.state.clone();
        next.operation_intents.insert(intent.id.clone(), intent);
        next.clock_floor = clock.now;
        self.commit(next)
    }

    pub fn bind_operation_permit(
        &mut self,
        id: &str,
        permit_digest: String,
        clock: Clock,
    ) -> Result<(), Error> {
        self.check(clock)?;
        let prior = self.state.operation_intents.get(id).ok_or(Error::Binding)?;
        if prior.phase != OperationPhase::Intent
            || prior.permit_digest.is_some()
            || self.status(id)? != Some(Status::Reserved)
        {
            return Err(Error::Binding);
        }
        let mut next = self.state.clone();
        let op = next.operation_intents.get_mut(id).ok_or(Error::Binding)?;
        op.permit_digest = Some(permit_digest);
        op.phase = OperationPhase::Reserved;
        next.clock_floor = clock.now;
        self.commit(next)
    }

    /// Persist an exact typed ACK. A mismatch leaves the reserved operation unusable.
    pub fn acknowledge_operation_prepare(
        &mut self,
        id: &str,
        ack: PreparedAdmission,
        clock: Clock,
    ) -> Result<(), Error> {
        self.check(clock)?;
        let op = self.state.operation_intents.get(id).ok_or(Error::Binding)?;
        let delegation = self
            .state
            .delegation_intents
            .get(&op.delegation)
            .ok_or(Error::Binding)?;
        if op.phase != OperationPhase::Reserved
            || op.permit.exp <= clock.now.saturating_add(clock.uncertainty)
            || !self.delegation_intent_ready(&op.delegation)?
            || ack.admission != op.id
            || ack.delegation != delegation.request.id
            || ack.grant_digest != delegation.expected.grant_digest
            || Some(&ack.permit_digest) != op.permit_digest.as_ref()
            || ack.request_digest != op.request_digest
            || ack.allocation_refs != op.permit.allocations
            || ack.ownership != delegation.request.installation
            || ack.ownership_generation != delegation.request.generation
            || ack.host_instance != op.host_instance
            || ack.expires_at != op.permit.exp
            || ack.dispatched
        {
            return Err(Error::Binding);
        }
        let mut next = self.state.clone();
        let op = next.operation_intents.get_mut(id).ok_or(Error::Binding)?;
        op.prepared = Some(ack);
        op.phase = OperationPhase::Prepared;
        next.clock_floor = clock.now;
        self.commit(next)
    }

    pub fn mark_operation_dispatch(&mut self, id: &str, clock: Clock) -> Result<(), Error> {
        self.check(clock)?;
        let op = self.state.operation_intents.get(id).ok_or(Error::Binding)?;
        if op.phase != OperationPhase::Prepared
            || op.permit.exp <= clock.now.saturating_add(clock.uncertainty)
            || !self.delegation_intent_ready(&op.delegation)?
        {
            return Err(Error::Binding);
        }
        let mut next = self.state.clone();
        next.operation_intents
            .get_mut(id)
            .ok_or(Error::Binding)?
            .phase = OperationPhase::Dispatched;
        next.clock_floor = clock.now;
        self.commit(next)
    }

    pub fn record_operation_evidence(
        &mut self,
        id: &str,
        phase: OperationPhase,
        outcome_digest: Option<String>,
        clock: Clock,
    ) -> Result<(), Error> {
        self.check(clock)?;
        let op = self.state.operation_intents.get(id).ok_or(Error::Binding)?;
        if op.phase != OperationPhase::Dispatched
            || !matches!(phase, OperationPhase::Consumed | OperationPhase::Finished)
            || (phase == OperationPhase::Finished) != outcome_digest.is_some()
        {
            return Err(Error::Binding);
        }
        let mut next = self.state.clone();
        let op = next.operation_intents.get_mut(id).ok_or(Error::Binding)?;
        op.phase = phase;
        op.outcome_digest = outcome_digest;
        next.clock_floor = clock.now;
        self.commit(next)
    }

    pub fn mark_operation_unconfirmed(&mut self, id: &str, clock: Clock) -> Result<(), Error> {
        self.check(clock)?;
        let mut next = self.state.clone();
        next.operation_intents
            .get_mut(id)
            .ok_or(Error::Binding)?
            .unconfirmed = true;
        next.clock_floor = clock.now;
        self.commit(next)
    }
}
