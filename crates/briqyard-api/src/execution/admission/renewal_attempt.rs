//! One-shot authority continuation attempts. These never reserve quota or authorize
//! command dispatch. An uncertain external call is retained and never replayed.
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RenewalAttempt {
    pub id: String,
    pub operation_id: String,
    pub previous_sequence: u64,
    pub binding: ActiveOperationBinding,
    pub protection_intent: String,
    pub protection_admission: String,
    pub protection_expires_at_ms: u64,
    pub continuation_digest: Option<String>,
}
impl Journal {
    pub fn renewal_attempt(&self, id: &str) -> Result<Option<&RenewalAttempt>, Error> {
        self.ownership()?;
        Ok(self.state.renewal_attempts.get(id))
    }
    pub fn begin_renewal_attempt(
        &mut self,
        attempt: RenewalAttempt,
        clock: Clock,
    ) -> Result<bool, Error> {
        self.check(clock)?;
        if !matches!(self.role(), Role::Authority(_))
            || !valid_id(&attempt.id)
            || !valid_id(&attempt.protection_intent)
            || !valid_id(&attempt.protection_admission)
            || !attempt.binding.is_valid()
            || attempt.operation_id != attempt.binding.operation_id
            || attempt.operation_id != attempt.binding.admission
            || attempt.previous_sequence >= MAX_SAFE_INTEGER
            || attempt.continuation_digest.is_some()
            || attempt.protection_expires_at_ms > MAX_SAFE_INTEGER
            || attempt.protection_expires_at_ms
                <= clock
                    .now
                    .saturating_add(clock.uncertainty)
                    .saturating_mul(1000)
        {
            return Err(Error::Binding);
        }
        self.renewal_operation(&attempt.operation_id, &attempt.binding)?;
        if let Some(old) = self.state.renewal_attempts.get(&attempt.id) {
            let mut original = old.clone();
            original.continuation_digest = None;
            return if original == attempt {
                Ok(false)
            } else {
                Err(Error::Binding)
            };
        }
        if self.state.renewal_attempts.values().any(|old| {
            old.operation_id == attempt.operation_id
                && old.previous_sequence == attempt.previous_sequence
        }) {
            return Err(Error::AlreadyAdmitted);
        }
        let mut next = self.state.clone();
        next.renewal_attempts.insert(attempt.id.clone(), attempt);
        next.clock_floor = clock.now;
        self.commit(next)?;
        Ok(true)
    }
    pub fn renewal_operation(
        &self,
        id: &str,
        binding: &ActiveOperationBinding,
    ) -> Result<(), Error> {
        let op = self.operation_intent(id)?.ok_or(Error::Binding)?;
        let delegation = self
            .delegation_intent(&op.delegation)?
            .ok_or(Error::Binding)?;
        let policy = delegation
            .operation_policy_ack
            .as_ref()
            .ok_or(Error::Binding)?;
        if !matches!(
            op.phase,
            OperationPhase::Dispatched | OperationPhase::Consumed
        ) || op.unconfirmed
            || !self.delegation_intent_ready(&op.delegation)?
            || binding.admission != op.id
            || binding.operation_id != op.id
            || binding.host_instance != op.host_instance
            || binding.authority_epoch != op.authority_epoch
            || binding.authority != op.permit.authority
            || binding.request_digest != op.request_digest
            || Some(&binding.permit_digest) != op.permit_digest.as_ref()
            || binding.grant_digest != op.permit.grant_digest
            || binding.target != op.permit.target
            || binding.limits != op.permit.limits
            || binding.metadata_revision != op.permit.metadata_revision
            || binding.delegation != policy.delegation
            || binding.delegation_version != policy.delegation_version
            || binding.ownership != policy.ownership
            || binding.ownership_generation != policy.ownership_generation
            || binding.policy_revision != policy.policy_revision
            || binding.grant_digest != policy.grant_digest
            || delegation.trusted_source.as_ref() != Some(&binding.source)
        {
            return Err(Error::Binding);
        }
        let owner = self
            .authority_intent(&delegation.ownership)?
            .ok_or(Error::Binding)?;
        let AuthorityPayload::Ownership(owner) = &owner.payload else {
            return Err(Error::Binding);
        };
        if binding.resource_set != owner.resource_set
            || binding.team != owner.team
            || binding.subject != owner.subject
            || binding.principal != delegation.request.principal
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
    /// Commit before the sole delivery. Repeated identical tokens are status-only.
    pub fn bind_renewal_delivery(
        &mut self,
        id: &str,
        verified: &VerifiedContinuation,
        digest: String,
        clock: Clock,
    ) -> Result<bool, Error> {
        self.check(clock)?;
        let c = verified.claims();
        let attempt = self.renewal_attempt(id)?.ok_or(Error::Binding)?;
        self.renewal_operation(&attempt.operation_id, &c.binding)?;
        let protection = self
            .protection_intent(&attempt.protection_intent)?
            .ok_or(Error::Binding)?;
        if !valid_id(id)
            || !super::super::verify::digest(&digest)
            || attempt.binding != c.binding
            || attempt.previous_sequence != c.previous_sequence
            || c.protection.admission != attempt.protection_admission
            || c.protection.expires_at_ms != attempt.protection_expires_at_ms
            || protection.acknowledgement.as_ref()
                != Some(&crate::execution::channel::ProtectionAck {
                    admission: c.protection.admission.clone(),
                    expires_at_ms: c.protection.expires_at_ms,
                    resources: c.protection.resources.clone(),
                    revision: c.protection.resource_revision.clone(),
                })
            || !self.protection_intent_ready(&attempt.protection_intent)?
        {
            return Err(Error::Binding);
        }
        if let Some(old) = &attempt.continuation_digest {
            return if old == &digest {
                Ok(false)
            } else {
                Err(Error::Binding)
            };
        }
        let mut next = self.state.clone();
        next.renewal_attempts
            .get_mut(id)
            .ok_or(Error::Binding)?
            .continuation_digest = Some(digest);
        next.clock_floor = clock.now;
        self.commit(next)?;
        Ok(true)
    }
}
