//! Host lease state. Consumption, guest acceptance acknowledgement and live
//! timers remain separate steps; recovery never interprets this as work to resume.
use super::*;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActivePhase {
    Consumed,
    Active,
    Finished,
    Revoked,
    Recovered,
    Unresolved,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActiveOperation {
    pub binding: ActiveOperationBinding,
    pub phase: ActivePhase,
    pub sequence: u64,
    pub checked_at: u64,
    pub lease_expires_at: u64,
    pub protection: InstalledProtection,
}

impl Journal {
    /// Called under the initial dispatch fence only after durable consumption.
    /// This does not prove that a guest request has been written.
    pub fn record_consumed_operation(
        &mut self,
        bundle: &VerifiedBundle,
        binding: ActiveOperationBinding,
        protection: InstalledProtection,
        clock: Clock,
    ) -> Result<(), Error> {
        self.check(clock)?;
        let p = bundle.permit();
        let g = bundle.grant();
        let prepared = self
            .state
            .prepared
            .get(&p.admission)
            .ok_or(Error::Binding)?;
        let delegated = self
            .state
            .delegations
            .get(&binding.delegation)
            .ok_or(Error::Binding)?;
        if !matches!(self.role(), Role::Host(_))
            || !binding.is_valid()
            || !self.bound(bundle)
            || self
                .state
                .admissions
                .get(&p.admission)
                .map(|a| (&a.permit, a.status))
                != Some((p, Status::Consumed))
            || self.state.active_operations.contains_key(&p.admission)
            || binding.admission != p.admission
            || binding.grant_digest != p.grant_digest
            || binding.permit_digest != prepared.permit_digest
            || binding.request_digest != p.request_digest
            || binding.authority != p.authority
            || binding.authority_epoch != p.authority_epoch
            || binding.host_instance != self.instance()
            || binding.ownership != prepared.ownership
            || binding.ownership_generation != prepared.ownership_generation
            || binding.delegation != prepared.delegation
            || binding.delegation_version != delegated.version
            || delegated.grant_digest != binding.grant_digest
            || delegated.principal != binding.principal
            || delegated.ownership != binding.ownership
            || delegated.ownership_generation != binding.ownership_generation
            || prepared.grant_digest != p.grant_digest
            || prepared.request_digest != p.request_digest
            || prepared.allocation_refs != p.allocations
            || prepared.expires_at != p.exp
            || binding.principal != g.principal
            || binding.source != g.source
            || binding.team != g.team
            || binding.subject != g.subject
            || binding.metadata_revision != g.metadata_revision
            || binding.target != p.target
            || binding.resource_set != g.resource_set
            || binding.limits != p.limits
            || !prepared.dispatched
            || p.exp <= clock.now.saturating_add(clock.uncertainty)
            || p.exp > g.iat.saturating_add(MAX_COMMAND_SECONDS)
            || p.exp.saturating_mul(1000) > binding.operation_deadline_ms
            || binding.started_at_ms
                < clock
                    .now
                    .saturating_sub(clock.uncertainty)
                    .saturating_mul(1000)
            || binding.started_at_ms
                > clock
                    .now
                    .saturating_add(clock.uncertainty)
                    .saturating_mul(1000)
            || protection.installation != binding.ownership
            || protection.generation != binding.ownership_generation
            || protection.resources != binding.resource_set.resources
            || protection.resource_revision != binding.resource_set.revision
            || protection.expires_at_ms < p.exp.saturating_mul(1000)
            || self.state.protections.get(&protection.admission) != Some(&protection)
        {
            return Err(Error::Binding);
        }
        self.active_fence(&binding)?;
        let mut next = self.state.clone();
        next.active_operations.insert(
            p.admission.clone(),
            ActiveOperation {
                binding,
                phase: ActivePhase::Consumed,
                sequence: 0,
                lease_expires_at: p.exp,
                checked_at: g.iat,
                protection,
            },
        );
        next.clock_floor = clock.now;
        self.commit(next)
    }

    /// Trusted guest transport calls this exactly once after the first request
    /// frame. Polling or Reserved/Consumed status must never invoke it.
    pub fn acknowledge_active_operation(
        &mut self,
        admission: &str,
        clock: Clock,
    ) -> Result<ActiveOperation, Error> {
        self.check(clock)?;
        let saved = self
            .state
            .active_operations
            .get(admission)
            .ok_or(Error::Binding)?;
        self.active_fence(&saved.binding)?;
        if saved.phase != ActivePhase::Consumed
            || saved.lease_expires_at <= clock.now.saturating_add(clock.uncertainty)
        {
            return Err(Error::Binding);
        }
        let mut next = self.state.clone();
        let saved = next
            .active_operations
            .get_mut(admission)
            .ok_or(Error::Binding)?;
        saved.phase = ActivePhase::Active;
        let evidence = saved.clone();
        next.clock_floor = clock.now;
        self.commit(next)?;
        Ok(evidence)
    }

    /// Apply before the *old* lease expires, under the same journal turn used by
    /// revoke and finish. Return only after fsync; the live timer follows this ACK.
    pub fn continue_operation(
        &mut self,
        verified: &VerifiedContinuation,
        clock: Clock,
    ) -> Result<ActiveOperation, Error> {
        self.check(clock)?;
        let c = verified.claims();
        let saved = self
            .state
            .active_operations
            .get(&c.binding.admission)
            .ok_or(Error::Binding)?;
        self.active_fence(&saved.binding)?;
        let latest = clock.now.saturating_add(clock.uncertainty);
        if saved.phase != ActivePhase::Active
            || saved.binding != c.binding
            || saved.sequence != c.previous_sequence
            || saved.sequence.checked_add(1) != Some(c.sequence)
            || saved.lease_expires_at <= latest
            || c.checked_at < saved.checked_at
            || c.exp <= saved.lease_expires_at
            || c.exp <= latest
            || c.iat > clock.now.saturating_sub(clock.uncertainty)
            || c.nbf > clock.now.saturating_sub(clock.uncertainty)
            || c.exp > c.checked_at.saturating_add(MAX_COMMAND_SECONDS)
            || c.exp > saved.binding.source.expires_at
            || c.exp.saturating_mul(1000) > saved.binding.operation_deadline_ms
            || c.protection.expires_at_ms < c.exp.saturating_mul(1000)
            || self.state.protections.get(&c.protection.admission) != Some(&c.protection)
        {
            return Err(Error::Binding);
        }
        let mut next = self.state.clone();
        let saved = next
            .active_operations
            .get_mut(&c.binding.admission)
            .ok_or(Error::Binding)?;
        saved.sequence = c.sequence;
        saved.checked_at = c.checked_at;
        saved.lease_expires_at = c.exp;
        saved.protection = c.protection.clone();
        let evidence = saved.clone();
        next.clock_floor = clock.now;
        self.commit(next)?;
        Ok(evidence)
    }

    /// Status is evidence only, including after the permit/quota window expires.
    pub fn active_operation(&self, admission: &str) -> Result<Option<&ActiveOperation>, Error> {
        self.ownership()?;
        Ok(self.state.active_operations.get(admission))
    }

    /// No time authority is required to permanently end uncertain work.
    pub fn end_active_operation(&mut self, admission: &str) -> Result<(), Error> {
        self.ownership()?;
        let mut next = self.state.clone();
        let saved = next
            .active_operations
            .get_mut(admission)
            .ok_or(Error::Binding)?;
        if matches!(saved.phase, ActivePhase::Consumed | ActivePhase::Active) {
            saved.phase = ActivePhase::Unresolved;
            self.commit(next)?;
        }
        Ok(())
    }

    fn active_fence(&self, b: &ActiveOperationBinding) -> Result<(), Error> {
        if b.host_instance != self.instance()
            || self
                .state
                .registration
                .as_ref()
                .map(|r| (&r.authority, &r.epoch))
                != Some((&b.authority, &b.authority_epoch))
            || !self.state.ownership.get(&b.ownership).is_some_and(|o| {
                o.generation == b.ownership_generation
                    && o.host_instance == b.host_instance
                    && o.team == b.team
                    && o.subject == b.subject
                    && o.primary == b.target
                    && o.metadata_revision == b.metadata_revision
                    && o.resource_set == b.resource_set
            })
            || !self
                .state
                .operation_policies
                .get(&b.grant_digest)
                .is_some_and(|p| {
                    p.host_instance == b.host_instance
                        && p.ownership == b.ownership
                        && p.ownership_generation == b.ownership_generation
                        && p.delegation == b.delegation
                        && p.delegation_version == b.delegation_version
                        && p.policy_revision == b.policy_revision
                })
            || self.state.delegation_tombstones.contains_key(&b.delegation)
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
}
