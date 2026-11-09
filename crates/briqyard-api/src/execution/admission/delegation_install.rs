//! Authority-side signed delegation intent. Host readiness is evidence, not permission
//! to install allocations, issue a permit, or dispatch a command.
use super::*;
use crate::execution::channel::InstallDelegation;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DelegationIntent {
    pub host: String,
    pub authority_epoch: String,
    pub registration: String,
    pub ownership: String,
    pub protection: String,
    /// Authenticated source snapshot captured before signed credential inspection.
    #[serde(default)]
    pub trusted_source: Option<Source>,
    pub request: InstallDelegation,
    pub expected: HostDelegation,
    pub acknowledgement: Option<HostDelegation>,
}

impl Journal {
    pub fn begin_delegation_intent(
        &mut self,
        intent_id: &str,
        intended: DelegationIntent,
        clock: Clock,
    ) -> Result<bool, Error> {
        self.check(clock)?;
        if !matches!(self.role(), Role::Authority(_))
            || !valid_id(intent_id)
            || !valid_id(&intended.host)
            || !valid_id(&intended.request.id)
            || intended.request.version == 0
            || !intended.trusted_source.as_ref().is_some_and(|source| {
                valid_id(&source.kind)
                    && valid_id(&source.id)
                    && source.expires_at > clock.now.saturating_add(clock.uncertainty)
            })
            || intended.authority_epoch != self.instance()
            || intended.acknowledgement.is_some()
            || self.delegation_revoked(&intended.request.id)?
            || !self.delegation_dependencies_ready(
                &intended.host,
                &intended.registration,
                &intended.ownership,
                &intended.protection,
                &intended.request,
            )?
        {
            return Err(Error::Binding);
        }
        if intended.expected.id != intended.request.id
            || intended.expected.version != intended.request.version
            || intended.expected.ownership != intended.request.installation
            || intended.expected.ownership_generation != intended.request.generation
            || intended.expected.principal != intended.request.principal
            || intended.expected.expires_at <= clock.now.saturating_add(clock.uncertainty)
        {
            return Err(Error::Binding);
        }
        if let Some(prior) = self.state.delegation_intents.get(intent_id) {
            if prior.host == intended.host
                && prior.authority_epoch == intended.authority_epoch
                && prior.registration == intended.registration
                && prior.ownership == intended.ownership
                && prior.protection == intended.protection
                && prior.trusted_source == intended.trusted_source
                && prior.request == intended.request
                && prior.expected == intended.expected
            {
                return Ok(false);
            }
            return Err(Error::Binding);
        }
        if self.state.delegation_intents.len() >= MAX_RECORDS
            || self
                .state
                .delegation_intents
                .values()
                .any(|intent| intent.request.id == intended.request.id)
        {
            return Err(Error::Full);
        }
        let mut next = self.state.clone();
        next.delegation_intents.insert(intent_id.into(), intended);
        next.clock_floor = clock.now;
        self.commit(next)?;
        Ok(true)
    }

    pub fn delegation_intent(&self, id: &str) -> Result<Option<&DelegationIntent>, Error> {
        self.ownership()?;
        Ok(self.state.delegation_intents.get(id))
    }

    pub fn delegation_revoked(&self, id: &str) -> Result<bool, Error> {
        self.ownership()?;
        Ok(self.state.authority_intents.values().any(|intent| {
            matches!(&intent.payload, AuthorityPayload::Revoke { id: revoked, .. } if revoked == id)
        }))
    }

    fn delegation_dependencies_ready(
        &self,
        host: &str,
        registration: &str,
        ownership: &str,
        protection: &str,
        request: &InstallDelegation,
    ) -> Result<bool, Error> {
        let Some(reg) = self.authority_intent(registration)? else {
            return Ok(false);
        };
        let Some(owner) = self.authority_intent(ownership)? else {
            return Ok(false);
        };
        let Some(protect) = self.protection_intent(protection)? else {
            return Ok(false);
        };
        let (AuthorityPayload::Registration(r), AuthorityPayload::Ownership(o)) =
            (&reg.payload, &owner.payload)
        else {
            return Ok(false);
        };
        Ok(reg.host == host
            && owner.host == host
            && protect.host == host
            && reg.authority_epoch == self.instance()
            && owner.authority_epoch == self.instance()
            && protect.authority_epoch == self.instance()
            && owner
                .registration_dependency
                .as_ref()
                .is_some_and(|d| d.intent == registration && d.generation == r.generation)
            && protect.ownership == ownership
            && r.host_instance == o.host_instance
            && o.installation == request.installation
            && o.generation == request.generation
            && protect.request.installation == request.installation
            && protect.request.generation == request.generation
            && protect.request.expires_at_ms == request.protection_expires_at_ms
            && self.authority_intent_ready(registration)?
            && self.authority_intent_ready(ownership)?
            && self.protection_intent_ready(protection)?)
    }

    pub fn acknowledge_delegation_intent(
        &mut self,
        id: &str,
        ack: HostDelegation,
        clock: Clock,
    ) -> Result<(), Error> {
        self.check(clock)?;
        let intent = self
            .state
            .delegation_intents
            .get(id)
            .ok_or(Error::Binding)?;
        if intent.authority_epoch != self.instance()
            || intent.expected.expires_at <= clock.now.saturating_add(clock.uncertainty)
            || self.delegation_revoked(&intent.request.id)?
            || !self.delegation_dependencies_ready(
                &intent.host,
                &intent.registration,
                &intent.ownership,
                &intent.protection,
                &intent.request,
            )?
            || ack != intent.expected
        {
            return Err(Error::Binding);
        }
        if intent.acknowledgement.as_ref() == Some(&ack) {
            return Ok(());
        }
        if intent.acknowledgement.is_some() {
            return Err(Error::Binding);
        }
        let mut next = self.state.clone();
        next.delegation_intents
            .get_mut(id)
            .ok_or(Error::Binding)?
            .acknowledgement = Some(ack);
        next.clock_floor = clock.now;
        self.commit(next)
    }

    pub fn delegation_intent_ready(&self, id: &str) -> Result<bool, Error> {
        let Some(intent) = self.delegation_intent(id)? else {
            return Ok(false);
        };
        Ok(intent.authority_epoch == self.instance()
            && intent.trusted_source.is_some()
            && intent.acknowledgement.as_ref() == Some(&intent.expected)
            && !self.delegation_revoked(&intent.request.id)?
            && self.delegation_dependencies_ready(
                &intent.host,
                &intent.registration,
                &intent.ownership,
                &intent.protection,
                &intent.request,
            )?)
    }
}
