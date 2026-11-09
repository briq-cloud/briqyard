//! Dormant trusted installer. The caller must supply authenticated control input;
//! submitted grants and permits never construct these records.
use crate::execution_host::{Error as TransportError, HostTransport, Route};
use briqyard_api::execution::{
    admission::{
        AuthorityPayload, DelegationIntent, Error as JournalError, HostDelegation, HostOwnership,
        HostRegistration, Journal, OwnershipControl,
    },
    channel::{
        InstallDelegation, InstallationAck, Instance, Invalidate, Protect, ProtectionAck, Revoke,
    },
    token_digest, verify_delegation, Clock, DelegationContext, DiscoveryReceipt, Source, Trust,
    MAX_BODY_BYTES,
};

#[derive(Clone, Debug)]
pub(super) struct CommittedIdle {
    pub admission: String,
    pub expires_at_ms: u64,
}

/// Authenticated control input, independent of the submitted signed credentials.
pub(super) struct DelegationControl {
    pub id: String,
    pub version: u64,
    pub principal: String,
    pub ownership: String,
    pub protection: String,
    pub source: Source,
    pub projection: briqyard_api::execution::admission::Projection,
}

pub(super) struct SignedDelegation {
    pub grant: String,
    pub allocations: Vec<String>,
}

#[derive(Debug)]
pub(super) enum InstallError {
    Journal(JournalError),
    Transport(TransportError),
    HostMismatch,
    Binding,
}

impl From<JournalError> for InstallError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}
impl From<TransportError> for InstallError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    Ready,
    Pending,
}

/// Each operation sends at most once, after fsync of its immutable intent.
/// A pending ID is never resent by this path after a crash or lost ACK.
pub(super) struct Installer<'a> {
    pub journal: &'a mut Journal,
    pub host: &'a HostTransport,
    pub host_id: &'a str,
}

impl Installer<'_> {
    async fn instance(&self, expected: &str) -> Result<(), InstallError> {
        let actual: Instance = self.host.call(Route::Instance, &()).await?;
        if actual.host_instance != expected {
            return Err(InstallError::HostMismatch);
        }
        Ok(())
    }

    pub async fn register(
        &mut self,
        id: &str,
        record: HostRegistration,
        clock: Clock,
    ) -> Result<Outcome, InstallError> {
        self.instance(&record.host_instance).await?;
        if !self.journal.begin_authority_intent(
            id,
            self.host_id,
            &record.host_instance,
            AuthorityPayload::Registration(record.clone()),
            clock,
        )? {
            return self.outcome(id);
        }
        let ack: InstallationAck = self.host.call(Route::Register, &record).await?;
        self.journal.acknowledge_authority_intent(id, ack, clock)?;
        self.outcome(id)
    }

    pub async fn discover(
        &mut self,
        id: &str,
        registration: &str,
        control: OwnershipControl,
        clock: Clock,
    ) -> Result<Outcome, InstallError> {
        let request = control.discovery_request();
        if serde_json::to_vec(&request)
            .map_err(|_| InstallError::Binding)?
            .len()
            > MAX_BODY_BYTES
        {
            return Err(InstallError::Binding);
        }
        self.instance(&control.host_instance).await?;
        if !self
            .journal
            .begin_discovery_intent(id, self.host_id, registration, control, clock)?
        {
            return Ok(if self.journal.discovery_intent_ready(id)? {
                Outcome::Ready
            } else {
                Outcome::Pending
            });
        }
        let receipt: DiscoveryReceipt = self.host.call(Route::Discover, &request).await?;
        self.journal
            .acknowledge_discovery_intent(id, receipt, clock)?;
        Ok(if self.journal.discovery_intent_ready(id)? {
            Outcome::Ready
        } else {
            Outcome::Pending
        })
    }

    pub async fn ownership(
        &mut self,
        id: &str,
        discovery: &str,
        clock: Clock,
    ) -> Result<Outcome, InstallError> {
        if !self.journal.discovery_intent_ready(discovery)? {
            return Err(InstallError::Binding);
        }
        let found = self
            .journal
            .discovery_intent(discovery)?
            .ok_or(InstallError::Binding)?;
        if found.host != self.host_id {
            return Err(InstallError::Binding);
        }
        let receipt = found.receipt.as_ref().ok_or(InstallError::Binding)?;
        let record = HostOwnership {
            installation: found.control.installation.clone(),
            generation: found.control.generation,
            team: found.control.team.clone(),
            subject: found.control.primary_id.clone(),
            metadata_revision: found.control.metadata_revision.clone(),
            primary: receipt.primary.clone(),
            public_seeds: receipt.public_seeds.clone(),
            public_resources: receipt.public_resources.clone(),
            resource_set: receipt.resource_set.clone(),
            host_instance: found.control.host_instance.clone(),
        };
        if serde_json::to_vec(&record)
            .map_err(|_| InstallError::Binding)?
            .len()
            > MAX_BODY_BYTES
        {
            return Err(InstallError::Binding);
        }
        self.instance(&record.host_instance).await?;
        if !self.journal.begin_authority_intent(
            id,
            self.host_id,
            &record.host_instance,
            AuthorityPayload::Ownership(Box::new(record.clone())),
            clock,
        )? {
            return self.outcome(id);
        }
        let ack: InstallationAck = self.host.call(Route::Ownership, &record).await?;
        self.journal.acknowledge_authority_intent(id, ack, clock)?;
        self.outcome(id)
    }

    pub async fn protect(
        &mut self,
        id: &str,
        ownership: &str,
        committed: CommittedIdle,
        clock: Clock,
    ) -> Result<Outcome, InstallError> {
        if clock.uncertainty > 5
            || committed.expires_at_ms
                <= clock
                    .now
                    .saturating_sub(clock.uncertainty)
                    .saturating_mul(1000)
            || committed.expires_at_ms > clock.now.saturating_add(60).saturating_mul(1000)
        {
            return Err(InstallError::Binding);
        }
        let owner_intent = self
            .journal
            .authority_intent(ownership)?
            .ok_or(InstallError::Binding)?;
        let AuthorityPayload::Ownership(owner) = &owner_intent.payload else {
            return Err(InstallError::Binding);
        };
        let request = Protect {
            installation: owner.installation.clone(),
            generation: owner.generation,
            admission: committed.admission,
            expires_at_ms: committed.expires_at_ms,
        };
        if serde_json::to_vec(&request)
            .map_err(|_| InstallError::Binding)?
            .len()
            > MAX_BODY_BYTES
        {
            return Err(InstallError::Binding);
        }
        let host_instance = owner.host_instance.clone();
        if !self.journal.begin_protection_intent(
            id,
            self.host_id,
            ownership,
            request.clone(),
            clock,
        )? {
            return Ok(if self.journal.protection_intent_ready(id)? {
                Outcome::Ready
            } else {
                Outcome::Pending
            });
        }
        self.instance(&host_instance).await?;
        let ack: ProtectionAck = self.host.call(Route::Protect, &request).await?;
        self.journal.acknowledge_protection_intent(id, ack, clock)?;
        Ok(if self.journal.protection_intent_ready(id)? {
            Outcome::Ready
        } else {
            Outcome::Pending
        })
    }

    pub async fn delegation(
        &mut self,
        intent_id: &str,
        registration: &str,
        control: DelegationControl,
        signed: SignedDelegation,
        trust: &Trust<'_>,
        clock: Clock,
    ) -> Result<Outcome, InstallError> {
        let registration_intent = self
            .journal
            .authority_intent(registration)?
            .ok_or(InstallError::Binding)?;
        let AuthorityPayload::Registration(reg) = &registration_intent.payload else {
            return Err(InstallError::Binding);
        };
        let ownership_intent = self
            .journal
            .authority_intent(&control.ownership)?
            .ok_or(InstallError::Binding)?;
        let AuthorityPayload::Ownership(owner) = &ownership_intent.payload else {
            return Err(InstallError::Binding);
        };
        let protection_intent = self
            .journal
            .protection_intent(&control.protection)?
            .ok_or(InstallError::Binding)?;
        if registration_intent.host != self.host_id
            || ownership_intent.host != self.host_id
            || protection_intent.host != self.host_id
            || !self.journal.authority_intent_ready(registration)?
            || !self.journal.authority_intent_ready(&control.ownership)?
            || !self.journal.protection_intent_ready(&control.protection)?
            || self.journal.delegation_revoked(&control.id)?
            || reg.epoch != self.journal.instance()
            || owner.host_instance != reg.host_instance
            || protection_intent.ownership != control.ownership
            || protection_intent.request.installation != owner.installation
            || protection_intent.request.generation != owner.generation
        {
            return Err(InstallError::Binding);
        }
        let tokens = signed
            .allocations
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let checked = verify_delegation(
            &signed.grant,
            &tokens,
            trust,
            clock,
            &DelegationContext {
                principal: &control.principal,
                team: &owner.team,
                subject: &owner.subject,
                target: &owner.primary,
                resource_set: &owner.resource_set,
                metadata_revision: &owner.metadata_revision,
                authority: &reg.authority,
                authority_epoch: &reg.epoch,
            },
        )
        .map_err(|_| InstallError::Binding)?;
        let signed_idle = checked.grant().idle.expires_at;
        let receipt_ms = protection_intent.request.expires_at_ms;
        if checked.grant().id != control.id
            || checked.grant().source != control.source
            || checked.grant().idle.admission != protection_intent.request.admission
            || receipt_ms / 1000 != signed_idle
            || signed_idle < checked.grant().exp
        {
            return Err(InstallError::Binding);
        }
        let request = InstallDelegation {
            installation: owner.installation.clone(),
            generation: owner.generation,
            id: control.id,
            version: control.version,
            principal: control.principal,
            grant: signed.grant,
            allocations: signed.allocations,
            protection_expires_at_ms: receipt_ms,
        };
        if serde_json::to_vec(&request)
            .map_err(|_| InstallError::Binding)?
            .len()
            > MAX_BODY_BYTES
        {
            return Err(InstallError::Binding);
        }
        let expected = HostDelegation {
            id: request.id.clone(),
            version: request.version,
            ownership: request.installation.clone(),
            ownership_generation: request.generation,
            grant_digest: token_digest(&request.grant),
            allocation_digests: checked.allocation_digests().to_vec(),
            principal: request.principal.clone(),
            expires_at: checked.grant().exp,
        };
        let host_instance = reg.host_instance.clone();
        let intent = DelegationIntent {
            host: self.host_id.into(),
            authority_epoch: self.journal.instance().into(),
            registration: registration.into(),
            ownership: control.ownership,
            protection: control.protection,
            trusted_source: Some(control.source),
            projection: Some(control.projection),
            request: request.clone(),
            expected,
            acknowledgement: None,
        };
        if !self
            .journal
            .begin_delegation_intent(intent_id, intent, clock)?
        {
            return Ok(if self.journal.delegation_intent_ready(intent_id)? {
                Outcome::Ready
            } else {
                Outcome::Pending
            });
        }
        self.instance(&host_instance).await?;
        let ack: HostDelegation = self.host.call(Route::Delegation, &request).await?;
        self.journal
            .acknowledge_delegation_intent(intent_id, ack, clock)?;
        Ok(if self.journal.delegation_intent_ready(intent_id)? {
            Outcome::Ready
        } else {
            Outcome::Pending
        })
    }

    pub async fn invalidate(
        &mut self,
        id: &str,
        host_instance: &str,
        request: Invalidate,
        clock: Clock,
    ) -> Result<Outcome, InstallError> {
        if !self.journal.begin_authority_intent(
            id,
            self.host_id,
            host_instance,
            AuthorityPayload::Invalidate {
                installation: request.installation.clone(),
                generation: request.generation,
            },
            clock,
        )? {
            return self.outcome(id);
        }
        self.instance(host_instance).await?;
        let ack: Instance = self.host.call(Route::Invalidate, &request).await?;
        self.journal
            .confirm_authority_instance(id, &ack.host_instance, clock)?;
        self.outcome(id)
    }

    pub async fn revoke(
        &mut self,
        id: &str,
        host_instance: &str,
        request: Revoke,
        clock: Clock,
    ) -> Result<Outcome, InstallError> {
        if !self.journal.begin_authority_intent(
            id,
            self.host_id,
            host_instance,
            AuthorityPayload::Revoke {
                id: request.id.clone(),
                version: request.version,
            },
            clock,
        )? {
            return self.outcome(id);
        }
        self.instance(host_instance).await?;
        let ack: Instance = self.host.call(Route::Revoke, &request).await?;
        self.journal
            .confirm_authority_instance(id, &ack.host_instance, clock)?;
        self.outcome(id)
    }

    fn outcome(&self, id: &str) -> Result<Outcome, InstallError> {
        Ok(if self.journal.authority_intent_ready(id)? {
            Outcome::Ready
        } else {
            Outcome::Pending
        })
    }
}

#[cfg(test)]
mod tests;
