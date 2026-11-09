//! Dormant trusted installer. The caller must supply authenticated control input;
//! submitted grants and permits never construct these records.
use crate::execution_host::{Error as TransportError, HostTransport, Route};
use briqyard_api::execution::{
    admission::{
        AuthorityPayload, Error as JournalError, HostOwnership, HostRegistration, Journal,
    },
    channel::{InstallationAck, Instance, Invalidate, Revoke},
    Clock,
};

#[derive(Debug)]
pub(super) enum InstallError {
    Journal(JournalError),
    Transport(TransportError),
    HostMismatch,
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

    pub async fn ownership(
        &mut self,
        id: &str,
        record: HostOwnership,
        clock: Clock,
    ) -> Result<Outcome, InstallError> {
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

    pub async fn invalidate(
        &mut self,
        id: &str,
        host_instance: &str,
        request: Invalidate,
        clock: Clock,
    ) -> Result<Outcome, InstallError> {
        self.instance(host_instance).await?;
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
        self.instance(host_instance).await?;
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
