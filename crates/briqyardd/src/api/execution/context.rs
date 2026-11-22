use axum::http::StatusCode;
use briqyard_api::execution::{
    admission::{HostRegistration, Journal, JournalReader, Role},
    sealed::{
        objects::{Ctx, Members, Reg},
        prim::{HexDigest, Ident},
    },
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    num::NonZeroUsize,
    sync::{Arc, RwLock as Publication},
};
use tokio::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestRole {
    Installer,
    Execution,
}

/// Exact retained cohort evidence from the native sealed guard. No bearer or
/// request-controlled plan, key, or coordinator enters this interface.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedCohort {
    pub context: Ctx,
    pub members: Members,
    pub release: HexDigest,
}

pub struct CommittedCohorts {
    current: Option<Arc<VerifiedCohort>>,
    retired: Vec<Arc<VerifiedCohort>>,
}

/// The native guard supplies its committed, verified phase projection, not a
/// projection of a prospective transition. It must serialize phase changes
/// with the host admission write turn, and publish only after durable success.
/// No native guard implements this contract on the ordinary v1 startup path.
pub trait SealedContextSource: Send + Sync {
    fn committed_cohorts(&self) -> Option<Arc<CommittedCohorts>>;
}

impl CommittedCohorts {
    pub fn new(
        current: Option<Arc<VerifiedCohort>>,
        retired: Vec<Arc<VerifiedCohort>>,
        member_limit: NonZeroUsize,
    ) -> Option<Self> {
        let mut fingerprints = BTreeSet::new();
        let mut epochs = BTreeSet::new();
        current
            .iter()
            .chain(&retired)
            .all(|c| {
                if !epochs.insert((&c.context.host, &c.context.authority, &c.context.epoch)) {
                    return false;
                }
                let m = &c.members;
                [&m.hi, &m.he, &m.ni, &m.ng]
                    .into_iter()
                    .chain(m.tr.iter())
                    .all(|fingerprint| {
                        fingerprints.insert(fingerprint) && fingerprints.len() <= member_limit.get()
                    })
            })
            .then_some(Self { current, retired })
    }
}

#[derive(Clone, PartialEq, Eq)]
struct JournalIdentity {
    host: String,
    instance: String,
    registration: Option<HostRegistration>,
}

impl JournalIdentity {
    fn read(journal: &Journal) -> Result<Self, StatusCode> {
        let Role::Host(host) = journal.role() else {
            return Err(StatusCode::CONFLICT);
        };
        Ok(Self {
            host: host.clone(),
            instance: journal.instance().into(),
            registration: journal
                .registration()
                .map_err(|_| StatusCode::CONFLICT)?
                .cloned(),
        })
    }

    fn matches_cohort(&self, cohort: &VerifiedCohort) -> bool {
        let Some(registration) = self.registration.as_ref() else {
            return false;
        };
        let Ok(host) = Ident::new(&self.host) else {
            return false;
        };
        registration.host_instance == self.instance
            && Reg::from_native(registration).is_ok_and(|r| r.ctx(&host) == cohort.context)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RequestIdentity {
    journal: Arc<JournalIdentity>,
    cohort: Option<Arc<VerifiedCohort>>,
    role: RequestRole,
}

impl RequestIdentity {
    pub(crate) fn execution(&self) -> bool {
        self.role == RequestRole::Execution
    }

    pub(crate) fn protected(&self) -> bool {
        self.cohort.is_some()
    }

    pub(crate) fn registration(&self) -> Option<&HostRegistration> {
        self.journal.registration.as_ref()
    }

    pub(crate) fn same_context(&self, other: &Self) -> bool {
        self.journal == other.journal && self.cohort == other.cohort
    }
}

pub(crate) struct AdmissionTurns {
    turn: RwLock<()>,
    journal: JournalReader,
    identity: Publication<Arc<JournalIdentity>>,
    sealed: Option<Arc<dyn SealedContextSource>>,
}

impl AdmissionTurns {
    pub(super) fn new(journal: &Journal) -> Result<Self, StatusCode> {
        Ok(Self {
            turn: RwLock::new(()),
            journal: journal.reader(),
            identity: Publication::new(Arc::new(JournalIdentity::read(journal)?)),
            sealed: None,
        })
    }

    pub(super) fn with_sealed_contexts(mut self, source: Arc<dyn SealedContextSource>) -> Self {
        self.sealed = Some(source);
        self
    }

    pub(super) fn publish(&self, journal: &Journal) -> Result<(), StatusCode> {
        let identity = JournalIdentity::read(journal)?;
        journal.publish();
        *self.identity.write().unwrap() = Arc::new(identity);
        Ok(())
    }

    pub(super) fn capture(
        &self,
        role: RequestRole,
        bearer: &[u8],
        legacy_bearer: &[u8],
    ) -> Result<RequestIdentity, StatusCode> {
        let cohort = if self.sealed.is_some() {
            let cohort = self
                .cohorts()?
                .current
                .clone()
                .ok_or(StatusCode::CONFLICT)?;
            let fingerprint = HexDigest::from_raw(Sha256::digest(bearer).into());
            let expected = match role {
                RequestRole::Installer => &cohort.members.hi,
                RequestRole::Execution => &cohort.members.he,
            };
            if !briqyard_api::constant_eq(
                fingerprint.as_str().as_bytes(),
                expected.as_str().as_bytes(),
            ) {
                return Err(StatusCode::UNAUTHORIZED);
            }
            Some(cohort)
        } else {
            if !briqyard_api::constant_eq(bearer, legacy_bearer) {
                return Err(StatusCode::UNAUTHORIZED);
            }
            None
        };
        self.journal
            .view()
            .owned()
            .map_err(|_| StatusCode::CONFLICT)?;
        let journal = self.identity.read().unwrap().clone();
        if cohort.as_ref().is_some_and(|c| !journal.matches_cohort(c)) {
            return Err(StatusCode::CONFLICT);
        }
        Ok(RequestIdentity {
            journal,
            cohort,
            role,
        })
    }

    fn cohorts(&self) -> Result<Arc<CommittedCohorts>, StatusCode> {
        self.sealed
            .as_ref()
            .and_then(|source| source.committed_cohorts())
            .ok_or(StatusCode::CONFLICT)
    }

    pub(crate) fn current(
        &self,
        request: &RequestIdentity,
        journal: &Journal,
    ) -> Result<(), StatusCode> {
        if *request.journal != JournalIdentity::read(journal)? {
            return Err(StatusCode::CONFLICT);
        }
        match &request.cohort {
            None if self.sealed.is_none() => Ok(()),
            Some(cohort) if self.cohorts()?.current.as_ref() == Some(cohort) => Ok(()),
            _ => Err(StatusCode::CONFLICT),
        }
    }

    pub(crate) fn terminal(
        &self,
        request: &RequestIdentity,
        journal: &Journal,
    ) -> Result<(), StatusCode> {
        if !request.execution() || *request.journal != JournalIdentity::read(journal)? {
            return Err(StatusCode::CONFLICT);
        }
        match &request.cohort {
            None if self.sealed.is_none() => Ok(()),
            Some(cohort) => {
                let evidence = self.cohorts()?;
                if evidence.current.as_ref() == Some(cohort) || evidence.retired.contains(cohort) {
                    Ok(())
                } else {
                    Err(StatusCode::CONFLICT)
                }
            }
            _ => Err(StatusCode::CONFLICT),
        }
    }

    pub(super) async fn writer<'a>(
        &self,
        request: &RequestIdentity,
        journal: &'a Mutex<Journal>,
    ) -> Result<MutexGuard<'a, Journal>, StatusCode> {
        let writer = journal.lock().await;
        self.current(request, &writer)?;
        Ok(writer)
    }

    pub(super) async fn read(
        &self,
        request: &RequestIdentity,
        journal: &Mutex<Journal>,
    ) -> Result<RwLockReadGuard<'_, ()>, StatusCode> {
        let turn = self.turn.read().await;
        drop(self.writer(request, journal).await?);
        Ok(turn)
    }

    pub(super) async fn write(
        &self,
        request: &RequestIdentity,
        journal: &Mutex<Journal>,
    ) -> Result<RwLockWriteGuard<'_, ()>, StatusCode> {
        let turn = self.turn.write().await;
        drop(self.writer(request, journal).await?);
        Ok(turn)
    }

    pub(crate) async fn terminal_turn(&self) -> RwLockReadGuard<'_, ()> {
        self.turn.read().await
    }
}
