//! The target's local owner of one enrolled operation: the durable active attempt, the receipts
//! it writes, the read-only collector's projection and the lineage checks that stand between a
//! launch grant and its consumption (ADR 0149).
//!
//! **Not an activation path.** Nothing here selects an operation, reads a manifest, signs, or
//! starts a process. A transition takes measurements from a [`TargetFacts`] and a
//! [`RetainedProcess`]: the production [`LiveHost`] measures processes and refuses every fact
//! without a producer (ADR 0149), so no production caller can enroll or answer a read yet.
//! A future sealed startup must attach its source of enrolled operations unconditionally
//! before it opens a guarded listener; constructing these types is not owner authority.

mod attempt;
mod facts;
mod fragment;
mod store;

#[cfg(test)]
mod tests;

pub use attempt::{CustodianInput, GuardPins};
pub use facts::{FinalIo, LiveHost, MeasuredProc, RetainedProcess, TargetFacts, UnitMeasure};
pub use fragment::read_fragment;

use super::plan_reader::{
    EnrolledTrust, OriginalOwner, OwnerRefusal, OwnerSnapshot, PlanReadOwner, ReadScope,
};
use super::CustodyError;
use attempt::Attempt;
use briqyard_api::execution::sealed::{
    canonical::{decode, encode, CodecError},
    custody::{Capture, Resource},
    owner::{ObserveRequest, Point, Turn},
    plan_pin::{LocalPlan, ReadPoint},
    prim::{HexDigest, Ident},
    sig::SigError,
    transition::{Death, LGrant, Launch, Receipt},
};
use store::{Guard, Store};
use thiserror::Error;

/// Why the local owner refused or could not know. No variant carries key, plan or bearer bytes.
#[derive(Debug, Error)]
pub enum OwnerError {
    #[error("sealed owner refused: {0}")]
    Refused(&'static str),
    #[error("sealed owner input is unprovisioned: {0}")]
    Unprovisioned(&'static str),
    #[error("the active attempt changed under the caller")]
    Stale,
    #[error("the commit outcome is unknown; read the attempt, never repeat the effect")]
    CommitUnknown,
    #[error(
        "the commit is durable and known, but {operation} failed: {source}; stop this turn, \
         do not retry it and do not release its next effect"
    )]
    CommittedCleanupFailed {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("sealed owner {operation} failed: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Custody(#[from] CustodyError),
    #[error("sealed owner wire refused: {0}")]
    Codec(#[from] CodecError),
    #[error("sealed owner signature refused: {0}")]
    Sig(#[from] SigError),
}

/// The target's local owner. One per process; the store lock is the cross-process exclusion.
pub struct LocalOwner<F: TargetFacts> {
    store: Store,
    facts: F,
}

impl<F: TargetFacts> LocalOwner<F> {
    /// The fixed root-private store. Root only.
    pub fn system(facts: F) -> Result<Self, OwnerError> {
        Ok(Self {
            store: Store::system()?,
            facts,
        })
    }

    #[cfg(test)]
    fn rooted_at(root: &std::path::Path, owner: u32, facts: F) -> Result<Self, OwnerError> {
        Ok(Self {
            store: Store::rooted_at(root, owner)?,
            facts,
        })
    }

    fn mutate<T>(
        &self,
        change: impl FnOnce(&Attempt) -> Result<(Attempt, T), OwnerError>,
    ) -> Result<T, OwnerError> {
        let guard = self.store.lock(true)?;
        let current = self
            .store
            .load(&guard)?
            .ok_or(OwnerError::Refused("no active attempt"))?;
        let (next, out) = change(&current)?;
        self.store.commit(&guard, Some(&current), &next)?;
        Ok(out)
    }

    /// Install the one attempt. The trust record must be the operation's own enrolled
    /// `(Rk, Bk)` and equal the Plan's keys; the Plan's originals must be the live processes it
    /// names; the guard pins come from the validated inputs and must equal the measured guard
    /// images. An existing attempt, at any stage, is never replaced.
    pub fn install(
        &self,
        plan_bytes: &[u8],
        trust: &EnrolledTrust,
        target: Ident,
        daemon: &CustodianInput<'_>,
        authority: &CustodianInput<'_>,
        guards: &GuardPins,
    ) -> Result<(), OwnerError> {
        let plan = LocalPlan::decode(plan_bytes)?;
        let record = trust.record();
        let local = plan.plan();
        if record.x != local.x
            || record.registered != local.registered
            || record.rk != local.rk
            || record.bk != local.bk
        {
            return Err(OwnerError::Refused(
                "trust record is not this Plan's enrollment",
            ));
        }
        let guard = self.store.lock(true)?;
        if self.store.load(&guard)?.is_some() {
            return Err(OwnerError::Refused("an attempt already exists"));
        }
        let genesis = Attempt::genesis(
            &plan,
            plan_bytes,
            target,
            [daemon, authority],
            guards,
            &self.facts,
        )?;
        self.store.commit(&guard, None, &genesis)
    }

    pub fn allocate_lease(&self, resource: Resource) -> Result<(), OwnerError> {
        self.mutate(|attempt| Ok((attempt.allocate_lease(resource)?, ())))
    }

    pub fn install_fragment(&self, resource: Resource) -> Result<(), OwnerError> {
        self.mutate(|attempt| Ok((attempt.install_fragment(resource, &self.facts)?, ())))
    }

    pub fn record_capture(
        &self,
        resource: Resource,
        launch: &Launch,
        capture: &Capture,
        retained: &dyn RetainedProcess,
    ) -> Result<(), OwnerError> {
        self.mutate(|attempt| {
            Ok((
                attempt.record_capture(resource, launch, capture, retained)?,
                (),
            ))
        })
    }

    pub fn commit_enrollment(&self) -> Result<(), OwnerError> {
        self.mutate(|attempt| Ok((attempt.commit_enrollment(&self.facts)?, ())))
    }

    pub fn accept_handoff(
        &self,
        grant: &LGrant,
        turn: &Turn,
        retained: &dyn RetainedProcess,
    ) -> Result<(), OwnerError> {
        self.mutate(|attempt| {
            Ok((
                attempt.accept_handoff(grant, turn, retained, &self.facts)?,
                (),
            ))
        })
    }

    /// The seal's local acceptance: the exact accepted version, compared once, at its effect.
    pub fn accept_seal(&self, grant: &LGrant, turn: &Turn) -> Result<(), OwnerError> {
        self.mutate(|attempt| Ok((attempt.accept_seal(grant, turn, &self.facts)?, ())))
    }

    pub fn record_exit(
        &self,
        resource: Resource,
        retained: &dyn RetainedProcess,
    ) -> Result<(), OwnerError> {
        self.mutate(|attempt| Ok((attempt.record_exit(resource, retained)?, ())))
    }

    pub fn record_final_io(&self, resource: Resource) -> Result<(), OwnerError> {
        self.mutate(|attempt| Ok((attempt.record_final_io(resource, &self.facts)?, ())))
    }

    pub fn record_guard_start(&self, resource: Resource) -> Result<(), OwnerError> {
        self.mutate(|attempt| Ok((attempt.record_guard_start(resource, &self.facts)?, ())))
    }

    /// The guard's callback: verify the lineage since the handoff and spend the one use. The
    /// caller is the root custodian, which authenticated `guard` from the connected socket.
    pub fn consume(&self, resource: Resource, guard: &MeasuredProc) -> Result<Launch, OwnerError> {
        self.mutate(|attempt| {
            let (next, launch) = attempt.consume(resource, guard, &self.facts)?;
            Ok((next, launch))
        })
    }

    pub fn record_retirement(
        &self,
        launch: &Launch,
        death: &Death,
        writer_profile: &HexDigest,
    ) -> Result<(), OwnerError> {
        self.mutate(|attempt| {
            Ok((
                attempt.record_retirement(launch, death, writer_profile, &self.facts)?,
                (),
            ))
        })
    }

    pub fn bind_seal_receipt(&self, receipt: &Receipt) -> Result<(), OwnerError> {
        self.mutate(|attempt| Ok((attempt.bind_seal_receipt(receipt)?, ())))
    }

    /// `sealed-owner-observe`: one strict request in, one canonical answer out. Read-only: the
    /// shared lock keeps every mutation out while the live facts are measured, and nothing is
    /// written. A point the target's own state does not allow refuses.
    pub fn observe(&self, request_bytes: &[u8]) -> Result<Vec<u8>, OwnerError> {
        let request = decode::<ObserveRequest>(request_bytes)?;
        let guard = self.store.lock(false)?;
        let attempt = self
            .store
            .load(&guard)?
            .ok_or(OwnerError::Refused("no active attempt"))?;
        let collected = attempt.collect(&request, &self.facts)?;
        if self.store.load(&guard)?.as_ref() != Some(&attempt) {
            return Err(OwnerError::Stale);
        }
        Ok(encode(&collected)?)
    }
}

impl<F: TargetFacts> PlanReadOwner for LocalOwner<F> {
    type Facts = Attempt;
    type Held<'a>
        = Guard<'a>
    where
        Self: 'a;

    fn capture(&self, scope: &ReadScope) -> Result<OwnerSnapshot<Attempt>, OwnerRefusal> {
        let guard = self
            .store
            .lock(false)
            .map_err(|_| OwnerRefusal("owner store is unavailable"))?;
        self.snapshot(&guard, scope)
    }

    fn lock_and_capture<'a>(
        &'a self,
        scope: &ReadScope,
    ) -> Result<(Guard<'a>, OwnerSnapshot<Attempt>), OwnerRefusal> {
        let guard = self
            .store
            .lock(true)
            .map_err(|_| OwnerRefusal("owner store is unavailable"))?;
        let snapshot = self.snapshot(&guard, scope)?;
        Ok((guard, snapshot))
    }
}

impl<F: TargetFacts> LocalOwner<F> {
    fn snapshot(
        &self,
        guard: &Guard<'_>,
        scope: &ReadScope,
    ) -> Result<OwnerSnapshot<Attempt>, OwnerRefusal> {
        let attempt = self
            .store
            .load(guard)
            .map_err(|_| OwnerRefusal("active attempt is unreadable"))?
            .ok_or(OwnerRefusal("no active attempt"))?;
        if attempt.x != *scope.x() || attempt.registered != *scope.registered() {
            return Err(OwnerRefusal("operation is not the active attempt"));
        }
        let record = attempt.record(scope.resource());
        let launched = record.handoff.is_some() || record.exit.is_some();
        let allowed = match scope.point() {
            ReadPoint::Prearm => attempt.enrolled.is_none() && !launched,
            ReadPoint::Launch => attempt.enrolled.is_some() && record.consumed.is_none(),
            ReadPoint::Seal => {
                scope.resource() == Resource::Daemon
                    && attempt.daemon.retirement.is_some()
                    && attempt.daemon.seal.is_some()
            }
        };
        if !allowed {
            return Err(OwnerRefusal("point is not available in this attempt state"));
        }
        let rebooted = self
            .facts
            .boot()
            .map_err(|_| OwnerRefusal("the target's boot is unreadable"))?
            != attempt.boot;
        if rebooted {
            return Err(OwnerRefusal("the target rebooted"));
        }
        for role in [Resource::Daemon, Resource::Authority] {
            attempt.check_processes(role, &self.facts).map_err(|_| {
                OwnerRefusal("an original or custodian is not the enrolled process")
            })?;
        }
        let original = OriginalOwner::from_local_owner(
            scope.resource(),
            attempt.registered.clone(),
            attempt.x.host.clone(),
            record.original.clone(),
            record.custodian.clone(),
        );
        let bytes = hex::decode(&attempt.plan_bytes).map_err(|_| OwnerRefusal("stored plan"))?;
        OwnerSnapshot::new(&bytes, original, attempt)
            .map_err(|_| OwnerRefusal("stored plan is not the original's"))
    }
}

#[allow(dead_code)]
fn _point_name(point: Point) -> &'static str {
    match point {
        Point::Prearm => "prearm",
        Point::Launch => "launch",
        Point::Seal => "seal",
    }
}
