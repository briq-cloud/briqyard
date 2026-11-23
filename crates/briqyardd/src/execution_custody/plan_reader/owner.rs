//! The join an operation owner implements, and the non-authorizing result of a read.
//!
//! A read is network and process I/O, so it never runs under the owner's lock. The flow is:
//! capture the owner's immutable facts and exact local Plan, release every lock, read, then
//! reacquire the owner's locks in their prescribed order and compare **all** captured facts
//! again before the observation may be used. The owner supplies the state; this module owns
//! the comparison, so an owner cannot answer "unchanged" for itself.
//!
//! No concrete root operation owner exists at this boundary yet. [`PlanReadOwner`] is
//! the exact interface the next package implements; nothing here substitutes an
//! `is_owned` flag, a trusted callback, a hash argument or a synthetic owner state.

use super::trust::TrustLoader;
use super::verify::verify_pair;
use super::wire::{EnrolledHelper, ReaderEndpoint};
use super::{Deadline, PlanReadError};
use briqyard_api::execution::sealed::{
    canonical::encode,
    custody::Resource,
    objects::X,
    plan_pin::{LocalPlan, Pin, Read, ReadFormat, ReadPoint},
    prim::{Ident, Nonce},
};
use std::sync::{Arc, Mutex, PoisonError};

/// Exactly what one read is about: the operation, the resource and the point. The point selects
/// the state the owner must be in; it is not an action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadScope {
    x: X,
    registered: Ident,
    resource: Resource,
    point: ReadPoint,
}

impl ReadScope {
    pub fn new(
        x: X,
        registered: Ident,
        resource: Resource,
        point: ReadPoint,
    ) -> Result<Self, PlanReadError> {
        if point == ReadPoint::Seal && resource != Resource::Daemon {
            return Err(PlanReadError::Scope("seal is daemon-only"));
        }
        Ok(Self {
            x,
            registered,
            resource,
            point,
        })
    }

    pub fn x(&self) -> &X {
        &self.x
    }

    pub fn registered(&self) -> &Ident {
        &self.registered
    }

    pub fn resource(&self) -> Resource {
        self.resource
    }

    pub fn point(&self) -> ReadPoint {
        self.point
    }

    fn request(&self, nonce: Nonce) -> Read {
        Read {
            format: ReadFormat::V1,
            x: self.x.clone(),
            registered: self.registered.clone(),
            resource: self.resource,
            point: self.point,
            nonce,
        }
    }
}

/// Why an owner declined to produce a snapshot: a historical, terminal, unknown or competing
/// operation, a missing hold, a wrong stage for the point, or no durable state at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerRefusal(pub &'static str);

impl From<OwnerRefusal> for PlanReadError {
    fn from(refusal: OwnerRefusal) -> Self {
        PlanReadError::Owner(refusal.0)
    }
}

/// The owner's immutable facts at one instant: the exact canonical Plan bytes from its own
/// durable record (never an offer's) and whatever else must not change across the read
/// (owner, boot, phase, serial, holds, floors, freshness).
#[derive(Debug, PartialEq, Eq)]
pub struct OwnerSnapshot<F> {
    plan: LocalPlan,
    facts: F,
}

impl<F> OwnerSnapshot<F> {
    pub fn new(plan_bytes: &[u8], facts: F) -> Result<Self, PlanReadError> {
        let plan = LocalPlan::decode(plan_bytes)
            .map_err(|_| PlanReadError::Owner("owner Plan is not canonical"))?;
        Ok(Self { plan, facts })
    }
}

/// What a root operation owner implements for this reader.
///
/// * `capture` takes the owner's locks in their prescribed order, reads the snapshot for
///   `scope`, and releases every lock before returning. It refuses a non-active, terminal,
///   historical, competing or unknown operation and a point the state does not allow.
/// * `lock_and_capture` takes the same locks in the same order, reads the snapshot again
///   and **keeps** them in the returned `Held`. It must not deadlock against the owner's own
///   install lease, and no I/O may run while it holds anything.
///
/// The reader compares the two snapshots. Implementations never report their own equality.
pub trait PlanReadOwner {
    type Facts: Eq + std::fmt::Debug;
    type Held<'a>
    where
        Self: 'a;

    fn capture(&self, scope: &ReadScope) -> Result<OwnerSnapshot<Self::Facts>, OwnerRefusal>;

    fn lock_and_capture<'a>(
        &'a self,
        scope: &ReadScope,
    ) -> Result<(Self::Held<'a>, OwnerSnapshot<Self::Facts>), OwnerRefusal>;
}

/// At most one outstanding read per resource, held from the request until the observation
/// is dropped, so a nonce is never in two uses and a proof is consumed once.
#[derive(Default)]
struct ReadLedger {
    outstanding: Mutex<Vec<(Resource, Nonce)>>,
}

struct NonceSlot {
    ledger: Arc<ReadLedger>,
    resource: Resource,
}

impl ReadLedger {
    fn begin(
        self: &Arc<Self>,
        resource: Resource,
        nonce: Nonce,
    ) -> Result<NonceSlot, PlanReadError> {
        let mut outstanding = self
            .outstanding
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if outstanding
            .iter()
            .any(|(held, used)| *held == resource || *used == nonce)
        {
            return Err(PlanReadError::Scope(
                "a read of this resource is outstanding",
            ));
        }
        outstanding.push((resource, nonce));
        Ok(NonceSlot {
            ledger: Arc::clone(self),
            resource,
        })
    }
}

impl Drop for NonceSlot {
    fn drop(&mut self) {
        self.ledger
            .outstanding
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(held, _)| *held != self.resource);
    }
}

fn fresh_nonce() -> Result<Nonce, PlanReadError> {
    let mut raw = [0u8; 32];
    let mut filled = 0;
    while filled < raw.len() {
        let got =
            unsafe { libc::getrandom(raw[filled..].as_mut_ptr().cast(), raw.len() - filled, 0) };
        if got < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(super::io("read the OS random source", error));
        }
        filled += got as usize;
    }
    Ok(Nonce::from_array(raw))
}

/// Both enrolled observers signed this pin of this local Plan for one nonce, and nothing has
/// changed locally since.
///
/// **Not authority.** It carries no capability, has no wire form, cannot be cloned or turned
/// into a rooted act, and must not be offered to a guard or candidate as a trusted pin. It
/// holds its nonce until dropped and expires five seconds after the request began.
#[must_use = "an observation authorizes nothing and expires"]
pub struct VerifiedPlanObservation {
    read: Read,
    pin: Pin,
    deadline: Deadline,
    _slot: NonceSlot,
}

impl VerifiedPlanObservation {
    pub fn read(&self) -> &Read {
        &self.read
    }

    pub fn pin(&self) -> &Pin {
        &self.pin
    }
}

/// An observation and the owner's locks it was compared under, for the next package's single
/// consequential gate. Dropping it releases both.
#[must_use = "an observation authorizes nothing and expires"]
pub struct RejoinedObservation<H> {
    observation: VerifiedPlanObservation,
    held: H,
}

impl<H> RejoinedObservation<H> {
    /// The observation and the held owner state, only while the five seconds last.
    pub fn fresh(&self) -> Result<(&VerifiedPlanObservation, &H), PlanReadError> {
        self.observation.deadline.check("local use")?;
        Ok((&self.observation, &self.held))
    }
}

pub struct PlanReader {
    trust: TrustLoader,
    endpoint: ReaderEndpoint,
    ledger: Arc<ReadLedger>,
}

impl PlanReader {
    /// The production reader: the fixed trust tree and the fixed socket, root only.
    pub fn system(helper: EnrolledHelper) -> Result<Self, PlanReadError> {
        Ok(Self {
            trust: TrustLoader::system()?,
            endpoint: ReaderEndpoint::fixed(helper)?,
            ledger: Arc::default(),
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(trust: TrustLoader, endpoint: ReaderEndpoint) -> Self {
        Self {
            trust,
            endpoint,
            ledger: Arc::default(),
        }
    }

    pub fn observe<'o, O: PlanReadOwner>(
        &self,
        owner: &'o O,
        scope: &ReadScope,
    ) -> Result<RejoinedObservation<O::Held<'o>>, PlanReadError> {
        self.observe_within(owner, scope, Deadline::start())
    }

    pub(super) fn observe_within<'o, O: PlanReadOwner>(
        &self,
        owner: &'o O,
        scope: &ReadScope,
        deadline: Deadline,
    ) -> Result<RejoinedObservation<O::Held<'o>>, PlanReadError> {
        let before = owner.capture(scope)?;
        let plan = before.plan.plan();
        if plan.x != scope.x || plan.registered != scope.registered {
            return Err(PlanReadError::Scope(
                "owner Plan is not the requested operation",
            ));
        }
        let trust = self.trust.load(&scope.x, &scope.registered)?;

        let nonce = fresh_nonce()?;
        let slot = self.ledger.begin(scope.resource, nonce)?;
        let request = scope.request(nonce);
        let reply = self.endpoint.exchange(
            &encode(&request).map_err(|_| PlanReadError::Scope("request is not encodable"))?,
            deadline,
        )?;
        let pin = verify_pair(&reply, &request, &before.plan, &trust)?;

        let (held, after) = owner.lock_and_capture(scope)?;
        if after != before {
            return Err(PlanReadError::Owner("owner changed during the read"));
        }
        deadline.check("local consumption")?;
        Ok(RejoinedObservation {
            observation: VerifiedPlanObservation {
                read: request,
                pin,
                deadline,
                _slot: slot,
            },
            held,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use briqyard_api::execution::sealed::{
        objects::X,
        plan_pin::{PinFormat, ReadPoint},
        prim::{Env, HexDigest, PosInt},
    };
    use std::time::Duration;

    fn observation(ledger: &Arc<ReadLedger>, deadline: Deadline) -> VerifiedPlanObservation {
        let x = X {
            aud: Env::Staging,
            host: Ident::new("host.test").unwrap(),
            op: HexDigest::from_raw([0; 32]),
            serial: PosInt::new(1).unwrap(),
        };
        let registered = Ident::new("registered.test").unwrap();
        let nonce = Nonce::from_array([1; 32]);
        VerifiedPlanObservation {
            read: Read {
                format: ReadFormat::V1,
                x: x.clone(),
                registered: registered.clone(),
                resource: Resource::Daemon,
                point: ReadPoint::Launch,
                nonce,
            },
            pin: Pin {
                format: PinFormat::V1,
                x,
                registered,
                plan: HexDigest::from_raw([2; 32]),
            },
            deadline,
            _slot: ledger.begin(Resource::Daemon, nonce).unwrap(),
        }
    }

    #[test]
    fn an_observation_expires_with_its_deadline_and_releases_its_nonce_on_drop() {
        let ledger = Arc::new(ReadLedger::default());
        let live = RejoinedObservation {
            observation: observation(&ledger, Deadline::within(Duration::from_secs(60))),
            held: (),
        };
        assert!(live.fresh().is_ok());
        assert!(ledger
            .begin(Resource::Daemon, Nonce::from_array([2; 32]))
            .is_err());
        drop(live);

        let expired = RejoinedObservation {
            observation: observation(&ledger, Deadline::within(Duration::ZERO)),
            held: (),
        };
        assert!(matches!(
            expired.fresh(),
            Err(PlanReadError::Deadline { stage: "local use" })
        ));
        drop(expired);
        assert!(ledger.outstanding.lock().unwrap().is_empty());
    }

    #[test]
    fn the_ledger_holds_at_most_one_read_per_resource_and_never_a_repeated_nonce() {
        let ledger = Arc::new(ReadLedger::default());
        let nonce = Nonce::from_array([3; 32]);
        let first = ledger.begin(Resource::Daemon, nonce).unwrap();
        assert!(ledger
            .begin(Resource::Daemon, Nonce::from_array([4; 32]))
            .is_err());
        assert!(ledger.begin(Resource::Authority, nonce).is_err());
        let second = ledger
            .begin(Resource::Authority, Nonce::from_array([5; 32]))
            .unwrap();
        assert_eq!(ledger.outstanding.lock().unwrap().len(), 2);
        drop((first, second));
        assert!(ledger.outstanding.lock().unwrap().is_empty());
    }

    #[test]
    fn nonces_come_from_the_os_and_do_not_repeat() {
        let drawn: Vec<Nonce> = (0..64).map(|_| fresh_nonce().unwrap()).collect();
        for (at, nonce) in drawn.iter().enumerate() {
            assert_ne!(nonce.as_array(), &[0; 32]);
            assert!(drawn[at + 1..].iter().all(|other| other != nonce));
        }
    }
}
