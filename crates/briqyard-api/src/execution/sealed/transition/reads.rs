//! The signed reads (`HRead`, `ARead`, `ApiView`), the pre-adoption observe pair and the
//! capacity predicates every read repeats.

use super::common::{check_clock_binding, clock_is_from, refuse, HostClock, LitNull};
use super::evidence::{check_bind, Gate, Guard, GuardPhase, Intent, IntentPhase};
use crate::execution::sealed::canonical::{h, CodecError, Wire};
use crate::execution::sealed::objects::{
    Ack, Bind, ClaimKind, Dims, Proc, Projection, ProjectionAction, Q,
};
use crate::execution::sealed::prim::{nullable, HexDigest, Ident, Nonce, Uint};
use crate::execution::sealed::sig::Sig;
use serde::{Deserialize, Serialize};

/// One owner's capacity view: its actual dimensions and exactly the projection rows that owner
/// answers for, in the contract's order. Same wire shape as the contract's `Cap`; the host's
/// are `[seal, arm, host_register, release]` and the authority's are
/// `[authority_intent, authority_ack]`. A row of another owner is never present, not
/// even as an all-null placeholder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerCap {
    pub actual: Dims,
    pub projections: Vec<Projection>,
}

impl OwnerCap {
    /// Exactly these rows in this order, each well-formed and based on `basis` (`H(Gate)` or
    /// `H(Guard)`); rows of actions the owner has already passed carry no target, next, reserve
    /// or ACK, and keep their basis.
    fn check(
        &self,
        rows: &[ProjectionAction],
        basis: &HexDigest,
        past: &[ProjectionAction],
    ) -> Result<(), CodecError> {
        if self.projections.len() != rows.len()
            || self
                .projections
                .iter()
                .zip(rows)
                .any(|(row, want)| row.action != *want)
        {
            return refuse("capacity rows");
        }
        for row in &self.projections {
            row.validate()?;
            if row.basis != *basis {
                return refuse("projection basis");
            }
            let null = row.target.is_none();
            if past.contains(&row.action) && !null {
                return refuse("past projection");
            }
        }
        Ok(())
    }
}

/// The listed rows all have an exact target, a reserve and fit: unknown input is never
/// read as fitting. When a candidate (`next`) is present it must fit too.
pub fn require_fit(cap: &OwnerCap, actions: &[ProjectionAction]) -> Result<(), CodecError> {
    let fits = |dims: &Option<Dims>| dims.as_ref().is_some_and(|d| d.fits);
    for action in actions {
        let row: &Projection = cap
            .projections
            .iter()
            .find(|row| row.action == *action)
            .ok_or(CodecError::Value("capacity row"))?;
        if row.target.is_none() || !fits(&row.reserve) || row.next.as_ref().is_some_and(|d| !d.fits)
        {
            return refuse("capacity does not fit");
        }
    }
    Ok(())
}

const H_ROWS: [ProjectionAction; 4] = [
    ProjectionAction::Seal,
    ProjectionAction::Arm,
    ProjectionAction::HostRegister,
    ProjectionAction::Release,
];
const A_ROWS: [ProjectionAction; 2] = [
    ProjectionAction::AuthorityIntent,
    ProjectionAction::AuthorityAck,
];

/// `HRead` body: the host's signed gate for one fresh query.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HReadBody {
    pub q: Q,
    pub plan: HexDigest,
    pub proc: Proc,
    pub gate: Gate,
    pub gate_hash: HexDigest,
    pub water: Uint,
    pub cap: OwnerCap,
}

impl Wire for HReadBody {
    /// The gate is for this query's X and plan and hashes to `gate_hash`; the reader is the
    /// process the cut started for this serial; the registration high-water is the one the
    /// phase implies; the capacity rows are exactly the host's four, based on the gate, and
    /// rows of actions the gate already passed are all-null.
    fn validate(&self) -> Result<(), CodecError> {
        self.gate.validate()?;
        if self.gate.x != self.q.x
            || self.gate.plan != self.plan
            || self.gate_hash != self.gate.hash()?
            || self.proc != self.gate.committed_cut().new_proc
            || self.water.get() != self.gate.implied_water()
        {
            return refuse("host read");
        }
        let rank = self.gate.phase as usize;
        self.cap
            .check(&H_ROWS, &self.gate_hash, &H_ROWS[..rank.min(H_ROWS.len())])
    }
}

pub type HRead = Sig<HReadBody>;

/// `ARead` body: the authority's signed guard and registration intent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AReadBody {
    pub q: Q,
    pub plan: HexDigest,
    pub proc: Proc,
    pub guard: Guard,
    pub guard_hash: HexDigest,
    pub salt: Nonce,
    pub host_clock: HostClock,
    pub native_water: Uint,
    #[serde(deserialize_with = "nullable")]
    pub intent: Option<Intent>,
    pub uncertain: bool,
    pub ready: bool,
    pub cap: OwnerCap,
}

impl Wire for AReadBody {
    /// Guard and process are the authority's own; the nested clock answers this query's
    /// salted challenge; an actual intent is the adopted guard's original one; ready needs a
    /// ready intent and no permanent uncertainty; rows for passed actions are all-null.
    fn validate(&self) -> Result<(), CodecError> {
        self.guard.validate()?;
        self.host_clock.validate()?;
        if self.guard.x != self.q.x
            || self.guard.plan != self.plan
            || self.guard.proc != self.proc
            || self.guard_hash != self.guard.hash()?
        {
            return refuse("authority read");
        }
        check_clock_binding(&self.host_clock, &self.q, &self.plan, &self.salt)?;

        let mut past: &[ProjectionAction] = &[];
        match &self.intent {
            None => {
                if self.ready {
                    return refuse("ready without intent");
                }
            }
            Some(intent) => {
                intent.validate()?;
                let adopted = self
                    .guard
                    .bind
                    .as_ref()
                    .filter(|_| self.guard.phase == GuardPhase::Adopted);
                let Some(bind) = adopted else {
                    return refuse("intent outside the binding");
                };
                if intent.id != bind.intent
                    || intent.record != bind.record
                    || intent.guard != self.guard_hash
                {
                    return refuse("intent outside the binding");
                }
                past = match intent.phase {
                    IntentPhase::Pending => &A_ROWS[..1],
                    IntentPhase::Ready => &A_ROWS[..],
                };
                if self.ready && (intent.phase != IntentPhase::Ready || self.uncertain) {
                    return refuse("ready state");
                }
            }
        }
        self.cap.check(&A_ROWS, &self.guard_hash, past)
    }
}

impl AReadBody {
    /// The nested clock sample is this host process and journal instance, the ones the verified
    /// host read and its cut name.
    pub fn check_host(&self, proc: &Proc, instance: &Ident) -> Result<(), CodecError> {
        if !clock_is_from(&self.host_clock, proc, instance) {
            return refuse("host clock sample");
        }
        Ok(())
    }

    /// `ARead` selects the intent ID from its adopted guard's bind or, for an unbound
    /// started guard only, the query's preview, which must match its own epoch and set. With no
    /// ID selected there is no intent, nothing ready and no uncertain marker.
    pub fn check_selection(&self, preview: Option<&Bind>) -> Result<(), CodecError> {
        let selected = match (&self.guard.bind, preview) {
            (Some(bind), _) => Some(bind),
            (None, Some(preview)) if self.guard.phase == GuardPhase::Started => {
                if preview.set != self.guard.set || preview.record.epoch != self.guard.epoch {
                    return refuse("preview selection");
                }
                Some(preview)
            }
            (None, _) => None,
        };
        match selected {
            None if self.intent.is_some() || self.ready || self.uncertain => {
                refuse("no selected intent")
            }
            Some(bind) if self.intent.as_ref().is_some_and(|i| i.id != bind.intent) => {
                refuse("selected intent")
            }
            _ => Ok(()),
        }
    }
}

pub type ARead = Sig<AReadBody>;

/// `ApiView.state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiState {
    #[serde(rename = "frozen")]
    Frozen,
    #[serde(rename = "reserved")]
    Reserved,
    #[serde(rename = "committing")]
    Committing,
    #[serde(rename = "observed")]
    Observed,
    #[serde(rename = "abandoned")]
    Abandoned,
}

/// `snapshot = H({bind, intent: row_intent, ack: row_ack})`.
#[derive(Serialize)]
struct RowSnapshot<'a> {
    bind: &'a Bind,
    intent: &'a Ident,
    ack: &'a Ack,
}

/// `ApiView` body: B's own durable stage for the one active slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiViewBody {
    pub q: Q,
    pub plan: HexDigest,
    #[serde(deserialize_with = "nullable")]
    pub bind: Option<Bind>,
    #[serde(deserialize_with = "nullable")]
    pub step: Option<ClaimKind>,
    pub state: ApiState,
    #[serde(deserialize_with = "nullable")]
    pub claim: Option<Nonce>,
    #[serde(deserialize_with = "nullable")]
    pub permit: Option<HexDigest>,
    pub api_water: Uint,
    #[serde(deserialize_with = "nullable")]
    pub row_ack: Option<Ack>,
    #[serde(deserialize_with = "nullable")]
    pub row_intent: Option<Ident>,
    #[serde(deserialize_with = "nullable")]
    pub snapshot: Option<HexDigest>,
    pub pause_owned: bool,
    pub interlock_owned: bool,
}

impl Wire for ApiViewBody {
    /// Frozen has no step, claim or permit (its bind is null only before the prospective bind
    /// exists); reserved and abandoned keep bind, step and claim and never a permit; committing
    /// has them and a permit only once persisted; observed keeps all four. The row triple is
    /// all-null or all-present and then bound to the bind's own intent and ACK.
    fn validate(&self) -> Result<(), CodecError> {
        let identity = self.bind.is_some() && self.step.is_some() && self.claim.is_some();
        let ok = match self.state {
            ApiState::Frozen => {
                self.step.is_none() && self.claim.is_none() && self.permit.is_none()
            }
            ApiState::Reserved | ApiState::Abandoned => identity && self.permit.is_none(),
            ApiState::Committing => identity,
            ApiState::Observed => identity && self.permit.is_some(),
        };
        if !ok {
            return refuse("api view state");
        }
        if let Some(bind) = &self.bind {
            check_bind(bind)?;
            if bind.x != self.q.x || bind.plan != self.plan {
                return refuse("api view bind");
            }
            if self.state == ApiState::Observed
                && self.step == Some(ClaimKind::RecordAck)
                && (self.snapshot.is_none() || self.api_water.get() != bind.record.generation.get())
            {
                return refuse("api view record_ack");
            }
        }
        match (&self.row_intent, &self.row_ack, &self.snapshot, &self.bind) {
            (None, None, None, _) => Ok(()),
            (Some(intent), Some(ack), Some(snapshot), Some(bind)) => {
                if *intent != bind.intent
                    || *ack != bind.record.ack()
                    || *snapshot != h(&RowSnapshot { bind, intent, ack })?
                {
                    return refuse("api view row");
                }
                Ok(())
            }
            _ => refuse("api view row"),
        }
    }
}

impl ApiViewBody {
    /// B's view permits a crossing: this exact bind, action, claim and permit, committing,
    /// the pause and interlock owned, and API water at the value the action needs.
    pub fn check_crossing(
        &self,
        bind: &Bind,
        action: ClaimKind,
        claim: &Nonce,
        permit: &HexDigest,
    ) -> Result<(), CodecError> {
        let water = if action == ClaimKind::Arm || action == ClaimKind::Adopt {
            bind.prior.get()
        } else {
            bind.record.generation.get()
        };
        if self.state != ApiState::Committing
            || self.bind.as_ref() != Some(bind)
            || self.step != Some(action)
            || self.claim.as_ref() != Some(claim)
            || self.permit.as_ref() != Some(permit)
            || !self.pause_owned
            || !self.interlock_owned
            || self.api_water.get() != water
        {
            return refuse("api crossing");
        }
        Ok(())
    }

    /// Before a release decision R requires `record_ack` observed with this bind and claim,
    /// the original ready row's triple and the API water at N+1, all together.
    pub fn check_release_ready(&self, bind: &Bind, claim: &Nonce) -> Result<(), CodecError> {
        if self.state != ApiState::Observed
            || self.step != Some(ClaimKind::RecordAck)
            || self.bind.as_ref() != Some(bind)
            || self.claim.as_ref() != Some(claim)
            || self.snapshot.is_none()
            || self.api_water.get() != bind.record.generation.get()
        {
            return refuse("api release readiness");
        }
        Ok(())
    }
}

pub type ApiView = Sig<ApiViewBody>;

/// `query.observe`/`authority.observe` `kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObserveKind {
    #[serde(rename = "clock")]
    Clock,
    #[serde(rename = "protection")]
    Protection,
}

/// `authority.observe.status`: only these two are ever reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObserveStatus {
    #[serde(rename = "not_requested")]
    NotRequested,
    #[serde(rename = "unknown")]
    Unknown,
}

/// `query.observe` body: a clock id is null, a protection id names the approved singleton.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserveQueryBody {
    pub q: Q,
    pub plan: HexDigest,
    pub kind: ObserveKind,
    #[serde(deserialize_with = "nullable")]
    pub id: Option<Ident>,
}

impl Wire for ObserveQueryBody {
    fn validate(&self) -> Result<(), CodecError> {
        if (self.kind == ObserveKind::Clock) != self.id.is_none() {
            return refuse("observe id");
        }
        Ok(())
    }
}

/// `authority.observe` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityObserveBody {
    pub q: Q,
    pub plan: HexDigest,
    pub proc: Proc,
    pub guard: HexDigest,
    pub salt: Nonce,
    pub host_clock: HostClock,
    pub kind: ObserveKind,
    #[serde(deserialize_with = "nullable")]
    pub id: Option<Ident>,
    pub now: Uint,
    pub uncertainty: Uint,
    pub host_now: Uint,
    pub host_uncertainty: Uint,
    pub status: ObserveStatus,
    pub evidence: LitNull,
}

impl Wire for AuthorityObserveBody {
    /// A clock observation has a null id and `not_requested`; a protection one has an id and
    /// `unknown`; evidence is always null. Uncertainties are at most 5 s and the host sample
    /// equals the nested clock reply that answers this query's salted challenge.
    fn validate(&self) -> Result<(), CodecError> {
        self.host_clock.validate()?;
        let (id, status) = match self.kind {
            ObserveKind::Clock => (false, ObserveStatus::NotRequested),
            ObserveKind::Protection => (true, ObserveStatus::Unknown),
        };
        if self.id.is_some() != id || self.status != status {
            return refuse("observe kind");
        }
        let clock = &self.host_clock.body;
        if self.uncertainty.get() > 5
            || self.host_uncertainty.get() > 5
            || self.host_now != clock.now
            || self.host_uncertainty != clock.uncertainty
        {
            return refuse("observe clock");
        }
        check_clock_binding(&self.host_clock, &self.q, &self.plan, &self.salt)
    }
}

impl AuthorityObserveBody {
    /// The nested clock sample is the host process and journal instance of the verified host
    /// read and its cut.
    pub fn check_host(&self, proc: &Proc, instance: &Ident) -> Result<(), CodecError> {
        if !clock_is_from(&self.host_clock, proc, instance) {
            return refuse("host clock sample");
        }
        Ok(())
    }

    /// It answers exactly this request: same query, plan, kind and id; and this guard.
    pub fn check_request(
        &self,
        request: &ObserveQueryBody,
        guard: &Guard,
    ) -> Result<(), CodecError> {
        if self.q != request.q
            || self.plan != request.plan
            || self.kind != request.kind
            || self.id != request.id
            || self.guard != guard.hash()?
            || guard.phase != GuardPhase::Started
            || self.proc != guard.proc
        {
            return refuse("observe request");
        }
        Ok(())
    }
}

/// `final.query` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalQueryBody {
    pub q: Q,
    pub plan: HexDigest,
}

impl Wire for FinalQueryBody {}

/// `final.read.stage`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FinalStage {
    #[serde(rename = "held")]
    Held,
    #[serde(rename = "verified")]
    Verified,
    #[serde(rename = "readmitted")]
    Readmitted,
}

/// `final.read.placement`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Placement {
    #[serde(rename = "unknown")]
    Unknown,
    #[serde(rename = "ready")]
    Ready,
}

/// `final.read` body: B's own durable external stage. `trial` is the archived complete
/// B-challenged status's hash, null until verified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalReadBody {
    pub q: Q,
    pub plan: HexDigest,
    pub stage: FinalStage,
    #[serde(deserialize_with = "nullable")]
    pub trial: Option<HexDigest>,
    #[serde(deserialize_with = "nullable")]
    pub release: Option<HexDigest>,
    pub placement: Placement,
    #[serde(deserialize_with = "nullable")]
    pub row_ack: Option<Ack>,
}

impl Wire for FinalReadBody {
    /// Held has no trial commitment. Verified and readmitted have the trial, the release digest
    /// and the original row ACK; readmitted also has `ready` as the last successful placement
    /// observation (not a claim of current liveness).
    fn validate(&self) -> Result<(), CodecError> {
        let verified = self.stage != FinalStage::Held;
        if verified != self.trial.is_some() {
            return refuse("final stage trial");
        }
        if verified && (self.release.is_none() || self.row_ack.is_none()) {
            return refuse("final stage evidence");
        }
        if self.stage == FinalStage::Readmitted && self.placement != Placement::Ready {
            return refuse("final stage placement");
        }
        Ok(())
    }
}

impl FinalReadBody {
    /// It answers exactly this query.
    pub fn check_query(&self, query: &FinalQueryBody) -> Result<(), CodecError> {
        if self.q != query.q || self.plan != query.plan {
            return refuse("final query");
        }
        Ok(())
    }
}
