//! The target's one active local attempt: every durable fact the collector projects and every
//! transition that is allowed to change one. A transition takes the current record and returns
//! the next; the caller commits it by version compare-and-set. Nothing here does I/O except
//! the live measurements a [`TargetFacts`] and a [`RetainedProcess`] answer, and nothing
//! reads a version it was not handed.

use super::facts::{
    version_after, FinalIo, MeasuredProc, RetainedProcess, TargetFacts, UnitMeasure,
};
use super::OwnerError;
use briqyard_api::execution::sealed::{
    canonical::{h, CodecError, Wire},
    custody::{Capture, Resource},
    objects::{Plan, Proc, X},
    owner::{
        ArmFormat, ArmReceipt, DaemonRetirement, ExitState, FragmentState, Fragments, Images,
        JobState, LaunchCapture, Leases, Observation, ObservationFormat, ObserveRequest, Point,
        Retired, TargetTag, Turn, UnitObservation, UnitState,
    },
    prim::{nullable, BootId, HexDigest, Ident, Nonce, PosInt},
    sig::{PinnedKey, Tag},
    transition::{Death, LGrant, LKind, Launch, LaunchStage, Receipt},
};
use serde::{Deserialize, Serialize};

const MAX_EVENTS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum EventKind {
    #[serde(rename = "handoff")]
    Handoff,
    #[serde(rename = "exit")]
    Exit,
    #[serde(rename = "guard_start")]
    GuardStart,
}

/// One lineage fact: the evidence version that recorded it, what it was and for which resource.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Event {
    pub(super) version: PosInt,
    pub(super) kind: EventKind,
    pub(super) resource: Resource,
}

/// The four effective-unit commitments seen at one instant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UnitCommit {
    pub(super) fragment: HexDigest,
    pub(super) argv: HexDigest,
    pub(super) sandbox: HexDigest,
    pub(super) fdstore: HexDigest,
}

impl From<&UnitMeasure> for UnitCommit {
    fn from(unit: &UnitMeasure) -> Self {
        Self {
            fragment: unit.fragment.clone(),
            argv: unit.argv.clone(),
            sandbox: unit.sandbox.clone(),
            fdstore: unit.fdstore.clone(),
        }
    }
}

/// The one-use local authorization recorded before the process changes: the exact grant, the
/// target version it was compared at and everything the lineage must leave unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Handoff {
    pub(super) action: LKind,
    pub(super) base: PosInt,
    pub(super) grant: HexDigest,
    pub(super) turn: HexDigest,
    pub(super) decision: HexDigest,
    pub(super) owner: Nonce,
    #[serde(deserialize_with = "nullable")]
    pub(super) captured_launch: Option<HexDigest>,
    #[serde(deserialize_with = "nullable")]
    pub(super) capture: Option<HexDigest>,
    pub(super) unit: UnitCommit,
    pub(super) leases: Leases,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GuardStart {
    pub(super) version: PosInt,
    pub(super) pid: PosInt,
    pub(super) start: PosInt,
    pub(super) exe: HexDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Consumed {
    pub(super) version: PosInt,
    pub(super) grant: HexDigest,
    pub(super) launch: HexDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    #[serde(deserialize_with = "nullable")]
    pub(super) lease: Option<HexDigest>,
    pub(super) original: Proc,
    pub(super) custodian: Proc,
    pub(super) guard_image: HexDigest,
    pub(super) fragment: FragmentState,
    #[serde(deserialize_with = "nullable")]
    pub(super) arm: Option<ArmReceipt>,
    #[serde(deserialize_with = "nullable")]
    pub(super) captured: Option<LaunchCapture>,
    #[serde(deserialize_with = "nullable")]
    pub(super) exit: Option<PosInt>,
    pub(super) final_io: bool,
    #[serde(deserialize_with = "nullable")]
    pub(super) retirement: Option<DaemonRetirement>,
    #[serde(deserialize_with = "nullable")]
    pub(super) handoff: Option<Handoff>,
    #[serde(deserialize_with = "nullable")]
    pub(super) seal: Option<Handoff>,
    #[serde(deserialize_with = "nullable")]
    pub(super) guard: Option<GuardStart>,
    #[serde(deserialize_with = "nullable")]
    pub(super) consumed: Option<Consumed>,
}

impl Record {
    fn new(original: Proc, custodian: Proc, guard_image: HexDigest) -> Self {
        Self {
            lease: None,
            original,
            custodian,
            guard_image,
            fragment: FragmentState::Legacy,
            arm: None,
            captured: None,
            exit: None,
            final_io: false,
            retirement: None,
            handoff: None,
            seal: None,
            guard: None,
            consumed: None,
        }
    }
}

/// `active.json`: the target-wide owner of one enrolled operation. `version` is the monotone
/// evidence revision of the whole attempt; no transition leaves it unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attempt {
    pub(super) version: PosInt,
    pub(super) x: X,
    pub(super) registered: Ident,
    pub(super) plan: HexDigest,
    pub(super) plan_bytes: String,
    pub(super) target: Ident,
    pub(super) boot: BootId,
    pub(super) generation: PosInt,
    pub(super) lockout: HexDigest,
    #[serde(deserialize_with = "nullable")]
    pub(super) enrolled: Option<PosInt>,
    #[serde(deserialize_with = "nullable")]
    pub(super) seal_receipt: Option<HexDigest>,
    pub(super) daemon: Record,
    pub(super) authority: Record,
    pub(super) events: Vec<Event>,
}

impl Wire for Attempt {
    fn validate(&self) -> Result<(), CodecError> {
        let bytes = hex::decode(&self.plan_bytes).map_err(|_| CodecError::Value("plan bytes"))?;
        let ordered = self
            .events
            .windows(2)
            .all(|pair| pair[0].version < pair[1].version);
        let latest = self
            .events
            .last()
            .is_none_or(|event| event.version <= self.version);
        let armed = self.daemon.arm.is_some() && self.authority.arm.is_some();
        if HexDigest::of(&bytes) != self.plan
            || self.events.len() > MAX_EVENTS
            || !ordered
            || !latest
            || self.enrolled.is_some() != armed
            || (self.daemon.arm.is_some() != self.authority.arm.is_some())
        {
            return Err(CodecError::Value("active attempt"));
        }
        Ok(())
    }
}

/// What the install owner is given for one resource: the retained custodian descriptor and the
/// release pin's build label for it.
pub struct CustodianInput<'a> {
    pub(super) retained: &'a dyn RetainedProcess,
    pub(super) build: briqyard_api::execution::sealed::prim::Build,
}

/// The pinned executable the unit's guard must map, taken from the validated inputs.
pub struct GuardPins {
    pub(super) daemon: HexDigest,
    pub(super) authority: HexDigest,
}

fn random_digest() -> Result<HexDigest, OwnerError> {
    let nonce = crate::execution_custody::plan_reader::fresh_nonce()
        .map_err(|_| OwnerError::Refused("the OS random source is unavailable"))?;
    Ok(HexDigest::from_raw(*nonce.as_array()))
}

fn proc_of(
    measured: &MeasuredProc,
    build: briqyard_api::execution::sealed::prim::Build,
) -> Result<Proc, OwnerError> {
    Ok(Proc {
        boot: measured.boot.clone(),
        pid: PosInt::new(measured.pid).map_err(|_| OwnerError::Refused("pid"))?,
        start: PosInt::new(measured.start).map_err(|_| OwnerError::Refused("start ticks"))?,
        exe: measured.exe.clone(),
        build,
    })
}

impl Attempt {
    pub(super) fn record(&self, resource: Resource) -> &Record {
        match resource {
            Resource::Daemon => &self.daemon,
            Resource::Authority => &self.authority,
        }
    }

    fn record_mut(&mut self, resource: Resource) -> &mut Record {
        match resource {
            Resource::Daemon => &mut self.daemon,
            Resource::Authority => &mut self.authority,
        }
    }

    pub(super) fn plan(&self) -> Result<Plan, OwnerError> {
        let bytes = hex::decode(&self.plan_bytes).map_err(|_| OwnerError::Refused("plan bytes"))?;
        briqyard_api::execution::sealed::decode::<Plan>(&bytes)
            .map_err(|_| OwnerError::Refused("stored plan is not canonical"))
    }

    pub(super) fn keys(&self) -> Result<(PinnedKey, PinnedKey, PinnedKey), OwnerError> {
        use briqyard_api::execution::sealed::sig::Role;
        let plan = self.plan()?;
        let pin = |role, key: &briqyard_api::execution::sealed::prim::KeyBytes| {
            PinnedKey::new(role, *key.as_array()).map_err(|_| OwnerError::Refused("plan key"))
        };
        Ok((
            pin(Role::Rk, &plan.rk)?,
            pin(Role::Bk, &plan.bk)?,
            pin(Role::Hk, &plan.hk)?,
        ))
    }

    fn next(&self) -> Result<Attempt, OwnerError> {
        let mut next = self.clone();
        next.version = version_after(&self.version)?;
        Ok(next)
    }

    fn event(&mut self, kind: EventKind, resource: Resource) -> Result<(), OwnerError> {
        if self.events.len() >= MAX_EVENTS {
            return Err(OwnerError::Refused("lineage log is full"));
        }
        self.events.push(Event {
            version: self.version,
            kind,
            resource,
        });
        Ok(())
    }

    /// The genesis record: one operation, from its own trust record, its Plan's originals and
    /// the retained custodians. Never replaces an existing attempt.
    pub(super) fn genesis(
        plan: &briqyard_api::execution::sealed::plan_pin::LocalPlan,
        plan_bytes: &[u8],
        target: Ident,
        custodians: [&CustodianInput<'_>; 2],
        guards: &GuardPins,
        facts: &dyn TargetFacts,
    ) -> Result<Attempt, OwnerError> {
        let local = plan.plan();
        let boot = facts.boot()?;
        let live = |resource: Resource,
                    original: &Proc,
                    custodian: &CustodianInput<'_>,
                    guard: &HexDigest| {
            let running = facts.process(original.pid.get())?;
            if original.boot != boot || !running.is_some_and(|process| process.matches(original)) {
                return Err(OwnerError::Refused(
                    "original is not the live process the Plan names",
                ));
            }
            let retained = custodian.retained.identity()?;
            if custodian.retained.has_exited()? || retained.boot != boot {
                return Err(OwnerError::Refused("custodian is not live on this boot"));
            }
            if facts.guard_image(resource)? != *guard {
                return Err(OwnerError::Refused(
                    "guard image is not the pinned executable",
                ));
            }
            Ok(Record::new(
                original.clone(),
                proc_of(&retained, custodian.build.clone())?,
                guard.clone(),
            ))
        };
        let daemon = live(
            Resource::Daemon,
            &local.pre_d,
            custodians[0],
            &guards.daemon,
        )?;
        let authority = live(
            Resource::Authority,
            &local.pre_a,
            custodians[1],
            &guards.authority,
        )?;
        if daemon.custodian.pid == authority.custodian.pid
            || daemon.custodian.pid == authority.original.pid
            || authority.custodian.pid == daemon.original.pid
            || daemon.original.pid == authority.original.pid
        {
            return Err(OwnerError::Refused(
                "custodians and originals must be distinct processes",
            ));
        }
        let attempt = Attempt {
            version: PosInt::new(1).map_err(|_| OwnerError::Refused("version"))?,
            x: local.x.clone(),
            registered: local.registered.clone(),
            plan: plan.digest().clone(),
            plan_bytes: hex::encode(plan_bytes),
            target,
            boot,
            generation: PosInt::new(1).map_err(|_| OwnerError::Refused("generation"))?,
            lockout: random_digest()?,
            enrolled: None,
            seal_receipt: None,
            daemon,
            authority,
            events: Vec::new(),
        };
        attempt
            .validate()
            .map_err(|_| OwnerError::Refused("genesis record"))?;
        Ok(attempt)
    }

    /// Both leases are the target's own random identities, daemon first, each once.
    pub(super) fn allocate_lease(&self, resource: Resource) -> Result<Attempt, OwnerError> {
        if self.record(resource).lease.is_some() {
            return Err(OwnerError::Refused("lease already allocated"));
        }
        if resource == Resource::Authority && self.daemon.lease.is_none() {
            return Err(OwnerError::Refused("lease order is daemon then authority"));
        }
        let mut next = self.next()?;
        next.record_mut(resource).lease = Some(random_digest()?);
        Ok(next)
    }

    /// The guarded fragment is on disk for `resource`: observed, in lease order, once.
    pub(super) fn install_fragment(
        &self,
        resource: Resource,
        facts: &dyn TargetFacts,
    ) -> Result<Attempt, OwnerError> {
        if self.enrolled.is_some() || self.record(resource).fragment == FragmentState::Guarded {
            return Err(OwnerError::Refused("fragment already installed"));
        }
        if self.record(resource).lease.is_none() {
            return Err(OwnerError::Refused("fragment needs the resource lease"));
        }
        if resource == Resource::Authority && self.daemon.fragment != FragmentState::Guarded {
            return Err(OwnerError::Refused(
                "fragment order is daemon then authority",
            ));
        }
        if facts.fragment(resource)? != FragmentState::Guarded {
            return Err(OwnerError::Refused("the guarded fragment is not on disk"));
        }
        self.require_originals_running(facts)?;
        let mut next = self.next()?;
        next.record_mut(resource).fragment = FragmentState::Guarded;
        Ok(next)
    }

    fn require_originals_running(&self, facts: &dyn TargetFacts) -> Result<(), OwnerError> {
        for resource in [Resource::Daemon, Resource::Authority] {
            let record = self.record(resource);
            if record.exit.is_some() {
                continue;
            }
            let running = facts.process(record.original.pid.get())?;
            if !running.is_some_and(|process| process.matches(&record.original)) {
                return Err(OwnerError::Refused(
                    "an original changed without a witnessed exit",
                ));
            }
        }
        Ok(())
    }

    /// The retained original's own pidfd names the process the Plan does, and it still runs.
    pub(super) fn record_capture(
        &self,
        resource: Resource,
        launch: &Launch,
        capture: &Capture,
        retained: &dyn RetainedProcess,
    ) -> Result<Attempt, OwnerError> {
        let record = self.record(resource);
        let (rk, _, _) = self.keys()?;
        let wire = &capture.verify(Tag::CustodyCapture, &rk)?.wire;
        launch.check_capture(wire)?;
        let live = retained.identity()?;
        if record.captured.is_some()
            || record.lease.is_none()
            || launch.stage != LaunchStage::Captured
            || launch.x != self.x
            || launch.plan != self.plan
            || launch.resource != resource
            || launch.old != record.original
            || launch.custodian != record.custodian
            || retained.has_exited()?
            || !live.matches(&record.original)
        {
            return Err(OwnerError::Refused(
                "capture is not this resource's retained original",
            ));
        }
        let mut next = self.next()?;
        next.record_mut(resource).captured = Some(LaunchCapture {
            launch: launch.clone(),
            capture: capture.clone(),
        });
        Ok(next)
    }

    /// A unit is active while its original or its guard runs. The authority's, between its
    /// original's witnessed exit and its guard's start, is inactive.
    fn expected_state(&self, resource: Resource) -> UnitState {
        let record = self.record(resource);
        if resource == Resource::Authority && record.exit.is_some() && record.guard.is_none() {
            UnitState::Inactive
        } else {
            UnitState::Active
        }
    }

    fn measure_pair(&self, facts: &dyn TargetFacts) -> Result<[UnitMeasure; 2], OwnerError> {
        let measure = |resource| -> Result<UnitMeasure, OwnerError> {
            let unit = facts.unit(resource)?;
            if unit.state != self.expected_state(resource)
                || unit.job != JobState::None
                || !unit.reloaded
                || facts.fragment(resource)? != FragmentState::Guarded
                || facts.guard_image(resource)? != self.record(resource).guard_image
            {
                return Err(OwnerError::Refused("guarded unit is not effective"));
            }
            Ok(unit)
        };
        Ok([measure(Resource::Daemon)?, measure(Resource::Authority)?])
    }

    /// Both receipts, written together at one evidence version, only after both guarded
    /// fragments are installed, both effective units verify after the reload and the daemon's
    /// capture is staged. The receipts name verified facts, not copied files.
    pub(super) fn commit_enrollment(
        &self,
        target_facts: &dyn TargetFacts,
    ) -> Result<Attempt, OwnerError> {
        if self.enrolled.is_some()
            || self.daemon.fragment != FragmentState::Guarded
            || self.authority.fragment != FragmentState::Guarded
            || self.daemon.lease.is_none()
            || self.authority.lease.is_none()
            || self.daemon.captured.is_none()
            || target_facts.boot()? != self.boot
        {
            return Err(OwnerError::Refused("enrollment preconditions are not met"));
        }
        self.require_originals_running(target_facts)?;
        let [daemon, authority] = self.measure_pair(target_facts)?;
        let mut next = self.next()?;
        for (resource, unit) in [(Resource::Daemon, daemon), (Resource::Authority, authority)] {
            let record = self.record(resource);
            let arm = ArmReceipt {
                format: ArmFormat::V1,
                x: self.x.clone(),
                registered: self.registered.clone(),
                plan: self.plan.clone(),
                target: self.target.clone(),
                boot: self.boot.clone(),
                generation: self.generation,
                version: next.version,
                lockout: self.lockout.clone(),
                resource,
                lease: record.lease.clone().ok_or(OwnerError::Refused("lease"))?,
                original: record.original.clone(),
                custodian: record.custodian.clone(),
                fragment: unit.fragment,
                argv: unit.argv,
                sandbox: unit.sandbox,
                fdstore: unit.fdstore,
            };
            next.record_mut(resource).arm = Some(arm);
        }
        next.enrolled = Some(next.version);
        Ok(next)
    }

    fn unit_unchanged(
        &self,
        resource: Resource,
        unit: &UnitMeasure,
    ) -> Result<UnitCommit, OwnerError> {
        let arm = self
            .record(resource)
            .arm
            .as_ref()
            .ok_or(OwnerError::Refused("not enrolled"))?;
        let commit = UnitCommit::from(unit);
        if commit.fragment != arm.fragment
            || commit.argv != arm.argv
            || commit.sandbox != arm.sandbox
            || commit.fdstore != arm.fdstore
        {
            return Err(OwnerError::Refused(
                "effective unit differs from its receipt",
            ));
        }
        Ok(commit)
    }

    fn leases(&self) -> Leases {
        Leases {
            daemon: self.daemon.lease.clone(),
            authority: self.authority.lease.clone(),
        }
    }

    /// The first local handoff: both grant signatures and B's evidence binding are checked
    /// against this attempt's own keys and exact version before anything changes, and the one
    /// use is recorded. It is not permission to run a candidate or release a descriptor.
    pub(super) fn accept_handoff(
        &self,
        grant: &LGrant,
        turn: &Turn,
        retained: &dyn RetainedProcess,
        facts: &dyn TargetFacts,
    ) -> Result<Attempt, OwnerError> {
        let (rk, bk, _) = self.keys()?;
        let decision = grant.verify(&rk, &bk)?;
        let signed = turn.verify(Tag::OwnerTurn, &bk)?;
        let resource = decision.action.resource();
        let record = self.record(resource);
        self.enrolled
            .ok_or(OwnerError::Refused("target is not enrolled"))?;
        let captured = record
            .captured
            .as_ref()
            .ok_or(OwnerError::Refused("no captured launch"))?;
        decision.check_launch(&captured.launch)?;
        if decision.action == LKind::Seal {
            return Err(OwnerError::Refused("a seal has its own acceptance"));
        }
        let fresh_capture = Some(h(&captured.capture)?);
        let fresh_launch = Some(h(&captured.launch)?);
        if signed.x != self.x
            || signed.registered != self.registered
            || signed.plan != self.plan
            || signed.resource != resource
            || signed.action != decision.action
            || signed.owner != captured.launch.owner
            || signed.decision != h(decision)?
            || signed.boot != self.boot
            || signed.generation != self.generation
            || signed.lockout != self.lockout
            || signed.target_version != self.version
            || signed.captured_launch != fresh_launch
            || signed.capture != fresh_capture
            || record.handoff.is_some()
            || facts.boot()? != self.boot
        {
            return Err(OwnerError::Refused(
                "turn does not bind this target version and evidence",
            ));
        }
        let unit = self.unit_unchanged(
            resource,
            &self.measure_pair(facts)?[resource_index(resource)],
        )?;
        match resource {
            Resource::Daemon => {
                if record.retirement.is_some() || record.exit.is_some() {
                    return Err(OwnerError::Refused(
                        "daemon launch is already past its handoff",
                    ));
                }
                let identity = retained.identity()?;
                if retained.has_exited()? || !identity.matches(&record.original) {
                    return Err(OwnerError::Refused(
                        "daemon original is not the retained live process",
                    ));
                }
            }
            Resource::Authority => {
                if self.seal_receipt.is_none()
                    || record.exit.is_none()
                    || !record.final_io
                    || self.daemon.retirement.is_none()
                    || !retained.has_exited()?
                {
                    return Err(OwnerError::Refused(
                        "authority launch needs the sealed receipt and the proved exit",
                    ));
                }
            }
        }
        let mut next = self.next()?;
        next.record_mut(resource).handoff = Some(Handoff {
            action: decision.action,
            base: self.version,
            grant: grant.hash()?,
            turn: h(turn)?,
            decision: h(decision)?,
            owner: decision.owner,
            captured_launch: fresh_launch,
            capture: fresh_capture,
            unit,
            leases: self.leases(),
        });
        next.event(EventKind::Handoff, resource)?;
        Ok(next)
    }

    /// Seal has no process transition: the exact accepted version is compared at its effect.
    pub(super) fn accept_seal(
        &self,
        grant: &LGrant,
        turn: &Turn,
        facts: &dyn TargetFacts,
    ) -> Result<Attempt, OwnerError> {
        let (rk, bk, _) = self.keys()?;
        let decision = grant.verify(&rk, &bk)?;
        let signed = turn.verify(Tag::OwnerTurn, &bk)?;
        let retirement = self
            .daemon
            .retirement
            .as_ref()
            .ok_or(OwnerError::Refused("daemon is not retired"))?;
        decision.check_launch(&retirement.launch)?;
        if decision.action != LKind::Seal
            || self.daemon.seal.is_some()
            || signed.x != self.x
            || signed.registered != self.registered
            || signed.plan != self.plan
            || signed.resource != Resource::Daemon
            || signed.action != LKind::Seal
            || signed.owner != retirement.launch.owner
            || signed.decision != h(decision)?
            || signed.boot != self.boot
            || signed.generation != self.generation
            || signed.lockout != self.lockout
            || signed.target_version != self.version
            || facts.boot()? != self.boot
        {
            return Err(OwnerError::Refused(
                "seal turn does not bind this target version",
            ));
        }
        let unit = self.unit_unchanged(Resource::Daemon, &facts.unit(Resource::Daemon)?)?;
        let mut next = self.next()?;
        next.daemon.seal = Some(Handoff {
            action: LKind::Seal,
            base: self.version,
            grant: grant.hash()?,
            turn: h(turn)?,
            decision: h(decision)?,
            owner: decision.owner,
            captured_launch: None,
            capture: None,
            unit,
            leases: self.leases(),
        });
        Ok(next)
    }

    /// The exact enrolled original's own retained descriptor reports its exit.
    pub(super) fn record_exit(
        &self,
        resource: Resource,
        retained: &dyn RetainedProcess,
    ) -> Result<Attempt, OwnerError> {
        let record = self.record(resource);
        if record.exit.is_some() || record.captured.is_none() || self.enrolled.is_none() {
            return Err(OwnerError::Refused("exit is not expected"));
        }
        match resource {
            Resource::Daemon if record.handoff.is_none() => {
                return Err(OwnerError::Refused("daemon exit before its handoff"));
            }
            Resource::Authority if self.seal_receipt.is_none() => {
                return Err(OwnerError::Refused(
                    "authority exit before the sealed receipt",
                ));
            }
            Resource::Authority if record.handoff.is_some() => {
                return Err(OwnerError::Refused("authority exit after its handoff"));
            }
            _ => {}
        }
        if !retained.has_exited()?
            || retained
                .identity()
                .is_ok_and(|live| !live.matches(&record.original))
        {
            return Err(OwnerError::Refused(
                "the retained descriptor does not report this exit",
            ));
        }
        let mut next = self.next()?;
        next.record_mut(resource).exit = Some(next.version);
        if resource == Resource::Daemon {
            next.event(EventKind::Exit, resource)?;
        }
        Ok(next)
    }

    /// The authority's completed final I/O, from the host's own record.
    pub(super) fn record_final_io(
        &self,
        resource: Resource,
        facts: &dyn TargetFacts,
    ) -> Result<Attempt, OwnerError> {
        let record = self.record(resource);
        if resource != Resource::Authority || record.exit.is_none() || record.final_io {
            return Err(OwnerError::Refused("final I/O is not expected"));
        }
        let _completed: FinalIo = facts.final_io(resource)?;
        let mut next = self.next()?;
        next.record_mut(resource).final_io = true;
        Ok(next)
    }

    /// The enrolled systemd guard is the unit's running main process, not the original.
    pub(super) fn record_guard_start(
        &self,
        resource: Resource,
        facts: &dyn TargetFacts,
    ) -> Result<Attempt, OwnerError> {
        let record = self.record(resource);
        let handoff = record
            .handoff
            .as_ref()
            .ok_or(OwnerError::Refused("no accepted handoff"))?;
        let _ = handoff;
        if record.guard.is_some() || (resource == Resource::Daemon && record.exit.is_none()) {
            return Err(OwnerError::Refused("guard start is not expected"));
        }
        let guard = facts
            .unit_process(resource)?
            .ok_or(OwnerError::Refused("the unit runs no process"))?;
        if guard.boot != self.boot
            || guard.exe != record.guard_image
            || guard.pid == record.original.pid.get()
        {
            return Err(OwnerError::Refused(
                "the running process is not the enrolled guard",
            ));
        }
        let mut next = self.next()?;
        next.record_mut(resource).guard = Some(GuardStart {
            version: next.version,
            pid: PosInt::new(guard.pid).map_err(|_| OwnerError::Refused("pid"))?,
            start: PosInt::new(guard.start).map_err(|_| OwnerError::Refused("start"))?,
            exe: guard.exe,
        });
        next.event(EventKind::GuardStart, resource)?;
        Ok(next)
    }

    /// Verify the lineage from the accepted handoff to the guard now calling, then spend the
    /// one use: the Launch becomes consumed and the action records the grant and that image.
    /// Any other mutation, gap or process change since the handoff refuses.
    pub(super) fn consume(
        &self,
        resource: Resource,
        guard: &MeasuredProc,
        facts: &dyn TargetFacts,
    ) -> Result<(Attempt, Launch), OwnerError> {
        let record = self.record(resource);
        let handoff = record
            .handoff
            .as_ref()
            .ok_or(OwnerError::Refused("no accepted handoff"))?;
        let started = record
            .guard
            .as_ref()
            .ok_or(OwnerError::Refused("guard start is not proved"))?;
        let captured = record
            .captured
            .as_ref()
            .ok_or(OwnerError::Refused("no captured launch"))?;
        if record.consumed.is_some() {
            return Err(OwnerError::Refused("launch already consumed"));
        }
        let expected: Vec<(EventKind, Resource)> = match resource {
            Resource::Daemon => vec![
                (EventKind::Handoff, resource),
                (EventKind::Exit, resource),
                (EventKind::GuardStart, resource),
            ],
            Resource::Authority => vec![
                (EventKind::Handoff, resource),
                (EventKind::GuardStart, resource),
            ],
        };
        let tail: Vec<&Event> = self
            .events
            .iter()
            .skip_while(|event| !(event.kind == EventKind::Handoff && event.resource == resource))
            .collect();
        let consecutive = tail
            .windows(2)
            .all(|pair| pair[1].version.get() == pair[0].version.get() + 1);
        let shaped = tail.len() == expected.len()
            && tail
                .iter()
                .zip(&expected)
                .all(|(event, want)| (event.kind, event.resource) == *want);
        let handoff_version = tail.first().map(|event| event.version.get());
        if !shaped
            || !consecutive
            || handoff_version != Some(handoff.base.get() + 1)
            || tail.last().map(|event| event.version) != Some(self.version)
            || started.version != self.version
            || guard.pid != started.pid.get()
            || guard.start != started.start.get()
            || guard.exe != started.exe
            || guard.boot != self.boot
            || facts.boot()? != self.boot
            || handoff.leases != self.leases()
        {
            return Err(OwnerError::Refused(
                "lineage since the handoff is not the authorized one",
            ));
        }
        let [daemon, authority] = self
            .measure_pair(facts)
            .or_else(|_| Err(OwnerError::Refused("units changed since the handoff")))?;
        let current = UnitCommit::from(if resource == Resource::Daemon {
            &daemon
        } else {
            &authority
        });
        if current != handoff.unit {
            return Err(OwnerError::Refused("units changed since the handoff"));
        }
        let mut launch = captured.launch.clone();
        launch.stage = LaunchStage::Consumed;
        captured.launch.check_next(&launch)?;
        let mut next = self.next()?;
        next.record_mut(resource).consumed = Some(Consumed {
            version: next.version,
            grant: handoff.grant.clone(),
            launch: launch.hash()?,
        });
        Ok((next, launch))
    }

    /// The daemon custodian's committed retirement: the retired Launch and the Death it names,
    /// after the consumed launch and the witnessed exit. `profile` is the writer profile the
    /// validated inputs pin.
    pub(super) fn record_retirement(
        &self,
        launch: &Launch,
        death: &Death,
        profile: &HexDigest,
    ) -> Result<Attempt, OwnerError> {
        let record = &self.daemon;
        let captured = record
            .captured
            .as_ref()
            .ok_or(OwnerError::Refused("no captured launch"))?;
        if record.retirement.is_some()
            || record.consumed.is_none()
            || record.exit.is_none()
            || launch.stage != LaunchStage::Retired
            || launch.nonce != captured.launch.nonce
            || launch.owner != captured.launch.owner
            || launch.old != record.original
            || launch.custodian != record.custodian
            || launch.x != self.x
            || launch.plan != self.plan
            || death.profile != *profile
        {
            return Err(OwnerError::Refused(
                "retirement is not this daemon's consumed launch",
            ));
        }
        launch.check_death(death)?;
        let mut next = self.next()?;
        next.daemon.retirement = Some(DaemonRetirement {
            launch: launch.clone(),
            death: death.clone(),
        });
        next.daemon.final_io = true;
        Ok(next)
    }

    /// The host's sealed Receipt for the daemon's own Cut, bound to the authority's gate.
    pub(super) fn bind_seal_receipt(&self, receipt: &Receipt) -> Result<Attempt, OwnerError> {
        let (_, _, hk) = self.keys()?;
        let retirement = self
            .daemon
            .retirement
            .as_ref()
            .ok_or(OwnerError::Refused("daemon is not retired"))?;
        let cut = &receipt.verify(Tag::Retired, &hk)?.cut;
        if self.seal_receipt.is_some()
            || self.daemon.seal.is_none()
            || cut.x != self.x
            || cut.plan != self.plan
            || cut.custody
                != retirement
                    .launch
                    .death
                    .clone()
                    .ok_or(OwnerError::Refused("death"))?
            || cut.old_proc != retirement.death.old
            || cut.new_proc != retirement.death.next
            || cut.profile != retirement.death.profile
        {
            return Err(OwnerError::Refused(
                "receipt is not this daemon's sealed cut",
            ));
        }
        let mut next = self.next()?;
        next.seal_receipt = Some(h(receipt)?);
        Ok(next)
    }

    /// The collector's answer. The projection follows from the target's own state, the resource
    /// and the point; a point the state does not allow refuses.
    pub(super) fn collect(
        &self,
        request: &ObserveRequest,
        facts: &dyn TargetFacts,
    ) -> Result<briqyard_api::execution::sealed::owner::Collected, OwnerError> {
        use briqyard_api::execution::sealed::owner::Collected;
        if request.x != self.x || request.registered != self.registered {
            return Err(OwnerError::Refused(
                "observation is not for the active operation",
            ));
        }
        let resource = request.resource;
        let record = self.record(resource);
        if facts.boot()? != self.boot {
            return Err(OwnerError::Refused("the target rebooted"));
        }
        let own = facts.process(record.original.pid.get())?;
        let running = own
            .as_ref()
            .is_some_and(|process| process.matches(&record.original));
        let exited = record.exit.is_some();
        if exited && running {
            return Err(OwnerError::Refused(
                "an original runs after its witnessed exit",
            ));
        }
        if !running && !exited {
            return Err(OwnerError::Refused(
                "an original vanished without a witnessed exit",
            ));
        }
        let custodian = facts.process(record.custodian.pid.get())?;
        if !custodian.is_some_and(|process| process.matches(&record.custodian)) {
            return Err(OwnerError::Refused(
                "custodian is not the live enrolled process",
            ));
        }
        let unit = facts.unit(resource)?;
        if facts.guard_image(resource)? != record.guard_image
            || unit.job != JobState::None
            || unit.state != self.expected_state(resource)
        {
            return Err(OwnerError::Refused("guard image or unit state changed"));
        }
        let launch_d = self.daemon.retirement.is_none();
        let (arm, launch_capture, daemon_retirement) = match (request.point, resource) {
            (Point::Prearm, _) if self.enrolled.is_none() => (None, None, None),
            (Point::Launch, Resource::Daemon)
                if launch_d && self.enrolled.is_some() && record.handoff.is_none() =>
            {
                let pair = record
                    .captured
                    .clone()
                    .ok_or(OwnerError::Refused("no captured launch"))?;
                self.unit_unchanged(resource, &unit)?;
                (record.arm.clone(), Some(pair), None)
            }
            (Point::Launch, Resource::Authority) if launch_d && self.enrolled.is_some() => {
                self.unit_unchanged(resource, &unit)?;
                (record.arm.clone(), None, None)
            }
            (Point::Seal, Resource::Daemon) if !launch_d && self.daemon.seal.is_none() => {
                self.unit_unchanged(resource, &unit)?;
                (None, None, self.daemon.retirement.clone())
            }
            (Point::Launch, Resource::Authority) if !launch_d && self.seal_receipt.is_some() => {
                if !record.final_io || !exited || record.handoff.is_some() {
                    return Err(OwnerError::Refused(
                        "authority exit and final I/O are not recorded",
                    ));
                }
                let pair = record
                    .captured
                    .clone()
                    .ok_or(OwnerError::Refused("no captured launch"))?;
                self.unit_unchanged(resource, &unit)?;
                (None, Some(pair), self.daemon.retirement.clone())
            }
            _ => {
                return Err(OwnerError::Refused(
                    "point is not available in this target state",
                ))
            }
        };
        let observation = Observation {
            format: ObservationFormat::V1,
            request: request.clone(),
            boot: self.boot.clone(),
            version: self.version,
            target: TargetTag {
                generation: self.generation,
                lockout: self.lockout.clone(),
            },
            leases: self.leases(),
            original: record.original.clone(),
            custodian: record.custodian.clone(),
            images: Images {
                original: record.original.exe.clone(),
                guard: record.guard_image.clone(),
                custodian: record.custodian.exe.clone(),
            },
            fragments: Fragments {
                daemon: self.daemon.fragment,
                authority: self.authority.fragment,
            },
            retired: Retired {
                exit: if exited {
                    ExitState::Exited
                } else {
                    ExitState::Running
                },
                final_io: record.final_io,
                receipt: if resource == Resource::Authority {
                    self.seal_receipt.clone()
                } else {
                    None
                },
            },
            unit: UnitObservation {
                fragment: unit.fragment,
                argv: unit.argv,
                sandbox: unit.sandbox,
                fdstore: unit.fdstore,
                job: unit.job,
                state: unit.state,
            },
        };
        Ok(Collected {
            observation,
            arm,
            launch_capture,
            daemon_retirement,
        })
    }
}

fn resource_index(resource: Resource) -> usize {
    match resource {
        Resource::Daemon => 0,
        Resource::Authority => 1,
    }
}
