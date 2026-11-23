//! Comparison with independently supplied facts. Every operand is a value or exact bytes that
//! its own owner obtained and checked (release records, the receiver topology snapshot, the
//! deployment profile, the live process observations, the closure source owners); this module
//! only compares them with the manifest and with the independently loaded Plan. It performs no
//! I/O. A pass is consistency of the manifest, not proof of any operand's source.

use super::release::VerifiedRelease;
use super::*;
use crate::execution::sealed::canonical::{decode, CodecError};
use crate::execution::sealed::objects::Plan;

/// The independently bound identity of one actor row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessIdentity {
    /// A service-scoped identity bound elsewhere: the manifest row has a null process. This
    /// is the only form for H and A, and for B and R when their approved identity is not a
    /// process; it is never a default for a missing process.
    Service,
    /// The live process observed for an installer or gateway replica, or for a
    /// process-scoped B or R.
    Process(Proc),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorObservation {
    pub actor: ActorKind,
    pub id: Ident,
    pub identity: ProcessIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegionFloor {
    pub id: Ident,
    pub minimum_accepting: PosInt,
}

/// What the receiver and deployment owners hold about the topology.
pub struct TopologyPolicy {
    /// The exact bytes of the separately installed receiver topology/policy inventory.
    pub inventory: Vec<u8>,
    pub order: Vec<Ident>,
    pub floors: Vec<RegionFloor>,
    /// The exact public minimum-reader policy bytes of every enrolled host, by registered ID.
    pub reader_floors: Vec<(Ident, Vec<u8>)>,
}

/// The owner of a live process as the independently trusted OS observer measured it. This
/// reader only compares: the caller that builds it owns the observation (for example the
/// kernel's credentials of the retained process), and nothing here reads or infers one. There
/// is no default, and no constructor takes a verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessOwner {
    uid: Uint,
    gid: Uint,
}

impl ProcessOwner {
    pub fn measured(uid: Uint, gid: Uint) -> Self {
        Self { uid, gid }
    }

    pub fn uid(&self) -> Uint {
        self.uid
    }

    pub fn gid(&self) -> Uint {
        self.gid
    }
}

/// What root's deployment profile and the live owners hold about one resource.
pub struct ResourcePolicy {
    pub custodian: Proc,
    /// The measured owner of that custodian process. `None` is a missing observation and
    /// refuses; the custodian must be measured as root:root (uid 0, gid 0).
    pub custodian_owner: Option<ProcessOwner>,
    pub guard_build: Build,
    pub guard_bytes: Vec<u8>,
    pub candidate_path: Path,
    pub config_path: Path,
    pub config: Vec<u8>,
    pub tls_cert: Vec<u8>,
    pub tls_key: Vec<u8>,
    pub fragment: Path,
    pub legacy_fragment: Vec<u8>,
    pub guarded_fragment: Vec<u8>,
    pub control_gid: Uint,
    pub journal: Directory,
    /// `LISTEN_FDNAMES` entries in kernel delivery order.
    pub listener_names: Vec<String>,
    pub store_max: Uint,
    /// The exact public bytes of the source/build scoped-writer qualification artifact.
    pub writer_profile: Vec<u8>,
}

pub struct SupportPolicy {
    pub image_root: HexDigest,
    pub boot_id: BootId,
    pub release_policy: Vec<u8>,
    pub profile: Vec<u8>,
}

/// The closure's public pins as each source owner independently holds them.
pub struct ClosurePolicy {
    pub registry: Vec<u8>,
    pub admin_host: HexDigest,
    pub admin_fleet: HexDigest,
    pub continuation: Continuation,
    pub peers: Vec<Peer>,
    pub admin_tls: Option<Pair>,
    pub backup_s3: Option<HexDigest>,
    pub file_key: Option<Hex32>,
    pub support: SupportPolicy,
}

/// Everything `Inputs::bind` compares the manifest with. Both releases are explicit
/// selections, never derived from the manifest or from a tag name.
pub struct DeploymentPolicy<'a> {
    pub source_release: &'a VerifiedRelease,
    pub target_release: &'a VerifiedRelease,
    /// The independently approved build of the source daemon binary. Both resource
    /// custodians run that binary, and it is the build of `Plan.pre_d`.
    pub source_daemon_build: Build,
    pub topology: TopologyPolicy,
    pub actors: Vec<ActorObservation>,
    pub daemon: ResourcePolicy,
    pub authority: ResourcePolicy,
    pub closure: ClosurePolicy,
}

/// A manifest that decoded canonically and agrees with the Plan and every supplied operand.
/// Only [`Inputs::bind`] makes one. Its fields are readable and immutable, and holding it
/// grants nothing: it is not a proof, an approval or permission to arm, launch or seal.
#[derive(Debug)]
pub struct BoundInputs {
    inputs: Inputs,
    bytes: Vec<u8>,
}

impl BoundInputs {
    pub fn inputs(&self) -> &Inputs {
        &self.inputs
    }

    /// The exact bytes, the preimage of `Plan.inputs`.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

fn mismatch(what: &'static str) -> Result<(), CodecError> {
    Err(CodecError::Value(what))
}

fn same_bytes(digest: &HexDigest, count: PosInt, bytes: &[u8]) -> bool {
    count.get() == bytes.len() as u64 && *digest == HexDigest::of(bytes)
}

impl Inputs {
    /// Decode `bytes` strictly, then compare them with the Plan and the supplied operands.
    /// `plan` must come from its own independent pin; a Plan read from this manifest is not one.
    pub fn bind(
        bytes: &[u8],
        plan: &Plan,
        policy: &DeploymentPolicy<'_>,
    ) -> Result<BoundInputs, CodecError> {
        plan.validate()?;
        let inputs: Inputs = decode(bytes)?;
        if plan.inputs != HexDigest::of(bytes) {
            return Err(CodecError::Value("plan inputs digest"));
        }
        if inputs.x != plan.x || inputs.registered != plan.registered {
            return Err(CodecError::Value("plan scope"));
        }
        inputs.check_releases(plan, policy)?;
        inputs.check_topology(&policy.topology)?;
        inputs.check_actors(&policy.actors)?;
        let custodian = (&inputs.source_release.daemon, &policy.source_daemon_build);
        check_resource(
            &inputs.daemon,
            &policy.daemon,
            policy.target_release.daemon_asset_bytes(),
            custodian,
        )?;
        check_resource(
            &inputs.authority,
            &policy.authority,
            policy.target_release.fleet_asset_bytes(),
            custodian,
        )?;
        inputs.check_closure(plan, &policy.closure)?;
        Ok(BoundInputs {
            inputs,
            bytes: bytes.to_vec(),
        })
    }

    fn check_releases(&self, plan: &Plan, policy: &DeploymentPolicy<'_>) -> Result<(), CodecError> {
        if self.source_release != *policy.source_release.release() {
            return mismatch("source release");
        }
        if self.target_release != *policy.target_release.release() {
            return mismatch("target release");
        }
        let (daemon, authority) = (&self.daemon, &self.authority);
        if daemon.pre != plan.pre_d
            || authority.pre != plan.pre_a
            || daemon.pre.exe != self.source_release.daemon
            || authority.pre.exe != self.source_release.fleet
        {
            return mismatch("predecessor pins");
        }
        if plan.pre_d.build != policy.source_daemon_build {
            return mismatch("source daemon build");
        }
        if daemon.candidate.file.sha256 != plan.next_d
            || authority.candidate.file.sha256 != plan.next_a
            || daemon.candidate.file.sha256 != self.target_release.daemon
            || authority.candidate.file.sha256 != self.target_release.fleet
            || daemon.candidate.build != plan.dbuild
            || authority.candidate.build != plan.abuild
        {
            return mismatch("successor pins");
        }
        Ok(())
    }

    fn check_topology(&self, policy: &TopologyPolicy) -> Result<(), CodecError> {
        let topology = &self.topology;
        let hosts: usize = topology.regions.iter().map(|r| r.hosts.len()).sum();
        if topology.policy_inventory != HexDigest::of(&policy.inventory)
            || topology.order != policy.order
            || policy.floors.len() != topology.regions.len()
            || policy.reader_floors.len() != hosts
        {
            return mismatch("topology policy");
        }
        for region in &topology.regions {
            let mut floors = policy.floors.iter().filter(|f| f.id == region.id);
            match (floors.next(), floors.next()) {
                (Some(floor), None) if floor.minimum_accepting == region.minimum_accepting => {}
                _ => return mismatch("regional floor policy"),
            }
            for host in &region.hosts {
                let mut rows = policy
                    .reader_floors
                    .iter()
                    .filter(|(registered, _)| *registered == host.registered);
                match (rows.next(), rows.next()) {
                    (Some((_, bytes)), None) if host.reader_floor == HexDigest::of(bytes) => {}
                    _ => return mismatch("reader floor policy"),
                }
            }
        }
        Ok(())
    }

    fn check_actors(&self, policy: &[ActorObservation]) -> Result<(), CodecError> {
        if policy.len() != self.actors.len() {
            return mismatch("actor roster");
        }
        for actor in &self.actors {
            let mut rows = policy
                .iter()
                .filter(|o| o.actor == actor.actor && o.id == actor.id);
            let valid = match (rows.next(), rows.next()) {
                (Some(row), None) => match (&row.identity, actor.actor) {
                    (
                        ProcessIdentity::Service,
                        ActorKind::Host
                        | ActorKind::Authority
                        | ActorKind::Api
                        | ActorKind::Receiver,
                    ) => actor.proc.is_none(),
                    (
                        ProcessIdentity::Process(proc),
                        ActorKind::Installer
                        | ActorKind::Gateway
                        | ActorKind::Api
                        | ActorKind::Receiver,
                    ) => actor.proc.as_ref() == Some(proc),
                    _ => false,
                },
                _ => false,
            };
            if !valid {
                return mismatch("actor process identity");
            }
        }
        Ok(())
    }

    fn check_closure(&self, plan: &Plan, policy: &ClosurePolicy) -> Result<(), CodecError> {
        let closure = &self.closure;
        let credentials = [
            &closure.admin_host,
            &closure.admin_fleet,
            &closure.continuation.bearer,
        ];
        for members in [&plan.old, &plan.new] {
            let members = [
                Some(&members.hi),
                Some(&members.he),
                Some(&members.ni),
                Some(&members.ng),
                members.tr.as_ref(),
            ];
            if members
                .into_iter()
                .flatten()
                .any(|m| credentials.contains(&m))
            {
                return mismatch("closure credential reuse");
            }
        }
        let support = &policy.support;
        if closure.registry != HexDigest::of(&policy.registry)
            || closure.admin_host != policy.admin_host
            || closure.admin_fleet != policy.admin_fleet
            || closure.continuation != policy.continuation
            || closure.peers != policy.peers
            || closure.admin_tls != policy.admin_tls
            || closure.backup_s3 != policy.backup_s3
            || closure.file_key != policy.file_key
        {
            return mismatch("closure policy");
        }
        if closure.support.image_root != support.image_root
            || closure.support.boot_id != support.boot_id
            || closure.support.release_policy != HexDigest::of(&support.release_policy)
            || closure.support.profile != HexDigest::of(&support.profile)
        {
            return mismatch("support policy");
        }
        Ok(())
    }
}

fn check_resource(
    actual: &Resource,
    policy: &ResourcePolicy,
    candidate_asset_bytes: u64,
    (daemon_exe, daemon_build): (&HexDigest, &Build),
) -> Result<(), CodecError> {
    if actual.custodian != policy.custodian {
        return mismatch("custodian process");
    }
    if actual.custodian.exe != *daemon_exe {
        return mismatch("custodian image");
    }
    if actual.custodian.build != *daemon_build {
        return mismatch("custodian build");
    }
    let root = Uint::new(0)?;
    match &policy.custodian_owner {
        Some(owner) if owner.uid() == root && owner.gid() == root => {}
        _ => return mismatch("custodian owner"),
    }
    if actual.guard.build != policy.guard_build
        || !same_bytes(
            &actual.guard.file.sha256,
            actual.guard.file.bytes,
            &policy.guard_bytes,
        )
    {
        return mismatch("guard program");
    }
    if actual.candidate.file.path != policy.candidate_path
        || actual.candidate.file.bytes.get() != candidate_asset_bytes
    {
        return mismatch("candidate locator");
    }
    if actual.config.path != policy.config_path
        || !same_bytes(&actual.config.sha256, actual.config.bytes, &policy.config)
        || !same_bytes(
            &actual.tls_cert.sha256,
            actual.tls_cert.bytes,
            &policy.tls_cert,
        )
        || !same_bytes(
            &actual.tls_key.sha256,
            actual.tls_key.bytes,
            &policy.tls_key,
        )
    {
        return mismatch("config or TLS pins");
    }
    if actual.fragment != policy.fragment
        || actual.legacy_fragment != HexDigest::of(&policy.legacy_fragment)
        || actual.guarded_fragment != HexDigest::of(&policy.guarded_fragment)
    {
        return mismatch("unit fragment");
    }
    if actual.control.gid != policy.control_gid || actual.journal != policy.journal {
        return mismatch("control or journal ownership");
    }
    let names = &policy.listener_names;
    let valid_names = names
        .iter()
        .all(|name| !name.is_empty() && name.bytes().all(|b| b.is_ascii_graphic() && b != b':'));
    if !valid_names
        || actual.listeners.count.get() != names.len() as u64
        || actual.listeners.names != HexDigest::of(names.join(":").as_bytes())
        || actual.listeners.store_max != policy.store_max
    {
        return mismatch("listener table");
    }
    if actual.writer_profile != HexDigest::of(&policy.writer_profile) {
        return mismatch("writer profile");
    }
    Ok(())
}
