//! The closed `native.inputs/v1` reader from interface v3.6 and its v3.3 closure child.
//!
//! These are public, non-secret locators and commitments, not approvals. Decoding with
//! [`super::decode`] checks the grammar only. [`Inputs::bind`] additionally compares the exact
//! bytes with an independently loaded [`Plan`] and with facts and bytes that each owner
//! supplies, and returns a [`BoundInputs`] that can only be made that way. Nothing here opens
//! a path, resolves a name, selects a release, defaults an omitted input, builds a proof or
//! approval record, or permits anything to start.
//!
//! * `grammar`: the v3.6 closed grammar and every invariant a field type cannot express.
//! * `policy`: the equality checks against independently supplied facts and the bound value.
//! * `release`: pin-file, checksum-list and asset checks over explicitly supplied bytes.
//! * `scalars`: `Version`, `Git`, `T`, `Path` and the other closed forms this reader adds.

mod grammar;
mod policy;
mod release;
mod scalars;

use super::canonical::{wire, Wire};
use super::objects::{Proc, X};
use super::prim::{nullable, BootId, Build, HexDigest, Ident, LitU, PosInt, Uint};
use serde::{Deserialize, Serialize};

pub use policy::{
    ActorObservation, BoundInputs, ClosurePolicy, DeploymentPolicy, ProcessIdentity, RegionFloor,
    ResourcePolicy, SupportPolicy, TopologyPolicy,
};
pub use release::{ReleaseAssets, VerifiedRelease};
pub use scalars::{DerBytes, Git, Hex32, Path, Text, Version};

pub const INPUTS_FORMAT: &str = "native.inputs/v1";
pub const CLOSURE_FORMAT: &str = "native.closure/v1";
/// The fixed read cap of a guard or candidate executable (companion, 256 MiB).
pub const EXECUTABLE_LIMIT: u64 = 256 * 1024 * 1024;
/// Every other small object, config and TLS blobs included, is at most 64 KiB (v3.3).
pub const SMALL_LIMIT: u64 = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inputs {
    pub format: String,
    pub assets_abi: LitU<3>,
    pub x: X,
    pub registered: Ident,
    pub source_release: Release,
    pub target_release: Release,
    pub topology: Topology,
    pub actors: Vec<Actor>,
    pub daemon: Resource,
    pub authority: Resource,
    pub closure: Closure,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub version: Version,
    pub commit: Git,
    pub release_id: PosInt,
    pub pin_file: HexDigest,
    pub sums: HexDigest,
    pub daemon: HexDigest,
    pub fleet: HexDigest,
    pub cli: HexDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Topology {
    pub regions: Vec<Region>,
    pub order: Vec<Ident>,
    pub policy_inventory: HexDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Region {
    pub id: Ident,
    pub hosts: Vec<Host>,
    pub minimum_accepting: PosInt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub registered: Ident,
    pub intrinsic: Ident,
    pub reader_floor: HexDigest,
}

/// The six actor spellings. Rows are ordered by their wire names (`"A" < "B" < "H" < "R" <
/// "gateway" < "installer"`), never by this declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActorKind {
    #[serde(rename = "H")]
    Host,
    #[serde(rename = "A")]
    Authority,
    #[serde(rename = "B")]
    Api,
    #[serde(rename = "R")]
    Receiver,
    #[serde(rename = "installer")]
    Installer,
    #[serde(rename = "gateway")]
    Gateway,
}

impl ActorKind {
    pub const ALL: [Self; 6] = [
        Self::Host,
        Self::Authority,
        Self::Api,
        Self::Receiver,
        Self::Installer,
        Self::Gateway,
    ];

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Host => "H",
            Self::Authority => "A",
            Self::Api => "B",
            Self::Receiver => "R",
            Self::Installer => "installer",
            Self::Gateway => "gateway",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    pub actor: ActorKind,
    pub id: Ident,
    #[serde(deserialize_with = "nullable")]
    pub proc: Option<Proc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub pre: Proc,
    pub custodian: Proc,
    pub guard: Program,
    pub candidate: Program,
    pub config: File,
    pub tls_cert: Blob,
    pub tls_key: Blob,
    pub fragment: Path,
    pub legacy_fragment: HexDigest,
    pub guarded_fragment: HexDigest,
    pub control: Socket,
    pub journal: Directory,
    pub listeners: Listeners,
    pub writer_profile: HexDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Program {
    pub file: File,
    pub build: Build,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct File {
    pub path: Path,
    pub bytes: PosInt,
    pub sha256: HexDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Blob {
    pub bytes: PosInt,
    pub sha256: HexDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Socket {
    pub path: Path,
    pub uid: Uint,
    pub gid: Uint,
    pub mode: Uint,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Directory {
    pub path: Path,
    pub uid: Uint,
    pub gid: Uint,
    pub mode: Uint,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listeners {
    pub count: Uint,
    pub names: HexDigest,
    pub store_max: Uint,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Closure {
    pub format: String,
    pub x: X,
    pub registry: HexDigest,
    pub admin_host: HexDigest,
    pub admin_fleet: HexDigest,
    pub continuation: Continuation,
    pub peers: Vec<Peer>,
    #[serde(deserialize_with = "nullable")]
    pub admin_tls: Option<Pair>,
    #[serde(deserialize_with = "nullable")]
    pub backup_s3: Option<HexDigest>,
    #[serde(deserialize_with = "nullable")]
    pub file_key: Option<Hex32>,
    pub support: Support,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Continuation {
    pub url: Text,
    pub bearer: HexDigest,
    pub roots: Vec<DerBytes>,
    pub server_name: Text,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pair {
    pub leaf: HexDigest,
    pub spki: HexDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub actor: ActorKind,
    pub id: Ident,
    pub endpoint: Text,
    pub server_name: Text,
    pub server: Pair,
    pub client: Pair,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Support {
    pub image_root: HexDigest,
    pub boot_id: BootId,
    pub release_policy: HexDigest,
    pub profile: HexDigest,
}

wire!(
    Release,
    Topology,
    Region,
    Host,
    ActorKind,
    Actor,
    Resource,
    Program,
    File,
    Blob,
    Socket,
    Directory,
    Listeners,
    Closure,
    Continuation,
    Pair,
    Peer,
    Support,
);

#[cfg(test)]
mod tests;
