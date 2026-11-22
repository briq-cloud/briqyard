//! The shared objects of the sealed wire: process and operation identity, the native
//! registration and its two digests, the plan's building blocks, capacity and clock
//! vocabulary. Field names are the literal wire names; order is irrelevant on the wire
//! (`C` sorts) except for `Reg`'s one native digest, which is the legacy exception.

use super::canonical::{h, wire, CodecError, Wire};
use super::prim::{
    nullable, BootId, Build, Bytes, Env, HexDigest, Ident, KeyBytes, Nonce, PosInt, Uint,
};
use super::sig::{Sig, SigError, Tag};
use crate::execution::admission::HostRegistration;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// `X`: the operation scope every remote proof repeats and every verifier compares whole.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X {
    pub aud: Env,
    pub host: Ident,
    pub op: HexDigest,
    pub serial: PosInt,
}

/// `Proc`: a process by boot, PID, kernel start ticks, mapped executable and build.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proc {
    pub boot: BootId,
    pub pid: PosInt,
    pub start: PosInt,
    pub exe: HexDigest,
    pub build: Build,
}

/// `Q`: an operation scope and a verifier-issued single-use challenge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Q {
    pub x: X,
    pub nonce: Nonce,
}

/// `Reg`: the native host registration. Field order is the native digest order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reg {
    pub authority: Ident,
    pub epoch: Ident,
    pub key_id: Ident,
    pub public_key: [u8; 32],
    pub host_instance: Ident,
    pub generation: PosInt,
}

/// `Ack = {host_instance, generation, digest}`; `digest` is the native digest, base64url.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    pub host_instance: Ident,
    pub generation: PosInt,
    pub digest: Nonce,
}

/// `Ctx = ctx(reg)`: the registration context a host pins.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ctx {
    pub host: Ident,
    pub instance: Ident,
    pub authority: Ident,
    pub epoch: Ident,
    pub generation: PosInt,
    pub reg_hash: HexDigest,
}

impl Reg {
    /// The legacy bytes: the six fields in declared order, compact, never sorted. This is
    /// byte for byte what the native `HostRegistration` serializes to.
    pub fn native_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a validated registration serializes")
    }

    pub fn native_digest(&self) -> [u8; 32] {
        Sha256::digest(self.native_bytes()).into()
    }

    /// `ctx.reg_hash`: hex of the native digest.
    pub fn reg_hash(&self) -> HexDigest {
        HexDigest::from_raw(self.native_digest())
    }

    /// `Ack`: base64url of the same native digest.
    pub fn ack(&self) -> Ack {
        Ack {
            host_instance: self.host_instance.clone(),
            generation: self.generation,
            digest: Bytes::from_array(self.native_digest()),
        }
    }

    /// `ctx(reg)` for the intrinsic `host`.
    pub fn ctx(&self, host: &Ident) -> Ctx {
        Ctx {
            host: host.clone(),
            instance: self.host_instance.clone(),
            authority: self.authority.clone(),
            epoch: self.epoch.clone(),
            generation: self.generation,
            reg_hash: self.reg_hash(),
        }
    }

    /// `H(Reg)` under v3 canonical (sorted) order. Not the native digest.
    pub fn canonical_hash(&self) -> Result<HexDigest, CodecError> {
        h(self)
    }

    pub fn from_native(native: &HostRegistration) -> Result<Self, CodecError> {
        Ok(Self {
            authority: Ident::new(native.authority.as_str())?,
            epoch: Ident::new(native.epoch.as_str())?,
            key_id: Ident::new(native.key_id.as_str())?,
            public_key: native.public_key,
            host_instance: Ident::new(native.host_instance.as_str())?,
            generation: PosInt::new(native.generation)?,
        })
    }
}

/// `Members`: digests of the exact UTF-8 bearer bytes of each role's secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Members {
    pub hi: HexDigest,
    pub he: HexDigest,
    pub ni: HexDigest,
    pub ng: HexDigest,
    #[serde(deserialize_with = "nullable")]
    pub tr: Option<HexDigest>,
}

impl Members {
    /// `set = H(Members)`.
    pub fn set(&self) -> Result<HexDigest, CodecError> {
        h(self)
    }
}

/// `Bind`: the original public API decision every later proof binds to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bind {
    pub x: X,
    pub plan: HexDigest,
    pub registered: Ident,
    pub prior: PosInt,
    pub intent: Ident,
    pub record: Reg,
    pub ctx: Ctx,
    pub set: HexDigest,
}

/// `Plan`: what R and B each pin by `H(Plan)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub x: X,
    pub registered: Ident,
    pub pre: Ctx,
    pub pre_record: Reg,
    pub pre_intent: Ident,
    pub pre_d: Proc,
    pub pre_a: Proc,
    pub next_d: HexDigest,
    pub next_a: HexDigest,
    pub dbuild: Build,
    pub abuild: Build,
    pub old: Members,
    pub new: Members,
    pub hk: KeyBytes,
    pub ak: KeyBytes,
    pub bk: KeyBytes,
    pub rk: KeyBytes,
    pub ordinary_key: KeyBytes,
    pub exception: HexDigest,
    pub inputs: HexDigest,
}

impl Wire for Plan {
    /// The derived context must be the registration's own, and the five signing keys must
    /// be pairwise distinct (no key shared across roles or with the ordinary signing key).
    fn validate(&self) -> Result<(), CodecError> {
        if self.pre != self.pre_record.ctx(&self.x.host) {
            return Err(CodecError::Value("plan context"));
        }
        let keys = [&self.hk, &self.ak, &self.bk, &self.rk, &self.ordinary_key];
        for (i, a) in keys.iter().enumerate() {
            if keys[i + 1..].iter().any(|b| a == b) {
                return Err(CodecError::Value("plan keys"));
            }
        }
        Ok(())
    }
}

/// `ClaimKind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClaimKind {
    #[serde(rename = "arm")]
    Arm,
    #[serde(rename = "adopt")]
    Adopt,
    #[serde(rename = "register")]
    Register,
    #[serde(rename = "record_ack")]
    RecordAck,
    #[serde(rename = "release")]
    Release,
}

/// The twenty-one `Dims.counts`, in wire order.
pub const DIM_NAMES: [&str; 21] = [
    "allocations",
    "fences",
    "retired_epochs",
    "admissions",
    "ownership",
    "ownership_highwater",
    "delegations",
    "delegation_versions",
    "delegation_tombstones",
    "prepared",
    "protections",
    "authority_intents",
    "authority_highwater",
    "discovery_intents",
    "protection_intents",
    "delegation_intents",
    "operation_intents",
    "uncertain_installations",
    "active_operations",
    "operation_policies",
    "renewal_attempts",
];

/// `Dims`: exact production snapshot size and the native count vector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dims {
    pub bytes: Uint,
    pub counts: [Uint; 21],
    pub fits: bool,
}

/// `Projection.action`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProjectionAction {
    #[serde(rename = "seal")]
    Seal,
    #[serde(rename = "arm")]
    Arm,
    #[serde(rename = "host_register")]
    HostRegister,
    #[serde(rename = "release")]
    Release,
    #[serde(rename = "authority_intent")]
    AuthorityIntent,
    #[serde(rename = "authority_ack")]
    AuthorityAck,
}

/// The six rows of a `Cap`, always in this order: H rows, then A rows.
pub const PROJECTION_ORDER: [ProjectionAction; 6] = [
    ProjectionAction::Seal,
    ProjectionAction::Arm,
    ProjectionAction::HostRegister,
    ProjectionAction::Release,
    ProjectionAction::AuthorityIntent,
    ProjectionAction::AuthorityAck,
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Projection {
    pub action: ProjectionAction,
    pub basis: HexDigest,
    #[serde(deserialize_with = "nullable")]
    pub target: Option<HexDigest>,
    #[serde(deserialize_with = "nullable")]
    pub next: Option<Dims>,
    #[serde(deserialize_with = "nullable")]
    pub reserve: Option<Dims>,
    #[serde(deserialize_with = "nullable")]
    pub expected_ack: Option<Ack>,
}

impl Wire for Projection {
    /// Unknown input is all-null: a row with no target has no next, reserve or ACK, and
    /// never assumes `fits`.
    fn validate(&self) -> Result<(), CodecError> {
        if self.target.is_none()
            && (self.next.is_some() || self.reserve.is_some() || self.expected_ack.is_some())
        {
            return Err(CodecError::Value("projection"));
        }
        Ok(())
    }
}

/// `Cap`: actual dimensions and the six ordered projections.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cap {
    pub actual: Dims,
    pub projections: Vec<Projection>,
}

impl Wire for Cap {
    fn validate(&self) -> Result<(), CodecError> {
        if self.projections.len() != PROJECTION_ORDER.len()
            || self
                .projections
                .iter()
                .zip(PROJECTION_ORDER)
                .any(|(row, want)| row.action != want)
        {
            return Err(CodecError::Value("capacity rows"));
        }
        self.projections.iter().try_for_each(Wire::validate)
    }
}

/// The body of every `ProofQuery(T)`; `T` is the tag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofQuery {
    pub q: Q,
    pub plan: HexDigest,
    #[serde(deserialize_with = "nullable")]
    pub preview: Option<Bind>,
}

/// `HostClock` body: the Hk-signed private clock reply, in qualified seconds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostClockBody {
    pub q: Q,
    pub plan: HexDigest,
    pub proc: Proc,
    pub instance: Ident,
    pub now: Uint,
    pub uncertainty: Uint,
}

impl Wire for HostClockBody {
    fn validate(&self) -> Result<(), CodecError> {
        if self.uncertainty.get() > 5 {
            return Err(CodecError::Value("host clock uncertainty"));
        }
        Ok(())
    }
}

wire!(X, Proc, Q, Reg, Ack, Ctx, Members, Bind, Dims, ClaimKind);

impl Wire for ProofQuery {}

impl ProofQuery {
    /// Decode a `ProofQuery(T)` envelope for the target named by `tag`: `query.api` has no
    /// preview.
    pub fn decode_signed(bytes: &[u8], tag: Tag) -> Result<Sig<ProofQuery>, SigError> {
        if !matches!(tag, Tag::QueryHost | Tag::QueryAuthority | Tag::QueryApi) {
            return Err(SigError::WrongTag);
        }
        let query = Sig::<ProofQuery>::decode(bytes, tag)?;
        if tag == Tag::QueryApi && query.body.preview.is_some() {
            return Err(CodecError::Value("api query preview").into());
        }
        Ok(query)
    }
}
