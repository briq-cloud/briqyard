//! The two prior Plan commitments and the root custody read of them (interface v3.5, SYL-268).
//!
//! Shared canonical types only: the receiver's pin (R), the closed read request root custody
//! sends, the observation pair that answers it, and the root-private trust record that names
//! the independently enrolled Rk/Bk. Nothing here performs I/O, holds a private key or decides
//! policy. A [`Pin`] says which Plan was committed; it is neither enrollment, a launch
//! grant, a consumed owner nor permission to act, and neither observation tag is ever an
//! effect or claim tag.

use super::canonical::{decode, CodecError, Wire};
use super::custody::Resource;
use super::objects::{Plan, X};
use super::prim::{Env, HexDigest, Ident, KeyBytes, Nonce, PosInt};
use super::sig::{PinnedKey, Role, Sig, SigError};
use serde::{Deserialize, Serialize};

macro_rules! format_literal {
    ($(#[$meta:meta])* $name:ident, $text:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub enum $name {
            #[serde(rename = $text)]
            V1,
        }
    };
}

format_literal!(
    /// `format:"plan.pin/v1"`.
    PinFormat,
    "plan.pin/v1"
);
format_literal!(
    /// `format:"plan.read/v1"`.
    ReadFormat,
    "plan.read/v1"
);
format_literal!(
    /// `format:"plan.reader.trust/v1"`.
    TrustFormat,
    "plan.reader.trust/v1"
);

/// `Pin = {format,x,registered,plan}`: `plan = h(exact C(Plan))`, `x = Plan.x` in full and
/// `registered = Plan.registered`. R and B each commit one of these independently.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub format: PinFormat,
    pub x: X,
    pub registered: Ident,
    pub plan: HexDigest,
}

impl Wire for Pin {}

/// The caller's own exact canonical Plan bytes, decoded strictly. The digest is taken over
/// the received bytes, never over a re-serialization, and never from a requester or a relayed
/// pin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalPlan {
    plan: Plan,
    digest: HexDigest,
}

impl LocalPlan {
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let plan = decode::<Plan>(bytes)?;
        Ok(Self {
            plan,
            digest: HexDigest::of(bytes),
        })
    }

    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    /// `h(exact C(Plan))`.
    pub fn digest(&self) -> &HexDigest {
        &self.digest
    }

    /// The pin this Plan commits to.
    pub fn pin(&self) -> Pin {
        Pin {
            format: PinFormat::V1,
            x: self.plan.x.clone(),
            registered: self.plan.registered.clone(),
            plan: self.digest.clone(),
        }
    }
}

/// The point a read observes. It selects the required state, never an action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReadPoint {
    #[serde(rename = "prearm")]
    Prearm,
    #[serde(rename = "launch")]
    Launch,
    #[serde(rename = "seal")]
    Seal,
}

/// `Read`: the closed request root custody sends. `seal` is daemon-only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Read {
    pub format: ReadFormat,
    pub x: X,
    pub registered: Ident,
    pub resource: Resource,
    pub point: ReadPoint,
    pub nonce: Nonce,
}

impl Wire for Read {
    fn validate(&self) -> Result<(), CodecError> {
        if self.point == ReadPoint::Seal && self.resource != Resource::Daemon {
            return Err(CodecError::Value("authority seal read"));
        }
        Ok(())
    }
}

/// `Body = {read, pin}`: what both observers sign.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadBody {
    pub read: Read,
    pub pin: Pin,
}

impl Wire for ReadBody {
    fn validate(&self) -> Result<(), CodecError> {
        self.read.validate()
    }
}

/// `RProof = Sig("plan.read.receiver", Body)`, Rk only.
pub type RProof = Sig<ReadBody>;
/// `BProof = Sig("plan.read.api", Body)`, Bk only.
pub type BProof = Sig<ReadBody>;

/// `Pair = {receiver: RProof, api: BProof}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadPair {
    pub receiver: RProof,
    pub api: BProof,
}

impl Wire for ReadPair {
    fn validate(&self) -> Result<(), CodecError> {
        self.receiver.validate()?;
        self.api.validate()
    }
}

/// `reg-hash`: lowercase hex SHA-256 of the exact UTF-8 bytes of `registered`.
pub fn reg_hash(registered: &Ident) -> HexDigest {
    HexDigest::of(registered.as_str().as_bytes())
}

/// The typed components of `<aud>/<reg-hash>/<serial>`: no raw host name selects a path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustSelector {
    aud: Env,
    reg_hash: HexDigest,
    serial: PosInt,
}

impl TrustSelector {
    pub fn new(x: &X, registered: &Ident) -> Self {
        Self {
            aud: x.aud,
            reg_hash: reg_hash(registered),
            serial: x.serial,
        }
    }

    pub fn aud(&self) -> &'static str {
        match self.aud {
            Env::Staging => "staging",
            Env::Production => "production",
        }
    }

    pub fn reg_hash(&self) -> &HexDigest {
        &self.reg_hash
    }

    /// Shortest positive decimal, no leading zero.
    pub fn serial(&self) -> String {
        self.serial.get().to_string()
    }

    /// `<serial>.json`.
    pub fn file_name(&self) -> String {
        format!("{}.json", self.serial())
    }
}

/// `{format:"plan.reader.trust/v1",x,registered,rk,bk}`: the root-private trust root
/// installed independently of the guard, the candidate and any offered Plan. It holds no
/// Plan digest and no private key, and entitles nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustRecord {
    pub format: TrustFormat,
    pub x: X,
    pub registered: Ident,
    pub rk: KeyBytes,
    pub bk: KeyBytes,
}

impl Wire for TrustRecord {
    fn validate(&self) -> Result<(), CodecError> {
        if self.rk == self.bk {
            return Err(CodecError::Value("trust keys"));
        }
        Ok(())
    }
}

impl TrustRecord {
    pub fn selector(&self) -> TrustSelector {
        TrustSelector::new(&self.x, &self.registered)
    }

    /// The enrolled `(Rk, Bk)` under strict public-key and subgroup checks.
    pub fn pinned(&self) -> Result<(PinnedKey, PinnedKey), SigError> {
        Ok((
            PinnedKey::new(Role::Rk, *self.rk.as_array())?,
            PinnedKey::new(Role::Bk, *self.bk.as_array())?,
        ))
    }
}

#[cfg(test)]
mod tests;
