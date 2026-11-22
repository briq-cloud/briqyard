//! Literals, the bearer secret type, the `HostClock` envelope and the salted challenge.

use crate::execution::sealed::canonical::{encode, CodecError};
use crate::execution::sealed::objects::{HostClockBody, Proc, Q};
use crate::execution::sealed::prim::{Bytes, HexDigest, Ident, Nonce};
use crate::execution::sealed::sig::{Sig, Tag};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;

/// The Hk-signed private clock reply nested in `ARead` and `authority.observe`.
pub type HostClock = Sig<HostClockBody>;

pub(crate) fn refuse<T>(what: &'static str) -> Result<T, CodecError> {
    Err(CodecError::Value(what))
}

/// A nested signature envelope carries exactly the tag literal its enclosing object expects.
/// The signature bytes cover the tag, so they can never stand for another signature domain;
/// this makes the same fact part of the enclosing object's validity at decode time, before
/// and independent of any verification under a pinned key.
pub(crate) fn expect_tag<T>(sig: &Sig<T>, tag: Tag) -> Result<(), CodecError> {
    if sig.tag != tag {
        return refuse("nested tag");
    }
    Ok(())
}

/// The nested clock sample was taken from this host process and this journal instance.
pub(crate) fn clock_is_from(clock: &HostClock, proc: &Proc, instance: &Ident) -> bool {
    clock.body.proc == *proc && clock.body.instance == *instance
}

/// The JSON literal `null` fixed by a schema (`evidence:null`): never omitted, never a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LitNull;

impl Serialize for LitNull {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_unit()
    }
}

impl<'de> Deserialize<'de> for LitNull {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        <()>::deserialize(d).map(|()| Self)
    }
}

/// `closure` of a receipt: the only closure a host can attest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Closure {
    #[serde(rename = "host_scoped_writes")]
    HostScopedWrites,
}

/// `Resume.mode`: observer reattachment only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResumeMode {
    #[serde(rename = "reattach_read_only")]
    ReattachReadOnly,
}

/// A secret bearer value, `brx_` + the unpadded base64url of 32 random bytes. It prints as
/// redacted and is serialized only into the private `Secrets` file, never onto HTTP.
#[derive(Clone, PartialEq, Eq)]
pub struct Bearer(String);

impl Bearer {
    pub fn new(text: &str) -> Result<Self, CodecError> {
        let rest = text
            .strip_prefix("brx_")
            .ok_or(CodecError::Value("bearer"))?;
        Nonce::parse(rest).map_err(|_| CodecError::Value("bearer"))?;
        Ok(Self(text.to_owned()))
    }

    pub fn from_random(random: &Nonce) -> Self {
        Self(format!("brx_{}", random.to_text()))
    }

    /// The member digest: hex SHA-256 of the exact UTF-8 bearer bytes.
    pub fn digest(&self) -> HexDigest {
        HexDigest::of(self.0.as_bytes())
    }

    /// The raw secret, for the one place that sends it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Bearer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Bearer(<redacted>)")
    }
}

impl Serialize for Bearer {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Bearer {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        Self::new(&text).map_err(de::Error::custom)
    }
}

/// The nonce A uses to challenge H for its own observation:
/// `base64url(SHA256(C({outer:q, plan:plan, salt:salt})))`. It binds the clock sample to
/// A's outer query, so a sample made for another verifier cannot be substituted.
pub fn host_challenge_nonce(
    outer: &Q,
    plan: &HexDigest,
    salt: &Nonce,
) -> Result<Nonce, CodecError> {
    #[derive(Serialize)]
    struct Challenge<'a> {
        outer: &'a Q,
        plan: &'a HexDigest,
        salt: &'a Nonce,
    }
    let bytes = encode(&Challenge { outer, plan, salt })?;
    Ok(Bytes::from_array(Sha256::digest(bytes).into()))
}

/// The nested clock sample answers exactly this outer query: same X and plan, and the
/// nonce is the salted derivation.
pub(crate) fn check_clock_binding(
    clock: &HostClock,
    q: &Q,
    plan: &HexDigest,
    salt: &Nonce,
) -> Result<(), CodecError> {
    expect_tag(clock, Tag::HostClock)?;
    let body = &clock.body;
    if body.q.x != q.x || body.plan != *plan {
        return refuse("host clock scope");
    }
    if body.q.nonce != host_challenge_nonce(q, plan, salt)? {
        return refuse("host clock challenge");
    }
    Ok(())
}
