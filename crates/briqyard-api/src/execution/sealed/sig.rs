//! `Sig(tag, T) = {tag, kid, body, sig}`.
//!
//! Pure Ed25519 (RFC 8032) over ASCII `BRIQ-SEAL/2`, NUL, the ASCII tag, NUL, the ASCII
//! `kid`, NUL, `C(body)`; `kid = h(raw public key)`. A verifier never takes a key from the
//! envelope: the caller pins an exact key *and* the role it plays, the tag must be the
//! one expected, and the tag must be one that role may sign. Verification is strict:
//! canonical point and scalar encodings, no small-order point and no point outside the
//! prime-order subgroup, for both the public key and the signature's `R`.

use super::canonical::{encode, CodecError, Wire};
use super::prim::{HexDigest, SigBytes};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// The domain-separation prefix of every signature in the sealed protocol.
pub const DOMAIN: &[u8] = b"BRIQ-SEAL/2";

/// The four independent signing roles: host evidence, authority evidence, API decision,
/// receiver/custodian approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    Hk,
    Ak,
    Bk,
    Rk,
}

/// Every tag this module can sign or verify. The closed vocabulary is the allowlist: an
/// unknown tag does not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tag {
    #[serde(rename = "query.host")]
    QueryHost,
    #[serde(rename = "query.authority")]
    QueryAuthority,
    #[serde(rename = "query.api")]
    QueryApi,
    #[serde(rename = "host.clock")]
    HostClock,
    #[serde(rename = "custody.capture")]
    CustodyCapture,
    #[serde(rename = "custody.load")]
    CustodyLoad,
    #[serde(rename = "custody.match")]
    CustodyMatch,
    #[serde(rename = "custody.exit")]
    CustodyExit,
    #[serde(rename = "trial3.receiver")]
    Trial3Receiver,
    #[serde(rename = "trial3.api")]
    Trial3Api,
    #[serde(rename = "trial3.issued")]
    Trial3Issued,
    #[serde(rename = "trial3.status")]
    Trial3Status,
    #[serde(rename = "retired")]
    Retired,
    #[serde(rename = "decision")]
    Decision,
    #[serde(rename = "receiver")]
    Receiver,
    #[serde(rename = "intent")]
    Intent,
    #[serde(rename = "host.read")]
    HostRead,
    #[serde(rename = "authority.read")]
    AuthorityRead,
    #[serde(rename = "api.read")]
    ApiRead,
    #[serde(rename = "query.observe")]
    QueryObserve,
    #[serde(rename = "authority.observe")]
    AuthorityObserve,
    #[serde(rename = "review.request")]
    ReviewRequest,
    #[serde(rename = "launch.receiver")]
    LaunchReceiver,
    #[serde(rename = "launch.api")]
    LaunchApi,
    #[serde(rename = "resume.request")]
    ResumeRequest,
    #[serde(rename = "resume.challenge")]
    ResumeChallenge,
    #[serde(rename = "resume.receiver")]
    ResumeReceiver,
    #[serde(rename = "resume.api")]
    ResumeApi,
    #[serde(rename = "client.stage")]
    ClientStage,
    #[serde(rename = "client.query")]
    ClientQuery,
    #[serde(rename = "client.enable")]
    ClientEnable,
    #[serde(rename = "final.query")]
    FinalQuery,
    #[serde(rename = "final.read")]
    FinalRead,
    #[serde(rename = "trial3.offer.query")]
    Trial3OfferQuery,
    #[serde(rename = "trial3.offer")]
    Trial3Offer,
    #[serde(rename = "trial3.observe")]
    Trial3Observe,
    #[serde(rename = "trial3.archive")]
    Trial3Archive,
    #[serde(rename = "trial3.archive.reply")]
    Trial3ArchiveReply,
}

impl Tag {
    pub const fn as_str(self) -> &'static str {
        match self {
            Tag::QueryHost => "query.host",
            Tag::QueryAuthority => "query.authority",
            Tag::QueryApi => "query.api",
            Tag::HostClock => "host.clock",
            Tag::CustodyCapture => "custody.capture",
            Tag::CustodyLoad => "custody.load",
            Tag::CustodyMatch => "custody.match",
            Tag::CustodyExit => "custody.exit",
            Tag::Trial3Receiver => "trial3.receiver",
            Tag::Trial3Api => "trial3.api",
            Tag::Trial3Issued => "trial3.issued",
            Tag::Trial3Status => "trial3.status",
            Tag::Retired => "retired",
            Tag::Decision => "decision",
            Tag::Receiver => "receiver",
            Tag::Intent => "intent",
            Tag::HostRead => "host.read",
            Tag::AuthorityRead => "authority.read",
            Tag::ApiRead => "api.read",
            Tag::QueryObserve => "query.observe",
            Tag::AuthorityObserve => "authority.observe",
            Tag::ReviewRequest => "review.request",
            Tag::LaunchReceiver => "launch.receiver",
            Tag::LaunchApi => "launch.api",
            Tag::ResumeRequest => "resume.request",
            Tag::ResumeChallenge => "resume.challenge",
            Tag::ResumeReceiver => "resume.receiver",
            Tag::ResumeApi => "resume.api",
            Tag::ClientStage => "client.stage",
            Tag::ClientQuery => "client.query",
            Tag::ClientEnable => "client.enable",
            Tag::FinalQuery => "final.query",
            Tag::FinalRead => "final.read",
            Tag::Trial3OfferQuery => "trial3.offer.query",
            Tag::Trial3Offer => "trial3.offer",
            Tag::Trial3Observe => "trial3.observe",
            Tag::Trial3Archive => "trial3.archive",
            Tag::Trial3ArchiveReply => "trial3.archive.reply",
        }
    }

    /// The single-use trial ABI 3 vocabulary. A `trial3.` tag is never a v2 transition
    /// authorization and a v2 tag is never a trial3 one: the two sets are disjoint.
    pub const fn is_trial3(self) -> bool {
        matches!(
            self,
            Tag::Trial3Receiver
                | Tag::Trial3Api
                | Tag::Trial3Issued
                | Tag::Trial3Status
                | Tag::Trial3OfferQuery
                | Tag::Trial3Offer
                | Tag::Trial3Observe
                | Tag::Trial3Archive
                | Tag::Trial3ArchiveReply
        )
    }

    /// The roles allowed to sign this tag: a query is signed by a participant of the
    /// target's X (H by Ak/Rk/Bk, A by Hk/Rk/Bk, API by Hk/Ak/Rk); the rest have one signer.
    pub const fn signers(self) -> &'static [Role] {
        match self {
            Tag::QueryHost => &[Role::Ak, Role::Rk, Role::Bk],
            Tag::QueryAuthority => &[Role::Hk, Role::Rk, Role::Bk],
            Tag::QueryApi => &[Role::Hk, Role::Ak, Role::Rk],
            Tag::HostClock => &[Role::Hk],
            Tag::CustodyCapture | Tag::CustodyLoad | Tag::CustodyMatch | Tag::CustodyExit => {
                &[Role::Rk]
            }
            Tag::Trial3Receiver => &[Role::Rk],
            Tag::Trial3Api | Tag::Trial3Issued => &[Role::Bk],
            Tag::Trial3Status => &[Role::Ak],
            Tag::Retired => &[Role::Hk],
            Tag::Decision => &[Role::Bk],
            Tag::Receiver => &[Role::Rk],
            Tag::Intent => &[Role::Ak],
            Tag::HostRead => &[Role::Hk],
            Tag::AuthorityRead => &[Role::Ak],
            Tag::ApiRead => &[Role::Bk],
            Tag::QueryObserve => &[Role::Rk, Role::Bk],
            Tag::AuthorityObserve => &[Role::Ak],
            Tag::ReviewRequest => &[Role::Bk],
            Tag::LaunchReceiver => &[Role::Rk],
            Tag::LaunchApi => &[Role::Bk],
            Tag::ResumeRequest => &[Role::Rk],
            Tag::ResumeChallenge => &[Role::Rk],
            Tag::ResumeReceiver => &[Role::Rk],
            Tag::ResumeApi => &[Role::Bk],
            Tag::ClientStage => &[Role::Bk],
            Tag::ClientQuery => &[Role::Bk, Role::Rk],
            Tag::ClientEnable => &[Role::Bk],
            Tag::FinalQuery => &[Role::Rk],
            Tag::FinalRead => &[Role::Bk],
            Tag::Trial3OfferQuery => &[Role::Rk],
            Tag::Trial3Offer => &[Role::Bk],
            Tag::Trial3Observe => &[Role::Rk, Role::Bk],
            Tag::Trial3Archive => &[Role::Rk],
            Tag::Trial3ArchiveReply => &[Role::Bk],
        }
    }
}

/// Why a signature or key was refused. Never carries message or key bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SigError {
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error("envelope tag is not the expected tag")]
    WrongTag,
    #[error("the pinned role may not sign this tag")]
    RoleNotPermitted,
    #[error("envelope kid is not the pinned key's kid")]
    KeyMismatch,
    #[error("public key refused: {0}")]
    InvalidKey(&'static str),
    #[error("signature does not verify")]
    BadSignature,
}

/// Signs raw bytes. The wire crate never holds a private key: implementors live at the
/// signer, and this trait carries no secret in any type it names.
pub trait Signer {
    fn public_key(&self) -> [u8; 32];
    fn sign(&self, message: &[u8]) -> [u8; 64];
}

/// An independently pinned public key and the role it plays. The only way to verify.
#[derive(Clone, Debug)]
pub struct PinnedKey {
    role: Role,
    raw: [u8; 32],
    kid: HexDigest,
    key: VerifyingKey,
}

/// A point encoding is canonical, not of small order and in the prime-order subgroup.
fn strict_point(bytes: &[u8; 32]) -> Result<VerifyingKey, SigError> {
    let key =
        VerifyingKey::from_bytes(bytes).map_err(|_| SigError::InvalidKey("not a curve point"))?;
    let point = key.to_edwards();
    if point.compress().to_bytes() != *bytes {
        return Err(SigError::InvalidKey("non-canonical encoding"));
    }
    if key.is_weak() {
        return Err(SigError::InvalidKey("small-order point"));
    }
    if !point.is_torsion_free() {
        return Err(SigError::InvalidKey("outside the prime-order subgroup"));
    }
    Ok(key)
}

/// RFC 8032 verification with the cofactorless equation, a canonical scalar (dalek's
/// `verify_strict`), and a signature point `R` held to the same rules as a key.
fn verify_raw(key: &VerifyingKey, message: &[u8], sig: &[u8; 64]) -> Result<(), SigError> {
    let mut r = [0u8; 32];
    r.copy_from_slice(&sig[..32]);
    strict_point(&r).map_err(|_| SigError::BadSignature)?;
    key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(sig))
        .map_err(|_| SigError::BadSignature)
}

/// The bytes that are signed: `BRIQ-SEAL/2 NUL tag NUL kid NUL C(body)`.
pub fn preimage(tag: Tag, kid: &HexDigest, canonical_body: &[u8]) -> Vec<u8> {
    [
        DOMAIN,
        &[0],
        tag.as_str().as_bytes(),
        &[0],
        kid.as_str().as_bytes(),
        &[0],
        canonical_body,
    ]
    .concat()
}

impl PinnedKey {
    pub fn new(role: Role, raw: [u8; 32]) -> Result<Self, SigError> {
        let key = strict_point(&raw)?;
        Ok(Self {
            role,
            raw,
            kid: HexDigest::of(&raw),
            key,
        })
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn raw(&self) -> &[u8; 32] {
        &self.raw
    }

    pub fn kid(&self) -> &HexDigest {
        &self.kid
    }
}

/// `Sig(tag, T)`. Decoding fixes the shape; `verify` is what makes it evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sig<T> {
    pub tag: Tag,
    pub kid: HexDigest,
    pub body: T,
    pub sig: SigBytes,
}

impl<T: Wire> Wire for Sig<T> {
    fn validate(&self) -> Result<(), CodecError> {
        self.body.validate()
    }
}

impl<T: Wire> Sig<T> {
    /// Sign `body` with `signer`; the result is re-verified against the signer's own key so
    /// a faulty signer or a weak key cannot produce an envelope.
    pub fn sign(tag: Tag, body: T, signer: &dyn Signer) -> Result<Self, SigError> {
        let raw = signer.public_key();
        let key = strict_point(&raw)?;
        body.validate()?;
        let kid = HexDigest::of(&raw);
        let message = preimage(tag, &kid, &encode(&body)?);
        let sig = signer.sign(&message);
        verify_raw(&key, &message, &sig)?;
        Ok(Self {
            tag,
            kid,
            body,
            sig: SigBytes::from_array(sig),
        })
    }

    /// Decode an envelope that must carry `tag`.
    pub fn decode(bytes: &[u8], tag: Tag) -> Result<Self, SigError> {
        let sig: Self = super::canonical::decode(bytes)?;
        if sig.tag != tag {
            return Err(SigError::WrongTag);
        }
        Ok(sig)
    }

    /// Verify against the pinned key and role for exactly `tag`; returns the verified body.
    pub fn verify(&self, tag: Tag, pinned: &PinnedKey) -> Result<&T, SigError> {
        if self.tag != tag {
            return Err(SigError::WrongTag);
        }
        if !tag.signers().contains(&pinned.role) {
            return Err(SigError::RoleNotPermitted);
        }
        if self.kid != pinned.kid {
            return Err(SigError::KeyMismatch);
        }
        self.body.validate()?;
        let message = preimage(self.tag, &self.kid, &encode(&self.body)?);
        verify_raw(&pinned.key, &message, self.sig.as_array())?;
        Ok(&self.body)
    }
}
