//! The custody frame ABI: the wire every frame repeats and the signed bodies. The pidfd
//! and the kernel comparison live in the custodian; nothing here serializes a descriptor.
//!
//! `slot` is the custodian's own local slot. It is opaque metadata copied through the
//! frames so both ends compare whole wires: the candidate never uses it as a file
//! descriptor number and no field of any frame carries the descriptor the candidate holds.

use super::canonical::{h, wire, CodecError, Wire};
use super::objects::{Proc, X};
use super::prim::{HexDigest, LitBool, Nonce, Uint};
use super::sig::{PinnedKey, Sig, SigError, Tag};
use serde::{Deserialize, Serialize};

/// The two supervised resources.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Resource {
    #[serde(rename = "daemon")]
    Daemon,
    #[serde(rename = "authority")]
    Authority,
}

/// The custodian-local slot: a number the custodian chose, never a descriptor the holder
/// of this value may use. It has no conversion to a file descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Slot(Uint);

impl Slot {
    pub fn new(value: u64) -> Result<Self, CodecError> {
        Uint::new(value).map(Self)
    }
}

/// `Wire`: the identity every custody frame repeats.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyWire {
    pub x: X,
    pub plan: HexDigest,
    pub resource: Resource,
    pub owner: Nonce,
    pub custodian: Proc,
    pub old: Proc,
    #[serde(deserialize_with = "super::prim::nullable")]
    pub next: Option<Proc>,
    pub challenge: Nonce,
    pub slot: Slot,
}

impl CustodyWire {
    /// `W` of the request frame: the capture's wire with its actual consumed successor and
    /// a fresh challenge.
    pub fn request_for(
        capture: &CustodyWire,
        successor: Proc,
        challenge: Nonce,
    ) -> Result<Self, CodecError> {
        if capture.next.is_some() || challenge == capture.challenge {
            return Err(CodecError::Value("request wire"));
        }
        Ok(Self {
            next: Some(successor),
            challenge,
            ..capture.clone()
        })
    }

    /// A request wire is the capture's with only `next` and `challenge` replaced.
    pub fn is_request_for(&self, capture: &CustodyWire) -> bool {
        capture.next.is_none()
            && self.next.is_some()
            && self.challenge != capture.challenge
            && Self {
                next: None,
                challenge: capture.challenge,
                ..self.clone()
            } == *capture
    }
}

/// `Capture` body: `wire.next` is null.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureBody {
    pub wire: CustodyWire,
}

impl Wire for CaptureBody {
    fn validate(&self) -> Result<(), CodecError> {
        if self.wire.next.is_some() {
            return Err(CodecError::Value("capture next"));
        }
        Ok(())
    }
}

/// `custody.load` body, signed by Rk for the consumed launch only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBody {
    pub x: X,
    pub plan: HexDigest,
    pub resource: Resource,
    pub owner: Nonce,
    pub launch: HexDigest,
    pub capture: HexDigest,
}

macro_rules! kind {
    ($name:ident, $text:literal) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub enum $name {
            #[serde(rename = $text)]
            Only,
        }
    };
}
kind!(RequestKind, "request");
kind!(HandleKind, "handle");
kind!(EchoKind, "echo");

macro_rules! frame {
    ($(#[$meta:meta])* $name:ident, $kind:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            pub kind: $kind,
            pub wire: CustodyWire,
        }

        impl Wire for $name {
            fn validate(&self) -> Result<(), CodecError> {
                if self.wire.next.is_none() {
                    return Err(CodecError::Value("frame wire"));
                }
                Ok(())
            }
        }
    };
}
frame!(/// Candidate to custodian; no FD.
    RequestFrame, RequestKind);
frame!(/// Custodian to candidate; carries one pidfd out of band.
    HandleFrame, HandleKind);
frame!(/// Candidate to custodian; returns the same descriptor out of band.
    EchoFrame, EchoKind);

/// `custody.match` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchBody {
    pub wire: CustodyWire,
    pub capture: HexDigest,
    pub same: LitBool<true>,
}

/// `custody.exit` body; `match` is the hash of the complete matched envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitBody {
    pub wire: CustodyWire,
    #[serde(rename = "match")]
    pub matched: HexDigest,
    pub exited: LitBool<true>,
}

wire!(LoadBody, MatchBody, ExitBody, CustodyWire);

/// A signed capture, load, match or exit.
pub type Capture = Sig<CaptureBody>;
pub type Matched = Sig<MatchBody>;
pub type Exited = Sig<ExitBody>;

/// Verify capture then matched under the pinned Rk: the match is for exactly `request`,
/// which must be the capture's wire with only successor and challenge replaced, and it
/// names the hash of the complete capture envelope.
pub fn verify_match(
    capture: &Capture,
    matched: &Matched,
    rk: &PinnedKey,
    request: &CustodyWire,
) -> Result<(), SigError> {
    let captured = capture.verify(Tag::CustodyCapture, rk)?;
    let body = matched.verify(Tag::CustodyMatch, rk)?;
    if !request.is_request_for(&captured.wire)
        || body.wire != *request
        || body.capture != h(capture)?
    {
        return Err(CodecError::Value("custody match").into());
    }
    Ok(())
}

/// Verify the full chain: capture, matched, exited. The exit repeats the same wire and
/// names the hash of the complete matched envelope.
pub fn verify_exit(
    capture: &Capture,
    matched: &Matched,
    exited: &Exited,
    rk: &PinnedKey,
    request: &CustodyWire,
) -> Result<(), SigError> {
    verify_match(capture, matched, rk, request)?;
    let body = exited.verify(Tag::CustodyExit, rk)?;
    if body.wire != *request || body.matched != h(matched)? {
        return Err(CodecError::Value("custody exit").into());
    }
    Ok(())
}
