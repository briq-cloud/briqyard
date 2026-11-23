//! Sealed-start wire contract, interface revision 3.1 (SYL-268).
//!
//! Shared canonical codec, signature envelope and typed wire objects for the bifurcated
//! runtime. Nothing here performs I/O, holds a private key or decides policy: it parses
//! and encodes bytes, checks one pinned signer per envelope, and names the exact objects
//! the contract defines. Every message is validated from its **raw bytes** (before any
//! JSON middleware) and must re-encode to the identical bytes.
//!
//! * [`canonical`]: the `C(t)` codec, its bounds and the `Wire` trait.
//! * [`prim`]: the scalar vocabulary (`U`, `P`, `I`, `D`, `N`/`K`/`S`, UUIDs, literals).
//! * [`sig`]: `Sig(tag, T)`, signer roles, strict Ed25519 verification.
//! * [`objects`]: `X`, `Proc`, `Q`, `Reg`/`Ack`/`Ctx`, `Members`, `Plan`, capacity and clock objects.
//! * [`plan_pin`]: the two prior Plan commitments, the root custody read and its trust record.
//! * [`trial`]: the single sealed-trial ABI and its native command/result commitments.
//! * [`custody`]: the custody frame ABI's wire and signed bodies.
//! * [`transition`]: the durable gate, guard and cut, the action permits, the signed reads, the
//!   launch/death/resume evidence and the private control envelopes of the v2 transition.

pub mod canonical;
pub mod custody;
pub mod objects;
pub mod plan_pin;
pub mod prim;
pub mod sig;
pub mod transition;
pub mod trial;

pub use canonical::{decode, decode_with, encode, encode_with, h, CodecError, Limits, Wire};

#[cfg(test)]
mod tests;
