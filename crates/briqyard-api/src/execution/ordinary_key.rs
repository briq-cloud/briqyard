//! The one native profile of the ordinary authority signing key (interface v3.2).
//!
//! Private material only ever crosses as a sealed, read-only anonymous file; this module owns
//! its exact encoding, portable everywhere, and (Linux only, `descriptor`) the checks of such a
//! descriptor. No other platform reads the key from a file. It never hashes, logs, names or
//! serializes the private bytes, and it supplies no signing method of its own. Closing a
//! descriptor or dropping a buffer does not revoke other copies or guarantee physical erasure.

use ring::signature::{Ed25519KeyPair, KeyPair};
use thiserror::Error;

/// 16-byte fixed prefix, 32 seed bytes, `812100`, 32 public bytes, nothing else.
pub const PKCS8_BYTES: usize = 83;

const PREFIX: [u8; 16] = [
    0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const PUBLIC_WRAPPER: [u8; 3] = [0x81, 0x21, 0x00];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("ordinary authority key is not the exact PKCS#8 v2 profile")]
    Profile,
    #[error("ordinary authority key descriptor is missing, aliased or malformed")]
    Descriptor,
    #[error("sealed ordinary authority key has unexpected metadata")]
    Metadata,
    #[error("ordinary authority key {operation} failed with errno {errno}")]
    Io { operation: &'static str, errno: i32 },
}

/// A key that passed the exact profile. It has no signing method: only the guarded issuer
/// takes it, after comparing its derived public key with the independently pinned identity.
pub struct OrdinaryAuthorityKey(Ed25519KeyPair);

impl std::fmt::Debug for OrdinaryAuthorityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OrdinaryAuthorityKey(..)")
    }
}

impl OrdinaryAuthorityKey {
    /// `ring` checks the version, algorithm and that the embedded public key belongs to the
    /// seed; the explicit constraints reject every other encoding it would still accept.
    pub fn from_profile(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() != PKCS8_BYTES || bytes[..16] != PREFIX || bytes[48..51] != PUBLIC_WRAPPER {
            return Err(KeyError::Profile);
        }
        let pair = Ed25519KeyPair::from_pkcs8(bytes).map_err(|_| KeyError::Profile)?;
        if pair.public_key().as_ref() != &bytes[51..] {
            return Err(KeyError::Profile);
        }
        Ok(Self(pair))
    }

    /// The public key derived from the actual private key, never an advertised value.
    pub fn public(&self) -> [u8; 32] {
        self.0
            .public_key()
            .as_ref()
            .try_into()
            .expect("Ed25519 public keys have 32 bytes")
    }

    pub(super) fn into_pair(self) -> Ed25519KeyPair {
        self.0
    }
}

#[cfg(target_os = "linux")]
mod descriptor;
#[cfg(target_os = "linux")]
pub use descriptor::*;

#[cfg(test)]
mod tests;
