//! Conformance tests. Every expected value below is copied from the interface revision
//! (SYL-268 v3.1), never computed by the code under test. The RFC 8032 section 7.1 seeds
//! are synthetic test fixtures: they exist only in this cfg(test) module and are not
//! provisioning defaults.

mod custody;
mod negative;
mod objects;
mod owner;
mod trial;
mod vectors;

use super::objects::{Proc, X};
use super::prim::{BootId, Build, Bytes, Env, HexDigest, Ident, KeyBytes, Nonce, PosInt};
use super::sig::{PinnedKey, Role, Signer};
use ed25519_dalek::SigningKey;

/// A synthetic signer around an RFC 8032 test seed.
pub(crate) struct TestSigner(SigningKey);

impl TestSigner {
    fn from_seed_hex(seed: &str) -> Self {
        let seed: [u8; 32] = hex::decode(seed).unwrap().try_into().unwrap();
        Self(SigningKey::from_bytes(&seed))
    }
    /// RFC 8032 7.1 test 1, played as Rk.
    pub(crate) fn rk() -> Self {
        Self::from_seed_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    }
    /// Test 2, Bk.
    pub(crate) fn bk() -> Self {
        Self::from_seed_hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    }
    /// Test 3, Ak.
    pub(crate) fn ak() -> Self {
        Self::from_seed_hex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
    }
    pub(crate) fn pinned(&self, role: Role) -> PinnedKey {
        PinnedKey::new(role, self.public_key()).unwrap()
    }
}

impl Signer for TestSigner {
    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer as _;
        self.0.sign(message).to_bytes()
    }
}

/// n(k): 32 bytes all equal to k.
pub(crate) fn n(k: u8) -> Nonce {
    Bytes::from_array([k; 32])
}

pub(crate) fn fixture_nonce(label: u8) -> Nonce {
    use std::sync::{Mutex, OnceLock};
    static NONCES: OnceLock<Mutex<[Option<Nonce>; 256]>> = OnceLock::new();
    let nonces = NONCES.get_or_init(|| Mutex::new([None; 256]));
    let mut nonces = nonces.lock().unwrap();
    let entry = &mut nonces[usize::from(label)];
    *entry.get_or_insert_with(|| {
        let mut raw = [0; 32];
        getrandom::fill(&mut raw).unwrap();
        Bytes::from_array(raw)
    })
}

pub(crate) fn key(k: u8) -> KeyBytes {
    Bytes::from_array([k; 32])
}

pub(crate) fn id(text: &str) -> Ident {
    Ident::new(text).unwrap()
}

pub(crate) fn pos(value: u64) -> PosInt {
    PosInt::new(value).unwrap()
}

/// 64 copies of one hex digit.
pub(crate) fn dg(digit: char) -> HexDigest {
    HexDigest::new(digit.to_string().repeat(64)).unwrap()
}

pub(crate) fn x() -> X {
    X {
        aud: Env::Staging,
        host: id("host.test"),
        op: dg('0'),
        serial: pos(1),
    }
}

/// The fixtures' Proc p, with a chosen PID.
pub(crate) fn proc(pid: u64) -> Proc {
    Proc {
        boot: BootId::new("00000000-0000-4000-8000-000000000004").unwrap(),
        pid: pos(pid),
        start: pos(912),
        exe: dg('3'),
        build: Build::new("fence-3").unwrap(),
    }
}
