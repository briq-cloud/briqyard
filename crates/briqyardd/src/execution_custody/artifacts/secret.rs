//! Typed acquisition and profile checks of the v3 secret and suffix classes. A secret payload
//! never leaves its descriptor as a raw buffer: each accessor returns only its narrowly
//! validated role or possession material. Clearing is best effort: `ring` and the JSON decoder
//! keep their own copies, which this module cannot erase, so none of this is a guarantee that
//! secret bytes are gone from memory.

use super::{
    check_syscall, create_memfd, io_error,
    protocol::{Class, Descriptor, PoolKeyId, Signer, MAX_BEARER, POOL_KEY_BYTES},
    CustodyError, FrozenArtifact, StageDeadline, SEALS,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use briqyard_api::execution::{
    private_cert::{self, Usage},
    provision,
    sealed::{
        decode,
        objects::Plan,
        prim::{HexDigest, KeyBytes},
        sig::{PinnedKey, Role, Signer as SigSigner},
        CodecError, Wire,
    },
    KeyRole, VerificationKey,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use zeroize::Zeroizing;

const MAX_CREDENTIAL: usize = 4096;

fn refuse(reason: &'static str) -> CustodyError {
    CustodyError::Protocol(reason)
}

/// The Ed25519 evidence signer behind Hk or Ak. It only signs through the wire crate's
/// [`SigSigner`] trait; the seed cannot be read back and no accessor serializes it.
pub struct EvidenceSigner {
    role: Signer,
    pair: Ed25519KeyPair,
}

impl std::fmt::Debug for EvidenceSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvidenceSigner")
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

impl EvidenceSigner {
    pub fn role(&self) -> Signer {
        self.role
    }
}

impl SigSigner for EvidenceSigner {
    fn public_key(&self) -> [u8; 32] {
        self.pair
            .public_key()
            .as_ref()
            .try_into()
            .expect("Ed25519 public keys have 32 bytes")
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.pair
            .sign(message)
            .as_ref()
            .try_into()
            .expect("Ed25519 signatures have 64 bytes")
    }
}

/// A validated unencrypted PKCS#8 P-256 key and the digest of the SPKI derived from it.
pub struct TlsPrivateKey {
    pkcs8: Zeroizing<Vec<u8>>,
    spki: HexDigest,
}

impl std::fmt::Debug for TlsPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsPrivateKey")
            .field("spki", &self.spki)
            .finish_non_exhaustive()
    }
}

impl TlsPrivateKey {
    pub fn spki(&self) -> &HexDigest {
        &self.spki
    }

    /// For the one rustls or transport constructor that consumes the key.
    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }
}

/// A continuation bearer: 1..=4096 ASCII bytes 0x21..=0x7e.
pub struct ContinuationBearer(Zeroizing<String>);

impl std::fmt::Debug for ContinuationBearer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ContinuationBearer(..)")
    }
}

impl ContinuationBearer {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The host backup credential pair, each field decoded and checked.
pub struct BackupS3Credentials {
    access: Zeroizing<String>,
    secret: Zeroizing<String>,
}

impl std::fmt::Debug for BackupS3Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BackupS3Credentials(..)")
    }
}

impl BackupS3Credentials {
    pub fn access(&self) -> &str {
        &self.access
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }
}

/// The original file-backed pool key (64 lowercase hex digits) and its existing key id.
pub struct PoolFileKey {
    hex: Zeroizing<String>,
    id: PoolKeyId,
}

impl std::fmt::Debug for PoolFileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolFileKey")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl PoolFileKey {
    pub fn id(&self) -> &PoolKeyId {
        &self.id
    }

    /// For the one ZFS key loader.
    pub fn hex(&self) -> &str {
        &self.hex
    }
}

fn signer_pair(seed: &[u8]) -> Result<Ed25519KeyPair, CustodyError> {
    let seed: &[u8; 32] = seed
        .try_into()
        .map_err(|_| refuse("evidence signer seed length"))?;
    Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| refuse("invalid evidence signer seed"))
}

fn derived_public(pair: &Ed25519KeyPair) -> [u8; 32] {
    pair.public_key()
        .as_ref()
        .try_into()
        .expect("Ed25519 public keys have 32 bytes")
}

fn bearer(bytes: &[u8]) -> Result<Zeroizing<String>, CustodyError> {
    if !(1..=MAX_BEARER as usize).contains(&bytes.len()) || !bytes.iter().all(u8::is_ascii_graphic)
    {
        return Err(refuse("invalid continuation bearer"));
    }
    String::from_utf8(bytes.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| refuse("invalid continuation bearer"))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct S3Wire {
    access: String,
    secret: String,
}

impl Wire for S3Wire {}

fn credential(text: &str) -> Result<Zeroizing<String>, CustodyError> {
    let invalid = || refuse("invalid backup credential pair");
    let raw = Zeroizing::new(URL_SAFE_NO_PAD.decode(text).map_err(|_| invalid())?);
    if raw.is_empty()
        || raw.len() > MAX_CREDENTIAL
        || !raw.iter().all(u8::is_ascii_graphic)
        || URL_SAFE_NO_PAD.encode(&*raw) != text
    {
        return Err(invalid());
    }
    String::from_utf8(raw.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| invalid())
}

fn s3_pair(bytes: &[u8]) -> Result<BackupS3Credentials, CustodyError> {
    let wire: S3Wire = briqyard_api::execution::sealed::decode(bytes)
        .map_err(|_: CodecError| refuse("invalid backup credential pair"))?;
    Ok(BackupS3Credentials {
        access: credential(&wire.access)?,
        secret: credential(&wire.secret)?,
    })
}

fn pool_key(bytes: &[u8]) -> Result<PoolFileKey, CustodyError> {
    let invalid = || refuse("invalid local pool key");
    if bytes.len() as u64 != POOL_KEY_BYTES
        || !bytes.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(invalid());
    }
    let hex = Zeroizing::new(String::from_utf8(bytes.to_vec()).map_err(|_| invalid())?);
    let id = briqyard_api::poolkey::id(&hex).ok_or_else(invalid)?;
    Ok(PoolFileKey {
        id: PoolKeyId::new(id).map_err(|_| invalid())?,
        hex,
    })
}

fn tls_key(bytes: &[u8]) -> Result<TlsPrivateKey, CustodyError> {
    let spki =
        private_cert::key_spki_digest(bytes).map_err(|_| refuse("invalid TLS private key"))?;
    Ok(TlsPrivateKey {
        pkcs8: Zeroizing::new(bytes.to_vec()),
        spki,
    })
}

/// The closed profile of the retained public registry on top of the sealed grammar: one
/// authority entry, one or more central entries of one issuer, every kid and key unique and
/// every key a strict Ed25519 point.
fn registry(bytes: &[u8]) -> Result<Vec<VerificationKey>, CustodyError> {
    let invalid = || refuse("invalid verification registry");
    let keys = provision::sealed_registry(bytes).map_err(|_| invalid())?;
    let mut kids = HashSet::new();
    let mut publics = HashSet::new();
    let (mut authority, mut central_issuer, mut central) = (0, None, 0);
    if keys.len() < 2 {
        return Err(invalid());
    }
    for key in &keys {
        PinnedKey::new(Role::Bk, key.public_key).map_err(|_| invalid())?;
        if key.kid.is_empty() || !kids.insert(&key.kid) || !publics.insert(key.public_key) {
            return Err(invalid());
        }
        match (key.role, &key.authority) {
            (KeyRole::Authority, Some(_)) => authority += 1,
            (KeyRole::Central, None) => {
                central += 1;
                if *central_issuer.get_or_insert(&key.issuer) != &key.issuer {
                    return Err(invalid());
                }
            }
            _ => return Err(invalid()),
        }
    }
    if authority != 1 || central == 0 {
        return Err(invalid());
    }
    Ok(keys)
}

fn seal_memory(bytes: &[u8], class: Class, operation: &'static str) -> Result<File, CustodyError> {
    let file = create_memfd()?;
    (&file)
        .write_all(bytes)
        .map_err(|e| io_error(operation, e))?;
    check_syscall(
        unsafe { libc::fchmod(file.as_raw_fd(), class.mode()) },
        "set native secret mode",
    )?;
    check_syscall(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, SEALS) },
        "seal native secret",
    )?;
    File::open(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(|e| io_error("open sealed native secret read-only", e))
}

impl FrozenArtifact {
    fn stage_secret(bytes: &[u8], class: Class) -> Result<Self, CustodyError> {
        if !class.accepts(bytes.len() as u64) {
            return Err(refuse("invalid native artifact length"));
        }
        let frozen = Self {
            file: seal_memory(bytes, class, "stage native secret")?,
            class,
            bytes: bytes.len() as u64,
        };
        frozen.check_metadata()?;
        Ok(frozen)
    }

    /// Stage a raw RFC 8032 seed from the provisioner's private memory. The derived public
    /// key must equal the advertised one; no digest of the seed is computed. The caller owns,
    /// and should clear, `seed`.
    pub fn freeze_signer(
        seed: &[u8],
        role: Signer,
        public: &KeyBytes,
        deadline: StageDeadline,
    ) -> Result<Self, CustodyError> {
        if derived_public(&signer_pair(seed)?) != *public.as_array() {
            return Err(refuse("evidence signer differs from its advertised key"));
        }
        let frozen = Self::stage_secret(seed, Class::Signer(role))?;
        if frozen.evidence_signer(deadline)?.public_key() != *public.as_array() {
            return Err(refuse("sealed evidence signer changed"));
        }
        deadline.check()?;
        Ok(frozen)
    }

    /// Stage a P-256 PKCS#8 key for one of the three suffix TLS key classes; the advertised
    /// SPKI digest must equal the one derived from the key.
    pub fn freeze_tls_key(
        class: Class,
        pkcs8: &[u8],
        spki: &HexDigest,
        deadline: StageDeadline,
    ) -> Result<Self, CustodyError> {
        if !matches!(
            class,
            Class::TransitionServerKey | Class::TransitionClientKey | Class::DaemonApiKey
        ) {
            return Err(refuse("not a suffix TLS key class"));
        }
        if tls_key(pkcs8)?.spki != *spki {
            return Err(refuse("TLS key differs from its advertised SPKI"));
        }
        let frozen = Self::stage_secret(pkcs8, class)?;
        if frozen.tls_private_key(deadline)?.spki != *spki {
            return Err(refuse("sealed TLS key changed"));
        }
        deadline.check()?;
        Ok(frozen)
    }

    /// Stage the 64-hex file-mode pool key; its id must be the existing pool key id.
    pub fn freeze_pool_key(
        hex: &[u8],
        key_id: &PoolKeyId,
        deadline: StageDeadline,
    ) -> Result<Self, CustodyError> {
        if pool_key(hex)?.id != *key_id {
            return Err(refuse("pool key differs from its advertised id"));
        }
        let frozen = Self::stage_secret(hex, Class::LocalPoolKey)?;
        deadline.check()?;
        Ok(frozen)
    }

    /// Exact bytes of a private descriptor, cleared on drop. Only this module's typed
    /// accessors call it; the generic bounded read refuses secret classes.
    fn read_private(&self, deadline: StageDeadline) -> Result<Zeroizing<Vec<u8>>, CustodyError> {
        let length = self.bytes as usize;
        let mut out = Zeroizing::new(vec![0; length + 1]);
        let mut filled = 0;
        loop {
            deadline.check()?;
            match self.file.read_at(&mut out[filled..], filled as u64) {
                Ok(0) => break,
                Ok(read) => filled += read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(io_error("read native secret", error)),
            }
            if filled > length {
                break;
            }
        }
        if filled != length {
            return Err(refuse("native artifact byte count mismatch"));
        }
        out.truncate(length);
        Ok(out)
    }

    fn expect(&self, class: Class) -> Result<(), CustodyError> {
        if self.class != class {
            return Err(refuse("unexpected native artifact class"));
        }
        self.check_metadata().map(|_| ())
    }

    /// The signer behind an Hk or Ak descriptor, from the actual seed. The caller compares
    /// its derived public key with the independently pinned Plan key.
    pub fn evidence_signer(&self, deadline: StageDeadline) -> Result<EvidenceSigner, CustodyError> {
        let Class::Signer(role) = self.class else {
            return Err(refuse("not an evidence signer"));
        };
        self.check_metadata()?;
        Ok(EvidenceSigner {
            role,
            pair: signer_pair(&self.read_private(deadline)?)?,
        })
    }

    pub fn tls_private_key(&self, deadline: StageDeadline) -> Result<TlsPrivateKey, CustodyError> {
        if !matches!(
            self.class,
            Class::TransitionServerKey | Class::TransitionClientKey | Class::DaemonApiKey
        ) {
            return Err(refuse("not a suffix TLS key"));
        }
        self.check_metadata()?;
        tls_key(&self.read_private(deadline)?)
    }

    pub fn continuation_bearer(
        &self,
        deadline: StageDeadline,
    ) -> Result<ContinuationBearer, CustodyError> {
        self.expect(Class::ContinuationBearer)?;
        bearer(&self.read_private(deadline)?).map(ContinuationBearer)
    }

    pub fn backup_s3(&self, deadline: StageDeadline) -> Result<BackupS3Credentials, CustodyError> {
        self.expect(Class::BackupS3Pair)?;
        s3_pair(&self.read_private(deadline)?)
    }

    pub fn pool_file_key(&self, deadline: StageDeadline) -> Result<PoolFileKey, CustodyError> {
        self.expect(Class::LocalPoolKey)?;
        pool_key(&self.read_private(deadline)?)
    }

    /// The public registry through the common parser and the closed profile.
    pub fn verification_registry(
        &self,
        deadline: StageDeadline,
    ) -> Result<Vec<VerificationKey>, CustodyError> {
        self.expect(Class::VerificationRegistry)?;
        registry(&super::read_exact(&self.file, self.bytes, deadline)?)
    }

    /// Class-specific syntax and, with the offered descriptor, every field it advertises.
    /// Digest-pinned bytes are compared separately by the content check.
    pub(super) fn check_profile(
        &self,
        offered: Option<&Descriptor>,
        deadline: StageDeadline,
    ) -> Result<(), CustodyError> {
        let mismatch = || refuse("native artifact differs from its advertised descriptor");
        match (self.class, offered) {
            (Class::Signer(_), offered) => {
                let signer = self.evidence_signer(deadline)?;
                if let Some(Descriptor::Signer { public, role, .. }) = offered {
                    if *public.as_array() != signer.public_key() || *role != signer.role {
                        return Err(mismatch());
                    }
                }
            }
            (
                Class::TransitionServerKey | Class::TransitionClientKey | Class::DaemonApiKey,
                offered,
            ) => {
                let key = self.tls_private_key(deadline)?;
                if let Some(
                    Descriptor::TransitionServerKey { spki, .. }
                    | Descriptor::TransitionClientKey { spki, .. }
                    | Descriptor::DaemonApiKey { spki, .. },
                ) = offered
                {
                    if key.spki != *spki {
                        return Err(mismatch());
                    }
                }
            }
            (Class::Plan, _) => {
                decode::<Plan>(&super::read_exact(&self.file, self.bytes, deadline)?)
                    .map_err(|_| refuse("invalid native plan record"))?;
            }
            (Class::ContinuationBearer, _) => drop(self.continuation_bearer(deadline)?),
            (Class::BackupS3Pair, _) => drop(self.backup_s3(deadline)?),
            (Class::LocalPoolKey, offered) => {
                let key = self.pool_file_key(deadline)?;
                if let Some(Descriptor::LocalPoolKey { key_id, .. }) = offered {
                    if key.id != *key_id {
                        return Err(mismatch());
                    }
                }
            }
            (Class::VerificationRegistry, _) => drop(self.verification_registry(deadline)?),
            (Class::TransitionServerCert, _) => {
                private_cert::parse(
                    &super::read_exact(&self.file, self.bytes, deadline)?,
                    Usage::Server,
                )
                .map_err(|_| refuse("invalid transition certificate"))?;
            }
            (Class::TransitionClientCert, _) => {
                private_cert::parse(
                    &super::read_exact(&self.file, self.bytes, deadline)?,
                    Usage::Client,
                )
                .map_err(|_| refuse("invalid transition certificate"))?;
            }
            _ => {}
        }
        Ok(())
    }
}
