//! The v3.3 suffix of a sealed startup: typed acquisition of the signer, registry and
//! private credentials, and the pins that bind them to the frozen closure. Every accessor
//! derives from the actual immutable bytes; an advertised field is only ever compared.

use super::SealedInput;
use crate::execution_custody::artifacts::{
    BackupS3Credentials, Class, ContinuationBearer, Descriptor, EvidenceSigner, FrozenArtifact,
    PoolFileKey, PoolKeyId, Requirements, Signer as AssetSigner, TlsPrivateKey,
};
use crate::execution_custody::{CustodyError, StageDeadline};
use briqyard_api::execution::{
    private_cert::{self, Name, Pair, Usage},
    sealed::{
        custody::Resource,
        prim::HexDigest,
        sig::{PinnedKey, Role, Signer},
    },
    KeyRole, VerificationKey,
};

/// The closure pins of this resource's own suffix, from the independently validated manifest.
/// Which options are present is the closure's own statement: they must equal the requirements
/// the offer was bound with, never be guessed from the descriptors.
pub struct SuffixPins {
    pub registry: HexDigest,
    pub server: Pair,
    pub server_name: Name,
    pub client: Pair,
    pub continuation: Option<HexDigest>,
    pub admin_tls: Option<Pair>,
    pub backup_s3: Option<HexDigest>,
    pub file_key: Option<PoolKeyId>,
}

fn refuse(reason: &'static str) -> CustodyError {
    CustodyError::Protocol(reason)
}

impl SealedInput {
    fn suffix(&self, class: Class) -> Result<&FrozenArtifact, CustodyError> {
        self.assets
            .artifact(class)
            .ok_or(refuse("missing startup suffix artifact"))
    }

    fn descriptor(&self, class: Class) -> Result<&Descriptor, CustodyError> {
        self.assets
            .offer()
            .descriptors()
            .iter()
            .find(|descriptor| descriptor.class() == class)
            .ok_or(refuse("missing startup suffix descriptor"))
    }

    fn digest(&self, class: Class) -> Result<&HexDigest, CustodyError> {
        match self.descriptor(class)? {
            Descriptor::VerificationRegistry { digest, .. }
            | Descriptor::TransitionServerCert { digest, .. }
            | Descriptor::TransitionClientCert { digest, .. }
            | Descriptor::ContinuationBearer { digest, .. }
            | Descriptor::DaemonApiCert { digest, .. }
            | Descriptor::BackupS3Pair { digest, .. } => Ok(digest),
            _ => Err(refuse("suffix class without a byte digest")),
        }
    }

    /// The signer of this resource (Hk for the daemon, Ak for the authority), from the actual
    /// seed. Its derived public key equals the advertised one and the independently pinned
    /// Plan key, which must itself be a strict Ed25519 point. Possession is no permission.
    pub fn evidence_signer(&self, deadline: StageDeadline) -> Result<EvidenceSigner, CustodyError> {
        let (class, role, pin) = match self.assets.requirements().resource() {
            Resource::Daemon => (AssetSigner::Hk, Role::Hk, &self.plan.hk),
            Resource::Authority => (AssetSigner::Ak, Role::Ak, &self.plan.ak),
        };
        let pinned = PinnedKey::new(role, *pin.as_array())
            .map_err(|_| refuse("invalid startup evidence key pin"))?;
        let signer = self.suffix(Class::Signer(class))?.evidence_signer(deadline)?;
        let advertised = match self.descriptor(Class::Signer(class))? {
            Descriptor::Signer { public, .. } => public,
            _ => return Err(refuse("missing startup signer descriptor")),
        };
        if signer.public_key() != *pinned.raw() || signer.public_key() != *advertised.as_array() {
            return Err(refuse("startup evidence signer public binding"));
        }
        Ok(signer)
    }

    /// The public registry through the common parser and closed profile, whose only authority
    /// entry is exactly the registered predecessor of the Plan.
    pub fn verification_registry(
        &self,
        deadline: StageDeadline,
    ) -> Result<Vec<VerificationKey>, CustodyError> {
        let keys = self
            .suffix(Class::VerificationRegistry)?
            .verification_registry(deadline)?;
        let record = &self.plan.pre_record;
        let bound = keys.iter().any(|key| {
            key.role == KeyRole::Authority
                && key.kid == record.key_id.as_str()
                && key.authority.as_deref() == Some(record.authority.as_str())
                && key.public_key == record.public_key
        });
        if !bound {
            return Err(refuse("startup registry predecessor binding"));
        }
        Ok(keys)
    }

    fn tls_key(
        &self,
        class: Class,
        deadline: StageDeadline,
    ) -> Result<TlsPrivateKey, CustodyError> {
        let key = self.suffix(class)?.tls_private_key(deadline)?;
        match self.descriptor(class)? {
            Descriptor::TransitionServerKey { spki, .. }
            | Descriptor::TransitionClientKey { spki, .. }
            | Descriptor::DaemonApiKey { spki, .. }
                if spki == key.spki() =>
            {
                Ok(key)
            }
            _ => Err(refuse("startup TLS key SPKI binding")),
        }
    }

    pub fn transition_server_key(
        &self,
        deadline: StageDeadline,
    ) -> Result<TlsPrivateKey, CustodyError> {
        self.tls_key(Class::TransitionServerKey, deadline)
    }

    pub fn transition_client_key(
        &self,
        deadline: StageDeadline,
    ) -> Result<TlsPrivateKey, CustodyError> {
        self.tls_key(Class::TransitionClientKey, deadline)
    }

    pub fn daemon_api_key(&self, deadline: StageDeadline) -> Result<TlsPrivateKey, CustodyError> {
        self.tls_key(Class::DaemonApiKey, deadline)
    }

    pub fn continuation_bearer(
        &self,
        deadline: StageDeadline,
    ) -> Result<ContinuationBearer, CustodyError> {
        self.suffix(Class::ContinuationBearer)?
            .continuation_bearer(deadline)
    }

    pub fn backup_s3(&self, deadline: StageDeadline) -> Result<BackupS3Credentials, CustodyError> {
        self.suffix(Class::BackupS3Pair)?.backup_s3(deadline)
    }

    pub fn pool_file_key(&self, deadline: StageDeadline) -> Result<PoolFileKey, CustodyError> {
        let key = self.suffix(Class::LocalPoolKey)?.pool_file_key(deadline)?;
        match self.descriptor(Class::LocalPoolKey)? {
            Descriptor::LocalPoolKey { key_id, .. } if key_id == key.id() => Ok(key),
            _ => Err(refuse("startup pool key id binding")),
        }
    }

    /// Everything that needs only the Plan: run once at decode so a bundle with a wrong seed
    /// or registry is refused before any consumer sees it.
    pub(super) fn check_suffix_bindings(&self, deadline: StageDeadline) -> Result<(), CustodyError> {
        self.evidence_signer(deadline)?;
        self.verification_registry(deadline)?;
        Ok(())
    }

    /// Compare the bound bytes with the closure's pins. Certificate validity needs the
    /// qualified clock and is checked where the identity is consumed.
    pub fn check_suffix_pins(&self, pins: &SuffixPins) -> Result<(), CustodyError> {
        let (admin_tls, backup_s3, file_key) = match self.assets.requirements() {
            Requirements::Daemon {
                admin_tls,
                backup_s3,
                file_key,
            } => (admin_tls, backup_s3, file_key),
            Requirements::Authority => (false, false, false),
        };
        if pins.admin_tls.is_some() != admin_tls
            || pins.backup_s3.is_some() != backup_s3
            || pins.file_key.is_some() != file_key
            || pins.continuation.is_some()
                != (self.assets.requirements().resource() == Resource::Authority)
        {
            return Err(refuse("startup suffix pins disagree with the requirements"));
        }
        let same = |class, expected: &HexDigest| -> Result<(), CustodyError> {
            if self.digest(class)? == expected {
                Ok(())
            } else {
                Err(refuse("startup suffix pin"))
            }
        };
        same(Class::VerificationRegistry, &pins.registry)?;
        if let Some(digest) = &pins.continuation {
            same(Class::ContinuationBearer, digest)?;
        }
        if let Some(digest) = &pins.backup_s3 {
            same(Class::BackupS3Pair, digest)?;
        }
        if let Some(id) = &pins.file_key {
            match self.descriptor(Class::LocalPoolKey)? {
                Descriptor::LocalPoolKey { key_id, .. } if key_id == id => {}
                _ => return Err(refuse("startup suffix pin")),
            }
        }
        let identity = |cert, key, pair: &Pair, usage| -> Result<_, CustodyError> {
            let artifact = self.suffix(cert)?;
            let der = artifact
                .read_small(StageDeadline::frame("startup identity pins"))?;
            let leaf = private_cert::verify(&der, pair, usage)
                .map_err(|_| refuse("startup transition identity pin"))?;
            match self.descriptor(key)? {
                Descriptor::TransitionServerKey { spki, .. }
                | Descriptor::TransitionClientKey { spki, .. }
                    if *spki == pair.spki =>
                {
                    Ok(leaf)
                }
                _ => Err(refuse("startup transition identity pin")),
            }
        };
        let server = identity(
            Class::TransitionServerCert,
            Class::TransitionServerKey,
            &pins.server,
            Usage::Server,
        )?;
        identity(
            Class::TransitionClientCert,
            Class::TransitionClientKey,
            &pins.client,
            Usage::Client,
        )?;
        if server.name != pins.server_name || pins.server.spki == pins.client.spki {
            return Err(refuse("startup transition identity name or reuse"));
        }
        if let Some(pair) = &pins.admin_tls {
            same(Class::DaemonApiCert, &pair.leaf)?;
            match self.descriptor(Class::DaemonApiKey)? {
                Descriptor::DaemonApiKey { spki, .. } if *spki == pair.spki => {}
                _ => return Err(refuse("startup suffix pin")),
            }
        }
        Ok(())
    }
}
