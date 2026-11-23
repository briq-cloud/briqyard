use super::IMAGE_LIMIT;
use briqyard_api::execution::{
    ordinary_key,
    sealed::{
        canonical::MAX_MESSAGE_BYTES,
        custody::Resource,
        objects::Plan,
        prim::{HexDigest, KeyBytes, Uint},
        CodecError, Wire,
    },
};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashSet;

mod layout;
pub use layout::{Requirements, MAX_ASSET_RIGHTS};

const MAX_CERTIFICATE: u64 = 4096;
const MAX_TLS_KEY: u64 = 512;
pub(super) const MAX_BEARER: u64 = 4096;
pub(super) const SEED_BYTES: u64 = 32;
pub(super) const POOL_KEY_BYTES: u64 = 64;

/// A pool key's identifier: exactly 32 lowercase hexadecimal characters, as
/// `briqyard_api::poolkey::id` produces. It identifies a key and is never the key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PoolKeyId(String);

impl PoolKeyId {
    pub fn new(text: impl Into<String>) -> Result<Self, CodecError> {
        let text = text.into();
        if text.len() != 32 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(CodecError::Value("pool key id"));
        }
        Ok(Self(text))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for PoolKeyId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Member {
    Hi,
    He,
    Ni,
    Ng,
    Tr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Signer {
    Hk,
    Ak,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Plan,
    Launch,
    Grant,
    Inputs,
    Candidate,
    Config,
    CaptureLoad,
    Member(Member),
    Signer(Signer),
    TlsCert,
    TlsKey,
    OrdinaryAuthorityKey,
    VerificationRegistry,
    TransitionServerCert,
    TransitionServerKey,
    TransitionClientCert,
    TransitionClientKey,
    ContinuationBearer,
    DaemonApiCert,
    DaemonApiKey,
    BackupS3Pair,
    LocalPoolKey,
}

impl Class {
    pub(super) fn env(self) -> &'static str {
        match self {
            Self::Plan => "BRIQ_SEALED_PLAN_FD",
            Self::Launch => "BRIQ_SEALED_LAUNCH_FD",
            Self::Grant => "BRIQ_SEALED_GRANT_FD",
            Self::Inputs => "BRIQ_SEALED_INPUTS_FD",
            Self::Candidate => "BRIQ_SEALED_CANDIDATE_FD",
            Self::Config => "BRIQ_SEALED_CONFIG_FD",
            Self::CaptureLoad => "BRIQ_SEALED_CAPTURE_FD",
            Self::Member(Member::Hi) => "BRIQ_SEALED_MEMBER_HI_FD",
            Self::Member(Member::He) => "BRIQ_SEALED_MEMBER_HE_FD",
            Self::Member(Member::Ni) => "BRIQ_SEALED_MEMBER_NI_FD",
            Self::Member(Member::Ng) => "BRIQ_SEALED_MEMBER_NG_FD",
            Self::Member(Member::Tr) => "BRIQ_SEALED_MEMBER_TR_FD",
            Self::Signer(Signer::Hk) => "BRIQ_SEALED_SIGNER_HK_FD",
            Self::Signer(Signer::Ak) => "BRIQ_SEALED_SIGNER_AK_FD",
            Self::TlsCert => "BRIQ_SEALED_TLS_CERT_FD",
            Self::TlsKey => "BRIQ_SEALED_TLS_KEY_FD",
            Self::OrdinaryAuthorityKey => ordinary_key::FD_ENV,
            Self::VerificationRegistry => "BRIQ_SEALED_VERIFICATION_REGISTRY_FD",
            Self::TransitionServerCert => "BRIQ_SEALED_TRANSITION_SERVER_CERT_FD",
            Self::TransitionServerKey => "BRIQ_SEALED_TRANSITION_SERVER_KEY_FD",
            Self::TransitionClientCert => "BRIQ_SEALED_TRANSITION_CLIENT_CERT_FD",
            Self::TransitionClientKey => "BRIQ_SEALED_TRANSITION_CLIENT_KEY_FD",
            Self::ContinuationBearer => "BRIQ_SEALED_CONTINUATION_BEARER_FD",
            Self::DaemonApiCert => "BRIQ_SEALED_DAEMON_API_CERT_FD",
            Self::DaemonApiKey => "BRIQ_SEALED_DAEMON_API_KEY_FD",
            Self::BackupS3Pair => "BRIQ_SEALED_BACKUP_S3_PAIR_FD",
            Self::LocalPoolKey => "BRIQ_SEALED_LOCAL_POOL_KEY_FD",
        }
    }

    /// Payloads that only a typed, narrowly validating accessor may read. The generic
    /// bounded read refuses them, so no raw buffer of a secret ever leaves a descriptor.
    pub(super) fn is_secret(self) -> bool {
        matches!(
            self,
            Self::OrdinaryAuthorityKey
                | Self::Signer(_)
                | Self::TransitionServerKey
                | Self::TransitionClientKey
                | Self::DaemonApiKey
                | Self::ContinuationBearer
                | Self::BackupS3Pair
                | Self::LocalPoolKey
        )
    }

    pub(super) fn accepts(self, bytes: u64) -> bool {
        match self {
            Self::Candidate => (1..=IMAGE_LIMIT).contains(&bytes),
            Self::OrdinaryAuthorityKey => bytes == ordinary_key::PKCS8_BYTES as u64,
            Self::Signer(_) => bytes == SEED_BYTES,
            Self::LocalPoolKey => bytes == POOL_KEY_BYTES,
            Self::ContinuationBearer => (1..=MAX_BEARER).contains(&bytes),
            Self::TransitionServerCert | Self::TransitionClientCert => {
                (1..=MAX_CERTIFICATE).contains(&bytes)
            }
            Self::TransitionServerKey | Self::TransitionClientKey | Self::DaemonApiKey => {
                (1..=MAX_TLS_KEY).contains(&bytes)
            }
            _ => (1..=MAX_MESSAGE_BYTES as u64).contains(&bytes),
        }
    }

    pub(super) fn mode(self) -> u32 {
        if self == Self::Candidate {
            0o555
        } else {
            0o400
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "class", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Descriptor {
    Plan {
        bytes: Uint,
        digest: HexDigest,
    },
    Launch {
        bytes: Uint,
        digest: HexDigest,
    },
    Grant {
        bytes: Uint,
        digest: HexDigest,
    },
    Inputs {
        bytes: Uint,
        digest: HexDigest,
    },
    Candidate {
        bytes: Uint,
        digest: HexDigest,
    },
    Config {
        bytes: Uint,
        digest: HexDigest,
    },
    CaptureLoad {
        bytes: Uint,
        digest: HexDigest,
    },
    Member {
        bytes: Uint,
        member: Member,
        digest: HexDigest,
        member_hash: HexDigest,
    },
    Signer {
        bytes: Uint,
        role: Signer,
        public: KeyBytes,
    },
    TlsCert {
        bytes: Uint,
        digest: HexDigest,
    },
    TlsKey {
        bytes: Uint,
        digest: HexDigest,
    },
    OrdinaryAuthorityKey {
        bytes: Uint,
        public: KeyBytes,
    },
    VerificationRegistry {
        bytes: Uint,
        digest: HexDigest,
    },
    TransitionServerCert {
        bytes: Uint,
        digest: HexDigest,
    },
    TransitionServerKey {
        bytes: Uint,
        spki: HexDigest,
    },
    TransitionClientCert {
        bytes: Uint,
        digest: HexDigest,
    },
    TransitionClientKey {
        bytes: Uint,
        spki: HexDigest,
    },
    ContinuationBearer {
        bytes: Uint,
        digest: HexDigest,
    },
    DaemonApiCert {
        bytes: Uint,
        digest: HexDigest,
    },
    DaemonApiKey {
        bytes: Uint,
        spki: HexDigest,
    },
    BackupS3Pair {
        bytes: Uint,
        digest: HexDigest,
    },
    LocalPoolKey {
        bytes: Uint,
        key_id: PoolKeyId,
    },
}

impl Descriptor {
    pub fn class(&self) -> Class {
        match self {
            Self::Plan { .. } => Class::Plan,
            Self::Launch { .. } => Class::Launch,
            Self::Grant { .. } => Class::Grant,
            Self::Inputs { .. } => Class::Inputs,
            Self::Candidate { .. } => Class::Candidate,
            Self::Config { .. } => Class::Config,
            Self::CaptureLoad { .. } => Class::CaptureLoad,
            Self::Member { member, .. } => Class::Member(*member),
            Self::Signer { role, .. } => Class::Signer(*role),
            Self::TlsCert { .. } => Class::TlsCert,
            Self::TlsKey { .. } => Class::TlsKey,
            Self::OrdinaryAuthorityKey { .. } => Class::OrdinaryAuthorityKey,
            Self::VerificationRegistry { .. } => Class::VerificationRegistry,
            Self::TransitionServerCert { .. } => Class::TransitionServerCert,
            Self::TransitionServerKey { .. } => Class::TransitionServerKey,
            Self::TransitionClientCert { .. } => Class::TransitionClientCert,
            Self::TransitionClientKey { .. } => Class::TransitionClientKey,
            Self::ContinuationBearer { .. } => Class::ContinuationBearer,
            Self::DaemonApiCert { .. } => Class::DaemonApiCert,
            Self::DaemonApiKey { .. } => Class::DaemonApiKey,
            Self::BackupS3Pair { .. } => Class::BackupS3Pair,
            Self::LocalPoolKey { .. } => Class::LocalPoolKey,
        }
    }

    pub(super) fn integrity(&self) -> (u64, Option<&HexDigest>) {
        match self {
            Self::Plan { bytes, digest }
            | Self::Launch { bytes, digest }
            | Self::Grant { bytes, digest }
            | Self::Inputs { bytes, digest }
            | Self::Candidate { bytes, digest }
            | Self::Config { bytes, digest }
            | Self::CaptureLoad { bytes, digest }
            | Self::Member { bytes, digest, .. }
            | Self::TlsCert { bytes, digest }
            | Self::TlsKey { bytes, digest }
            | Self::VerificationRegistry { bytes, digest }
            | Self::TransitionServerCert { bytes, digest }
            | Self::TransitionClientCert { bytes, digest }
            | Self::ContinuationBearer { bytes, digest }
            | Self::DaemonApiCert { bytes, digest }
            | Self::BackupS3Pair { bytes, digest } => (bytes.get(), Some(digest)),
            Self::Signer { bytes, .. }
            | Self::OrdinaryAuthorityKey { bytes, .. }
            | Self::TransitionServerKey { bytes, .. }
            | Self::TransitionClientKey { bytes, .. }
            | Self::DaemonApiKey { bytes, .. }
            | Self::LocalPoolKey { bytes, .. } => (bytes.get(), None),
        }
    }
}

#[derive(Deserialize, Serialize)]
enum Format {
    #[serde(rename = "native.prepare/v3")]
    Prepare,
    #[serde(rename = "native.assets/v3")]
    Assets,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Prepare {
    format: Format,
}

impl Wire for Prepare {
    fn validate(&self) -> Result<(), CodecError> {
        if !matches!(self.format, Format::Prepare) {
            return Err(CodecError::Value("native prepare format"));
        }
        Ok(())
    }
}

pub fn prepare_packet() -> &'static [u8] {
    br#"{"format":"native.prepare/v3"}"#
}

pub fn check_prepare(bytes: &[u8]) -> Result<(), CodecError> {
    briqyard_api::execution::sealed::decode::<Prepare>(bytes).map(|_| ())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetOffer {
    format: Format,
    pub(super) assets: Vec<Descriptor>,
}

impl Wire for AssetOffer {
    fn validate(&self) -> Result<(), CodecError> {
        if !matches!(self.format, Format::Assets) {
            return Err(CodecError::Value("native assets format"));
        }
        if self.assets.len() > MAX_ASSET_RIGHTS
            || self
                .assets
                .iter()
                .any(|asset| !asset.class().accepts(asset.integrity().0))
        {
            return Err(CodecError::Value("native asset length"));
        }
        Ok(())
    }
}

impl AssetOffer {
    pub fn decode(requirements: Requirements, bytes: &[u8]) -> Result<Self, CodecError> {
        let offer: Self = briqyard_api::execution::sealed::decode(bytes)?;
        offer.check_resource(requirements)?;
        Ok(offer)
    }

    pub fn encode(
        requirements: Requirements,
        assets: Vec<Descriptor>,
    ) -> Result<Vec<u8>, CodecError> {
        let offer = Self {
            format: Format::Assets,
            assets,
        };
        offer.validate()?;
        offer.check_resource(requirements)?;
        briqyard_api::execution::sealed::encode(&offer)
    }

    pub fn descriptors(&self) -> &[Descriptor] {
        &self.assets
    }

    /// The exact class sequence of the resource and the caller's typed requirements; there is
    /// no negotiation, omission or extra right.
    pub(super) fn check_resource(&self, requirements: Requirements) -> Result<(), CodecError> {
        if !self
            .assets
            .iter()
            .map(Descriptor::class)
            .eq(requirements.classes())
        {
            return Err(CodecError::Value("native asset class order or role"));
        }
        Ok(())
    }

    /// Compare metadata with an independently validated plan; this does not validate the plan,
    /// member envelopes/values, signer handle or either launch-grant signature.
    pub fn check_plan_pins(
        &self,
        requirements: Requirements,
        plan: &Plan,
    ) -> Result<(), CodecError> {
        self.check_resource(requirements)?;
        let plan_digest = briqyard_api::execution::sealed::h(plan)?;
        let members = &plan.new;
        let transition = members
            .tr
            .as_ref()
            .ok_or(CodecError::Value("native transition member pin"))?;
        if [
            &members.hi,
            &members.he,
            &members.ni,
            &members.ng,
            transition,
        ]
        .into_iter()
        .collect::<HashSet<_>>()
        .len()
            != 5
        {
            return Err(CodecError::Value("duplicate native member pin"));
        }
        let image = match requirements.resource() {
            Resource::Daemon => &plan.next_d,
            Resource::Authority => &plan.next_a,
        };
        for asset in &self.assets {
            let valid = match asset {
                Descriptor::Plan { digest, .. } => digest == &plan_digest,
                Descriptor::Inputs { digest, .. } => digest == &plan.inputs,
                Descriptor::Candidate { digest, .. } => digest == image,
                Descriptor::Member {
                    member,
                    member_hash,
                    ..
                } => {
                    Some(member_hash)
                        == match member {
                            Member::Hi => Some(&plan.new.hi),
                            Member::He => Some(&plan.new.he),
                            Member::Ni => Some(&plan.new.ni),
                            Member::Ng => Some(&plan.new.ng),
                            Member::Tr => plan.new.tr.as_ref(),
                        }
                }
                Descriptor::Signer { role, public, .. } => {
                    public
                        == match role {
                            Signer::Hk => &plan.hk,
                            Signer::Ak => &plan.ak,
                        }
                }
                Descriptor::OrdinaryAuthorityKey { public, .. } => {
                    public == &plan.ordinary_key && public.as_array() == &plan.pre_record.public_key
                }
                _ => true,
            };
            if !valid {
                return Err(CodecError::Value("native asset plan pin"));
            }
        }
        Ok(())
    }
}
