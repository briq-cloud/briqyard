//! Synthetic, valid payloads for every native asset class. Nothing here is a production
//! credential: keys and certificates are generated per test process.

use super::super::*;
use briqyard_api::execution::sealed::custody::Resource;
use briqyard_api::execution::{
    private_cert::{self, Name, Usage},
    sealed::prim::KeyBytes,
};
use rcgen::{
    date_time_ymd, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType,
    PKCS_ECDSA_P256_SHA256,
};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::sync::OnceLock;

pub(crate) fn source(bytes: &[u8]) -> (tempfile::NamedTempFile, File) {
    let mut temporary = tempfile::NamedTempFile::new().unwrap();
    temporary.write_all(bytes).unwrap();
    let file = File::open(temporary.path()).unwrap();
    (temporary, file)
}

pub(crate) fn freeze_fixture_file(
    file: &File,
    class: Class,
    bytes: &[u8],
    deadline: StageDeadline,
) -> Result<FrozenArtifact, CustodyError> {
    FrozenArtifact::freeze(
        file,
        file.metadata().unwrap().uid(),
        class,
        bytes.len() as u64,
        &HexDigest::of(bytes),
        deadline,
    )
}

pub(crate) fn freeze_fixture(class: Class, bytes: &[u8]) -> FrozenArtifact {
    let (_temporary, file) = source(bytes);
    freeze_fixture_file(&file, class, bytes, StageDeadline::frame("fixture freeze")).unwrap()
}

pub(crate) const SERVER_NAME: &str = "h-1.peer.test";

/// One generated certificate and its PKCS#8 key.
#[derive(Clone)]
pub(crate) struct Identity {
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
}

pub(crate) fn issue(name: &Name, usage: Option<Usage>) -> Identity {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![match name {
        Name::Dns(text) => SanType::DnsName(text.as_str().try_into().unwrap()),
        Name::Ip(ip) => SanType::IpAddress(*ip),
    }];
    if let Some(usage) = usage {
        params.extended_key_usages = vec![match usage {
            Usage::Server => ExtendedKeyUsagePurpose::ServerAuth,
            Usage::Client => ExtendedKeyUsagePurpose::ClientAuth,
        }];
        params.is_ca = IsCa::NoCa;
    }
    params.not_before = date_time_ymd(2026, 1, 1);
    params.not_after = date_time_ymd(2030, 1, 1);
    let cert = params.self_signed(&key).unwrap();
    Identity {
        cert: cert.der().to_vec(),
        key: key.serialize_der(),
    }
}

pub(crate) struct Identities {
    pub server: Identity,
    pub client: Identity,
    pub daemon_api: Identity,
}

pub(crate) fn identities() -> &'static Identities {
    static IDENTITIES: OnceLock<Identities> = OnceLock::new();
    IDENTITIES.get_or_init(|| Identities {
        server: issue(&Name::dns(SERVER_NAME).unwrap(), Some(Usage::Server)),
        client: issue(&Name::dns("a-1.peer.test").unwrap(), Some(Usage::Client)),
        daemon_api: issue(&Name::dns("api.host.test").unwrap(), None),
    })
}

pub(crate) fn spki(pkcs8: &[u8]) -> HexDigest {
    private_cert::key_spki_digest(pkcs8).unwrap()
}

pub(crate) fn b64(text: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(text)
}

pub(crate) const POOL_KEY: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
pub(crate) const BEARER: &[u8] = b"continuation~Bearer.0123456789!";

pub(crate) fn s3_pair() -> Vec<u8> {
    format!(
        r#"{{"access":"{}","secret":"{}"}}"#,
        b64(b"AKIAFIXTUREACCESS"),
        b64(b"fixture/secret+key")
    )
    .into_bytes()
}

pub(crate) fn evidence_seed(role: Signer) -> [u8; 32] {
    match role {
        Signer::Hk => [0x48; 32],
        Signer::Ak => [0x41; 32],
    }
}

pub(crate) fn public_of(seed: &[u8; 32]) -> KeyBytes {
    let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
    KeyBytes::from_array(
        ring::signature::KeyPair::public_key(&pair)
            .as_ref()
            .try_into()
            .unwrap(),
    )
}

pub(crate) fn evidence_public(role: Signer) -> KeyBytes {
    public_of(&evidence_seed(role))
}

pub(crate) fn registry_json(authority: (&str, &str, [u8; 32])) -> Vec<u8> {
    let central = |seed: u8| -> Vec<u8> {
        let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
        ring::signature::KeyPair::public_key(&pair)
            .as_ref()
            .to_vec()
    };
    serde_json::to_vec(&serde_json::json!([
        {"kid": "central-1", "role": "central", "issuer": "central", "authority": null,
         "public_key": central(0x11)},
        {"kid": "central-2", "role": "central", "issuer": "central", "authority": null,
         "public_key": central(0x12)},
        {"kid": authority.0, "role": "authority", "issuer": "authority",
         "authority": authority.1, "public_key": authority.2.to_vec()},
    ]))
    .unwrap()
}

pub(crate) fn default_registry() -> Vec<u8> {
    registry_json(("k", "auth", *key_public(KEY_SEED).as_array()))
}

pub(crate) fn requirements(resource: Resource) -> Requirements {
    match resource {
        Resource::Daemon => Requirements::Daemon {
            admin_tls: false,
            backup_s3: false,
            file_key: false,
        },
        Resource::Authority => Requirements::Authority,
    }
}

pub(crate) fn classes(resource: Resource) -> Vec<Class> {
    requirements(resource).classes()
}

pub(crate) const KEY_SEED: u8 = 5;

pub(crate) fn key_profile(seed: u8) -> Vec<u8> {
    let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
    let mut bytes = hex::decode("3051020101300506032b657004220420").unwrap();
    bytes.extend([seed; 32]);
    bytes.extend([0x81, 0x21, 0x00]);
    bytes.extend(ring::signature::KeyPair::public_key(&pair).as_ref());
    assert_eq!(bytes.len(), 83);
    bytes
}

pub(crate) fn key_public(seed: u8) -> KeyBytes {
    KeyBytes::from_array(key_profile(seed)[51..].try_into().unwrap())
}

/// The valid payload of a class; generic prefix classes are distinct synthetic text by index.
/// A canonical Plan that passes its own validation: distinct keys, distinct members, and the
/// ordinary key equal to the registered predecessor's. Nothing here authorizes anything.
pub(crate) fn plan_bytes() -> Vec<u8> {
    use briqyard_api::execution::sealed::{
        encode,
        objects::{Members, Plan, Proc, Reg, X},
        prim::{BootId, Build, Env, HexDigest, Ident, KeyBytes, PosInt},
    };
    let id = |text| Ident::new(text).unwrap();
    let proc = |pid| Proc {
        boot: BootId::new("00000000-0000-4000-8000-000000000004").unwrap(),
        pid: PosInt::new(pid).unwrap(),
        start: PosInt::new(912).unwrap(),
        exe: HexDigest::from_raw([0x33; 32]),
        build: Build::new("fence-3").unwrap(),
    };
    let members = |base: u8| Members {
        hi: HexDigest::from_raw([base; 32]),
        he: HexDigest::from_raw([base + 1; 32]),
        ni: HexDigest::from_raw([base + 2; 32]),
        ng: HexDigest::from_raw([base + 3; 32]),
        tr: Some(HexDigest::from_raw([base + 4; 32])),
    };
    let x = X {
        aud: Env::Staging,
        host: id("host.test"),
        op: HexDigest::from_raw([0; 32]),
        serial: PosInt::new(1).unwrap(),
    };
    let key = |byte: u8| KeyBytes::from_array([byte; 32]);
    let pre_record = Reg {
        authority: id("auth"),
        epoch: id("ep"),
        key_id: id("k"),
        public_key: [5; 32],
        host_instance: id("hi"),
        generation: PosInt::new(2).unwrap(),
    };
    encode(&Plan {
        pre: pre_record.ctx(&x.host),
        x,
        registered: id("hi"),
        pre_record,
        pre_intent: id("original.intent"),
        pre_d: proc(12),
        pre_a: proc(13),
        next_d: HexDigest::from_raw([0x61; 32]),
        next_a: HexDigest::from_raw([0x62; 32]),
        dbuild: Build::new("next-daemon").unwrap(),
        abuild: Build::new("next-authority").unwrap(),
        old: members(80),
        new: members(0),
        hk: key(1),
        ak: key(2),
        bk: key(3),
        rk: key(4),
        ordinary_key: key(5),
        exception: HexDigest::from_raw([0x63; 32]),
        inputs: HexDigest::from_raw([0x64; 32]),
    })
    .unwrap()
}

pub(crate) fn payload(class: Class, index: usize) -> Vec<u8> {
    let identities = identities();
    match class {
        Class::OrdinaryAuthorityKey => key_profile(KEY_SEED),
        Class::Signer(role) => evidence_seed(role).to_vec(),
        Class::Plan => plan_bytes(),
        Class::VerificationRegistry => default_registry(),
        Class::TransitionServerCert => identities.server.cert.clone(),
        Class::TransitionServerKey => identities.server.key.clone(),
        Class::TransitionClientCert => identities.client.cert.clone(),
        Class::TransitionClientKey => identities.client.key.clone(),
        Class::ContinuationBearer => BEARER.to_vec(),
        Class::DaemonApiCert => identities.daemon_api.cert.clone(),
        Class::DaemonApiKey => identities.daemon_api.key.clone(),
        Class::BackupS3Pair => s3_pair(),
        Class::LocalPoolKey => POOL_KEY.as_bytes().to_vec(),
        _ => format!("synthetic fixture {index}").into_bytes(),
    }
}

/// Stage a payload the way its class's real producer does: private classes from memory with
/// their advertised field checked, the rest from a trusted read-only source.
pub(crate) fn stage(class: Class, bytes: &[u8]) -> FrozenArtifact {
    let deadline = StageDeadline::frame("fixture stage");
    match class {
        Class::OrdinaryAuthorityKey => {
            FrozenArtifact::freeze_ordinary_key(bytes, &key_public(KEY_SEED), deadline).unwrap()
        }
        Class::Signer(role) => {
            let seed: [u8; 32] = bytes.try_into().unwrap();
            FrozenArtifact::freeze_signer(bytes, role, &public_of(&seed), deadline).unwrap()
        }
        Class::TransitionServerKey | Class::TransitionClientKey | Class::DaemonApiKey => {
            FrozenArtifact::freeze_tls_key(class, bytes, &spki(bytes), deadline).unwrap()
        }
        Class::LocalPoolKey => FrozenArtifact::freeze_pool_key(
            bytes,
            &PoolKeyId::new(briqyard_api::poolkey::id(POOL_KEY).unwrap()).unwrap(),
            deadline,
        )
        .unwrap(),
        _ => freeze_fixture(class, bytes),
    }
}

pub(crate) fn descriptor_value(class: Class, bytes: &[u8]) -> serde_json::Value {
    let length = bytes.len();
    let digest = HexDigest::of(bytes);
    let literal = match class {
        Class::Plan => "plan",
        Class::Launch => "launch",
        Class::Grant => "grant",
        Class::Inputs => "inputs",
        Class::Candidate => "candidate",
        Class::Config => "config",
        Class::CaptureLoad => "capture-load",
        Class::Member(member) => {
            return serde_json::json!({
                "class": "member", "bytes": length, "digest": digest,
                "member": member, "member_hash": HexDigest::of(b"synthetic member hash"),
            })
        }
        Class::Signer(role) => {
            return serde_json::json!({
                "class": "signer", "bytes": length, "role": role, "public": evidence_public(role),
            })
        }
        Class::TlsCert => "tls-cert",
        Class::TlsKey => "tls-key",
        Class::OrdinaryAuthorityKey => {
            return serde_json::json!({
                "class": "ordinary-authority-key", "bytes": length, "public": key_public(KEY_SEED),
            })
        }
        Class::VerificationRegistry => "verification-registry",
        Class::TransitionServerCert => "transition-server-cert",
        Class::TransitionClientCert => "transition-client-cert",
        Class::ContinuationBearer => "continuation-bearer",
        Class::DaemonApiCert => "daemon-api-cert",
        Class::BackupS3Pair => "backup-s3-pair",
        Class::TransitionServerKey | Class::TransitionClientKey | Class::DaemonApiKey => {
            let name = match class {
                Class::TransitionServerKey => "transition-server-key",
                Class::TransitionClientKey => "transition-client-key",
                _ => "daemon-api-key",
            };
            return serde_json::json!({"class": name, "bytes": length, "spki": spki(bytes)});
        }
        Class::LocalPoolKey => {
            return serde_json::json!({
                "class": "local-pool-key", "bytes": length,
                "key_id": briqyard_api::poolkey::id(POOL_KEY).unwrap(),
            })
        }
    };
    serde_json::json!({"class": literal, "bytes": length, "digest": digest})
}

pub(crate) fn envelope(assets: Vec<serde_json::Value>) -> Vec<u8> {
    briqyard_api::execution::sealed::encode(&serde_json::json!({
        "format": "native.assets/v3", "assets": assets,
    }))
    .unwrap()
}
