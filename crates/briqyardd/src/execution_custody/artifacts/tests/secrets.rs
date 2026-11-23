//! Content profiles of the v3 private classes: what each payload must be byte for byte, which
//! field it must prove, and that nothing outside a typed accessor can read it.

use super::*;
use briqyard_api::execution::{
    private_cert::{self, Name, Usage},
    sealed::{
        objects::{HostClockBody, Q},
        sig::{PinnedKey, Role, Sig, SigError, Signer as _, Tag},
    },
};
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    SanType, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ED25519,
};

fn deadline() -> StageDeadline {
    StageDeadline::frame("secret profile test")
}

fn from_file(class: Class, bytes: &[u8]) -> Result<FrozenArtifact, CustodyError> {
    let (_temporary, file) = source(bytes);
    freeze_fixture_file(&file, class, bytes, deadline())
}

fn protocol(result: Result<impl Sized, CustodyError>) -> &'static str {
    match result {
        Err(CustodyError::Protocol(reason)) => reason,
        Err(other) => panic!("not a protocol refusal: {other}"),
        Ok(_) => panic!("accepted"),
    }
}

#[test]
fn the_signer_is_exactly_thirty_two_raw_seed_octets_and_nothing_else() {
    let public = evidence_public(Signer::Hk);
    let seed = evidence_seed(Signer::Hk);
    let frozen = FrozenArtifact::freeze_signer(&seed, Signer::Hk, &public, deadline()).unwrap();
    assert_eq!(
        frozen.evidence_signer(deadline()).unwrap().public_key(),
        *public.as_array()
    );
    for bad in [
        &seed[..31],
        &[seed.as_slice(), &[0]].concat()[..],
        &[0; 64][..],
        &[][..],
    ] {
        assert_eq!(
            protocol(FrozenArtifact::freeze_signer(
                bad,
                Signer::Hk,
                &public,
                deadline()
            )),
            "evidence signer seed length"
        );
    }
    let ordinary = key_profile(KEY_SEED);
    assert_eq!(ordinary.len(), 83);
    assert!(
        FrozenArtifact::freeze_signer(&ordinary, Signer::Ak, &key_public(KEY_SEED), deadline())
            .is_err(),
        "the ordinary key's PKCS#8 form is not a seed"
    );
    assert!(
        FrozenArtifact::freeze_signer(
            &ordinary[16..48],
            Signer::Ak,
            &key_public(KEY_SEED),
            deadline()
        )
        .is_ok(),
        "the embedded seed alone is a seed; only its own derived public key may be advertised"
    );
    assert!(
        FrozenArtifact::freeze_ordinary_key(&seed, &public, deadline()).is_err(),
        "a raw seed is not the ordinary profile"
    );
    assert!(
        from_file(Class::Signer(Signer::Hk), &seed).is_err(),
        "never staged from a file"
    );
    assert_eq!(
        protocol(FrozenArtifact::freeze_signer(
            &seed,
            Signer::Hk,
            &evidence_public(Signer::Ak),
            deadline()
        )),
        "evidence signer differs from its advertised key"
    );
}

#[test]
fn a_seed_that_looks_printable_is_still_an_arbitrary_binary_seed() {
    let seed = *b"abcdefghijklmnopqrstuvwxyzABCDEF";
    let public = public_of(&seed);
    let frozen = FrozenArtifact::freeze_signer(&seed, Signer::Ak, &public, deadline()).unwrap();
    assert_eq!(
        frozen.evidence_signer(deadline()).unwrap().public_key(),
        *public.as_array()
    );
    let newline = [b'\n'; 32];
    assert!(
        FrozenArtifact::freeze_signer(&newline, Signer::Ak, &public_of(&newline), deadline())
            .is_ok()
    );
}

fn clock_body() -> HostClockBody {
    use briqyard_api::execution::sealed::{
        objects::{Proc, X},
        prim::{BootId, Build, Env, Ident, Nonce, PosInt, Uint},
    };
    let id = |text| Ident::new(text).unwrap();
    HostClockBody {
        q: Q {
            x: X {
                aud: Env::Staging,
                host: id("host.test"),
                op: HexDigest::from_raw([0; 32]),
                serial: PosInt::new(1).unwrap(),
            },
            nonce: Nonce::from_array([7; 32]),
        },
        plan: HexDigest::of(b"plan"),
        proc: Proc {
            boot: BootId::new("00000000-0000-4000-8000-000000000004").unwrap(),
            pid: PosInt::new(12).unwrap(),
            start: PosInt::new(912).unwrap(),
            exe: HexDigest::from_raw([0x33; 32]),
            build: Build::new("fence-3").unwrap(),
        },
        instance: id("hi"),
        now: Uint::new(1_900_000_000).unwrap(),
        uncertainty: Uint::new(1).unwrap(),
    }
}

#[test]
fn the_acquired_signer_produces_real_signatures_that_verify_only_under_its_pinned_key() {
    let hk = FrozenArtifact::freeze_signer(
        &evidence_seed(Signer::Hk),
        Signer::Hk,
        &evidence_public(Signer::Hk),
        deadline(),
    )
    .unwrap()
    .evidence_signer(deadline())
    .unwrap();
    let signed = Sig::sign(Tag::HostClock, clock_body(), &hk).unwrap();
    let pinned = PinnedKey::new(Role::Hk, *evidence_public(Signer::Hk).as_array()).unwrap();
    signed.verify(Tag::HostClock, &pinned).unwrap();
    let other = PinnedKey::new(Role::Hk, *evidence_public(Signer::Ak).as_array()).unwrap();
    assert_eq!(
        signed.verify(Tag::HostClock, &other),
        Err(SigError::KeyMismatch)
    );
    let wrong_role = PinnedKey::new(Role::Ak, *evidence_public(Signer::Hk).as_array()).unwrap();
    assert_eq!(
        signed.verify(Tag::HostClock, &wrong_role),
        Err(SigError::RoleNotPermitted)
    );
    let mut forged = signed.clone();
    forged.body.uncertainty = briqyard_api::execution::sealed::prim::Uint::new(2).unwrap();
    assert_eq!(
        forged.verify(Tag::HostClock, &pinned),
        Err(SigError::BadSignature)
    );
    assert!(!format!("{hk:?}").contains("48"), "no seed in Debug");
}

#[test]
fn a_small_order_or_noncanonical_public_key_is_refused_by_the_strict_pin() {
    let identity = {
        let mut point = [0u8; 32];
        point[0] = 1;
        point
    };
    let noncanonical = {
        let mut point = [0xff; 32];
        point[31] = 0x7f;
        point
    };
    for point in [identity, noncanonical] {
        assert!(PinnedKey::new(Role::Hk, point).is_err());
    }
    let registry = registry_json(("k", "auth", identity));
    assert_eq!(
        protocol(from_file(Class::VerificationRegistry, &registry)),
        "invalid verification registry"
    );
}

fn key_for(algorithm: &'static rcgen::SignatureAlgorithm) -> Vec<u8> {
    KeyPair::generate_for(algorithm).unwrap().serialize_der()
}

#[test]
fn a_tls_key_is_unencrypted_pkcs8_p256_with_its_spki_derived_from_the_actual_key() {
    let identities = identities();
    let key = &identities.server.key;
    let advertised = spki(key);
    let frozen =
        FrozenArtifact::freeze_tls_key(Class::TransitionServerKey, key, &advertised, deadline())
            .unwrap();
    assert_eq!(
        frozen.tls_private_key(deadline()).unwrap().spki(),
        &advertised
    );
    assert_ne!(
        advertised,
        HexDigest::of(key),
        "never a digest of the private bytes"
    );
    let other = spki(&identities.client.key);
    assert_eq!(
        protocol(FrozenArtifact::freeze_tls_key(
            Class::TransitionServerKey,
            key,
            &other,
            deadline()
        )),
        "TLS key differs from its advertised SPKI"
    );
    let mut trailing = key.clone();
    trailing.push(0);
    let mut duplicated = key.clone();
    duplicated.extend(key);
    let mut truncated = key.clone();
    truncated.pop();
    let mut encrypted = vec![0x30, 0x20, 0x30, 0x1b];
    encrypted.extend([
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d,
    ]);
    encrypted.extend([0; 16]);
    for (name, bytes) in [
        ("trailing", trailing),
        ("duplicate object", duplicated),
        ("truncated", truncated),
        ("encrypted shell", encrypted),
        ("empty", Vec::new()),
        ("P-384", key_for(&PKCS_ECDSA_P384_SHA384)),
        ("Ed25519", key_for(&PKCS_ED25519)),
        ("ordinary authority profile", key_profile(KEY_SEED)),
        ("raw seed", evidence_seed(Signer::Hk).to_vec()),
        ("pem text", b"-----BEGIN PRIVATE KEY-----\n".to_vec()),
    ] {
        let claimed = if bytes.is_empty() {
            other.clone()
        } else {
            HexDigest::of(&bytes)
        };
        for class in [
            Class::TransitionServerKey,
            Class::TransitionClientKey,
            Class::DaemonApiKey,
        ] {
            assert!(
                FrozenArtifact::freeze_tls_key(class, &bytes, &claimed, deadline()).is_err(),
                "{name} as {class:?}"
            );
        }
    }
    assert!(
        FrozenArtifact::freeze_tls_key(Class::TlsKey, key, &advertised, deadline()).is_err(),
        "only the three suffix key classes"
    );
    assert!(
        from_file(Class::TransitionServerKey, key).is_err(),
        "never staged from a file"
    );
    assert!(from_file(Class::DaemonApiKey, key).is_err());
}

fn leaf(
    algorithm: &'static rcgen::SignatureAlgorithm,
    usage: Option<Usage>,
    tweak: impl FnOnce(&mut CertificateParams),
) -> Vec<u8> {
    let key = KeyPair::generate_for(algorithm).unwrap();
    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![SanType::DnsName("h-1.peer.test".try_into().unwrap())];
    params.extended_key_usages = usage
        .map(|usage| {
            vec![match usage {
                Usage::Server => ExtendedKeyUsagePurpose::ServerAuth,
                Usage::Client => ExtendedKeyUsagePurpose::ClientAuth,
            }]
        })
        .unwrap_or_default();
    params.is_ca = IsCa::NoCa;
    params.not_before = date_time_ymd(2026, 1, 1);
    params.not_after = date_time_ymd(2030, 1, 1);
    tweak(&mut params);
    params.self_signed(&key).unwrap().der().to_vec()
}

#[test]
fn the_transition_certificates_use_the_transports_closed_profile_and_their_own_role() {
    let identities = identities();
    assert!(from_file(Class::TransitionServerCert, &identities.server.cert).is_ok());
    assert!(from_file(Class::TransitionClientCert, &identities.client.cert).is_ok());
    assert!(
        from_file(Class::TransitionClientCert, &identities.server.cert).is_err(),
        "server leaf in the client slot"
    );
    assert!(
        from_file(Class::TransitionServerCert, &identities.client.cert).is_err(),
        "client leaf in the server slot"
    );
    let ca = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca).unwrap();
    let issued = {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![SanType::DnsName("h-1.peer.test".try_into().unwrap())];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params
            .signed_by(&key, &ca_cert, &ca)
            .unwrap()
            .der()
            .to_vec()
    };
    let mut trailing = identities.server.cert.clone();
    trailing.push(0);
    let mut duplicated = identities.server.cert.clone();
    duplicated.extend(&identities.server.cert);
    for (name, der) in [
        ("issued by a CA, not self-signed", issued),
        (
            "CA leaf",
            leaf(&PKCS_ECDSA_P256_SHA256, Some(Usage::Server), |p| {
                p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained)
            }),
        ),
        (
            "P-384",
            leaf(&PKCS_ECDSA_P384_SHA384, Some(Usage::Server), |_| ()),
        ),
        ("Ed25519", leaf(&PKCS_ED25519, Some(Usage::Server), |_| ())),
        (
            "no extended key usage",
            leaf(&PKCS_ECDSA_P256_SHA256, None, |_| ()),
        ),
        (
            "both usages",
            leaf(&PKCS_ECDSA_P256_SHA256, Some(Usage::Server), |p| {
                p.extended_key_usages
                    .push(ExtendedKeyUsagePurpose::ClientAuth)
            }),
        ),
        (
            "two names",
            leaf(&PKCS_ECDSA_P256_SHA256, Some(Usage::Server), |p| {
                p.subject_alt_names
                    .push(SanType::DnsName("two.peer.test".try_into().unwrap()))
            }),
        ),
        (
            "wildcard name",
            leaf(&PKCS_ECDSA_P256_SHA256, Some(Usage::Server), |p| {
                p.subject_alt_names = vec![SanType::DnsName("*.peer.test".try_into().unwrap())]
            }),
        ),
        ("trailing bytes", trailing),
        ("duplicate object", duplicated),
        ("empty", Vec::new()),
        ("pem text", b"-----BEGIN CERTIFICATE-----".to_vec()),
    ] {
        assert!(
            from_file(Class::TransitionServerCert, &der).is_err(),
            "{name}"
        );
    }
    assert!(private_cert::parse(&identities.server.cert, Usage::Server).is_ok());
    assert_eq!(
        private_cert::parse(&identities.server.cert, Usage::Server)
            .unwrap()
            .name,
        Name::dns("h-1.peer.test").unwrap()
    );
}

fn registry_with(mutate: impl FnOnce(&mut Vec<serde_json::Value>)) -> Vec<u8> {
    let mut entries: Vec<serde_json::Value> = serde_json::from_slice(&default_registry()).unwrap();
    mutate(&mut entries);
    serde_json::to_vec(&entries).unwrap()
}

fn central(seed: u8) -> serde_json::Value {
    serde_json::json!({
        "kid": format!("central-{seed}"), "role": "central", "issuer": "central", "authority": null,
        "public_key": public_of(&[seed; 32]).as_array().to_vec(),
    })
}

#[test]
fn the_registry_is_the_common_parser_plus_the_one_authority_closed_profile() {
    let good = default_registry();
    let frozen = from_file(Class::VerificationRegistry, &good).unwrap();
    let keys = frozen.verification_registry(deadline()).unwrap();
    assert_eq!(keys.len(), 3);
    let many = |count: usize| {
        registry_with(|entries| {
            entries.truncate(1);
            entries.extend((100..100 + count as u8 - 2).map(central));
            entries.push(serde_json::json!({
                "kid": "k", "role": "authority", "issuer": "authority", "authority": "auth",
                "public_key": key_public(KEY_SEED).as_array().to_vec(),
            }));
        })
    };
    assert!(
        from_file(Class::VerificationRegistry, &many(32)).is_ok(),
        "32 entries"
    );
    assert!(
        from_file(Class::VerificationRegistry, &many(33)).is_err(),
        "33 entries"
    );
    let mut duplicate_key = good.clone();
    duplicate_key.splice(1..1, br#"{"kid":"x","kid":"y"},"#.iter().copied());
    for (name, bytes) in [
        ("one entry", registry_with(|e| e.truncate(1))),
        ("empty", b"[]".to_vec()),
        ("no authority", registry_with(|e| drop(e.pop()))),
        ("no central", registry_with(|e| drop(e.drain(..2)))),
        (
            "two authorities",
            registry_with(|e| {
                e.push(serde_json::json!({
            "kid": "k2", "role": "authority", "issuer": "authority", "authority": "auth",
            "public_key": public_of(&[0x77; 32]).as_array().to_vec()}))
            }),
        ),
        (
            "duplicate kid",
            registry_with(|e| e[1]["kid"] = e[0]["kid"].clone()),
        ),
        (
            "duplicate public key",
            registry_with(|e| e[1]["public_key"] = e[0]["public_key"].clone()),
        ),
        (
            "central with an authority",
            registry_with(|e| e[0]["authority"] = "auth".into()),
        ),
        (
            "authority without one",
            registry_with(|e| e[2]["authority"] = serde_json::Value::Null),
        ),
        (
            "two central issuers",
            registry_with(|e| e[1]["issuer"] = "other".into()),
        ),
        (
            "cross role",
            registry_with(|e| e[0]["role"] = "authority".into()),
        ),
        (
            "unknown role",
            registry_with(|e| e[0]["role"] = "gateway".into()),
        ),
        (
            "unknown field",
            registry_with(|e| e[0]["extra"] = true.into()),
        ),
        (
            "short key",
            registry_with(|e| e[0]["public_key"] = vec![1; 31].into()),
        ),
        ("empty kid", registry_with(|e| e[0]["kid"] = "".into())),
        ("object, not array", br#"{"keys":[]}"#.to_vec()),
        ("duplicate json key", duplicate_key),
        ("byte order mark", [&[0xef, 0xbb, 0xbf][..], &good].concat()),
        ("invalid utf-8", [&good[..], &[0xff]].concat()),
        ("trailing garbage", [&good[..], b"x"].concat()),
    ] {
        assert!(
            from_file(Class::VerificationRegistry, &bytes).is_err(),
            "{name}"
        );
    }
}

#[test]
fn the_registry_grammar_is_five_named_fields_with_authority_explicit() {
    let good = default_registry();
    from_file(Class::VerificationRegistry, &good).expect("positive control");
    let text = String::from_utf8(good.clone()).unwrap();
    assert!(text.contains(r#""kid":"central-1""#) && text.contains(r#""authority":null"#));
    let missing_authority = registry_with(|e| {
        e[0].as_object_mut().unwrap().remove("authority");
    });
    let positional = registry_with(|e| {
        let row = e[0].as_object().unwrap().clone();
        e[0] = serde_json::Value::Array(
            ["kid", "role", "issuer", "authority", "public_key"]
                .iter()
                .map(|name| row[*name].clone())
                .collect(),
        );
    });
    let duplicate_field = text
        .replacen(
            r#""kid":"central-1""#,
            r#""kid":"central-1","kid":"central-1""#,
            1,
        )
        .into_bytes();
    let duplicate_authority = text
        .replacen(
            r#""authority":null"#,
            r#""authority":null,"authority":null"#,
            1,
        )
        .into_bytes();
    let central_reuses_authority_key =
        registry_with(|e| e[0]["public_key"] = e[2]["public_key"].clone());
    for (name, bytes) in [
        ("authority missing, not null", missing_authority),
        ("positional row", positional),
        ("duplicate kid", duplicate_field),
        ("duplicate authority", duplicate_authority),
        (
            "central key equal to the authority key",
            central_reuses_authority_key,
        ),
    ] {
        assert_eq!(
            protocol(from_file(Class::VerificationRegistry, &bytes)),
            "invalid verification registry",
            "{name}"
        );
    }
}

#[test]
fn the_continuation_bearer_is_one_to_4096_printable_ascii_bytes() {
    let accepted = |bytes: &[u8]| from_file(Class::ContinuationBearer, bytes).is_ok();
    assert!(accepted(b"x") && accepted(&[b'~'; 4096]) && accepted(&[b'!'; 4096]));
    assert!(!accepted(&[b'x'; 4097]));
    assert!(!accepted(&[b'x'; 5000]));
    for bad in [
        &b"has space"[..],
        b"trailing\n",
        b"tab\there",
        b"\x7fdel",
        b"\x1fctl",
        b"caf\xc3\xa9",
        b"\xff",
        b"nul\0",
    ] {
        assert!(!accepted(bad), "{bad:?}");
    }
    assert!(from_file(Class::ContinuationBearer, b"").is_err());
    let frozen = from_file(Class::ContinuationBearer, BEARER).unwrap();
    assert_eq!(
        frozen
            .continuation_bearer(deadline())
            .unwrap()
            .as_str()
            .as_bytes(),
        BEARER
    );
}

fn s3_text(access: &str, secret: &str) -> Vec<u8> {
    format!(r#"{{"access":"{access}","secret":"{secret}"}}"#).into_bytes()
}

#[test]
fn the_s3_pair_is_canonical_with_strict_unpadded_base64url_graphic_credentials() {
    let frozen = from_file(Class::BackupS3Pair, &s3_pair()).unwrap();
    let pair = frozen.backup_s3(deadline()).unwrap();
    assert_eq!(
        (pair.access(), pair.secret()),
        ("AKIAFIXTUREACCESS", "fixture/secret+key")
    );
    let long = |count: usize| b64("a".repeat(count).as_bytes());
    assert!(from_file(Class::BackupS3Pair, &s3_text(&long(4096), &long(4096))).is_ok());
    assert!(from_file(Class::BackupS3Pair, &s3_text(&long(4097), &long(1))).is_err());
    assert!(from_file(Class::BackupS3Pair, &s3_text(&long(1), &long(4097))).is_err());
    let ok = b64(b"ok");
    for (name, bytes) in [
        ("empty access", s3_text("", &ok)),
        ("empty secret", s3_text(&ok, "")),
        ("padded", s3_text("YWI=", &ok)),
        ("standard alphabet", s3_text("Pj4+", &ok)),
        ("trailing bits", s3_text("YWJ", &ok)),
        ("space in a credential", s3_text(&b64(b"a b"), &ok)),
        ("control", s3_text(&b64(b"a\x01b"), &ok)),
        ("del", s3_text(&b64(b"a\x7fb"), &ok)),
        ("non-ascii", s3_text(&b64("café".as_bytes()), &ok)),
        ("newline", s3_text(&b64(b"a\nb"), &ok)),
        (
            "whitespace in the object",
            format!(r#"{{"access": "{ok}","secret":"{ok}"}}"#).into_bytes(),
        ),
        (
            "swapped order",
            format!(r#"{{"secret":"{ok}","access":"{ok}"}}"#).into_bytes(),
        ),
        (
            "duplicate access",
            format!(r#"{{"access":"{ok}","access":"{ok}","secret":"{ok}"}}"#).into_bytes(),
        ),
        (
            "missing secret",
            format!(r#"{{"access":"{ok}"}}"#).into_bytes(),
        ),
        (
            "extra bucket",
            format!(r#"{{"access":"{ok}","bucket":"b","secret":"{ok}"}}"#).into_bytes(),
        ),
        (
            "null credential",
            format!(r#"{{"access":null,"secret":"{ok}"}}"#).into_bytes(),
        ),
        (
            "trailing newline",
            [s3_text(&ok, &ok), b"\n".to_vec()].concat(),
        ),
        ("array", b"[]".to_vec()),
    ] {
        assert!(from_file(Class::BackupS3Pair, &bytes).is_err(), "{name}");
    }
}

#[test]
fn the_pool_key_is_sixty_four_lowercase_hex_digits_and_its_id_is_the_existing_primitive() {
    let id = PoolKeyId::new(briqyard_api::poolkey::id(POOL_KEY).unwrap()).unwrap();
    let frozen = FrozenArtifact::freeze_pool_key(POOL_KEY.as_bytes(), &id, deadline()).unwrap();
    let key = frozen.pool_file_key(deadline()).unwrap();
    assert_eq!(key.id(), &id);
    assert_eq!(key.hex(), POOL_KEY);
    use sha2::{Digest, Sha256};
    let mut labelled = Sha256::new();
    labelled.update(b"briqyard pool key id\0");
    labelled.update(hex::decode(POOL_KEY).unwrap());
    assert_eq!(
        id.as_str(),
        hex::encode(&labelled.finalize()[..16]),
        "ADR 0035's label and truncation"
    );
    let plain = Sha256::digest(hex::decode(POOL_KEY).unwrap());
    assert_ne!(
        id.as_str(),
        hex::encode(&plain[..16]),
        "not a plain hash of the key"
    );
    for bad in [
        POOL_KEY[..63].to_owned(),
        format!("{POOL_KEY}0"),
        POOL_KEY.to_uppercase(),
        format!("{POOL_KEY}\n"),
        format!("{}g", &POOL_KEY[..63]),
        format!(" {}", &POOL_KEY[..63]),
        String::new(),
    ] {
        assert!(
            FrozenArtifact::freeze_pool_key(bad.as_bytes(), &id, deadline()).is_err(),
            "{bad:?}"
        );
    }
    let other = PoolKeyId::new(briqyard_api::poolkey::id(&"ab".repeat(32)).unwrap()).unwrap();
    assert_eq!(
        protocol(FrozenArtifact::freeze_pool_key(
            POOL_KEY.as_bytes(),
            &other,
            deadline()
        )),
        "pool key differs from its advertised id"
    );
    assert!(
        from_file(Class::LocalPoolKey, POOL_KEY.as_bytes()).is_err(),
        "never staged from a file"
    );
}

#[test]
fn the_generic_read_refuses_every_secret_class_and_typed_debug_never_prints_one() {
    let deadline = deadline();
    let identities = identities();
    let id = PoolKeyId::new(briqyard_api::poolkey::id(POOL_KEY).unwrap()).unwrap();
    let secrets = [
        (Class::OrdinaryAuthorityKey, key_profile(KEY_SEED)),
        (
            Class::Signer(Signer::Hk),
            evidence_seed(Signer::Hk).to_vec(),
        ),
        (Class::TransitionServerKey, identities.server.key.clone()),
        (Class::TransitionClientKey, identities.client.key.clone()),
        (Class::DaemonApiKey, identities.daemon_api.key.clone()),
        (Class::ContinuationBearer, BEARER.to_vec()),
        (Class::BackupS3Pair, s3_pair()),
        (Class::LocalPoolKey, POOL_KEY.as_bytes().to_vec()),
    ];
    for (class, bytes) in &secrets {
        let frozen = stage(*class, bytes);
        assert_eq!(
            protocol(frozen.read_small(deadline)),
            "secret bytes are not a readable artifact",
            "{class:?}"
        );
        assert!(class.is_secret());
    }
    for class in [
        Class::Plan,
        Class::Inputs,
        Class::Config,
        Class::VerificationRegistry,
        Class::TransitionServerCert,
        Class::TransitionClientCert,
        Class::DaemonApiCert,
    ] {
        assert!(!class.is_secret(), "public bytes stay readable: {class:?}");
    }
    let signer = stage(Class::Signer(Signer::Hk), &evidence_seed(Signer::Hk))
        .evidence_signer(deadline)
        .unwrap();
    let key = stage(Class::TransitionServerKey, &identities.server.key)
        .tls_private_key(deadline)
        .unwrap();
    let bearer = stage(Class::ContinuationBearer, BEARER)
        .continuation_bearer(deadline)
        .unwrap();
    let pair = stage(Class::BackupS3Pair, &s3_pair())
        .backup_s3(deadline)
        .unwrap();
    let pool = FrozenArtifact::freeze_pool_key(POOL_KEY.as_bytes(), &id, deadline)
        .unwrap()
        .pool_file_key(deadline)
        .unwrap();
    let shown = format!("{signer:?}{key:?}{bearer:?}{pair:?}{pool:?}");
    for secret in [
        std::str::from_utf8(BEARER).unwrap().to_owned(),
        "AKIAFIXTUREACCESS".to_owned(),
        "fixture/secret+key".to_owned(),
        b64(b"AKIAFIXTUREACCESS"),
        POOL_KEY.to_owned(),
        hex::encode(evidence_seed(Signer::Hk)),
        format!("{:?}", evidence_seed(Signer::Hk)),
        hex::encode(&identities.server.key),
        b64(&identities.server.key),
    ] {
        assert!(!shown.contains(&secret), "{secret}");
    }
    assert!(shown.contains(id.as_str()), "the id is not secret");
}

#[test]
fn a_typed_accessor_refuses_another_class_even_with_valid_bytes_of_its_own() {
    let bearer = stage(Class::ContinuationBearer, BEARER);
    assert!(bearer.backup_s3(deadline()).is_err());
    assert!(bearer.pool_file_key(deadline()).is_err());
    assert!(bearer.evidence_signer(deadline()).is_err());
    assert!(bearer.tls_private_key(deadline()).is_err());
    assert!(bearer.verification_registry(deadline()).is_err());
    let seed = stage(Class::Signer(Signer::Hk), &evidence_seed(Signer::Hk));
    assert!(seed.continuation_bearer(deadline()).is_err());
    assert!(seed.tls_private_key(deadline()).is_err());
}
