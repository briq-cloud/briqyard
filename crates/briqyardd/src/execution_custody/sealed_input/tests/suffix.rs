//! The v3.3 suffix under a signed, consumed startup: typed acquisition, the Plan and closure
//! bindings, and the cases where an advertised field alone would have been believed.

use super::*;
use briqyard_api::execution::{
    private_cert::{Name, Pair},
    sealed::{
        objects::HostClockBody,
        objects::Q,
        prim::{Env, Nonce},
        sig::{PinnedKey, Role},
    },
    KeyRole,
};
use fixtures::{BEARER, POOL_KEY, SERVER_NAME};

fn profiles() -> Vec<Requirements> {
    let mut all: Vec<_> = (0..8)
        .map(|bits| Requirements::Daemon {
            admin_tls: bits & 1 != 0,
            backup_s3: bits & 2 != 0,
            file_key: bits & 4 != 0,
        })
        .collect();
    all.push(Requirements::Authority);
    all
}

fn deadline() -> StageDeadline {
    StageDeadline::frame("suffix test")
}

fn body(fixture: &Fixture) -> HostClockBody {
    use briqyard_api::execution::sealed::prim::Uint;
    HostClockBody {
        q: Q {
            x: fixture.plan.x.clone(),
            nonce: Nonce::from_array([7; 32]),
        },
        plan: h(&fixture.plan).unwrap(),
        proc: proc(12),
        instance: Ident::new("hi").unwrap(),
        now: Uint::new(1_900_000_000).unwrap(),
        uncertainty: Uint::new(1).unwrap(),
    }
}

fn pins(fixture: &Fixture) -> SuffixPins {
    let requirements = fixture.requirements;
    let identities = identities();
    let (admin_tls, backup_s3, file_key) = match requirements {
        Requirements::Daemon {
            admin_tls,
            backup_s3,
            file_key,
        } => (admin_tls, backup_s3, file_key),
        Requirements::Authority => (false, false, false),
    };
    let pair = |cert: &[u8], key: &[u8]| Pair {
        leaf: HexDigest::of(cert),
        spki: spki(key),
    };
    SuffixPins {
        registry: HexDigest::of(&fixtures::registry_json((
            fixture.plan.pre_record.key_id.as_str(),
            fixture.plan.pre_record.authority.as_str(),
            fixture.plan.pre_record.public_key,
        ))),
        server: pair(&identities.server.cert, &identities.server.key),
        server_name: Name::dns(SERVER_NAME).unwrap(),
        client: pair(&identities.client.cert, &identities.client.key),
        continuation: (requirements == Requirements::Authority).then(|| HexDigest::of(BEARER)),
        admin_tls: admin_tls.then(|| pair(&identities.daemon_api.cert, &identities.daemon_api.key)),
        backup_s3: backup_s3.then(|| HexDigest::of(&fixtures::s3_pair())),
        file_key: file_key
            .then(|| PoolKeyId::new(briqyard_api::poolkey::id(POOL_KEY).unwrap()).unwrap()),
    }
}

#[test]
fn every_profile_decodes_and_hands_out_the_material_its_requirements_name() {
    for requirements in profiles() {
        let fixture = Fixture::with_requirements(requirements);
        let input = fixture.verify().unwrap();
        let (role, tag, pin) = match requirements {
            Requirements::Authority => (Role::Ak, Tag::AuthorityObserve, fixture.plan.ak),
            Requirements::Daemon { .. } => (Role::Hk, Tag::HostClock, fixture.plan.hk),
        };
        let signer = input.evidence_signer(deadline()).unwrap();
        assert_eq!(
            signer.public_key(),
            *pin.as_array(),
            "derived equals the Plan pin"
        );
        let signed = Sig::sign(tag, body(&fixture), &signer).unwrap();
        signed
            .verify(tag, &PinnedKey::new(role, *pin.as_array()).unwrap())
            .unwrap();
        let wrong = fixtures::public_of(&[0x31; 32]);
        assert!(signed
            .verify(tag, &PinnedKey::new(role, *wrong.as_array()).unwrap())
            .is_err());
        let registry = input.verification_registry(deadline()).unwrap();
        assert_eq!(
            registry
                .iter()
                .filter(|key| key.role == KeyRole::Authority)
                .count(),
            1
        );
        let identities = identities();
        assert_eq!(
            input.transition_server_key(deadline()).unwrap().spki(),
            &spki(&identities.server.key)
        );
        assert_eq!(
            input.transition_client_key(deadline()).unwrap().spki(),
            &spki(&identities.client.key)
        );
        input.check_suffix_pins(&pins(&fixture)).unwrap();
        match requirements {
            Requirements::Authority => {
                assert_eq!(
                    input
                        .continuation_bearer(deadline())
                        .unwrap()
                        .as_str()
                        .as_bytes(),
                    BEARER
                );
                assert!(input.backup_s3(deadline()).is_err());
                assert!(input.pool_file_key(deadline()).is_err());
                assert!(input.daemon_api_key(deadline()).is_err());
            }
            Requirements::Daemon {
                admin_tls,
                backup_s3,
                file_key,
            } => {
                assert!(
                    input.continuation_bearer(deadline()).is_err(),
                    "never a daemon right"
                );
                assert_eq!(input.daemon_api_key(deadline()).is_ok(), admin_tls);
                assert_eq!(input.backup_s3(deadline()).is_ok(), backup_s3);
                assert_eq!(input.pool_file_key(deadline()).is_ok(), file_key);
                if file_key {
                    let key = input.pool_file_key(deadline()).unwrap();
                    assert_eq!(
                        key.id().as_str(),
                        briqyard_api::poolkey::id(POOL_KEY).unwrap()
                    );
                    assert_eq!(key.hex(), POOL_KEY);
                }
            }
        }
    }
}

#[test]
fn an_advertised_signer_key_is_never_believed_over_the_actual_seed() {
    let fixture = Fixture::new(Resource::Daemon);
    let attacker = fixtures::public_of(&[0x66; 32]);
    let refused = fixture.try_bind(
        &fixture.grant(),
        &fixture.capture_load(),
        |assets| {
            for (descriptor, _) in assets.iter_mut() {
                if let Descriptor::Signer { public, .. } = descriptor {
                    *public = attacker;
                }
            }
        },
        deadline(),
    );
    assert!(matches!(
        refused,
        Err(CustodyError::Protocol(
            "native artifact differs from its advertised descriptor"
        ))
    ));
    for resource in [Resource::Daemon, Resource::Authority] {
        let mut pinned_elsewhere = Fixture::new(resource);
        match resource {
            Resource::Daemon => pinned_elsewhere.plan.hk = attacker,
            Resource::Authority => pinned_elsewhere.plan.ak = attacker,
        }
        rejected(pinned_elsewhere.verify(), "startup asset plan pins");
    }
}

fn with_registry(
    mutate: impl FnOnce(&mut Vec<serde_json::Value>),
) -> Result<SealedInput, CustodyError> {
    let fixture = Fixture::new(Resource::Daemon);
    let mut entries: Vec<serde_json::Value> = serde_json::from_slice(&fixtures::registry_json((
        fixture.plan.pre_record.key_id.as_str(),
        fixture.plan.pre_record.authority.as_str(),
        fixture.plan.pre_record.public_key,
    )))
    .unwrap();
    mutate(&mut entries);
    let replacement = serde_json::to_vec(&entries).unwrap();
    let deadline = deadline();
    let assets = fixture.try_bind(
        &fixture.grant(),
        &fixture.capture_load(),
        |assets| {
            let (descriptor, bytes) = assets
                .iter_mut()
                .find(|(descriptor, _)| descriptor.class() == Class::VerificationRegistry)
                .unwrap();
            *descriptor = Descriptor::VerificationRegistry {
                bytes: Uint::new(replacement.len() as u64).unwrap(),
                digest: HexDigest::of(&replacement),
            };
            *bytes = replacement.clone();
        },
        deadline,
    )?;
    SealedInput::decode(
        assets,
        &fixture.directory(),
        &h(&fixture.plan).unwrap(),
        deadline,
    )
}

#[test]
fn the_registry_authority_entry_is_exactly_the_registered_predecessor() {
    assert!(with_registry(|_| {}).is_ok());
    let authority = |entries: &mut Vec<serde_json::Value>| {
        entries
            .iter()
            .position(|entry| entry["role"] == "authority")
            .unwrap()
    };
    for (_name, mutate) in [
        (
            "another kid",
            (|e: &mut Vec<serde_json::Value>, at: usize| e[at]["kid"] = "other".into())
                as fn(&mut Vec<serde_json::Value>, usize),
        ),
        ("another authority", |e, at| {
            e[at]["authority"] = "other".into()
        }),
        ("another public key", |e, at| {
            e[at]["public_key"] = fixtures::public_of(&[0x44; 32]).as_array().to_vec().into()
        }),
    ] {
        let result = with_registry(|entries| {
            let at = authority(entries);
            mutate(entries, at)
        });
        rejected(result, "startup registry predecessor binding");
    }
}

#[test]
fn the_closure_pins_must_each_match_the_actual_bound_bytes() {
    for requirements in profiles() {
        let fixture = Fixture::with_requirements(requirements);
        let input = fixture.verify().unwrap();
        let good = pins(&fixture);
        input.check_suffix_pins(&good).unwrap();
        let other = HexDigest::of(b"another pin");
        let mut cases: Vec<(&str, SuffixPins)> = Vec::new();
        let mut add = |name, edit: &dyn Fn(&mut SuffixPins)| {
            let mut changed = pins(&fixture);
            edit(&mut changed);
            cases.push((name, changed));
        };
        add("registry", &|p| p.registry = other.clone());
        add("server leaf", &|p| p.server.leaf = other.clone());
        add("server spki", &|p| p.server.spki = other.clone());
        add("server name", &|p| {
            p.server_name = Name::dns("other.peer.test").unwrap()
        });
        add("client leaf", &|p| p.client.leaf = other.clone());
        add("client spki", &|p| p.client.spki = other.clone());
        add("swapped identities", &|p| {
            std::mem::swap(&mut p.server, &mut p.client)
        });
        add("reused identity", &|p| p.client = p.server.clone());
        if requirements == Requirements::Authority {
            add("continuation", &|p| p.continuation = Some(other.clone()));
            add("no continuation", &|p| p.continuation = None);
            add("daemon feature on the authority", &|p| {
                p.backup_s3 = Some(other.clone())
            });
        } else {
            add("a continuation on the daemon", &|p| {
                p.continuation = Some(other.clone())
            });
            add("s3 toggled", &|p| {
                p.backup_s3 = if p.backup_s3.is_some() {
                    None
                } else {
                    Some(other.clone())
                }
            });
            add("admin tls toggled", &|p| {
                p.admin_tls = if p.admin_tls.is_some() {
                    None
                } else {
                    Some(p.server.clone())
                }
            });
            add("file key toggled", &|p| {
                p.file_key = if p.file_key.is_some() {
                    None
                } else {
                    Some(PoolKeyId::new("0".repeat(32)).unwrap())
                }
            });
            if let Requirements::Daemon {
                admin_tls: true,
                backup_s3,
                file_key,
            } = requirements
            {
                add("admin leaf", &|p| {
                    p.admin_tls.as_mut().unwrap().leaf = other.clone()
                });
                add("admin spki", &|p| {
                    p.admin_tls.as_mut().unwrap().spki = other.clone()
                });
                if backup_s3 {
                    add("s3 digest", &|p| p.backup_s3 = Some(other.clone()));
                }
                if file_key {
                    add("pool key id", &|p| {
                        p.file_key = Some(PoolKeyId::new("1".repeat(32)).unwrap())
                    });
                }
            }
        }
        for (name, pins) in cases {
            assert!(
                input.check_suffix_pins(&pins).is_err(),
                "{requirements:?}: {name}"
            );
        }
    }
}

#[test]
fn no_suffix_accessor_exists_for_a_feature_the_requirements_leave_out() {
    let input = Fixture::new(Resource::Daemon).verify().unwrap();
    for class in [
        Class::DaemonApiKey,
        Class::BackupS3Pair,
        Class::LocalPoolKey,
        Class::ContinuationBearer,
    ] {
        assert!(input.artifact(class).is_none(), "{class:?}");
    }
    assert!(input.daemon_api_key(deadline()).is_err());
    assert!(input.backup_s3(deadline()).is_err());
    assert!(input.pool_file_key(deadline()).is_err());
    assert!(input.continuation_bearer(deadline()).is_err());
    let _ = Env::Staging;
}
