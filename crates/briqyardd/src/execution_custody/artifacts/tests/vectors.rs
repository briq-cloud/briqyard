//! The frozen v3 vectors: prefix indices never move, the six-or-fewer suffix rights follow
//! in one fixed order, and nothing short, long, reordered or mixed is accepted.

use super::*;

const DAEMON_PREFIX: [&str; 13] = [
    "plan",
    "launch",
    "grant",
    "inputs",
    "candidate",
    "config",
    "capture-load",
    "member",
    "member",
    "member",
    "signer",
    "tls-cert",
    "tls-key",
];
const AUTHORITY_PREFIX: [&str; 16] = [
    "plan",
    "launch",
    "grant",
    "inputs",
    "candidate",
    "config",
    "capture-load",
    "member",
    "member",
    "member",
    "member",
    "member",
    "signer",
    "tls-cert",
    "tls-key",
    "ordinary-authority-key",
];
const COMMON_SUFFIX: [&str; 5] = [
    "verification-registry",
    "transition-server-cert",
    "transition-server-key",
    "transition-client-cert",
    "transition-client-key",
];

fn combos() -> Vec<Requirements> {
    (0..8)
        .map(|bits| Requirements::Daemon {
            admin_tls: bits & 1 != 0,
            backup_s3: bits & 2 != 0,
            file_key: bits & 4 != 0,
        })
        .collect()
}

fn expected_suffix(requirements: Requirements) -> Vec<&'static str> {
    let mut suffix = COMMON_SUFFIX.to_vec();
    match requirements {
        Requirements::Authority => suffix.push("continuation-bearer"),
        Requirements::Daemon {
            admin_tls,
            backup_s3,
            file_key,
        } => {
            if admin_tls {
                suffix.extend(["daemon-api-cert", "daemon-api-key"]);
            }
            if backup_s3 {
                suffix.push("backup-s3-pair");
            }
            if file_key {
                suffix.push("local-pool-key");
            }
        }
    }
    suffix
}

fn vector(requirements: Requirements) -> Vec<serde_json::Value> {
    requirements
        .classes()
        .into_iter()
        .map(|class| descriptor_value(class, &payload(class, 0)))
        .collect()
}

fn names(fields: &[serde_json::Value]) -> Vec<String> {
    fields
        .iter()
        .map(|field| field["class"].as_str().unwrap().to_owned())
        .collect()
}

fn decode(
    requirements: Requirements,
    fields: Vec<serde_json::Value>,
) -> Result<AssetOffer, CodecError> {
    AssetOffer::decode(requirements, &envelope(fields))
}

#[test]
fn every_boolean_combination_has_the_exact_canonical_count_prefix_and_suffix() {
    for requirements in combos() {
        let Requirements::Daemon {
            admin_tls,
            backup_s3,
            file_key,
        } = requirements
        else {
            unreachable!()
        };
        let fields = vector(requirements);
        let count =
            18 + 2 * usize::from(admin_tls) + usize::from(backup_s3) + usize::from(file_key);
        assert_eq!(fields.len(), count, "{requirements:?}");
        assert!(count <= MAX_ASSET_RIGHTS);
        let names = names(&fields);
        assert_eq!(
            names[..13],
            DAEMON_PREFIX,
            "prefix indices 0..=12 never move"
        );
        assert_eq!(
            names[13..],
            expected_suffix(requirements),
            "{requirements:?}"
        );
        let wire = envelope(fields.clone());
        let offer = AssetOffer::decode(requirements, &wire).unwrap();
        assert_eq!(
            AssetOffer::encode(requirements, offer.assets).unwrap(),
            wire
        );
    }
    let all = Requirements::Daemon {
        admin_tls: true,
        backup_s3: true,
        file_key: true,
    };
    assert_eq!(all.classes().len(), 22);
}

#[test]
fn the_authority_has_exactly_twenty_two_with_the_ordinary_key_still_at_fifteen() {
    let fields = vector(Requirements::Authority);
    assert_eq!(fields.len(), 22);
    let names = names(&fields);
    assert_eq!(names[..16], AUTHORITY_PREFIX);
    assert_eq!(names[15], "ordinary-authority-key");
    assert_eq!(names[16..], expected_suffix(Requirements::Authority));
    assert!(decode(Requirements::Authority, fields).is_ok());
}

#[test]
fn an_offer_for_one_profile_is_refused_by_every_other_requirement() {
    let mut all: Vec<Requirements> = combos();
    all.push(Requirements::Authority);
    for offered in &all {
        let wire = envelope(vector(*offered));
        for required in &all {
            let accepted = AssetOffer::decode(*required, &wire).is_ok();
            assert_eq!(
                accepted,
                offered == required,
                "{offered:?} against {required:?}"
            );
        }
    }
}

#[test]
fn omission_reorder_duplicate_and_extra_rights_are_refused_in_every_profile() {
    let mut all = combos();
    all.push(Requirements::Authority);
    for requirements in all {
        let fields = vector(requirements);
        for index in 0..fields.len() {
            let mut omitted = fields.clone();
            omitted.remove(index);
            assert!(
                decode(requirements, omitted).is_err(),
                "omit {index} of {requirements:?}"
            );
            let mut duplicated = fields.clone();
            duplicated.insert(index, fields[index].clone());
            assert!(
                decode(requirements, duplicated).is_err(),
                "duplicate {index}"
            );
            if index + 1 < fields.len() {
                let mut swapped = fields.clone();
                swapped.swap(index, index + 1);
                assert!(
                    decode(requirements, swapped).is_err(),
                    "swap {index} {requirements:?}"
                );
            }
        }
        let mut longer = fields.clone();
        longer.push(fields[0].clone());
        assert!(decode(requirements, longer).is_err());
        assert!(decode(requirements, Vec::new()).is_err());
        assert!(decode(requirements, fields[..fields.len() - 1].to_vec()).is_err());
    }
}

#[test]
fn a_twenty_third_right_is_refused_as_an_offer_before_any_layout_comparison() {
    let all = Requirements::Daemon {
        admin_tls: true,
        backup_s3: true,
        file_key: true,
    };
    let mut fields = vector(all);
    assert_eq!(fields.len(), MAX_ASSET_RIGHTS);
    fields.push(fields[21].clone());
    for requirements in [all, Requirements::Authority] {
        assert!(decode(requirements, fields.clone()).is_err());
    }
}

#[test]
fn the_other_resource_suffix_right_is_refused_at_any_position() {
    let authority = vector(Requirements::Authority);
    let continuation = authority[21].clone();
    let all = Requirements::Daemon {
        admin_tls: true,
        backup_s3: true,
        file_key: true,
    };
    for requirements in combos() {
        let fields = vector(requirements);
        for position in 0..=fields.len() {
            let mut hybrid = fields.clone();
            hybrid.insert(position, continuation.clone());
            assert!(
                decode(requirements, hybrid).is_err(),
                "continuation in the daemon at {position}"
            );
        }
    }
    let daemon = vector(all);
    for suffix in [&daemon[18], &daemon[19], &daemon[20], &daemon[21]] {
        for position in 16..=authority.len() {
            let mut hybrid = authority.clone();
            hybrid.insert(position, suffix.clone());
            assert!(decode(Requirements::Authority, hybrid).is_err());
        }
    }
    let mut ordinary_in_daemon = vector(requirements(Resource::Daemon));
    ordinary_in_daemon.insert(13, authority[15].clone());
    assert!(decode(requirements(Resource::Daemon), ordinary_in_daemon).is_err());
}

#[test]
fn wire_shapes_are_exactly_the_frozen_descriptor_fields() {
    let all = Requirements::Daemon {
        admin_tls: true,
        backup_s3: true,
        file_key: true,
    };
    let fields = vector(all);
    for field in &fields[13..] {
        let class = field["class"].as_str().unwrap();
        let mut keys: Vec<_> = field
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        let expected: &[&str] = match class {
            "transition-server-key" | "transition-client-key" | "daemon-api-key" => {
                &["bytes", "class", "spki"]
            }
            "local-pool-key" => &["bytes", "class", "key_id"],
            _ => &["bytes", "class", "digest"],
        };
        assert_eq!(keys, expected, "{class}");
    }
    let refuses = |index: usize, alter: fn(&mut serde_json::Value)| {
        let mut invalid = fields.clone();
        alter(&mut invalid[index]);
        assert!(decode(all, invalid).is_err(), "{index}");
    };
    for index in [15, 17] {
        refuses(index, |key| {
            let spki = key.as_object_mut().unwrap().remove("spki").unwrap();
            key["digest"] = spki;
        });
        refuses(index, |key| {
            key["digest"] = serde_json::json!(HexDigest::of(b"private"))
        });
        refuses(index, |key| key["spki"] = "not-a-digest".into());
    }
    for index in [13, 14, 16, 18, 20] {
        refuses(index, |cert| {
            let digest = cert.as_object_mut().unwrap().remove("digest").unwrap();
            cert["spki"] = digest;
        });
        refuses(index, |cert| cert["extra"] = true.into());
    }
    refuses(21, |key| {
        let id = key.as_object_mut().unwrap().remove("key_id").unwrap();
        key["digest"] = id;
    });
    for bad in [
        "".to_owned(),
        "0".repeat(31),
        "0".repeat(33),
        "A".repeat(32),
        "g".repeat(32),
        format!("{} ", "0".repeat(31)),
    ] {
        let mut invalid = fields.clone();
        invalid[21]["key_id"] = bad.into();
        assert!(decode(all, invalid).is_err());
    }
    let mut padded = fields.clone();
    padded[21]["key_id"] = HexDigest::of(b"digest, not an id").as_str().into();
    assert!(
        decode(all, padded).is_err(),
        "a 64-hex digest is not a key id"
    );
}

#[test]
fn per_class_lengths_are_exact_at_the_boundaries() {
    let all = Requirements::Daemon {
        admin_tls: true,
        backup_s3: true,
        file_key: true,
    };
    let fields = vector(all);
    let at = |index: usize, bytes: u64| {
        let mut invalid = fields.clone();
        invalid[index]["bytes"] = bytes.into();
        decode(all, invalid)
    };
    let limit = MAX_MESSAGE_BYTES as u64;
    assert!(at(10, 32).is_ok());
    for bad in [0, 1, 31, 33, 64, 83] {
        assert!(at(10, bad).is_err(), "signer {bad}");
    }
    assert!(at(21, 64).is_ok());
    for bad in [0, 32, 63, 65, 128] {
        assert!(at(21, bad).is_err(), "pool key {bad}");
    }
    assert!(at(13, 1).is_ok() && at(13, limit).is_ok(), "registry");
    assert!(at(13, 0).is_err() && at(13, limit + 1).is_err());
    for cert in [14, 16] {
        assert!(at(cert, 1).is_ok() && at(cert, 4096).is_ok());
        assert!(
            at(cert, 0).is_err() && at(cert, 4097).is_err(),
            "transition cert"
        );
    }
    for key in [15, 17, 19] {
        assert!(at(key, 1).is_ok() && at(key, 512).is_ok());
        assert!(
            at(key, 0).is_err() && at(key, 513).is_err(),
            "tls key {key}"
        );
    }
    assert!(
        at(18, 1).is_ok() && at(18, limit).is_ok(),
        "daemon API certificate"
    );
    assert!(at(20, 1).is_ok() && at(20, limit).is_ok(), "s3 pair");
    assert!(at(20, 0).is_err() && at(20, limit + 1).is_err());
    let authority = vector(Requirements::Authority);
    let bearer = |bytes: u64| {
        let mut invalid = authority.clone();
        invalid[21]["bytes"] = bytes.into();
        decode(Requirements::Authority, invalid)
    };
    assert!(bearer(1).is_ok() && bearer(4096).is_ok());
    assert!(
        bearer(0).is_err() && bearer(4097).is_err(),
        "continuation bearer"
    );
}

#[test]
fn old_mixed_and_unknown_asset_versions_never_decode() {
    let fields = vector(Requirements::Authority);
    for format in [
        "native.assets/v1",
        "native.assets/v2",
        "native.assets/v4",
        "native.assets",
        "native.prepare/v3",
        "",
    ] {
        let wire = briqyard_api::execution::sealed::encode(
            &serde_json::json!({"format": format, "assets": fields}),
        )
        .unwrap();
        assert!(
            AssetOffer::decode(Requirements::Authority, &wire).is_err(),
            "{format}"
        );
    }
    assert!(decode(Requirements::Authority, fields).is_ok());
}

#[test]
fn a_full_offer_fits_one_custody_packet() {
    for requirements in [
        Requirements::Daemon {
            admin_tls: true,
            backup_s3: true,
            file_key: true,
        },
        Requirements::Authority,
    ] {
        let wire = envelope(vector(requirements));
        assert!(
            wire.len() <= briqyard_api::execution::sealed::canonical::MAX_CUSTODY_PACKET_BYTES,
            "{}",
            wire.len()
        );
    }
}
