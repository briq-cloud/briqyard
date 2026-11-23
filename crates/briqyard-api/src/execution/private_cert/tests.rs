use super::*;
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
};

fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match body.len() {
        0..=0x7f => out.push(body.len() as u8),
        0x80..=0xff => out.extend([0x81, body.len() as u8]),
        _ => out.extend([0x82, (body.len() >> 8) as u8, body.len() as u8]),
    }
    out.extend_from_slice(body);
    out
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// Bytes appended at one nesting level of one certificate element. `outer` follows the
/// element's own SEQUENCE inside its wrapper; `inner` sits inside that SEQUENCE.
#[derive(Default, Clone, Copy)]
struct Tails {
    wrapper_outer: &'static [u8],
    extensions_inner: &'static [u8],
    san_outer: &'static [u8],
    san_inner: &'static [u8],
    eku_outer: &'static [u8],
    eku_inner: &'static [u8],
    basic_outer: &'static [u8],
    basic_inner: &'static [u8],
    empty_validity: bool,
    no_extensions: bool,
    empty_extensions: bool,
    empty_issuer_rdn: bool,
    empty_subject_rdn: bool,
    explicit_default_critical: bool,
}

struct Built {
    der: Vec<u8>,
    pkcs8: Vec<u8>,
}

fn extension(id: &[u8], value: &[u8]) -> Vec<u8> {
    der(SEQUENCE, &cat(&[&der(OID, id), &der(OCTET_STRING, value)]))
}

/// A leaf of the exact profile, assembled and signed by hand so any one element can be made
/// non-minimal while the signature stays valid.
fn build(usage: Usage, tails: Tails, with_basic: bool) -> Built {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .unwrap()
        .as_ref()
        .to_vec();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8, &rng).unwrap();
    let spki = cat(&[
        &SPKI_PREFIX[..SPKI_PREFIX.len() - 1],
        key.public_key().as_ref(),
    ]);
    let algorithm = der(SEQUENCE, &der(OID, ECDSA_SHA256));
    let element = |inner: &[u8], outer: &[u8], body: &[u8]| {
        cat(&[&der(SEQUENCE, &cat(&[body, inner])), outer])
    };
    let san = element(
        tails.san_inner,
        tails.san_outer,
        &der(DNS_NAME, b"node.example"),
    );
    let oid = match usage {
        Usage::Server => SERVER_AUTH,
        Usage::Client => CLIENT_AUTH,
    };
    let eku = element(tails.eku_inner, tails.eku_outer, &der(OID, oid));
    let san_extension = if tails.explicit_default_critical {
        der(
            SEQUENCE,
            &cat(&[
                &der(OID, SAN),
                &der(BOOLEAN, &[0x00]),
                &der(OCTET_STRING, &san),
            ]),
        )
    } else {
        extension(SAN, &san)
    };
    let mut extensions = cat(&[&san_extension, &extension(EKU, &eku)]);
    if with_basic {
        extensions.extend(extension(
            BASIC,
            &element(tails.basic_inner, tails.basic_outer, &[]),
        ));
    }
    let name = |empty_rdn: bool| {
        der(
            SEQUENCE,
            &if empty_rdn { der(SET, &[]) } else { Vec::new() },
        )
    };
    let extensions_field = if tails.no_extensions {
        Vec::new()
    } else if tails.empty_extensions {
        der(EXTENSIONS, &der(SEQUENCE, &[]))
    } else {
        der(
            EXTENSIONS,
            &cat(&[
                &der(SEQUENCE, &cat(&[&extensions, tails.extensions_inner])),
                tails.wrapper_outer,
            ]),
        )
    };
    let tbs = der(
        SEQUENCE,
        &cat(&[
            &der(VERSION, &[0x02, 0x01, 0x02]),
            &der(INTEGER, &[0x01]),
            &algorithm,
            &name(tails.empty_issuer_rdn),
            &if tails.empty_validity {
                der(SEQUENCE, &[])
            } else {
                der(
                    SEQUENCE,
                    &cat(&[
                        &der(UTC_TIME, b"250101000000Z"),
                        &der(UTC_TIME, b"350101000000Z"),
                    ]),
                )
            },
            &name(tails.empty_subject_rdn),
            &spki,
            &extensions_field,
        ]),
    );
    let signature = key.sign(&rng, &tbs).unwrap();
    let der = der(
        SEQUENCE,
        &cat(&[
            &tbs,
            &algorithm,
            &der(BIT_STRING, &cat(&[&[0], signature.as_ref()])),
        ]),
    );
    Built { der, pkcs8 }
}

const SET: u8 = 0x31;

const TRAILING: [&[u8]; 2] = [&[0x00], &[0x30, 0x00]];

#[test]
fn the_hand_built_leaf_is_the_profile_for_both_usages_and_with_basic_constraints() {
    for (usage, with_basic) in [
        (Usage::Server, false),
        (Usage::Server, true),
        (Usage::Client, true),
    ] {
        let built = build(usage, Tails::default(), with_basic);
        let leaf = parse(&built.der, usage).unwrap();
        assert_eq!(leaf.name, Name::dns("node.example").unwrap());
        assert_eq!(
            leaf.spki_digest(),
            key_spki_digest(&built.pkcs8).unwrap(),
            "{usage:?}"
        );
    }
}

#[test]
fn trailing_bytes_after_any_nested_element_are_refused_at_both_levels() {
    let mut accepted = Vec::new();
    for tail in TRAILING {
        let sites: [(&str, Tails, CertError); 8] = [
            (
                "[3] wrapper after the extension list",
                Tails {
                    wrapper_outer: tail,
                    ..Tails::default()
                },
                CertError::Encoding,
            ),
            (
                "inside the extension list",
                Tails {
                    extensions_inner: tail,
                    ..Tails::default()
                },
                CertError::Encoding,
            ),
            (
                "SAN value after its sequence",
                Tails {
                    san_outer: tail,
                    ..Tails::default()
                },
                CertError::Encoding,
            ),
            (
                "SAN sequence after its name",
                Tails {
                    san_inner: tail,
                    ..Tails::default()
                },
                CertError::Encoding,
            ),
            (
                "EKU value after its sequence",
                Tails {
                    eku_outer: tail,
                    ..Tails::default()
                },
                CertError::Encoding,
            ),
            (
                "EKU sequence after its usage",
                Tails {
                    eku_inner: tail,
                    ..Tails::default()
                },
                CertError::Encoding,
            ),
            (
                "basic constraints value after its sequence",
                Tails {
                    basic_outer: tail,
                    ..Tails::default()
                },
                CertError::Encoding,
            ),
            (
                "basic constraints sequence with content",
                Tails {
                    basic_inner: tail,
                    ..Tails::default()
                },
                CertError::Profile,
            ),
        ];
        for (site, tails, refusal) in sites {
            let built = build(Usage::Server, tails, true);
            if parse(&built.der, Usage::Server).map(|_| ()) != Err(refusal) {
                accepted.push(format!("{site}: {tail:?}"));
            }
        }
    }
    assert!(accepted.is_empty(), "not refused: {accepted:#?}");
}

#[test]
fn an_ordinary_leaf_yields_its_spki_digest_only_as_one_complete_object() {
    let built = build(Usage::Server, Tails::default(), true);
    let spki = key_spki_digest(&built.pkcs8).unwrap();
    assert_eq!(leaf_spki_digest(&built.der).unwrap(), spki);

    let mut trailing = built.der.clone();
    trailing.push(0);
    let doubled = cat(&[&built.der, &built.der]);
    let mut inside = built.der.clone();
    inside.truncate(built.der.len() - 1);
    let mut garbage = built.der.clone();
    garbage[0] = 0x31;
    for (case, bytes) in [
        ("trailing byte", trailing),
        ("two certificates", doubled),
        ("truncated", inside),
        ("not a sequence", garbage),
        ("empty", Vec::new()),
    ] {
        assert!(leaf_spki_digest(&bytes).is_err(), "{case}");
    }
}

#[test]
fn a_validly_signed_leaf_with_an_empty_validity_is_not_a_certificate_at_all() {
    let tails = Tails {
        empty_validity: true,
        ..Tails::default()
    };
    let built = build(Usage::Server, tails, true);
    assert_eq!(
        parse(&built.der, Usage::Server).map(|_| ()),
        Err(CertError::Encoding),
        "the profile parser refuses it"
    );
    assert_eq!(
        leaf_spki_digest(&built.der),
        Err(CertError::Encoding),
        "so does the ordinary schema decode"
    );
    let control = build(Usage::Server, Tails::default(), true);
    assert_eq!(
        leaf_spki_digest(&control.der).unwrap(),
        key_spki_digest(&control.pkcs8).unwrap(),
        "the same builder without the defect is accepted and carries its key"
    );
}

#[test]
fn the_ordinary_decode_is_canonical_and_refuses_structurally_empty_elements() {
    let reference = |tails: Tails| {
        let built = build(Usage::Server, tails, true);
        (
            leaf_spki_digest(&built.der),
            key_spki_digest(&built.pkcs8).unwrap(),
        )
    };
    for (case, tails) in [
        ("extensions and empty names", Tails::default()),
        (
            "no extensions at all",
            Tails {
                no_extensions: true,
                ..Tails::default()
            },
        ),
    ] {
        let (digest, expected) = reference(tails);
        assert_eq!(digest, Ok(expected), "{case}");
    }
    let mut accepted = Vec::new();
    for (case, tails) in [
        (
            "an extension list present but empty",
            Tails {
                empty_extensions: true,
                ..Tails::default()
            },
        ),
        (
            "an issuer RDN set with no attribute",
            Tails {
                empty_issuer_rdn: true,
                ..Tails::default()
            },
        ),
        (
            "a subject RDN set with no attribute",
            Tails {
                empty_subject_rdn: true,
                ..Tails::default()
            },
        ),
        (
            "a default critical FALSE encoded",
            Tails {
                explicit_default_critical: true,
                ..Tails::default()
            },
        ),
    ] {
        if reference(tails).0 != Err(CertError::Encoding) {
            accepted.push(case);
        }
    }
    assert!(accepted.is_empty(), "not refused: {accepted:#?}");
}
