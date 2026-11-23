use super::{pki::*, *};
use crate::execution_service::protected::transport::{
    cert::{self, CertError, Usage},
    Name,
};
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, CustomExtension, ExtendedKeyUsagePurpose,
    IsCa, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ED25519,
};

fn server(name: &Name) -> Issued {
    issue(name, Usage::Server)
}

fn ip() -> Name {
    Name::Ip(LOOPBACK)
}

fn refused(issued: &Issued, usage: Usage) -> CertError {
    cert::verify(&issued.cert, &issued.pair(), usage).unwrap_err()
}

#[test]
fn a_conforming_server_and_client_leaf_is_accepted_with_its_name_and_validity() {
    let server = server(&ip());
    let leaf = cert::verify(&server.cert, &server.pair(), Usage::Server).unwrap();
    assert_eq!(leaf.name, ip());
    assert_eq!(leaf.spki_digest(), server.pair().spki);
    let name = Name::dns("h-1.peer.test").unwrap();
    let client = issue(&name, Usage::Client);
    let leaf = cert::verify(&client.cert, &client.pair(), Usage::Client).unwrap();
    assert_eq!(leaf.name, name);
    let ipv6 = issue(&Name::Ip("::1".parse().unwrap()), Usage::Server);
    assert_eq!(
        cert::verify(&ipv6.cert, &ipv6.pair(), Usage::Server)
            .unwrap()
            .name,
        Name::Ip("::1".parse().unwrap())
    );
}

#[test]
fn a_server_leaf_is_not_a_client_leaf_and_the_reverse() {
    let name = Name::dns("peer.test").unwrap();
    assert_eq!(
        refused(&issue(&name, Usage::Server), Usage::Client),
        CertError::Profile
    );
    assert_eq!(
        refused(&issue(&name, Usage::Client), Usage::Server),
        CertError::Profile
    );
    let both = issue_with(&name, Usage::Server, |p| {
        p.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ]
    });
    assert_eq!(refused(&both, Usage::Server), CertError::Encoding);
    let any = issue_with(&name, Usage::Server, |p| {
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::Any]
    });
    assert_eq!(refused(&any, Usage::Server), CertError::Profile);
    let none = issue_with(&name, Usage::Server, |p| p.extended_key_usages = vec![]);
    assert_eq!(refused(&none, Usage::Server), CertError::Profile);
}

#[test]
fn san_must_be_one_exact_non_wildcard_name() {
    let name = Name::dns("peer.test").unwrap();
    let with = |names: Vec<rcgen::SanType>| {
        issue_with(&name, Usage::Server, |p| p.subject_alt_names = names)
    };
    let dns = |text: &str| rcgen::SanType::DnsName(text.try_into().unwrap());
    assert_eq!(refused(&with(vec![]), Usage::Server), CertError::Name);
    assert_eq!(
        refused(&with(vec![dns("*.peer.test")]), Usage::Server),
        CertError::Name
    );
    assert_eq!(
        refused(&with(vec![dns("Peer.test")]), Usage::Server),
        CertError::Name
    );
    assert_eq!(
        refused(&with(vec![dns("peer.test."),]), Usage::Server),
        CertError::Name
    );
    assert_eq!(
        refused(&with(vec![dns("a.test"), dns("b.test")]), Usage::Server),
        CertError::Encoding
    );
    assert_eq!(
        refused(
            &with(vec![rcgen::SanType::Rfc822Name(
                "a@b.test".try_into().unwrap()
            )]),
            Usage::Server
        ),
        CertError::Name
    );
}

#[test]
fn keys_other_than_p256_and_non_self_signed_or_ca_leaves_are_refused() {
    let name = ip();
    for algorithm in [&PKCS_ECDSA_P384_SHA384, &PKCS_ED25519] {
        let key = KeyPair::generate_for(algorithm).unwrap();
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![san(&name)];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = date_time_ymd(2026, 1, 1);
        params.not_after = date_time_ymd(2030, 1, 1);
        let cert = params.self_signed(&key).unwrap();
        let der = cert.der().to_vec();
        assert!(cert::parse(&der, Usage::Server).is_err());
    }
    let ca = issue_with(&name, Usage::Server, ca_flags);
    assert_eq!(refused(&ca, Usage::Server), CertError::Profile);

    let issuer_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut issuer_params = CertificateParams::default();
    issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let issuer = issuer_params.self_signed(&issuer_key).unwrap();
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![san(&name)];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let signed = params.signed_by(&key, &issuer, &issuer_key).unwrap();
    assert!(cert::parse(signed.der(), Usage::Server).is_err());

    let custom = issue_with(&name, Usage::Server, |p| {
        p.custom_extensions
            .push(CustomExtension::from_oid_content(&[1, 2, 3, 4], vec![5, 0]))
    });
    assert_eq!(refused(&custom, Usage::Server), CertError::Profile);
}

#[test]
fn validity_needs_the_whole_qualified_interval_inside_the_certificate() {
    let issued = server(&ip());
    let leaf = cert::verify(&issued.cert, &issued.pair(), Usage::Server).unwrap();
    for (clock, ok) in [
        (TestClock::at(2026, 11, 23), true),
        (TestClock::at(2026, 1, 1), false),
        (TestClock::at(2025, 12, 31), false),
        (TestClock::at(2030, 1, 1), false),
        (TestClock::at(2031, 1, 1), false),
    ] {
        assert_eq!(leaf.valid_at(clock.as_ref()).is_ok(), ok);
    }
    let edge = TestClock::at(2030, 1, 1);
    edge.set(Some(date_time_ymd(2030, 1, 1).unix_timestamp() as u64 - 2));
    assert!(leaf.valid_at(edge.as_ref()).is_ok());
    edge.set(Some(date_time_ymd(2030, 1, 1).unix_timestamp() as u64 - 1));
    assert!(leaf.valid_at(edge.as_ref()).is_ok());
    edge.set(Some(date_time_ymd(2030, 1, 1).unix_timestamp() as u64));
    assert_eq!(leaf.valid_at(edge.as_ref()), Err(CertError::Time));
    edge.set(None);
    assert_eq!(leaf.valid_at(edge.as_ref()), Err(CertError::Time));
}

#[test]
fn the_pin_is_checked_before_the_certificate_is_read() {
    let issued = server(&ip());
    let other = server(&ip());
    let pair = issued.pair();
    assert_eq!(
        cert::verify(&other.cert, &pair, Usage::Server).unwrap_err(),
        CertError::Pin
    );
    let mut wrong_key = pair.clone();
    wrong_key.spki = other.pair().spki;
    assert_eq!(
        cert::verify(&issued.cert, &wrong_key, Usage::Server).unwrap_err(),
        CertError::Pin
    );
    let garbage = vec![0x30, 0x80, 0x00];
    assert_eq!(
        cert::verify(&garbage, &pair, Usage::Server).unwrap_err(),
        CertError::Pin
    );
}

#[test]
fn malformed_encodings_are_refused_without_panicking() {
    let issued = server(&ip());
    let der = &issued.cert;
    assert!(cert::parse(der, Usage::Server).is_ok());
    let mut trailing = der.clone();
    trailing.push(0);
    assert!(cert::parse(&trailing, Usage::Server).is_err());
    for end in 0..der.len() {
        assert!(cert::parse(&der[..end], Usage::Server).is_err(), "{end}");
    }
    for index in 0..der.len() {
        for flip in [0x01, 0x80, 0xff] {
            let mut copy = der.clone();
            copy[index] ^= flip;
            let _ = cert::parse(&copy, Usage::Server);
            assert!(cert::verify(&copy, &issued.pair(), Usage::Server).is_err());
        }
    }
    let mut indefinite = der.clone();
    indefinite[1] = 0x80;
    assert!(cert::parse(&indefinite, Usage::Server).is_err());
    assert!(cert::parse(&vec![0x30; 5000], Usage::Server).is_err());
}
