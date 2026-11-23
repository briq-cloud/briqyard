use super::*;

fn profile(seed: u8) -> Vec<u8> {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
    let mut bytes = hex::decode("3051020101300506032b657004220420").unwrap();
    bytes.extend([seed; 32]);
    bytes.extend([0x81, 0x21, 0x00]);
    bytes.extend(pair.public_key().as_ref());
    assert_eq!(bytes.len(), PKCS8_BYTES);
    bytes
}

#[test]
fn profile_accepts_exactly_the_canonical_83_byte_v2_form_and_derives_the_public_key() {
    let bytes = profile(7);
    let key = OrdinaryAuthorityKey::from_profile(&bytes).unwrap();
    assert_eq!(key.public().as_slice(), &bytes[51..]);
    let pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    assert_eq!(key.public().as_slice(), pair.public_key().as_ref());
    assert_eq!(format!("{key:?}"), "OrdinaryAuthorityKey(..)");
}

#[test]
fn profile_rejects_every_alternate_or_inconsistent_encoding() {
    let good = profile(7);
    let other = profile(8);
    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("seed only", good[16..48].to_vec()),
        ("truncated", good[..82].to_vec()),
        ("trailing byte", [good.clone(), vec![0]].concat()),
        (
            "pem",
            b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n".to_vec(),
        ),
        (
            "v1 without public",
            [&good[..2], &[0x2e], &good[3..5], &[0], &good[6..48]].concat(),
        ),
        (
            "public of another key",
            [&good[..51], &other[51..]].concat(),
        ),
        ("seed of another key", [&other[..48], &good[48..]].concat()),
    ];
    let mut flipped = good.clone();
    flipped[60] ^= 1;
    cases.push(("flipped embedded public", flipped));
    for index in 0..48 {
        let mut altered = good.clone();
        if index >= 16 {
            continue;
        }
        altered[index] ^= 1;
        cases.push(("altered fixed prefix", altered));
    }
    for index in 48..51 {
        let mut altered = good.clone();
        altered[index] ^= 1;
        cases.push(("altered public wrapper", altered));
    }
    let mut constructed = good[..48].to_vec();
    constructed[1] = 0x53;
    constructed.extend([0xa1, 0x23, 0x03, 0x21, 0x00]);
    constructed.extend(&good[51..]);
    cases.push(("ring legacy constructed public form", constructed));
    let mut encrypted = vec![0x30, 0x81, 0x80, 0x30, 0x1b];
    encrypted.extend(&good[5..]);
    cases.push(("encrypted-looking container", encrypted));
    for (name, bytes) in cases {
        assert_eq!(
            OrdinaryAuthorityKey::from_profile(&bytes).unwrap_err(),
            KeyError::Profile,
            "{name}"
        );
    }
}

#[test]
fn errors_carry_what_failed_and_never_key_bytes() {
    let bytes = profile(9);
    let mut wrong = bytes.clone();
    wrong[60] ^= 1;
    let error = OrdinaryAuthorityKey::from_profile(&wrong).unwrap_err();
    let text = format!("{error} {error:?}");
    assert!(!text.contains(&hex::encode(&bytes[16..48])));
    assert!(!text.contains(&hex::encode(&bytes[51..])));
}

#[cfg(target_os = "linux")]
mod linux;
