//! Refusals: before and after validation, at the byte level, the schema level and the
//! signature level. Each case names the contract clause it comes from.

use super::trial::{trial, TRIAL_C};
use super::vectors::{query_envelope_text, QUERY_BODY, QUERY_SIG};
use super::*;
use crate::execution::sealed::canonical::{
    decode, decode_with, encode, parse_strict, CodecError, Limits,
};
use crate::execution::sealed::objects::{ProofQuery, Reg};
use crate::execution::sealed::sig::{PinnedKey, Role, Sig, SigError, Signer, Tag};
use crate::execution::sealed::trial::{
    trial_timeout_ms, Origin, TimeoutRefused, Trial, TrialRequest,
};
use ed25519_dalek::VerifyingKey;

type Query = Sig<ProofQuery>;

fn rk() -> PinnedKey {
    TestSigner::rk().pinned(Role::Rk)
}

fn mutate(from: &str, to: &str) -> String {
    let text = query_envelope_text();
    assert!(text.contains(from), "fixture lacks {from}");
    text.replacen(from, to, 1)
}

fn query(text: &str) -> Result<Query, CodecError> {
    decode(text.as_bytes())
}

#[test]
fn the_unmodified_envelope_is_the_control() {
    let signed = query(&query_envelope_text()).unwrap();
    signed.verify(Tag::QueryHost, &rk()).unwrap();
}

#[test]
fn an_altered_tag_fails_before_and_after_validation() {
    let text = mutate("query.host", "query.authority");
    assert_eq!(
        Sig::<ProofQuery>::decode(text.as_bytes(), Tag::QueryHost),
        Err(SigError::WrongTag)
    );
    let relabeled = query(&text).unwrap();
    assert_eq!(
        relabeled.verify(Tag::QueryHost, &rk()),
        Err(SigError::WrongTag)
    );
    assert_eq!(
        relabeled.verify(Tag::QueryAuthority, &rk()),
        Err(SigError::BadSignature)
    );
    let unknown = mutate("query.host", "query.other");
    assert_eq!(query(&unknown), Err(CodecError::Schema));
}

#[test]
fn an_altered_key_or_role_or_body_does_not_verify() {
    let kid = mutate("9\",\"sig\"", "8\",\"sig\"");
    assert_eq!(
        query(&kid).unwrap().verify(Tag::QueryHost, &rk()),
        Err(SigError::KeyMismatch)
    );
    let other_key = TestSigner::bk().pinned(Role::Bk);
    assert_eq!(
        query(&query_envelope_text())
            .unwrap()
            .verify(Tag::QueryHost, &other_key),
        Err(SigError::KeyMismatch)
    );
    let wrong_role = PinnedKey::new(Role::Hk, TestSigner::rk().public_key()).unwrap();
    assert_eq!(
        query(&query_envelope_text())
            .unwrap()
            .verify(Tag::QueryHost, &wrong_role),
        Err(SigError::RoleNotPermitted)
    );
    let body = mutate("\"serial\":1", "\"serial\":2");
    assert_eq!(
        query(&body).unwrap().verify(Tag::QueryHost, &rk()),
        Err(SigError::BadSignature)
    );
}

#[test]
fn a_signature_that_is_not_canonical_or_not_a_signature_does_not_verify() {
    let signed = query(&query_envelope_text()).unwrap();
    let mut forged = signed.clone();
    let mut sig = *forged.sig.as_array();
    let mut carry = 0u16;
    const ELL: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    for i in 0..32 {
        let sum = u16::from(sig[32 + i]) + u16::from(ELL[i]) + carry;
        sig[32 + i] = sum as u8;
        carry = sum >> 8;
    }
    forged.sig = Bytes::from_array(sig);
    assert_eq!(
        forged.verify(Tag::QueryHost, &rk()),
        Err(SigError::BadSignature)
    );

    let mut zero = signed.clone();
    zero.sig = Bytes::from_array([0u8; 64]);
    assert_eq!(
        zero.verify(Tag::QueryHost, &rk()),
        Err(SigError::BadSignature)
    );
    let mut small_order_r = signed;
    let mut raw = *small_order_r.sig.as_array();
    raw[..32].copy_from_slice(
        &hex::decode("0100000000000000000000000000000000000000000000000000000000000000").unwrap(),
    );
    small_order_r.sig = Bytes::from_array(raw);
    assert_eq!(
        small_order_r.verify(Tag::QueryHost, &rk()),
        Err(SigError::BadSignature)
    );
}

#[test]
fn nested_duplicates_and_reordered_keys_are_refused() {
    let dup = mutate("\"serial\":1}", "\"serial\":1,\"serial\":1}");
    assert_eq!(query(&dup), Err(CodecError::DuplicateKey));
    let top = query_envelope_text().replacen("{\"body\"", "{\"tag\":\"query.host\",\"body\"", 1);
    assert_eq!(query(&top), Err(CodecError::UnsortedKeys));
    let swapped = format!(
        r#"{{"body":{QUERY_BODY},"sig":"{QUERY_SIG}","kid":"{}","tag":"query.host"}}"#,
        "21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9"
    );
    assert_eq!(query(&swapped), Err(CodecError::UnsortedKeys));
    assert_eq!(
        parse_strict(br#"{"a":1,"a":2}"#, Limits::MESSAGE),
        Err(CodecError::DuplicateKey)
    );
    assert_eq!(
        parse_strict(br#"{"b":1,"a":2}"#, Limits::MESSAGE),
        Err(CodecError::UnsortedKeys)
    );
}

#[test]
fn only_canonical_bytes_decode() {
    let ok = query_envelope_text();
    for (name, text) in [
        ("trailing newline", format!("{ok}\n")),
        ("leading newline", format!("\n{ok}")),
        ("space", ok.replacen("{\"body\":", "{\"body\": ", 1)),
        ("space after comma", ok.replacen(",\"kid\"", ", \"kid\"", 1)),
        ("bom", format!("\u{feff}{ok}")),
        ("trailing bytes", format!("{ok}{{}}")),
        ("float", mutate("\"serial\":1", "\"serial\":1.0")),
        ("exponent", mutate("\"serial\":1", "\"serial\":1e0")),
        ("leading zero", mutate("\"serial\":1", "\"serial\":01")),
        ("negative zero", mutate("\"serial\":1", "\"serial\":-0")),
        ("negative", mutate("\"serial\":1", "\"serial\":-1")),
        ("plus", mutate("\"serial\":1", "\"serial\":+1")),
        ("zero is not P", mutate("\"serial\":1", "\"serial\":0")),
        (
            "above safe",
            mutate("\"serial\":1", "\"serial\":9007199254740992"),
        ),
        ("string integer", mutate("\"serial\":1", "\"serial\":\"1\"")),
        ("null integer", mutate("\"serial\":1", "\"serial\":null")),
        (
            "u escape",
            mutate(r#""host":"host.test""#, r#""host":"\u0068ost.test""#),
        ),
        (
            "slash escape",
            mutate(r#""host":"host.test""#, r#""host":"host\/test""#),
        ),
        (
            "non-ascii",
            mutate(r#""host":"host.test""#, "\"host\":\"h\u{f3}st.test\""),
        ),
        (
            "control byte",
            mutate(r#""host":"host.test""#, "\"host\":\"host\u{1}test\""),
        ),
        (
            "space in id",
            mutate(r#""host":"host.test""#, r#""host":"host test""#),
        ),
        ("empty id", mutate(r#""host":"host.test""#, r#""host":"""#)),
        ("unknown environment", mutate("\"staging\"", "\"Staging\"")),
        (
            "unknown field",
            mutate(
                "\"tag\":\"query.host\"}",
                "\"tag\":\"query.host\",\"zz\":1}",
            ),
        ),
        ("missing nullable", mutate("\"preview\":null,", "")),
        (
            "missing field",
            mutate(
                "\"kid\":\"21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9\",",
                "",
            ),
        ),
        (
            "array as object",
            mutate(
                r#""x":{"aud":"staging","host":"host.test","op":"0000000000000000000000000000000000000000000000000000000000000000","serial":1}"#,
                r#""x":["staging","host.test","0000000000000000000000000000000000000000000000000000000000000000",1]"#,
            ),
        ),
        (
            "uppercase digest",
            mutate("\"plan\":\"1111", "\"plan\":\"AAAA"),
        ),
        ("short digest", mutate("\"plan\":\"1111", "\"plan\":\"111")),
    ] {
        assert!(query(&text).is_err(), "{name} must be refused");
    }
}

#[test]
fn base64url_is_strict() {
    let ok = n(0).to_text();
    assert_eq!(ok.len(), 43);
    assert_eq!(Nonce::parse(&ok), Ok(n(0)));
    for (name, text) in [
        ("padded", format!("{ok}=")),
        ("padded and short", format!("{}==", &ok[..42])),
        ("short", ok[..42].to_owned()),
        ("long", format!("{ok}A")),
        ("empty", String::new()),
        ("nonzero residual bits", format!("{}B", &ok[..42])),
        ("standard plus", format!("{}+", &ok[..42])),
        ("standard slash", format!("{}/", &ok[..42])),
        ("newline", format!("{}\n", &ok[..42])),
        ("whitespace", format!("{} ", &ok[..42])),
    ] {
        assert!(Nonce::parse(&text).is_err(), "{name} must be refused");
    }
    assert!(
        Nonce::parse(&format!("{}E", &ok[..42])).is_ok(),
        "zero residual bits are fine"
    );
    let sig = QUERY_SIG;
    assert_eq!(sig.len(), 86);
    assert!(SigBytes::parse(sig).is_ok());
    assert!(SigBytes::parse(&format!("{sig}==")).is_err());
    assert!(SigBytes::parse(&format!("{}B", &sig[..85])).is_err());
    assert!(query(&mutate(QUERY_SIG, &format!("{}B", &QUERY_SIG[..85]))).is_err());
    assert!(query(&mutate(QUERY_SIG, &format!("{QUERY_SIG}=="))).is_err());
}

#[test]
fn identifier_uuid_and_integer_domains_are_exact() {
    assert!(Ident::new("a".repeat(128)).is_ok());
    for bad in [
        "",
        "a b",
        "a\u{e9}",
        "a+b",
        "a@b",
        "a\"b",
        "a\\b",
        &"a".repeat(129),
    ] {
        assert!(Ident::new(bad).is_err(), "{bad:?}");
    }
    assert!(Build::new("fence-3+x").is_ok());
    assert!(
        Build::new("").is_err()
            && Build::new("a b").is_err()
            && Build::new("a".repeat(129)).is_err()
    );
    assert!(Ident::new("a+b").is_err());
    assert!(BootId::new("00000000-0000-4000-8000-000000000004").is_ok());
    assert!(
        BootId::new("00000000-0000-1000-c000-000000000004").is_ok(),
        "boot IDs are any lowercase UUID text"
    );
    for bad in [
        "00000000-0000-4000-8000-00000000000A",
        "0000000000004000800000000000000004",
        "00000000-0000-4000-8000-0000000000044",
        "{00000000-0000-4000-8000-000000000004}",
    ] {
        assert!(BootId::new(bad).is_err(), "{bad}");
    }
    assert!(V4::new("00000000-0000-4000-8000-000000000001").is_ok());
    assert!(V4::new("00000000-0000-4000-b000-000000000001").is_ok());
    for bad in [
        "00000000-0000-1000-8000-000000000001",
        "00000000-0000-5000-8000-000000000001",
        "00000000-0000-4000-c000-000000000001",
        "00000000-0000-4000-7000-000000000001",
        "00000000-0000-4000-8000-00000000000A",
    ] {
        assert!(V4::new(bad).is_err(), "{bad}");
    }
    assert!(Uint::new(0).is_ok() && Uint::new(9_007_199_254_740_991).is_ok());
    assert!(Uint::new(9_007_199_254_740_992).is_err() && PosInt::new(0).is_err());
    assert!(crate::execution::sealed::custody::Slot::new(9_007_199_254_740_992).is_err());
}

use crate::execution::sealed::prim::{BootId, Build, Ident, Nonce, PosInt, SigBytes, Uint, V4};

#[test]
fn registration_bytes_are_bounded_values() {
    let good = r#"{"authority":"auth","epoch":"ep","generation":2,"host_instance":"hi","key_id":"k","public_key":[215,90,152,1,130,177,10,183,213,75,254,211,201,100,7,58,14,225,114,243,218,166,35,37,175,2,26,104,247,7,81,26]}"#;
    assert!(decode::<Reg>(good.as_bytes()).is_ok());
    assert!(decode::<Reg>(good.replace("215,", "256,").as_bytes()).is_err());
    assert!(decode::<Reg>(good.replace("215,", "").as_bytes()).is_err());
    assert!(decode::<Reg>(good.replace("[215,", "[1,215,").as_bytes()).is_err());
    assert!(decode::<Reg>(
        good.replace("\"generation\":2", "\"generation\":0")
            .as_bytes()
    )
    .is_err());
}

#[test]
fn codec_bounds_are_explicit() {
    let nest = |levels: usize| {
        format!(
            "{{\"a\":{}1{}}}",
            "[".repeat(levels - 1),
            "]".repeat(levels - 1)
        )
    };
    assert!(parse_strict(nest(24).as_bytes(), Limits::MESSAGE).is_ok());
    assert_eq!(
        parse_strict(nest(25).as_bytes(), Limits::MESSAGE),
        Err(CodecError::TooDeep)
    );
    let array = |len: usize| format!("{{\"a\":[{}]}}", vec!["1"; len].join(","));
    assert!(parse_strict(array(256).as_bytes(), Limits::MESSAGE).is_ok());
    assert_eq!(
        parse_strict(array(257).as_bytes(), Limits::MESSAGE),
        Err(CodecError::ArrayTooLong)
    );
    let text = |len: usize| format!("{{\"a\":\"{}\"}}", "x".repeat(len - 8));
    assert!(parse_strict(text(64 * 1024).as_bytes(), Limits::MESSAGE).is_ok());
    assert_eq!(
        parse_strict(text(64 * 1024 + 1).as_bytes(), Limits::MESSAGE),
        Err(CodecError::TooLarge)
    );
    assert!(parse_strict(b"", Limits::MESSAGE).is_err());
    assert!(parse_strict(b"[]", Limits::MESSAGE).is_err());
    assert!(parse_strict(b"{\"a\":tru}", Limits::MESSAGE).is_err());
    assert!(parse_strict(b"{\"a\":[1,]}", Limits::MESSAGE).is_err());
    assert!(parse_strict(b"{\"a\":1,}", Limits::MESSAGE).is_err());
    assert!(parse_strict(b"{\"a\":\"unterminated}", Limits::MESSAGE).is_err());
    assert!(decode_with::<Reg>(
        &[b'{'; 10],
        Limits {
            max_bytes: 4,
            ..Limits::MESSAGE
        }
    )
    .is_err());
}

#[test]
fn errors_never_echo_payload() {
    let marker = "SECRETMARKERSECRETMARKERSECRETMARKERSECRETMARKERSECRETMARKER12";
    let text = mutate(
        "21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9",
        marker,
    );
    let error = query(&text).unwrap_err();
    assert!(!format!("{error} {error:?}").contains("SECRETMARKER"));
    let error = Ident::new("SECRET MARKER").unwrap_err();
    assert!(!format!("{error} {error:?}").contains("SECRET"));
    let error = HexDigest::new(marker).unwrap_err();
    assert!(!format!("{error} {error:?}").contains("SECRET"));
}

#[test]
fn weak_noncanonical_and_mixed_order_keys_are_refused() {
    let weak = [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ];
    for hex_key in weak {
        let raw: [u8; 32] = hex::decode(hex_key).unwrap().try_into().unwrap();
        assert!(
            matches!(PinnedKey::new(Role::Rk, raw), Err(SigError::InvalidKey(_))),
            "{hex_key}"
        );
    }
    let torsion = VerifyingKey::from_bytes(&hex::decode(weak[4]).unwrap().try_into().unwrap())
        .unwrap()
        .to_edwards();
    let honest = VerifyingKey::from_bytes(&TestSigner::rk().public_key())
        .unwrap()
        .to_edwards();
    let mixed = (honest + torsion).compress().to_bytes();
    assert_ne!(mixed, TestSigner::rk().public_key());
    assert!(matches!(
        PinnedKey::new(Role::Rk, mixed),
        Err(SigError::InvalidKey(_))
    ));

    let mut y = 2u8;
    let not_on_curve = loop {
        let mut raw = [0u8; 32];
        raw[0] = y;
        if VerifyingKey::from_bytes(&raw).is_err() {
            break raw;
        }
        y += 1;
    };
    assert!(matches!(
        PinnedKey::new(Role::Rk, not_on_curve),
        Err(SigError::InvalidKey(_))
    ));
    assert!(PinnedKey::new(Role::Rk, TestSigner::rk().public_key()).is_ok());
}

#[test]
fn every_small_y_and_its_non_canonical_alias_is_refused() {
    for y in 0u8..=18 {
        for sign in [0u8, 0x80] {
            let mut canonical = [0u8; 32];
            canonical[0] = y;
            canonical[31] = sign;
            let mut alias = [0xff; 32];
            alias[0] = 0xed + y;
            alias[31] = 0x7f | sign;
            for raw in [canonical, alias] {
                assert!(
                    matches!(PinnedKey::new(Role::Rk, raw), Err(SigError::InvalidKey(_))),
                    "{raw:?}"
                );
            }
        }
    }
}

fn trial_text(from: &str, to: &str) -> String {
    assert!(TRIAL_C.contains(from), "fixture lacks {from}");
    TRIAL_C.replacen(from, to, 1)
}

#[test]
fn trial_identities_and_commitments_are_validated_when_decoded() {
    assert!(decode::<Trial>(TRIAL_C.as_bytes()).is_ok());
    for (name, text) in [
        (
            "version 1 grant id",
            trial_text(
                "00000000-0000-4000-8000-000000000001",
                "00000000-0000-1000-8000-000000000001",
            ),
        ),
        (
            "variant c run",
            trial_text(
                "00000000-0000-4000-8000-000000000003",
                "00000000-0000-4000-c000-000000000003",
            ),
        ),
        (
            "uppercase uuid",
            trial_text(
                "00000000-0000-4000-8000-000000000001",
                "00000000-0000-4000-8000-00000000000A",
            ),
        ),
        (
            "grant id as delegation intent",
            trial_text(
                "\"delegation_intent\":\"00000000-0000-4000-8000-000000000002\"",
                "\"delegation_intent\":\"00000000-0000-4000-8000-000000000001\"",
            ),
        ),
        (
            "run reused as grant",
            trial_text(
                "\"run\":\"00000000-0000-4000-8000-000000000003\"",
                "\"run\":\"00000000-0000-4000-8000-000000000001\"",
            ),
        ),
        (
            "command hash not the nonce's",
            trial_text(
                "2185b234c3057b055f3b29f9a70ff91c3bf02ecbfff0e68a4a23f30528e30287",
                "0185b234c3057b055f3b29f9a70ff91c3bf02ecbfff0e68a4a23f30528e30287",
            ),
        ),
        (
            "another nonce under the same hash",
            trial_text("\"nonce\":\"AAAA", "\"nonce\":\"AAAB"),
        ),
        (
            "signing key id is not an id",
            trial_text("key.test", "key test"),
        ),
        (
            "unknown field",
            trial_text("{\"bind_hash\"", "{\"aaa\":1,\"bind_hash\""),
        ),
    ] {
        assert!(decode::<Trial>(text.as_bytes()).is_err(), "{name}");
    }
}

#[test]
fn only_the_canonical_gateway_origin_is_admitted() {
    assert!(Origin::new("https://gw.staging.example").is_ok());
    assert!(Origin::new("https://g").is_ok());
    for bad in [
        "https://gw.staging.example:443",
        "https://GW.staging.example",
        "https://gw.staging.example/",
        "https://gw.staging.example.",
        "http://gw.staging.example",
        "https://user@gw.staging.example",
        "https://gw.staging.example/path",
        "https://gw.staging.example?q=1",
        "https://gw.staging.example#f",
        "https://1.2.3.4",
        "https://[::1]",
        "https://-gw.staging.example",
        "https://gw-.staging.example",
        "https://gw..staging.example",
        "https://gw_staging.example",
        "https://",
        "https:// gw.example",
        "gw.staging.example",
        "HTTPS://gw.staging.example",
        "https://gw.staging.example\n",
    ] {
        assert!(Origin::new(bad).is_err(), "{bad}");
    }
    assert!(
        Origin::new(&format!("https://{}", "a".repeat(64))).is_err(),
        "label of 64"
    );
    assert!(
        Origin::new(&format!("https://{}", vec!["a".repeat(63); 4].join("."))).is_err(),
        "name of 255"
    );
    let other = Origin::new("https://gw.other.example").unwrap();
    assert!(trial().check_origin(&other).is_err());
}

#[test]
fn the_canary_request_admits_no_alternative() {
    let canonical = String::from_utf8(encode(&TrialRequest::for_nonce(n(0))).unwrap()).unwrap();
    assert!(decode::<TrialRequest>(canonical.as_bytes()).is_ok());
    let swap = |from: &str, to: &str| {
        assert!(canonical.contains(from), "fixture lacks {from}");
        canonical.replacen(from, to, 1)
    };
    for (name, text) in [
        ("other binary", swap("/bin/busybox", "/bin/sh")),
        ("other applet", swap("printf", "echo")),
        ("other format", swap("%s", "%s\\n")),
        (
            "shell",
            swap("[\"/bin/busybox\",\"printf\"", "[\"/bin/sh\",\"-c\""),
        ),
        (
            "extra argument",
            swap(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"]",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"x\"]",
            ),
        ),
        (
            "missing nonce",
            swap(",\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"", ""),
        ),
        (
            "non-nonce argument",
            swap("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"]", "hello\"]"),
        ),
        ("timeout 999", swap("1000", "999")),
        ("timeout 1001", swap("1000", "1001")),
        ("timeout 60000", swap("1000", "60000")),
        ("wake", swap("\"wake\":false", "\"wake\":true")),
        ("wake null", swap("\"wake\":false", "\"wake\":null")),
        ("stdin", swap("\"stdin\":\"\"", "\"stdin\":\"x\"")),
        ("stdin null", swap("\"stdin\":\"\"", "\"stdin\":null")),
        ("cwd", swap("\"cwd\":\"\"", "\"cwd\":\"/\"")),
        ("env", swap("\"env\":{}", "\"env\":{\"A\":\"b\"}")),
        ("env null", swap("\"env\":{}", "\"env\":null")),
        ("omitted wake", swap(",\"wake\":false", "")),
        ("omitted timeout", swap("\"timeout_ms\":1000,", "")),
    ] {
        assert!(decode::<TrialRequest>(text.as_bytes()).is_err(), "{name}");
    }
}

#[test]
fn the_trial_timeout_never_shortens() {
    assert_eq!(
        trial_timeout_ms(2_000_000_000, 60, 1_999_999_998_000),
        Ok(1000)
    );
    assert_eq!(
        trial_timeout_ms(2_000_000_000, 60, 1_999_999_998_001),
        Err(TimeoutRefused)
    );
    assert_eq!(
        trial_timeout_ms(2_000_000_000, 1, 1_000_000_000_000),
        Ok(1000)
    );
    assert_eq!(trial_timeout_ms(2_000_000_000, 0, 0), Err(TimeoutRefused));
    assert_eq!(trial_timeout_ms(0, 60, 0), Err(TimeoutRefused));
    assert_eq!(
        trial_timeout_ms(1, 60, 5_000_000_000_000),
        Err(TimeoutRefused)
    );
    assert_eq!(trial_timeout_ms(u64::MAX, u64::MAX, 0), Ok(1000));
    assert_eq!(trial_timeout_ms(u64::MAX, u64::MAX, u64::MAX), Ok(1000));
    assert_eq!(trial_timeout_ms(1, u64::MAX, u64::MAX), Err(TimeoutRefused));
    assert_eq!(
        trial_timeout_ms(2_000_000_000, 60, 1_999_999_997_999),
        Ok(1000)
    );
}
