//! The query.host signing vector, the native registration vectors and the key vectors.

use super::*;
use crate::execution::admission::HostRegistration;
use crate::execution::sealed::canonical::{decode, encode, h};
use crate::execution::sealed::objects::{Dims, ProofQuery, Reg, DIM_NAMES};
use crate::execution::sealed::sig::{preimage, Sig, Tag};

pub(super) const QUERY_BODY: &str = r#"{"plan":"1111111111111111111111111111111111111111111111111111111111111111","preview":null,"q":{"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","x":{"aud":"staging","host":"host.test","op":"0000000000000000000000000000000000000000000000000000000000000000","serial":1}}}"#;
pub(super) const RK_PUBLIC: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
pub(super) const BK_PUBLIC: &str = "PUAXw-hDiVqStwqnTRt-vJyYLM8uxJaMwM1V8Sr0Zgw";
pub(super) const AK_PUBLIC: &str = "_FHNjmIYoaONpH7QAjDwWAgW7RO6MwOsXeuRFUiQgCU";
pub(super) const RK_KID: &str = "21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9";
pub(super) const QUERY_SIG: &str =
    "oK7eDY0rsAdCXv-wt8cgL4I1u7xqbPUDQKBiSPsfHSUNpj5Tdeyq7t0b1D79_ZY8eBHeftc-ptF994vAXIS4AA";
const QUERY_PREIMAGE_HASH: &str =
    "250a1e17ca1d8c9c86e807d3b48529a9fe0dbe28a1e37840ee7fdaea42b4d689";
const QUERY_ENVELOPE_HASH: &str =
    "b905304fc3e6927deea1f38275b7b0b6e860fc07d82917e2b24c60346cac161b";

pub(super) fn query_envelope_text() -> String {
    format!(r#"{{"body":{QUERY_BODY},"kid":"{RK_KID}","sig":"{QUERY_SIG}","tag":"query.host"}}"#)
}

#[test]
fn rfc8032_roles_have_the_published_public_keys() {
    assert_eq!(
        Bytes::from_array(TestSigner::rk().public_key()).to_text(),
        RK_PUBLIC
    );
    assert_eq!(
        Bytes::from_array(TestSigner::bk().public_key()).to_text(),
        BK_PUBLIC
    );
    assert_eq!(
        Bytes::from_array(TestSigner::ak().public_key()).to_text(),
        AK_PUBLIC
    );
    assert_eq!(
        HexDigest::of(&TestSigner::rk().public_key()).as_str(),
        RK_KID
    );
}

#[test]
fn query_host_body_is_the_exact_canonical_bytes() {
    let body: ProofQuery = decode(QUERY_BODY.as_bytes()).unwrap();
    assert_eq!(encode(&body).unwrap(), QUERY_BODY.as_bytes());
    assert!(body.preview.is_none());
}

#[test]
fn query_host_signing_preimage_digest_signature_and_envelope() {
    let body: ProofQuery = decode(QUERY_BODY.as_bytes()).unwrap();
    let kid = HexDigest::new(RK_KID).unwrap();

    let expected_preimage = [
        &b"BRIQ-SEAL/2"[..],
        &[0],
        b"query.host",
        &[0],
        RK_KID.as_bytes(),
        &[0],
        QUERY_BODY.as_bytes(),
    ]
    .concat();
    let actual = preimage(Tag::QueryHost, &kid, QUERY_BODY.as_bytes());
    assert_eq!(actual, expected_preimage);
    assert_eq!(HexDigest::of(&actual).as_str(), QUERY_PREIMAGE_HASH);

    let signed = Sig::sign(Tag::QueryHost, body, &TestSigner::rk()).unwrap();
    assert_eq!(signed.sig.to_text(), QUERY_SIG);
    assert_eq!(encode(&signed).unwrap(), query_envelope_text().as_bytes());
    assert_eq!(h(&signed).unwrap().as_str(), QUERY_ENVELOPE_HASH);

    let decoded =
        Sig::<ProofQuery>::decode(query_envelope_text().as_bytes(), Tag::QueryHost).unwrap();
    assert_eq!(decoded, signed);
    decoded
        .verify(Tag::QueryHost, &TestSigner::rk().pinned(Role::Rk))
        .unwrap();
}

#[test]
fn reordering_before_encoding_does_not_change_the_bytes() {
    #[derive(serde::Serialize)]
    struct Reversed {
        preview: Option<()>,
        plan: &'static str,
        q: ReversedQ,
    }
    #[derive(serde::Serialize)]
    struct ReversedQ {
        x: ReversedX,
        nonce: &'static str,
    }
    #[derive(serde::Serialize)]
    struct ReversedX {
        serial: u64,
        op: &'static str,
        host: &'static str,
        aud: &'static str,
    }
    let reordered = Reversed {
        preview: None,
        plan: "1111111111111111111111111111111111111111111111111111111111111111",
        q: ReversedQ {
            x: ReversedX {
                serial: 1,
                op: "0000000000000000000000000000000000000000000000000000000000000000",
                host: "host.test",
                aud: "staging",
            },
            nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        },
    };
    assert_eq!(encode(&reordered).unwrap(), QUERY_BODY.as_bytes());
}

const NATIVE_REG: &str = r#"{"authority":"auth","epoch":"ep","key_id":"k","public_key":[215,90,152,1,130,177,10,183,213,75,254,211,201,100,7,58,14,225,114,243,218,166,35,37,175,2,26,104,247,7,81,26],"host_instance":"hi","generation":2}"#;
const NATIVE_REG_HASH: &str = "dd89dfa1cbcdf3e2c47d1cf01eb18a177333aeac913dd29dc3d6ef390d69c832";
const NATIVE_ACK_DIGEST: &str = "3YnfocvN8-LEfRzwHrGKF3MzrqyRPdKdw9bvOQ1pyDI";
const CANONICAL_REG_HASH: &str = "6bb4cd031db4a790afbb8e0340b1528210e84a1730a1ac41f82bb05cee9ac299";

fn reg() -> Reg {
    let native: HostRegistration = serde_json::from_str(NATIVE_REG).unwrap();
    Reg::from_native(&native).unwrap()
}

#[test]
fn native_registration_bytes_digest_ack_and_context_hash() {
    let reg = reg();
    assert_eq!(reg.public_key, TestSigner::rk().public_key());
    assert_eq!(reg.native_bytes(), NATIVE_REG.as_bytes());
    assert_eq!(reg.reg_hash().as_str(), NATIVE_REG_HASH);
    let ack = reg.ack();
    assert_eq!(ack.digest.to_text(), NATIVE_ACK_DIGEST);
    assert_eq!(
        (ack.host_instance.as_str(), ack.generation.get()),
        ("hi", 2)
    );
    let ctx = reg.ctx(&id("host.test"));
    assert_eq!(ctx.reg_hash.as_str(), NATIVE_REG_HASH);
    assert_eq!(ctx.instance.as_str(), "hi");
}

#[test]
fn canonical_registration_hash_is_not_the_native_digest() {
    let reg = reg();
    let canonical = reg.canonical_hash().unwrap();
    assert_eq!(canonical.as_str(), CANONICAL_REG_HASH);
    assert_ne!(canonical.as_str(), NATIVE_REG_HASH);
    let sorted = encode(&reg).unwrap();
    assert!(sorted.starts_with(br#"{"authority":"auth","epoch":"ep","generation":2,"host_instance":"hi","key_id":"k","public_key":["#));
    assert_eq!(decode::<Reg>(&sorted).unwrap(), reg);
}

#[test]
fn the_native_registration_type_still_serializes_in_its_original_order() {
    let native: HostRegistration = serde_json::from_str(NATIVE_REG).unwrap();
    assert_eq!(serde_json::to_vec(&native).unwrap(), NATIVE_REG.as_bytes());
    assert_eq!(
        HexDigest::of(&serde_json::to_vec(&native).unwrap()).as_str(),
        NATIVE_REG_HASH
    );
}

#[test]
fn legacy_order_is_refused_wherever_canonical_order_is_required() {
    assert!(decode::<Reg>(NATIVE_REG.as_bytes()).is_err());
}

#[test]
fn dims_count_vector_has_exactly_the_specified_order() {
    assert_eq!(DIM_NAMES.len(), 21);
    assert_eq!(
        (DIM_NAMES[16], DIM_NAMES[17]),
        ("operation_intents", "uncertain_installations")
    );
    let text = r#"{"bytes":0,"counts":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,7,3,0,0,0],"fits":true}"#;
    let dims: Dims = decode(text.as_bytes()).unwrap();
    assert_eq!(dims.counts[16].get(), 7);
    assert_eq!(dims.counts[17].get(), 3);
    assert_eq!(encode(&dims).unwrap(), text.as_bytes());
    let short = r#"{"bytes":0,"counts":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,7,3,0,0],"fits":true}"#;
    assert!(decode::<Dims>(short.as_bytes()).is_err());
}
