//! The interop fixture `testdata/sealed_v3_1/vectors.json` is what the TypeScript and Python
//! consumers read. These tests pin it to the Rust implementation, so the three languages can
//! only agree on values the Rust codec reproduces too, and the fixture cannot drift.

use super::control::{status, trial, StatusChallenge};
use super::fixtures::*;
use crate::execution::sealed::canonical::{decode, encode, h};
use crate::execution::sealed::custody::{
    CaptureBody, CustodyWire, ExitBody, MatchBody, Resource, Slot,
};
use crate::execution::sealed::objects::{ProofQuery, Reg};
use crate::execution::sealed::prim::{LitBool, Nonce};
use crate::execution::sealed::sig::{Sig, Tag};
use crate::execution::sealed::tests::{dg, proc, x, TestSigner};
use crate::execution::sealed::trial::{command_hash, command_preimage, trial_timeout_ms, Origin};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use std::sync::OnceLock;

const VECTORS_JSON: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/sealed_v3_1/vectors.json"
));
const _: () = assert!(
    VECTORS_JSON.len() <= 16 * 1024,
    "sealed vectors exceed 16 KiB"
);

#[derive(Deserialize)]
pub(super) struct VectorInputs {
    pub trial: TrialInputs,
    custody: CustodyInputs,
}

#[derive(Deserialize)]
pub(super) struct TrialInputs {
    pub c: String,
    #[serde(rename = "status_b_nonce_fill", deserialize_with = "nonce_from_fill")]
    pub status_b_nonce: Nonce,
    #[serde(rename = "status_r_nonce_fill", deserialize_with = "nonce_from_fill")]
    pub status_r_nonce: Nonce,
}

#[derive(Deserialize)]
struct CustodyInputs {
    capture: CaptureInputs,
    request: RequestInputs,
}

#[derive(Deserialize)]
struct CaptureInputs {
    #[serde(rename = "owner_fill", deserialize_with = "nonce_from_fill")]
    owner: Nonce,
    #[serde(rename = "challenge_fill", deserialize_with = "nonce_from_fill")]
    challenge: Nonce,
}

#[derive(Deserialize)]
struct RequestInputs {
    #[serde(rename = "challenge_fill", deserialize_with = "nonce_from_fill")]
    challenge: Nonce,
}

fn nonce_from_fill<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Nonce, D::Error> {
    let fill = u8::deserialize(deserializer)?;
    Ok(Nonce::from_array([fill; 32]))
}

pub(super) fn vector_inputs() -> &'static VectorInputs {
    static INPUTS: OnceLock<VectorInputs> = OnceLock::new();
    INPUTS.get_or_init(|| {
        serde_json::from_slice(VECTORS_JSON).expect("invalid sealed vectors.json inputs")
    })
}

fn vectors() -> Value {
    serde_json::from_slice(VECTORS_JSON).expect("invalid sealed vectors.json")
}

fn text<'a>(value: &'a Value, path: &[&str]) -> &'a str {
    path.iter()
        .fold(value, |v, key| &v[*key])
        .as_str()
        .unwrap_or_else(|| panic!("vectors.json lacks {path:?}"))
}

#[test]
fn the_fixture_names_the_contract_it_was_copied_from() {
    let v = vectors();
    assert_eq!(
        text(&v, &["contract_sha256"]),
        "de7b14d3517090f537d01d0f6effc566337ed863cf9f88871bea7304d967f5ac"
    );
    assert_eq!(text(&v, &["domain"]), "BRIQ-SEAL/2");
}

#[test]
fn query_and_registration_vectors_match_the_rust_codec() {
    let v = vectors();
    let body: ProofQuery = decode(text(&v, &["query", "body"]).as_bytes()).unwrap();
    let signed = Sig::sign(Tag::QueryHost, body, &TestSigner::rk()).unwrap();
    assert_eq!(signed.sig.to_text(), text(&v, &["query", "sig"]));
    assert_eq!(
        h(&signed).unwrap().as_str(),
        text(&v, &["query", "envelope_hash"])
    );
    assert_eq!(signed.kid.as_str(), text(&v, &["keys", "rk", "kid"]));

    let native = text(&v, &["native_reg", "text"]);
    let reg: crate::execution::admission::HostRegistration = serde_json::from_str(native).unwrap();
    let reg = Reg::from_native(&reg).unwrap();
    assert_eq!(reg.native_bytes(), native.as_bytes());
    assert_eq!(
        reg.reg_hash().as_str(),
        text(&v, &["native_reg", "reg_hash"])
    );
    assert_eq!(
        reg.ack().digest.to_text(),
        text(&v, &["native_reg", "ack_digest"])
    );
    assert_eq!(
        reg.canonical_hash().unwrap().as_str(),
        text(&v, &["native_reg", "canonical_h_reg"])
    );
    assert!(String::from_utf8(encode(&reg).unwrap())
        .unwrap()
        .starts_with(text(&v, &["native_reg", "canonical_prefix"])));
}

#[test]
fn trial_vectors_match_the_rust_codec() {
    let v = vectors();
    let t = trial();
    assert_eq!(
        String::from_utf8(encode(&t).unwrap()).unwrap(),
        text(&v, &["trial", "c"])
    );
    assert_eq!(t.hash().unwrap().as_str(), text(&v, &["trial", "hash"]));
    assert_eq!(
        Origin::new(text(&v, &["trial", "origin"]))
            .unwrap()
            .hash()
            .as_str(),
        text(&v, &["trial", "origin_hash"])
    );
    assert_eq!(
        hex::encode(command_preimage(&t.nonce)),
        text(&v, &["trial", "command_preimage_hex"])
    );
    assert_eq!(
        command_hash(&t.nonce).as_str(),
        text(&v, &["trial", "command_hash"])
    );
    assert_eq!(
        status(StatusChallenge::B).sig.to_text(),
        text(&v, &["trial", "status_b_sig"])
    );
    assert_eq!(
        h(&status(StatusChallenge::B)).unwrap().as_str(),
        text(&v, &["trial", "status_b_hash"])
    );
    assert_eq!(
        h(&status(StatusChallenge::R)).unwrap().as_str(),
        text(&v, &["trial", "status_r_hash"])
    );
    assert_eq!(
        text(&v, &["trial", "final_read_trial"]),
        text(&v, &["trial", "status_b_hash"])
    );
    assert_eq!(
        text(&v, &["trial", "client_enable_trial"]),
        text(&v, &["trial", "hash"])
    );
    let timeout = &v["trial"]["timeout"];
    let (exp, max) = (
        timeout["exp"].as_u64().unwrap(),
        timeout["max_duration_seconds"].as_u64().unwrap(),
    );
    assert_eq!(
        trial_timeout_ms(exp, max, timeout["send"]["now_ms"].as_u64().unwrap()),
        Ok(1000)
    );
    assert!(trial_timeout_ms(exp, max, timeout["refuse"]["now_ms"].as_u64().unwrap()).is_err());
}

#[test]
fn custody_vectors_match_the_rust_codec() {
    let v = vectors();
    let custody = &vector_inputs().custody;
    let wire = CustodyWire {
        x: x(),
        plan: dg('1'),
        resource: Resource::Authority,
        owner: custody.capture.owner,
        custodian: proc(10),
        old: proc(12),
        next: None,
        challenge: custody.capture.challenge,
        slot: Slot::new(27).unwrap(),
    };
    let request = CustodyWire {
        next: Some(proc(18)),
        challenge: custody.request.challenge,
        ..wire.clone()
    };
    let capture = Sig::sign(Tag::CustodyCapture, CaptureBody { wire }, &TestSigner::rk()).unwrap();
    let matched = Sig::sign(
        Tag::CustodyMatch,
        MatchBody {
            wire: request.clone(),
            capture: h(&capture).unwrap(),
            same: LitBool,
        },
        &TestSigner::rk(),
    )
    .unwrap();
    let exited = Sig::sign(
        Tag::CustodyExit,
        ExitBody {
            wire: request,
            matched: h(&matched).unwrap(),
            exited: LitBool,
        },
        &TestSigner::rk(),
    )
    .unwrap();
    assert_eq!(
        h(&capture).unwrap().as_str(),
        text(&v, &["custody", "capture_hash"])
    );
    assert_eq!(
        h(&matched).unwrap().as_str(),
        text(&v, &["custody", "matched_hash"])
    );
    assert_eq!(
        h(&exited).unwrap().as_str(),
        text(&v, &["custody", "exited_hash"])
    );
}

#[test]
fn every_fixture_negative_is_refused_by_the_rust_codec_too() {
    let v = vectors();
    let envelope = {
        let body: ProofQuery = decode(text(&v, &["query", "body"]).as_bytes()).unwrap();
        String::from_utf8(
            encode(&Sig::sign(Tag::QueryHost, body, &TestSigner::rk()).unwrap()).unwrap(),
        )
        .unwrap()
    };
    let negatives = v["query"]["negatives"].as_array().unwrap();
    assert_eq!(negatives.len(), 7);
    for negative in negatives {
        let id = negative["id"].as_str().unwrap();
        let mutated = match negative["append"].as_str() {
            Some(extra) => format!("{envelope}{extra}"),
            None => {
                let find = negative["find"].as_str().unwrap();
                assert!(envelope.contains(find), "{id}");
                envelope.replacen(find, negative["replace"].as_str().unwrap(), 1)
            }
        };
        let decoded = decode::<Sig<ProofQuery>>(mutated.as_bytes());
        match negative["expect"].as_str().unwrap() {
            "decode" => assert!(decoded.is_err(), "{id} decoded"),
            _ => {
                let decoded = decoded.unwrap();
                assert!(
                    decoded.verify(Tag::QueryHost, &rk()).is_err()
                        && decoded.verify(decoded.tag, &rk()).is_err(),
                    "{id} verified"
                );
            }
        }
    }
}
