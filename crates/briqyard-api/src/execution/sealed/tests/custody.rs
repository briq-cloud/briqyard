//! The custody fixture: Capture, matched and exited hashes, same wire W in both Signs.

use super::*;
use crate::execution::sealed::canonical::{decode, decode_with, encode, h, CodecError, Limits};
use crate::execution::sealed::custody::{
    verify_exit, verify_match, CaptureBody, CustodyWire, EchoFrame, EchoKind, ExitBody,
    HandleFrame, HandleKind, MatchBody, RequestFrame, RequestKind, Resource, Slot,
};
use crate::execution::sealed::prim::LitBool;
use crate::execution::sealed::sig::{Role, Sig, SigError, Tag};

const CAPTURE_HASH: &str = "a17581c93c2b8ef9a766f446d070dc71e6f0ae7f7586cdb75376fd6084788c8b";
const MATCHED_HASH: &str = "5de8b02dd876d49af6755ca1a86cb9e6a2164fdf38f406edab64210a2529b389";
const EXITED_HASH: &str = "8f1437fe0ccb2f91ef872b92b70c37e8715649b13e88998d62ba57a446a5cf4c";

fn capture_wire() -> CustodyWire {
    CustodyWire {
        x: x(),
        plan: dg('1'),
        resource: Resource::Authority,
        owner: n(3),
        custodian: proc(10),
        old: proc(12),
        next: None,
        challenge: n(4),
        slot: Slot::new(27).unwrap(),
    }
}

fn request_wire() -> CustodyWire {
    CustodyWire {
        next: Some(proc(18)),
        challenge: n(5),
        ..capture_wire()
    }
}

fn capture() -> Sig<CaptureBody> {
    Sig::sign(
        Tag::CustodyCapture,
        CaptureBody {
            wire: capture_wire(),
        },
        &TestSigner::rk(),
    )
    .unwrap()
}

fn matched() -> Sig<MatchBody> {
    let body = MatchBody {
        wire: request_wire(),
        capture: h(&capture()).unwrap(),
        same: LitBool,
    };
    Sig::sign(Tag::CustodyMatch, body, &TestSigner::rk()).unwrap()
}

fn exited() -> Sig<ExitBody> {
    let body = ExitBody {
        wire: request_wire(),
        matched: h(&matched()).unwrap(),
        exited: LitBool,
    };
    Sig::sign(Tag::CustodyExit, body, &TestSigner::rk()).unwrap()
}

#[test]
fn capture_matched_and_exited_hashes() {
    assert_eq!(h(&capture()).unwrap().as_str(), CAPTURE_HASH);
    assert_eq!(h(&matched()).unwrap().as_str(), MATCHED_HASH);
    assert_eq!(h(&exited()).unwrap().as_str(), EXITED_HASH);
}

#[test]
fn both_signs_carry_the_same_wire_and_the_chain_verifies() {
    assert_eq!(matched().body.wire, exited().body.wire);
    assert_eq!(matched().body.wire, request_wire());
    assert_eq!(matched().body.capture.as_str(), CAPTURE_HASH);
    assert_eq!(exited().body.matched.as_str(), MATCHED_HASH);
    let rk = TestSigner::rk().pinned(Role::Rk);
    verify_match(&capture(), &matched(), &rk, &request_wire()).unwrap();
    verify_exit(&capture(), &matched(), &exited(), &rk, &request_wire()).unwrap();
}

#[test]
fn a_different_owner_challenge_slot_or_successor_gets_no_match() {
    let rk = TestSigner::rk().pinned(Role::Rk);
    let mut others = vec![];
    others.push(CustodyWire {
        owner: n(9),
        ..request_wire()
    });
    others.push(CustodyWire {
        challenge: n(4),
        ..request_wire()
    });
    others.push(CustodyWire {
        slot: Slot::new(28).unwrap(),
        ..request_wire()
    });
    others.push(CustodyWire {
        next: None,
        ..request_wire()
    });
    others.push(CustodyWire {
        old: proc(13),
        ..request_wire()
    });
    for other in others {
        assert!(
            verify_match(&capture(), &matched(), &rk, &other).is_err(),
            "{other:?}"
        );
    }
}

#[test]
fn a_match_signed_over_another_capture_or_by_another_role_refuses() {
    let rk = TestSigner::rk().pinned(Role::Rk);
    let bk = TestSigner::bk().pinned(Role::Bk);
    let other_capture = Sig::sign(
        Tag::CustodyCapture,
        CaptureBody {
            wire: CustodyWire {
                slot: Slot::new(1).unwrap(),
                ..capture_wire()
            },
        },
        &TestSigner::rk(),
    )
    .unwrap();
    assert!(verify_match(&other_capture, &matched(), &rk, &request_wire()).is_err());
    assert_eq!(
        verify_match(&capture(), &matched(), &bk, &request_wire()),
        Err(SigError::RoleNotPermitted)
    );
    let wrong_chain = Sig::sign(
        Tag::CustodyExit,
        ExitBody {
            wire: request_wire(),
            matched: dg('0'),
            exited: LitBool,
        },
        &TestSigner::rk(),
    )
    .unwrap();
    assert!(verify_exit(&capture(), &matched(), &wrong_chain, &rk, &request_wire()).is_err());
}

#[test]
fn capture_wire_next_must_be_null_and_frames_need_a_successor() {
    let bytes = encode(&CaptureBody {
        wire: request_wire(),
    })
    .unwrap();
    assert!(decode::<CaptureBody>(&bytes).is_err());
    let frame = RequestFrame {
        kind: RequestKind::Only,
        wire: capture_wire(),
    };
    let bytes = encode(&frame).unwrap();
    assert!(decode::<RequestFrame>(&bytes).is_err());
}

#[test]
fn frames_carry_only_kind_and_wire_never_a_descriptor_number() {
    let request = RequestFrame {
        kind: RequestKind::Only,
        wire: request_wire(),
    };
    let handle = HandleFrame {
        kind: HandleKind::Only,
        wire: request_wire(),
    };
    let echo = EchoFrame {
        kind: EchoKind::Only,
        wire: request_wire(),
    };
    for (bytes, kind) in [
        (encode(&request).unwrap(), "request"),
        (encode(&handle).unwrap(), "handle"),
        (encode(&echo).unwrap(), "echo"),
    ] {
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let top: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
        assert_eq!(top, ["kind", "wire"]);
        assert_eq!(value["kind"], kind);
        let wire: Vec<_> = value["wire"].as_object().unwrap().keys().cloned().collect();
        assert_eq!(
            wire,
            [
                "challenge",
                "custodian",
                "next",
                "old",
                "owner",
                "plan",
                "resource",
                "slot",
                "x"
            ]
        );
        assert!(bytes.len() <= 4096);
    }
    assert_eq!(
        decode_with::<RequestFrame>(&encode(&request).unwrap(), Limits::CUSTODY_PACKET).unwrap(),
        request
    );
}

#[test]
fn a_packet_over_4kib_is_refused_before_parsing() {
    let mut bytes = encode(&RequestFrame {
        kind: RequestKind::Only,
        wire: request_wire(),
    })
    .unwrap();
    bytes.extend(std::iter::repeat_n(b' ', 4096));
    assert_eq!(
        decode_with::<RequestFrame>(&bytes, Limits::CUSTODY_PACKET),
        Err(CodecError::TooLarge)
    );
}
