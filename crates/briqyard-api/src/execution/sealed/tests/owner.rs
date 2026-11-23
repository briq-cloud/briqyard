//! The shared owner vectors: R's merged golden, read as bytes and never regenerated here.
//! Every record decodes with the native wire types, re-encodes to the same bytes and hash, and
//! the three signed records verify under the vectors' own public keys.

use crate::execution::sealed::canonical::{decode, encode, h};
use crate::execution::sealed::custody::Capture;
use crate::execution::sealed::objects::Proc;
use crate::execution::sealed::owner::{
    ArmReceipt, Collected, EnrollQuery, Enrolled, Observation, ObserveRequest, Point, Turn,
};
use crate::execution::sealed::prim::{HexDigest, KeyBytes};
use crate::execution::sealed::sig::{PinnedKey, Role, Tag};
use crate::execution::sealed::transition::{Death, LKind, Launch, LaunchStage};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const GOLDEN: &[u8] = include_bytes!("../../../../testdata/owner_v1/sealed_owner_v1.golden");
const GOLDEN_SHA256: &str = "3e14f6a769042dae6e17fbea5c83ca8ac99d3c6057c5cd7fd5624a577aae9337";

fn records() -> BTreeMap<&'static str, (&'static str, &'static str)> {
    std::str::from_utf8(GOLDEN)
        .unwrap()
        .lines()
        .map(|line| {
            let mut columns = line.splitn(3, '\t');
            let name = columns.next().unwrap();
            let digest = columns.next().unwrap();
            (name, (digest, columns.next().unwrap()))
        })
        .collect()
}

fn body(name: &str) -> &'static str {
    records()[name].1
}

fn pinned(name: &str, role: Role) -> PinnedKey {
    let key = KeyBytes::parse(records()[name].1).unwrap();
    PinnedKey::new(role, *key.as_array()).unwrap()
}

fn typed<T: crate::execution::sealed::canonical::Wire>(name: &str) -> T {
    let (digest, text) = records()[name];
    let value: T = decode(text.as_bytes()).unwrap_or_else(|error| panic!("{name}: {error}"));
    assert_eq!(
        encode(&value).unwrap(),
        text.as_bytes(),
        "{name} re-encodes"
    );
    assert_eq!(h(&value).unwrap().as_str(), digest, "{name} hash");
    value
}

#[test]
fn the_vector_file_is_the_one_receiver_and_api_agree_on() {
    assert_eq!(hex::encode(Sha256::digest(GOLDEN)), GOLDEN_SHA256);
}

#[test]
fn every_native_record_decodes_and_reencodes_to_its_vector() {
    let request: ObserveRequest = typed("observe.request");
    assert_eq!(request.point, Point::Prearm);
    let observation: Observation = typed("observation");
    assert_eq!(observation.request, request);
    let _: EnrollQuery = typed("enroll.query");
    let arm: ArmReceipt = typed("arm");
    assert_eq!(arm.hash().unwrap().as_str(), records()["arm"].0);
    let captured: Launch = typed("launch.captured");
    assert_eq!(captured.stage, LaunchStage::Captured);
    let retired: Launch = typed("launch.retired");
    assert_eq!(retired.stage, LaunchStage::Retired);
    let death: Death = typed("death");
    assert_eq!(retired.death.as_ref().unwrap(), &h(&death).unwrap());
    retired.check_death(&death).unwrap();
    let _: Collected = typed("collected");
    let _: Collected = typed("collected.arm");
    let _: Collected = typed("collected.retire");
}

#[test]
fn the_signed_records_verify_under_the_vectors_own_public_keys() {
    let rk = pinned("test.rk.public", Role::Rk);
    let bk = pinned("test.bk.public", Role::Bk);

    let capture: Capture = typed("capture");
    let wire = &capture.verify(Tag::CustodyCapture, &rk).unwrap().wire;
    let captured: Launch = typed("launch.captured");
    captured.check_capture(wire).unwrap();
    assert!(capture.verify(Tag::CustodyCapture, &bk).is_err());

    let enrolled: Enrolled = typed("enroll");
    let enroll = enrolled.verify(Tag::OwnerEnroll, &rk).unwrap();
    assert_eq!(enroll.revision.get(), 2);
    assert!(enrolled.verify(Tag::OwnerEnroll, &bk).is_err());

    let turn: Turn = typed("turn");
    let signed = turn.verify(Tag::OwnerTurn, &bk).unwrap();
    assert_eq!(signed.action, LKind::LaunchD);
    assert_eq!(signed.captured_launch, Some(h(&captured).unwrap()));
    assert_eq!(signed.capture, Some(h(&capture).unwrap()));
    assert!(turn.verify(Tag::OwnerTurn, &rk).is_err());
}

#[test]
fn the_collected_answers_carry_exactly_the_records_they_project() {
    let arm: ArmReceipt = typed("arm");
    let captured: Launch = typed("launch.captured");
    let capture: Capture = typed("capture");
    let observation: Observation = typed("observation");

    let plain: Collected = typed("collected");
    assert_eq!(plain.observation, observation);
    assert!(
        plain.arm.is_none() && plain.launch_capture.is_none() && plain.daemon_retirement.is_none()
    );

    let armed: Collected = typed("collected.arm");
    assert_eq!(armed.arm.as_ref(), Some(&arm));
    let pair = armed.launch_capture.as_ref().unwrap();
    assert_eq!((&pair.launch, &pair.capture), (&captured, &capture));
    assert!(armed.daemon_retirement.is_none());

    let retire: Collected = typed("collected.retire");
    let retirement = retire.daemon_retirement.as_ref().unwrap();
    assert_eq!(retirement.launch, typed::<Launch>("launch.retired"));
    assert_eq!(retirement.death, typed::<Death>("death"));
    assert!(retire.arm.is_none());
}

#[test]
fn a_collected_answer_with_an_unknown_missing_or_misplaced_field_refuses() {
    let text = body("collected");
    let missing = text.replacen("\"arm\":null,", "", 1);
    assert!(decode::<Collected>(missing.as_bytes()).is_err());
    let extra = text.replacen('{', "{\"extra\":1,", 1);
    assert!(decode::<Collected>(extra.as_bytes()).is_err());
    let proc_extra = text.replacen("\"pid\":4242", "\"pid\":4242,\"tid\":1", 1);
    assert!(decode::<Collected>(proc_extra.as_bytes()).is_err());
    let _: Proc = typed::<Observation>("observation").original;
    let unsorted = text.replacen(
        "{\"arm\":null,\"daemon_retirement\":null",
        "{\"daemon_retirement\":null,\"arm\":null",
        1,
    );
    assert!(decode::<Collected>(unsorted.as_bytes()).is_err());
    let both = body("collected.arm").replace(
        "\"daemon_retirement\":null",
        &format!("\"daemon_retirement\":{}", {
            let retire = body("collected.retire");
            let start =
                retire.find("\"daemon_retirement\":").unwrap() + "\"daemon_retirement\":".len();
            let rest = &retire[start..];
            let end = rest.find(",\"launch_capture\"").unwrap();
            rest[..end].to_string()
        }),
    );
    assert!(decode::<Collected>(both.as_bytes()).is_err());
    let _ = HexDigest::of(b"");
}

#[test]
fn a_seal_turn_carries_no_launch_hashes_and_a_launch_turn_carries_both() {
    use crate::execution::sealed::owner::TurnBody;
    let turn: Turn = typed("turn");
    let mut seal = turn.body.clone();
    seal.action = LKind::Seal;
    assert!(crate::execution::sealed::canonical::Wire::validate(&seal).is_err());
    seal.captured_launch = None;
    seal.capture = None;
    crate::execution::sealed::canonical::Wire::validate(&seal).unwrap();
    let mut half: TurnBody = turn.body.clone();
    half.capture = None;
    assert!(crate::execution::sealed::canonical::Wire::validate(&half).is_err());
    let mut authority = turn.body.clone();
    authority.resource = crate::execution::sealed::custody::Resource::Authority;
    assert!(crate::execution::sealed::canonical::Wire::validate(&authority).is_err());
}
