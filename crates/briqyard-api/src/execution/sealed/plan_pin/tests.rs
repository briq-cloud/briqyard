//! Wire and tag tests for the plan pin, the read pair and the trust record. The signers are
//! RFC 8032 synthetic seeds from this cfg(test) tree: they are not enrollment and nothing
//! here authorizes an action.

use super::*;
use crate::execution::sealed::canonical::{decode, encode};
use crate::execution::sealed::objects::{Members, Reg};
use crate::execution::sealed::prim::{Build, Bytes};
use crate::execution::sealed::sig::{Signer, Tag};
use crate::execution::sealed::tests::{dg, id, key, pos, proc, x, TestSigner};

const REGISTERED_TEST_HASH: &str =
    "d1db6793cf9c14050f6ae171addb1400565c1187095b4b579ba804c31ea1bb96";

fn members(k: char) -> Members {
    Members {
        hi: dg(k),
        he: dg(k),
        ni: dg(k),
        ng: dg(k),
        tr: None,
    }
}

fn plan() -> Plan {
    let record = Reg {
        authority: id("auth"),
        epoch: id("ep"),
        key_id: id("k"),
        public_key: TestSigner::rk().public_key(),
        host_instance: id("hi"),
        generation: pos(2),
    };
    Plan {
        x: x(),
        registered: id("registered.test"),
        pre: record.ctx(&x().host),
        pre_record: record,
        pre_intent: id("pre"),
        pre_d: proc(10),
        pre_a: proc(12),
        next_d: dg('a'),
        next_a: dg('b'),
        dbuild: Build::new("fence-3").unwrap(),
        abuild: Build::new("fence-3").unwrap(),
        old: members('1'),
        new: members('2'),
        hk: key(1),
        ak: Bytes::from_array(TestSigner::ak().public_key()),
        bk: Bytes::from_array(TestSigner::bk().public_key()),
        rk: Bytes::from_array(TestSigner::rk().public_key()),
        ordinary_key: key(5),
        exception: dg('c'),
        inputs: dg('d'),
    }
}

fn nonce(k: u8) -> Nonce {
    Bytes::from_array([k; 32])
}

fn read(resource: Resource, point: ReadPoint) -> Read {
    Read {
        format: ReadFormat::V1,
        x: x(),
        registered: id("registered.test"),
        resource,
        point,
        nonce: nonce(7),
    }
}

fn local() -> LocalPlan {
    LocalPlan::decode(&encode(&plan()).unwrap()).unwrap()
}

fn trust() -> TrustRecord {
    TrustRecord {
        format: TrustFormat::V1,
        x: x(),
        registered: id("registered.test"),
        rk: Bytes::from_array(TestSigner::rk().public_key()),
        bk: Bytes::from_array(TestSigner::bk().public_key()),
    }
}

const X_TEXT: &str = r#"{"aud":"staging","host":"host.test","op":"0000000000000000000000000000000000000000000000000000000000000000","serial":1}"#;

#[test]
fn pin_trust_and_read_bytes_are_the_contract() {
    let digest = local().digest().clone();
    let pin = format!(
        r#"{{"format":"plan.pin/v1","plan":"{digest}","registered":"registered.test","x":{X_TEXT}}}"#
    );
    assert_eq!(
        String::from_utf8(encode(&local().pin()).unwrap()).unwrap(),
        pin
    );

    let rk = trust().rk.to_text();
    let bk = trust().bk.to_text();
    let trust_text = format!(
        r#"{{"bk":"{bk}","format":"plan.reader.trust/v1","registered":"registered.test","rk":"{rk}","x":{X_TEXT}}}"#
    );
    assert_eq!(
        String::from_utf8(encode(&trust()).unwrap()).unwrap(),
        trust_text
    );
    assert_eq!(
        decode::<TrustRecord>(trust_text.as_bytes()).unwrap(),
        trust()
    );

    let n = nonce(7).to_text();
    let read_text = format!(
        r#"{{"format":"plan.read/v1","nonce":"{n}","point":"prearm","registered":"registered.test","resource":"daemon","x":{X_TEXT}}}"#
    );
    assert_eq!(
        String::from_utf8(encode(&read(Resource::Daemon, ReadPoint::Prearm)).unwrap()).unwrap(),
        read_text
    );
    assert_eq!(
        decode::<Read>(read_text.as_bytes()).unwrap(),
        read(Resource::Daemon, ReadPoint::Prearm)
    );
}

#[test]
fn read_refuses_authority_seal_and_every_unknown_selector() {
    for (resource, point, ok) in [
        (Resource::Daemon, ReadPoint::Prearm, true),
        (Resource::Daemon, ReadPoint::Launch, true),
        (Resource::Daemon, ReadPoint::Seal, true),
        (Resource::Authority, ReadPoint::Prearm, true),
        (Resource::Authority, ReadPoint::Launch, true),
        (Resource::Authority, ReadPoint::Seal, false),
    ] {
        let decoded = encode(&read(resource, point)).and_then(|bytes| decode::<Read>(&bytes));
        assert_eq!(decoded.is_ok(), ok, "{resource:?} {point:?}");
    }
    let n = nonce(7).to_text();
    let template = |format: &str, resource: &str, point: &str, extra: &str| {
        format!(
            r#"{{{extra}"format":"{format}","nonce":"{n}","point":"{point}","registered":"registered.test","resource":"{resource}","x":{X_TEXT}}}"#
        )
    };
    assert!(decode::<Read>(template("plan.read/v1", "daemon", "launch", "").as_bytes()).is_ok());
    for bad in [
        template("plan.read/v2", "daemon", "launch", ""),
        template("plan.read/v1", "gate", "launch", ""),
        template("plan.read/v1", "daemon", "authority-seal", ""),
        template("plan.read/v1", "authority", "seal", ""),
        template("plan.read/v1", "daemon", "launch", r#""aaa":1,"#),
        template("plan.read/v1", "daemon", "launch", "").replace(',', ", "),
    ] {
        assert!(decode::<Read>(bad.as_bytes()).is_err(), "{bad}");
    }
}

#[test]
fn trust_record_refuses_shared_weak_and_noncanonical_keys() {
    let mut shared = trust();
    shared.bk = shared.rk;
    assert!(decode::<TrustRecord>(&serde_json::to_vec(&shared).unwrap()).is_err());
    assert!(encode(&shared).is_ok());

    let mut weak = trust();
    weak.rk = Bytes::from_array([0; 32]);
    assert!(weak.pinned().is_err());
    let mut weak = trust();
    weak.bk = Bytes::from_array([0; 32]);
    assert!(weak.pinned().is_err());

    let (rk, bk) = trust().pinned().unwrap();
    assert_eq!(rk.role(), Role::Rk);
    assert_eq!(bk.role(), Role::Bk);

    let canonical = String::from_utf8(encode(&trust()).unwrap()).unwrap();
    for bad in [
        format!("{canonical}\n"),
        canonical.replacen("registered.test", "registered.test ", 1),
        canonical.replacen("plan.reader.trust/v1", "plan.reader.trust/v2", 1),
        canonical.replacen(",\"x\":", ",\"extra\":0,\"x\":", 1),
    ] {
        assert!(decode::<TrustRecord>(bad.as_bytes()).is_err(), "{bad}");
    }
}

#[test]
fn selector_is_typed_and_the_registered_hash_is_over_exact_utf8() {
    let selector = TrustSelector::new(&x(), &id("registered.test"));
    assert_eq!(selector.aud(), "staging");
    assert_eq!(selector.reg_hash().as_str(), REGISTERED_TEST_HASH);
    assert_eq!(selector.serial(), "1");
    assert_eq!(selector.file_name(), "1.json");
    let mut production = x();
    production.aud = Env::Production;
    production.serial = pos(12);
    let selector = TrustSelector::new(&production, &id("registered.test"));
    assert_eq!(
        (selector.aud(), selector.file_name().as_str()),
        ("production", "12.json")
    );
    assert_ne!(
        TrustSelector::new(&x(), &id("Registered.test")).reg_hash(),
        &reg_hash(&id("registered.test"))
    );
    assert_eq!(
        trust().selector(),
        TrustSelector::new(&x(), &id("registered.test"))
    );
}

#[test]
fn local_plan_digest_is_over_the_exact_canonical_bytes() {
    let bytes = encode(&plan()).unwrap();
    let local = LocalPlan::decode(&bytes).unwrap();
    assert_eq!(local.digest(), &HexDigest::of(&bytes));
    assert_eq!(local.plan(), &plan());
    let pin = local.pin();
    assert_eq!((pin.x, pin.registered), (plan().x, plan().registered));
    assert_eq!(pin.plan, HexDigest::of(&bytes));

    let mut spaced = bytes.clone();
    spaced.insert(1, b' ');
    assert!(LocalPlan::decode(&spaced).is_err());
    let mut trailing = bytes;
    trailing.push(b'\n');
    assert!(LocalPlan::decode(&trailing).is_err());
}

#[test]
fn observation_tags_are_single_role_and_not_interchangeable() {
    assert_eq!(Tag::PlanReadReceiver.signers(), [Role::Rk]);
    assert_eq!(Tag::PlanReadApi.signers(), [Role::Bk]);
    assert!(!Tag::PlanReadReceiver.is_trial3() && !Tag::PlanReadApi.is_trial3());

    let (rk, bk) = trust().pinned().unwrap();
    let body = ReadBody {
        read: read(Resource::Daemon, ReadPoint::Launch),
        pin: local().pin(),
    };
    let receiver = Sig::sign(Tag::PlanReadReceiver, body.clone(), &TestSigner::rk()).unwrap();
    let api = Sig::sign(Tag::PlanReadApi, body, &TestSigner::bk()).unwrap();
    receiver.verify(Tag::PlanReadReceiver, &rk).unwrap();
    api.verify(Tag::PlanReadApi, &bk).unwrap();
    assert_eq!(
        receiver.verify(Tag::PlanReadApi, &rk),
        Err(SigError::WrongTag)
    );
    assert_eq!(
        receiver.verify(Tag::PlanReadReceiver, &bk),
        Err(SigError::RoleNotPermitted)
    );
    assert_eq!(
        api.verify(Tag::PlanReadApi, &rk),
        Err(SigError::RoleNotPermitted)
    );
    assert_eq!(
        api.verify(Tag::PlanReadReceiver, &bk),
        Err(SigError::WrongTag)
    );

    let pair = ReadPair { receiver, api };
    let bytes = encode(&pair).unwrap();
    assert_eq!(decode::<ReadPair>(&bytes).unwrap(), pair);
    assert!(decode::<ReadPair>(&[bytes.as_slice(), b"\n"].concat()).is_err());
    let mut extra = bytes;
    extra.truncate(extra.len() - 1);
    extra.extend_from_slice(b",\"zzz\":0}");
    assert!(decode::<ReadPair>(&extra).is_err());
}

#[test]
fn a_signer_cannot_produce_an_authority_seal_body() {
    let body = ReadBody {
        read: read(Resource::Authority, ReadPoint::Seal),
        pin: local().pin(),
    };
    assert!(Sig::sign(Tag::PlanReadReceiver, body, &TestSigner::rk()).is_err());
}
