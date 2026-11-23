//! The role and tag table: one signer set per tag, disjoint trial vocabularies.

use super::fixtures::*;
use crate::execution::sealed::prim::Bytes;
use crate::execution::sealed::sig::{Role, Tag};
use crate::execution::sealed::tests::{fixture_nonce, x};
use crate::execution::sealed::transition::*;

#[test]
fn the_tag_table_is_exactly_the_contract() {
    use Role::*;
    let table: [(Tag, &str, &[Role]); 40] = [
        (Tag::QueryHost, "query.host", &[Ak, Rk, Bk]),
        (Tag::QueryAuthority, "query.authority", &[Hk, Rk, Bk]),
        (Tag::QueryApi, "query.api", &[Hk, Ak, Rk]),
        (Tag::HostClock, "host.clock", &[Hk]),
        (Tag::CustodyCapture, "custody.capture", &[Rk]),
        (Tag::CustodyLoad, "custody.load", &[Rk]),
        (Tag::CustodyMatch, "custody.match", &[Rk]),
        (Tag::CustodyExit, "custody.exit", &[Rk]),
        (Tag::Trial3Receiver, "trial3.receiver", &[Rk]),
        (Tag::Trial3Api, "trial3.api", &[Bk]),
        (Tag::Trial3Issued, "trial3.issued", &[Bk]),
        (Tag::Trial3Status, "trial3.status", &[Ak]),
        (Tag::Retired, "retired", &[Hk]),
        (Tag::Decision, "decision", &[Bk]),
        (Tag::Receiver, "receiver", &[Rk]),
        (Tag::Intent, "intent", &[Ak]),
        (Tag::HostRead, "host.read", &[Hk]),
        (Tag::AuthorityRead, "authority.read", &[Ak]),
        (Tag::ApiRead, "api.read", &[Bk]),
        (Tag::QueryObserve, "query.observe", &[Rk, Bk]),
        (Tag::AuthorityObserve, "authority.observe", &[Ak]),
        (Tag::ReviewRequest, "review.request", &[Bk]),
        (Tag::LaunchReceiver, "launch.receiver", &[Rk]),
        (Tag::LaunchApi, "launch.api", &[Bk]),
        (Tag::ResumeRequest, "resume.request", &[Rk]),
        (Tag::ResumeChallenge, "resume.challenge", &[Rk]),
        (Tag::ResumeReceiver, "resume.receiver", &[Rk]),
        (Tag::ResumeApi, "resume.api", &[Bk]),
        (Tag::ClientStage, "client.stage", &[Bk]),
        (Tag::ClientQuery, "client.query", &[Bk, Rk]),
        (Tag::ClientEnable, "client.enable", &[Bk]),
        (Tag::FinalQuery, "final.query", &[Rk]),
        (Tag::FinalRead, "final.read", &[Bk]),
        (Tag::Trial3OfferQuery, "trial3.offer.query", &[Rk]),
        (Tag::Trial3Offer, "trial3.offer", &[Bk]),
        (Tag::Trial3Observe, "trial3.observe", &[Rk, Bk]),
        (Tag::Trial3Archive, "trial3.archive", &[Rk]),
        (Tag::Trial3ArchiveReply, "trial3.archive.reply", &[Bk]),
        (Tag::PlanReadReceiver, "plan.read.receiver", &[Rk]),
        (Tag::PlanReadApi, "plan.read.api", &[Bk]),
    ];
    let mut seen = std::collections::HashSet::new();
    for (tag, text, signers) in table {
        assert_eq!(tag.as_str(), text);
        assert_eq!(tag.signers(), signers, "{text}");
        assert!(seen.insert(text), "duplicate tag {text}");
        assert_eq!(tag.is_trial3(), text.starts_with("trial3."), "{text}");
        let json = format!("\"{text}\"");
        assert_eq!(serde_json::from_str::<Tag>(&json).unwrap(), tag);
        assert_eq!(serde_json::to_string(&tag).unwrap(), json);
    }
}

#[test]
fn no_tag_outside_the_vocabulary_decodes() {
    for text in [
        "\"trial.status\"",
        "\"v2.retired\"",
        "\"Retired\"",
        "\"query.\"",
        "\"\"",
    ] {
        assert!(serde_json::from_str::<Tag>(text).is_err(), "{text}");
    }
}

#[test]
fn every_host_authority_and_api_fact_has_its_own_signer_role() {
    assert_eq!(Tag::HostRead.signers(), [Role::Hk]);
    assert_eq!(Tag::AuthorityRead.signers(), [Role::Ak]);
    assert_eq!(Tag::ApiRead.signers(), [Role::Bk]);
    assert_eq!(Tag::Decision.signers(), [Role::Bk]);
    assert_eq!(Tag::Receiver.signers(), [Role::Rk]);
}

#[test]
fn a_tag_signed_by_the_wrong_role_does_not_verify() {
    let body = HostClockOrQuery::query();
    let signed = crate::execution::sealed::sig::Sig::sign(
        Tag::FinalQuery,
        body,
        &crate::execution::sealed::tests::TestSigner::rk(),
    )
    .unwrap();
    signed.verify(Tag::FinalQuery, &rk()).unwrap();
    assert!(signed.verify(Tag::FinalQuery, &bk()).is_err());
    assert!(signed.verify(Tag::FinalRead, &rk()).is_err());
}

struct HostClockOrQuery;
impl HostClockOrQuery {
    fn query() -> FinalQueryBody {
        FinalQueryBody {
            q: crate::execution::sealed::objects::Q {
                x: x(),
                nonce: fixture_nonce(7),
            },
            plan: plan_hash(),
        }
    }
}

#[allow(dead_code)]
fn _unused(_: Bytes<32>) {}
