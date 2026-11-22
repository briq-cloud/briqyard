#![cfg(feature = "execution-admission")]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use briqyard_api::execution::{
    admission::{Error, Journal, Role},
    token_digest, Clock, DelegationContext, Grant, KeyRole, Trust, VerificationKey, VerifyError,
};
use serde_json::Value;

#[test]
fn retired_authority_payload_is_inert_and_keeps_historical_evidence() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/execution-v1.json")).unwrap();
    let retired = include_bytes!("fixtures/authority-compacted-v1.json");
    let grant: Grant = serde_json::from_value(fixture["grant"].clone()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("authority");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(root.join("journal.json"), retired).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        root.join("journal.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let journal = Journal::open(&root, Role::Authority("authority".into())).unwrap();
    let installed = journal.delegation_intent("legacy").unwrap().unwrap();
    assert!(installed.request.grant.is_empty());
    assert!(installed.request.allocations.is_empty());
    assert_eq!(
        installed.acknowledgement.as_ref(),
        Some(&installed.expected)
    );
    assert_eq!(
        installed.expected.grant_digest,
        token_digest(fixture["grant_token"].as_str().unwrap())
    );
    assert_eq!(
        installed.expected.allocation_digests,
        vec![token_digest(fixture["allocation_token"].as_str().unwrap())]
    );
    let keys = fixture["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| VerificationKey {
            kid: key["kid"].as_str().unwrap().into(),
            role: if key["role"] == "central" {
                KeyRole::Central
            } else {
                KeyRole::Authority
            },
            issuer: key["issuer"].as_str().unwrap().into(),
            authority: key["authority"].as_str().map(str::to_owned),
            public_key: URL_SAFE_NO_PAD
                .decode(key["public_key"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        })
        .collect::<Vec<_>>();
    let trust = Trust {
        keys: &keys,
        central_issuer: "central",
        authority_issuer: "authority",
        audience: "runtime",
    };
    let context = DelegationContext {
        principal: &grant.principal,
        team: &grant.team,
        subject: &grant.subject,
        target: &grant.target,
        resource_set: &grant.resource_set,
        metadata_revision: &grant.metadata_revision,
        authority: "authority-1",
        authority_epoch: "authority-epoch-1",
    };
    assert!(matches!(
        briqyard_api::execution::verify_delegation(
            &installed.request.grant,
            &[fixture["allocation_token"].as_str().unwrap()],
            &trust,
            Clock {
                now: 1010,
                uncertainty: 1
            },
            &context,
        ),
        Err(VerifyError::Encoding)
    ));
    assert!(matches!(
        briqyard_api::execution::verify_delegation(
            fixture["grant_token"].as_str().unwrap(),
            &installed
                .request
                .allocations
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            &trust,
            Clock {
                now: 1010,
                uncertainty: 1
            },
            &context,
        ),
        Err(VerifyError::Claims)
    ));
    assert!(matches!(
        journal.presented_projection(
            "legacy",
            fixture["grant_token"].as_str().unwrap(),
            Clock {
                now: 2000,
                uncertainty: 1
            },
        ),
        Err(Error::Binding)
    ));
    drop(journal);
    let reopened: Value =
        serde_json::from_slice(&std::fs::read(root.join("journal.json")).unwrap()).unwrap();
    assert_eq!(reopened["v"], 1);
    assert_eq!(
        reopened["delegation_intents"]["legacy"]["request"]["grant"],
        ""
    );
    assert_eq!(
        reopened["delegation_intents"]["legacy"]["request"]["allocations"],
        serde_json::json!([])
    );
}
