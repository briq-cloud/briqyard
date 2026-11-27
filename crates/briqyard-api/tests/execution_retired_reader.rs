#![cfg(feature = "execution-admission")]

use briqyard_api::execution::admission::{Journal, Role};
use std::os::unix::fs::PermissionsExt;

/// A journal after retirement (ADR 0149) is a plain v1 state: this file also runs, unchanged,
/// against the sources of earlier runtimes that have no retirement.
#[test]
fn retired_authority_journal_opens_and_keeps_the_current_generation() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("authority");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(
        root.join("journal.json"),
        include_bytes!("fixtures/authority-retired-v1.json"),
    )
    .unwrap();
    std::fs::set_permissions(
        root.join("journal.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let journal = Journal::open(&root, Role::Authority("region".into())).unwrap();
    for kept in [
        "registration-2",
        "ownership-10",
        "ownership-11",
        "revoke-11",
        "invalidate-11",
    ] {
        assert!(journal.authority_intent(kept).unwrap().is_some(), "{kept}");
    }
    for retired in ["registration-1", "ownership-0", "ownership-9", "revoke-9"] {
        assert!(
            journal.authority_intent(retired).unwrap().is_none(),
            "{retired}"
        );
    }
    assert!(journal.discovery_intent("discovery-11").unwrap().is_some());
    assert!(journal.discovery_intent("discovery-9").unwrap().is_none());
    assert!(journal
        .delegation_intent("delegation-11")
        .unwrap()
        .is_some());
    assert!(journal
        .delegation_intent("delegation-10")
        .unwrap()
        .is_none());
    // A reopened authority has a new epoch: nothing from the file is ready.
    assert!(!journal.authority_intent_ready("ownership-11").unwrap());
}
