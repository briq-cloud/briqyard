use super::*;

fn host() -> String {
    "x".repeat(128)
}

fn target(index: usize) -> Target {
    Target {
        host: host(),
        machine: format!("{index:0>128}"),
        namespace: "team".into(),
        run: format!("run-{index}"),
        placement: "version-1".into(),
    }
}

fn clock() -> Clock {
    Clock {
        now: 100,
        uncertainty: 1,
    }
}

fn register() -> (tempfile::TempDir, Journal) {
    let directory = tempfile::tempdir().unwrap();
    let mut journal = Journal::open(
        &directory.path().join("authority"),
        Role::Authority("authority".into()),
    )
    .unwrap();
    let record = HostRegistration {
        authority: "authority".into(),
        epoch: journal.instance().into(),
        key_id: "key".into(),
        public_key: [7; 32],
        host_instance: "host-instance".into(),
        generation: 1,
    };
    let payload = AuthorityPayload::Registration(record);
    assert!(journal
        .begin_authority_intent(
            "registration",
            &host(),
            "host-instance",
            payload.clone(),
            clock()
        )
        .unwrap());
    journal
        .acknowledge_authority_intent(
            "registration",
            payload.expected_ack("host-instance").unwrap(),
            clock(),
        )
        .unwrap();
    (directory, journal)
}

fn control() -> OwnershipControl {
    OwnershipControl {
        require_renewable: false,
        host_instance: "host-instance".into(),
        installation: "new-installation".into(),
        generation: 1,
        team: "team".into(),
        primary_id: "seed-0".into(),
        seeds: (0..2)
            .map(|index| PublicSeed {
                id: format!("seed-{index}"),
                machine: target(index).machine,
                namespace: "team".into(),
                team: "team".into(),
                expected_version: None,
            })
            .collect(),
        metadata_revision: "metadata".into(),
    }
}

fn intent(journal: &Journal, control: OwnershipControl) -> DiscoveryIntent {
    DiscoveryIntent {
        host: host(),
        registration: "registration".into(),
        authority_epoch: journal.instance().into(),
        control: control.clone(),
        request: control.discovery_request(),
        receipt: None,
    }
}

#[test]
fn first_discovery_reserves_a_valid_maximum_receipt_without_ownership() {
    let (_directory, journal) = register();
    let intended = intent(&journal, control());
    let receipt = maximum_discovery_receipt(&intended);
    validate_discovery_receipt(&host(), &intended.request, &receipt).unwrap();
}

#[test]
fn first_discovery_refuses_before_an_unretainable_receipt() {
    let (_directory, mut journal) = register();
    let control = control();
    let intended = intent(&journal, control.clone());
    let mut projected = State::clone(&journal.state);
    projected
        .discovery_intents
        .insert("first".into(), intended.clone());
    projected.clock_floor = clock().now;
    let mut reserve = projected.clone();
    reserve.discovery_intents.get_mut("first").unwrap().receipt =
        Some(maximum_discovery_receipt(&intended));
    reserve.clock_floor = MAX_SAFE_INTEGER;
    reserve
        .uncertain_installations
        .insert("discovery:first".into());
    let padding = MAX_BYTES as usize + 1 - serde_json::to_vec(&reserve).unwrap().len();
    let expected_pending_bytes = serde_json::to_vec(&projected).unwrap().len() + padding + 3;
    assert!(expected_pending_bytes <= MAX_BYTES as usize);
    Arc::make_mut(&mut journal.view.state)
        .uncertain_installations
        .insert("p".repeat(padding - 3));
    assert!(matches!(
        journal.begin_discovery_intent("first", &host(), "registration", control, clock()),
        Err(Error::Full)
    ));
    assert!(journal.state.discovery_intents.is_empty());
    assert!(journal.owned().is_ok());
}

#[test]
fn typed_ack_plus_clock_loss_fits_exactly_the_reserved_bytes() {
    let (_directory, mut journal) = register();
    let prior = AuthorityPayload::Registration(HostRegistration {
        authority: "authority".into(),
        epoch: journal.instance().into(),
        key_id: "other".into(),
        public_key: [8; 32],
        host_instance: "host-instance".into(),
        generation: 2,
    });
    let mut projected = State::clone(&journal.state);
    projected.authority_intents.insert(
        "second".into(),
        AuthorityIntent {
            host: host(),
            host_instance: "host-instance".into(),
            authority_epoch: journal.instance().into(),
            registration_dependency: None,
            discovery_dependency: None,
            payload: prior.clone(),
            acknowledgement: None,
            instance_confirmed: false,
        },
    );
    projected
        .authority_highwater
        .insert(format!("registration:{}", host()), 2);
    let mut reserve = projected.clone();
    reserve
        .authority_intents
        .get_mut("second")
        .unwrap()
        .acknowledgement = Some(prior.expected_ack("host-instance").unwrap());
    reserve.clock_floor = MAX_SAFE_INTEGER;
    reserve
        .uncertain_installations
        .insert("authority:second".into());
    let padding = MAX_BYTES as usize - serde_json::to_vec(&reserve).unwrap().len();
    Arc::make_mut(&mut journal.view.state)
        .uncertain_installations
        .insert("p".repeat(padding - 3));
    assert!(journal
        .begin_authority_intent("second", &host(), "host-instance", prior.clone(), clock())
        .unwrap());
    journal
        .acknowledge_authority_intent(
            "second",
            prior.expected_ack("host-instance").unwrap(),
            Clock {
                now: MAX_SAFE_INTEGER,
                uncertainty: 1,
            },
        )
        .unwrap();
    journal
        .refuse_installation_readiness("authority", "second")
        .unwrap();
    assert_eq!(
        serde_json::to_vec(&State::clone(&journal.state))
            .unwrap()
            .len(),
        MAX_BYTES as usize
    );
    assert!(journal.owned().is_ok());
}

#[test]
fn historical_confirmed_controls_do_not_consume_synthetic_refusal_slots() {
    let (_directory, mut journal) = register();
    let current_epoch = journal.instance().to_owned();
    for index in 0..(MAX_RECORDS - 1) {
        let substitute = Arc::make_mut(&mut journal.view.state);
        substitute.authority_intents.insert(
            format!("revoke-{index}"),
            AuthorityIntent {
                host: host(),
                host_instance: "host-instance".into(),
                authority_epoch: current_epoch.clone(),
                registration_dependency: None,
                discovery_dependency: None,
                payload: AuthorityPayload::Revoke {
                    id: format!("old-{index}"),
                    version: 1,
                },
                acknowledgement: None,
                instance_confirmed: true,
            },
        );
    }
    assert!(journal
        .begin_discovery_intent("after-history", &host(), "registration", control(), clock())
        .unwrap());
    assert_eq!(journal.state.uncertain_installations.len(), 0);
}
