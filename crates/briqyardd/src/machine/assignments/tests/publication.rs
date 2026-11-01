use super::*;

#[tokio::test]
async fn startup_publication_defers_assigned_stages_while_preserving_legacy_records() {
    for phase in 0..4 {
        let (h, entry, request) = fixture().await;
        let digest = templates::sandbox::request_digest(&request).unwrap();
        h.m.stage_destination_assignment(request, &entry, 2)
            .await
            .unwrap();
        h.m.commit_destination_assignment("destination", "assignment-one", &digest)
            .await
            .unwrap();
        if phase == 1 {
            h.lose_destination_ack();
        }
        if phase == 2 {
            h.assigned_first_exec_code(7);
        }
        if phase != 0 {
            let result =
                h.m.start_destination_assignment("destination", "assignment-one", &digest)
                    .await;
            assert_eq!(result.is_ok(), phase == 3);
        }
        let assigned = entry.snapshot();
        let expected = [
            templates::CloneStage::UnboundPaused,
            templates::CloneStage::Configuring,
            templates::CloneStage::IdentityDone,
            templates::CloneStage::Active,
        ][phase]
            .clone();
        assert_eq!(assigned.clone_origin.as_ref().unwrap().stage, expected);
        let legacy = h.add("m_legacy", state::RUNNING, 256);
        {
            let mut record = legacy.rec.lock().unwrap();
            record.namespace = "destination".into();
            record.subnet_index = 2;
            record.host_num = 3;
            record.ip = "10.64.2.3".into();
            record.name = "legacy".into();
        }
        h.m.save(&legacy).unwrap();
        // New Manager Entries start untrusted. load performs metadata recovery only;
        // publication must remain fenced before any assignment-aware adoption exists.
        restart_load(&h.m).unwrap();
        h.m.inner.policies.lock().unwrap().clear();
        h.host_calls();
        let names = h.m.namespace_dns_names("destination");
        assert!(!names.contains_key(&assigned.hostname()));
        assert_eq!(
            names.get("legacy.internal"),
            Some(&"10.64.2.3".parse::<Ipv4Addr>().unwrap())
        );
        let rules = h.m.rules().unwrap();
        assert!(!rules.pins.iter().any(|(_, ip)| ip == &assigned.ip));
        assert!(!rules.members.iter().any(|(_, ip)| ip == &assigned.ip));
        assert!(!rules.counted.contains(&assigned.ip));
        assert!(rules.pins.iter().any(|(_, ip)| ip == "10.64.2.3"));
        assert!(rules.counted.contains(&"10.64.2.3".into()));
        assert!(
            h.host_calls().is_empty(),
            "pure publication classification has no host effects"
        );
    }
}

#[tokio::test]
async fn startup_legacy_via_cannot_publish_an_unverified_assigned_target() {
    let (h, entry, request) = fixture().await;
    let digest = templates::sandbox::request_digest(&request).unwrap();
    h.m.stage_destination_assignment(request, &entry, 2)
        .await
        .unwrap();
    h.m.start_destination_assignment("destination", "assignment-one", &digest)
        .await
        .unwrap();
    let assigned = entry.snapshot();
    let via = h.add("m_via", state::RUNNING, 256);
    {
        let mut record = via.rec.lock().unwrap();
        record.namespace = "destination".into();
        record.subnet_index = 2;
        record.host_num = 3;
        record.ip = "10.64.2.3".into();
        record.egress = api::Egress {
            mode: "via".into(),
            via: Some(assigned.id.clone()),
            siblings: false,
        };
    }
    h.m.save(&via).unwrap();
    restart_load(&h.m).unwrap();
    h.m.inner.policies.lock().unwrap().clear();
    let rules = h.m.rules().unwrap();
    assert!(!rules
        .pins
        .iter()
        .any(|(_, ip)| ip == "10.64.2.3" || ip == &assigned.ip));
    assert!(!rules
        .policies
        .iter()
        .any(|policy| matches!(policy, nft::Policy::Via { to, .. } if to == &assigned.ip)));
}

#[tokio::test]
async fn live_completed_assignment_publication_still_requires_exact_receipt_and_reader() {
    let (h, entry, request) = fixture().await;
    let digest = templates::sandbox::request_digest(&request).unwrap();
    h.m.stage_destination_assignment(request, &entry, 2)
        .await
        .unwrap();
    h.m.start_destination_assignment("destination", "assignment-one", &digest)
        .await
        .unwrap();
    let assigned = entry.snapshot();
    assert!(h
        .m
        .namespace_dns_names("destination")
        .contains_key(&assigned.hostname()));
    assert!(h
        .m
        .rules()
        .unwrap()
        .pins
        .iter()
        .any(|(_, ip)| ip == &assigned.ip));
    let reader: templates::CloneReader =
        h.m.inner
            .store
            .get(templates::READERS, &assigned.id)
            .unwrap()
            .unwrap();
    let mut wrong = reader.clone();
    wrong.namespace = "wrong".into();
    h.m.inner
        .store
        .put_durable(templates::READERS, &assigned.id, &wrong)
        .unwrap();
    assert!(!h
        .m
        .namespace_dns_names("destination")
        .contains_key(&assigned.hostname()));
    h.m.inner.policies.lock().unwrap().clear();
    assert!(!h
        .m
        .rules()
        .unwrap()
        .pins
        .iter()
        .any(|(_, ip)| ip == &assigned.ip));
    h.m.inner
        .store
        .put_durable(templates::READERS, &assigned.id, &reader)
        .unwrap();
    let mut receipt =
        h.m.destination_receipt("destination", "assignment-one")
            .unwrap()
            .unwrap();
    receipt.create_sha256 = "a".repeat(64);
    h.m.inner
        .store
        .put_durable(REQUESTS, &receipt.key(), &receipt)
        .unwrap();
    assert!(!h
        .m
        .namespace_dns_names("destination")
        .contains_key(&assigned.hostname()));
}
