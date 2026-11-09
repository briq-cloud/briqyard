use super::*;

#[tokio::test]
async fn assignment_creation_origin_is_unknown_until_settled_and_rebuilds_from_authority() {
    let (h, slot, request) = fixture().await;
    let id = slot.snapshot().id;
    let digest = templates::sandbox::request_digest(&request).unwrap();
    h.m.stage_destination_assignment(request.clone(), &slot, 2)
        .await
        .unwrap();
    assert!(h.m.get(&id).unwrap().create_origin.is_none());
    h.m.commit_destination_assignment(&request.namespace, "assignment-one", &digest)
        .await
        .unwrap();
    let expected = api::CreateOrigin {
        kind: api::CreateOriginKind::UnboundWarm,
        request_id: "assignment-one".into(),
        create_sha256: digest,
    };
    assert_eq!(h.m.get(&id).unwrap().create_origin, Some(expected.clone()));
    h.m.inner
        .assignments
        .lock()
        .unwrap()
        .pending
        .insert(id.clone());
    assert!(h.m.get(&id).unwrap().create_origin.is_none());
    h.m.inner.assignments.lock().unwrap().pending.remove(&id);
    restart_load(&h.m).unwrap();
    assert_eq!(h.m.get(&id).unwrap().create_origin, Some(expected));
}
