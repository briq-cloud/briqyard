//! Backups across hosts.

use super::*;

#[tokio::test]
async fn backups_are_listed_from_any_host_that_is_up() {
    let (f, ds) = fleet_with_daemons(2).await;
    // A machine nobody has: the store is shared, so any ready host answers.
    let (s, _, body) = call(&f.st, "GET", "/v1/machines/m_gone/backups", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(json(&body), serde_json::json!([]));
    let asked: usize = ds
        .iter()
        .map(|d| {
            d.stub
                .calls()
                .iter()
                .filter(|c| c.contains("backups"))
                .count()
        })
        .sum();
    assert_eq!(asked, 1, "one host asked, the first that answered");
    // The host that holds the machine is the one asked; down, nothing else is tried.
    let m = ds[0].stub.add("t1", "web", 512);
    f.st.reg
        .lock()
        .unwrap()
        .machines
        .insert(m.id.clone(), "d1".into());
    set_state(&f.st, "d1", "down");
    let before = ds[0].stub.calls().len();
    let (s, _, body) = call(
        &f.st,
        "GET",
        &format!("/v1/machines/{}/backups", m.id),
        "api",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(ds[0].stub.calls().len(), before, "a down host is not asked");
}

#[tokio::test]
async fn every_backup_is_listed_from_every_host() {
    let (f, ds) = fleet_with_daemons(2).await;
    let (s, _, body) = call(&f.st, "GET", "/v1/backups", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let ids: Vec<String> = serde_json::from_str::<Vec<api::Backup>>(&body)
        .unwrap()
        .into_iter()
        .map(|b| b.machine_id)
        .collect();
    assert_eq!(ids, ["m_d1", "m_d2"]);
    // A namespace's: every host too, the query as it came. Its host is d2, and the host it moved
    // from still holds the backups of what was destroyed there (ADR 0045).
    f.st.reg
        .lock()
        .unwrap()
        .namespaces
        .insert("t1".into(), "d2".into());
    let (s, _, body) = call(&f.st, "GET", "/v1/backups?namespace=t1", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(json(&body).as_array().unwrap().len(), 2);
    for d in &ds {
        assert_eq!(
            d.stub.calls().last().unwrap(),
            "GET /v1/backups?namespace=t1"
        );
    }
    // Every host or nothing: one down fails the listing.
    set_state(&f.st, "d1", "down");
    let (s, _, body) = call(&f.st, "GET", "/v1/backups?namespace=t1", "api", None).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
}

#[tokio::test]
async fn a_destroyed_machine_s_backup_is_deleted_on_the_host_that_holds_it() {
    let (f, ds) = fleet_with_daemons(2).await;
    // Its namespace moved to d2 (ADR 0045): the backups of m_d1 stay held on d1.
    f.st.reg
        .lock()
        .unwrap()
        .namespaces
        .insert("t1".into(), "d2".into());
    for (query, search) in [
        (
            "chain=true&namespace=t1",
            "GET /v1/backups?machine=m_d1&namespace=t1",
        ),
        ("chain=true", "GET /v1/backups?machine=m_d1"),
    ] {
        let path = format!("/v1/machines/m_d1/backups/b1?{query}");
        let (s, _, body) = call(&f.st, "DELETE", &path, "api", None).await;
        assert_eq!(s, StatusCode::NO_CONTENT, "{query}: {body}");
        let calls = ds[0].stub.calls();
        assert_eq!(calls.last().unwrap(), &format!("DELETE {path}"), "{query}");
        // The search asks for that machine's alone; every host at once.
        assert_eq!(calls[calls.len() - 2], search);
        assert_eq!(ds[1].stub.calls().last().unwrap(), search);
        assert!(!ds[1].stub.calls().iter().any(|c| c.starts_with("DELETE")));
    }
    // Held nowhere: not found, and no host is asked to delete.
    let (s, _, _) = call(
        &f.st,
        "DELETE",
        "/v1/machines/m_gone/backups/b1",
        "api",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // A host that cannot say what it holds fails a search no other host answers with its
    // answer: it may be the one. The host that lists the machine's backups is the one,
    // whatever another could not say. The stubs list all they hold whatever the filter, as a
    // host older than it does: the fleet reads the machine's alone.
    set_state(&f.st, "d1", "down");
    let (s, _, body) = call(
        &f.st,
        "DELETE",
        "/v1/machines/m_gone/backups/b1",
        "api",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(json(&body)["code"], "host_down");
    let (s, _, body) = call(&f.st, "DELETE", "/v1/machines/m_d2/backups/b1", "api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(
        ds[1].stub.calls().last().unwrap(),
        "DELETE /v1/machines/m_d2/backups/b1"
    );
    // Only a backup's path searches: anything else about a machine no host has is a 404.
    set_state(&f.st, "d1", "ready");
    let before = ds[0].stub.calls().len();
    let (s, _, _) = call(&f.st, "POST", "/v1/machines/m_d1/start", "api", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(!ds[0].stub.calls()[before..]
        .iter()
        .any(|c| c.starts_with("GET /v1/backups")));
}
