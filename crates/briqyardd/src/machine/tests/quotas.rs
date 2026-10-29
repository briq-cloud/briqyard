//! Tests of a tenant's quota.

use super::*;

#[test]
fn a_quota_refuses_the_first_limit_a_request_passes() {
    let q = api::Quota {
        machines: Some(2),
        memory_mb: Some(512),
        disk_gb: Some(10),
        vcpus: None,
    };
    let used = api::QuotaUse {
        machines: 1,
        memory_mb: 256,
        vcpus: 1,
        disk_gb: 10,
    };
    let need = |machines, memory_mb, disk_gb| api::QuotaUse {
        machines,
        memory_mb,
        vcpus: 64,
        disk_gb,
    };
    assert_eq!(
        over_quota("t1", &q, &used, &need(1, 256, 0)),
        None,
        "up to the limit"
    );
    let x = over_quota("t1", &q, &used, &need(1, 512, 0)).unwrap();
    assert_eq!(
        x.to_string(),
        "tenant t1's quota: memory_mb 256 of 512 used, 512 more asked"
    );
    // Disk is used up: a machine with no volume still fits, one with a volume does not.
    assert_eq!(over_quota("t1", &q, &used, &need(1, 0, 0)), None);
    let x = over_quota("t1", &q, &used, &need(1, 0, 1)).unwrap();
    assert_eq!(
        (x.resource, x.limit, x.used, x.need),
        ("disk_gb", 10, 10, 1)
    );
    // Machines are checked first; no limit is none.
    let x = over_quota("t1", &q, &used, &need(2, 9999, 9)).unwrap();
    assert_eq!(x.resource, "machines");
    assert_eq!(
        over_quota("t1", &api::Quota::default(), &used, &need(99, 99_999, 999)),
        None
    );
    let none = api::Quota {
        machines: Some(0),
        ..Default::default()
    };
    assert!(over_quota("t1", &none, &api::QuotaUse::default(), &need(1, 0, 0)).is_some());
}

#[tokio::test]
async fn quotas_hold_a_tenant_at_create_fork_and_start() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    assert!(matches!(h.m.quota("t9"), Err(MError::NotFound)));
    let set = |machines, memory_mb| api::Quota {
        machines: Some(machines),
        memory_mb: Some(memory_mb),
        disk_gb: Some(5),
        vcpus: None,
    };
    // Put before any machine (the tenant is made, as `ensure_tenant` makes one; the
    // network needs the host, so known here).
    h.tenant("t2");
    let q = h.m.set_quota("t2", set(1, 384)).await.unwrap();
    assert_eq!((q.quota, q.used), (set(1, 384), api::QuotaUse::default()));
    assert_eq!(h.m.tenant("t2").unwrap().machines, 0);
    let stored: TenantRec = h.m.inner.store.get("tenants", "t2").unwrap().unwrap();
    assert_eq!(stored.quota, set(1, 384), "kept across a restart");
    h.m.set_quota("t1", set(2, 384)).await.unwrap();
    let a = h.m.create_made(h.request("a")).await.unwrap();
    let mut b = h.request("b");
    b.start = Some(false);
    let b = h.m.create_made(b).await.unwrap();
    // The use, as the quota counts it: two machines, one of them running.
    let used = |t| h.m.quota(t).unwrap().used;
    assert_eq!(
        used("t1"),
        api::QuotaUse {
            machines: 2,
            memory_mb: 256,
            vcpus: 1,
            disk_gb: 0
        }
    );
    // A start past memory: refused, the machine as it was, an event about it.
    let err = h.m.start(&b.id, None).await.unwrap_err();
    assert!(matches!(err, MError::Quota(_)), "{err}");
    assert_eq!(
        err.to_string(),
        "tenant t1's quota: memory_mb 256 of 384 used, 256 more asked"
    );
    assert_eq!(h.m.get(&b.id).unwrap().state, state::CREATED);
    let ev = h.events_of(&b.id).pop().unwrap();
    assert_eq!(
        (ev.reason.as_str(), ev.kind.as_str()),
        ("quota_exceeded", "warning")
    );
    assert_eq!(ev.message, format!("start refused: {err}"));
    assert_eq!(
        ev.data.unwrap(),
        json!({"resource": "memory_mb", "limit": 384, "used": 256, "need": 256})
    );
    assert_eq!(h.m.get(&b.id).unwrap().version, ev.seq, "an event about it");
    // A fork past the machines: refused before anything is made, an event of the tenant.
    let mut fork = h.request("f");
    fork.image.clear();
    fork.fork = Some(api::ForkSpec {
        machine_id: a.id.clone(),
        copy: String::new(),
    });
    let err = h.m.create_made(fork).await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "tenant t1's quota: machines 2 of 2 used, 1 more asked"
    );
    assert_eq!(h.m.list(Some("t1"), &[]).len(), 2);
    let f = events::Filter {
        tenant: Some("t1".into()),
        ..Default::default()
    };
    let last =
        h.m.inner
            .events
            .read(0, &f, 5000)
            .unwrap()
            .events
            .pop()
            .unwrap();
    assert_eq!(
        (
            last.reason.as_str(),
            last.machine_id.as_str(),
            last.tenant.as_str()
        ),
        ("quota_exceeded", "", "t1")
    );
    assert_eq!(last.message, format!("create of f refused: {err}"));
    // The gateway counts as a machine.
    let err = h.m.set_gateway("t1", gateway_spec(3128)).await.unwrap_err();
    assert!(err.to_string().contains("machines 2 of 2"), "{err}");
    // With room for machines: a create that starts is held to memory before it is made,
    // and one with a volume to disk.
    h.m.set_quota("t1", set(5, 384)).await.unwrap();
    let err = h.m.create_made(h.request("c")).await.unwrap_err();
    assert!(err.to_string().contains("memory_mb 256 of 384"), "{err}");
    let mut v = h.request("v");
    v.volume = Some(api::VolumeSpec {
        size_gb: 6,
        mount: "/data".into(),
    });
    let err = h.m.create_made(v).await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "tenant t1's quota: disk_gb 0 of 5 used, 6 more asked"
    );
    assert_eq!(h.m.list(Some("t1"), &[]).len(), 2, "nothing made");
    // Once a stops, b starts: memory is what runs.
    h.m.stop(&a.id, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    assert_eq!(used("t1").memory_mb, 0);
    assert_eq!(h.m.start(&b.id, None).await.unwrap().state, state::RUNNING);
    // A quota lowered under the use stops nothing.
    h.m.set_quota("t1", set(1, 0)).await.unwrap();
    assert_eq!(h.m.get(&b.id).unwrap().state, state::RUNNING);
    assert_eq!(used("t1").machines, 2);
}
