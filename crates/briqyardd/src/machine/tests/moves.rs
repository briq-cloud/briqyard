//! Tests of moving a machine into another namespace (ADR 0056).

use super::*;

fn tcp(port: u16) -> api::CreateEndpointRequest {
    api::CreateEndpointRequest {
        port,
        protocol: "tcp".into(),
        host: String::new(),
    }
}

/// The addresses the host counts, as the tables would hold them.
fn counted(h: &Harness) -> Vec<String> {
    h.host.counted.lock().unwrap().keys().cloned().collect()
}

#[tokio::test]
async fn alone_into_a_new_namespace_is_a_rename() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let q = api::Quota {
        machines: Some(3),
        ..Default::default()
    };
    h.m.set_quota("t1", q).await.unwrap();
    let a = h.m.create_made(h.request("a")).await.unwrap();
    assert_eq!(a.state, state::RUNNING);
    let ep = h.m.create_endpoint(&a.id, tcp(8080)).unwrap();
    h.host_calls();
    let r = h.m.move_machine(&a.id, "t2", None).await.unwrap();
    assert_eq!(r.from, "t1");
    assert!(!r.restarted);
    assert_eq!(r.machine.namespace, "t2");
    assert_eq!(
        (r.machine.ip.as_str(), r.previous_ip.as_str()),
        (a.ip.as_str(), a.ip.as_str())
    );
    assert_eq!(r.machine.state, state::RUNNING, "never stopped");
    assert!(h.host_calls().is_empty(), "nothing touched the host");
    assert!(h.m.namespace("t1").is_err());
    let t = h.m.namespace("t2").unwrap();
    assert_eq!(t.machines, 1);
    assert_eq!(
        t.subnet,
        h.m.inner.range.subnet(1).unwrap().cidr(),
        "the same network"
    );
    assert_eq!(h.m.quota("t2").unwrap().quota, q, "the quota went with it");
    // On disk: one namespace record, the machine and its endpoint under the new name.
    let stored: Vec<NamespaceRec> = h.m.inner.store.list(crate::store::NAMESPACES).unwrap();
    assert_eq!(
        stored.iter().map(|t| t.id.as_str()).collect::<Vec<_>>(),
        ["t2"]
    );
    assert_eq!(h.stored(&a.id).unwrap().namespace, "t2");
    assert_eq!(h.m.endpoint(&ep.id).unwrap().namespace, "t2");
    let on_disk: EndpointRec = h.m.inner.store.get("endpoints", &ep.id).unwrap().unwrap();
    assert_eq!(on_disk.namespace, "t2");
    // Listed under its new namespace; a new machine goes into the renamed network.
    assert!(h.m.list(Some("t1"), &[]).is_empty());
    assert_eq!(h.m.list(Some("t2"), &[]).len(), 1);
    let mut b = h.request("b");
    b.namespace = "t2".into();
    let b = h.m.create_made(b).await.unwrap();
    assert!(b.ip.starts_with("10.64.1."), "{}", b.ip);
    // One event in each namespace; the machine's own moves its version.
    let moved = |t: &str| {
        let f = events::Filter {
            namespace: Some(t.into()),
            ..Default::default()
        };
        let evs = h.m.inner.events.read(0, &f, 5000).unwrap().events;
        evs.into_iter()
            .filter(|e| e.reason == reason::MOVED)
            .count()
    };
    assert_eq!((moved("t1"), moved("t2")), (1, 1));
    assert!(h.m.get(&a.id).unwrap().version > 0);
}

#[tokio::test]
async fn moving_into_the_namespace_it_is_in_does_nothing() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let a = h.m.create_made(h.request("a")).await.unwrap();
    let r = h.m.move_machine(&a.id, "t1", None).await.unwrap();
    assert_eq!((r.from.as_str(), r.restarted), ("t1", false));
    assert_eq!(r.machine.version, a.version);
}

#[tokio::test]
async fn into_a_namespace_that_exists_it_restarts_on_that_network() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    h.namespace("t2");
    let mut b = h.request("b");
    b.namespace = "t2".into();
    let b = h.m.create_made(b).await.unwrap();
    let a = h.m.create_made(h.request("a")).await.unwrap();
    let ep = h.m.create_endpoint(&a.id, tcp(8080)).unwrap();
    assert!(b.ip.starts_with("10.64.2."), "{}", b.ip);
    assert!(counted(&h).contains(&a.ip));
    let pid = h.m.get(&a.id).unwrap().started_at;
    let r = h.m.move_machine(&a.id, "t2", None).await.unwrap();
    assert!(r.restarted);
    assert_eq!(
        (r.from.as_str(), r.previous_ip.as_str()),
        ("t1", a.ip.as_str())
    );
    let m = r.machine;
    assert_eq!(
        (m.namespace.as_str(), m.state.as_str()),
        ("t2", state::RUNNING)
    );
    assert!(
        m.ip.starts_with("10.64.2.") && m.ip != b.ip && m.ip != a.ip,
        "{}",
        m.ip
    );
    assert_ne!(m.started_at, pid, "it booted again");
    // Its data, its name, its endpoint.
    assert_eq!(m.name, "a");
    assert!(h
        .pool
        .zfs
        .exists(&h.stored(&a.id).unwrap().dataset())
        .await
        .unwrap());
    assert_eq!(h.m.endpoint(&ep.id).unwrap().namespace, "t2");
    assert_eq!(h.m.endpoints_of(&a.id).len(), 1);
    // The counters followed the address.
    let c = counted(&h);
    assert!(c.contains(&m.ip) && !c.contains(&a.ip), "{c:?}");
    let rec = h.stored(&a.id).unwrap();
    assert_eq!((rec.subnet_index, rec.ip.as_str()), (2, m.ip.as_str()));
    // Both networks still exist; the one it left is empty and stays.
    assert_eq!(h.m.namespace("t1").unwrap().machines, 0);
    assert_eq!(h.m.namespace("t2").unwrap().machines, 2);
    assert!(h.reasons(&a.id).contains(&"moved".to_string()));
}

#[tokio::test]
async fn a_stopped_machine_moves_and_stays_stopped() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    h.namespace("t2");
    let mut a = h.request("a");
    a.start = Some(false);
    let a = h.m.create_made(a).await.unwrap();
    assert_eq!(a.state, state::CREATED);
    let r = h.m.move_machine(&a.id, "t2", None).await.unwrap();
    assert!(!r.restarted);
    assert_eq!(
        (r.machine.state.as_str(), r.machine.namespace.as_str()),
        (state::CREATED, "t2")
    );
    assert_ne!(r.machine.ip, a.ip);
    // It starts on the new network.
    let m = h.m.start(&a.id, None).await.unwrap();
    assert_eq!(m.state, state::RUNNING);
}

#[tokio::test]
async fn others_staying_behind_do_not_stop_the_move() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    h.namespace("t2");
    let a = h.m.create_made(h.request("a")).await.unwrap();
    let b = h.m.create_made(h.request("b")).await.unwrap();
    let r = h.m.move_machine(&a.id, "t2", None).await.unwrap();
    assert!(r.restarted);
    assert!(r.machine.ip.starts_with("10.64.2."), "{}", r.machine.ip);
    assert_eq!(h.m.get(&b.id).unwrap().namespace, "t1");
    assert_eq!(h.m.namespace("t2").unwrap().machines, 1);
}

#[tokio::test]
async fn a_move_the_target_refuses_changes_nothing() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    h.namespace("t2");
    let a = h.m.create_made(h.request("a")).await.unwrap();
    // A name taken in the target.
    let mut same = h.request("a");
    same.namespace = "t2".into();
    h.m.create_made(same).await.unwrap();
    let err = h.m.move_machine(&a.id, "t2", None).await.unwrap_err();
    assert!(matches!(err, MError::Conflict(_)), "{err}");
    // A quota the machine would pass.
    let mut b = h.request("b");
    b.namespace = "t2".into();
    h.m.create_made(b).await.unwrap();
    h.m.set_quota(
        "t2",
        api::Quota {
            machines: Some(2),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let mut c = h.request("c");
    c.start = Some(false);
    let c = h.m.create_made(c).await.unwrap();
    let err = h.m.move_machine(&c.id, "t2", None).await.unwrap_err();
    assert!(matches!(err, MError::Quota(_)), "{err}");
    // A namespace id that is not one.
    let err = h.m.move_machine(&a.id, "../x", None).await.unwrap_err();
    assert!(matches!(err, MError::Invalid(_)), "{err}");
    // Nothing moved, nothing stopped.
    let now = h.m.get(&a.id).unwrap();
    assert_eq!(
        (now.namespace.as_str(), now.state.as_str(), now.ip.as_str()),
        ("t1", state::RUNNING, a.ip.as_str())
    );
    assert_eq!(h.m.get(&c.id).unwrap().namespace, "t1");
}

#[tokio::test]
async fn a_refusal_after_the_stop_starts_a_running_machine_again() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    h.namespace("t2");
    let a = h.m.create_made(h.request("a")).await.unwrap();
    assert_eq!(a.state, state::RUNNING);
    let mut s = h.request("s");
    s.start = Some(false);
    let s = h.m.create_made(s).await.unwrap();
    // The counters for the new address are refused once the machine is stopped.
    h.host.refuse_count.store(true, Relaxed);
    let err = h.m.move_machine(&a.id, "t2", None).await.unwrap_err();
    assert!(matches!(err, MError::Other(_)), "{err}");
    let now = h.m.get(&a.id).unwrap();
    assert_eq!(
        (now.namespace.as_str(), now.state.as_str(), now.ip.as_str()),
        ("t1", state::RUNNING, a.ip.as_str()),
        "as it was, running"
    );
    assert!(counted(&h).contains(&a.ip));
    // A machine that was stopped stays stopped.
    let err = h.m.move_machine(&s.id, "t2", None).await.unwrap_err();
    assert!(matches!(err, MError::Other(_)), "{err}");
    assert_eq!(h.m.get(&s.id).unwrap().state, state::CREATED);
    // Once the host counts again, the same move works.
    h.host.refuse_count.store(false, Relaxed);
    let r = h.m.move_machine(&a.id, "t2", None).await.unwrap();
    assert!(r.restarted);
}

#[tokio::test]
async fn a_machine_others_send_their_traffic_through_stays() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    h.namespace("t2");
    let a = h.m.create_made(h.request("a")).await.unwrap();
    let mut b = h.request("b");
    b.egress = Some(api::Egress {
        mode: api::egress::VIA.into(),
        via: Some(a.id.clone()),
        siblings: false,
    });
    h.m.create_made(b).await.unwrap();
    let err = h.m.move_machine(&a.id, "t2", None).await.unwrap_err();
    assert!(matches!(err, MError::Conflict(_)), "{err}");
}

#[tokio::test]
async fn a_machine_in_a_namespace_with_a_gateway_is_not_alone() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    h.namespace("t2");
    let a = h.m.create_made(h.request("a")).await.unwrap();
    h.m.set_gateway(
        "t1",
        api::GatewaySpec {
            image: IMAGE.into(),
            port: 3128,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    // Not alone: the gateway is the namespace's too. It joins a new network.
    let r = h.m.move_machine(&a.id, "t2", None).await.unwrap();
    assert!(r.restarted);
    assert!(h.m.namespace("t1").is_ok());
}

#[tokio::test]
async fn a_rename_cut_short_keeps_the_record_a_machine_names() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let a = h.m.create_made(h.request("a")).await.unwrap();
    let old = h.m.inner.namespaces.lock().unwrap()["t1"].rec.clone();
    h.m.inner
        .store
        .put(crate::store::NAMESPACES, "t1", &old)
        .unwrap();
    // The new record written, the machine's not yet: both namespaces on one subnet.
    let renamed = NamespaceRec {
        id: "t2".into(),
        ..old.clone()
    };
    h.m.inner
        .store
        .put(crate::store::NAMESPACES, "t2", &renamed)
        .unwrap();
    h.m.inner.namespaces.lock().unwrap().insert(
        "t2".into(),
        Namespace::new(renamed, h.m.inner.range.subnet(old.subnet_index).unwrap()),
    );
    h.m.drop_renamed_leftovers().unwrap();
    assert!(h.m.namespace("t1").is_ok() && h.m.namespace("t2").is_err());
    assert!(h
        .m
        .inner
        .store
        .get::<NamespaceRec>(crate::store::NAMESPACES, "t2")
        .unwrap()
        .is_none());
    assert_eq!(h.m.get(&a.id).unwrap().namespace, "t1");
}

#[tokio::test]
async fn a_fork_may_name_another_namespace() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    h.namespace("t2");
    let a = h.m.create_made(h.request("a")).await.unwrap();
    let mut f = h.request("a");
    f.namespace = "t2".into();
    f.fork = Some(api::ForkSpec {
        machine_id: a.id.clone(),
        copy: String::new(),
    });
    let f = h.m.create_made(f).await.unwrap();
    assert_eq!(f.namespace, "t2");
    assert!(f.ip.starts_with("10.64.2."), "{}", f.ip);
    assert_eq!(h.m.get(&a.id).unwrap().namespace, "t1");
    assert!(h.reasons(&f.id).contains(&"forked".to_string()));
}
