//! Tests of the namespace's gateway.

use super::*;

// --- the namespace's gateway (ADR 0016) ---

pub(super) const IMAGE2: &str =
    "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000002";

pub(super) fn gateway_spec(port: u16) -> api::GatewaySpec {
    api::GatewaySpec {
        image: IMAGE.into(),
        env: BTreeMap::from([("TOKEN".to_string(), "t0k".to_string())]),
        port,
        ..Default::default()
    }
}

impl Harness {
    /// Namespace `t1` with a gateway on port 3128, not started; its machine id.
    pub(super) async fn with_gateway(&self) -> String {
        self.ready().await;
        let t = self.m.set_gateway("t1", gateway_spec(3128)).await.unwrap();
        self.host.calls();
        self.pool.calls();
        t.gateway.unwrap().machine_id
    }

    /// A machine of `t1` that sends through the namespace's gateway.
    pub(super) fn consumer(&self, name: &str) -> api::CreateMachineRequest {
        self.request_egress(name, "via", Some("gateway"))
    }

    pub(super) fn gateway_view(&self) -> api::GatewayView {
        self.m.namespace("t1").unwrap().gateway.expect("a gateway")
    }

    fn boots_of(calls: &[String], id: &str) -> usize {
        let boot = format!("boot {id} ");
        calls.iter().filter(|c| c.starts_with(&boot)).count()
    }
}

const VIA_GATEWAY: &str = "via 10.64.1.3 to 10.64.1.2 host 10.64.1.1";

#[tokio::test]
async fn a_gateway_is_a_machine_of_the_daemon_not_of_the_namespace() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let t = h.m.set_gateway("t1", gateway_spec(3128)).await.unwrap();
    let gw = t.gateway.clone().unwrap();
    assert_eq!(
        (gw.state.as_str(), gw.ip.as_str(), gw.port),
        (state::CREATED, "10.64.1.2", 3128)
    );
    assert_eq!(t.machines, 0);
    // Made, not started: disks, no process, no TAP.
    assert!(!h.host.calls().iter().any(|c| c.starts_with("boot ")));
    assert!(h
        .pool
        .dev()
        .join(format!("byard/m/{}/root", gw.machine_id))
        .exists());
    // Its record says what it is; its name in the namespace is `gateway.internal`.
    let r = h.stored(&gw.machine_id).unwrap();
    assert_eq!(r.role, Some(Role::Gateway));
    assert_eq!(r.env["TOKEN"], "t0k");
    let m = h.m.get(&gw.machine_id).unwrap();
    assert_eq!(m.hostname, "gateway.internal");
    assert_eq!(
        (
            m.sleep.as_str(),
            m.egress.clone(),
            m.restart.policy.as_str()
        ),
        ("never", api::Egress::default(), "always")
    );
    // Not one of the namespace's machines: not listed, not counted, its console readable.
    assert!(h.m.list(None, &[]).is_empty() && h.m.list(Some("t1"), &[]).is_empty());
    assert_eq!(h.m.usage().2, 0);
    assert!(h.m.logs(&gw.machine_id, "", 10).is_ok());
    // The name is taken in the namespace, like any machine's.
    assert!(matches!(
        h.m.create_made(h.request("gateway")).await,
        Err(MError::NameTaken(_))
    ));
    assert!(matches!(h.m.namespace("t9"), Err(MError::NotFound)));
    // A spec the gateway cannot run is refused before anything is made.
    for bad in [
        gateway_spec(0),
        api::GatewaySpec {
            image: String::new(),
            ..gateway_spec(3128)
        },
        api::GatewaySpec {
            size: Some(api::Size {
                vcpus: 0,
                memory_mb: 256,
                cpu_millis: None,
            }),
            ..gateway_spec(3128)
        },
    ] {
        assert!(matches!(
            h.m.set_gateway("t1", bad).await,
            Err(MError::Invalid(_))
        ));
    }
    assert_eq!(h.gateway_view().machine_id, gw.machine_id);
}

#[tokio::test]
async fn a_start_through_the_gateway_boots_it_first() {
    let h = harness("10.64.0.0/22", 4096).await;
    let gw = h.with_gateway().await;
    let m = h.m.create_made(h.consumer("sbx")).await.unwrap();
    assert_eq!(m.state, state::RUNNING);
    // The gateway's boot and its port, then the machine's pin, its policy naming the
    // gateway's address, and its boot.
    let (gtap, tap) = (netw::tap_name(&gw), netw::tap_name(&m.id));
    assert_eq!(
        h.host.calls(),
        vec![
            format!("ensure_tap {gtap} by1 10.64.1.2"),
            format!("boot {gw} tap={gtap} resume=false"),
            "wait_ready 1000".to_string(),
            "wait_port 10.64.1.2:3128".to_string(),
            format!("ensure_tap {tap} by1 10.64.1.3"),
            format!("set_policy {VIA_GATEWAY}"),
            format!("boot {} tap={tap} resume=false", m.id),
            "wait_ready 1001".to_string(),
        ]
    );
    assert_eq!(h.gateway_view().state, state::RUNNING);
    // The namespace has one machine; the host runs two and commits both.
    assert_eq!(h.m.namespace("t1").unwrap().machines, 1);
    let (used, running, total) = h.m.usage();
    assert_eq!((used.memory_mb, running, total), (512, 2, 1));
    // The tables a daemon start renders name the gateway too.
    let rules = h.m.rules().unwrap();
    assert!(rules.policies.iter().any(|p| matches!(p,
        nft::Policy::Via { to, .. } if to == "10.64.1.2")));
    // Running already: the next start probes its port and boots nothing for it.
    h.m.stop(&m.id, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    h.host.calls();
    h.m.start(&m.id, None).await.unwrap();
    let calls = h.host.calls();
    assert_eq!(Harness::boots_of(&calls, &gw), 0, "{calls:?}");
    assert_eq!(calls[0], "wait_port 10.64.1.2:3128");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_starts_through_the_gateway_boot_it_once() {
    let h = harness("10.64.0.0/22", 4096).await;
    let gw = h.with_gateway().await;
    let mut ids = Vec::new();
    for name in ["a", "b"] {
        let mut req = h.consumer(name);
        req.start = Some(false);
        ids.push(h.m.create_made(req).await.unwrap().id);
    }
    h.host.boots(Boots::Ready(Duration::from_millis(50)));
    let (ma, mb) = (h.m.clone(), h.m.clone());
    let (a, b) = (ids[0].clone(), ids[1].clone());
    let (ra, rb) = tokio::join!(
        tokio::spawn(async move { ma.start(&a, None).await }),
        tokio::spawn(async move { mb.start(&b, None).await })
    );
    assert_eq!(ra.unwrap().unwrap().state, state::RUNNING);
    assert_eq!(rb.unwrap().unwrap().state, state::RUNNING);
    let calls = h.host.calls();
    assert_eq!(Harness::boots_of(&calls, &gw), 1, "{calls:?}");
    assert_eq!(h.gateway_view().state, state::RUNNING);
}

#[tokio::test(start_paused = true)]
async fn a_gateway_that_does_not_come_up_fails_the_start_and_says_so() {
    let h = harness("10.64.0.0/22", 4096).await;
    let gw = h.with_gateway().await;
    let mut req = h.consumer("sbx");
    req.start = Some(false);
    let m = h.m.create_made(req).await.unwrap();
    h.host.calls();
    // Its program never listens: the gateway is ended, in error, with the port named.
    h.host.silent_ports.store(true, Relaxed);
    let failed = |r: Result<api::Machine, MError>| match r {
        Err(MError::BootFailed(b)) => *b,
        other => panic!("{other:?}"),
    };
    let b = failed(h.m.start(&m.id, None).await);
    // The answer is the machine asked for, not moved, the gateway's reason in it.
    assert_eq!(
        (b.id.as_str(), b.state.as_str()),
        (m.id.as_str(), state::CREATED)
    );
    assert!(
        b.error
            .starts_with("the namespace's gateway did not come up: port 3128 did not answer"),
        "{}",
        b.error
    );
    let g = h.gateway_view();
    assert_eq!(g.state, state::ERROR);
    assert!(
        g.error.starts_with("port 3128 did not answer"),
        "{}",
        g.error
    );
    let calls = h.host.calls();
    assert_eq!(Harness::boots_of(&calls, &m.id), 0, "{calls:?}");
    assert!(!calls.iter().any(|c| c.contains("10.64.1.3")), "{calls:?}");
    assert!(h.host.alive().is_empty());
    assert_eq!(h.stored(&m.id).unwrap().state, state::CREATED);
    // Its guest never comes up: the same answer, with the boot's reason.
    h.host.silent_ports.store(false, Relaxed);
    h.host.boots(Boots::Silent);
    let b = failed(h.m.start(&m.id, None).await);
    assert!(
        b.error
            .starts_with("the namespace's gateway did not come up: the guest did not come up: "),
        "{}",
        b.error
    );
    assert_eq!(h.m.get(&m.id).unwrap().state, state::CREATED);
    // Fixed: the next start brings the gateway back from `error`, then the machine.
    h.host.boots(Boots::Ready(Duration::ZERO));
    assert_eq!(h.m.start(&m.id, None).await.unwrap().state, state::RUNNING);
    assert_eq!(h.gateway_view().state, state::RUNNING);
    assert_eq!(h.m.get(&gw).unwrap().error, "");
}

#[tokio::test]
async fn the_sleeper_stops_the_gateway_once_nothing_needs_it() {
    let h = harness("10.64.0.0/22", 4096).await;
    let gw = h.with_gateway().await;
    let a = h.m.create_made(h.consumer("a")).await.unwrap();
    let b = h.m.create_made(h.consumer("b")).await.unwrap();
    let mut open = h.request("open");
    open.sleep = "never".into();
    h.m.create_made(open).await.unwrap();
    let long_ago = Some(Utc::now() - chrono::Duration::hours(1));
    let idle = |id: &str| h.m.entry(id).unwrap().rec.lock().unwrap().last_used_at = long_ago;
    // Nothing idle: the gateway stays.
    h.m.tick().await;
    assert_eq!(h.gateway_view().state, state::RUNNING);
    // One consumer asleep, the other running: it stays.
    idle(&a.id);
    h.m.tick().await;
    assert_eq!(h.m.get(&a.id).unwrap().stopped_reason, stop::IDLE);
    assert_eq!(h.gateway_view().state, state::RUNNING);
    // The last one asleep: the gateway goes in the same tick; a machine that does not
    // send through it does not keep it.
    idle(&b.id);
    h.m.tick().await;
    assert_eq!(h.m.get(&b.id).unwrap().stopped_reason, stop::IDLE);
    let g = h.m.get(&gw).unwrap();
    assert_eq!(
        (g.state.as_str(), g.stopped_reason.as_str()),
        (state::STOPPED, stop::IDLE)
    );
    // A wake of a consumer (an exec here, a connection alike) goes through the start.
    h.host.calls();
    let woken =
        h.m.exec(
            &a.id,
            api::ExecRequest {
                cmd: vec!["true".into()],
                wake: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(woken.exit_code, 0);
    assert_eq!(Harness::boots_of(&h.host.calls(), &gw), 1);
    assert_eq!(h.gateway_view().state, state::RUNNING);
}

#[tokio::test]
async fn the_sleeper_leaves_a_gateway_whose_namespace_is_busy() {
    let h = harness("10.64.0.0/22", 4096).await;
    let gw = h.with_gateway().await;
    let m = h.m.create_made(h.consumer("sbx")).await.unwrap();
    h.m.stop(&m.id, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    // A start that needs the gateway holds the namespace's lock until it is `starting`:
    // nothing runs through the gateway yet, and still it is not stopped under that start.
    let t = h.m.namespace_of("t1").unwrap();
    let held = t.lock.lock().await;
    h.m.tick().await;
    assert_eq!(h.m.get(&gw).unwrap().state, state::RUNNING);
    drop(held);
    h.m.tick().await;
    assert_eq!(h.m.get(&gw).unwrap().state, state::STOPPED);
}

#[tokio::test]
async fn a_gateway_in_use_is_kept_and_one_unused_removed() {
    let h = harness("10.64.0.0/22", 4096).await;
    let gw = h.with_gateway().await;
    let m = h.m.create_made(h.consumer("sbx")).await.unwrap();
    assert!(matches!(
        h.m.delete_gateway("t1").await,
        Err(MError::GatewayInUse)
    ));
    assert_eq!(h.gateway_view().state, state::RUNNING);
    h.m.stop(&m.id, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    h.m.delete_gateway("t1").await.unwrap();
    // Stopped and destroyed: no record, no process, no disks.
    assert!(h.m.namespace("t1").unwrap().gateway.is_none());
    assert!(matches!(h.m.get(&gw), Err(MError::NotFound)));
    assert!(h.stored(&gw).is_none());
    assert!(h.host.alive().is_empty());
    assert!(!h.pool.dev().join(format!("byard/m/{gw}")).exists());
    // Its consumer's next start is refused, with what to do; none is success.
    assert_eq!(
        refused(h.m.start(&m.id, None).await),
        "namespace has no gateway: PUT /v1/namespaces/t1/gateway first"
    );
    assert_eq!(h.stored(&m.id).unwrap().state, state::STOPPED);
    h.m.delete_gateway("t1").await.unwrap();
    h.m.delete_gateway("t-none").await.unwrap();
}

#[tokio::test]
async fn the_namespaces_removal_destroys_its_gateway() {
    let h = harness("10.64.0.0/22", 4096).await;
    let gw = h.with_gateway().await;
    let m = h.m.create_made(h.request("web")).await.unwrap();
    // The namespace's own machine keeps the namespace, and the gateway with it.
    assert!(matches!(
        h.m.delete_namespace("t1").await,
        Err(MError::NamespaceInUse)
    ));
    assert!(h.m.get(&gw).is_ok());
    h.m.destroy(&m.id, None).await.unwrap();
    h.m.delete_namespace("t1").await.unwrap();
    assert!(matches!(h.m.get(&gw), Err(MError::NotFound)));
    assert!(!h.pool.dev().join(format!("byard/m/{gw}")).exists());
    assert!(h.m.namespaces().is_empty());
}

#[tokio::test]
async fn via_gateway_needs_the_namespace_to_have_one() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let want = "namespace has no gateway: PUT /v1/namespaces/t1/gateway first";
    assert_eq!(refused(h.m.create_made(h.consumer("sbx")).await), want);
    let m = h.m.create_made(h.request("web")).await.unwrap();
    let patch =
        h.m.update(&m.id, set_egress("via", Some("gateway")), None)
            .await;
    assert_eq!(refused(patch), want);
    assert_eq!(h.stored(&m.id).unwrap().egress, api::Egress::default());
    // The gateway itself cannot send through itself: a start of it refuses.
    let t = h.m.set_gateway("t1", gateway_spec(3128)).await.unwrap();
    let gw = h.m.entry(&t.gateway.unwrap().machine_id).unwrap();
    gw.rec.lock().unwrap().egress = egress("via", Some("gateway"));
    assert_eq!(
        refused(h.m.start_entry(&gw, true).await),
        "egress.via names the machine itself"
    );
}

#[tokio::test]
async fn a_patch_to_via_gateway_runs_the_gateway_before_the_policy() {
    let h = harness("10.64.0.0/22", 4096).await;
    let gw = h.with_gateway().await;
    let mut req = h.request("sbx");
    req.sleep = "never".into();
    let m = h.m.create_made(req).await.unwrap();
    h.host.calls();
    let patched =
        h.m.update(&m.id, set_egress("via", Some("gateway")), None)
            .await
            .unwrap();
    assert!(patched.egress.via_gateway());
    let calls = h.host.calls();
    let at = |line: &str| calls.iter().position(|c| c == line).unwrap_or(usize::MAX);
    assert!(
        at("wait_port 10.64.1.2:3128") < at(&format!("set_policy {VIA_GATEWAY}")),
        "{calls:?}"
    );
    assert_eq!(Harness::boots_of(&calls, &gw), 1);
    // From now on it needs the gateway: the sleeper keeps it.
    h.m.tick().await;
    assert_eq!(h.gateway_view().state, state::RUNNING);
}

#[tokio::test]
async fn a_put_on_a_running_gateway_restarts_it_with_the_new_spec() {
    let h = harness("10.64.0.0/22", 4096).await;
    let gw = h.with_gateway().await;
    h.m.inner
        .images
        .seed(IMAGE2, ImageConfig::default())
        .await
        .unwrap();
    h.m.create_made(h.consumer("sbx")).await.unwrap();
    h.host.calls();
    h.pool.calls();
    let spec = api::GatewaySpec {
        image: IMAGE2.into(),
        ..gateway_spec(8080)
    };
    let t = h.m.set_gateway("t1", spec).await.unwrap();
    // Same machine, same address; the new port and image, running again.
    let g = t.gateway.unwrap();
    assert_eq!(
        (
            g.machine_id.as_str(),
            g.ip.as_str(),
            g.port,
            g.state.as_str()
        ),
        (gw.as_str(), "10.64.1.2", 8080, state::RUNNING)
    );
    let calls = h.host.calls();
    assert!(calls[0].starts_with("shutdown "), "{calls:?}");
    assert_eq!(Harness::boots_of(&calls, &gw), 1);
    assert_eq!(calls.last().unwrap(), "wait_port 10.64.1.2:8080");
    let key2 = h.stored(&gw).unwrap().image_key;
    // The old root disk swapped out (ADR 0031), then gone: no fork holds it.
    let zfs = h.pool.calls();
    let retired = format!("byard/m/{gw}/root.r_");
    assert!(
        zfs.iter()
            .any(|c| c.starts_with(&format!("rename byard/m/{gw}/root {retired}"))),
        "{zfs:?}"
    );
    assert!(
        zfs.iter()
            .any(|c| c.starts_with(&format!("destroy -r {retired}"))),
        "{zfs:?}"
    );
    assert!(
        zfs.contains(&format!(
            "clone byard/images/{key2}@base byard/m/{gw}/root.next"
        )),
        "{zfs:?}"
    );
    assert_eq!(h.m.get(&gw).unwrap().image, IMAGE2);
    // Asleep with a memory snapshot, then replaced: the next start boots it cold.
    let sbx = h.m.list(None, &[])[0].id.clone();
    h.m.stop(&sbx, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    let e = h.m.entry(&gw).unwrap();
    h.m.stop_entry(&e, stop::USER, Duration::from_secs(1), true, None)
        .await
        .unwrap();
    assert!(h.m.get(&gw).unwrap().suspended);
    h.m.set_gateway("t1", gateway_spec(8080)).await.unwrap();
    assert!(!h.m.get(&gw).unwrap().suspended);
    h.host.calls();
    h.m.start(&sbx, None).await.unwrap();
    let calls = h.host.calls();
    assert!(
        calls.contains(&format!(
            "boot {gw} tap={} resume=false",
            netw::tap_name(&gw)
        )),
        "{calls:?}"
    );
    // The volume is the gateway's for its life.
    let spec = api::GatewaySpec {
        volume_gb: Some(1),
        ..gateway_spec(8080)
    };
    assert!(refused(h.m.set_gateway("t1", spec).await).starts_with("volume_gb is fixed"));
}

/// A stock proxy reads its configuration and its CA from files (iron-proxy, ADR 0016):
/// the gateway's boot files are a machine's, on its config drive at each boot; a PUT that
/// changes them restarts it with the new ones; a bad one is refused as a create's is.
#[tokio::test]
async fn a_gateway_has_boot_files_as_a_machine_does() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let file = |body: &[u8]| api::File {
        path: "/etc/proxy.yaml".into(),
        base64: api::guest::base64_encode(body),
        mode: Some("0600".into()),
    };
    let spec = |body: &[u8]| api::GatewaySpec {
        files: vec![file(body)],
        ..gateway_spec(3128)
    };
    let t = h.m.set_gateway("t1", spec(b"v1")).await.unwrap();
    let gw = t.gateway.unwrap().machine_id;
    h.m.create_made(h.consumer("sbx")).await.unwrap();
    let on_drive = |body: &[u8]| vec![("files/etc/proxy.yaml".to_string(), 0o600, body.to_vec())];
    assert_eq!(h.drive(&gw).1, on_drive(b"v1"));
    h.m.set_gateway("t1", spec(b"v2")).await.unwrap();
    assert_eq!(h.gateway_view().state, state::RUNNING);
    assert_eq!(h.drive(&gw).1, on_drive(b"v2"));
    let ev = h
        .events_of(&gw)
        .into_iter()
        .rev()
        .find(|e| e.reason == "updated")
        .unwrap();
    assert_eq!(ev.data, Some(json!({"fields": ["files"]})));
    let bad = api::GatewaySpec {
        files: vec![api::File {
            path: "etc/proxy.yaml".into(),
            ..file(b"")
        }],
        ..gateway_spec(3128)
    };
    assert_eq!(
        refused(h.m.set_gateway("t1", bad).await),
        "file \"etc/proxy.yaml\": path must be absolute"
    );
}

#[tokio::test]
async fn the_gateways_address_stays_reserved_while_a_policy_names_it() {
    let h = harness("10.64.0.0/22", 4096).await;
    let gw = h.with_gateway().await;
    h.m.create_made(h.consumer("sbx")).await.unwrap();
    // Destroyed under a running consumer (by its machine id): a new gateway gets another
    // address, so the consumer's policy reaches nothing rather than a stranger.
    h.m.destroy_machine(&gw, None).await.unwrap();
    let t = h.m.set_gateway("t1", gateway_spec(3128)).await.unwrap();
    assert_eq!(t.gateway.unwrap().ip, "10.64.1.4");
}

#[tokio::test]
async fn the_gateway_is_read_only_through_the_machine_routes() {
    let h = harness("10.64.0.0/22", 4096).await;
    let gw = h.with_gateway().await;
    // Read: the machine, its console, its use.
    assert_eq!(h.m.get(&gw).unwrap().name, "gateway");
    assert!(h.m.logs(&gw, "", 10).is_ok());
    assert!(h.m.stats(&gw).await.is_ok());
    h.pool.calls();
    // Everything that changes or runs something in it is the namespace route's.
    let gateway = |r: Result<(), MError>| match r {
        Err(MError::Gateway(t)) => t,
        other => panic!("{other:?}"),
    };
    let exec = api::ExecRequest {
        cmd: vec!["true".into()],
        wake: true,
        ..Default::default()
    };
    let put = api::PutFileRequest {
        path: "/x".into(),
        base64: String::new(),
        mode: None,
    };
    let mut fork = h.request("fork");
    fork.image = String::new();
    fork.fork = Some(api::ForkSpec {
        machine_id: gw.clone(),
        copy: String::new(),
    });
    let refused = [
        gateway(h.m.destroy(&gw, None).await),
        gateway(
            h.m.stop(&gw, Duration::from_secs(1), false, None)
                .await
                .map(|_| ()),
        ),
        gateway(h.m.start(&gw, None).await.map(|_| ())),
        gateway(h.m.wake(&gw, None).await.map(|_| ())),
        gateway(h.m.touch(&gw)),
        gateway(
            h.m.update(&gw, set_egress("none", None), None)
                .await
                .map(|_| ()),
        ),
        gateway(h.m.create_made(fork).await.map(|_| ())),
        gateway(h.m.exec(&gw, exec).await.map(|_| ())),
        gateway(h.m.put_file(&gw, put).await),
        gateway(h.m.get_file(&gw, "/etc/hostname").await.map(|_| ())),
        gateway(
            h.m.snapshot(&gw, api::SnapshotRequest::default())
                .await
                .map(|_| ()),
        ),
        gateway(h.m.snapshots(&gw).await.map(|_| ())),
        gateway(h.m.delete_snapshot(&gw, "s_1").await),
        gateway(h.m.restore_snapshot(&gw, "s_1", None).await.map(|_| ())),
        gateway(h.m.backup(&gw).await.map(|_| ())),
        gateway(
            h.m.create_endpoint(
                &gw,
                api::CreateEndpointRequest {
                    port: 3128,
                    ..Default::default()
                },
            )
            .map(|_| ()),
        ),
    ];
    assert!(refused.iter().all(|t| t == "t1"), "{refused:?}");
    assert_eq!(
        MError::Gateway("t1".into()).to_string(),
        "the namespace's gateway: use /v1/namespaces/t1/gateway"
    );
    // Untouched: not started, not destroyed, no other machine made, no snapshot taken.
    assert_eq!(h.gateway_view().state, state::CREATED);
    assert!(h.host.calls().is_empty());
    assert!(h.m.list(None, &[]).is_empty());
    assert!(h.pool.calls().is_empty());
}

#[tokio::test]
async fn recovery_starts_the_gateway_an_adopted_machine_needs() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.namespace("t1");
    h.namespace("t2");
    let gateway = |id: &str, namespace: &str| {
        // Found running, its process gone with the daemon: nothing to adopt.
        let e = h.add(id, state::RUNNING, 256);
        e.set_state(state::RUNNING, |r| {
            (r.role, r.namespace, r.name) =
                (Some(Role::Gateway), namespace.into(), "gateway".into());
            (r.ports, r.pid) = (vec![3128], 4242);
            None
        });
        e
    };
    let adopted = |id: &str, namespace: &str, n: u8, eg: api::Egress| {
        let e = h.add(id, state::RUNNING, 256);
        let pid = h.host.left_running(id, &h.m.inner.cfg.run_dir().join(id));
        e.set_state(state::RUNNING, |r| {
            (r.namespace, r.name, r.egress, r.pid) = (namespace.into(), id.into(), eg, pid);
            (r.host_num, r.ip) = (n, format!("10.64.1.{n}"));
            None
        });
        e
    };
    let needed = gateway("m_gw", "t1");
    h.disks(&needed).await;
    let sbx = adopted("m_sbx", "t1", 3, egress("via", Some("gateway")));
    // A namespace whose adopted machine does not send through its gateway.
    let unneeded = gateway("m_gw2", "t2");
    adopted("m_open", "t2", 4, api::Egress::default());
    h.m.recover().await;
    // Started detached, as a start that needs it would: boot, then its port.
    tokio::time::timeout(Duration::from_secs(5), async {
        while needed.snapshot().state != state::RUNNING {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the gateway runs");
    let calls = h.host.calls();
    assert!(
        calls.contains(&"wait_port 10.64.1.2:3128".to_string()),
        "{calls:?}"
    );
    assert!(
        sbx.live.lock().unwrap().is_some(),
        "the machine was adopted"
    );
    assert_eq!(sbx.snapshot().state, state::RUNNING);
    let r = unneeded.snapshot();
    assert_eq!(
        (r.state.as_str(), r.stopped_reason.as_str()),
        (state::STOPPED, stop::HOST)
    );
    assert!(
        !calls.iter().any(|c| c.starts_with("boot m_gw2 ")),
        "{calls:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_put_with_start_runs_the_gateway_before_any_machine_needs_it() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let start = api::GatewaySpec {
        start: true,
        ..gateway_spec(3128)
    };
    let t = h.m.set_gateway("t1", start.clone()).await.unwrap();
    let gw = t.gateway.unwrap();
    assert_eq!(gw.state, state::RUNNING);
    let tap = netw::tap_name(&gw.machine_id);
    assert_eq!(
        h.host.calls(),
        [
            format!("ensure_tap {tap} by1 10.64.1.2"),
            format!("boot {} tap={tap} resume=false", gw.machine_id),
            "wait_ready 1000".to_string(),
            "wait_port 10.64.1.2:3128".to_string(),
        ]
    );
    // Running with the spec it has: left as is, its port asked again.
    h.m.set_gateway("t1", start.clone()).await.unwrap();
    assert_eq!(h.host.calls(), ["wait_port 10.64.1.2:3128"]);
    // Nothing needs it: the sleeper may stop it, and a machine's start brings it back.
    h.m.tick().await;
    assert_eq!(h.gateway_view().state, state::STOPPED);
    // A program that never listens: boot_failed names the gateway, with its console.
    h.m.inner.store.delete("machines", &gw.machine_id).unwrap();
    h.host.silent_ports.store(true, Relaxed);
    let b = match h.m.set_gateway("t1", start).await {
        Err(MError::BootFailed(b)) => b,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        (b.id.as_str(), b.state.as_str()),
        (gw.machine_id.as_str(), state::ERROR)
    );
    assert!(
        b.error.starts_with("port 3128 did not answer"),
        "{}",
        b.error
    );
    assert_eq!(h.gateway_view().state, state::ERROR);
}

#[tokio::test(start_paused = true)]
async fn an_unenforceable_gateway_size_leaves_the_running_gateway_unchanged() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let mut spec = gateway_spec(3128);
    spec.start = true;
    let before =
        h.m.set_gateway("t1", spec.clone())
            .await
            .unwrap()
            .gateway
            .unwrap();
    let old = h.stored(&before.machine_id).unwrap();
    h.host.calls();
    spec.size = Some(api::Size {
        vcpus: 1,
        memory_mb: 128,
        cpu_millis: Some(250),
    });
    let err = h.m.set_gateway("t1", spec).await.unwrap_err();
    assert!(err.to_string().contains("requires the jailer"));
    let after = h.m.get(&before.machine_id).unwrap();
    assert_eq!(after.state, state::RUNNING);
    assert_eq!(after.size, old.size);
    assert!(h.host.calls().is_empty(), "no stop or boot before refusal");
}
