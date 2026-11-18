//! Tests of the gateway's loaded-policy fence (ADR 0143). The host is the mock one: these show
//! the order of calls, the refusals and what stays closed, never packets.

use super::mock::PolicyReply;
use super::*;

mod moves;
mod ownership;

const GW_IP: &str = "10.64.1.2";

fn binding(byte: &str) -> api::GatewayPolicyBinding {
    api::GatewayPolicyBinding {
        policy_format: 1,
        policy_digest: format!("sha256:{}", byte.repeat(32)),
        enforcement_version: 1,
    }
}

fn report(challenge: &str, b: &api::GatewayPolicyBinding) -> Vec<u8> {
    let mut out = serde_json::to_vec(&json!({
        "challenge": challenge,
        "policy_format": b.policy_format,
        "policy_digest": b.policy_digest,
        "enforcement_version": b.enforcement_version,
        "ready": true,
    }))
    .unwrap();
    out.push(b'\n');
    out
}

fn answer(b: &api::GatewayPolicyBinding) -> impl Fn(&str, u32) -> PolicyReply + Send + Sync {
    let b = b.clone();
    move |challenge, _| PolicyReply {
        stdout: report(challenge, &b),
        ..Default::default()
    }
}

fn bound_spec(b: &api::GatewayPolicyBinding) -> api::GatewaySpec {
    api::GatewaySpec {
        policy: Some(b.clone()),
        ..gateway_spec(3128)
    }
}

impl Harness {
    fn helper(&self, f: impl Fn(&str, u32) -> PolicyReply + Send + Sync + 'static) {
        *self.host.policy_reply.lock().unwrap() = Some(Arc::new(f));
    }

    fn gate_closed(&self) -> bool {
        self.host.gates.lock().unwrap().contains(GW_IP)
    }

    /// A namespace with a bound gateway, not started, answering as its helper should.
    async fn with_bound_gateway(&self, b: &api::GatewayPolicyBinding) -> String {
        self.ready().await;
        self.helper(answer(b));
        let t = self.m.set_gateway("t1", bound_spec(b)).await.unwrap();
        self.host.calls();
        self.pool.calls();
        t.gateway.unwrap().machine_id
    }

    fn bound_consumer(
        &self,
        name: &str,
        b: &api::GatewayPolicyBinding,
    ) -> api::CreateMachineRequest {
        let mut request = self.consumer(name);
        request.egress.as_mut().unwrap().gateway_policy = Some(b.clone());
        request
    }
}

type Case = Box<dyn Fn(&str, u32) -> PolicyReply + Send + Sync>;

fn challenge() -> String {
    "c".repeat(64)
}

#[tokio::test]
async fn delayed_report_from_a_prior_incarnation_cannot_verify_a_new_live_handle() {
    let h = Arc::new(harness("10.64.0.0/22", 4096).await);
    let b = binding("ab");
    let id = h.with_bound_gateway(&b).await;
    drop(h.m.ensure_gateway("t1", Some(&b)).await.unwrap());
    let arrived = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    {
        let (arrived, release, b) = (arrived.clone(), release.clone(), b.clone());
        h.helper(move |challenge, _| PolicyReply {
            stdout: report(challenge, &b),
            arrived: Some(arrived.clone()),
            wait: Some(release.clone()),
            ..Default::default()
        });
    }
    let reading = {
        let h = h.clone();
        tokio::spawn(async move {
            h.m.ensure_gateway("t1", Some(&binding("ab")))
                .await
                .map(drop)
        })
    };
    arrived.notified().await;
    let gw = h.m.entry(&id).unwrap();
    let old = gw.snapshot().boot_incarnation;
    let dir = h.m.inner.cfg.run_dir().join(&id);
    let pid = h.host.left_running(&id, &dir);
    let live =
        h.m.inner
            .vmm
            .adopt(
                &id,
                &dir,
                h.m.jail_for(&gw.snapshot()).as_ref(),
                pid,
                gw.disk_io.clone(),
            )
            .await
            .unwrap();
    assert_ne!(live.incarnation, old);
    {
        let mut record = gw.rec.lock().unwrap();
        record.pid = pid;
        record.boot_incarnation = live.incarnation.clone();
    }
    *gw.live.lock().unwrap() = Some(live);
    release.notify_one();
    assert!(matches!(
        reading.await.unwrap(),
        Err(MError::GatewayPolicy(_))
    ));
    assert!(gw.gateway_proof.lock().unwrap().is_none());
    assert!(h.gate_closed());
}

#[tokio::test]
async fn policy_status_deadline_includes_namespace_lock_contention() {
    let h = harness("10.64.0.0/22", 4096).await;
    let b = binding("ab");
    h.with_bound_gateway(&b).await;
    let namespace = h.m.namespace_of("t1").unwrap();
    let _turn = namespace.lock.lock().await;
    h.host.calls();
    tokio::time::pause();
    let err =
        h.m.gateway_policy_status(
            "t1",
            api::GatewayPolicyStatusRequest {
                challenge: challenge(),
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, MError::GatewayPolicy(_)));
    assert!(h.host.calls().is_empty());
}

#[tokio::test]
async fn actual_readback_deadline_revokes_previous_verification() {
    let h = harness("10.64.0.0/22", 4096).await;
    let b = binding("ab");
    let id = h.with_bound_gateway(&b).await;
    drop(h.m.ensure_gateway("t1", Some(&b)).await.unwrap());
    let release = Arc::new(tokio::sync::Notify::new());
    h.helper(move |_, _| PolicyReply {
        wait: Some(release.clone()),
        ..Default::default()
    });
    tokio::time::pause();
    assert!(matches!(
        h.m.ensure_gateway("t1", Some(&b)).await,
        Err(MError::GatewayPolicy(_))
    ));
    assert!(h.gate_closed());
    assert!(h
        .m
        .entry(&id)
        .unwrap()
        .gateway_proof
        .lock()
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn ordinary_restart_and_recovery_never_use_the_gateway_policy_path() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let m = h.m.create_made(h.request("ordinary")).await.unwrap();
    h.host.calls();
    h.m.restart(&m.id, None).await.unwrap();
    let entry = h.m.entry(&m.id).unwrap();
    assert!(h
        .m
        .adopt(&entry, entry.snapshot().pid, false)
        .await
        .unwrap());
    let calls = h.host.calls();
    assert!(
        !calls
            .iter()
            .any(|c| c.contains("policy-status") || c.contains("gateway_gate")),
        "{calls:?}"
    );
}

#[tokio::test]
async fn failed_fresh_verification_revokes_an_open_gate_and_cached_proof() {
    for timed_out in [false, true] {
        let h = harness("10.64.0.0/22", 4096).await;
        let b = binding("ab");
        let id = h.with_bound_gateway(&b).await;
        let turn = h.m.ensure_gateway("t1", Some(&b)).await.unwrap();
        drop(turn);
        let gw = h.m.entry(&id).unwrap();
        let live = gw.live.lock().unwrap().clone().unwrap();
        assert!(!h.gate_closed());
        assert!(gw.gateway_proof.lock().unwrap().is_some());
        h.helper(move |_, _| PolicyReply {
            stdout: b"malformed".to_vec(),
            timed_out,
            ..Default::default()
        });
        assert!(matches!(
            h.m.ensure_gateway("t1", Some(&b)).await,
            Err(MError::GatewayPolicy(_))
        ));
        assert!(h.gate_closed());
        assert!(gw.gateway_proof.lock().unwrap().is_none());
        assert!(!*live.exited.borrow());
        assert!(gw
            .live
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .exited
            .same_channel(&live.exited));
    }
}

#[tokio::test]
async fn failed_open_revokes_cached_proof_and_attempts_to_close() {
    let h = harness("10.64.0.0/22", 4096).await;
    let b = binding("ab");
    let id = h.with_bound_gateway(&b).await;
    drop(h.m.ensure_gateway("t1", Some(&b)).await.unwrap());
    h.host.calls();
    h.host.refuse_open_gate.store(true, Relaxed);
    assert!(matches!(
        h.m.ensure_gateway("t1", Some(&b)).await,
        Err(MError::GatewayPolicy(_))
    ));
    assert!(h
        .m
        .entry(&id)
        .unwrap()
        .gateway_proof
        .lock()
        .unwrap()
        .is_none());
    let calls = h.host.calls();
    assert!(calls
        .iter()
        .any(|c| c == &format!("gateway_gate {GW_IP} open")));
    assert!(calls
        .iter()
        .any(|c| c == &format!("gateway_gate {GW_IP} closed")));
    assert!(h.gate_closed());
}

#[tokio::test]
async fn a_bound_machine_starts_only_after_the_gateway_is_read_back() {
    let h = harness("10.64.0.0/22", 4096).await;
    let b = binding("ab");
    let gw = h.with_bound_gateway(&b).await;
    assert_eq!(h.gateway_view().policy, Some(b.clone()));
    assert_eq!(h.stored(&gw).unwrap().gateway_policy, Some(b.clone()));
    let m = h.m.create_made(h.bound_consumer("sbx", &b)).await.unwrap();
    assert_eq!(m.state, state::RUNNING);
    let calls = h.host.calls();
    let at = |needle: &str| {
        calls
            .iter()
            .position(|c| c.contains(needle))
            .unwrap_or_else(|| panic!("{needle}: {calls:?}"))
    };
    let (close, tap, readback, open, consumer) = (
        at(&format!("gateway_gate {GW_IP} closed")),
        at(&format!("ensure_tap {} ", netw::tap_name(&gw))),
        at("policy-status"),
        at(&format!("gateway_gate {GW_IP} open")),
        at(&format!("ensure_tap {} ", netw::tap_name(&m.id))),
    );
    assert!(
        close < tap && tap < readback && readback < open && open < consumer,
        "{calls:?}"
    );
    assert!(!h.gate_closed());
}

#[tokio::test]
async fn nothing_but_an_exact_current_report_opens_the_gate() {
    let b = binding("ab");
    let other = binding("cd");
    let good = {
        let b = b.clone();
        move |c: &str| report(c, &b)
    };
    let cases: Vec<(&str, Case)> = vec![
        (
            "no helper",
            Box::new(|_, _| PolicyReply {
                code: 127,
                stderr: b"x".to_vec(),
                ..Default::default()
            }),
        ),
        (
            "malformed",
            Box::new(|_, _| PolicyReply {
                stdout: b"{".to_vec(),
                ..Default::default()
            }),
        ),
        ("empty", Box::new(|_, _| PolicyReply::default())),
        ("trailing document", {
            let good = good.clone();
            Box::new(move |c, _| {
                let mut out = good(c);
                out.extend(good(c));
                PolicyReply {
                    stdout: out,
                    ..Default::default()
                }
            })
        }),
        ("trailing text", {
            let good = good.clone();
            Box::new(move |c, _| {
                let mut out = good(c);
                out.extend(b"extra");
                PolicyReply {
                    stdout: out,
                    ..Default::default()
                }
            })
        }),
        (
            "oversized",
            Box::new(|_, _| PolicyReply {
                stdout: vec![b' '; 5000],
                ..Default::default()
            }),
        ),
        ("wrong challenge", {
            let b = b.clone();
            Box::new(move |_, _| PolicyReply {
                stdout: report(&"0".repeat(64), &b),
                ..Default::default()
            })
        }),
        ("wrong digest", {
            let other = other.clone();
            Box::new(move |c, _| PolicyReply {
                stdout: report(c, &other),
                ..Default::default()
            })
        }),
        ("not ready", {
            let b = b.clone();
            Box::new(move |c, _| {
                let mut doc: serde_json::Value = serde_json::from_slice(&report(c, &b)).unwrap();
                doc["ready"] = json!(false);
                PolicyReply {
                    stdout: serde_json::to_vec(&doc).unwrap(),
                    ..Default::default()
                }
            })
        }),
        ("unknown field", {
            let b = b.clone();
            Box::new(move |c, _| {
                let mut doc: serde_json::Value = serde_json::from_slice(&report(c, &b)).unwrap();
                doc["extra"] = json!(1);
                PolicyReply {
                    stdout: serde_json::to_vec(&doc).unwrap(),
                    ..Default::default()
                }
            })
        }),
        ("exit code", {
            let good = good.clone();
            Box::new(move |c, _| PolicyReply {
                stdout: good(c),
                code: 1,
                ..Default::default()
            })
        }),
        ("stderr", {
            let good = good.clone();
            Box::new(move |c, _| PolicyReply {
                stdout: good(c),
                stderr: b"warn".to_vec(),
                ..Default::default()
            })
        }),
        ("timed out", {
            let good = good.clone();
            Box::new(move |c, _| PolicyReply {
                stdout: good(c),
                timed_out: true,
                ..Default::default()
            })
        }),
    ];
    for (name, reply) in cases {
        let h = harness("10.64.0.0/22", 4096).await;
        h.with_bound_gateway(&b).await;
        h.helper(reply);
        let err =
            h.m.create_made(h.bound_consumer("sbx", &b))
                .await
                .unwrap_err();
        let said = err.to_string();
        assert!(said.contains("not verified"), "{name}: {said}");
        assert!(
            !said.contains("extra") && !said.contains("warn"),
            "{name}: {said}"
        );
        assert!(h.gate_closed(), "{name}: the gate must stay closed");
        assert!(
            !h.host
                .calls()
                .iter()
                .any(|c| c.contains(&format!("gateway_gate {GW_IP} open"))),
            "{name}"
        );
        assert!(
            h.m.list(Some("t1"), &[])
                .iter()
                .all(|m| m.state != state::RUNNING),
            "{name}"
        );
    }
}

#[tokio::test]
async fn a_gate_that_cannot_be_closed_or_opened_fails_the_start() {
    let h = harness("10.64.0.0/22", 4096).await;
    let b = binding("ab");
    h.with_bound_gateway(&b).await;
    h.host.refuse_gate.store(true, Relaxed);
    assert!(h.m.create_made(h.bound_consumer("sbx", &b)).await.is_err());
    assert!(h
        .m
        .list(Some("t1"), &[])
        .iter()
        .all(|m| m.state != state::RUNNING));
}

#[tokio::test]
async fn the_status_route_reports_the_daemons_own_identity_and_never_starts_anything() {
    let h = harness("10.64.0.0/22", 4096).await;
    let b = binding("ab");
    let gw = h.with_bound_gateway(&b).await;
    let ask = || api::GatewayPolicyStatusRequest {
        challenge: challenge(),
    };
    // Not running: no wake, no start.
    let err = h.m.gateway_policy_status("t1", ask()).await.unwrap_err();
    assert!(matches!(err, MError::GatewayPolicy(_)), "{err}");
    assert_eq!(h.m.entry(&gw).unwrap().snapshot().state, state::CREATED);
    assert!(h.host.calls().is_empty());
    let mut spec = bound_spec(&b);
    spec.start = true;
    h.m.set_gateway("t1", spec).await.unwrap();
    let status = h.m.gateway_policy_status("t1", ask()).await.unwrap();
    let rec = h.m.entry(&gw).unwrap().snapshot();
    let inc = rec.boot_incarnation.unwrap();
    assert_eq!(
        (status.namespace.as_str(), status.machine_id.as_str()),
        ("t1", gw.as_str())
    );
    assert_eq!(
        (
            status.native_incarnation.pid,
            status.native_incarnation.start_ticks,
            status.native_incarnation.host_boot_id.as_str()
        ),
        (inc.pid, inc.start_ticks, inc.host_boot_id.as_str())
    );
    assert_eq!(status.report.challenge, challenge());
    // Malformed challenges are refused before the guest is asked.
    for bad in ["", "ABC", &"C".repeat(64), &"c".repeat(63)] {
        let req = api::GatewayPolicyStatusRequest {
            challenge: bad.into(),
        };
        assert!(matches!(
            h.m.gateway_policy_status("t1", req).await,
            Err(MError::Invalid(_))
        ));
    }
    assert!(matches!(
        h.m.gateway_policy_status("t9", ask()).await,
        Err(MError::NotFound)
    ));
}

#[tokio::test]
async fn a_gateway_with_no_binding_has_nothing_to_read_back() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let mut spec = gateway_spec(3128);
    spec.start = true;
    h.m.set_gateway("t1", spec).await.unwrap();
    let err =
        h.m.gateway_policy_status(
            "t1",
            api::GatewayPolicyStatusRequest {
                challenge: challenge(),
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, MError::GatewayPolicy(_)));
    let calls = h.host.calls();
    assert!(
        !calls
            .iter()
            .any(|c| c.contains("gateway_gate") || c.contains("policy-status")),
        "{calls:?}"
    );
}

#[tokio::test]
async fn a_process_that_ends_during_the_readback_is_not_a_verification() {
    let h = Arc::new(harness("10.64.0.0/22", 4096).await);
    let b = binding("ab");
    let gw = h.with_bound_gateway(&b).await;
    let mut spec = bound_spec(&b);
    spec.start = true;
    h.m.set_gateway("t1", spec).await.unwrap();
    let arrived = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    {
        let (arrived, release, b) = (arrived.clone(), release.clone(), b.clone());
        h.helper(move |c, _| PolicyReply {
            stdout: report(c, &b),
            arrived: Some(arrived.clone()),
            wait: Some(release.clone()),
            ..Default::default()
        });
    }
    let asking = {
        let h = h.clone();
        tokio::spawn(async move {
            h.m.gateway_policy_status(
                "t1",
                api::GatewayPolicyStatusRequest {
                    challenge: challenge(),
                },
            )
            .await
        })
    };
    arrived.notified().await;
    // The old process dies while its answer is in flight, and the reply still arrives.
    let pid = h.m.entry(&gw).unwrap().snapshot().pid;
    h.host.exit(pid, 1, false);
    release.notify_one();
    let err = asking.await.unwrap().unwrap_err();
    assert!(matches!(err, MError::GatewayPolicy(_)), "{err}");
}

#[tokio::test]
async fn any_bound_machine_keeps_the_gateway_from_replacement_or_deletion() {
    let h = harness("10.64.0.0/22", 4096).await;
    let b = binding("ab");
    let gw = h.with_bound_gateway(&b).await;
    let mut request = h.bound_consumer("sbx", &b);
    request.start = Some(false);
    let m = h.m.create_made(request).await.unwrap();
    assert_eq!(m.state, state::CREATED);
    let before = h.m.entry(&gw).unwrap().snapshot();
    h.host.calls();
    // The same spec is still a no-op.
    h.m.set_gateway("t1", bound_spec(&b)).await.unwrap();
    // A change, or any other binding, is refused before anything moves.
    let mut changed = bound_spec(&b);
    changed.env.insert("CHANGED".into(), "yes".into());
    assert!(matches!(
        h.m.set_gateway("t1", changed).await,
        Err(MError::Conflict(_))
    ));
    assert!(matches!(
        h.m.set_gateway("t1", bound_spec(&binding("cd"))).await,
        Err(MError::Invalid(_))
    ));
    assert!(matches!(
        h.m.set_gateway("t1", gateway_spec(3128)).await,
        Err(MError::Invalid(_))
    ));
    assert!(matches!(
        h.m.delete_gateway("t1").await,
        Err(MError::Conflict(_))
    ));
    let after = h.m.entry(&gw).unwrap().snapshot();
    assert_eq!((after.env, after.state), (before.env, before.state));
    assert!(h.host.calls().is_empty());
    // Destroying the machine lets the gateway go.
    h.m.destroy(&m.id, None).await.unwrap();
    h.m.delete_gateway("t1").await.unwrap();
}

#[tokio::test]
async fn a_binding_is_fixed_for_the_machine_and_must_equal_the_gateways() {
    let h = harness("10.64.0.0/22", 4096).await;
    let b = binding("ab");
    h.with_bound_gateway(&b).await;
    // Another digest, siblings, or a legacy gateway: refused at admission.
    for bad in [binding("cd")] {
        assert!(matches!(
            h.m.create_made(h.bound_consumer("x", &bad)).await,
            Err(MError::Invalid(_))
        ));
    }
    let mut siblings = h.bound_consumer("x", &b);
    siblings.egress.as_mut().unwrap().siblings = true;
    assert!(matches!(
        h.m.create_made(siblings).await,
        Err(MError::Invalid(_))
    ));
    let mut request = h.bound_consumer("sbx", &b);
    request.start = Some(false);
    let m = h.m.create_made(request).await.unwrap();
    let update = |egress: api::Egress| api::UpdateMachineRequest {
        egress: Some(egress),
        ..Default::default()
    };
    // Removing, changing or re-stating it: only the last is allowed.
    let mut bare = h.consumer("y").egress.unwrap();
    assert!(matches!(
        h.m.update(&m.id, update(bare.clone()), None).await,
        Err(MError::Invalid(_))
    ));
    bare.gateway_policy = Some(binding("cd"));
    assert!(matches!(
        h.m.update(&m.id, update(bare), None).await,
        Err(MError::Invalid(_))
    ));
    assert!(matches!(
        h.m.update(&m.id, update(api::Egress::default()), None)
            .await,
        Err(MError::Invalid(_))
    ));
    h.m.update(
        &m.id,
        update(h.bound_consumer("z", &b).egress.unwrap()),
        None,
    )
    .await
    .unwrap();
    // Nor can an unbound machine be converted.
    let plain = h.m.create_made(h.request("plain")).await.unwrap();
    assert!(matches!(
        h.m.update(
            &plain.id,
            update(h.bound_consumer("z", &b).egress.unwrap()),
            None
        )
        .await,
        Err(MError::Invalid(_))
    ));
    // A bound machine in a namespace whose gateway carries no binding is refused.
    let h2 = harness("10.64.0.0/22", 4096).await;
    let _ = h2.with_gateway().await;
    assert!(matches!(
        h2.m.create_made(h2.bound_consumer("x", &b)).await,
        Err(MError::Invalid(_))
    ));
}

#[tokio::test]
async fn a_restart_of_a_bound_gateway_is_closed_until_it_is_read_back_again() {
    let h = harness("10.64.0.0/22", 4096).await;
    let b = binding("ab");
    let gw = h.with_bound_gateway(&b).await;
    let mut spec = bound_spec(&b);
    spec.start = true;
    h.m.set_gateway("t1", spec).await.unwrap();
    assert!(!h.gate_closed());
    let first = h.m.entry(&gw).unwrap().snapshot().boot_incarnation.unwrap();
    // The restart finds a helper that no longer answers: the gate must stay closed.
    h.helper(|_, _| PolicyReply {
        stdout: b"nope".to_vec(),
        ..Default::default()
    });
    let pid = h.m.entry(&gw).unwrap().snapshot().pid;
    h.host.calls();
    h.host.exit(pid, 1, false);
    let e = h.m.entry(&gw).unwrap();
    for _ in 0..200 {
        if h.m.entry(&gw).unwrap().snapshot().boot_incarnation.as_ref() != Some(&first)
            && e.snapshot().state == state::RUNNING
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let calls = h.host.calls();
    let close = calls
        .iter()
        .position(|c| c.contains(&format!("gateway_gate {GW_IP} closed")));
    let tap = calls
        .iter()
        .position(|c| c.starts_with(&format!("ensure_tap {} ", netw::tap_name(&gw))));
    assert!(close.is_some() && close < tap, "{calls:?}");
    assert!(h.gate_closed(), "{calls:?}");
}

#[tokio::test]
async fn a_legacy_gateway_and_its_machines_are_untouched() {
    let h = harness("10.64.0.0/22", 4096).await;
    let gw = h.with_gateway().await;
    let m = h.m.create_made(h.consumer("sbx")).await.unwrap();
    assert_eq!(m.state, state::RUNNING);
    let calls = h.host.calls();
    assert!(
        !calls
            .iter()
            .any(|c| c.contains("gateway_gate") || c.contains("policy-status")),
        "{calls:?}"
    );
    assert_eq!(h.stored(&gw).unwrap().gateway_policy, None);
    assert!(h
        .m
        .entry(&m.id)
        .unwrap()
        .snapshot()
        .egress
        .gateway_policy
        .is_none());
}

#[tokio::test]
async fn the_daemon_renders_every_bound_gateway_closed_at_start() {
    let h = harness("10.64.0.0/22", 4096).await;
    let b = binding("ab");
    h.with_bound_gateway(&b).await;
    let rules = h.m.rules().unwrap().render();
    assert!(rules.contains("set gateway_gate"), "{rules}");
    let gate = rules.split("set gateway_gate").nth(1).unwrap();
    assert!(gate.split('}').next().unwrap().contains(GW_IP), "{rules}");
}

fn derived(h: &Harness, id: &str, state: &str, egress: api::Egress) -> Arc<Entry> {
    let e = h.add(id, state, 256);
    {
        let mut r = e.rec.lock().unwrap();
        r.from_source = true;
        r.egress = egress;
    }
    e
}

async fn refused(h: &Harness, request: api::CreateMachineRequest) -> MError {
    match h.m.record(request, None).await {
        Err(err) => err,
        Ok(_) => panic!("the request was admitted"),
    }
}

fn via_alias() -> api::Egress {
    api::Egress {
        mode: api::egress::VIA.into(),
        via: Some(api::egress::GATEWAY.into()),
        ..Default::default()
    }
}

#[tokio::test]
async fn an_ordinary_bound_create_takes_the_cold_path() {
    let h = harness("10.64.0.0/22", 4096).await;
    let b = binding("ab");
    h.with_bound_gateway(&b).await;
    let (e, how) = h.m.record(h.bound_consumer("sbx", &b), None).await.unwrap();
    assert!(matches!(how, Make::Image));
    assert!(e.snapshot().is_cold_born());
}

#[tokio::test]
async fn derived_requests_are_refused_before_any_claim_or_mutation() {
    let h = harness("10.64.0.0/22", 4096).await;
    let b = binding("ab");
    let gw = h.with_bound_gateway(&b).await;
    let source = h.m.create_made(h.request("src")).await.unwrap();
    let held = h.m.inner.machines.lock().unwrap().len();
    h.host.calls();
    let fork = || api::ForkSpec {
        consistency: None,
        machine_id: source.id.clone(),
        copy: String::new(),
        snapshot: None,
    };
    let mut cases: Vec<(&str, api::CreateMachineRequest)> = Vec::new();
    for (label, bound) in [("bound", true), ("alias", false)] {
        let base = || match bound {
            true => h.bound_consumer("x", &b),
            false => h.consumer("x"),
        };
        let mut r = base();
        r.fork = Some(fork());
        cases.push((label, r));
        let mut r = base();
        r.restore = Some(api::RestoreSpec {
            machine_id: source.id.clone(),
            backup: "latest".into(),
        });
        cases.push((label, r));
        let mut r = base();
        r.sandbox_seed = Some(api::SandboxSeed {
            machine_id: source.id.clone(),
            snapshot: "s_a".into(),
            generation: "g_a".into(),
            request_id: "r_a".into(),
        });
        cases.push((label, r));
        let mut r = base();
        r.template_build = Some("tb".into());
        cases.push((label, r));
    }
    let mut literal = h.consumer("x");
    literal.egress.as_mut().unwrap().via = Some(gw.clone());
    literal.fork = Some(fork());
    cases.push(("literal", literal));
    for (label, request) in cases {
        let err = refused(&h, request).await;
        assert!(
            matches!(err, MError::Invalid(_) | MError::Conflict(_)),
            "{label}: {err}"
        );
        assert!(err.to_string().contains("gateway"), "{label}: {err}");
        assert_eq!(h.m.inner.machines.lock().unwrap().len(), held, "{label}");
        assert!(h.m.assignment_targets().is_empty(), "{label}");
        assert!(h.host.calls().is_empty(), "{label}");
    }
}

#[tokio::test]
async fn a_bound_source_is_never_forked_whatever_the_request_overrides() {
    let h = harness("10.64.0.0/22", 4096).await;
    let b = binding("ab");
    h.with_bound_gateway(&b).await;
    let mut request = h.bound_consumer("sbx", &b);
    request.start = Some(false);
    let source = h.m.create_made(request).await.unwrap();
    h.host.calls();
    let mut fork = h.request("child");
    fork.egress = Some(api::Egress::default());
    fork.image = String::new();
    fork.fork = Some(api::ForkSpec {
        consistency: None,
        machine_id: source.id,
        copy: String::new(),
        snapshot: None,
    });
    let err = refused(&h, fork).await;
    assert!(
        matches!(&err, MError::Invalid(m) if m.contains("created fresh")),
        "{err}"
    );
    assert!(h.host.calls().is_empty());
}

#[tokio::test]
async fn a_policy_gateway_is_refused_while_a_derived_machine_routes_through_it() {
    for held in [state::STOPPED, state::ERROR, state::DESTROYING] {
        let h = harness("10.64.0.0/22", 4096).await;
        h.ready().await;
        h.namespace("t1");
        let e = derived(&h, "m_derived", held, via_alias());
        assert!(matches!(
            h.m.set_gateway("t1", bound_spec(&binding("ab"))).await,
            Err(MError::Conflict(_))
        ));
        assert!(h.m.gateway_of("t1").is_none());
        e.rec.lock().unwrap().from_source = false;
        h.helper(answer(&binding("ab")));
        h.m.set_gateway("t1", bound_spec(&binding("ab")))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn patch_and_move_refuse_unsupported_shapes_before_any_effect() {
    let h = harness("10.64.0.0/22", 4096).await;
    let b = binding("ab");
    h.with_bound_gateway(&b).await;
    let mut request = h.bound_consumer("sbx", &b);
    request.start = Some(false);
    let bound = h.m.create_made(request).await.unwrap();
    let e = derived(&h, "m_derived", state::STOPPED, api::Egress::default());
    h.host.calls();
    assert!(matches!(
        h.m.move_machine(&bound.id, "t2", None).await,
        Err(MError::Conflict(_))
    ));
    let update = api::UpdateMachineRequest {
        egress: Some(via_alias()),
        ..Default::default()
    };
    assert!(matches!(
        h.m.update("m_derived", update, None).await,
        Err(MError::Conflict(_))
    ));
    assert_eq!(e.snapshot().egress, api::Egress::default());
    assert!(h.host.calls().is_empty());
}

#[tokio::test]
async fn unsupported_stored_records_are_withheld_and_never_pinned() {
    let h = harness("10.64.0.0/22", 4096).await;
    let b = binding("ab");
    h.with_bound_gateway(&b).await;
    let e = derived(&h, "m_derived", state::RUNNING, via_alias());
    e.rec.lock().unwrap().ip = "10.64.1.9".into();
    let ok = h.m.create_made(h.bound_consumer("sbx", &b)).await.unwrap();
    assert_eq!(
        h.m.unsupported_policy_records(),
        vec!["m_derived".to_string()]
    );
    let ruleset = h.m.rules().unwrap();
    let ip = e.snapshot().ip;
    assert!(ruleset.render().contains("set gateway_gate"));
    assert!(!ruleset.pins.iter().any(|(_, pinned)| *pinned == ip));
    assert!(!ruleset.members.iter().any(|(_, member)| *member == ip));
    let kept = h.m.entry(&ok.id).unwrap().snapshot().ip;
    assert!(ruleset.pins.iter().any(|(_, pinned)| *pinned == kept));
    h.m.save(&e).unwrap();
    h.host.calls();
    h.m.load_backing_at_start().await.unwrap();
    assert!(h.m.recovery_fault().is_some());
    assert_eq!(
        h.m.entry("m_derived").unwrap().snapshot().state,
        state::RUNNING
    );
    assert!(h
        .host
        .calls()
        .iter()
        .all(|c| !c.starts_with("kill ") && !c.starts_with("recover-stopped ")));
}
