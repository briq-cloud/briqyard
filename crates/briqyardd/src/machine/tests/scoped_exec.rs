//! Signed scoped exec through the real manager, with the existing mock guest transport.
use super::*;
use api::execution::{
    self as access,
    admission::{Journal, Role, Status},
    *,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::signature::{Ed25519KeyPair, KeyPair};

#[tokio::test]
async fn internal_execution_route_requires_its_installer_credential_on_loopback() {
    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
    };
    use tower::ServiceExt;
    let h = harness("10.64.0.0/22", 4096).await;
    let dir = tempfile::tempdir().unwrap();
    let journal = Journal::open(&dir.path().join("journal"), Role::Host("h_test".into())).unwrap();
    let key = VerificationKey {
        kid: "authority-key".into(),
        role: KeyRole::Authority,
        issuer: "authority".into(),
        authority: Some("authority-1".into()),
        public_key: [7; 32],
    };
    let channel = crate::api::execution::HostExecutionChannel::new(
        h.m,
        journal,
        "installer-secret".into(),
        "execution-secret".into(),
        vec![key],
        "central".into(),
        "authority".into(),
        "runtime".into(),
        1,
    )
    .unwrap();
    let app = crate::api::execution::router(std::sync::Arc::new(channel));
    for token in [None, Some("execution-secret"), Some("installer-secret")] {
        let mut builder = Request::builder().uri("/internal/execution/v1/instance");
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = app
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if token == Some("installer-secret") {
                StatusCode::OK
            } else {
                StatusCode::UNAUTHORIZED
            }
        );
    }

    // Parsing a supported logical input must fit even when JSON expands it 6x.
    // No credential is sent, so the command cannot reach guest dispatch.
    let dispatch = access::channel::Dispatch {
        bundle: access::channel::BundleRequest {
            installation: "installation".into(),
            generation: 1,
            delegation: "delegation".into(),
            grant: "untrusted".into(),
            allocations: vec![],
            permit: "untrusted".into(),
        },
        admission: "admission".into(),
        request: api::ExecRequest {
            cmd: vec!["true".into()],
            stdin: "\0".repeat(1024 * 1024),
            ..Default::default()
        },
    };
    let body = serde_json::to_vec(&dispatch).unwrap();
    assert!(body.len() > 6 * 1024 * 1024);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/execution/v1/dispatch")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

fn sign(body: &impl Serialize, typ: &str, seed: u8, kid: &str) -> String {
    let key = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
    let header = serde_json::json!({"alg":"EdDSA","typ":typ,"kid":kid,"v":1});
    let signed = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(body).unwrap())
    );
    format!(
        "{}.{}",
        signed,
        URL_SAFE_NO_PAD.encode(key.sign(signed.as_bytes()).as_ref())
    )
}
#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires Linux kernel process identity"
)]
async fn scoped_command_consumes_once_and_old_journal_snapshots_cannot_replay() {
    let h = harness("10.64.0.0/22", 4096).await;
    let gateway = h.with_gateway().await;
    let mut gateway_spec = gateway_spec(3128);
    gateway_spec.start = true;
    h.m.set_gateway("t1", gateway_spec).await.unwrap();
    let peer = h.m.create_made(h.request("native-peer")).await.unwrap();
    let machine = h.m.create_made(h.request("scoped")).await.unwrap();
    let entry = h.m.entry(&machine.id).unwrap();
    // The fake VMM has no kernel incarnation. Supply real positive kernel evidence
    // for this test process; the mocked guest transport still starts no host process.
    let incarnation = fc::Incarnation::read(std::process::id()).unwrap();
    for id in [&machine.id, &peer.id, &gateway] {
        let resource = h.m.entry(id).unwrap();
        let mut live = resource.live.lock().unwrap();
        let vm = live.as_mut().unwrap();
        vm.pid = incarnation.pid;
        vm.incarnation = Some(incarnation.clone());
        let mut record = resource.rec.lock().unwrap();
        record.pid = incarnation.pid;
        record.boot_incarnation = Some(incarnation.clone());
    }
    entry
        .rec
        .lock()
        .unwrap()
        .metadata
        .insert("briq_id".into(), "bq-test".into());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal");
    let journal =
        tokio::sync::Mutex::new(Journal::open(&path, Role::Host("h_test".into())).unwrap());
    let before_install = std::fs::read(path.join("journal.json")).unwrap();
    let target = h.m.execution_target(&machine.id, &journal).await.unwrap();
    let required = [target.clone()];
    let scope = ExecutionResourceScope {
        primary: &target,
        required: &required,
    };
    let complete = h.m.execution_resources(scope, &journal).await.unwrap();
    assert_eq!(complete.resources.len(), 3);
    assert!(complete
        .resources
        .iter()
        .any(|target| target.machine == gateway));
    assert!(complete
        .resources
        .iter()
        .any(|target| target.machine == peer.id));
    assert!(!h
        .m
        .entry(&gateway)
        .unwrap()
        .snapshot()
        .metadata
        .contains_key("briq_id"));
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../briqyard-api/tests/fixtures/execution-v1.json"
    ))
    .unwrap();
    let now = access::clock::ClockSample::read()
        .expect("scoped manager tests require a qualified Linux clock")
        .interval()
        .unwrap()
        .now;
    let mut grant: Grant = serde_json::from_value(fixture["grant"].clone()).unwrap();
    grant.target = target.clone();
    grant.subject = "bq-test".into();
    grant.resource_set = complete;
    grant.iat = now - 10;
    grant.nbf = now - 10;
    grant.exp = now + 30;
    grant.source.expires_at = now + 3600;
    grant.idle.expires_at = now + 30;
    let grant_token = sign(&grant, GRANT_TYPE, 1, "central-test");
    let request = api::ExecRequest {
        cmd: vec!["true".into()],
        timeout_ms: 1000,
        wake: false,
        ..Default::default()
    };
    let mut permit: Permit = serde_json::from_value(fixture["permit"].clone()).unwrap();
    permit.target = target.clone();
    permit.grant_digest = token_digest(&grant_token);
    permit.request_digest = access::exec_request_digest(&request, &permit.limits).unwrap();
    permit.iat = now - 10;
    permit.nbf = now - 10;
    permit.exp = now + 25;
    let mut tokens = Vec::new();
    permit.allocations.clear();
    for (id, bucket) in [("general", "requests"), ("calls", "exec_calls")] {
        let mut allocation: Allocation =
            serde_json::from_value(fixture["allocation"].clone()).unwrap();
        allocation.id = id.into();
        allocation.bucket = bucket.into();
        allocation.units = 1;
        allocation.iat = now - 10;
        allocation.nbf = now - 10;
        allocation.exp = now + 30;
        allocation.window_start = now - 60;
        allocation.window_end = now + 60;
        let token = sign(&allocation, ALLOCATION_TYPE, 1, "central-test");
        permit.allocations.push(AllocationRef {
            id: allocation.id,
            epoch: allocation.epoch,
            digest: token_digest(&token),
            units: 1,
        });
        tokens.push(token);
    }
    let permit_token = sign(&permit, PERMIT_TYPE, 2, "authority-test");
    let keys = [
        (1, "central-test", KeyRole::Central, "central", None),
        (
            2,
            "authority-test",
            KeyRole::Authority,
            "authority",
            Some("authority-1"),
        ),
    ]
    .into_iter()
    .map(|(seed, kid, role, issuer, authority)| VerificationKey {
        kid: kid.into(),
        role,
        issuer: issuer.into(),
        authority: authority.map(str::to_owned),
        public_key: Ed25519KeyPair::from_seed_unchecked(&[seed; 32])
            .unwrap()
            .public_key()
            .as_ref()
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
    let context = DispatchContext {
        principal: &grant.principal,
        team: &grant.team,
        subject: &grant.subject,
        target: &grant.target,
        resource_set: &grant.resource_set,
        metadata_revision: &grant.metadata_revision,
        authority: &permit.authority,
        authority_epoch: &permit.authority_epoch,
        installed_allocations: &permit.allocations,
        operation: Operation::Exec,
        request_digest: &permit.request_digest,
    };
    let tokens = tokens.iter().map(String::as_str).collect::<Vec<_>>();
    let bundle = verify_bundle(
        &grant_token,
        &permit_token,
        &tokens,
        &trust,
        Clock {
            now,
            uncertainty: 0,
        },
        &context,
    )
    .unwrap();
    {
        let mut ledger = journal.lock().await;
        let instance = ledger.instance().to_owned();
        ledger
            .fence(
                &permit.authority,
                &permit.authority_epoch,
                &instance,
                Clock {
                    now,
                    uncertainty: 0,
                },
            )
            .unwrap();
        ledger
            .install(
                &bundle,
                &instance,
                Clock {
                    now,
                    uncertainty: 0,
                },
            )
            .unwrap();
    }
    let expiry_ms = grant.idle.expires_at * 1000 + 123;
    let protection = || ExecutionProtectionRequest {
        admission: &grant.idle.admission,
        expires_at_ms: expiry_ms,
        scope,
        subject: &grant.subject,
        resources: &grant.resource_set.resources,
        resource_revision: &grant.resource_set.revision,
    };
    let version = entry.snapshot().version;
    let receipt =
        h.m.protect_execution_resources(protection(), &journal, 0)
            .await
            .unwrap();
    assert_eq!(receipt.expires_at_ms, expiry_ms);
    assert_eq!(receipt.targets, grant.resource_set.resources);
    assert_eq!(
        h.m.protect_execution_resources(protection(), &journal, 0)
            .await
            .unwrap(),
        receipt
    );
    assert_eq!(entry.snapshot().version, version);
    assert_eq!(entry.snapshot().last_used_at, machine.last_used_at);
    // Namespace protection and a freshly computed hash do not attest completeness.
    // Keep the independently installed seeds while proposing only the primary run.
    let mut subset_grant = grant.clone();
    subset_grant.resource_set.resources = vec![target.clone()];
    subset_grant.resource_set.revision =
        h.m.execution_resource_revision(&subset_grant.resource_set.resources)
            .unwrap();
    let protection_error =
        h.m.protect_execution_resources(
            ExecutionProtectionRequest {
                admission: &grant.idle.admission,
                expires_at_ms: expiry_ms,
                scope,
                subject: &grant.subject,
                resources: &subset_grant.resource_set.resources,
                resource_revision: &subset_grant.resource_set.revision,
            },
            &journal,
            0,
        )
        .await
        .unwrap_err();
    assert!(protection_error.to_string().contains("closure"));
    let subset_grant_token = sign(&subset_grant, GRANT_TYPE, 1, "central-test");
    let mut subset_permit = permit.clone();
    subset_permit.grant_digest = token_digest(&subset_grant_token);
    let subset_permit_token = sign(&subset_permit, PERMIT_TYPE, 2, "authority-test");
    let subset_context = DispatchContext {
        resource_set: &subset_grant.resource_set,
        ..context
    };
    // Prove cryptographic validity independently: refusal must be host closure validation.
    verify_bundle(
        &subset_grant_token,
        &subset_permit_token,
        &tokens,
        &trust,
        Clock {
            now,
            uncertainty: 0,
        },
        &subset_context,
    )
    .unwrap();
    let before_subset = std::fs::read(path.join("journal.json")).unwrap();
    let dispatch_error =
        h.m.scoped_exec(
            request.clone(),
            ScopedCredentials {
                grant: &subset_grant_token,
                permit: &subset_permit_token,
                allocations: &tokens,
            },
            &trust,
            ScopedExecutionContext {
                binding: &subset_context,
                scope,
            },
            &journal,
            0,
        )
        .await
        .unwrap_err();
    assert!(
        dispatch_error.to_string().contains("closure"),
        "{dispatch_error}"
    );
    assert_eq!(
        std::fs::read(path.join("journal.json")).unwrap(),
        before_subset
    );
    assert_eq!(
        journal.lock().await.status(&permit.admission).unwrap(),
        None
    );
    assert_eq!(
        h.host
            .calls()
            .iter()
            .filter(|call| call.starts_with("exec "))
            .count(),
        0
    );
    // A descriptor protects the namespace before its first command. Neither a
    // new peer nor even an apparently harmless policy rewrite may publish into it.
    assert!(h.m.create_made(h.request("late-peer")).await.is_err());
    assert!(h.m.replace_policy(&machine.id, None).await.is_err());
    assert_eq!(
        h.m.execution_resource_revision(&grant.resource_set.resources)
            .unwrap(),
        grant.resource_set.revision,
        "refused mutations must leave the installed generation intact"
    );
    entry.rec.lock().unwrap().last_used_at = Some(Utc::now() - chrono::Duration::hours(1));
    h.m.stop_entry(&entry, stop::IDLE, Duration::from_secs(1), false, None)
        .await
        .unwrap();
    assert_eq!(entry.snapshot().state, state::RUNNING);
    let before_consume = std::fs::read(path.join("journal.json")).unwrap();
    let call = || ScopedCredentials {
        grant: &grant_token,
        permit: &permit_token,
        allocations: &tokens,
    };
    let out =
        h.m.scoped_exec(
            request.clone(),
            call(),
            &trust,
            ScopedExecutionContext {
                binding: &context,
                scope,
            },
            &journal,
            0,
        )
        .await
        .unwrap();
    assert_eq!(out.exit_code, 0);
    assert_eq!(
        journal.lock().await.status(&permit.admission).unwrap(),
        Some(Status::Finished)
    );
    assert!(h
        .m
        .scoped_exec(
            request.clone(),
            call(),
            &trust,
            ScopedExecutionContext {
                binding: &context,
                scope
            },
            &journal,
            0
        )
        .await
        .is_err());
    assert_eq!(
        h.host
            .calls()
            .iter()
            .filter(|c| c.starts_with("exec "))
            .count(),
        1
    );
    drop(journal);
    for snapshot in [before_install, before_consume] {
        std::fs::write(path.join("journal.json"), snapshot).unwrap();
        let journal =
            tokio::sync::Mutex::new(Journal::open(&path, Role::Host("h_test".into())).unwrap());
        assert_eq!(
            journal.lock().await.status(&permit.admission).unwrap(),
            None
        );
        let restarted = h.m.execution_target(&machine.id, &journal).await.unwrap();
        assert_ne!(
            restarted.run, grant.target.run,
            "restored journal must not preserve dispatch identity"
        );
        assert!(h
            .m
            .scoped_exec(
                request.clone(),
                call(),
                &trust,
                ScopedExecutionContext {
                    binding: &context,
                    scope
                },
                &journal,
                0
            )
            .await
            .is_err());
        assert_eq!(
            h.host
                .calls()
                .iter()
                .filter(|c| c.starts_with("exec "))
                .count(),
            0
        );
    }
}
