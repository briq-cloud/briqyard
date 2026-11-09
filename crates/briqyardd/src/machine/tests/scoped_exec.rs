//! Signed scoped exec through the real manager, with the existing mock guest transport.
use super::*;
use api::execution::{
    self as access,
    admission::{Journal, Role, Status},
    *,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::signature::{Ed25519KeyPair, KeyPair};

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
async fn scoped_command_consumes_once_and_old_journal_snapshots_cannot_replay() {
    let h = harness("10.64.0.0/22", 4096).await;
    h.ready().await;
    let machine = h.m.create_made(h.request("scoped")).await.unwrap();
    let entry = h.m.entry(&machine.id).unwrap();
    // The fake VMM has no kernel incarnation. Supply real positive kernel evidence
    // for this test process; the mocked guest transport still starts no host process.
    let incarnation = fc::Incarnation::read(std::process::id()).unwrap();
    {
        let mut live = entry.live.lock().unwrap();
        let vm = live.as_mut().unwrap();
        vm.pid = incarnation.pid;
        vm.incarnation = Some(incarnation.clone());
        let mut record = entry.rec.lock().unwrap();
        record.boot_incarnation = Some(incarnation);
        record.metadata.insert("briq_id".into(), "bq-test".into());
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal");
    let journal =
        tokio::sync::Mutex::new(Journal::open(&path, Role::Host("h_test".into())).unwrap());
    let before_install = std::fs::read(path.join("journal.json")).unwrap();
    let target = h.m.execution_target(&machine.id, &journal).await.unwrap();
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../briqyard-api/tests/fixtures/execution-v1.json"
    ))
    .unwrap();
    let now = Utc::now().timestamp() as u64;
    let mut grant: Grant = serde_json::from_value(fixture["grant"].clone()).unwrap();
    grant.target = target.clone();
    grant.subject = "bq-test".into();
    grant.resource_set.resources = vec![target.clone()];
    grant.iat = now - 1;
    grant.nbf = now - 1;
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
    permit.target = target;
    permit.grant_digest = token_digest(&grant_token);
    permit.request_digest = access::exec_request_digest(&request, &permit.limits).unwrap();
    permit.iat = now;
    permit.nbf = now;
    permit.exp = now + 25;
    let mut tokens = Vec::new();
    permit.allocations.clear();
    for (id, bucket) in [("general", "requests"), ("calls", "exec_calls")] {
        let mut allocation: Allocation =
            serde_json::from_value(fixture["allocation"].clone()).unwrap();
        allocation.id = id.into();
        allocation.bucket = bucket.into();
        allocation.units = 1;
        allocation.iat = now - 1;
        allocation.nbf = now - 1;
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
        target: &grant.target,
        subject: &grant.subject,
        resources: &grant.resource_set.resources,
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
        h.m.scoped_exec(request.clone(), call(), &trust, &context, &journal, 0)
            .await
            .unwrap();
    assert_eq!(out.exit_code, 0);
    assert_eq!(
        journal.lock().await.status(&permit.admission).unwrap(),
        Some(Status::Finished)
    );
    assert!(h
        .m
        .scoped_exec(request.clone(), call(), &trust, &context, &journal, 0)
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
            .scoped_exec(request.clone(), call(), &trust, &context, &journal, 0)
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
