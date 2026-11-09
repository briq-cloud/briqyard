use super::*;
use briqyard_api::execution::admission::Role;
use briqyard_api::execution::{
    KeyRole, PublicResource, PublicSeed, ResourceSet, Target, VerificationKey, ALLOCATION_TYPE,
    GRANT_TYPE,
};
use ring::signature::KeyPair;
use std::time::Duration;

fn projection() -> briqyard_api::execution::admission::Projection {
    briqyard_api::execution::admission::Projection::new(b"opaque snapshot".to_vec()).unwrap()
}

fn target(machine: &str) -> Target {
    Target {
        host: "host".into(),
        machine: machine.into(),
        namespace: "team".into(),
        run: format!("run-{machine}"),
        placement: "version-1".into(),
    }
}

#[tokio::test]
async fn typed_pinned_installation_persists_each_exact_ack() {
    use axum::{extract::State, http::Uri, response::IntoResponse, Router};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use sha2::{Digest, Sha256};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct Server {
        handle: axum_server::Handle,
        task: tokio::task::JoinHandle<std::io::Result<()>>,
    }
    impl Drop for Server {
        fn drop(&mut self) {
            self.handle.shutdown();
            self.task.abort();
        }
    }

    async fn endpoint(
        State(calls): State<Arc<AtomicUsize>>,
        uri: Uri,
        body: axum::body::Bytes,
    ) -> axum::response::Response {
        let path = uri.path();
        if path.ends_with("/instance") {
            return axum::Json(Instance {
                host_instance: "host-instance".into(),
            })
            .into_response();
        }
        if path.ends_with("/prepare") {
            calls.fetch_add(1, Ordering::SeqCst);
            let req: briqyard_api::execution::channel::Prepare =
                serde_json::from_slice(&body).unwrap();
            if req.admission == "uncertain-prepare" {
                return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            return axum::Json(briqyard_api::execution::admission::PreparedAdmission {
                admission: req.admission.clone(),
                delegation: req.bundle.delegation,
                grant_digest: token_digest(&req.bundle.grant),
                permit_digest: token_digest(&req.bundle.permit),
                request_digest: if req.admission == "ack-mismatch" {
                    "wrong".into()
                } else {
                    req.request_digest
                },
                allocation_refs: {
                    let parts: Vec<_> = req.bundle.permit.split('.').collect();
                    let body = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
                    serde_json::from_slice::<briqyard_api::execution::Permit>(&body)
                        .unwrap()
                        .allocations
                },
                ownership: req.bundle.installation,
                ownership_generation: req.bundle.generation,
                host_instance: "host-instance".into(),
                expires_at: 1050,
                dispatched: false,
            })
            .into_response();
        }
        if path.ends_with("/dispatch") {
            calls.fetch_add(1, Ordering::SeqCst);
            let req: briqyard_api::execution::channel::Dispatch =
                serde_json::from_slice(&body).unwrap();
            let parts: Vec<_> = req.bundle.permit.split('.').collect();
            let permit: briqyard_api::execution::Permit =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
            assert_eq!(permit.limits.max_output_bytes, 4096);
            assert!(!req.request.wake);
            if req.admission == "uncertain-dispatch" {
                return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            return axum::Json(briqyard_api::ExecResult {
                stdout: if req.admission == "oversize-output" {
                    "é".repeat(1500)
                } else {
                    "ok".into()
                },
                stderr: if req.admission == "oversize-output" {
                    "y".repeat(1097)
                } else {
                    String::new()
                },
                exit_code: 0,
                timed_out: false,
            })
            .into_response();
        }
        if path.ends_with("/status") {
            return axum::Json(briqyard_api::execution::channel::AdmissionStatus {
                prepared: false,
                dispatched: false,
                journal: None,
            })
            .into_response();
        }
        if path.ends_with("/discover") {
            return axum::Json(DiscoveryReceipt {
                host_instance: "host-instance".into(),
                primary: target("a"),
                public_seeds: vec![target("a")],
                public_resources: vec![PublicResource {
                    id: "public-a".into(),
                    target: target("a"),
                }],
                resource_set: ResourceSet {
                    revision: "revision-1".into(),
                    resources: vec![target("a"), target("gateway")],
                },
            })
            .into_response();
        }
        if path.ends_with("/protect") {
            let req: Protect = serde_json::from_slice(&body).unwrap();
            return axum::Json(ProtectionAck {
                admission: req.admission,
                expires_at_ms: req.expires_at_ms,
                resources: vec![target("a"), target("gateway")],
                revision: "revision-1".into(),
            })
            .into_response();
        }
        if path.ends_with("/delegation") {
            calls.fetch_add(1, Ordering::SeqCst);
            let req: InstallDelegation = serde_json::from_slice(&body).unwrap();
            return axum::Json(HostDelegation {
                id: req.id,
                version: req.version,
                ownership: req.installation,
                ownership_generation: req.generation,
                grant_digest: token_digest(&req.grant),
                allocation_digests: req.allocations.iter().map(|a| token_digest(a)).collect(),
                principal: req.principal,
                expires_at: if req.version == 2 { 1049 } else { 1050 },
            })
            .into_response();
        }
        let (generation, bytes) = if path.ends_with("/register") {
            let record: HostRegistration = serde_json::from_slice(&body).unwrap();
            (record.generation, serde_json::to_vec(&record).unwrap())
        } else {
            let record: HostOwnership = serde_json::from_slice(&body).unwrap();
            (record.generation, serde_json::to_vec(&record).unwrap())
        };
        axum::Json(InstallationAck {
            host_instance: "host-instance".into(),
            generation,
            digest: URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)),
        })
        .into_response()
    }
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let config = briqyard_api::tls::server_config(
        cert.cert.pem().as_bytes(),
        cert.key_pair.serialize_pem().as_bytes(),
    )
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let host = crate::registry::HostRec {
        id: "host".into(),
        url: format!("https://{}", listener.local_addr().unwrap()),
        token: "admin".into(),
        tls_fingerprint: briqyard_api::tls::fingerprint(cert.cert.der()),
        ..Default::default()
    };
    let handle = axum_server::Handle::new();
    let running = handle.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let server_calls = calls.clone();
    let task = tokio::spawn(async move {
        axum_server::from_tcp_rustls(
            listener,
            axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config)),
        )
        .handle(running)
        .serve(
            Router::new()
                .fallback(endpoint)
                .with_state(server_calls)
                .into_make_service(),
        )
        .await
    });
    let _server = Server { handle, task };
    let transport =
        HostTransport::new(&host, "installer", "execution", Duration::from_secs(5)).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let journal =
        Journal::open(&dir.path().join("issuer"), Role::Authority("region".into())).unwrap();
    let authority = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[2; 32]).unwrap();
    let mut issuer =
        briqyard_api::execution::DurableIssuer::new(journal, authority, "authority-test".into())
            .unwrap();
    let clock = Clock {
        now: 1010,
        uncertainty: 1,
    };
    let registration = HostRegistration {
        authority: "region".into(),
        epoch: issuer.instance().into(),
        key_id: "key".into(),
        public_key: ring::signature::Ed25519KeyPair::from_seed_unchecked(&[2; 32])
            .unwrap()
            .public_key()
            .as_ref()
            .try_into()
            .unwrap(),
        host_instance: "host-instance".into(),
        generation: 1,
    };
    let mut installer = Installer {
        journal: issuer.installation_journal(),
        host: &transport,
        host_id: &host.id,
    };
    assert_eq!(
        installer
            .register("registration", registration, clock)
            .await
            .unwrap(),
        Outcome::Ready
    );
    let control = OwnershipControl {
        host_instance: "host-instance".into(),
        installation: "install".into(),
        generation: 1,
        team: "team".into(),
        primary_id: "public-a".into(),
        seeds: vec![PublicSeed {
            id: "public-a".into(),
            machine: "a".into(),
            namespace: "team".into(),
            team: "team".into(),
            expected_version: Some(1),
        }],
        metadata_revision: "metadata-1".into(),
    };
    assert_eq!(
        installer
            .discover("discovery", "registration", control, clock)
            .await
            .unwrap(),
        Outcome::Ready
    );
    assert_eq!(
        installer
            .ownership("ownership", "discovery", clock)
            .await
            .unwrap(),
        Outcome::Ready
    );
    assert_eq!(
        installer
            .protect(
                "protection",
                "ownership",
                CommittedIdle {
                    admission: "admission".into(),
                    expires_at_ms: 1_060_001
                },
                clock
            )
            .await
            .unwrap(),
        Outcome::Ready
    );
    assert!(installer
        .journal
        .protection_intent_ready("protection")
        .unwrap());
    let central = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[1; 32]).unwrap();
    let keys = [
        VerificationKey {
            kid: "central-test".into(),
            role: KeyRole::Central,
            issuer: "central".into(),
            authority: None,
            public_key: central.public_key().as_ref().try_into().unwrap(),
        },
        VerificationKey {
            kid: "authority-test".into(),
            role: KeyRole::Authority,
            issuer: "authority".into(),
            authority: Some("region".into()),
            public_key: ring::signature::Ed25519KeyPair::from_seed_unchecked(&[2; 32])
                .unwrap()
                .public_key()
                .as_ref()
                .try_into()
                .unwrap(),
        },
    ];
    let trust = Trust {
        keys: &keys,
        central_issuer: "central",
        authority_issuer: "authority",
        audience: "runtime",
    };
    let sign = |kind: &str, body: serde_json::Value| {
        let header = serde_json::json!({"alg":"EdDSA","typ":kind,"kid":"central-test","v":1});
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(body.to_string())
        );
        format!(
            "{}.{}",
            input,
            URL_SAFE_NO_PAD.encode(central.sign(input.as_bytes()).as_ref())
        )
    };
    let grant_body = serde_json::json!({
        "v":1,"iss":"central","aud":"runtime","iat":1000,"nbf":1000,"exp":1050,
        "id":"delegation","principal":"key:credential","source":{"kind":"api_key","id":"credential","expires_at":1100},
        "team":"team","subject":"public-a","target":target("a"),
        "resource_set":{"revision":"revision-1","resources":[target("a"),target("gateway")]},
        "idle":{"admission":"admission","expires_at":1060},"metadata_revision":"metadata-1",
        "operations":["exec"],"limits":{"max_duration_seconds":20,"max_input_bytes":1024,"max_output_bytes":4096}
    });
    let grant = sign(GRANT_TYPE, grant_body.clone());
    let allocation = sign(
        ALLOCATION_TYPE,
        serde_json::json!({
            "v":1,"iss":"central","aud":"runtime","iat":1000,"nbf":1000,"exp":1050,
            "id":"allocation","epoch":"allocation-epoch","authority":"region","authority_epoch":installer.journal.instance(),
            "principal":"key:credential","bucket":"requests","window_start":990,"window_end":1060,"units":10
        }),
    );
    let calls_allocation = sign(
        ALLOCATION_TYPE,
        serde_json::json!({
            "v":1,"iss":"central","aud":"runtime","iat":1000,"nbf":1000,"exp":1050,
            "id":"calls","epoch":"allocation-epoch","authority":"region","authority_epoch":installer.journal.instance(),
            "principal":"key:credential","bucket":"exec_calls","window_start":990,"window_end":1060,"units":10
        }),
    );
    let control = || DelegationControl {
        id: "delegation".into(),
        version: 1,
        principal: "key:credential".into(),
        ownership: "ownership".into(),
        protection: "protection".into(),
        projection: projection(),
        source: briqyard_api::execution::Source {
            kind: "api_key".into(),
            id: "credential".into(),
            expires_at: 1100,
        },
    };
    assert!(installer
        .delegation(
            "forged",
            "registration",
            control(),
            SignedDelegation {
                grant: format!("{grant}x"),
                allocations: vec![allocation.clone()]
            },
            &trust,
            clock
        )
        .await
        .is_err());
    assert!(installer
        .journal
        .delegation_intent("forged")
        .unwrap()
        .is_none());
    assert!(installer
        .delegation(
            "wrong-dependency",
            "registration",
            DelegationControl {
                protection: "missing".into(),
                ..control()
            },
            SignedDelegation {
                grant: grant.clone(),
                allocations: vec![allocation.clone()]
            },
            &trust,
            clock
        )
        .await
        .is_err());
    assert!(installer
        .journal
        .delegation_intent("wrong-dependency")
        .unwrap()
        .is_none());
    let mut wrong_source = control();
    wrong_source.source.id = "other".into();
    assert!(installer
        .delegation(
            "wrong-source",
            "registration",
            wrong_source,
            SignedDelegation {
                grant: grant.clone(),
                allocations: vec![allocation.clone(), calls_allocation.clone()],
            },
            &trust,
            clock,
        )
        .await
        .is_err());
    assert!(installer
        .journal
        .delegation_intent("wrong-source")
        .unwrap()
        .is_none());
    assert_eq!(
        installer
            .delegation(
                "signed",
                "registration",
                control(),
                SignedDelegation {
                    grant: grant.clone(),
                    allocations: vec![allocation.clone(), calls_allocation.clone()]
                },
                &trust,
                clock
            )
            .await
            .unwrap(),
        Outcome::Ready
    );
    assert!(installer.journal.delegation_intent_ready("signed").unwrap());
    let evidence = installer
        .journal
        .presented_projection("signed", &grant, clock)
        .unwrap();
    assert_eq!(evidence.projection, projection());
    assert!(installer
        .journal
        .presented_projection("signed", "another grant", clock)
        .is_err());
    assert!(installer
        .journal
        .presented_projection(
            "signed",
            &grant,
            Clock {
                now: 1050,
                uncertainty: 0
            }
        )
        .is_err());
    let mut changed_projection = control();
    changed_projection.projection =
        briqyard_api::execution::admission::Projection::new(b"changed".to_vec()).unwrap();
    assert!(installer
        .delegation(
            "signed",
            "registration",
            changed_projection,
            SignedDelegation {
                grant: grant.clone(),
                allocations: vec![allocation.clone(), calls_allocation.clone()]
            },
            &trust,
            clock
        )
        .await
        .is_err());

    assert_eq!(
        installer
            .delegation(
                "signed",
                "registration",
                control(),
                SignedDelegation {
                    grant: grant.clone(),
                    allocations: vec![allocation.clone(), calls_allocation.clone()]
                },
                &trust,
                clock
            )
            .await
            .unwrap(),
        Outcome::Ready
    );
    let mut wrong = installer
        .journal
        .delegation_intent("signed")
        .unwrap()
        .unwrap()
        .expected
        .clone();
    wrong.allocation_digests[0].push('x');
    assert!(installer
        .journal
        .acknowledge_delegation_intent("signed", wrong, clock)
        .is_err());
    let mut pending_body = grant_body.clone();
    pending_body["id"] = "pending-delegation".into();
    let pending_grant = sign(GRANT_TYPE, pending_body);
    let pending_control = || DelegationControl {
        id: "pending-delegation".into(),
        version: 2,
        principal: "key:credential".into(),
        ownership: "ownership".into(),
        protection: "protection".into(),
        projection: projection(),
        source: briqyard_api::execution::Source {
            kind: "api_key".into(),
            id: "credential".into(),
            expires_at: 1100,
        },
    };
    assert!(installer
        .delegation(
            "pending",
            "registration",
            pending_control(),
            SignedDelegation {
                grant: pending_grant.clone(),
                allocations: vec![allocation.clone()]
            },
            &trust,
            clock
        )
        .await
        .is_err());
    assert!(!installer
        .journal
        .delegation_intent_ready("pending")
        .unwrap());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        installer
            .delegation(
                "pending",
                "registration",
                pending_control(),
                SignedDelegation {
                    grant: pending_grant,
                    allocations: vec![allocation.clone()]
                },
                &trust,
                clock
            )
            .await
            .unwrap(),
        Outcome::Pending
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let mut coordinator = crate::execution_operation::Coordinator {
        issuer: &mut issuer,
        host: &transport,
        host_id: &host.id,
    };
    let request = || briqyard_api::ExecRequest {
        cmd: vec!["printf".into(), "ok".into()],
        timeout_ms: 1000,
        wake: false,
        ..Default::default()
    };
    let operation = |id: &str| crate::execution_operation::Control {
        id: id.into(),
        delegation_intent: "signed".into(),
        grant: grant.clone(),
        projection_digest: projection().digest().into(),
        request: request(),
    };
    for mismatch in ["grant", "projection"] {
        let mut bad = operation(mismatch);
        if mismatch == "grant" {
            bad.grant.push('x');
        } else {
            bad.projection_digest.push('x');
        }
        assert!(matches!(
            coordinator.exec(bad, &trust, || Ok(clock)).await,
            Err(crate::execution_operation::Error::Binding)
        ));
        assert!(coordinator.status(mismatch).unwrap().is_none());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let first = coordinator
        .exec(operation("first"), &trust, || Ok(clock))
        .await
        .unwrap();
    assert!(
        matches!(first, crate::execution_operation::ExecOutcome::Completed {
            status: crate::execution_operation::Status {
                phase: briqyard_api::execution::admission::OperationPhase::Finished,
                ..
            },
            result: briqyard_api::ExecResult { ref stdout, .. }
        } if stdout == "ok")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    assert!(matches!(
        coordinator
            .exec(operation("first"), &trust, || Ok(clock))
            .await
            .unwrap(),
        crate::execution_operation::ExecOutcome::Existing(_)
    ));
    let mut changed = operation("first");
    changed.request.cmd.push("changed".into());
    assert!(matches!(
        coordinator.exec(changed, &trust, || Ok(clock)).await,
        Err(crate::execution_operation::Error::Conflict)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    assert!(matches!(
        coordinator
            .exec(operation("uncertain-prepare"), &trust, || Ok(clock))
            .await,
        Err(crate::execution_operation::Error::Unconfirmed)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 5);
    assert!(matches!(
        coordinator
            .exec(operation("uncertain-prepare"), &trust, || Ok(clock))
            .await
            .unwrap(),
        crate::execution_operation::ExecOutcome::Existing(_)
    ));
    let absent = coordinator
        .observe("uncertain-prepare", clock)
        .await
        .unwrap();
    assert_eq!(
        absent.phase,
        briqyard_api::execution::admission::OperationPhase::Reserved
    );
    assert!(absent.unconfirmed);
    assert_eq!(calls.load(Ordering::SeqCst), 5);
    assert!(matches!(
        coordinator
            .exec(operation("uncertain-dispatch"), &trust, || Ok(clock))
            .await,
        Err(crate::execution_operation::Error::Unconfirmed)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 7);
    assert!(matches!(
        coordinator
            .exec(operation("uncertain-dispatch"), &trust, || Ok(clock))
            .await
            .unwrap(),
        crate::execution_operation::ExecOutcome::Existing(_)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 7);
    assert!(matches!(
        coordinator
            .exec(operation("ack-mismatch"), &trust, || Ok(clock))
            .await,
        Err(crate::execution_operation::Error::Unconfirmed)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 8);
    assert!(matches!(
        coordinator
            .exec(operation("ack-mismatch"), &trust, || Ok(clock))
            .await
            .unwrap(),
        crate::execution_operation::ExecOutcome::Existing(_)
    ));
    assert!(matches!(
        coordinator
            .exec(operation("oversize-output"), &trust, || Ok(clock))
            .await,
        Err(crate::execution_operation::Error::Unconfirmed)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 10);
    assert!(matches!(
        coordinator
            .exec(operation("oversize-output"), &trust, || Ok(clock))
            .await
            .unwrap(),
        crate::execution_operation::ExecOutcome::Existing(_)
    ));
    let mut oversized = operation("oversized");
    oversized.request.cmd = vec!["\u{0000}".repeat(1_500_000)];
    assert!(matches!(
        coordinator.exec(oversized, &trust, || Ok(clock)).await,
        Err(crate::execution_operation::Error::Binding)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 10);
    assert_eq!(coordinator.issuer.status("oversized").unwrap(), None);
    assert_eq!(
        coordinator.status("oversized").unwrap().unwrap().phase,
        briqyard_api::execution::admission::OperationPhase::Intent
    );
    let mut installer = Installer {
        journal: issuer.installation_journal(),
        host: &transport,
        host_id: &host.id,
    };
    installer
        .protect(
            "renewed-protection",
            "ownership",
            CommittedIdle {
                admission: "renewed-admission".into(),
                expires_at_ms: 1060000,
            },
            clock,
        )
        .await
        .unwrap();
    let mut renewed_body = grant_body;
    renewed_body["idle"]["admission"] = "renewed-admission".into();
    let renewed_grant = sign(GRANT_TYPE, renewed_body);
    let mut renewal = control();
    renewal.version = 2;
    renewal.protection = "renewed-protection".into();
    renewal.projection =
        briqyard_api::execution::admission::Projection::new(b"renewed snapshot".to_vec()).unwrap();
    // The host deliberately returns a wrong expiration for version 2. The durable
    // replacement still fences the old version before acknowledgement.
    assert!(installer
        .delegation(
            "renewed",
            "registration",
            renewal,
            SignedDelegation {
                grant: renewed_grant.clone(),
                allocations: vec![allocation.clone(), calls_allocation.clone()]
            },
            &trust,
            clock
        )
        .await
        .is_err());
    assert!(!installer.journal.delegation_intent_ready("signed").unwrap());
    assert!(!installer
        .journal
        .delegation_intent_ready("renewed")
        .unwrap());
    assert!(installer
        .journal
        .presented_projection("signed", &grant, clock)
        .is_err());
    let expected = installer
        .journal
        .delegation_intent("renewed")
        .unwrap()
        .unwrap()
        .expected
        .clone();
    installer
        .journal
        .acknowledge_delegation_intent("renewed", expected, clock)
        .unwrap();
    assert!(installer
        .journal
        .delegation_intent_ready("renewed")
        .unwrap());
    assert!(!installer.journal.delegation_intent_ready("signed").unwrap());
    assert_eq!(
        installer
            .journal
            .presented_projection("renewed", &renewed_grant, clock)
            .unwrap()
            .version,
        2
    );
    assert_eq!(calls.load(Ordering::SeqCst), 11);
    installer
        .journal
        .begin_authority_intent(
            "revoke",
            "host",
            "host-instance",
            AuthorityPayload::Revoke {
                id: "delegation".into(),
                version: 1,
            },
            clock,
        )
        .unwrap();
    assert!(!installer.journal.delegation_intent_ready("signed").unwrap());
    let mut coordinator = crate::execution_operation::Coordinator {
        issuer: &mut issuer,
        host: &transport,
        host_id: &host.id,
    };
    assert!(matches!(
        coordinator
            .exec(operation("after-revoke"), &trust, || Ok(clock))
            .await,
        Err(crate::execution_operation::Error::Binding)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 11);
    let mut installer = Installer {
        journal: issuer.installation_journal(),
        host: &transport,
        host_id: &host.id,
    };
    assert!(installer
        .delegation(
            "renewal",
            "registration",
            DelegationControl {
                version: 2,
                ..control()
            },
            SignedDelegation {
                grant,
                allocations: vec![allocation]
            },
            &trust,
            clock
        )
        .await
        .is_err());
    installer
        .journal
        .begin_authority_intent(
            "invalidate",
            "host",
            "host-instance",
            AuthorityPayload::Invalidate {
                installation: "install".into(),
                generation: 2,
            },
            clock,
        )
        .unwrap();
    assert!(!installer
        .journal
        .delegation_intent_ready("pending")
        .unwrap());
    drop(issuer);
    let reopened =
        Journal::open(&dir.path().join("issuer"), Role::Authority("region".into())).unwrap();
    assert!(!reopened.delegation_intent_ready("signed").unwrap());
    assert!(!reopened.delegation_intent_ready("pending").unwrap());
    assert_eq!(
        reopened.operation_intent("first").unwrap().unwrap().phase,
        briqyard_api::execution::admission::OperationPhase::Finished
    );
}

#[tokio::test]
async fn unavailable_host_does_not_prevent_local_invalidation_or_revocation() {
    // Reserve our own TCP port without serving TLS. Each call has a one-second deadline.
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let host = crate::registry::HostRec {
        id: "host-1".into(),
        url: format!("https://{}", socket.local_addr().unwrap()),
        token: "admin".into(),
        tls_fingerprint: "ab".repeat(32),
        ..Default::default()
    };
    let transport =
        HostTransport::new(&host, "installer", "execution", Duration::from_secs(1)).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut journal =
        Journal::open(&dir.path().join("issuer"), Role::Authority("region".into())).unwrap();
    let clock = Clock {
        now: 100,
        uncertainty: 0,
    };
    let mut installer = Installer {
        journal: &mut journal,
        host: &transport,
        host_id: &host.id,
    };
    assert!(installer
        .invalidate(
            "invalidate",
            "host-instance",
            Invalidate {
                installation: "ownership".into(),
                generation: 1,
            },
            clock
        )
        .await
        .is_err());
    assert!(matches!(
        installer
            .journal
            .authority_intent("invalidate")
            .unwrap()
            .unwrap()
            .payload,
        AuthorityPayload::Invalidate { .. }
    ));
    assert!(!installer
        .journal
        .authority_intent_ready("invalidate")
        .unwrap());
    assert!(installer
        .revoke(
            "revoke",
            "host-instance",
            Revoke {
                id: "delegation".into(),
                version: 1,
            },
            clock
        )
        .await
        .is_err());
    assert!(matches!(
        installer
            .journal
            .authority_intent("revoke")
            .unwrap()
            .unwrap()
            .payload,
        AuthorityPayload::Revoke { .. }
    ));
    assert!(!installer.journal.authority_intent_ready("revoke").unwrap());
}
