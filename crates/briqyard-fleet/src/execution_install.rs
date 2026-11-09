//! Dormant trusted installer. The caller must supply authenticated control input;
//! submitted grants and permits never construct these records.
use crate::execution_host::{Error as TransportError, HostTransport, Route};
use briqyard_api::execution::{
    admission::{
        AuthorityPayload, DelegationIntent, Error as JournalError, HostDelegation, HostOwnership,
        HostRegistration, Journal, OwnershipControl,
    },
    channel::{
        InstallDelegation, InstallationAck, Instance, Invalidate, Protect, ProtectionAck, Revoke,
    },
    token_digest, verify_delegation, Clock, DelegationContext, DiscoveryReceipt, Trust,
    MAX_BODY_BYTES,
};

#[derive(Clone, Debug)]
pub(super) struct CommittedIdle {
    pub admission: String,
    pub expires_at_ms: u64,
}

/// Authenticated control input, independent of the submitted signed credentials.
pub(super) struct DelegationControl {
    pub id: String,
    pub version: u64,
    pub principal: String,
    pub ownership: String,
    pub protection: String,
}

pub(super) struct SignedDelegation {
    pub grant: String,
    pub allocations: Vec<String>,
}

#[derive(Debug)]
pub(super) enum InstallError {
    Journal(JournalError),
    Transport(TransportError),
    HostMismatch,
    Binding,
}

impl From<JournalError> for InstallError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}
impl From<TransportError> for InstallError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    Ready,
    Pending,
}

/// Each operation sends at most once, after fsync of its immutable intent.
/// A pending ID is never resent by this path after a crash or lost ACK.
pub(super) struct Installer<'a> {
    pub journal: &'a mut Journal,
    pub host: &'a HostTransport,
    pub host_id: &'a str,
}

impl Installer<'_> {
    async fn instance(&self, expected: &str) -> Result<(), InstallError> {
        let actual: Instance = self.host.call(Route::Instance, &()).await?;
        if actual.host_instance != expected {
            return Err(InstallError::HostMismatch);
        }
        Ok(())
    }

    pub async fn register(
        &mut self,
        id: &str,
        record: HostRegistration,
        clock: Clock,
    ) -> Result<Outcome, InstallError> {
        self.instance(&record.host_instance).await?;
        if !self.journal.begin_authority_intent(
            id,
            self.host_id,
            &record.host_instance,
            AuthorityPayload::Registration(record.clone()),
            clock,
        )? {
            return self.outcome(id);
        }
        let ack: InstallationAck = self.host.call(Route::Register, &record).await?;
        self.journal.acknowledge_authority_intent(id, ack, clock)?;
        self.outcome(id)
    }

    pub async fn discover(
        &mut self,
        id: &str,
        registration: &str,
        control: OwnershipControl,
        clock: Clock,
    ) -> Result<Outcome, InstallError> {
        let request = control.discovery_request();
        if serde_json::to_vec(&request)
            .map_err(|_| InstallError::Binding)?
            .len()
            > MAX_BODY_BYTES
        {
            return Err(InstallError::Binding);
        }
        self.instance(&control.host_instance).await?;
        if !self
            .journal
            .begin_discovery_intent(id, self.host_id, registration, control, clock)?
        {
            return Ok(if self.journal.discovery_intent_ready(id)? {
                Outcome::Ready
            } else {
                Outcome::Pending
            });
        }
        let receipt: DiscoveryReceipt = self.host.call(Route::Discover, &request).await?;
        self.journal
            .acknowledge_discovery_intent(id, receipt, clock)?;
        Ok(if self.journal.discovery_intent_ready(id)? {
            Outcome::Ready
        } else {
            Outcome::Pending
        })
    }

    pub async fn ownership(
        &mut self,
        id: &str,
        discovery: &str,
        clock: Clock,
    ) -> Result<Outcome, InstallError> {
        if !self.journal.discovery_intent_ready(discovery)? {
            return Err(InstallError::Binding);
        }
        let found = self
            .journal
            .discovery_intent(discovery)?
            .ok_or(InstallError::Binding)?;
        if found.host != self.host_id {
            return Err(InstallError::Binding);
        }
        let receipt = found.receipt.as_ref().ok_or(InstallError::Binding)?;
        let record = HostOwnership {
            installation: found.control.installation.clone(),
            generation: found.control.generation,
            team: found.control.team.clone(),
            subject: found.control.primary_id.clone(),
            metadata_revision: found.control.metadata_revision.clone(),
            primary: receipt.primary.clone(),
            public_seeds: receipt.public_seeds.clone(),
            public_resources: receipt.public_resources.clone(),
            resource_set: receipt.resource_set.clone(),
            host_instance: found.control.host_instance.clone(),
        };
        if serde_json::to_vec(&record)
            .map_err(|_| InstallError::Binding)?
            .len()
            > MAX_BODY_BYTES
        {
            return Err(InstallError::Binding);
        }
        self.instance(&record.host_instance).await?;
        if !self.journal.begin_authority_intent(
            id,
            self.host_id,
            &record.host_instance,
            AuthorityPayload::Ownership(Box::new(record.clone())),
            clock,
        )? {
            return self.outcome(id);
        }
        let ack: InstallationAck = self.host.call(Route::Ownership, &record).await?;
        self.journal.acknowledge_authority_intent(id, ack, clock)?;
        self.outcome(id)
    }

    pub async fn protect(
        &mut self,
        id: &str,
        ownership: &str,
        committed: CommittedIdle,
        clock: Clock,
    ) -> Result<Outcome, InstallError> {
        if clock.uncertainty > 5
            || committed.expires_at_ms
                <= clock
                    .now
                    .saturating_sub(clock.uncertainty)
                    .saturating_mul(1000)
            || committed.expires_at_ms > clock.now.saturating_add(60).saturating_mul(1000)
        {
            return Err(InstallError::Binding);
        }
        let owner_intent = self
            .journal
            .authority_intent(ownership)?
            .ok_or(InstallError::Binding)?;
        let AuthorityPayload::Ownership(owner) = &owner_intent.payload else {
            return Err(InstallError::Binding);
        };
        let request = Protect {
            installation: owner.installation.clone(),
            generation: owner.generation,
            admission: committed.admission,
            expires_at_ms: committed.expires_at_ms,
        };
        if serde_json::to_vec(&request)
            .map_err(|_| InstallError::Binding)?
            .len()
            > MAX_BODY_BYTES
        {
            return Err(InstallError::Binding);
        }
        let host_instance = owner.host_instance.clone();
        if !self.journal.begin_protection_intent(
            id,
            self.host_id,
            ownership,
            request.clone(),
            clock,
        )? {
            return Ok(if self.journal.protection_intent_ready(id)? {
                Outcome::Ready
            } else {
                Outcome::Pending
            });
        }
        self.instance(&host_instance).await?;
        let ack: ProtectionAck = self.host.call(Route::Protect, &request).await?;
        self.journal.acknowledge_protection_intent(id, ack, clock)?;
        Ok(if self.journal.protection_intent_ready(id)? {
            Outcome::Ready
        } else {
            Outcome::Pending
        })
    }

    pub async fn delegation(
        &mut self,
        intent_id: &str,
        registration: &str,
        control: DelegationControl,
        signed: SignedDelegation,
        trust: &Trust<'_>,
        clock: Clock,
    ) -> Result<Outcome, InstallError> {
        let registration_intent = self
            .journal
            .authority_intent(registration)?
            .ok_or(InstallError::Binding)?;
        let AuthorityPayload::Registration(reg) = &registration_intent.payload else {
            return Err(InstallError::Binding);
        };
        let ownership_intent = self
            .journal
            .authority_intent(&control.ownership)?
            .ok_or(InstallError::Binding)?;
        let AuthorityPayload::Ownership(owner) = &ownership_intent.payload else {
            return Err(InstallError::Binding);
        };
        let protection_intent = self
            .journal
            .protection_intent(&control.protection)?
            .ok_or(InstallError::Binding)?;
        if registration_intent.host != self.host_id
            || ownership_intent.host != self.host_id
            || protection_intent.host != self.host_id
            || !self.journal.authority_intent_ready(registration)?
            || !self.journal.authority_intent_ready(&control.ownership)?
            || !self.journal.protection_intent_ready(&control.protection)?
            || self.journal.delegation_revoked(&control.id)?
            || reg.epoch != self.journal.instance()
            || owner.host_instance != reg.host_instance
            || protection_intent.ownership != control.ownership
            || protection_intent.request.installation != owner.installation
            || protection_intent.request.generation != owner.generation
        {
            return Err(InstallError::Binding);
        }
        let tokens = signed
            .allocations
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let checked = verify_delegation(
            &signed.grant,
            &tokens,
            trust,
            clock,
            &DelegationContext {
                principal: &control.principal,
                team: &owner.team,
                subject: &owner.subject,
                target: &owner.primary,
                resource_set: &owner.resource_set,
                metadata_revision: &owner.metadata_revision,
                authority: &reg.authority,
                authority_epoch: &reg.epoch,
            },
        )
        .map_err(|_| InstallError::Binding)?;
        let signed_idle = checked.grant().idle.expires_at;
        let receipt_ms = protection_intent.request.expires_at_ms;
        if checked.grant().id != control.id
            || checked.grant().idle.admission != protection_intent.request.admission
            || receipt_ms / 1000 != signed_idle
            || signed_idle < checked.grant().exp
        {
            return Err(InstallError::Binding);
        }
        let request = InstallDelegation {
            installation: owner.installation.clone(),
            generation: owner.generation,
            id: control.id,
            version: control.version,
            principal: control.principal,
            grant: signed.grant,
            allocations: signed.allocations,
            protection_expires_at_ms: receipt_ms,
        };
        if serde_json::to_vec(&request)
            .map_err(|_| InstallError::Binding)?
            .len()
            > MAX_BODY_BYTES
        {
            return Err(InstallError::Binding);
        }
        let expected = HostDelegation {
            id: request.id.clone(),
            version: request.version,
            ownership: request.installation.clone(),
            ownership_generation: request.generation,
            grant_digest: token_digest(&request.grant),
            allocation_digests: checked.allocation_digests().to_vec(),
            principal: request.principal.clone(),
            expires_at: checked.grant().exp,
        };
        let host_instance = reg.host_instance.clone();
        let intent = DelegationIntent {
            host: self.host_id.into(),
            authority_epoch: self.journal.instance().into(),
            registration: registration.into(),
            ownership: control.ownership,
            protection: control.protection,
            request: request.clone(),
            expected,
            acknowledgement: None,
        };
        if !self
            .journal
            .begin_delegation_intent(intent_id, intent, clock)?
        {
            return Ok(if self.journal.delegation_intent_ready(intent_id)? {
                Outcome::Ready
            } else {
                Outcome::Pending
            });
        }
        self.instance(&host_instance).await?;
        let ack: HostDelegation = self.host.call(Route::Delegation, &request).await?;
        self.journal
            .acknowledge_delegation_intent(intent_id, ack, clock)?;
        Ok(if self.journal.delegation_intent_ready(intent_id)? {
            Outcome::Ready
        } else {
            Outcome::Pending
        })
    }

    pub async fn invalidate(
        &mut self,
        id: &str,
        host_instance: &str,
        request: Invalidate,
        clock: Clock,
    ) -> Result<Outcome, InstallError> {
        if !self.journal.begin_authority_intent(
            id,
            self.host_id,
            host_instance,
            AuthorityPayload::Invalidate {
                installation: request.installation.clone(),
                generation: request.generation,
            },
            clock,
        )? {
            return self.outcome(id);
        }
        self.instance(host_instance).await?;
        let ack: Instance = self.host.call(Route::Invalidate, &request).await?;
        self.journal
            .confirm_authority_instance(id, &ack.host_instance, clock)?;
        self.outcome(id)
    }

    pub async fn revoke(
        &mut self,
        id: &str,
        host_instance: &str,
        request: Revoke,
        clock: Clock,
    ) -> Result<Outcome, InstallError> {
        if !self.journal.begin_authority_intent(
            id,
            self.host_id,
            host_instance,
            AuthorityPayload::Revoke {
                id: request.id.clone(),
                version: request.version,
            },
            clock,
        )? {
            return self.outcome(id);
        }
        self.instance(host_instance).await?;
        let ack: Instance = self.host.call(Route::Revoke, &request).await?;
        self.journal
            .confirm_authority_instance(id, &ack.host_instance, clock)?;
        self.outcome(id)
    }

    fn outcome(&self, id: &str) -> Result<Outcome, InstallError> {
        Ok(if self.journal.authority_intent_ready(id)? {
            Outcome::Ready
        } else {
            Outcome::Pending
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use briqyard_api::execution::admission::Role;
    use briqyard_api::execution::{
        KeyRole, PublicResource, PublicSeed, ResourceSet, Target, VerificationKey, ALLOCATION_TYPE,
        GRANT_TYPE,
    };
    use ring::signature::KeyPair;
    use std::time::Duration;

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
        let mut journal =
            Journal::open(&dir.path().join("issuer"), Role::Authority("region".into())).unwrap();
        let clock = Clock {
            now: 1010,
            uncertainty: 0,
        };
        let registration = HostRegistration {
            authority: "region".into(),
            epoch: journal.instance().into(),
            key_id: "key".into(),
            public_key: [1; 32],
            host_instance: "host-instance".into(),
            generation: 1,
        };
        let mut installer = Installer {
            journal: &mut journal,
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
        let keys = [VerificationKey {
            kid: "central-test".into(),
            role: KeyRole::Central,
            issuer: "central".into(),
            authority: None,
            public_key: central.public_key().as_ref().try_into().unwrap(),
        }];
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
                "principal":"key:credential","bucket":"exec","window_start":990,"window_end":1060,"units":10
            }),
        );
        let control = || DelegationControl {
            id: "delegation".into(),
            version: 1,
            principal: "key:credential".into(),
            ownership: "ownership".into(),
            protection: "protection".into(),
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
        assert_eq!(
            installer
                .delegation(
                    "signed",
                    "registration",
                    control(),
                    SignedDelegation {
                        grant: grant.clone(),
                        allocations: vec![allocation.clone()]
                    },
                    &trust,
                    clock
                )
                .await
                .unwrap(),
            Outcome::Ready
        );
        assert!(installer.journal.delegation_intent_ready("signed").unwrap());
        assert_eq!(
            installer
                .delegation(
                    "signed",
                    "registration",
                    control(),
                    SignedDelegation {
                        grant: grant.clone(),
                        allocations: vec![allocation.clone()]
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
        let mut pending_body = grant_body;
        pending_body["id"] = "pending-delegation".into();
        let pending_grant = sign(GRANT_TYPE, pending_body);
        let pending_control = || DelegationControl {
            id: "pending-delegation".into(),
            version: 2,
            principal: "key:credential".into(),
            ownership: "ownership".into(),
            protection: "protection".into(),
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
        drop(journal);
        let reopened =
            Journal::open(&dir.path().join("issuer"), Role::Authority("region".into())).unwrap();
        assert!(!reopened.delegation_intent_ready("signed").unwrap());
        assert!(!reopened.delegation_intent_ready("pending").unwrap());
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
}
