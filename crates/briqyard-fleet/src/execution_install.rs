//! Dormant trusted installer. The caller must supply authenticated control input;
//! submitted grants and permits never construct these records.
use crate::execution_host::{Error as TransportError, HostTransport, Route};
use briqyard_api::execution::{
    admission::{
        AuthorityPayload, Error as JournalError, HostOwnership, HostRegistration, Journal,
        OwnershipControl,
    },
    channel::{InstallationAck, Instance, Invalidate, Protect, ProtectionAck, Revoke},
    Clock, DiscoveryReceipt, MAX_BODY_BYTES,
};

#[derive(Clone, Debug)]
pub(super) struct CommittedIdle {
    pub admission: String,
    pub expires_at_ms: u64,
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
    use briqyard_api::execution::{PublicResource, PublicSeed, ResourceSet, Target};
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
        use std::sync::Arc;

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
            State(()): State<()>,
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
        let task = tokio::spawn(async move {
            axum_server::from_tcp_rustls(
                listener,
                axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config)),
            )
            .handle(running)
            .serve(
                Router::new()
                    .fallback(endpoint)
                    .with_state(())
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
            now: 100,
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
                        expires_at_ms: 110_001
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
