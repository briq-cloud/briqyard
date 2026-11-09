//! Authority-side installation evidence in the issuer's exclusive journal.
//! Pending is never evidence that a host applied an operation.
use super::*;
use crate::execution::channel::InstallationAck;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum AuthorityPayload {
    Registration(HostRegistration),
    Ownership(Box<HostOwnership>),
    Invalidate {
        installation: String,
        generation: u64,
    },
    Revoke {
        id: String,
        version: u64,
    },
}

impl AuthorityPayload {
    fn fence(&self) -> (String, u64) {
        match self {
            Self::Registration(r) => (format!("registration:{}", r.host_instance), r.generation),
            Self::Ownership(r) => (format!("ownership:{}", r.installation), r.generation),
            Self::Invalidate {
                installation,
                generation,
            } => (format!("ownership:{installation}"), *generation),
            Self::Revoke { id, version } => (format!("delegation:{id}"), *version),
        }
    }

    pub(super) fn expected_ack(&self, host_instance: &str) -> Result<InstallationAck, Error> {
        let (generation, bytes) = match self {
            Self::Registration(r) => (r.generation, serde_json::to_vec(r)),
            Self::Ownership(r) => (r.generation, serde_json::to_vec(r)),
            // Invalidation and revocation return only the instance. They are
            // confirmed by their typed response, not by a payload digest.
            _ => return Err(Error::Binding),
        };
        let bytes = bytes.map_err(|_| Error::Binding)?;
        Ok(InstallationAck {
            host_instance: host_instance.into(),
            generation,
            digest: URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityIntent {
    pub host: String,
    pub host_instance: String,
    pub authority_epoch: String,
    /// Missing in older records: ownership without this dependency is unready.
    #[serde(default)]
    pub registration_dependency: Option<AuthorityRegistrationDependency>,
    #[serde(default)]
    pub discovery_dependency: Option<String>,
    pub payload: AuthorityPayload,
    pub acknowledgement: Option<InstallationAck>,
    #[serde(default)]
    pub instance_confirmed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRegistrationDependency {
    pub intent: String,
    pub generation: u64,
}

impl Journal {
    /// Returns true only for a newly persisted intent. A pending retry must
    /// inspect host status or be reconciled by a fresh authority epoch.
    pub fn begin_authority_intent(
        &mut self,
        id: &str,
        host: &str,
        host_instance: &str,
        payload: AuthorityPayload,
        clock: Clock,
    ) -> Result<bool, Error> {
        self.check(clock)?;
        let Role::Authority(authority) = self.role() else {
            return Err(Error::Binding);
        };
        if !valid_id(authority) || !valid_id(id) || !valid_id(host) || !valid_id(host_instance) {
            return Err(Error::Binding);
        }
        let mut registration_dependency = None;
        let mut discovery_dependency = None;
        match &payload {
            AuthorityPayload::Registration(r) => {
                if r.host_instance != host_instance
                    || r.epoch != self.instance()
                    || r.authority != *authority
                    || r.generation == 0
                {
                    return Err(Error::Binding);
                }
            }
            AuthorityPayload::Ownership(r) => {
                if r.host_instance != host_instance || r.primary.host != host || r.generation == 0 {
                    return Err(Error::Binding);
                }
                registration_dependency =
                    self.state
                        .authority_intents
                        .iter()
                        .find_map(|(intent_id, intent)| {
                            if let AuthorityPayload::Registration(registration) = &intent.payload {
                                if intent.host == host
                                    && intent.host_instance == host_instance
                                    && intent.authority_epoch == self.instance()
                                    && self.authority_intent_ready(intent_id).unwrap_or(false)
                                {
                                    return Some(AuthorityRegistrationDependency {
                                        intent: intent_id.clone(),
                                        generation: registration.generation,
                                    });
                                }
                            }
                            None
                        });
                if registration_dependency.is_none() {
                    return Err(Error::Binding);
                }
                discovery_dependency =
                    self.state
                        .discovery_intents
                        .iter()
                        .find_map(|(discovery_id, discovery)| {
                            let receipt = discovery.receipt.as_ref()?;
                            (discovery.host == host
                                && discovery.authority_epoch == self.instance()
                                && self.discovery_intent_ready(discovery_id).unwrap_or(false)
                                && discovery.control.installation == r.installation
                                && discovery.control.generation == r.generation
                                && discovery.control.team == r.team
                                && discovery.control.primary_id == r.subject
                                && discovery.control.metadata_revision == r.metadata_revision
                                && receipt.host_instance == r.host_instance
                                && receipt.primary == r.primary
                                && receipt.public_seeds == r.public_seeds
                                && receipt.public_resources == r.public_resources
                                && receipt.resource_set == r.resource_set)
                                .then(|| discovery_id.clone())
                        });
                if discovery_dependency.is_none() {
                    return Err(Error::Binding);
                }
            }
            AuthorityPayload::Invalidate { .. } | AuthorityPayload::Revoke { .. } => {}
        }
        let intended = AuthorityIntent {
            host: host.into(),
            host_instance: host_instance.into(),
            authority_epoch: self.instance().into(),
            registration_dependency,
            discovery_dependency,
            payload,
            acknowledgement: None,
            instance_confirmed: false,
        };
        if let Some(prior) = self.state.authority_intents.get(id) {
            if prior.host == intended.host
                && prior.host_instance == intended.host_instance
                && prior.authority_epoch == intended.authority_epoch
                && prior.registration_dependency == intended.registration_dependency
                && prior.discovery_dependency == intended.discovery_dependency
                && prior.payload == intended.payload
            {
                return Ok(false);
            }
            return Err(Error::Binding);
        }
        let (mut key, generation) = intended.payload.fence();
        if matches!(intended.payload, AuthorityPayload::Registration(_)) {
            key = format!("registration:{host}");
        }
        if generation == 0
            || generation
                <= self
                    .state
                    .authority_highwater
                    .get(&key)
                    .copied()
                    .unwrap_or(0)
        {
            return Err(Error::Binding);
        }
        let mut next = self.state.clone();
        next.authority_highwater.insert(key, generation);
        next.authority_intents.insert(id.into(), intended);
        next.clock_floor = clock.now;
        self.commit(next)?;
        Ok(true)
    }

    pub fn authority_intent(&self, id: &str) -> Result<Option<&AuthorityIntent>, Error> {
        self.ownership()?;
        Ok(self.state.authority_intents.get(id))
    }

    /// Only the exact typed host ACK can turn a persisted pending intent ready.
    pub fn acknowledge_authority_intent(
        &mut self,
        id: &str,
        ack: InstallationAck,
        clock: Clock,
    ) -> Result<(), Error> {
        self.check(clock)?;
        let intent = self.state.authority_intents.get(id).ok_or(Error::Binding)?;
        if intent.authority_epoch != self.instance()
            || intent.host_instance != ack.host_instance
            || intent
                .payload
                .expected_ack(&intent.host_instance)?
                .generation
                != ack.generation
            || intent.payload.expected_ack(&intent.host_instance)?.digest != ack.digest
        {
            return Err(Error::Binding);
        }
        if intent.acknowledgement.as_ref().is_some_and(|prior| {
            prior.host_instance == ack.host_instance
                && prior.generation == ack.generation
                && prior.digest == ack.digest
        }) {
            return Ok(());
        }
        if intent.acknowledgement.is_some() {
            return Err(Error::Binding);
        }
        let mut next = self.state.clone();
        next.authority_intents
            .get_mut(id)
            .ok_or(Error::Binding)?
            .acknowledgement = Some(ack);
        next.clock_floor = clock.now;
        self.commit(next)
    }

    pub fn authority_intent_ready(&self, id: &str) -> Result<bool, Error> {
        let Some(intent) = self.authority_intent(id)? else {
            return Ok(false);
        };
        let (mut key, generation) = intent.payload.fence();
        if matches!(intent.payload, AuthorityPayload::Registration(_)) {
            key = format!("registration:{}", intent.host);
        }
        let invalidated = match &intent.payload {
            AuthorityPayload::Ownership(owner) => self.state.authority_intents.values().any(
                |other| {
                    matches!(&other.payload, AuthorityPayload::Invalidate { installation, generation }
                        if installation == &owner.installation && generation >= &owner.generation)
                },
            ),
            _ => false,
        };
        let registration_current = if matches!(intent.payload, AuthorityPayload::Ownership(_)) {
            let Some(dependency) = &intent.registration_dependency else {
                return Ok(false);
            };
            let Some(registration) = self.state.authority_intents.get(&dependency.intent) else {
                return Ok(false);
            };
            matches!(&registration.payload, AuthorityPayload::Registration(record)
                if record.generation == dependency.generation
                    && record.host_instance == intent.host_instance)
                && registration.host == intent.host
                && registration.host_instance == intent.host_instance
                && registration.authority_epoch == intent.authority_epoch
                && self.authority_intent_ready(&dependency.intent)?
        } else {
            true
        };
        let discovery_current = if matches!(intent.payload, AuthorityPayload::Ownership(_)) {
            intent
                .discovery_dependency
                .as_ref()
                .is_some_and(|id| self.discovery_intent_ready(id).unwrap_or(false))
        } else {
            true
        };
        Ok(intent.authority_epoch == self.instance()
            && (intent.acknowledgement.is_some() || intent.instance_confirmed)
            && self.state.authority_highwater.get(&key) == Some(&generation)
            && !invalidated
            && registration_current
            && discovery_current)
    }

    /// Invalidation and revocation return the current host instance only.
    pub fn confirm_authority_instance(
        &mut self,
        id: &str,
        host_instance: &str,
        clock: Clock,
    ) -> Result<(), Error> {
        self.check(clock)?;
        let intent = self.state.authority_intents.get(id).ok_or(Error::Binding)?;
        if intent.authority_epoch != self.instance()
            || intent.host_instance != host_instance
            || !matches!(
                intent.payload,
                AuthorityPayload::Invalidate { .. } | AuthorityPayload::Revoke { .. }
            )
        {
            return Err(Error::Binding);
        }
        if intent.instance_confirmed {
            return Ok(());
        }
        let mut next = self.state.clone();
        next.authority_intents
            .get_mut(id)
            .ok_or(Error::Binding)?
            .instance_confirmed = true;
        next.clock_floor = clock.now;
        self.commit(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clock() -> Clock {
        Clock {
            now: 100,
            uncertainty: 0,
        }
    }
    fn open(path: &Path) -> Journal {
        Journal::open(path, Role::Authority("regional".into())).unwrap()
    }
    fn registration(journal: &Journal) -> HostRegistration {
        HostRegistration {
            authority: "regional".into(),
            epoch: journal.instance().into(),
            key_id: "key-1".into(),
            public_key: [7; 32],
            host_instance: "host-run-1".into(),
            generation: 1,
        }
    }
    fn begin(journal: &mut Journal, id: &str, record: HostRegistration) -> Result<bool, Error> {
        journal.begin_authority_intent(
            id,
            "host-1",
            "host-run-1",
            AuthorityPayload::Registration(record),
            clock(),
        )
    }

    fn ownership(host_instance: &str, generation: u64) -> HostOwnership {
        let target = Target {
            host: "host-1".into(),
            machine: "machine-1".into(),
            namespace: "team".into(),
            run: "run-1".into(),
            placement: "version-1".into(),
        };
        HostOwnership {
            installation: "ownership".into(),
            generation,
            team: "team".into(),
            subject: "public-1".into(),
            metadata_revision: "metadata-1".into(),
            primary: target.clone(),
            public_seeds: vec![target.clone()],
            public_resources: vec![PublicResource {
                id: "public-1".into(),
                target: target.clone(),
            }],
            resource_set: ResourceSet {
                revision: "resources-1".into(),
                resources: vec![target],
            },
            host_instance: host_instance.into(),
        }
    }

    fn install_ownership(journal: &mut Journal, id: &str, owner: HostOwnership) {
        let registration = journal.state.authority_intents.iter()
            .find_map(|(id, intent)| matches!(&intent.payload, AuthorityPayload::Registration(r)
                if r.host_instance == owner.host_instance && journal.authority_intent_ready(id).unwrap()).then(|| id.clone()))
            .unwrap();
        let control = OwnershipControl {
            host_instance: owner.host_instance.clone(),
            installation: owner.installation.clone(),
            generation: owner.generation,
            team: owner.team.clone(),
            primary_id: owner.subject.clone(),
            seeds: owner
                .public_resources
                .iter()
                .map(|p| PublicSeed {
                    id: p.id.clone(),
                    machine: p.target.machine.clone(),
                    namespace: p.target.namespace.clone(),
                    team: owner.team.clone(),
                    expected_version: None,
                })
                .collect(),
            metadata_revision: owner.metadata_revision.clone(),
        };
        let discovery = format!("discovery-{id}");
        journal
            .begin_discovery_intent(&discovery, "host-1", &registration, control, clock())
            .unwrap();
        journal
            .acknowledge_discovery_intent(
                &discovery,
                DiscoveryReceipt {
                    host_instance: owner.host_instance.clone(),
                    primary: owner.primary.clone(),
                    public_seeds: owner.public_seeds.clone(),
                    public_resources: owner.public_resources.clone(),
                    resource_set: owner.resource_set.clone(),
                },
                clock(),
            )
            .unwrap();
        let payload = AuthorityPayload::Ownership(Box::new(owner.clone()));
        journal
            .begin_authority_intent(id, "host-1", &owner.host_instance, payload.clone(), clock())
            .unwrap();
        journal
            .acknowledge_authority_intent(
                id,
                payload.expected_ack(&owner.host_instance).unwrap(),
                clock(),
            )
            .unwrap();
    }

    #[test]
    fn ownership_depends_on_its_exact_current_ready_registration() {
        for replacement_instance in ["host-run-1", "host-run-2"] {
            let dir = tempfile::tempdir().unwrap();
            let mut journal = open(&dir.path().join("issuer"));
            let old = registration(&journal);
            begin(&mut journal, "register-1", old.clone()).unwrap();
            journal
                .acknowledge_authority_intent(
                    "register-1",
                    AuthorityPayload::Registration(old.clone())
                        .expected_ack(&old.host_instance)
                        .unwrap(),
                    clock(),
                )
                .unwrap();
            install_ownership(&mut journal, "owner-1", ownership(&old.host_instance, 1));
            assert!(journal.authority_intent_ready("owner-1").unwrap());
            assert_eq!(
                journal
                    .authority_intent("owner-1")
                    .unwrap()
                    .unwrap()
                    .registration_dependency,
                Some(AuthorityRegistrationDependency {
                    intent: "register-1".into(),
                    generation: 1
                })
            );
            let replacement = HostRegistration {
                generation: 2,
                host_instance: replacement_instance.into(),
                ..old
            };
            let payload = AuthorityPayload::Registration(replacement.clone());
            journal
                .begin_authority_intent(
                    "register-2",
                    "host-1",
                    replacement_instance,
                    payload.clone(),
                    clock(),
                )
                .unwrap();
            // Pending registration already fences old ownership, even before host ACK.
            assert!(!journal.authority_intent_ready("owner-1").unwrap());
            journal
                .acknowledge_authority_intent(
                    "register-2",
                    payload.expected_ack(replacement_instance).unwrap(),
                    clock(),
                )
                .unwrap();
            assert!(journal.authority_intent_ready("register-2").unwrap());
            // An arbitrary current registration cannot validate ownership from R1.
            assert!(!journal.authority_intent_ready("owner-1").unwrap());
            install_ownership(&mut journal, "owner-2", ownership(replacement_instance, 2));
            assert!(journal.authority_intent_ready("owner-2").unwrap());
            assert_eq!(
                journal
                    .authority_intent("owner-2")
                    .unwrap()
                    .unwrap()
                    .registration_dependency,
                Some(AuthorityRegistrationDependency {
                    intent: "register-2".into(),
                    generation: 2
                })
            );
            // Legacy records missing the dependency fail closed.
            journal
                .state
                .authority_intents
                .get_mut("owner-2")
                .unwrap()
                .registration_dependency = None;
            assert!(!journal.authority_intent_ready("owner-2").unwrap());
        }
    }

    #[test]
    fn pending_and_lost_ack_survive_reopen_but_old_epoch_never_becomes_ready() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("issuer");
        let mut journal = open(&path);
        let record = registration(&journal);
        assert!(begin(&mut journal, "intent-1", record.clone()).unwrap());
        assert!(!begin(&mut journal, "intent-1", record.clone()).unwrap());
        assert!(!journal.authority_intent_ready("intent-1").unwrap());
        drop(journal);
        let mut reopened = open(&path);
        assert!(reopened.authority_intent("intent-1").unwrap().is_some());
        assert!(!reopened.authority_intent_ready("intent-1").unwrap());
        assert!(reopened
            .acknowledge_authority_intent(
                "intent-1",
                AuthorityPayload::Registration(record.clone())
                    .expected_ack(&record.host_instance)
                    .unwrap(),
                clock()
            )
            .is_err());
        assert!(begin(&mut reopened, "intent-1", record).is_err());
    }

    #[test]
    fn exact_ack_is_durable_and_changed_payload_or_lower_generation_conflicts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("issuer");
        let mut journal = open(&path);
        let record = registration(&journal);
        begin(&mut journal, "intent-1", record.clone()).unwrap();
        let mut wrong = AuthorityPayload::Registration(record.clone())
            .expected_ack(&record.host_instance)
            .unwrap();
        wrong.digest = "different".into();
        assert!(journal
            .acknowledge_authority_intent("intent-1", wrong, clock())
            .is_err());
        assert!(!journal.authority_intent_ready("intent-1").unwrap());
        let exact = AuthorityPayload::Registration(record.clone())
            .expected_ack(&record.host_instance)
            .unwrap();
        journal
            .acknowledge_authority_intent("intent-1", exact, clock())
            .unwrap();
        assert!(journal.authority_intent_ready("intent-1").unwrap());
        let mut changed = record.clone();
        changed.public_key = [8; 32];
        assert!(begin(&mut journal, "intent-1", changed.clone()).is_err());
        assert!(begin(&mut journal, "intent-2", changed).is_err());
        drop(journal);
        let reopened = open(&path);
        assert!(!reopened.authority_intent_ready("intent-1").unwrap());
        assert!(reopened
            .authority_intent("intent-1")
            .unwrap()
            .unwrap()
            .acknowledgement
            .is_some());
    }

    #[test]
    fn invalidate_tombstone_precedes_host_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let mut journal = open(&dir.path().join("issuer"));
        let record = registration(&journal);
        begin(&mut journal, "register", record.clone()).unwrap();
        let ack = AuthorityPayload::Registration(record)
            .expected_ack("host-run-1")
            .unwrap();
        journal
            .acknowledge_authority_intent("register", ack, clock())
            .unwrap();
        assert!(journal
            .begin_authority_intent(
                "invalidate",
                "host-1",
                "host-run-1",
                AuthorityPayload::Invalidate {
                    installation: "install-1".into(),
                    generation: 2
                },
                clock(),
            )
            .unwrap());
        assert!(!journal.authority_intent_ready("invalidate").unwrap());
        assert!(journal
            .confirm_authority_instance("invalidate", "wrong", clock())
            .is_err());
        assert!(!journal.authority_intent_ready("invalidate").unwrap());
        journal
            .confirm_authority_instance("invalidate", "host-run-1", clock())
            .unwrap();
        assert!(journal.authority_intent_ready("invalidate").unwrap());
        assert!(journal
            .begin_authority_intent(
                "older",
                "host-1",
                "host-run-1",
                AuthorityPayload::Invalidate {
                    installation: "install-1".into(),
                    generation: 1
                },
                clock(),
            )
            .is_err());
    }

    #[test]
    fn revoked_version_is_fenced_while_propagation_is_pending() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("issuer");
        let mut journal = open(&path);
        assert!(journal
            .begin_authority_intent(
                "revoke-3",
                "host-1",
                "host-run-1",
                AuthorityPayload::Revoke {
                    id: "grant-1".into(),
                    version: 3
                },
                clock(),
            )
            .unwrap());
        assert!(!journal.authority_intent_ready("revoke-3").unwrap());
        assert!(journal
            .begin_authority_intent(
                "revoke-2",
                "host-1",
                "host-run-1",
                AuthorityPayload::Revoke {
                    id: "grant-1".into(),
                    version: 2
                },
                clock(),
            )
            .is_err());
        drop(journal);
        let mut journal = open(&path);
        assert!(!journal.authority_intent_ready("revoke-3").unwrap());
        assert!(journal
            .confirm_authority_instance("revoke-3", "host-run-1", clock())
            .is_err());
    }
}
