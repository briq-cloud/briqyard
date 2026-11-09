//! One-shot discovery and protection evidence in the issuer's exclusive journal.
use super::*;
use crate::execution::channel::{Protect, ProtectionAck};
use crate::execution::{DiscoveryReceipt, DiscoveryRequest, PublicSeed};
use std::collections::BTreeSet;

/// Check the host's complete public mapping against independently supplied logical seeds.
/// Native gateway members may occur only in the resource vector; the host validates them.
pub fn validate_discovery_receipt(
    host: &str,
    request: &DiscoveryRequest,
    receipt: &DiscoveryReceipt,
) -> Result<(), Error> {
    if !valid_id(host)
        || !valid_id(&request.host_instance)
        || !valid_id(&request.primary_id)
        || request.seeds.is_empty()
        || request.seeds.len() > MAX_RESOURCES
        || receipt.host_instance != request.host_instance
        || receipt.public_seeds.len() != request.seeds.len()
        || receipt.public_resources.len() != request.seeds.len()
        || receipt.resource_set.resources.is_empty()
        || receipt.resource_set.resources.len() > MAX_RESOURCES
        || !valid_id(&receipt.resource_set.revision)
    {
        return Err(Error::Binding);
    }
    let team = &request.seeds[0].team;
    let mut ids = BTreeSet::new();
    let mut machines = BTreeSet::new();
    for seed in &request.seeds {
        if !valid_id(&seed.id)
            || !valid_id(&seed.machine)
            || !valid_id(&seed.namespace)
            || !valid_id(&seed.team)
            || &seed.team != team
            || !ids.insert(seed.id.as_str())
            || !machines.insert(seed.machine.as_str())
        {
            return Err(Error::Binding);
        }
    }
    if ids.iter().filter(|id| **id == request.primary_id).count() != 1 {
        return Err(Error::Binding);
    }
    let resources = &receipt.resource_set.resources;
    if resources.windows(2).any(|w| {
        (w[0].host.as_str(), w[0].machine.as_str()) >= (w[1].host.as_str(), w[1].machine.as_str())
    }) || resources.iter().any(|t| {
        t.host != host
            || !valid_id(&t.machine)
            || !valid_id(&t.namespace)
            || !valid_id(&t.run)
            || !valid_id(&t.placement)
    }) || !resources.contains(&receipt.primary)
    {
        return Err(Error::Binding);
    }
    let mut mapped = BTreeSet::new();
    for (seed, target) in request.seeds.iter().zip(&receipt.public_seeds) {
        if target.host != host
            || target.machine != seed.machine
            || target.namespace != seed.namespace
            || seed
                .expected_version
                .is_some_and(|v| target.placement != format!("version-{v}"))
            || !resources.contains(target)
            || !mapped.insert(target.machine.as_str())
            || receipt
                .public_resources
                .iter()
                .filter(|p| p.id == seed.id && p.target == *target)
                .count()
                != 1
            || (seed.id == request.primary_id && receipt.primary != *target)
        {
            return Err(Error::Binding);
        }
    }
    if receipt
        .public_resources
        .iter()
        .any(|p| !ids.contains(p.id.as_str()) || p.target.host != host)
        || receipt.public_resources.windows(2).any(|w| {
            let a = resources.iter().position(|t| t == &w[0].target);
            let b = resources.iter().position(|t| t == &w[1].target);
            a >= b
        })
    {
        return Err(Error::Binding);
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnershipControl {
    pub host_instance: String,
    pub installation: String,
    pub generation: u64,
    pub team: String,
    pub primary_id: String,
    pub seeds: Vec<PublicSeed>,
    pub metadata_revision: String,
}

impl OwnershipControl {
    pub fn discovery_request(&self) -> DiscoveryRequest {
        DiscoveryRequest {
            host_instance: self.host_instance.clone(),
            primary_id: self.primary_id.clone(),
            seeds: self.seeds.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryIntent {
    pub host: String,
    pub registration: String,
    pub authority_epoch: String,
    pub control: OwnershipControl,
    pub request: DiscoveryRequest,
    pub receipt: Option<DiscoveryReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectionIntent {
    pub host: String,
    pub ownership: String,
    pub authority_epoch: String,
    pub request: Protect,
    pub resources: Vec<Target>,
    pub revision: String,
    pub acknowledgement: Option<ProtectionAck>,
}

impl Journal {
    pub fn begin_discovery_intent(
        &mut self,
        id: &str,
        host: &str,
        registration: &str,
        control: OwnershipControl,
        clock: Clock,
    ) -> Result<bool, Error> {
        self.check(clock)?;
        let request = control.discovery_request();
        if !matches!(self.role(), Role::Authority(_))
            || !valid_id(id)
            || !valid_id(host)
            || !valid_id(&control.installation)
            || control.generation == 0
            || !valid_id(&control.team)
            || !valid_id(&control.metadata_revision)
            || !valid_id(&control.primary_id)
            || control.seeds.is_empty()
            || control.seeds.len() > MAX_RESOURCES
            || control.seeds.iter().any(|s| {
                s.team != control.team
                    || !valid_id(&s.id)
                    || !valid_id(&s.machine)
                    || !valid_id(&s.namespace)
            })
            || control
                .seeds
                .iter()
                .filter(|s| s.id == control.primary_id)
                .count()
                != 1
            || control
                .seeds
                .iter()
                .map(|s| &s.id)
                .collect::<BTreeSet<_>>()
                .len()
                != control.seeds.len()
            || control
                .seeds
                .iter()
                .map(|s| &s.machine)
                .collect::<BTreeSet<_>>()
                .len()
                != control.seeds.len()
            || !self.authority_intent_ready(registration)?
            || !matches!(self.authority_intent(registration)?.map(|i| &i.payload),
                Some(AuthorityPayload::Registration(r)) if r.host_instance == request.host_instance)
            || self
                .authority_intent(registration)?
                .is_none_or(|i| i.host != host)
        {
            return Err(Error::Binding);
        }
        let intended = DiscoveryIntent {
            host: host.into(),
            registration: registration.into(),
            authority_epoch: self.instance().into(),
            control,
            request,
            receipt: None,
        };
        if let Some(prior) = self.state.discovery_intents.get(id) {
            if prior.host == intended.host
                && prior.registration == intended.registration
                && prior.authority_epoch == intended.authority_epoch
                && prior.control == intended.control
                && prior.request == intended.request
            {
                return Ok(false);
            }
            return Err(Error::Binding);
        }
        let mut next = self.state.clone();
        next.discovery_intents.insert(id.into(), intended);
        next.clock_floor = clock.now;
        self.commit(next)?;
        Ok(true)
    }

    pub fn discovery_intent(&self, id: &str) -> Result<Option<&DiscoveryIntent>, Error> {
        self.ownership()?;
        Ok(self.state.discovery_intents.get(id))
    }

    pub fn acknowledge_discovery_intent(
        &mut self,
        id: &str,
        receipt: DiscoveryReceipt,
        clock: Clock,
    ) -> Result<(), Error> {
        self.check(clock)?;
        let intent = self.state.discovery_intents.get(id).ok_or(Error::Binding)?;
        if intent.authority_epoch != self.instance()
            || !self.authority_intent_ready(&intent.registration)?
            || validate_discovery_receipt(&intent.host, &intent.request, &receipt).is_err()
        {
            return Err(Error::Binding);
        }
        if intent.receipt.as_ref() == Some(&receipt) {
            return Ok(());
        }
        if intent.receipt.is_some() {
            return Err(Error::Binding);
        }
        let mut next = self.state.clone();
        next.discovery_intents
            .get_mut(id)
            .ok_or(Error::Binding)?
            .receipt = Some(receipt);
        next.clock_floor = clock.now;
        self.commit(next)
    }

    pub fn discovery_intent_ready(&self, id: &str) -> Result<bool, Error> {
        if self.installation_uncertain("discovery", id) {
            return Ok(false);
        }
        let Some(intent) = self.discovery_intent(id)? else {
            return Ok(false);
        };
        Ok(intent.authority_epoch == self.instance()
            && intent.receipt.is_some()
            && self.authority_intent_ready(&intent.registration)?)
    }

    pub fn begin_protection_intent(
        &mut self,
        id: &str,
        host: &str,
        ownership: &str,
        request: Protect,
        clock: Clock,
    ) -> Result<bool, Error> {
        self.check(clock)?;
        if !valid_id(id)
            || !valid_id(host)
            || !valid_id(&request.admission)
            || clock.uncertainty > 5
            || request.expires_at_ms
                <= clock
                    .now
                    .saturating_sub(clock.uncertainty)
                    .saturating_mul(1000)
            || request.expires_at_ms > clock.now.saturating_add(60).saturating_mul(1000)
            || !self.authority_intent_ready(ownership)?
        {
            return Err(Error::Binding);
        }
        let Some(intent) = self.authority_intent(ownership)? else {
            return Err(Error::Binding);
        };
        let AuthorityPayload::Ownership(owner) = &intent.payload else {
            return Err(Error::Binding);
        };
        if intent.host != host
            || owner.installation != request.installation
            || owner.generation != request.generation
            || request.expires_at_ms == 0
            || request.expires_at_ms > MAX_SAFE_INTEGER
        {
            return Err(Error::Binding);
        }
        let intended = ProtectionIntent {
            host: host.into(),
            ownership: ownership.into(),
            authority_epoch: self.instance().into(),
            request,
            resources: owner.resource_set.resources.clone(),
            revision: owner.resource_set.revision.clone(),
            acknowledgement: None,
        };
        if let Some(prior) = self.state.protection_intents.get(id) {
            if prior.host == intended.host
                && prior.ownership == intended.ownership
                && prior.authority_epoch == intended.authority_epoch
                && prior.request == intended.request
                && prior.resources == intended.resources
                && prior.revision == intended.revision
            {
                return Ok(false);
            }
            return Err(Error::Binding);
        }
        if self
            .state
            .protection_intents
            .values()
            .any(|p| p.request.admission == intended.request.admission)
        {
            return Err(Error::Binding);
        }
        let mut next = self.state.clone();
        next.protection_intents.insert(id.into(), intended);
        next.clock_floor = clock.now;
        self.commit(next)?;
        Ok(true)
    }

    pub fn protection_intent(&self, id: &str) -> Result<Option<&ProtectionIntent>, Error> {
        self.ownership()?;
        Ok(self.state.protection_intents.get(id))
    }

    pub fn acknowledge_protection_intent(
        &mut self,
        id: &str,
        ack: ProtectionAck,
        clock: Clock,
    ) -> Result<(), Error> {
        self.check(clock)?;
        let intent = self
            .state
            .protection_intents
            .get(id)
            .ok_or(Error::Binding)?;
        if intent.authority_epoch != self.instance()
            || !self.authority_intent_ready(&intent.ownership)?
            || ack.admission != intent.request.admission
            || ack.expires_at_ms != intent.request.expires_at_ms
            || ack.resources != intent.resources
            || ack.revision != intent.revision
        {
            return Err(Error::Binding);
        }
        if intent.acknowledgement.as_ref() == Some(&ack) {
            return Ok(());
        }
        if intent.acknowledgement.is_some() {
            return Err(Error::Binding);
        }
        let mut next = self.state.clone();
        next.protection_intents
            .get_mut(id)
            .ok_or(Error::Binding)?
            .acknowledgement = Some(ack);
        next.clock_floor = clock.now;
        self.commit(next)
    }

    pub fn protection_intent_ready(&self, id: &str) -> Result<bool, Error> {
        if self.installation_uncertain("protection", id) {
            return Ok(false);
        }
        let Some(intent) = self.protection_intent(id)? else {
            return Ok(false);
        };
        Ok(intent.authority_epoch == self.instance()
            && intent.acknowledgement.is_some()
            && self.authority_intent_ready(&intent.ownership)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::{PublicResource, ResourceSet};

    fn clock() -> Clock {
        Clock {
            now: 100,
            uncertainty: 0,
        }
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
    fn control(instance: &str) -> OwnershipControl {
        OwnershipControl {
            host_instance: instance.into(),
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
        }
    }
    fn receipt(instance: &str) -> DiscoveryReceipt {
        DiscoveryReceipt {
            host_instance: instance.into(),
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
        }
    }
    fn registered(journal: &mut Journal, instance: &str) {
        let record = HostRegistration {
            authority: "region".into(),
            epoch: journal.instance().into(),
            key_id: "key".into(),
            public_key: [1; 32],
            host_instance: instance.into(),
            generation: 1,
        };
        journal
            .begin_authority_intent(
                "registration",
                "host",
                instance,
                AuthorityPayload::Registration(record.clone()),
                clock(),
            )
            .unwrap();
        let ack = AuthorityPayload::Registration(record)
            .expected_ack(instance)
            .unwrap();
        journal
            .acknowledge_authority_intent("registration", ack, clock())
            .unwrap();
    }
    fn discovered(journal: &mut Journal, instance: &str) {
        journal
            .begin_discovery_intent(
                "discovery",
                "host",
                "registration",
                control(instance),
                clock(),
            )
            .unwrap();
        journal
            .acknowledge_discovery_intent("discovery", receipt(instance), clock())
            .unwrap();
    }
    fn owned(journal: &mut Journal, instance: &str) {
        let found = journal.discovery_intent("discovery").unwrap().unwrap();
        let r = found.receipt.as_ref().unwrap();
        let owner = HostOwnership {
            installation: found.control.installation.clone(),
            generation: 1,
            team: "team".into(),
            subject: "public-a".into(),
            metadata_revision: "metadata-1".into(),
            primary: r.primary.clone(),
            public_seeds: r.public_seeds.clone(),
            public_resources: r.public_resources.clone(),
            resource_set: r.resource_set.clone(),
            host_instance: instance.into(),
        };
        let payload = AuthorityPayload::Ownership(Box::new(owner));
        journal
            .begin_authority_intent("ownership", "host", instance, payload.clone(), clock())
            .unwrap();
        journal
            .acknowledge_authority_intent(
                "ownership",
                payload.expected_ack(instance).unwrap(),
                clock(),
            )
            .unwrap();
    }

    #[test]
    fn discovery_requires_exact_host_public_closure_and_unchanged_input() {
        let dir = tempfile::tempdir().unwrap();
        let mut journal =
            Journal::open(&dir.path().join("issuer"), Role::Authority("region".into())).unwrap();
        registered(&mut journal, "instance");
        assert!(journal
            .begin_discovery_intent(
                "discovery",
                "host",
                "registration",
                control("instance"),
                clock()
            )
            .unwrap());
        let mut changed = control("instance");
        changed.metadata_revision = "metadata-2".into();
        assert!(journal
            .begin_discovery_intent("discovery", "host", "registration", changed, clock())
            .is_err());
        let mut wrong = receipt("instance");
        wrong.host_instance = "other".into();
        assert!(journal
            .acknowledge_discovery_intent("discovery", wrong, clock())
            .is_err());
        let mut omitted = receipt("instance");
        omitted.public_resources.push(PublicResource {
            id: "public-b".into(),
            target: target("gateway"),
        });
        assert!(journal
            .acknowledge_discovery_intent("discovery", omitted, clock())
            .is_err());
        let mut unsorted = receipt("instance");
        unsorted.resource_set.resources.reverse();
        assert!(journal
            .acknowledge_discovery_intent("discovery", unsorted, clock())
            .is_err());
        journal
            .acknowledge_discovery_intent("discovery", receipt("instance"), clock())
            .unwrap();
        assert!(journal.discovery_intent_ready("discovery").unwrap());
    }

    #[test]
    fn pending_protection_and_mismatched_ack_never_become_ready() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("issuer");
        let mut journal = Journal::open(&path, Role::Authority("region".into())).unwrap();
        registered(&mut journal, "instance");
        discovered(&mut journal, "instance");
        owned(&mut journal, "instance");
        let request = Protect {
            installation: "install".into(),
            generation: 1,
            admission: "admission".into(),
            expires_at_ms: 110_001,
        };
        let mut too_late = request.clone();
        too_late.expires_at_ms = 160_001;
        assert!(journal
            .begin_protection_intent("late", "host", "ownership", too_late, clock())
            .is_err());
        assert!(journal.protection_intent("late").unwrap().is_none());
        assert!(journal
            .begin_protection_intent("protect", "host", "ownership", request.clone(), clock())
            .unwrap());
        assert!(!journal.protection_intent_ready("protect").unwrap());
        let mut changed = request.clone();
        changed.expires_at_ms += 1;
        assert!(journal
            .begin_protection_intent("protect", "host", "ownership", changed, clock())
            .is_err());
        let ack = ProtectionAck {
            admission: "admission".into(),
            expires_at_ms: request.expires_at_ms,
            resources: receipt("instance").resource_set.resources,
            revision: "revision-1".into(),
        };
        let mut wrong = ack.clone();
        wrong.resources.reverse();
        assert!(journal
            .acknowledge_protection_intent("protect", wrong, clock())
            .is_err());
        let mut wrong = ack.clone();
        wrong.expires_at_ms += 1;
        assert!(journal
            .acknowledge_protection_intent("protect", wrong, clock())
            .is_err());
        journal
            .acknowledge_protection_intent("protect", ack, clock())
            .unwrap();
        assert!(journal.protection_intent_ready("protect").unwrap());
        let replacement = HostRegistration {
            authority: "region".into(),
            epoch: journal.instance().into(),
            key_id: "key".into(),
            public_key: [1; 32],
            host_instance: "instance".into(),
            generation: 2,
        };
        journal
            .begin_authority_intent(
                "registration-2",
                "host",
                "instance",
                AuthorityPayload::Registration(replacement),
                clock(),
            )
            .unwrap();
        assert!(!journal.discovery_intent_ready("discovery").unwrap());
        assert!(!journal.protection_intent_ready("protect").unwrap());
        drop(journal);
        let journal = Journal::open(&path, Role::Authority("region".into())).unwrap();
        assert!(!journal.protection_intent_ready("protect").unwrap());
    }
}
