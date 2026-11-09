//! Host-owned private reachability for scoped execution. A caller's resource set is
//! only a proposed commitment; installed scope and actual network state decide membership.
use super::*;
use api::execution::{admission::Journal, ResourceSet, Target, MAX_RESOURCES};
use std::collections::BTreeSet;

#[derive(Clone, Copy)]
pub struct ExecutionResourceScope<'a> {
    pub primary: &'a Target,
    pub required: &'a [Target],
}

#[derive(Clone)]
struct Candidate {
    id: String,
    namespace: String,
    ip: String,
    policy: Option<nft::Policy>,
    eligible: bool,
    gateway: bool,
    requested_via: Option<String>,
}

fn permits(from: &Candidate, to: &Candidate) -> bool {
    if from.namespace != to.namespace {
        return false;
    }
    match &from.policy {
        Some(nft::Policy::Via {
            to: ip,
            to_tap,
            siblings,
            ..
        }) => *siblings || (ip == &to.ip && to_tap == &netw::tap_name(&to.id)),
        _ => true,
    }
}

fn closure(candidates: &[Candidate], seeds: &BTreeSet<String>) -> Result<BTreeSet<String>, MError> {
    let mut reached = seeds.clone();
    loop {
        let mut grew = false;
        for candidate in candidates {
            if reached.contains(&candidate.id) {
                continue;
            }
            if !candidates.iter().any(|other| {
                reached.contains(&other.id)
                    && permits(other, candidate)
                    && permits(candidate, other)
            }) {
                continue;
            }
            if !candidate.eligible {
                return Err(MError::Conflict(
                    "reachable execution resource is not verifiable".into(),
                ));
            }
            reached.insert(candidate.id.clone());
            if reached.len() > MAX_RESOURCES {
                return Err(invalid("execution resource closure exceeds limit"));
            }
            grew = true;
        }
        if !grew {
            break;
        }
    }
    Ok(reached)
}

impl Manager {
    pub(super) fn validate_execution_scope(
        &self,
        scope: ExecutionResourceScope<'_>,
    ) -> Result<BTreeSet<String>, MError> {
        if scope.required.is_empty()
            || scope.required.len() > MAX_RESOURCES
            || scope
                .required
                .iter()
                .filter(|t| *t == scope.primary)
                .count()
                != 1
        {
            return Err(invalid("invalid installed execution resource scope"));
        }
        let mut ids = BTreeSet::new();
        for target in scope.required {
            if target.host != self.inner.host_id || !ids.insert(target.machine.clone()) {
                return Err(invalid("invalid local execution seed"));
            }
            self.own_entry(&target.machine)?;
        }
        Ok(ids)
    }

    fn execution_candidates(
        &self,
        namespaces: &BTreeSet<String>,
    ) -> Result<Vec<Candidate>, MError> {
        if self.recovery_fault().is_some() {
            return Err(MError::Conflict("execution recovery unresolved".into()));
        }
        let entries = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let known = entries.iter().map(|e| e.snapshot()).collect::<Vec<_>>();
        let policies = self.inner.policies.lock().unwrap().clone();
        let holds = self.inner.launch_holds.lock().unwrap().clone();
        if holds.iter().any(|(id, hold)| {
            namespaces.contains(&hold.namespace)
                && !known.iter().any(|r| {
                    r.id == *id
                        && r.namespace == hold.namespace
                        && r.launch_identity.as_ref() == Some(hold)
                })
        }) {
            return Err(MError::Conflict("unresolved execution launch hold".into()));
        }
        let mut candidates = Vec::new();
        for entry in entries {
            // Persistence takes removed before rec. Never retain rec while reading
            // another entry mutex, including during the unlocked discovery scan.
            let r = entry.snapshot();
            if !namespaces.contains(&r.namespace) {
                continue;
            }
            let vm = entry.live.lock().unwrap().clone();
            let live = vm.is_some();
            let pending = entry.launch_pending.load(Relaxed)
                || entry.launch_unproven.load(Relaxed)
                || entry.pending_adoption.lock().unwrap().is_some();
            let quarantined = r.template_birth.is_some()
                || r.clone_origin
                    .as_ref()
                    .is_some_and(|o| o.stage != templates::CloneStage::Active);
            let eligible = r.state == state::RUNNING
                && live
                && !pending
                && !*entry.removed.lock().unwrap()
                && !quarantined
                && self.assignment_publication_allowed(&r, entry.identity_trusted.load(Relaxed));
            let absent = r.state == state::STOPPED
                && !live
                && !pending
                && r.pid == 0
                && !holds.contains_key(&r.id)
                && self.inner.vmm.launch_settlement(&r.id) == fc::LaunchSettlement::Settled;
            if let Some(hold) = holds.get(&r.id) {
                if r.launch_identity.as_ref() != Some(hold) {
                    return Err(MError::Conflict(
                        "execution launch hold identity changed".into(),
                    ));
                }
                let vm = vm.as_ref().ok_or_else(|| {
                    MError::Conflict("execution launch hold has no live process".into())
                })?;
                self.verify_live_launch(&entry, vm).map_err(|_| {
                    MError::Conflict("execution launch hold process unconfirmed".into())
                })?;
                if entry.snapshot().launch_identity.as_ref() != Some(hold) {
                    return Err(MError::Conflict(
                        "execution launch hold identity changed".into(),
                    ));
                }
            } else if r.launch_identity.is_some() {
                return Err(MError::Conflict("execution launch hold missing".into()));
            }
            let policy = policies.get(&r.id).map(|(_, p)| p.clone());
            let expected_open = r.egress.mode == api::egress::OPEN
                && self.inner.cfg.egress_limits.with(&r.limits).is_none();
            // A policy-free record is open only when both its request and host limits
            // say so. A missing strict policy cannot broaden a private edge.
            if eligible
                && (policy.is_none() != expected_open
                    || policy.as_ref().is_some_and(|p| {
                        p.ip() != r.ip
                            || match p {
                                nft::Policy::Via { .. } => r.egress.mode != api::egress::VIA,
                                nft::Policy::None { .. } => r.egress.mode != api::egress::NONE,
                                nft::Policy::Open { .. } => r.egress.mode != api::egress::OPEN,
                            }
                    }))
            {
                return Err(MError::Conflict(
                    "installed execution policy unresolved".into(),
                ));
            }
            if !eligible && !absent {
                return Err(MError::Conflict(
                    "execution resource publication or launch unresolved".into(),
                ));
            }
            if absent {
                continue;
            }
            candidates.push(Candidate {
                id: r.id.clone(),
                namespace: r.namespace.clone(),
                ip: r.ip.clone(),
                policy,
                eligible,
                gateway: r.is_gateway(),
                requested_via: r.egress.via.clone(),
            });
        }
        Ok(candidates)
    }

    fn resolve_execution_members(
        &self,
        scope: ExecutionResourceScope<'_>,
    ) -> Result<BTreeSet<String>, MError> {
        let seeds = self.validate_execution_scope(scope)?;
        let namespaces = scope
            .required
            .iter()
            .map(|t| t.namespace.clone())
            .collect::<BTreeSet<_>>();
        let candidates = self.execution_candidates(&namespaces)?;
        if seeds
            .iter()
            .any(|id| !candidates.iter().any(|c| c.id == *id && c.eligible))
        {
            return Err(MError::Conflict(
                "installed execution seed is not running".into(),
            ));
        }
        for c in &candidates {
            if let Some(nft::Policy::Via { to, to_tap, .. }) = &c.policy {
                let expected = match c.requested_via.as_deref() {
                    Some(api::egress::GATEWAY) => candidates
                        .iter()
                        .find(|peer| peer.gateway && peer.namespace == c.namespace),
                    Some(id) => candidates
                        .iter()
                        .find(|peer| peer.id == id && peer.namespace == c.namespace),
                    None => None,
                };
                if !expected.is_some_and(|peer| {
                    peer.eligible && peer.ip == *to && netw::tap_name(&peer.id) == *to_tap
                }) {
                    return Err(MError::Conflict(
                        "installed execution via policy unresolved".into(),
                    ));
                }
            }
        }
        closure(&candidates, &seeds)
    }

    pub(super) fn validate_execution_set_locked(
        &self,
        scope: ExecutionResourceScope<'_>,
        proposed: &[Target],
        revision: &str,
        instance: &str,
    ) -> Result<(), MError> {
        let members = self.resolve_execution_members(scope)?;
        if members.len() != proposed.len() || proposed.iter().any(|t| !members.contains(&t.machine))
        {
            return Err(MError::Conflict(
                "execution resource closure changed".into(),
            ));
        }
        for target in proposed {
            let entry = self.entry(&target.machine)?;
            if self.scoped_target(&entry, instance)? != *target {
                return Err(MError::Conflict("execution target changed".into()));
            }
        }
        for seed in scope.required {
            if !proposed.contains(seed) {
                return Err(MError::Conflict("installed execution seed changed".into()));
            }
        }
        let snapshot = self.execution_namespace_snapshot(proposed)?;
        if execution_mutations::execution_resource_revision(proposed, &snapshot)? != revision {
            return Err(MError::Conflict(
                "execution namespace generation changed".into(),
            ));
        }
        Ok(())
    }

    pub async fn execution_resources(
        &self,
        scope: ExecutionResourceScope<'_>,
        journal: &tokio::sync::Mutex<Journal>,
    ) -> Result<ResourceSet, MError> {
        self.validate_execution_scope(scope)?;
        let initial = self.execution_namespace_snapshot(scope.required)?;
        let members = self.resolve_execution_members(scope)?;
        let entries = members
            .iter()
            .map(|id| self.entry(id))
            .collect::<Result<Vec<_>, _>>()?;
        let locks = entries.iter().map(|e| e.lock.clone()).collect::<Vec<_>>();
        let _turns =
            tokio::time::timeout(Duration::from_secs(10), scoped_exec::local_turns(&locks))
                .await
                .map_err(|_| MError::Conflict("execution resources remain busy".into()))?;
        let ledger = journal.lock().await;
        self.scoped_journal(&ledger)?;
        let again = self.resolve_execution_members(scope)?;
        if again != members {
            return Err(MError::Conflict(
                "execution resource closure changed".into(),
            ));
        }
        let mut resources = Vec::new();
        for entry in &entries {
            resources.push(self.scoped_target(entry, ledger.instance())?);
        }
        for seed in scope.required {
            if !resources.contains(seed) {
                return Err(MError::Conflict("installed execution seed changed".into()));
            }
        }
        let final_snapshot = self.execution_namespace_snapshot(&resources)?;
        if final_snapshot != initial {
            return Err(MError::Conflict(
                "execution namespace generation changed".into(),
            ));
        }
        let revision =
            execution_mutations::execution_resource_revision(&resources, &initial)?.to_string();
        Ok(ResourceSet {
            revision,
            resources,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, ip: &str, policy: Option<nft::Policy>) -> Candidate {
        Candidate {
            id: id.into(),
            namespace: "team".into(),
            ip: ip.into(),
            policy,
            eligible: true,
            gateway: false,
            requested_via: None,
        }
    }
    fn via(id: &str, ip: &str, to: &Candidate, siblings: bool) -> Candidate {
        node(
            id,
            ip,
            Some(nft::Policy::Via {
                ip: ip.into(),
                to: to.ip.clone(),
                to_tap: netw::tap_name(&to.id),
                host: "10.64.0.1".into(),
                siblings,
            }),
        )
    }
    fn reach(nodes: &[Candidate], seed: &str) -> BTreeSet<String> {
        closure(nodes, &BTreeSet::from([seed.into()])).unwrap()
    }
    #[test]
    fn private_edges_require_both_installed_policies() {
        let b = node("b", "10.64.0.3", None);
        let c = node("c", "10.64.0.4", None);
        let a = via("a", "10.64.0.2", &b, false);
        assert_eq!(reach(&[a.clone(), b.clone(), c.clone()], "a").len(), 3);
        let strict_b = via("b", "10.64.0.3", &c, false);
        assert_eq!(
            reach(&[a.clone(), strict_b, c], "a"),
            BTreeSet::from(["a".into()])
        );
        let sibling_b = via("b", "10.64.0.3", &a, true);
        assert!(permits(&sibling_b, &a));
        assert!(permits(
            &node(
                "none",
                "10.64.0.8",
                Some(nft::Policy::None {
                    ip: "10.64.0.8".into()
                })
            ),
            &a
        ));
    }
    #[test]
    fn closure_is_transitive_and_bounded_with_native_ids() {
        let gateway = node("native-gateway", "10.64.0.2", None);
        let a = via("a", "10.64.0.3", &gateway, false);
        let b = via("b", "10.64.0.4", &gateway, false);
        assert_eq!(reach(&[a, gateway, b], "a").len(), 3);
        let nodes = (0..64)
            .map(|n| node(&format!("native-{n}"), &format!("10.64.0.{}", n + 2), None))
            .collect::<Vec<_>>();
        assert_eq!(reach(&nodes, "native-0").len(), 64);
        let mut too_many = nodes;
        too_many.push(node("native-64", "10.64.0.66", None));
        assert!(closure(&too_many, &BTreeSet::from(["native-0".into()])).is_err());
    }
    #[tokio::test]
    async fn uncertain_local_records_refuse_before_kernel_identity() {
        let h = crate::machine::tests::harness("10.64.0.0/22", 4096).await;
        let mut record = crate::machine::tests::record();
        let id = record.id.clone();
        record.state = state::RUNNING.into();
        let entry = Entry::new(record, h.m.inner.events.clone());
        h.m.inner
            .machines
            .lock()
            .unwrap()
            .insert(id.clone(), entry.clone());
        let names = BTreeSet::from(["t1".into()]);
        assert!(matches!(
            h.m.execution_candidates(&names),
            Err(MError::Conflict(_))
        ));
        entry.rec.lock().unwrap().state = state::STOPPED.into();
        assert!(h.m.execution_candidates(&names).is_ok());
        entry.launch_unproven.store(true, Relaxed);
        assert!(matches!(
            h.m.execution_candidates(&names),
            Err(MError::Conflict(_))
        ));
        entry.launch_unproven.store(false, Relaxed);
        *entry.removed.lock().unwrap() = true;
        entry.rec.lock().unwrap().state = state::RUNNING.into();
        assert!(matches!(
            h.m.execution_candidates(&names),
            Err(MError::Conflict(_))
        ));
    }
    #[tokio::test]
    async fn running_builder_metadata_does_not_prove_quarantine() {
        let h = crate::machine::tests::harness("10.64.0.0/22", 4096).await;
        let mut record = crate::machine::tests::record();
        record.state = state::RUNNING.into();
        record.template_birth = Some(templates::TemplateBirth {
            schema: 1,
            profile: "test".into(),
            namespace: record.namespace.clone(),
            image: record.image.clone(),
            init_sha256: "test".into(),
        });
        let entry = Entry::new(record.clone(), h.m.inner.events.clone());
        let (_, exited) = tokio::sync::watch::channel(false);
        let (_, exit) = tokio::sync::watch::channel(None);
        *entry.live.lock().unwrap() = Some(fc::Vm {
            #[cfg(target_os = "linux")]
            identity: None,
            pid: 1,
            api: PathBuf::new(),
            vsock: PathBuf::new(),
            dir: PathBuf::new(),
            chroot: None,
            resumed: false,
            boot_identity: None,
            incarnation: None,
            exited,
            exit,
            vmm_oom: fc::VmmOom::default(),
        });
        h.m.inner.machines.lock().unwrap().insert(record.id, entry);
        assert!(matches!(
            h.m.execution_candidates(&BTreeSet::from(["t1".into()])),
            Err(MError::Conflict(_))
        ));
    }
    #[tokio::test]
    async fn installed_scope_accepts_distinct_local_seed_namespaces() {
        let h = crate::machine::tests::harness("10.64.0.0/22", 4096).await;
        let mut first = crate::machine::tests::record();
        first.id = "first".into();
        let mut second = first.clone();
        second.id = "second".into();
        second.namespace = "t2".into();
        for r in [first, second] {
            h.m.inner
                .machines
                .lock()
                .unwrap()
                .insert(r.id.clone(), Entry::new(r, h.m.inner.events.clone()));
        }
        let a = Target {
            host: h.m.inner.host_id.clone(),
            machine: "first".into(),
            namespace: "t1".into(),
            run: "r1".into(),
            placement: "p1".into(),
        };
        let b = Target {
            host: h.m.inner.host_id.clone(),
            machine: "second".into(),
            namespace: "t2".into(),
            run: "r2".into(),
            placement: "p2".into(),
        };
        let required = [a.clone(), b];
        assert_eq!(
            h.m.validate_execution_scope(ExecutionResourceScope {
                primary: &a,
                required: &required
            })
            .unwrap()
            .len(),
            2
        );
    }

    #[tokio::test]
    async fn retained_launch_hold_requires_exact_record_identity_and_live_proof() {
        let (h, entry, request) = assignments::tests::fixture_with(None).await;
        let digest = templates::sandbox::request_digest(&request).unwrap();
        h.m.stage_destination_assignment(request, &entry, 2)
            .await
            .unwrap();
        h.m.start_destination_assignment("destination", "assignment-one", &digest)
            .await
            .unwrap();
        let names = BTreeSet::from(["destination".into()]);
        let original = entry.snapshot();
        let hold = original.launch_identity.clone().unwrap();
        h.m.validate_launch_record(&original).unwrap();
        assert!(h
            .m
            .assignment_publication_allowed(&original, entry.identity_trusted.load(Relaxed)));
        assert!(h.m.execution_candidates(&names).is_ok());

        entry.rec.lock().unwrap().launch_identity = None;
        assert!(h
            .m
            .execution_candidates(&names)
            .err()
            .unwrap()
            .to_string()
            .contains("launch hold"));
        let mut different = hold.clone();
        different.host_num += 1;
        entry.rec.lock().unwrap().launch_identity = Some(different);
        assert!(h
            .m
            .execution_candidates(&names)
            .err()
            .unwrap()
            .to_string()
            .contains("launch hold"));

        entry.rec.lock().unwrap().launch_identity = Some(hold);
        assert!(h.m.execution_candidates(&names).is_ok());
        // Keep the valid configuration, provenance, held allocation and publication.
        // Only the represented live process now disagrees with that durable identity.
        let original_pid = entry.live.lock().unwrap().as_ref().unwrap().pid;
        entry.live.lock().unwrap().as_mut().unwrap().pid += 1;
        h.m.validate_launch_record(&entry.snapshot()).unwrap();
        assert!(h.m.assignment_publication_allowed(
            &entry.snapshot(),
            entry.identity_trusted.load(Relaxed)
        ));
        assert!(h
            .m
            .execution_candidates(&names)
            .err()
            .unwrap()
            .to_string()
            .contains("process unconfirmed"));
        entry.live.lock().unwrap().as_mut().unwrap().pid = original_pid;
        assert!(h.m.execution_candidates(&names).is_ok());
    }
}
