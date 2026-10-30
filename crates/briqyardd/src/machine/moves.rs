//! Moving a machine into another namespace of this host (ADR 0056): a rename of its namespace
//! when it is alone in it and the target is new, else a restart on the target's network.

use super::*;

impl Manager {
    /// Puts the machine in `namespace`. Alone in its namespace and the target not existing: the
    /// namespace is renamed, nothing restarts and the address stays. Otherwise the machine
    /// takes a free address of the target (made when it does not exist yet), a running one
    /// stopped before and started again after it, its disks kept. The namespace it leaves stays
    /// until `delete_namespace`, as when its last machine is destroyed.
    pub async fn move_machine(
        &self,
        id: &str,
        namespace: &str,
        at: Option<u64>,
    ) -> Result<api::MoveResult, MError> {
        check_namespace_id(namespace)?;
        let _admission = self.inner.namespace_lifecycle.read().await;
        let e = self.own_entry(id)?;
        let first = e.snapshot();
        if first.namespace == namespace {
            return Ok(self.moved(&e, &first, false));
        }
        self.check_version(&e, at)?;
        self.check_movable(&first, namespace)?;
        if self.rename_namespace(&e, namespace).await? {
            return Ok(self.moved(&e, &first, false));
        }
        if first.snapshots.iter().any(|s| s.memory.is_some()) {
            return Err(MError::Conflict(
                "a snapshot with memory resumes on the old address: delete it first".into(),
            ));
        }
        let t = self.ensure_namespace(namespace).await?;
        // Checked before a running machine is stopped, so a refusal costs it nothing.
        let was_running = first.state == state::RUNNING;
        self.slot_in(
            &self.inner.machines.lock().unwrap(),
            &first,
            &t,
            was_running,
        )?;
        if was_running {
            self.stop_entry(&e, stop::USER, Duration::ZERO, false, at)
                .await?;
        }
        // Its turn and its lock once no stop is under way; a start that slipped in between is
        // the caller's to repeat.
        let _turns = e.lock_once_stopped(true).await;
        // A refusal from here to the new address leaves the machine as it was: a running one
        // runs again.
        let joined: Result<(String, String), MError> = async {
            let rec = e.snapshot();
            if !matches!(rec.state.as_str(), state::STOPPED | state::CREATED) {
                return Err(MError::BadState(rec.state));
            }
            self.check_movable(&rec, namespace)?;
            // Usage up to now belongs to the namespace it leaves.
            self.meter(std::slice::from_ref(&e), Utc::now()).await;
            let from = rec.namespace.clone();
            let (ip, left) = {
                let machines = self.inner.machines.lock().unwrap();
                let n = self.slot_in(&machines, &rec, &t, false)?;
                let ip = t.subnet.host(n)?.to_string();
                let mut r = e.rec.lock().unwrap();
                let left = std::mem::replace(&mut r.ip, ip.clone());
                r.namespace = namespace.into();
                r.subnet_index = t.rec.subnet_index;
                r.host_num = n;
                // A memory snapshot resumes with the old address: the next start is a boot.
                r.suspended = false;
                (ip, left)
            };
            // The counters follow the address. Refused, the machine is as it was.
            if let Err(err) = self.inner.net.count(&ip).await.context("usage counters") {
                let mut r = e.rec.lock().unwrap();
                r.namespace.clone_from(&from);
                r.subnet_index = rec.subnet_index;
                r.host_num = rec.host_num;
                r.ip = left;
                r.suspended = rec.suspended;
                return Err(err.into());
            }
            if let Err(err) = self.inner.net.uncount(&left).await {
                tracing::warn!(machine = rec.id, ip = left, err = %err, "usage counter of the old address left");
            }
            Ok((from, left))
        }
        .await;
        let (from, left) = match joined {
            Ok(j) => j,
            Err(refusal) => {
                if was_running && e.snapshot().state == state::STOPPED {
                    if let Err(err) = self.start_entry(&e, true).await {
                        tracing::warn!(machine = first.id, err = %err, "not started again after a refused move");
                    }
                }
                return Err(refusal);
            }
        };
        self.rehome_records(&e)?;
        self.after_move(&e, &from, &left, was_running);
        if let Some(old) = self.namespace_of(&from) {
            self.refresh_dns(&old);
        }
        self.refresh_dns(&t);
        if was_running {
            self.start_entry(&e, true).await?;
        }
        Ok(self.moved(&e, &first, was_running))
    }

    fn moved(&self, e: &Entry, was: &Record, restarted: bool) -> api::MoveResult {
        api::MoveResult {
            machine: self.view(e),
            from: was.namespace.clone(),
            previous_ip: was.ip.clone(),
            restarted,
        }
    }

    /// What no move survives: a machine that is not settled, a namespace's own or another's
    /// network that it would break.
    fn check_movable(&self, r: &Record, namespace: &str) -> Result<(), MError> {
        if !r.is_namespaces() {
            return Err(MError::Gateway(r.namespace.clone()));
        }
        match r.state.as_str() {
            state::CREATING | state::STARTING | state::STOPPING | state::DESTROYING => {
                return Err(MError::BadState(r.state.clone()))
            }
            state::ERROR if !r.has_disks() => return Err(made_never(r)),
            _ => {}
        }
        if r.restoring.is_some() {
            return Err(MError::Conflict(format!(
                "machine {} has a restore to finish: start it first",
                r.id
            )));
        }
        let through_it = self.inner.machines.lock().unwrap().values().find_map(|o| {
            let o = o.rec.lock().unwrap();
            (o.namespace == r.namespace && o.egress.via.as_deref() == Some(r.id.as_str()))
                .then(|| o.id.clone())
        });
        if let Some(other) = through_it {
            return Err(MError::Conflict(format!(
                "machine {other} sends its traffic through this machine: change its egress first"
            )));
        }
        self.check_egress(&r.egress, namespace, &r.id)
    }

    /// The address, name and quota the machine would have in `t`; the host number it takes.
    fn slot_in(
        &self,
        machines: &HashMap<String, Arc<Entry>>,
        r: &Record,
        t: &Namespace,
        starting: bool,
    ) -> Result<u8, MError> {
        let mut used = Vec::new();
        for o in machines.values() {
            let o = o.rec.lock().unwrap();
            if o.namespace != t.rec.id || o.id == r.id {
                continue;
            }
            if o.name == r.name && o.state != state::DESTROYING {
                drop(o);
                return Err(MError::Conflict(format!(
                    "namespace {} has a machine named {}",
                    t.rec.id, r.name
                )));
            }
            used.push(o.host_num as u32);
        }
        let held = namespace_use(machines, &t.rec.id);
        if let Some(x) = over_quota(&t.rec.id, &t.rec.quota, &held, &quota_need(r, starting)) {
            let ev = x.event(format!("move of {} refused: {x}", r.name));
            self.inner.events.emit(ev.namespace(&t.rec.id));
            return Err(MError::Quota(x.to_string()));
        }
        // An address a `via` policy of the tables names stays its gateway's (`add_machine`).
        for (_, p) in self.inner.policies.lock().unwrap().values() {
            if let nft::Policy::Via { to, .. } = p {
                if let Ok(to) = to.parse::<Ipv4Addr>() {
                    if to.octets()[..3] == t.subnet.network.octets()[..3] {
                        used.push(to.octets()[3] as u32);
                    }
                }
            }
        }
        let n = netw::first_free(used, 2, 254).ok_or_else(|| {
            MError::Capacity(format!("namespace {} has no address left", t.rec.id))
        })?;
        Ok(n as u8)
    }

    /// The rename: the machine is alone in its namespace and `namespace` does not exist. Done
    /// in one step under the machines' lock, so a create that read the old name fails
    /// (`add_machine`) rather than land in a namespace that is gone. False when it does not
    /// apply.
    async fn rename_namespace(&self, e: &Arc<Entry>, namespace: &str) -> Result<bool, MError> {
        let _creating = self.inner.namespace_create.lock().await;
        let _turns = e.lock_once_stopped(true).await;
        let r = e.snapshot();
        self.check_movable(&r, namespace)?;
        let from = r.namespace.clone();
        // Usage up to now belongs to the name it leaves.
        self.meter(std::slice::from_ref(e), Utc::now()).await;
        let renamed = {
            let machines = self.inner.machines.lock().unwrap();
            let alone = machines.values().all(|o| {
                let o = o.rec.lock().unwrap();
                o.namespace != from || o.id == r.id
            });
            let mut namespaces = self.inner.namespaces.lock().unwrap();
            match namespaces.get(&from).cloned() {
                Some(t) if alone && !namespaces.contains_key(namespace) => {
                    // Both names resolve at every instant of the swap.
                    let mut renamed = t;
                    renamed.rec.id = namespace.into();
                    namespaces.insert(namespace.into(), renamed.clone());
                    e.rec.lock().unwrap().namespace = namespace.into();
                    namespaces.remove(&from);
                    Some(renamed)
                }
                _ => None,
            }
        };
        let Some(t) = renamed else {
            return Ok(false);
        };
        // The new record first, the old one last: a crash between leaves both, and the next
        // start keeps the one a machine names (`drop_renamed_leftovers`).
        self.inner
            .store
            .put(crate::store::NAMESPACES, namespace, &t.rec)?;
        self.rehome_records(e)?;
        self.inner.store.delete(crate::store::NAMESPACES, &from)?;
        self.after_move(e, &from, &r.ip, false);
        Ok(true)
    }

    /// Writes the machine's record and its endpoints' under its new namespace.
    fn rehome_records(&self, e: &Entry) -> Result<()> {
        let r = e.snapshot();
        self.save(e)?;
        let mut endpoints = self.inner.endpoints.lock().unwrap();
        for ep in endpoints.values_mut().filter(|x| x.machine_id == r.id) {
            ep.namespace.clone_from(&r.namespace);
            self.inner.store.put("endpoints", &ep.id, ep)?;
        }
        Ok(())
    }

    /// The event, in the namespace it left and in the one it joined; the second is the
    /// machine's own and moves its version.
    fn after_move(&self, e: &Entry, from: &str, previous_ip: &str, restarted: bool) {
        let r = e.snapshot();
        let ev = Ev::normal(
            reason::MOVED,
            format!("moved from namespace {from} to {}", r.namespace),
        )
        .data(json!({
            "from": from, "to": r.namespace,
            "previous_ip": previous_ip, "ip": r.ip, "restarted": restarted,
        }));
        self.inner.events.emit(ev.clone().of(&r.id, from));
        e.note(ev);
        let _ = self.save(e);
        tracing::info!(
            machine = r.id,
            from,
            to = r.namespace,
            ip = r.ip,
            "machine moved"
        );
    }
}

impl Manager {
    /// A rename cut short leaves two namespace records on one subnet: the new one written, the
    /// old one not yet deleted. The one no machine names goes; with none named, the older stays.
    pub(super) fn drop_renamed_leftovers(&self) -> Result<()> {
        let named: std::collections::HashSet<String> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .map(|e| e.rec.lock().unwrap().namespace.clone())
            .collect();
        let mut by_subnet: BTreeMap<u32, Vec<NamespaceRec>> = BTreeMap::new();
        for t in self.inner.namespaces.lock().unwrap().values() {
            by_subnet
                .entry(t.rec.subnet_index)
                .or_default()
                .push(t.rec.clone());
        }
        for (_, mut same) in by_subnet.into_iter().filter(|(_, v)| v.len() > 1) {
            same.sort_by(|a, b| {
                (!named.contains(&a.id), a.created_at, &a.id).cmp(&(
                    !named.contains(&b.id),
                    b.created_at,
                    &b.id,
                ))
            });
            for gone in same.into_iter().skip(1) {
                tracing::warn!(
                    namespace = gone.id,
                    "namespace record of a rename cut short, sharing its subnet with another: removed"
                );
                self.inner.namespaces.lock().unwrap().remove(&gone.id);
                self.inner
                    .store
                    .delete(crate::store::NAMESPACES, &gone.id)?;
            }
        }
        Ok(())
    }
}
