//! A namespace's bridge and rules, and the egress policy of each machine.

use super::*;

impl Manager {
    // --- namespaces ---

    pub(super) async fn plumb_namespace(&self, t: &Namespace) -> Result<()> {
        self.inner.net.ensure_bridge(&t.subnet).await?;
        self.inner.dns.listen(t.subnet.gateway()).await?;
        Ok(())
    }

    pub(super) async fn ensure_namespace(&self, id: &str) -> Result<Namespace> {
        if let Some(t) = self.inner.namespaces.lock().unwrap().get(id) {
            return Ok(t.clone());
        }
        // One namespace is made at a time: two made together would read the same free subnet
        // index before either had taken it, and share a bridge.
        let _creating = self.inner.namespace_create.lock().await;
        if let Some(t) = self.inner.namespaces.lock().unwrap().get(id) {
            return Ok(t.clone());
        }
        let t = {
            let namespaces = self.inner.namespaces.lock().unwrap();
            let used: Vec<u32> = namespaces.values().map(|t| t.rec.subnet_index).collect();
            let idx = netw::first_free(used, 0, self.inner.range.count() - 1)
                .ok_or_else(|| anyhow!("no namespace subnet left"))?;
            Namespace::new(
                NamespaceRec {
                    id: id.to_string(),
                    subnet_index: idx,
                    created_at: Utc::now(),
                    quota: api::Quota::default(),
                },
                self.inner.range.subnet(idx)?,
            )
        };
        self.plumb_namespace(&t).await?;
        self.inner.store.put(crate::store::NAMESPACES, id, &t.rec)?;
        self.inner
            .namespaces
            .lock()
            .unwrap()
            .insert(id.to_string(), t.clone());
        Ok(t)
    }

    /// Installs the host's nftables tables, once at start.
    pub(super) async fn apply_rules(&self) -> Result<()> {
        self.rules()?.apply().await
    }

    /// The tables as the daemon starts. A running record may be adopted with its TAP, so it
    /// is pinned here with its egress policy, which `policies` and the resolver then hold;
    /// everything else pins and sets its policy as it goes. A `via` machine whose gateway
    /// machine is gone (destroyed while it ran, then the daemon crashed) gets no pin: nothing
    /// it sends leaves its TAP. Every machine's internet traffic is counted, from zero.
    pub(super) fn rules(&self) -> Result<Ruleset> {
        let cfg = &self.inner.cfg;
        let all: Vec<Record> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .map(|e| e.snapshot())
            .collect();
        let mut counted: Vec<String> = all.iter().map(|r| r.ip.clone()).collect();
        counted.sort();
        let running = all.into_iter().filter(|r| r.state == state::RUNNING);
        let mut pins = Vec::new();
        for r in running {
            let Ok(policy) = self.policy_for(&r) else {
                continue;
            };
            pins.push((netw::tap_name(&r.id), r.ip.clone()));
            if let Some((gateway, p)) = policy {
                self.hold_policy(&r.id, gateway, p);
            }
        }
        pins.sort();
        let mut policies: Vec<nft::Policy> = self
            .inner
            .policies
            .lock()
            .unwrap()
            .values()
            .map(|(_, p)| p.clone())
            .collect();
        policies.sort_by(|a, b| a.ip().cmp(b.ip()));
        Ok(Ruleset {
            egress: self.inner.egress.clone(),
            range: self.inner.range.to_string(),
            allowed_clients: cfg
                .ingress
                .allowed_clients
                .iter()
                .map(|c| netw::cidr(c))
                .collect::<Result<_>>()?,
            ports: netw::nft::daemon_ports(&cfg.listen, &cfg.ingress.http, &cfg.ingress.tcp_ports)?,
            host_ports: cfg.network.host_ports.clone(),
            pins,
            policies,
            counted,
        })
    }

    // --- egress (ADR 0015) ---

    /// An egress policy a machine of `namespace` may take: one of the modes, and for `via` a
    /// machine of the same namespace other than `me`, or the namespace's gateway.
    pub(super) fn check_egress(
        &self,
        e: &api::Egress,
        namespace: &str,
        me: &str,
    ) -> Result<(), MError> {
        e.check().map_err(invalid)?;
        if e.mode == api::egress::VIA {
            self.via_target(e, namespace, me)?;
        }
        Ok(())
    }

    /// The address of the machine a `via` policy names: fixed for that machine's life.
    fn via_target(&self, e: &api::Egress, namespace: &str, me: &str) -> Result<String, MError> {
        let id = if e.via_gateway() {
            self.gateway_of(namespace)
                .ok_or_else(|| no_gateway(namespace))?
                .snapshot()
                .id
        } else {
            e.via.clone().unwrap_or_default()
        };
        if id == me {
            return Err(invalid("egress.via names the machine itself"));
        }
        let target = self
            .inner
            .machines
            .lock()
            .unwrap()
            .get(&id)
            .map(|e| e.snapshot())
            .filter(|r| r.state != state::DESTROYING)
            .ok_or_else(|| invalid(format!("egress.via {id}: no such machine")))?;
        if target.namespace != namespace {
            return Err(invalid(format!(
                "egress.via {id}: a machine of another namespace"
            )));
        }
        Ok(target.ip)
    }

    /// The policy a record asks for, resolved against its namespace, with the namespace's gateway:
    /// `None` for open with nothing to limit. An open machine's limits are its own over the
    /// host's (ADR 0018); `via` and `none` never reach the NAT, so they carry none.
    pub(super) fn policy_for(&self, r: &Record) -> Result<Option<(Ipv4Addr, nft::Policy)>, MError> {
        let limits = self.inner.cfg.egress_limits.with(&r.limits);
        if r.egress.mode == api::egress::OPEN && limits.is_none() {
            return Ok(None);
        }
        let t = self
            .namespace_of(&r.namespace)
            .ok_or_else(|| anyhow!("namespace network is gone"))?;
        let gateway = t.subnet.gateway();
        let ip = r.ip.clone();
        let p = match r.egress.mode.as_str() {
            api::egress::OPEN => nft::Policy::Open { ip, limits },
            api::egress::VIA => nft::Policy::Via {
                ip,
                to: self.via_target(&r.egress, &r.namespace, &r.id)?,
                host: gateway.to_string(),
            },
            _ => nft::Policy::None { ip },
        };
        Ok(Some((gateway, p)))
    }

    /// Tells the resolver to answer a machine internal names only, or no longer, when its
    /// policy says so.
    fn internal_dns(&self, gateway: Ipv4Addr, p: &nft::Policy, on: bool) {
        if !p.internal_only() {
            return;
        }
        if let Ok(ip) = p.ip().parse() {
            self.inner.dns.internal_only(gateway, ip, on);
        }
    }

    /// Puts a machine's policy in the tables and the resolver, in place of what they held
    /// for it; open with no limits leaves nothing. The resolver keeps the machine in from
    /// before the tables do until after they stop.
    pub(super) async fn set_policy(
        &self,
        id: &str,
        policy: Option<(Ipv4Addr, nft::Policy)>,
    ) -> Result<()> {
        self.unset_policy(id).await?;
        let Some((gateway, p)) = policy else {
            return Ok(());
        };
        self.internal_dns(gateway, &p, true);
        if let Err(err) = self.inner.net.set_policy(&p).await {
            self.internal_dns(gateway, &p, false);
            return Err(err);
        }
        self.inner
            .policies
            .lock()
            .unwrap()
            .insert(id.into(), (gateway, p));
        Ok(())
    }

    /// Records a policy the tables hold already (rendered at start).
    fn hold_policy(&self, id: &str, gateway: Ipv4Addr, p: nft::Policy) {
        self.internal_dns(gateway, &p, true);
        self.inner
            .policies
            .lock()
            .unwrap()
            .insert(id.into(), (gateway, p));
    }

    /// Takes a machine's policy out of the tables, then out of the resolver. None held is
    /// success.
    pub(super) async fn unset_policy(&self, id: &str) -> Result<()> {
        let held = self.inner.policies.lock().unwrap().get(id).cloned();
        let Some((gateway, p)) = held else {
            return Ok(());
        };
        self.inner.net.unset_policy(&p).await?;
        self.internal_dns(gateway, &p, false);
        self.inner.policies.lock().unwrap().remove(id);
        Ok(())
    }

    /// Changes a running machine's policy. From one policy to another is one transaction,
    /// so there is no moment with neither, and a refusal leaves the old one; the resolver
    /// takes the machine in before the tables change and lets it go after.
    pub(super) async fn replace_policy(
        &self,
        id: &str,
        new: Option<(Ipv4Addr, nft::Policy)>,
    ) -> Result<()> {
        let held = self.inner.policies.lock().unwrap().get(id).cloned();
        match (held, new) {
            (Some((_, old)), Some((gateway, p))) => {
                if old != p {
                    let (taken, let_go) = (
                        p.internal_only() && !old.internal_only(),
                        old.internal_only() && !p.internal_only(),
                    );
                    if taken {
                        self.internal_dns(gateway, &p, true);
                    }
                    if let Err(err) = self.inner.net.swap_policy(&old, &p).await {
                        if taken {
                            self.internal_dns(gateway, &p, false);
                        }
                        return Err(err);
                    }
                    if let_go {
                        self.internal_dns(gateway, &old, false);
                    }
                }
                self.inner
                    .policies
                    .lock()
                    .unwrap()
                    .insert(id.into(), (gateway, p));
                Ok(())
            }
            (None, new) => self.set_policy(id, new).await,
            (Some(_), None) => self.unset_policy(id).await,
        }
    }

    /// Withdraws what a machine's TAP carries on the host: the TAP, its pin and its egress
    /// policy. A policy left behind is replaced by the next start, and gone with the tables
    /// the next daemon renders.
    pub(super) async fn unplug(&self, id: &str, ip: &str) {
        let _ = self.inner.net.delete_tap(id, ip).await;
        if let Err(err) = self.unset_policy(id).await {
            tracing::warn!(machine = id, err = %err, "egress policy left in the tables");
        }
    }

    /// Republishes a namespace's names on its gateway.
    pub(super) fn refresh_dns(&self, t: &Namespace) {
        let mut names: HashMap<String, Ipv4Addr> = HashMap::new();
        for e in self.inner.machines.lock().unwrap().values() {
            let r = e.rec.lock().unwrap();
            if r.namespace != t.rec.id {
                continue;
            }
            if let Ok(ip) = r.ip.parse::<Ipv4Addr>() {
                names.insert(r.hostname(), ip);
                names.insert(r.machine_host(), ip);
            }
        }
        self.inner.dns.set(t.subnet.gateway(), names);
    }
}
