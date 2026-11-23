//! The v3.6 grammar invariants of `native.inputs/v1` that field types cannot express: exact
//! formats, strict ordering and uniqueness, the single target row, regional floors, the
//! actor/closure key set, fixed role locators, byte bounds and the v3.3 closure rules. No fact
//! here comes from outside the bytes; nothing is compared with a Plan or an observation.

use super::*;
use crate::execution::sealed::canonical::CodecError;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const DAEMON_GUARD: &str = "/usr/local/bin/briqyardd";
const AUTHORITY_GUARD: &str = "/usr/local/bin/briqyard-fleet";
const DAEMON_CONTROL: &str = "/run/briqyard-sealed/daemon/control";
const AUTHORITY_CONTROL: &str = "/run/briqyard-sealed/authority/control";
/// 0600 and 0660 (companion): permission bits only.
const DAEMON_MODE: u64 = 0o600;
const AUTHORITY_MODE: u64 = 0o660;
const HOST_PORT: u16 = 7541;
const AUTHORITY_PORT: u16 = 7542;
/// No v2 endpoint on the ordinary routes (v3.1).
const ORDINARY_PORTS: [u16; 3] = [7441, 7442, 3003];
const MAX_ROOTS: usize = 8;
const MAX_ID: u64 = u32::MAX as u64;

fn refuse(what: &'static str) -> Result<(), CodecError> {
    Err(CodecError::Value(what))
}

fn actor_key(kind: ActorKind, id: &Ident) -> (&'static str, &str) {
    (kind.wire_name(), id.as_str())
}

/// Ordering is lexical by wire name, then ID, byte by byte; strict, so also unique.
fn strictly_ascending<'a, T, K: Ord>(rows: &'a [T], key: impl Fn(&'a T) -> K) -> bool {
    rows.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

/// `https://host:port` with an explicit nonzero port, no userinfo, path, query or fragment.
fn origin_port(text: &Text) -> Option<u16> {
    let authority = text.as_str().strip_prefix("https://")?;
    let (host, port) = authority.rsplit_once(':')?;
    let host_ok = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(v6) => {
            !v6.is_empty()
                && v6
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
        }
        None => {
            !host.is_empty()
                && host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        }
    };
    let port_ok =
        !port.is_empty() && !port.starts_with('0') && port.bytes().all(|b| b.is_ascii_digit());
    if !host_ok || !port_ok {
        return None;
    }
    port.parse().ok()
}

/// The callback is an exact HTTPS URL: no userinfo, query or fragment, and a host.
fn valid_continuation_url(text: &Text) -> bool {
    let Some(rest) = text.as_str().strip_prefix("https://") else {
        return false;
    };
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => authority,
    };
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && path
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"?#@\\".contains(&b))
}

impl Wire for Inputs {
    fn validate(&self) -> Result<(), CodecError> {
        if self.format != INPUTS_FORMAT || self.closure.format != CLOSURE_FORMAT {
            return refuse("format");
        }
        if self.x != self.closure.x {
            return refuse("closure scope");
        }
        self.validate_topology()?;
        self.validate_actors()?;
        let boot = &self.closure.support.boot_id;
        validate_resource(
            &self.daemon,
            Role {
                guard: DAEMON_GUARD,
                control: DAEMON_CONTROL,
                gid: Some(0),
                mode: DAEMON_MODE,
            },
            boot,
        )?;
        validate_resource(
            &self.authority,
            Role {
                guard: AUTHORITY_GUARD,
                control: AUTHORITY_CONTROL,
                gid: None,
                mode: AUTHORITY_MODE,
            },
            boot,
        )?;
        self.validate_closure()
    }
}

struct Role {
    guard: &'static str,
    control: &'static str,
    /// The control socket's group where the companion fixes it; the authority's is a
    /// deployment fact the policy supplies.
    gid: Option<u64>,
    mode: u64,
}

fn validate_resource(r: &Resource, role: Role, boot: &BootId) -> Result<(), CodecError> {
    if r.guard.file.path.as_str() != role.guard {
        return refuse("guard locator");
    }
    if r.candidate.file.path == r.guard.file.path {
        return refuse("candidate locator");
    }
    if r.guard.file.bytes.get() > EXECUTABLE_LIMIT
        || r.candidate.file.bytes.get() > EXECUTABLE_LIMIT
    {
        return refuse("executable byte bound");
    }
    if r.config.bytes.get() > SMALL_LIMIT
        || r.tls_cert.bytes.get() > SMALL_LIMIT
        || r.tls_key.bytes.get() > SMALL_LIMIT
    {
        return refuse("config or TLS byte bound");
    }
    if r.pre.boot != *boot || r.custodian.boot != *boot {
        return refuse("surviving boot");
    }
    let control = &r.control;
    if control.path.as_str() != role.control
        || control.uid.get() != 0
        || role.gid.is_some_and(|gid| control.gid.get() != gid)
        || control.gid.get() > MAX_ID
        || control.mode.get() != role.mode
    {
        return refuse("control socket");
    }
    let journal = &r.journal;
    if journal.uid.get() > MAX_ID || journal.gid.get() > MAX_ID || journal.mode.get() > 0o777 {
        return refuse("journal directory");
    }
    let listeners = &r.listeners;
    if listeners.count.get() > listeners.store_max.get() {
        return refuse("listener count above the store maximum");
    }
    if listeners.count.get() == 0 && listeners.names != HexDigest::of(b"") {
        return refuse("empty listener table digest");
    }
    Ok(())
}

impl Inputs {
    fn validate_topology(&self) -> Result<(), CodecError> {
        let topology = &self.topology;
        if topology.regions.is_empty() || !strictly_ascending(&topology.regions, |r| r.id.as_str())
        {
            return refuse("region order");
        }
        let mut registered = BTreeSet::new();
        let mut intrinsic = BTreeSet::new();
        let mut host_count = 0;
        let mut target_rows = 0;
        for region in &topology.regions {
            if region.hosts.is_empty()
                || !strictly_ascending(&region.hosts, |h| h.registered.as_str())
            {
                return refuse("host order");
            }
            for host in &region.hosts {
                host_count += 1;
                if !registered.insert(host.registered.as_str())
                    || !intrinsic.insert(host.intrinsic.as_str())
                {
                    return refuse("host alias");
                }
                if host.registered == self.registered && host.intrinsic == self.x.host {
                    target_rows += 1;
                }
            }
        }
        if target_rows != 1 {
            return refuse("target host row");
        }
        let order: BTreeSet<&str> = topology.order.iter().map(Ident::as_str).collect();
        if topology.order.len() != host_count || order != registered {
            return refuse("rollout order");
        }
        for region in &topology.regions {
            let serving = region
                .hosts
                .iter()
                .filter(|h| !(h.registered == self.registered && h.intrinsic == self.x.host))
                .count() as u64;
            if serving < region.minimum_accepting.get() {
                return refuse("regional serving floor");
            }
        }
        Ok(())
    }

    fn validate_actors(&self) -> Result<(), CodecError> {
        if !strictly_ascending(&self.actors, |a| actor_key(a.actor, &a.id)) {
            return refuse("actor order");
        }
        let actors: BTreeSet<_> = self
            .actors
            .iter()
            .map(|a| actor_key(a.actor, &a.id))
            .collect();
        let peers: BTreeSet<_> = self
            .closure
            .peers
            .iter()
            .map(|p| actor_key(p.actor, &p.id))
            .collect();
        if actors != peers {
            return refuse("actor and peer key sets");
        }
        for kind in ActorKind::ALL {
            if !self.actors.iter().any(|a| a.actor == kind) {
                return refuse("actor roster");
            }
        }
        for actor in &self.actors {
            let valid = match actor.actor {
                ActorKind::Host | ActorKind::Authority => actor.proc.is_none(),
                ActorKind::Installer | ActorKind::Gateway => actor.proc.is_some(),
                ActorKind::Api | ActorKind::Receiver => true,
            };
            if !valid {
                return refuse("actor process form");
            }
        }
        Ok(())
    }

    fn validate_closure(&self) -> Result<(), CodecError> {
        let closure = &self.closure;
        if closure.admin_host == closure.admin_fleet
            || closure.admin_host == closure.continuation.bearer
            || closure.admin_fleet == closure.continuation.bearer
        {
            return refuse("credential purposes");
        }
        let continuation = &closure.continuation;
        if !valid_continuation_url(&continuation.url) {
            return refuse("continuation url");
        }
        let roots = &continuation.roots;
        let digests: Vec<[u8; 32]> = roots
            .iter()
            .map(|root| Sha256::digest(root.as_bytes()).into())
            .collect();
        if roots.is_empty() || roots.len() > MAX_ROOTS || !strictly_ascending(&digests, |d| *d) {
            return refuse("continuation roots");
        }
        if !strictly_ascending(&closure.peers, |p| actor_key(p.actor, &p.id)) {
            return refuse("peer order");
        }
        let mut leaves = BTreeSet::new();
        let mut spkis = BTreeSet::new();
        let mut pins = closure.admin_tls.iter().collect::<Vec<_>>();
        for peer in &closure.peers {
            let port = origin_port(&peer.endpoint).ok_or(CodecError::Value("peer endpoint"))?;
            let valid_port = match peer.actor {
                ActorKind::Host => port == HOST_PORT,
                ActorKind::Authority => port == AUTHORITY_PORT,
                _ => port != HOST_PORT && port != AUTHORITY_PORT,
            };
            if !valid_port || ORDINARY_PORTS.contains(&port) {
                return refuse("peer endpoint port");
            }
            pins.push(&peer.server);
            pins.push(&peer.client);
        }
        for pair in pins {
            if !leaves.insert(pair.leaf.as_str()) || !spkis.insert(pair.spki.as_str()) {
                return refuse("shared TLS identity");
            }
        }
        Ok(())
    }
}
