//! The hosts: registration, drain, retire, forget, keys, and the poll of static ones.

use super::*;

/// Prometheus text: hosts by state, each region's room and the creates refused for want of
/// it (ADR 0042).
pub(super) async fn metrics(State(st): S) -> Response {
    let text = {
        let reg = st.reg.lock().unwrap();
        signals::render(&reg, &signals::regions(&reg, &st.policy, &st.refusals))
    };
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        text,
    )
        .into_response()
}

pub(super) async fn status(State(st): S) -> Json<serde_json::Value> {
    let reg = st.reg.lock().unwrap();
    let mut cap = api::Capacity::default();
    let mut used = api::Capacity::default();
    let (mut machines, mut ready) = (0, 0);
    for h in reg.hosts.values() {
        if h.state == "ready" {
            ready += 1;
            cap.memory_mb += h.capacity.memory_mb;
            cap.vcpus += h.capacity.vcpus;
            used.memory_mb += h.used.memory_mb;
            used.vcpus += h.used.vcpus;
            machines += h.machines;
        }
    }
    // The daemon's Status, plus what only a fleet knows.
    Json(serde_json::json!({
        "version": api::VERSION, "host_id": "fleet",
        "capacity": cap, "used": used, "machines": machines, "running": machines,
        "hosts": reg.hosts.len(), "ready": ready, "namespaces": reg.namespaces.len(),
        "regions": signals::regions(&reg, &st.policy, &st.refusals),
    }))
}

pub(super) async fn list_hosts(State(st): S) -> Json<Vec<api::Host>> {
    let reg = st.reg.lock().unwrap();
    let mut hosts: Vec<api::Host> = reg.hosts.values().map(|h| h.to_api()).collect();
    hosts.sort_by(|a, b| a.id.cmp(&b.id));
    Json(hosts)
}

/// Who made a host's call, as the fleet sees it, and whether that is known.
/// - The fleet terminates the connection (its own TLS, or plain on loopback): the peer.
/// - `tls: off` on a loopback listener: a proxy of ours in front, by construction (nothing
///   else reaches a loopback port), so the last `X-Forwarded-For` value, which the proxy
///   writes; a call without one is from an unknown address.
/// - `tls: off` on any other address: whatever is in front, unknown: the token alone.
#[derive(Clone, Copy, Debug)]
pub(super) struct Caller {
    pub(super) peer: Option<std::net::IpAddr>,
    pub(super) checked: bool,
}

impl Caller {
    pub(super) fn of(
        st: &AppState,
        info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
        headers: &HeaderMap,
    ) -> Caller {
        let connection = info.map(|i| i.0.ip().to_canonical());
        if !matches!(st.cfg.tls, config::Tls::Off) {
            return Caller {
                peer: connection,
                checked: true,
            };
        }
        let loopback = st
            .cfg
            .listen
            .parse::<std::net::SocketAddr>()
            .is_ok_and(|a| a.ip().is_loopback());
        if !loopback {
            return Caller {
                peer: connection,
                checked: false,
            };
        }
        let forwarded = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .last()
            .and_then(|v| {
                v.trim()
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<std::net::IpAddr>()
                    .ok()
            })
            .map(|ip| ip.to_canonical());
        Caller {
            peer: forwarded,
            checked: true,
        }
    }
}

/// The record a host's own call belongs to: the one host at the address it advertises, when
/// the call presents that host's token and, where the fleet terminates the connection, comes
/// from that address (ADR 0026: a token on a disk that left our hands is not enough). Nothing
/// else passes, so no host can speak for another. `call` names the call for the log.
pub(super) fn the_host<'a>(
    reg: &'a Registry,
    url: &str,
    headers: &HeaderMap,
    caller: Caller,
    call: &str,
) -> Result<&'a HostRec, Refusal> {
    let Some(rec) = reg.expecting(url) else {
        tracing::warn!(
            call,
            url,
            "host call refused: no host expected at this address"
        );
        return Err(err(
            StatusCode::FORBIDDEN,
            "unknown_host",
            format!(
                "no host is expected at {}: add it with `briqyard host add`, or list it under hosts: with its token",
                url_host(url)
            ),
        ));
    };
    if rec.token.is_empty() || !api::constant_eq(bearer(headers).as_bytes(), rec.token.as_bytes()) {
        tracing::warn!(
            host = rec.id,
            call,
            "host call refused: not the host's token"
        );
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "the host's own token is required",
        ));
    }
    if caller.checked {
        let want = url_host(&rec.url)
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| ip.to_canonical());
        if want.is_none() || want != caller.peer {
            let peer = caller.peer.map(|p| p.to_string()).unwrap_or_default();
            tracing::warn!(
                host = rec.id,
                call,
                peer,
                "host call refused: not from the host's address"
            );
            return Err(err(
                StatusCode::FORBIDDEN,
                "unknown_host",
                match want {
                    None => format!(
                        "host {} is known by the name in {}: the fleet checks a host's calls by its address, so its url must be one",
                        rec.id, rec.url
                    ),
                    Some(want) => format!(
                        "host {}'s calls come from {want}, not {}",
                        rec.id,
                        if peer.is_empty() { "an unknown address" } else { &peer }
                    ),
                },
            ));
        }
    }
    Ok(rec)
}

/// A host's pool key (ADR 0026), for the host alone: asked by its bootstrap to create the
/// pool, and by its daemon at a start that finds the key not loaded. Made at the first ask
/// and written to the registry before it is answered.
pub(super) async fn host_key(
    State(st): S,
    info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<api::HostKeyRequest>,
) -> Result<Response, Refusal> {
    let caller = Caller::of(&st, info, &headers);
    // A backup's key is only read: it never waits behind a key being made.
    if let Some(want) = &req.key_id {
        return backup_key(&st, &req, &headers, caller, want);
    }
    let _turn = st.key_turn.lock().await;
    let (id, key, made) = {
        let mut reg = st.reg.lock().unwrap();
        let id = the_host(&reg, &req.url, &headers, caller, "pool key")?
            .id
            .clone();
        let (key, made) = reg.pool_key(&id).expect("the record was just found");
        (id, key, made)
    };
    if made {
        if let Err(e) = st.save().await {
            // Never served, never kept: the next ask makes one again.
            if let Some(h) = st.reg.lock().unwrap().hosts.get_mut(&id) {
                h.pool_key = Default::default();
            }
            return Err(registry_error(e));
        }
    }
    // A key in use is in the backup: written now when the store does not hold it yet.
    if let Some(b) = &st.backup {
        if !b.holds(&id, &key).await {
            if let Err(e) = b.push(&st.reg).await {
                tracing::error!(
                    host = id,
                    err = format!("{e:#}"),
                    "registry backup before a pool key"
                );
                return Err(err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "backup",
                    "the registry's backup could not be written, and no key is handed out before it is: the fleet's log says why",
                ));
            }
        }
    }
    let peer = caller.peer.map(|p| p.to_string()).unwrap_or_default();
    tracing::info!(host = id, made, peer, "pool key served");
    Ok(Json(api::HostKey {
        key: key.expose().to_string(),
    })
    .into_response())
}

/// The pool key of a backup (ADR 0035): the host's own at any ask, as `host_key` serves it
/// (ADR 0045); another's, a live host's or a forgotten one's, for the host the fleet forwarded
/// a restore to, once per restore. A raw stream opens only with the pool key of the host that
/// sent it, so that is what is served. Never made here; another host's key is a `warn` line.
pub(super) fn backup_key(
    st: &AppState,
    req: &api::HostKeyRequest,
    headers: &HeaderMap,
    caller: Caller,
    key_id: &str,
) -> Result<Response, Refusal> {
    let reg = st.reg.lock().unwrap();
    let host = the_host(&reg, &req.url, headers, caller, "backup key")?
        .id
        .clone();
    let Some((owner, key)) = reg.key_by_id(key_id) else {
        return Err(err(
            StatusCode::NOT_FOUND,
            "no_key",
            format!("the fleet holds no pool key {key_id}: the backup was made on a host with a key file, or on a host forgotten before ADR 0035"),
        ));
    };
    // The last check: a refusal above leaves the restore's ask to it, and so does the host's
    // own key.
    let open = owner == host
        || req
            .restore
            .as_ref()
            .is_some_and(|rs| st.restores.take(&host, rs, std::time::Instant::now()));
    if !open {
        let what = req
            .restore
            .as_ref()
            .map(|rs| format!("{}/{}", rs.machine_id, rs.backup))
            .unwrap_or_else(|| "none named".into());
        tracing::warn!(
            host,
            key_id,
            restore = what,
            "backup key refused: no restore open"
        );
        return Err(err(
            StatusCode::FORBIDDEN,
            "no_restore",
            format!("a backup's key is served once, for a restore the fleet forwarded to this host: none open for {host} ({what})"),
        ));
    }
    let peer = caller.peer.map(|p| p.to_string()).unwrap_or_default();
    // Its own key is routine; another host's is the hand-out worth a look.
    if owner == host {
        tracing::info!(host, owner, key_id, peer, "backup key served");
    } else {
        tracing::warn!(host, owner, key_id, peer, "backup key served");
    }
    Ok(Json(api::HostKey {
        key: key.expose().to_string(),
    })
    .into_response())
}

/// A daemon's heartbeat. It is taken for the one host record at its address, when it presents
/// that host's token: the one the bootstrap gave an added host, or the one `hosts:` lists.
/// Nothing else may register, so no host can speak for another.
pub(super) async fn register_host(
    State(st): S,
    info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<api::RegisterHostRequest>,
) -> Result<Response, Refusal> {
    let now = Utc::now();
    let caller = Caller::of(&st, info, &headers);
    {
        let mut reg = st.reg.lock().unwrap();
        let call = format!("heartbeat of {}", req.id);
        let rec = the_host(&reg, &req.url, &headers, caller, &call)?;
        // A host that joined has no certificate pinned yet (ADR 0057): its first heartbeat, made
        // with its own token from its own address over the fleet's channel, pins the one it
        // reports. Every other host's pin comes from the bootstrap or the operator.
        let joining = rec.state == "joining" && rec.tls_fingerprint.is_empty();
        let pin = if joining {
            &req.tls_fingerprint
        } else {
            &rec.tls_fingerprint
        };
        if let Err(why) = registry::tls_matches(pin, &req.tls_fingerprint, &req.url) {
            tracing::warn!(
                host = rec.id,
                daemon = req.id,
                url = req.url,
                reported = req.tls_fingerprint,
                pinned = rec.tls_fingerprint,
                "registration refused: not the pinned certificate"
            );
            return Err(err(StatusCode::FORBIDDEN, "tls_mismatch", why));
        }
        let id = rec.id.clone();
        if joining {
            // Trust on first use, made auditable: the operator compares this with
            // `briqyardd tls-fingerprint` on the server.
            tracing::warn!(
                host = id,
                peer = caller.peer.map(|p| p.to_string()).unwrap_or_default(),
                fingerprint = req.tls_fingerprint,
                "certificate pinned at the host's first heartbeat"
            );
        }
        let pinned_note = joining.then(|| {
            format!(
                "{}; api certificate {} pinned at its first heartbeat ({})",
                rec.note,
                req.tls_fingerprint,
                now.to_rfc3339()
            )
        });
        // What the host reports, applied to its record: the id, token, pin, provider fields
        // and state are the record's own (`heartbeat` leaves them).
        reg.heartbeat(
            HostRec {
                id: id.clone(),
                url: req.url,
                ssh: String::new(),
                token: String::new(),
                tls_fingerprint: if joining {
                    req.tls_fingerprint.clone()
                } else {
                    String::new()
                },
                region: req.region,
                provider: String::new(),
                state: String::new(),
                capacity: req.capacity,
                used: req.used,
                machines: req.machines,
                namespaces: req.namespaces,
                last_seen: now,
                version: req.version,
                disk_free_mb: req.disk_free_mb,
                note: String::new(),
                bootstrap_attempts: 0,
                public_tcp_ports: None,
                conditions: req.conditions,
                started: req.started,
                pool_key: Default::default(),
                labels: Default::default(),
                unknown: Default::default(),
                holds: Vec::new(),
            },
            now,
        );
        if let Some(note) = pinned_note {
            if let Some(h) = reg.hosts.get_mut(&id) {
                h.note = note;
            }
        }
    }
    st.save().await.map_err(registry_error)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Places nothing new on a host (Kubernetes's cordon); its machines go on.
pub(super) async fn drain_host(State(st): S, Path(id): Path<String>) -> Result<Response, Refusal> {
    set_host_state(&st, &id, "draining", |_| true).await
}

/// Undoes a drain or a retire: the host takes new namespaces again.
pub(super) async fn undrain_host(
    State(st): S,
    Path(id): Path<String>,
) -> Result<Response, Refusal> {
    set_host_state(&st, &id, "ready", |s| matches!(s, "draining" | "retiring")).await
}

/// Moves a host from a state `from` accepts to `to`; 409 from any other (an upgrade under way
/// owns its host's state, ADR 0027).
pub(super) async fn set_host_state(
    st: &AppState,
    id: &str,
    to: &str,
    from: impl Fn(&str) -> bool,
) -> Result<Response, Refusal> {
    {
        let mut reg = st.reg.lock().unwrap();
        match reg.hosts.get_mut(id) {
            Some(h) if h.state == "upgrading" || !from(&h.state) => {
                return Err(err(
                    StatusCode::CONFLICT,
                    "conflict",
                    format!("host {id} is {}", h.state),
                ))
            }
            Some(h) => h.state = to.into(),
            None => return Err(err(StatusCode::NOT_FOUND, "not_found", "host not found")),
        }
    }
    st.save().await.map_err(registry_error)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Adds a server (Kubernetes's `kubeadm join`): recorded `provisioning` with a fresh token and
/// nothing pinned, then installed by the bootstrap, which pins its SSH key and certificate (ADR
/// 0028). Its API may be on the private network while SSH reaches its public address.
pub(super) async fn add_host(
    State(st): S,
    Json(req): Json<api::AddHostRequest>,
) -> Result<Response, Refusal> {
    let h = new_added_host(&st.cfg.bootstrap, req, Utc::now())?;
    {
        let mut reg = st.reg.lock().unwrap();
        if let Some(other) = reg.hosts.values().find(|o| {
            o.id == h.id
                || (!o.url.is_empty() && url_host(&o.url) == url_host(&h.url))
                || (!h.ssh.is_empty() && o.ssh == h.ssh)
        }) {
            return Err(err(
                StatusCode::CONFLICT,
                "conflict",
                format!("host {} is already at {}", other.id, url_host(&other.url)),
            ));
        }
        reg.hosts.insert(h.id.clone(), h.clone());
    }
    st.save().await.map_err(registry_error)?;
    tracing::warn!(
        host = h.id,
        ssh = h.ssh,
        url = h.url,
        "host added; bootstrapped within two minutes"
    );
    Ok((StatusCode::ACCEPTED, Json(h.to_api())).into_response())
}

/// The id a host is given: the one asked for, else `h_` and its address.
pub(super) fn host_id(asked: String, ip: std::net::Ipv4Addr) -> Result<String, Refusal> {
    let id = if asked.is_empty() {
        format!("h_{}", ip.to_string().replace(['.', ':'], "-"))
    } else {
        asked
    };
    if !api::valid_id(&id) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid",
            format!("id {id:?}: a-z, 0-9, _ and -"),
        ));
    }
    Ok(id)
}

/// The record of a server added by hand, or why the request is refused.
pub(super) fn new_added_host(
    b: &config::Bootstrap,
    req: api::AddHostRequest,
    now: chrono::DateTime<Utc>,
) -> Result<HostRec, Refusal> {
    let invalid = |m: String| err(StatusCode::BAD_REQUEST, "invalid", m);
    if !b.enabled {
        return Err(err(
            StatusCode::CONFLICT,
            "bootstrap_off",
            "bootstrap.enabled is false: the fleet installs no host",
        ));
    }
    let ssh_ok = !req.ssh.is_empty()
        && !req.ssh.starts_with('-')
        && req
            .ssh
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-'));
    if !ssh_ok {
        return Err(invalid(format!(
            "ssh {:?}: want the server's address or name",
            req.ssh
        )));
    }
    let address = if req.address.is_empty() {
        req.ssh.clone()
    } else {
        req.address.clone()
    };
    let ip: std::net::Ipv4Addr = address.parse().map_err(|_| {
        invalid(format!(
            "address {address:?}: want the API's IPv4 address (its private one when it has one)"
        ))
    })?;
    let url = bootstrap::host_url(&ip.to_string());
    if address != req.ssh && bootstrap::private_address(b, &url).is_none() {
        return Err(invalid(format!(
            "address {address} is not in bootstrap.private_network ({:?}): an API apart from the SSH address lives on the private network",
            b.private_network
        )));
    }
    let id = host_id(req.id, ip)?;
    let public_tcp_ports = Some(
        req.public_tcp_ports
            .unwrap_or_else(|| b.public_tcp_ports.clone()),
    );
    if public_tcp_ports.iter().flatten().any(|&p| p == 0) {
        return Err(invalid("public_tcp_ports: 0 is not a port".into()));
    }
    Ok(HostRec {
        id,
        url,
        ssh: if address == req.ssh {
            String::new()
        } else {
            req.ssh
        },
        token: bootstrap::new_token(),
        tls_fingerprint: String::new(),
        region: req.region,
        provider: "manual".into(),
        state: "provisioning".into(),
        capacity: Default::default(),
        used: Default::default(),
        machines: 0,
        namespaces: vec![],
        last_seen: now,
        version: String::new(),
        disk_free_mb: 0,
        note: "added; waiting for the bootstrap".into(),
        bootstrap_attempts: 0,
        public_tcp_ports,
        conditions: vec![],
        started: Default::default(),
        pool_key: Default::default(),
        labels: Default::default(),
        unknown: Default::default(),
        holds: Vec::new(),
    })
}

/// Takes nothing new on a host and forgets it once nothing runs on it: at once when it is
/// already empty, else from `forget_retired` as soon as it is. The server is the operator's to
/// give back (ADR 0042).
pub(super) async fn retire_host(State(st): S, Path(id): Path<String>) -> Result<Response, Refusal> {
    let host = {
        let mut reg = st.reg.lock().unwrap();
        match reg.hosts.get_mut(&id) {
            Some(h) if h.state == "upgrading" => {
                return Err(err(
                    StatusCode::CONFLICT,
                    "conflict",
                    format!("host {id} is upgrading"),
                ))
            }
            Some(h) => {
                if matches!(h.state.as_str(), "ready" | "draining" | "down") {
                    h.state = "retiring".into();
                }
                h.clone()
            }
            None => return Err(err(StatusCode::NOT_FOUND, "not_found", "host not found")),
        }
    };
    let empty = host.machines == 0 && host.namespaces.is_empty();
    if empty || host.state != "retiring" {
        return Ok(Json(retired(&st, &host).await.map_err(registry_error)?).into_response());
    }
    st.save().await.map_err(registry_error)?;
    tracing::info!(
        host = id,
        machines = host.machines,
        "host retiring; forgotten once empty"
    );
    Ok(Json(host.to_api()).into_response())
}

/// Forgets a retired host: `retired` in the answer.
pub(super) async fn retired(st: &AppState, h: &HostRec) -> Result<api::Host> {
    tracing::warn!(host = h.id, "host retired");
    st.reg.lock().unwrap().forget(&h.id);
    st.save().await?;
    let mut out = h.to_api();
    out.state = "retired".into();
    Ok(out)
}

/// What a forget of a host that holds a pool key costs, said by its refusal and by `force`.
pub(super) const FORGET_KEYED: &str =
    "its pool key leaves the record and is kept only for its backups: the pool is unreadable at the host's next restart; retire it, or --force";

#[derive(serde::Deserialize, Default)]
pub(super) struct ForgetQuery {
    #[serde(default)]
    pub(super) force: bool,
}

/// Forgets a host. One whose record holds a pool key is refused unless `force`: the key goes
/// with the record (ADR 0026), and a static host polled back gets a new one its pool does not
/// open. Retiring a host forgets it once empty, on purpose.
pub(super) async fn forget_host(
    State(st): S,
    Path(id): Path<String>,
    Query(q): Query<ForgetQuery>,
) -> Result<Response, Refusal> {
    {
        let mut reg = st.reg.lock().unwrap();
        let keyed = reg.hosts.get(&id).is_some_and(|h| !h.pool_key.is_empty());
        if keyed && !q.force {
            return Err(err(
                StatusCode::CONFLICT,
                "pool_key",
                format!("host {id}: {FORGET_KEYED}"),
            ));
        }
        if keyed {
            tracing::warn!(
                host = id,
                "host forgotten with its pool key: {FORGET_KEYED}"
            );
        }
        reg.forget(&id);
    }
    st.save().await.map_err(registry_error)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(super) async fn get_json<T: serde::de::DeserializeOwned>(
    st: &AppState,
    h: &HostRec,
    path: &str,
) -> Option<T> {
    let mut r = st
        .client(h)
        .ok()?
        .get(format!("{}{}", h.url.trim_end_matches('/'), path))
        .timeout(FORWARD_TIMEOUT);
    if !h.token.is_empty() {
        r = r.bearer_auth(&h.token);
    }
    r.send().await.ok()?.json::<T>().await.ok()
}

/// Static hosts send no heartbeat of their own; the fleet asks them.
pub(super) async fn poll_static_hosts(st: Arc<AppState>) {
    loop {
        let unseen = poll_static_hosts_once(&st).await;
        tokio::time::sleep(std::time::Duration::from_secs(if unseen { 2 } else { 15 })).await;
    }
}

/// One round of the poll: every static host of the configuration is asked for its status and
/// namespaces, then silent hosts are marked down. True when a host has never answered yet.
pub(super) async fn poll_static_hosts_once(st: &AppState) -> bool {
    // From the configuration, not the registry: a static host forgotten through the API
    // is back on the next poll; it leaves the fleet by leaving the configuration.
    let now = Utc::now();
    let hosts: Vec<HostRec> = st.cfg.hosts.iter().map(|h| static_host(h, now)).collect();
    let mut unseen = false;
    for h in hosts {
        if let Some(s) = get_json::<api::Status>(st, &h, "/v1/status").await {
            // The deprecated path, which every daemon serves (ADR 0055): a host not yet upgraded
            // has no /v1/namespaces. A host that does not answer keeps the namespaces it had,
            // since a heartbeat's list is the truth and an empty one would drop their pins.
            let namespaces: Vec<String> =
                match get_json::<Vec<api::Namespace>>(st, &h, "/v1/tenants").await {
                    Some(list) => list.into_iter().map(|t| t.id).collect(),
                    None => {
                        let reg = st.reg.lock().unwrap();
                        reg.hosts
                            .get(&h.id)
                            .map(|prev| prev.namespaces.clone())
                            .unwrap_or_default()
                    }
                };
            let now = Utc::now();
            let mut rec = h.clone();
            rec.capacity = s.capacity;
            rec.used = s.used;
            rec.machines = s.machines;
            rec.namespaces = namespaces;
            rec.version = s.version;
            rec.disk_free_mb = s.disk_free_mb;
            rec.conditions = s.conditions;
            rec.started = s.started;
            st.reg.lock().unwrap().heartbeat(rec, now);
        } else if h.capacity.memory_mb == 0 {
            // Never answered yet (it may be starting with us): ask again soon.
            unseen = true;
        }
    }
    st.reg.lock().unwrap().sweep(&st.policy, Utc::now());
    // A background task: a failed write is logged by `save`, and the next round writes again.
    let _ = st.save().await;
    unseen
}

/// Every minute: forgets the retiring hosts that have emptied.
pub(super) async fn forget_retired(st: Arc<AppState>) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        let retirable = st.reg.lock().unwrap().retirable();
        for h in retirable {
            // A failed write is logged by `save`; the next pass writes again.
            let _ = retired(&st, &h).await;
        }
    }
}
