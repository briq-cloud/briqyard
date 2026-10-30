//! Creating a machine: placement, the hold on a host and the refusals.

use super::*;

/// A create's hold on its host (ADR 0044) while the request lasts: `made` once the host made
/// the machine; dropped otherwise, the hold given back. A refusal, no answer and a caller that
/// hung up (its handler dropped mid-forward) all end here.
pub(super) struct Held<'a> {
    pub(super) st: &'a AppState,
    pub(super) host: String,
    pub(super) id: u64,
}

impl Held<'_> {
    pub(super) fn made(mut self) {
        self.st
            .reg
            .lock()
            .unwrap()
            .made(&self.host, self.id, Utc::now());
        // Ids start at 1: nothing left to release.
        self.id = 0;
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        if let Ok(mut reg) = self.st.reg.lock() {
            reg.release(&self.host, self.id);
        }
    }
}

pub(super) async fn create_machine(
    State(st): S,
    headers: HeaderMap,
    mut body: Bytes,
) -> Result<Response, Refusal> {
    let mut req: api::CreateMachineRequest = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, "invalid", format!("body: {e}")))?;
    if req.fork.is_some() && req.restore.is_some() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid",
            "fork and restore are one or the other",
        ));
    }
    if let (true, Some(rs)) = (req.size == api::Size::default(), req.restore.as_mut()) {
        let (size, backup) = restore_size(&st, rs).await?;
        req.size = size;
        rs.backup = backup.clone();
        // Preserve any fields the forwarding API does not interpret. Pin latest to the exact
        // record whose size was reserved, so a concurrent backup cannot change the budget.
        let mut document: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| err(StatusCode::BAD_REQUEST, "invalid", format!("body: {e}")))?;
        document["size"] = serde_json::to_value(size).expect("Size serializes");
        document["restore"]["backup"] = backup.into();
        body = Bytes::from(serde_json::to_vec(&document).expect("JSON serializes"));
    }
    req.size
        .check()
        .map_err(|why| err(StatusCode::BAD_REQUEST, "invalid", why))?;
    let ask = Ask {
        namespace: &req.namespace,
        region: &req.region,
        memory_mb: req.size.memory_mb,
        cpu_millis: req.size.cpu_millis(),
        disk_mb: disk_need(req.volume.as_ref().map(|v| v.size_gb)),
        what: "machine",
    };
    let (host, first, hold) = {
        let mut reg = st.reg.lock().unwrap();
        let first = !reg.namespaces.contains_key(&req.namespace);
        let source = req
            .fork
            .as_ref()
            .and_then(|f| reg.host_of_machine(&f.machine_id).map(|h| h.id.clone()));
        // A fork is made on its source's host: into a namespace of another host it cannot be
        // (ADR 0056).
        if let (Some(src), Some(pinned)) = (&source, reg.namespaces.get(&req.namespace)) {
            if src != pinned {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    "invalid",
                    format!(
                        "namespace {} is on host {pinned}, the fork's source on host {src}: a fork is made on its source's host",
                        req.namespace
                    ),
                ));
            }
        }
        // The host the request is bound to: a fork's source's, else the namespace's.
        let bound = source
            .clone()
            .or_else(|| reg.namespaces.get(&req.namespace).cloned());
        refuse_outside(&reg, bound.as_deref(), &req.namespace, &req.region)?;
        refuse_under_pressure(&st, &reg, bound.as_deref(), &ask)?;
        let chosen = source.or_else(|| {
            reg.place(
                &req.namespace,
                &req.region,
                ask.memory_mb,
                ask.disk_mb,
                ask.cpu_millis,
                &st.policy,
            )
        });
        let Some(host) = chosen.and_then(|id| reg.hosts.get(&id).cloned()) else {
            return Err(no_room(&st, &reg, &ask));
        };
        // A fork's new namespace lives where its source does, as a placement would pin it.
        reg.pin(&req.namespace, &host.id);
        let id = reg.hold(&host.id, ask.memory_mb, ask.disk_mb, ask.cpu_millis);
        (host, first, id)
    };
    let hold = Held {
        st: &st,
        host: host.id.clone(),
        id: hold,
    };
    // The pin is written before the host makes anything: a fleet restarted after the create
    // still sends the namespace's next machine there.
    st.save().await.map_err(registry_error)?;
    // A restore may ask for its backup's key while this forward lasts (ADR 0035).
    let restoring = req
        .restore
        .as_ref()
        .map(|rs| st.restores.open(&host.id, rs, std::time::Instant::now()));
    let resp = forward(&st, &host, Method::POST, "/v1/machines", &headers, body).await;
    if let Some(f) = restoring {
        st.restores.close(f);
    }
    let (parts, data) = read(resp).await;
    if parts.status.is_success() {
        hold.made();
        if let Ok(m) = serde_json::from_slice::<api::Machine>(&data) {
            st.reg
                .lock()
                .unwrap()
                .machines
                .insert(m.id, host.id.clone());
        }
        // The machine exists: its answer is the caller's, whatever this write does.
        st.save_after_host().await;
        return Ok(Response::from_parts(
            parts,
            Body::from(with_host(data, &host.id)),
        ));
    }
    drop(hold);
    first_refused(&st, &req.namespace, first, &data).await;
    Ok(Response::from_parts(parts, Body::from(data)))
}

/// Resolve only an inherited restore size; explicit sizes need no backup lookup.
/// Listings expose the original backup's size without its environment or sealed contents.
async fn restore_size(
    st: &Arc<AppState>,
    rs: &api::RestoreSpec,
) -> Result<(api::Size, String), Refusal> {
    if !api::valid_id(&rs.machine_id) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid",
            "restore.machine_id is not a machine id",
        ));
    }
    // The store is shared. A restore must remain possible when its original host is down.
    let hosts = {
        let reg = st.reg.lock().unwrap();
        let source = reg.host_of_machine(&rs.machine_id).map(|h| h.id.as_str());
        let mut hosts = reg.ready();
        hosts.sort_by_key(|h| Some(h.id.as_str()) != source);
        hosts
    };
    let mut found = None;
    let mut failure = err(
        StatusCode::SERVICE_UNAVAILABLE,
        "no_host",
        "no ready host can resolve the restore size",
    );
    for host in hosts {
        let response = forward(
            st,
            &host,
            Method::GET,
            &format!("/v1/machines/{}/backups", rs.machine_id),
            &HeaderMap::new(),
            Bytes::new(),
        )
        .await;
        let (parts, bytes) = read(response).await;
        if !parts.status.is_success() {
            failure = err(
                parts.status,
                "backup_lookup",
                "cannot list the restore's backups to resolve its size",
            );
            continue;
        }
        match serde_json::from_slice::<Vec<api::Backup>>(&bytes) {
            Ok(backups) => {
                found = Some(backups);
                break;
            }
            Err(_) => {
                failure = err(
                    StatusCode::BAD_GATEWAY,
                    "host_unreachable",
                    "unreadable backup listing",
                )
            }
        }
    }
    let backups = found.ok_or(failure)?;
    let latest = rs.backup.is_empty() || rs.backup == "latest";
    let backup = backups
        .into_iter()
        .filter(|b| b.machine_id == rs.machine_id && (latest || b.id == rs.backup))
        .max_by(|a, b| a.id.cmp(&b.id))
        .ok_or_else(|| {
            err(
                StatusCode::NOT_FOUND,
                "not_found",
                "restore backup not found",
            )
        })?;
    let size = backup.size.ok_or_else(|| {
        err(
            StatusCode::BAD_REQUEST,
            "invalid",
            "this backup has no public size metadata; provide an explicit restore size",
        )
    })?;
    size.check().map_err(|why| {
        err(
            StatusCode::BAD_REQUEST,
            "invalid",
            format!("backup size: {why}"),
        )
    })?;
    Ok((size, backup.id))
}

/// A create bound to a host of another region than it asks: 400, a namespace never spans
/// regions (ADR 0025).
pub(super) fn refuse_outside(
    reg: &Registry,
    host: Option<&str>,
    namespace: &str,
    region: &str,
) -> Result<(), Refusal> {
    match host
        .and_then(|id| reg.hosts.get(id))
        .and_then(|h| h.outside(namespace, region))
    {
        Some(why) => Err(err(StatusCode::BAD_REQUEST, "invalid", why)),
        None => Ok(()),
    }
}

/// What a placement asks for: what a refusal counts and logs.
pub(super) struct Ask<'a> {
    pub(super) namespace: &'a str,
    pub(super) region: &'a str,
    pub(super) memory_mb: u32,
    pub(super) cpu_millis: u32,
    pub(super) disk_mb: u64,
    /// `machine`, `gateway`, `quota`: for the refusal's message.
    pub(super) what: &'a str,
}

/// No host (of the region asked) with room for a new namespace's machine: 503 `capacity`, which a
/// caller tries again later, counted by what ran out.
pub(super) fn no_room(st: &AppState, reg: &Registry, ask: &Ask) -> Refusal {
    let hosts = match ask.region {
        "" => "no host".to_string(),
        r => format!("no host in region {r}"),
    };
    let resource = reg.shortage(
        ask.region,
        ask.memory_mb,
        ask.disk_mb,
        ask.cpu_millis,
        &st.policy,
    );
    unschedulable(st, reg, ask.region, resource, ask, None);
    err(
        StatusCode::SERVICE_UNAVAILABLE,
        "capacity",
        format!("{hosts} has room for this {}", ask.what),
    )
}

/// A create on a host that takes nothing new while a condition is true (ADR 0021): a pinned
/// namespace's host, or a fork's source's. 503 `capacity`, which a caller tries again later,
/// counted as `pressure` in the host's region.
pub(super) fn refuse_under_pressure(
    st: &AppState,
    reg: &Registry,
    host: Option<&str>,
    ask: &Ask,
) -> Result<(), Refusal> {
    let Some(h) = host.and_then(|id| reg.hosts.get(id)) else {
        return Ok(());
    };
    if h.capacity.cpu_millis.is_none() {
        unschedulable(st, reg, &h.region, Resource::Cpu, ask, Some(&h.id));
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "capacity",
            "host must be upgraded to report and enforce CPU millis",
        ));
    }
    match h.pressure() {
        Some(why) => {
            unschedulable(st, reg, &h.region, Resource::Pressure, ask, Some(&h.id));
            Err(err(StatusCode::SERVICE_UNAVAILABLE, "capacity", why))
        }
        None => Ok(()),
    }
}

/// Counts a create refused for want of room and logs it at `warn` (ADR 0042): what ran out, in
/// which region (the host's, or the one asked), what was asked, and the most the region still
/// has on one host.
pub(super) fn unschedulable(
    st: &AppState,
    reg: &Registry,
    region: &str,
    resource: Resource,
    ask: &Ask,
    host: Option<&str>,
) {
    st.refusals
        .count(signals::counted_region(reg, region), resource);
    // An ask of any region could have had a host of any region.
    let largest = reg
        .room(&st.policy)
        .into_iter()
        .filter(|(r, _)| region.is_empty() || r == region)
        .fold(api::Room::default(), |a, (_, (_, l))| api::Room {
            memory_mb: a.memory_mb.max(l.memory_mb),
            disk_mb: a.disk_mb.max(l.disk_mb),
        });
    tracing::warn!(
        resource = resource.as_str(),
        region,
        namespace = ask.namespace,
        host,
        memory_mb = ask.memory_mb,
        disk_mb = ask.disk_mb,
        largest_memory_mb = largest.memory_mb,
        largest_disk_mb = largest.disk_mb,
        "unschedulable"
    );
}

/// The disk a machine is placed for: root disks are thin, a volume takes what it says, plus
/// headroom.
pub(super) fn disk_need(volume_gb: Option<u32>) -> u64 {
    volume_gb.map(|gb| gb as u64 * 1024).unwrap_or(0) + 2048
}

/// A host with no room for a namespace's first machine (or gateway): the pin the request made
/// goes, so a retry is placed afresh. A later one keeps it: the namespace's network is there.
pub(super) async fn first_refused(st: &AppState, namespace: &str, first: bool, answer: &[u8]) {
    if first && error_code(answer) == "capacity" {
        st.reg.lock().unwrap().unpin(namespace);
        st.save_after_host().await;
    }
}
