//! Finding the host of a machine or an endpoint by id.

use super::*;

/// What the fleet indexes to a host, and where a host is asked for one by id.
#[derive(Clone, Copy)]
pub(super) enum Indexed {
    Machine,
    Endpoint,
}

impl Indexed {
    pub(super) fn path(self, id: &str) -> String {
        match self {
            Indexed::Machine => format!("/v1/machines/{id}"),
            Indexed::Endpoint => format!("/v1/endpoints/{id}"),
        }
    }

    pub(super) fn index(
        self,
        reg: &mut Registry,
    ) -> &mut std::collections::HashMap<String, String> {
        match self {
            Indexed::Machine => &mut reg.machines,
            Indexed::Endpoint => &mut reg.endpoints,
        }
    }
}

/// Finds the host of a machine or an endpoint: from the index, else by asking every host.
pub(super) async fn locate(st: &AppState, what: Indexed, id: &str) -> Option<HostRec> {
    let hosts = {
        let mut reg = st.reg.lock().unwrap();
        let known = what.index(&mut reg).get(id).cloned();
        if let Some(h) = known.and_then(|hid| reg.hosts.get(&hid)) {
            return Some(h.clone());
        }
        reg.ready()
    };
    // A probe, not the caller's request: none of its headers (its `If-Match` is for the call).
    for h in hosts {
        let resp = forward(
            st,
            &h,
            Method::GET,
            &what.path(id),
            &HeaderMap::new(),
            Bytes::new(),
        )
        .await;
        if resp.status().is_success() {
            what.index(&mut st.reg.lock().unwrap())
                .insert(id.to_string(), h.id.clone());
            return Some(h);
        }
    }
    None
}

/// The backups of a machine id, from whichever host answers: the store is shared, and the
/// machine may be gone from every host.
pub(super) async fn list_backups(
    State(st): S,
    Path(params): Path<Vec<(String, String)>>,
    headers: HeaderMap,
) -> Response {
    let id = params
        .iter()
        .find(|(k, _)| k == "id")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let path = format!("/v1/machines/{id}/backups");
    let known = st.reg.lock().unwrap().host_of_machine(&id).cloned();
    let hosts: Vec<HostRec> = match known {
        Some(h) => vec![h],
        None => st.reg.lock().unwrap().ready(),
    };
    let mut last = err(
        StatusCode::SERVICE_UNAVAILABLE,
        "no_host",
        "no host is ready",
    )
    .into_response();
    for h in hosts {
        if h.state == "down" {
            continue;
        }
        let resp = forward(&st, &h, Method::GET, &path, &headers, Bytes::new()).await;
        if resp.status().is_success() {
            return resp;
        }
        last = resp;
    }
    last
}

/// The host that holds the backups of a machine no host has (ADR 0045): the one whose
/// `/v1/backups?machine=` lists one of it, of `namespace` when given. Every host is asked at
/// once, a down one included, so a backup left on the host a namespace moved from is found; a
/// host that does not hold it answers from memory. With no host listing it, a host that
/// could not answer fails the search with its answer, since it may be the one. A host older
/// than the `machine` filter lists all it holds: what is not the machine's is not read.
pub(super) async fn holder(
    st: &AppState,
    id: &str,
    namespace: Option<&str>,
) -> Result<Option<HostRec>, Box<Response>> {
    if !api::valid_id(id) {
        return Ok(None);
    }
    let mut path = format!("/v1/backups?machine={id}");
    if let Some(t) = namespace.filter(|t| api::valid_id(t)) {
        path.push_str(&format!("&namespace={t}"));
    }
    let hosts = st.reg.lock().unwrap().listed();
    let asked = hosts.into_iter().map(|h| {
        let path = &path;
        async move {
            let resp = forward(st, &h, Method::GET, path, &HeaderMap::new(), Bytes::new()).await;
            if !resp.status().is_success() {
                return Err(Box::new(resp));
            }
            let (_, data) = read(resp).await;
            let backups: Vec<api::Backup> =
                serde_json::from_slice(&data).map_err(|e| Box::new(unreadable(&h, e)))?;
            Ok(backups.iter().any(|b| b.machine_id == id).then_some(h))
        }
    });
    let mut failed = None;
    for answer in futures::future::join_all(asked).await {
        match answer {
            Ok(Some(h)) => return Ok(Some(h)),
            Ok(None) => {}
            Err(resp) => failed = failed.or(Some(resp)),
        }
    }
    failed.map_or(Ok(None), Err)
}

/// A host's memory and disk asked of it now, as its heartbeat would report them (ADR 0044).
/// Not answering within five seconds is nothing: the heartbeat comes.
pub(super) async fn refresh(st: &AppState, host: &HostRec) {
    let asked = Utc::now();
    let status = get_json::<api::Status>(st, host, "/v1/status");
    let within = std::time::Duration::from_secs(5);
    if let Ok(Some(s)) = tokio::time::timeout(within, status).await {
        if let Some(h) = st.reg.lock().unwrap().hosts.get_mut(&host.id) {
            h.egress_siblings_v1 = s.egress_siblings_v1;
            h.named_memory_fork_v1 = s.named_memory_fork_v1;
            h.report(s.used, s.disk_free_mb, asked);
        }
    }
}

pub(super) async fn by_machine(
    State(st): S,
    Path(params): Path<Vec<(String, String)>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Refusal> {
    let id = params
        .iter()
        .find(|(k, _)| k == "id")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    // A destroyed machine is its backups alone (ADR 0023): reached on the host that holds
    // them, which a moved namespace left (ADR 0045).
    let host = match locate(&st, Indexed::Machine, &id).await {
        Some(h) => h,
        None if uri
            .path()
            .starts_with(&format!("/v1/machines/{id}/backups/")) =>
        {
            match holder(&st, &id, query_namespace(&uri).as_deref()).await {
                Ok(Some(h)) => h,
                Ok(None) => {
                    return Err(err(StatusCode::NOT_FOUND, "not_found", "machine not found"))
                }
                Err(answer) => return Ok(*answer),
            }
        }
        None => return Err(err(StatusCode::NOT_FOUND, "not_found", "machine not found")),
    };
    let path = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();
    // What the call is, by its path alone: a query (`?namespace=`) changes nothing of it.
    let own = format!("/v1/machines/{id}");
    if method == Method::POST && uri.path() == format!("{own}/move") {
        return moves::move_machine(&st, host, &id, &headers, body).await;
    }
    if method == Method::PATCH && uri.path() == own {
        if let Ok(req) = serde_json::from_slice::<api::UpdateMachineRequest>(&body) {
            if req
                .spec
                .size
                .as_ref()
                .is_some_and(|size| size.cpu_millis.is_some())
                && st
                    .reg
                    .lock()
                    .unwrap()
                    .hosts
                    .get(&host.id)
                    .is_some_and(|h| h.capacity.cpu_millis.is_none())
            {
                return Err(err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "capacity",
                    "host must be upgraded to report and enforce CPU millis",
                ));
            }
        }
    }
    let is_delete = method == Method::DELETE && uri.path() == own;
    let plain_get = method == Method::GET && uri.path() == own;
    let adds_endpoint = method == Method::POST && uri.path() == format!("{own}/endpoints");
    // A logs follow (ADR 0025) is streamed through, as a watch is.
    let follows = method == Method::GET
        && uri.path() == format!("{own}/logs")
        && uri
            .query()
            .is_some_and(|q| q.split('&').any(|kv| kv == "follow=true"));
    if follows {
        return Ok(forward_watch(&st, &host, &path, &headers).await);
    }
    let resp = forward(&st, &host, method, &path, &headers, body).await;
    if !resp.status().is_success() {
        return Ok(resp);
    }
    if is_delete {
        st.reg.lock().unwrap().machines.remove(&id);
        st.save_after_host().await;
        // What the machine held is free now, not at the host's next heartbeat (ADR 0044).
        refresh(&st, &host).await;
    }
    if plain_get {
        let (parts, data) = read(resp).await;
        return Ok(Response::from_parts(
            parts,
            Body::from(with_host(data, &host.id)),
        ));
    }
    if adds_endpoint {
        let (parts, data) = read(resp).await;
        if let Ok(e) = serde_json::from_slice::<api::Endpoint>(&data) {
            st.reg
                .lock()
                .unwrap()
                .endpoints
                .insert(e.id, host.id.clone());
            st.save_after_host().await;
        }
        return Ok(Response::from_parts(parts, Body::from(data)));
    }
    Ok(resp)
}

pub(super) async fn by_endpoint(
    State(st): S,
    Path(id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Refusal> {
    let host = locate(&st, Indexed::Endpoint, &id).await.ok_or_else(|| {
        err(
            StatusCode::NOT_FOUND,
            "not_found",
            format!("endpoint {id} not found"),
        )
    })?;
    let path = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();
    let is_delete = method == Method::DELETE;
    let resp = forward(&st, &host, method, &path, &headers, body).await;
    if is_delete && resp.status().is_success() {
        st.reg.lock().unwrap().endpoints.remove(&id);
        st.save_after_host().await;
    }
    Ok(resp)
}
