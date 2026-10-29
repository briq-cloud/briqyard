//! The lists answered from every host: machines, endpoints, backups, usage, top, events.

use super::*;

/// Lists machines. A listing is the truth for whoever reads it (the control plane marks a
/// machine missing from it as gone), so it is never partial: a namespace's listing asks the
/// namespace's host alone, and a host that is down or does not answer fails the whole listing.
/// The `namespace` of a query.
pub(super) fn query_namespace(uri: &Uri) -> Option<String> {
    uri.query().and_then(namespace_param)
}

/// The `namespace` of a query string; `tenant`, its former name, is read the same.
pub(super) fn namespace_param(q: &str) -> Option<String> {
    q.split('&')
        .find_map(|kv| {
            kv.strip_prefix("namespace=")
                .or_else(|| kv.strip_prefix("tenant="))
        })
        .map(|t| t.to_string())
}

pub(super) async fn list_machines(State(st): S, headers: HeaderMap, uri: Uri) -> Response {
    let namespace = query_namespace(&uri);
    let hosts: Vec<HostRec> = {
        let reg = st.reg.lock().unwrap();
        match namespace.as_deref().and_then(|t| reg.host_of_namespace(t)) {
            Some(h) => vec![h.clone()],
            None => reg.listed(),
        }
    };
    let mut all: Vec<serde_json::Value> = Vec::new();
    let path = match uri.query() {
        Some(q) => format!("/v1/machines?{q}"),
        None => "/v1/machines".into(),
    };
    for h in hosts {
        let resp = forward(&st, &h, Method::GET, &path, &headers, Bytes::new()).await;
        if !resp.status().is_success() {
            return resp;
        }
        let (_, data) = read(resp).await;
        match serde_json::from_slice::<Vec<serde_json::Value>>(&data) {
            Ok(ms) => {
                let mut reg = st.reg.lock().unwrap();
                for mut m in ms {
                    if let Some(id) = m["id"].as_str() {
                        reg.machines.insert(id.to_string(), h.id.clone());
                    }
                    m["host"] = serde_json::Value::String(h.id.clone());
                    all.push(m);
                }
            }
            Err(e) => return unreadable(&h, e),
        }
    }
    Json(all).into_response()
}

pub(super) fn unreadable(h: &HostRec, e: serde_json::Error) -> Response {
    err(
        StatusCode::BAD_GATEWAY,
        "host_unreachable",
        format!("host {}: unreadable listing: {e}", h.id),
    )
    .into_response()
}

/// Lists endpoints, never partially, like machines; each one is indexed to its host.
pub(super) async fn list_endpoints(State(st): S, headers: HeaderMap) -> Response {
    let hosts = st.reg.lock().unwrap().listed();
    let mut all: Vec<api::Endpoint> = Vec::new();
    for h in hosts {
        let resp = forward(
            &st,
            &h,
            Method::GET,
            "/v1/endpoints",
            &headers,
            Bytes::new(),
        )
        .await;
        if !resp.status().is_success() {
            return resp;
        }
        let (_, data) = read(resp).await;
        match serde_json::from_slice::<Vec<api::Endpoint>>(&data) {
            Ok(eps) => {
                let mut reg = st.reg.lock().unwrap();
                for e in &eps {
                    reg.endpoints.insert(e.id.clone(), h.id.clone());
                }
                all.extend(eps);
            }
            Err(e) => return unreadable(&h, e),
        }
    }
    Json(all).into_response()
}

/// The backups of the hosts' machines, destroyed ones' included (ADR 0023): every host's, the
/// query as it came, never partial. A namespace's too: a host it moved from still holds the
/// backups of the machines destroyed there (ADR 0045).
pub(super) async fn all_backups(State(st): S, headers: HeaderMap, uri: Uri) -> Response {
    let hosts = st.reg.lock().unwrap().listed();
    let path = match uri.query() {
        Some(q) => format!("/v1/backups?{q}"),
        None => "/v1/backups".into(),
    };
    let mut all: Vec<api::Backup> = Vec::new();
    for h in hosts {
        let resp = forward(&st, &h, Method::GET, &path, &headers, Bytes::new()).await;
        if !resp.status().is_success() {
            return resp;
        }
        let (_, data) = read(resp).await;
        match serde_json::from_slice::<Vec<api::Backup>>(&data) {
            Ok(bs) => all.extend(bs),
            Err(e) => return unreadable(&h, e),
        }
    }
    Json(all).into_response()
}

/// Usage of every host, never partial (ADR 0017): a usage report missing a host undercounts.
/// Every listed host is asked, the query as it came (the hosts check it), and
/// each bucket says which host measured it.
pub(super) async fn usage(State(st): S, headers: HeaderMap, uri: Uri) -> Response {
    let hosts = st.reg.lock().unwrap().listed();
    let path = match uri.query() {
        Some(q) => format!("/v1/usage?{q}"),
        None => "/v1/usage".into(),
    };
    let mut all: Vec<api::UsageBucket> = Vec::new();
    for h in hosts {
        let resp = forward(&st, &h, Method::GET, &path, &headers, Bytes::new()).await;
        if !resp.status().is_success() {
            return resp;
        }
        let (_, data) = read(resp).await;
        match serde_json::from_slice::<Vec<api::UsageBucket>>(&data) {
            Ok(bs) => all.extend(bs.into_iter().map(|b| api::UsageBucket {
                host: h.id.clone(),
                ..b
            })),
            Err(e) => return unreadable(&h, e),
        }
    }
    Json(all).into_response()
}

/// The running machines' use (ADR 0021), asked as machines are listed: a namespace's of its
/// host, else of every host, never partial, each machine with its host.
pub(super) async fn top(State(st): S, headers: HeaderMap, uri: Uri) -> Response {
    let namespace = query_namespace(&uri);
    let hosts: Vec<HostRec> = {
        let reg = st.reg.lock().unwrap();
        match namespace.as_deref().and_then(|t| reg.host_of_namespace(t)) {
            Some(h) => vec![h.clone()],
            None => reg.listed(),
        }
    };
    let path = match uri.query() {
        Some(q) => format!("/v1/top?{q}"),
        None => "/v1/top".into(),
    };
    let mut all: Vec<api::TopMachine> = Vec::new();
    for h in hosts {
        let resp = forward(&st, &h, Method::GET, &path, &headers, Bytes::new()).await;
        if !resp.status().is_success() {
            return resp;
        }
        let (_, data) = read(resp).await;
        match serde_json::from_slice::<Vec<api::TopMachine>>(&data) {
            Ok(ms) => all.extend(ms.into_iter().map(|m| api::TopMachine {
                host: h.id.clone(),
                ..m
            })),
            Err(e) => return unreadable(&h, e),
        }
    }
    Json(all).into_response()
}

#[derive(serde::Deserialize)]
pub(super) struct EventsQuery {
    pub(super) since: Option<String>,
    #[serde(alias = "tenant")]
    pub(super) namespace: Option<String>,
    pub(super) machine: Option<String>,
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) watch: bool,
}

/// Events (ADR 0019), which are per host. With a namespace, from the namespace's host; else with a
/// machine, from the machine's host: the host's own cursor, a watch streamed through. With
/// neither, every host, never partial, merged by time with each event's host and a cursor of
/// every host's: `<host>:<seq>,…`. A watch of every host is refused.
pub(super) async fn events(
    State(st): S,
    headers: HeaderMap,
    uri: Uri,
    Query(q): Query<EventsQuery>,
) -> Response {
    let path = match uri.query() {
        Some(query) => format!("/v1/events?{query}"),
        None => "/v1/events".into(),
    };
    let host = match (&q.namespace, &q.machine) {
        (Some(t), _) => st.reg.lock().unwrap().host_of_namespace(t).cloned().ok_or_else(|| {
            err(StatusCode::NOT_FOUND, "not_found", format!("namespace {t} not found"))
        }),
        (None, Some(m)) => locate(&st, Indexed::Machine, m).await.ok_or_else(|| {
            err(
                StatusCode::NOT_FOUND,
                "not_found",
                format!("machine {m} not found: a destroyed machine's events are read with its namespace, ?namespace=…&machine={m}"),
            )
        }),
        (None, None) if q.watch => Err(err(
            StatusCode::BAD_REQUEST,
            "invalid",
            "a watch through the fleet names a namespace or a machine: events are per host, and a stream of every host would go on without one that drops",
        )),
        (None, None) => return events_of_every_host(&st, &headers, &uri, q).await,
    };
    match host {
        Ok(h) if q.watch => forward_watch(&st, &h, &path, &headers).await,
        Ok(h) => forward(&st, &h, Method::GET, &path, &headers, Bytes::new()).await,
        Err(refused) => refused.into_response(),
    }
}

/// A fleet-wide cursor, `<host>:<seq>,…`, as each host's seq; a host it does not name reads
/// from its start.
pub(super) fn parse_cursor(since: &str) -> Result<std::collections::HashMap<String, u64>, Refusal> {
    let bad = || {
        err(
            StatusCode::BAD_REQUEST,
            "invalid",
            format!("since {since:?}: want <host>:<seq>,… as a fleet-wide read's `next` gave it"),
        )
    };
    since
        .split(',')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (host, seq) = part.rsplit_once(':').ok_or_else(bad)?;
            Ok((host.to_string(), seq.parse().map_err(|_| bad())?))
        })
        .collect()
}

pub(super) fn cursor(seqs: &std::collections::BTreeMap<String, u64>) -> String {
    let parts: Vec<String> = seqs.iter().map(|(h, s)| format!("{h}:{s}")).collect();
    parts.join(",")
}

pub(super) async fn events_of_every_host(
    st: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    q: EventsQuery,
) -> Response {
    let mut since = match parse_cursor(q.since.as_deref().unwrap_or("")) {
        Ok(c) => c,
        Err(refused) => return refused.into_response(),
    };
    let limit = api::events_limit(q.limit);
    // The query as it came, for the hosts to read, but the cursor: each host gets its own.
    let rest: String = uri
        .query()
        .unwrap_or("")
        .split('&')
        .filter(|kv| !kv.is_empty() && !kv.starts_with("since="))
        .map(|kv| format!("&{kv}"))
        .collect();
    let hosts = st.reg.lock().unwrap().listed();
    let mut all: Vec<api::Event> = Vec::new();
    let mut next = std::collections::BTreeMap::new();
    for h in hosts {
        let path = format!(
            "/v1/events?since={}{rest}",
            since.remove(&h.id).unwrap_or(0)
        );
        let resp = forward(st, &h, Method::GET, &path, headers, Bytes::new()).await;
        if !resp.status().is_success() {
            return resp;
        }
        let (_, data) = read(resp).await;
        match serde_json::from_slice::<api::EventsPage>(&data) {
            Ok(page) => {
                next.insert(h.id.clone(), page.next.parse().unwrap_or(0));
                all.extend(page.events.into_iter().map(|e| api::Event {
                    host: h.id.clone(),
                    ..e
                }));
            }
            Err(e) => return unreadable(&h, e),
        }
    }
    all.sort_by(|a, b| (a.at, &a.host, a.seq).cmp(&(b.at, &b.host, b.seq)));
    // Past the limit, a host's cursor is its last event kept, so the next read goes on from it.
    if all.len() > limit {
        for e in all.drain(limit..) {
            let cut = next.get_mut(&e.host).expect("asked");
            *cut = (*cut).min(e.seq - 1);
        }
    }
    Json(api::EventsPage {
        events: all,
        next: cursor(&next),
    })
    .into_response()
}
