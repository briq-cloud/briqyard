//! A machine moved into another namespace through the fleet (ADR 0056). Into a namespace of its
//! own host (or one the fleet does not know), the host does it: a rename or a restart on the
//! new network. Into a namespace pinned to another host, the fleet moves the machine as the
//! operator's procedure does (ADR 0045): stop, back up, restore there, destroy here.

use super::*;
use api::state;
use std::time::Instant;

/// How long a restore on the other host may take to be made.
const MADE_WITHIN: std::time::Duration = std::time::Duration::from_secs(15 * 60);

pub(crate) async fn move_machine(
    st: &Arc<AppState>,
    host: HostRec,
    id: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<Response, Refusal> {
    let req: api::MoveRequest = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, "invalid", format!("body: {e}")))?;
    if !api::valid_id(&req.namespace) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid",
            "namespace must be a-z, 0-9, _ or -, at most 64 characters",
        ));
    }
    let there = st
        .reg
        .lock()
        .unwrap()
        .namespaces
        .get(&req.namespace)
        .cloned();
    match there {
        Some(other) if other != host.id => Ok(across(st, host, other, id, req, headers).await),
        _ => Ok(within(st, host, id, body, headers, &req.namespace).await),
    }
}

/// The host does it; the namespace it joins is pinned to it when it was new.
async fn within(
    st: &Arc<AppState>,
    host: HostRec,
    id: &str,
    body: Bytes,
    headers: &HeaderMap,
    namespace: &str,
) -> Response {
    let path = format!("/v1/machines/{id}/move");
    let resp = forward(st, &host, Method::POST, &path, headers, body).await;
    if !resp.status().is_success() {
        return resp;
    }
    st.reg.lock().unwrap().pin(namespace, &host.id);
    st.save_after_host().await;
    let (parts, data) = read(resp).await;
    Response::from_parts(parts, Body::from(on_host(data, &host.id)))
}

/// A result with the host that holds the machine now.
fn on_host(data: Bytes, host: &str) -> Bytes {
    match serde_json::from_slice::<serde_json::Value>(&data) {
        Ok(mut v) if v["machine"].is_object() => {
            v["machine"]["host"] = host.into();
            Bytes::from(serde_json::to_vec(&v).unwrap_or_default())
        }
        _ => data,
    }
}

fn json_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h
}

/// A call to a host whose answer is parsed: the response as it came when it is not a success.
async fn call<T: serde::de::DeserializeOwned>(
    st: &AppState,
    host: &HostRec,
    method: Method,
    path: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<T, Box<Response>> {
    let (parts, data) = read(forward(st, host, method, path, headers, body).await).await;
    if !parts.status.is_success() {
        return Err(Box::new(Response::from_parts(parts, Body::from(data))));
    }
    serde_json::from_slice(&data).map_err(|e| {
        Box::new(
            err(
                StatusCode::BAD_GATEWAY,
                "host_unreachable",
                format!("host {}: {path}: an answer that is not one: {e}", host.id),
            )
            .into_response(),
        )
    })
}

/// The machine on `from`, made again on `to` in the namespace there, from a backup taken with
/// it stopped. The source is destroyed only once the copy is made; any refusal before leaves
/// the source as it was, running again if it ran.
async fn across(
    st: &Arc<AppState>,
    from: HostRec,
    to: String,
    id: &str,
    req: api::MoveRequest,
    headers: &HeaderMap,
) -> Response {
    let Some(to) = st.reg.lock().unwrap().hosts.get(&to).cloned() else {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "host_down",
            format!("host {to} of namespace {} is not known", req.namespace),
        )
        .into_response();
    };
    let own = format!("/v1/machines/{id}");
    let json = json_headers();
    let m: api::Machine = match call(st, &from, Method::GET, &own, &json, Bytes::new()).await {
        Ok(m) => m,
        Err(why) => return *why,
    };
    let was_running = match m.state.as_str() {
        state::RUNNING => true,
        state::STOPPED | state::CREATED => false,
        other => {
            return err(
                StatusCode::CONFLICT,
                "bad_state",
                format!("machine {id} is {other}: a move waits for it to settle"),
            )
            .into_response()
        }
    };
    if was_running {
        let stop = format!("{own}/stop");
        if let Err(why) =
            call::<api::Machine>(st, &from, Method::POST, &stop, headers, Bytes::new()).await
        {
            return *why;
        }
    }
    let undo = Undo {
        st,
        from: &from,
        own: &own,
        was_running,
    };
    let backups = format!("{own}/backups");
    let backup: api::Backup =
        match call(st, &from, Method::POST, &backups, &json, Bytes::new()).await {
            Ok(b) => b,
            Err(why) => return undo.source(*why).await,
        };
    let create = api::CreateMachineRequest {
        namespace: req.namespace.clone(),
        name: m.name.clone(),
        sleep: m.sleep.clone(),
        restart: Some(m.restart.clone()),
        metadata: m.metadata.clone(),
        backup: Some(m.backup.clone()),
        start: Some(was_running),
        restore: Some(api::RestoreSpec {
            machine_id: id.into(),
            backup: backup.id.clone(),
        }),
        ..Default::default()
    };
    let body = Bytes::from(serde_json::to_vec(&create).unwrap_or_default());
    // The usual create: the namespace's host, its room, its refusal (`capacity`) as it is.
    let made = create_machine(State(st.clone()), json.clone(), body)
        .await
        .unwrap_or_else(IntoResponse::into_response);
    let (parts, data) = read(made).await;
    let new: api::Machine = match serde_json::from_slice(&data) {
        Ok(new) if parts.status.is_success() => new,
        _ => {
            return undo
                .source(Response::from_parts(parts, Body::from(data)))
                .await
        }
    };
    let ready = match settled(st, &to, &new.id).await {
        Ok(m) => m,
        Err(why) => return undo.copy(&to, &new.id, *why).await,
    };
    if was_running && ready.state != state::RUNNING {
        let why = err(
            StatusCode::CONFLICT,
            "boot_failed",
            format!(
                "machine {} on host {}: {} {}",
                ready.id, to.id, ready.state, ready.error
            ),
        );
        return undo.copy(&to, &new.id, why.into_response()).await;
    }
    // The copy stands: the source goes (its backups stay held, ADR 0023).
    let gone = forward(st, &from, Method::DELETE, &own, &json, Bytes::new()).await;
    if !gone.status().is_success() {
        return undo.copy(&to, &new.id, gone).await;
    }
    st.reg.lock().unwrap().machines.remove(id);
    st.save_after_host().await;
    refresh(st, &from).await;
    // Its endpoints, on the new host: the same port and, for HTTP, the same name.
    for ep in &m.endpoints {
        let ask = api::CreateEndpointRequest {
            port: ep.port,
            protocol: ep.protocol.clone(),
            host: ep.host.split('.').next().unwrap_or_default().to_string(),
        };
        let body = Bytes::from(serde_json::to_vec(&ask).unwrap_or_default());
        let path = format!("/v1/machines/{}/endpoints", new.id);
        match call::<api::Endpoint>(st, &to, Method::POST, &path, &json, body).await {
            Ok(e) => {
                st.reg.lock().unwrap().endpoints.insert(e.id, to.id.clone());
            }
            Err(_) => {
                tracing::warn!(
                    machine = new.id,
                    port = ep.port,
                    "endpoint not made again on the new host"
                )
            }
        }
    }
    st.save_after_host().await;
    refresh(st, &to).await;
    let path = format!("/v1/machines/{}", new.id);
    let mut now = call::<api::Machine>(st, &to, Method::GET, &path, &json, Bytes::new())
        .await
        .unwrap_or(ready);
    now.host = to.id.clone();
    Json(api::MoveResult {
        machine: now,
        from: m.namespace,
        previous_ip: m.ip,
        restarted: was_running,
        replaces: Some(id.into()),
    })
    .into_response()
}

/// What a move that fails gives back: the source running again if it ran, the copy gone.
struct Undo<'a> {
    st: &'a Arc<AppState>,
    from: &'a HostRec,
    own: &'a str,
    was_running: bool,
}

impl Undo<'_> {
    /// The source as it was; `why` is the answer.
    async fn source(&self, why: Response) -> Response {
        if self.was_running {
            let start = format!("{}/start", self.own);
            let _ = forward(
                self.st,
                self.from,
                Method::POST,
                &start,
                &json_headers(),
                Bytes::new(),
            )
            .await;
        }
        why
    }

    /// The copy destroyed, then the source as it was.
    async fn copy(&self, on: &HostRec, id: &str, why: Response) -> Response {
        let path = format!("/v1/machines/{id}");
        let _ = forward(
            self.st,
            on,
            Method::DELETE,
            &path,
            &json_headers(),
            Bytes::new(),
        )
        .await;
        self.st.reg.lock().unwrap().machines.remove(id);
        self.source(why).await
    }
}

/// The restored machine once its create is done: running or created, else the failure. It is
/// asked for each second, for as long as a restore may take.
async fn settled(st: &AppState, host: &HostRec, id: &str) -> Result<api::Machine, Box<Response>> {
    let until = Instant::now() + MADE_WITHIN;
    let json = json_headers();
    loop {
        let m: api::Machine = call(
            st,
            host,
            Method::GET,
            &format!("/v1/machines/{id}"),
            &json,
            Bytes::new(),
        )
        .await?;
        match m.state.as_str() {
            state::CREATING | state::STARTING => {}
            state::ERROR => {
                return Err(err(
                    StatusCode::CONFLICT,
                    if m.error_reason.is_empty() {
                        "create_failed"
                    } else {
                        "boot_failed"
                    },
                    format!("machine {id} on host {}: {}", host.id, m.error),
                )
                .into_response()
                .into())
            }
            _ => return Ok(m),
        }
        if Instant::now() > until {
            return Err(err(
                StatusCode::SERVICE_UNAVAILABLE,
                "not_ready",
                format!("machine {id} on host {} is still {}", host.id, m.state),
            )
            .into_response()
            .into());
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
