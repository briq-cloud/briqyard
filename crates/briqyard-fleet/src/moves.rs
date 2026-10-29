//! A machine moved into another namespace through the fleet (ADR 0056). Into a namespace of its
//! own host (or one the fleet does not know), the host does it: a rename or a restart on the
//! new network. Into a namespace pinned to another host it is refused, before anything
//! happens: moving across hosts is not supported yet.

use super::*;

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
        Some(other) if other != host.id => Err(err(
            StatusCode::CONFLICT,
            "other_host",
            format!(
                "the namespace {} is on host {other}, machine {id} on host {}; moving across hosts is not supported yet",
                req.namespace, host.id
            ),
        )),
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
