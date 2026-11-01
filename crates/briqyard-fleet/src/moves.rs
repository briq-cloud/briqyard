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
    let fence = {
        let mut reg = st.reg.lock().unwrap();
        if !reg.hosts.contains_key(&host.id) || reg.machines.get(id) != Some(&host.id) {
            return Err(err(
                StatusCode::CONFLICT,
                "conflict",
                "move source ownership changed before dispatch",
            ));
        }
        let there = reg.namespaces.get(&req.namespace).cloned();
        if let Some(other) = there.as_ref().filter(|other| **other != host.id) {
            return Err(err(StatusCode::CONFLICT, "other_host", format!(
                "the namespace {} is on host {other}, machine {id} on host {}; moving across hosts is not supported yet", req.namespace, host.id
            )));
        }
        if crate::create_replay::relocation_unresolved(&reg, &req.namespace, Some(&host.id)) {
            return Err(err(
                StatusCode::CONFLICT,
                "conflict",
                "namespace has an unresolved dispatch on another host",
            ));
        }
        // A unique monotonic generation identifies this forward even if another move finishes
        // first. Exhaustion must not let a stale completion settle a newer dispatch.
        if reg.namespace_version(&req.namespace) == u64::MAX {
            return Err(err(
                StatusCode::CONFLICT,
                "conflict",
                "namespace generation exhausted",
            ));
        }
        reg.pin(&req.namespace, &host.id);
        reg.note_namespace_create(&req.namespace);
        let fence = serde_json::to_string(&(&req.namespace, reg.namespace_version(&req.namespace)))
            .expect("tuple serializes");
        reg.namespace_moves.insert(
            fence.clone(),
            MoveFence {
                namespace: req.namespace.clone(),
                host: host.id.clone(),
            },
        );
        fence
    };
    // No move can reach a host until both its pin and unresolved intent are durable.
    st.save().await.map_err(registry_error)?;
    let path = format!("/v1/machines/{id}/move");
    let resp = forward(st, &host, Method::POST, &path, headers, body).await;
    let (parts, data) = read(resp).await;
    if parts.status.is_success()
        && serde_json::from_slice::<api::MoveResult>(&data)
            .is_ok_and(|m| m.machine.id == id && m.machine.namespace == req.namespace)
    {
        st.reg.lock().unwrap().namespace_moves.remove(&fence);
        st.save_after_host().await;
    }
    // An error or cancelled forward can follow a host-side commit. Keep that fence for
    // reconciliation, with no expiry; an HTTP status is not proof the move never happened.
    Ok(Response::from_parts(
        parts,
        Body::from(on_host(data, &host.id)),
    ))
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct MoveFence {
    pub namespace: String,
    pub host: String,
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
