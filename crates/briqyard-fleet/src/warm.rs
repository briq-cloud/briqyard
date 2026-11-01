//! Pool operations stay on the namespace/template host. Claims transfer existing
//! reservations, so they must not create a second fleet hold.
use super::*;

pub(super) async fn warm_catalog(
    State(st): S,
    Path(namespace): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Refusal> {
    let host = host(&st, &namespace, false)?;
    Ok(forward(
        &st,
        &host,
        Method::GET,
        &format!("/v1/namespaces/{namespace}/warm-catalog"),
        &headers,
        Bytes::new(),
    )
    .await)
}

pub(super) async fn put_warm_catalog(
    State(st): S,
    Path((namespace, entry)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Refusal> {
    let _: api::WarmDesiredRequest = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, "invalid", e.to_string()))?;
    if !api::valid_name(&entry) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid",
            "invalid catalog entry",
        ));
    }
    let host = host(&st, &namespace, true)?;
    if host.state != "ready" {
        return Err(err(
            StatusCode::CONFLICT,
            "host_unavailable",
            "host is not accepting pool changes",
        ));
    }
    Ok(forward(
        &st,
        &host,
        Method::PUT,
        &format!("/v1/namespaces/{namespace}/warm-catalog/{entry}"),
        &headers,
        body,
    )
    .await)
}

fn host(st: &AppState, namespace: &str, require: bool) -> Result<HostRec, Refusal> {
    if !api::valid_id(namespace) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid", "invalid namespace"));
    }
    let reg = st.reg.lock().unwrap();
    let host = reg.host_of_namespace(namespace).cloned().ok_or_else(|| {
        err(
            StatusCode::NOT_FOUND,
            "not_found",
            "namespace has no fleet host",
        )
    })?;
    if require
        && (host.warm_pool_profiles.is_empty()
            || Utc::now() - host.last_seen >= st.policy.down_after)
    {
        return Err(err(
            StatusCode::CONFLICT,
            "capability_unsupported",
            "namespace host does not advertise a current qualified warm pool profile",
        ));
    }
    Ok(host)
}

pub(super) async fn warm_pools(
    State(st): S,
    Path(namespace): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Refusal> {
    let host = host(&st, &namespace, false)?;
    Ok(forward(
        &st,
        &host,
        Method::GET,
        &format!("/v1/namespaces/{namespace}/warm-pools"),
        &headers,
        Bytes::new(),
    )
    .await)
}

pub(super) async fn put_warm_pool(
    State(st): S,
    Path((namespace, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Refusal> {
    let request: api::PutWarmPoolRequest = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, "invalid", e.to_string()))?;
    let host = host(&st, &namespace, true)?;
    let source = locate(&st, Indexed::Machine, &request.source_machine)
        .await
        .ok_or_else(|| {
            err(
                StatusCode::NOT_FOUND,
                "not_found",
                "template source not found",
            )
        })?;
    if source.id != host.id {
        return Err(err(
            StatusCode::CONFLICT,
            "conflict",
            "warm pool must stay with its template source and namespace",
        ));
    }
    if host.state != "ready" {
        return Err(err(
            StatusCode::CONFLICT,
            "host_unavailable",
            "host is not accepting pool changes",
        ));
    }
    Ok(forward(
        &st,
        &host,
        Method::PUT,
        &format!("/v1/namespaces/{namespace}/warm-pools/{name}"),
        &headers,
        body,
    )
    .await)
}

pub(super) async fn delete_warm_pool(
    State(st): S,
    Path((namespace, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Refusal> {
    let host = host(&st, &namespace, false)?;
    Ok(forward(
        &st,
        &host,
        Method::DELETE,
        &format!("/v1/namespaces/{namespace}/warm-pools/{name}"),
        &headers,
        Bytes::new(),
    )
    .await)
}

pub(super) async fn claim_warm_pool(
    State(st): S,
    Path((namespace, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Refusal> {
    let _: api::ClaimWarmPoolRequest = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, "invalid", e.to_string()))?;
    let host = host(&st, &namespace, true)?;
    let response = forward(
        &st,
        &host,
        Method::POST,
        &format!("/v1/namespaces/{namespace}/warm-pools/{name}/claims"),
        &headers,
        body,
    )
    .await;
    let (parts, mut bytes) = read(response).await;
    if parts.status.is_success() {
        if let Ok(mut machine) = serde_json::from_slice::<api::Machine>(&bytes) {
            machine.host = host.id.clone();
            st.reg
                .lock()
                .unwrap()
                .machines
                .insert(machine.id.clone(), host.id);
            bytes = serde_json::to_vec(&machine)
                .expect("machine serializes")
                .into();
        }
    }
    Ok(Response::from_parts(parts, Body::from(bytes)))
}
