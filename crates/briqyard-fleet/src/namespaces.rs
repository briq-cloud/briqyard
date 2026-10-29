//! Namespaces: listed, placed, pinned, deleted, with their gateway and quota.

use super::*;

pub(super) async fn list_namespaces(State(st): S) -> Json<Vec<api::Namespace>> {
    let reg = st.reg.lock().unwrap();
    let mut out: Vec<api::Namespace> = reg
        .namespaces
        .iter()
        .map(|(t, h)| api::Namespace {
            id: t.clone(),
            subnet: String::new(),
            router: String::new(),
            machines: 0,
            created_at: Utc::now(),
            host: h.clone(),
            region: reg.region_of(t).unwrap_or_default().into(),
            gateway: None,
        })
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Json(out)
}

pub(super) async fn delete_namespace(
    State(st): S,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Refusal> {
    let host = st.reg.lock().unwrap().host_of_namespace(&id).cloned();
    let host = match host {
        Some(h) => h,
        None => return Ok(StatusCode::NO_CONTENT.into_response()),
    };
    let resp = forward(
        &st,
        &host,
        Method::DELETE,
        &format!("/v1/namespaces/{id}"),
        &headers,
        Bytes::new(),
    )
    .await;
    if resp.status().is_success() {
        st.reg.lock().unwrap().unpin(&id);
        st.save_after_host().await;
    }
    Ok(resp)
}

/// A namespace, from its host, with that host and its region.
pub(super) async fn get_namespace(
    State(st): S,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Refusal> {
    let host = st.reg.lock().unwrap().host_of_namespace(&id).cloned();
    let host =
        host.ok_or_else(|| err(StatusCode::NOT_FOUND, "not_found", "namespace not found"))?;
    let path = format!("/v1/namespaces/{id}");
    let resp = forward(&st, &host, Method::GET, &path, &headers, Bytes::new()).await;
    let (parts, data) = read(resp).await;
    let data = match parts.status.is_success() {
        true => with_field(with_host(data, &host.id), "region", &host.region),
        false => data,
    };
    Ok(Response::from_parts(parts, Body::from(data)))
}

/// Where a PUT on a namespace with no host yet places it (ADR 0025).
#[derive(serde::Deserialize, Default)]
pub(super) struct PlaceQuery {
    #[serde(default)]
    pub(super) region: String,
}

/// A PUT on a namespace that the namespace's host answers: one with no host yet is placed as its
/// first machine would be, in `region`, with `need_mb` and `need_disk_mb` as the need. The
/// host's answer, with the host.
pub(super) async fn put_on_namespace(
    st: &AppState,
    id: &str,
    what: &str,
    region: &str,
    (need_mb, need_disk_mb): (u32, u64),
    headers: &HeaderMap,
    body: Bytes,
) -> Result<Response, Refusal> {
    if !api::valid_id(id) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid",
            "namespace must be a-z, 0-9, _ or -, at most 64 characters",
        ));
    }
    let ask = Ask {
        namespace: id,
        region,
        memory_mb: need_mb,
        disk_mb: need_disk_mb,
        what,
    };
    let (host, first, hold) = {
        let mut reg = st.reg.lock().unwrap();
        let first = !reg.namespaces.contains_key(id);
        let bound = reg.namespaces.get(id).cloned();
        refuse_outside(&reg, bound.as_deref(), id, region)?;
        refuse_under_pressure(st, &reg, bound.as_deref(), &ask)?;
        let chosen = reg.place(id, region, need_mb, need_disk_mb, &st.policy);
        let Some(host) = chosen.and_then(|h| reg.hosts.get(&h).cloned()) else {
            return Err(no_room(st, &reg, &ask));
        };
        let id = reg.hold(&host.id, need_mb, need_disk_mb);
        (host, first, id)
    };
    let hold = Held {
        st,
        host: host.id.clone(),
        id: hold,
    };
    st.save().await.map_err(registry_error)?;
    let path = format!("/v1/namespaces/{id}/{what}");
    let resp = forward(st, &host, Method::PUT, &path, headers, body).await;
    let (parts, data) = read(resp).await;
    if parts.status.is_success() {
        hold.made();
        return Ok(Response::from_parts(
            parts,
            Body::from(with_host(data, &host.id)),
        ));
    }
    drop(hold);
    first_refused(st, id, first, &data).await;
    Ok(Response::from_parts(parts, Body::from(data)))
}

/// Puts a namespace's gateway on the namespace's host; a namespace with none yet is placed as its first
/// machine would be, the gateway's size as the need.
pub(super) async fn set_gateway(
    State(st): S,
    Path(id): Path<String>,
    Query(q): Query<PlaceQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Refusal> {
    let spec: api::GatewaySpec = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, "invalid", format!("body: {e}")))?;
    let need = (spec.size().memory_mb, disk_need(spec.volume_gb));
    put_on_namespace(&st, &id, "gateway", &q.region, need, &headers, body).await
}

/// Puts a namespace's quota on the namespace's host (ADR 0025); a namespace with none yet is placed,
/// with no need: the quota is what its machines will be held to there.
pub(super) async fn set_quota(
    State(st): S,
    Path(id): Path<String>,
    Query(q): Query<PlaceQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Refusal> {
    serde_json::from_slice::<api::Quota>(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, "invalid", format!("body: {e}")))?;
    put_on_namespace(&st, &id, "quota", &q.region, (0, 0), &headers, body).await
}

/// A namespace's quota and use, from its host.
pub(super) async fn get_quota(
    State(st): S,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Refusal> {
    let host = st.reg.lock().unwrap().host_of_namespace(&id).cloned();
    let host =
        host.ok_or_else(|| err(StatusCode::NOT_FOUND, "not_found", "namespace not found"))?;
    let path = format!("/v1/namespaces/{id}/quota");
    Ok(forward(&st, &host, Method::GET, &path, &headers, Bytes::new()).await)
}

/// Removes a namespace's gateway on its host; a namespace the fleet never placed has none.
pub(super) async fn delete_gateway(
    State(st): S,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Refusal> {
    let host = st.reg.lock().unwrap().host_of_namespace(&id).cloned();
    let Some(host) = host else {
        return Ok(StatusCode::NO_CONTENT.into_response());
    };
    let path = format!("/v1/namespaces/{id}/gateway");
    Ok(forward(&st, &host, Method::DELETE, &path, &headers, Bytes::new()).await)
}

/// Releases a namespace from its host without touching the host: its next machine is placed
/// afresh. For the operator moving a namespace (backups, then a restore elsewhere) or freeing
/// one stuck on a host that is full or gone.
pub(super) async fn unpin_namespace(
    State(st): S,
    Path(id): Path<String>,
) -> Result<Response, Refusal> {
    st.reg.lock().unwrap().unpin(&id);
    st.save().await.map_err(registry_error)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
