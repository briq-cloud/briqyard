//! Machines: list, create, update and their lifecycle.

use super::*;

#[derive(Deserialize)]
pub(super) struct ListQuery {
    #[serde(alias = "tenant")]
    pub(super) namespace: Option<String>,
}

/// A listing's query: the namespace, and the label selectors, each `label=` one (ADR 0025).
pub(super) fn list_query(query: Option<&str>) -> Result<(Option<String>, Vec<api::Label>), MError> {
    let (mut namespace, mut labels) = (None, Vec::new());
    for (k, v) in url::form_urlencoded::parse(query.unwrap_or("").as_bytes()) {
        match k.as_ref() {
            "namespace" | "tenant" => namespace = Some(v.into_owned()),
            "label" => labels.push(api::Label::parse(&v).map_err(MError::Invalid)?),
            _ => {}
        }
    }
    Ok((namespace, labels))
}

pub(super) async fn list_machines(
    State(st): S,
    RawQuery(query): RawQuery,
) -> Result<Json<Vec<api::Machine>>, AppError> {
    let (namespace, labels) = list_query(query.as_deref())?;
    Ok(Json(st.mgr.list(namespace.as_deref(), &labels)))
}

// Every transition runs through `detached`: axum drops a handler's future when the client
// hangs up, and a create, start, stop or destroy cut short would leave the machine half-moved.

/// 201 once the machine is recorded, in `creating` (ADR 0048): its image, disks and start
/// follow; `/wait` waits for them.
pub(super) async fn create_machine(
    State(st): S,
    Json(req): Json<api::CreateMachineRequest>,
) -> Result<(StatusCode, Json<api::Machine>), AppError> {
    let m = st.mgr.clone();
    let made = detached(async move { m.create(req).await }).await?;
    Ok((StatusCode::CREATED, Json(made)))
}

pub(super) async fn get_machine(
    State(st): S,
    Path(id): Path<String>,
) -> Result<Json<api::Machine>, AppError> {
    Ok(Json(st.mgr.get(&id)?))
}

/// `If-Match: <version>` (ADR 0019), the quotes of an HTTP entity tag allowed; absent is no
/// condition.
pub(super) fn if_match(headers: &HeaderMap) -> Result<Option<u64>, AppError> {
    let Some(v) = headers.get(header::IF_MATCH) else {
        return Ok(None);
    };
    let text = v.to_str().unwrap_or("").trim().trim_matches('"');
    match text.parse() {
        Ok(n) => Ok(Some(n)),
        Err(_) => Err(MError::Invalid(format!(
            "If-Match {text:?}: want a machine's version, a number"
        ))
        .into()),
    }
}

pub(super) async fn update_machine(
    State(st): S,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<api::UpdateMachineRequest>,
) -> Result<Json<api::Machine>, AppError> {
    let at = if_match(&headers)?;
    // Detached too: a policy swap cut short between its two steps would leave none.
    let m = st.mgr.clone();
    Ok(Json(
        detached(async move { m.update(&id, req, at).await }).await?,
    ))
}

pub(super) async fn destroy_machine(
    State(st): S,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, AppError> {
    let at = if_match(&headers)?;
    let m = st.mgr.clone();
    detached(async move { m.destroy(&id, at).await }).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn start_machine(
    State(st): S,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<api::Machine>, AppError> {
    let at = if_match(&headers)?;
    let m = st.mgr.clone();
    Ok(Json(detached(async move { m.start(&id, at).await }).await?))
}

pub(super) async fn wake_machine(
    State(st): S,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<api::Machine>, AppError> {
    let at = if_match(&headers)?;
    let m = st.mgr.clone();
    Ok(Json(detached(async move { m.wake(&id, at).await }).await?))
}

pub(super) async fn stop_machine(
    State(st): S,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Option<Json<api::StopRequest>>,
) -> Result<Json<api::Machine>, AppError> {
    let at = if_match(&headers)?;
    let req = body.map(|b| b.0).unwrap_or_default();
    let m = st.mgr.clone();
    Ok(Json(
        detached(async move {
            m.stop(&id, stop_timeout(req.timeout_sec), req.suspend, at)
                .await
        })
        .await?,
    ))
}

pub(super) async fn restart_machine(
    State(st): S,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<api::Machine>, AppError> {
    let at = if_match(&headers)?;
    let m = st.mgr.clone();
    Ok(Json(
        detached(async move { m.restart(&id, at).await }).await?,
    ))
}

pub(super) async fn move_machine(
    State(st): S,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<api::MoveRequest>,
) -> Result<Json<api::MoveResult>, AppError> {
    let at = if_match(&headers)?;
    let m = st.mgr.clone();
    Ok(Json(
        detached(async move { m.move_machine(&id, &req.namespace, at).await }).await?,
    ))
}

pub(super) async fn touch_machine(
    State(st): S,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    st.mgr.touch(&id)?;
    Ok(StatusCode::NO_CONTENT)
}
