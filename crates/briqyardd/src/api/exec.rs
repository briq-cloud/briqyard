//! Waiting on a machine, exec, files and logs.

use super::*;

#[derive(Deserialize)]
pub(super) struct WaitQuery {
    timeout: Option<u64>,
    /// `ready` (the default) or `running`.
    #[serde(rename = "for")]
    until: Option<String>,
}

/// What a `/wait` waits for: `ready` unless asked for `running` (ADR 0022).
pub(super) fn wait_until(asked: Option<&str>) -> Result<Until, MError> {
    match asked {
        None | Some("ready") => Ok(Until::Ready),
        Some("running") => Ok(Until::Running),
        Some(other) => Err(MError::Invalid(format!(
            "for {other:?}: want \"ready\" or \"running\""
        ))),
    }
}

pub(super) async fn wait_machine(
    State(st): S,
    Path(id): Path<String>,
    Query(q): Query<WaitQuery>,
) -> Result<Json<api::Machine>, AppError> {
    let until = wait_until(q.until.as_deref())?;
    Ok(Json(
        st.mgr.wait(&id, until, wait_timeout(q.timeout)).await?,
    ))
}

pub(super) async fn exec(
    State(st): S,
    Path(id): Path<String>,
    Json(mut req): Json<api::ExecRequest>,
) -> Result<Json<api::ExecResult>, AppError> {
    if req.cmd.is_empty() {
        return Err(MError::Invalid("cmd is required".into()).into());
    }
    req.timeout_ms = exec_timeout_ms(req.timeout_ms);
    Ok(Json(st.mgr.exec(&id, req).await?))
}

/// The largest message a session takes: its stdin frame, base64 in JSON, stays under the
/// guest protocol's largest frame.
const MAX_SESSION_MESSAGE: usize = 1 << 20;

/// An exec session (ADR 0029): the command starts, the machine woken first when asked, then
/// the upgrade; every refusal before it is an HTTP answer like any other.
pub(super) async fn exec_session(
    State(st): S,
    Path(id): Path<String>,
    RawQuery(query): RawQuery,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Result<Response, AppError> {
    let ws = ws.map_err(|e| {
        MError::Invalid(format!(
            "a session is a WebSocket upgrade of GET /v1/machines/{id}/exec: {e}"
        ))
    })?;
    let pairs = url::form_urlencoded::parse(query.as_deref().unwrap_or("").as_bytes());
    let mut req = api::session::ExecSession::from_query(pairs).map_err(MError::Invalid)?;
    req.timeout_ms = exec_timeout_ms(req.timeout_ms);
    let session = st.mgr.open_session(&id, req).await?;
    Ok(ws
        .max_message_size(MAX_SESSION_MESSAGE)
        .max_frame_size(MAX_SESSION_MESSAGE)
        .on_upgrade(move |socket| crate::session::serve(socket, session)))
}

pub(super) async fn put_file(
    State(st): S,
    Path(id): Path<String>,
    Json(req): Json<api::PutFileRequest>,
) -> Result<StatusCode, AppError> {
    st.mgr.put_file(&id, req).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub(super) struct FileQuery {
    path: String,
}

pub(super) async fn get_file(
    State(st): S,
    Path(id): Path<String>,
    Query(q): Query<FileQuery>,
) -> Result<Json<api::FileResponse>, AppError> {
    let data = st.mgr.get_file(&id, &q.path).await?;
    Ok(Json(api::FileResponse {
        path: q.path,
        base64: api::guest::base64_encode(&data),
    }))
}

#[derive(Deserialize)]
pub(super) struct LogsQuery {
    since: Option<String>,
    limit: Option<usize>,
    #[serde(default)]
    follow: bool,
}

/// A page of the console; with `follow=true`, the lines and each new one as NDJSON, kept open
/// (ADR 0025).
pub(super) async fn logs(
    State(st): S,
    Path(id): Path<String>,
    Query(q): Query<LogsQuery>,
) -> Result<Response, AppError> {
    let since = q.since.as_deref().unwrap_or("");
    if !q.follow {
        return Ok(Json(st.mgr.logs(&id, since, log_limit(q.limit))?).into_response());
    }
    let (tx, rx) = tokio::sync::mpsc::channel::<String>(16);
    st.mgr.follow_logs(&id, since, tx)?;
    Ok(ndjson(rx))
}

/// A stream of lines as `application/x-ndjson`, until the sender is dropped.
pub(super) fn ndjson(rx: tokio::sync::mpsc::Receiver<String>) -> Response {
    let lines = futures::stream::unfold(rx, |mut rx| async move {
        rx.recv()
            .await
            .map(|l| (Ok::<_, std::convert::Infallible>(l), rx))
    });
    (
        [(header::CONTENT_TYPE, "application/x-ndjson")],
        Body::from_stream(lines),
    )
        .into_response()
}
