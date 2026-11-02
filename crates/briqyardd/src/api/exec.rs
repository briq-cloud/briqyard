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

/// Versioned sessions carry command fields in the first frame, never in the URL.
pub(super) async fn exec_stream_v1(
    State(st): S,
    Path(id): Path<String>,
    RawQuery(query): RawQuery,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Result<Response, AppError> {
    if query.is_some() {
        return Err(MError::Invalid("exec stream does not accept query parameters".into()).into());
    }
    // Authenticate and establish ownership before upgrading, without starting a command.
    let _ = st.mgr.in_use(&id)?;
    let ws = ws.map_err(|_| MError::Invalid("exec stream requires a WebSocket upgrade".into()))?;
    Ok(ws
        .max_message_size(api::session::stream::MAX_MESSAGE)
        .max_frame_size(api::session::stream::MAX_MESSAGE)
        .on_upgrade(move |mut socket| async move {
            use axum::extract::ws::Message;
            use futures::StreamExt;
            let start = tokio::time::timeout(Duration::from_secs(10), socket.next()).await;
            let request = match start {
                Ok(Some(Ok(Message::Text(text)))) => {
                    serde_json::from_str::<api::session::stream::Start>(&text).ok()
                }
                _ => None,
            };
            let result = match request {
                Some(req) => st.mgr.open_exec_stream_v1(&id, req).await,
                None => Err(MError::Invalid(
                    "expected initial exec stream request".into(),
                )),
            };
            match result {
                Ok(session) => {
                    let (tx, rx) = socket.split();
                    let _ =
                        crate::session::pump_stream(rx, tx, session.conn, crate::events::HEARTBEAT)
                            .await;
                    drop(session.in_use);
                }
                Err(error) => {
                    let end = exec_stream_refusal(error);
                    let payload = serde_json::to_vec(&end).unwrap_or_default();
                    let _ = socket
                        .send(Message::Binary(api::session::message(
                            api::session::channel::EXIT,
                            &payload,
                        )))
                        .await;
                    let _ = socket.send(Message::Close(None)).await;
                }
            }
        }))
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

/// Capability refusal has a typed cause; ordinary conflicts are never unsupported.
fn exec_stream_refusal(error: MError) -> api::session::SessionEnd {
    let code = match &error {
        MError::ExecStreamUnsupported => "unsupported",
        MError::Invalid(_) => "invalid",
        MError::NotRunning(_) => "not_running",
        _ => "exec_stream_refused",
    };
    api::session::SessionEnd::failed(code, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_stream_refusal_preserves_typed_capability_and_ordinary_errors() {
        let cases = [
            (MError::ExecStreamUnsupported, "unsupported"),
            (MError::Invalid("bad timeout".into()), "invalid"),
            (MError::NotRunning("stopped".into()), "not_running"),
            // Even identical prose cannot turn an ordinary conflict into unsupported.
            (
                MError::Conflict("running guest does not support exec_stream_v1".into()),
                "exec_stream_refused",
            ),
            (
                MError::Other(anyhow::anyhow!("transport failure")),
                "exec_stream_refused",
            ),
        ];
        for (error, code) in cases {
            let expected_message = error.to_string();
            let terminal = exec_stream_refusal(error);
            assert_eq!(terminal.code, code);
            assert_eq!(terminal.error, expected_message);
            assert!(terminal.exit_code.is_none());
            assert!(!terminal.cancelled);
            let value = serde_json::to_value(terminal).unwrap();
            assert_eq!(
                value,
                serde_json::json!({"code":code, "error":expected_message})
            );
        }
    }
}
