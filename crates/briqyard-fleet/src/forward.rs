//! The machine API, forwarded to the host that owns the namespace.

use super::*;

/// A host that stopped answering is not asked: its machines are unreachable until it is back.
pub(super) fn down(host: &HostRec) -> Option<Response> {
    (host.state == "down").then(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "host_down",
            format!(
                "host {} is down: its machines answer again once it does",
                host.id
            ),
        )
        .into_response()
    })
}

/// A request to a host, with the caller's content type and `If-Match` and the host's token,
/// through the client of its pinned certificate (ADR 0020).
pub(super) fn to_host(
    st: &AppState,
    host: &HostRec,
    method: Method,
    path: &str,
    headers: &HeaderMap,
) -> Result<reqwest::RequestBuilder, Refusal> {
    let url = format!("{}{}", host.url.trim_end_matches('/'), path);
    let client = st.client(host).map_err(|e| {
        err(
            StatusCode::BAD_GATEWAY,
            "host_unreachable",
            format!("host {}: a client for its certificate: {e}", host.id),
        )
    })?;
    let mut req = client.request(method, &url);
    for h in [header::CONTENT_TYPE, header::IF_MATCH] {
        if let Some(v) = headers.get(&h) {
            req = req.header(h, v);
        }
    }
    if !host.token.is_empty() {
        req = req.bearer_auth(&host.token);
    }
    Ok(req)
}

pub(super) async fn forward(
    st: &AppState,
    host: &HostRec,
    method: Method,
    path: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(refused) = down(host) {
        return refused;
    }
    if matches!(method, Method::POST | Method::PATCH)
        && path.starts_with("/v1/machines")
        && serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .is_some_and(|doc| doc["egress"]["siblings"] == true)
    {
        if let Err(refusal) = require_siblings(host) {
            return refusal.into_response();
        }
    }
    let req = match to_host(st, host, method, path, headers) {
        Ok(r) => r.body(body).timeout(FORWARD_TIMEOUT),
        Err(refused) => return refused.into_response(),
    };
    match req.send().await {
        Ok(resp) => relay(resp, host).await,
        Err(e) => unreachable_host(host, e),
    }
}

/// A host's answer as the fleet's: its status, body, content type and request id, and the
/// host's id.
pub(super) async fn relay(resp: reqwest::Response, host: &HostRec) -> Response {
    let status = resp.status();
    let ct = resp.headers().get(header::CONTENT_TYPE).cloned();
    let rid = resp.headers().get("x-request-id").cloned();
    // A body cut short is a host that did not answer, never its status with half a body.
    let data = match resp.bytes().await {
        Ok(data) => data,
        Err(e) => return unreachable_host(host, e),
    };
    let mut out = Response::new(Body::from(data));
    *out.status_mut() = status;
    if let Some(ct) = ct {
        out.headers_mut().insert(header::CONTENT_TYPE, ct);
    }
    if let Some(rid) = rid {
        out.headers_mut().insert("x-request-id", rid);
    }
    out.headers_mut()
        .insert("x-briqyard-host", host_header(host));
    out
}

pub(super) fn host_header(host: &HostRec) -> HeaderValue {
    HeaderValue::from_str(&host.id).unwrap_or(HeaderValue::from_static("?"))
}

/// A host that did not answer: its id and why, never the URL (a session's query holds its env).
pub(super) fn unreachable_host(host: &HostRec, e: reqwest::Error) -> Response {
    err(
        StatusCode::BAD_GATEWAY,
        "host_unreachable",
        format!("host {}: {}", host.id, causes(&e.without_url())),
    )
    .into_response()
}

/// The headers of a WebSocket handshake, passed through both ways as they are.
pub(super) const UPGRADE_HEADERS: [header::HeaderName; 7] = [
    header::CONNECTION,
    header::UPGRADE,
    header::SEC_WEBSOCKET_KEY,
    header::SEC_WEBSOCKET_VERSION,
    header::SEC_WEBSOCKET_PROTOCOL,
    header::SEC_WEBSOCKET_EXTENSIONS,
    header::SEC_WEBSOCKET_ACCEPT,
];

/// An exec session (ADR 0029) forwarded unchanged: the client's handshake goes to the
/// machine's host with the host's token; the host's `101` comes back, and from then on the
/// bytes are copied both ways until either side closes. Any other answer is relayed as it is.
pub(super) async fn exec_session(
    State(st): S,
    Path(id): Path<String>,
    mut req: Request,
) -> Result<Response, Refusal> {
    let client = req
        .extensions_mut()
        .remove::<hyper::upgrade::OnUpgrade>()
        .ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "invalid",
                format!("a session is a WebSocket upgrade of GET /v1/machines/{id}/exec"),
            )
        })?;
    let host = locate(&st, Indexed::Machine, &id)
        .await
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "not_found", "machine not found"))?;
    if let Some(refused) = down(&host) {
        return Ok(refused);
    }
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();
    let mut to = to_host(&st, &host, Method::GET, &path, req.headers())?;
    for h in &UPGRADE_HEADERS {
        if let Some(v) = req.headers().get(h) {
            to = to.header(h, v);
        }
    }
    let resp = match to.send().await {
        Ok(r) => r,
        Err(e) => return Ok(unreachable_host(&host, e)),
    };
    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Ok(relay(resp, &host).await);
    }
    let mut out = Response::new(Body::empty());
    *out.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    for h in &UPGRADE_HEADERS {
        if let Some(v) = resp.headers().get(h) {
            out.headers_mut().insert(h, v.clone());
        }
    }
    out.headers_mut()
        .insert("x-briqyard-host", host_header(&host));
    let machine = id.clone();
    tokio::spawn(async move {
        let (client, upstream) = match (client.await, resp.upgrade().await) {
            (Ok(c), Ok(u)) => (c, u),
            (c, u) => {
                let why = c
                    .err()
                    .map(|e| e.to_string())
                    .or(u.err().map(|e| causes(&e.without_url())));
                tracing::warn!(machine, err = why.unwrap_or_default(), "session upgrade");
                return;
            }
        };
        let mut client = hyper_util::rt::TokioIo::new(client);
        let mut upstream = upstream;
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    });
    Ok(out)
}

/// A watch forwarded: the host's answer streamed through as it comes, with no deadline (its
/// heartbeat shows it is alive).
pub(super) async fn forward_watch(
    st: &AppState,
    host: &HostRec,
    path: &str,
    headers: &HeaderMap,
) -> Response {
    if let Some(refused) = down(host) {
        return refused;
    }
    let req = match to_host(st, host, Method::GET, path, headers) {
        Ok(r) => r,
        Err(refused) => return refused.into_response(),
    };
    match req.send().await {
        Ok(resp) => {
            let status = resp.status();
            let ct = resp.headers().get(header::CONTENT_TYPE).cloned();
            let mut out = Response::new(Body::from_stream(resp.bytes_stream()));
            *out.status_mut() = status;
            if let Some(ct) = ct {
                out.headers_mut().insert(header::CONTENT_TYPE, ct);
            }
            out.headers_mut()
                .insert("x-briqyard-host", host_header(host));
            out
        }
        Err(e) => unreachable_host(host, e),
    }
}

/// An error and its sources, as one line: a refused certificate is two levels under reqwest's
/// "error sending request".
pub(super) fn causes(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut next = e.source();
    while let Some(s) = next {
        out.push_str(": ");
        out.push_str(&s.to_string());
        next = s.source();
    }
    out
}

/// A forwarded response, its body read so it can be looked at and sent on.
pub(super) async fn read(resp: Response) -> (axum::http::response::Parts, Bytes) {
    let (parts, body) = resp.into_parts();
    let data = axum::body::to_bytes(body, 64 << 20)
        .await
        .unwrap_or_default();
    (parts, data)
}

/// Adds the host id to a machine JSON body.
pub(super) fn with_host(body: Bytes, host: &str) -> Bytes {
    with_field(body, "host", host)
}

/// Sets a field of a JSON object body; any other body is sent on as it is.
pub(super) fn with_field(body: Bytes, key: &str, value: &str) -> Bytes {
    match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(mut v) if v.is_object() => {
            v[key] = serde_json::Value::String(value.into());
            Bytes::from(serde_json::to_vec(&v).unwrap_or_default())
        }
        _ => body,
    }
}

/// The `code` of an error body, empty when it is not one.
pub(super) fn error_code(body: &[u8]) -> String {
    serde_json::from_slice::<api::ApiError>(body)
        .map(|e| e.code)
        .unwrap_or_default()
}

/// Raw files are streamed in both directions without the JSON forwarding body's limit.
pub(super) async fn file_stream(
    State(st): S,
    Path(id): Path<String>,
    req: Request,
) -> Result<Response, Refusal> {
    use briqyard_api::files as wire;
    let host = locate(&st, Indexed::Machine, &id)
        .await
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "not_found", "machine not found"))?;
    if let Some(refused) = down(&host) {
        return Ok(refused);
    }
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or_default();
    let mut to = to_host(&st, &host, req.method().clone(), path, req.headers())?;
    if req.method() == Method::PUT {
        if let Some(value) = req.headers().get(header::CONTENT_LENGTH) {
            let length = value
                .to_str()
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "invalid", "invalid Content-Length"))?;
            wire::check_size(length).map_err(|e| err(StatusCode::BAD_REQUEST, "invalid", e))?;
            to = to.header(header::CONTENT_LENGTH, length);
        }
    }
    let to = to
        .body(reqwest::Body::wrap_stream(
            req.into_body().into_data_stream(),
        ))
        .timeout(std::time::Duration::from_secs(wire::TRANSFER_SEC));
    let resp = match to.send().await {
        Ok(r) => r,
        Err(e) => return Ok(unreachable_host(&host, e)),
    };
    if !resp.status().is_success() {
        return Ok(relay(resp, &host).await);
    }
    let mut out = Response::new(Body::empty());
    *out.status_mut() = resp.status();
    for name in [
        header::CONTENT_TYPE,
        header::CONTENT_LENGTH,
        header::HeaderName::from_static("x-request-id"),
    ] {
        if let Some(value) = resp.headers().get(&name) {
            out.headers_mut().insert(name, value.clone());
        }
    }
    out.headers_mut()
        .insert("x-briqyard-host", host_header(&host));
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        use futures::StreamExt;
        let transfer = async {
            let mut stream = resp.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let failed = chunk.is_err();
                if tx.send(chunk).await.is_err() || failed {
                    break;
                }
            }
        };
        tokio::select! {
            _ = tx.closed() => {},
            _ = tokio::time::timeout(std::time::Duration::from_secs(wire::TRANSFER_SEC), transfer) => {},
        }
    });
    *out.body_mut() = Body::from_stream(futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|chunk| (chunk, rx))
    }));
    Ok(out)
}

/// Missing capability means legacy semantics, never inferred from a version label.
pub(super) fn require_siblings(host: &HostRec) -> Result<(), Refusal> {
    if !host.egress_siblings_v1 {
        return Err(err(
            StatusCode::CONFLICT,
            "capability_unsupported",
            format!("host {} does not support egress.siblings", host.id),
        ));
    }
    Ok(())
}
