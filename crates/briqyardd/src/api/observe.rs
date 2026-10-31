//! Status, metrics and what the daemon reports about its machines.

use super::*;

pub(super) async fn openapi(State(st): S) -> Response {
    ([(header::CONTENT_TYPE, "application/yaml")], st.openapi).into_response()
}

pub(super) async fn metrics(State(st): S) -> Response {
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        st.mgr.metrics(),
    )
        .into_response()
}

pub(super) async fn status(State(st): S) -> Json<api::Status> {
    let (used, running, machines) = st.mgr.usage();
    Json(api::Status {
        egress_siblings_v1: true,
        named_memory_fork_v1: false,
        version: api::VERSION.into(),
        host_id: st.mgr.host_id().into(),
        capacity: st.mgr.capacity(),
        used,
        machines,
        running,
        disk_free_mb: st.mgr.disk_free_mb().await,
        tls_fingerprint: st.tls_fingerprint.clone(),
        conditions: st.mgr.conditions(),
        started: Some(st.mgr.started()),
        vmm_version: st.mgr.vmm_version(),
        regions: Vec::new(),
    })
}

pub(super) async fn stats(
    State(st): S,
    Path(id): Path<String>,
) -> Result<Json<api::MachineStats>, AppError> {
    Ok(Json(st.mgr.stats(&id).await?))
}

/// The running machines' use over the tick's last window (ADR 0021).
pub(super) async fn top(State(st): S, Query(q): Query<ListQuery>) -> Json<Vec<api::TopMachine>> {
    Json(st.mgr.top(q.namespace.as_deref()))
}

#[derive(Deserialize)]
pub(super) struct UsageQuery {
    pub(super) from: Option<String>,
    pub(super) to: Option<String>,
    #[serde(alias = "tenant")]
    pub(super) namespace: Option<String>,
}

/// The usage buckets of a range of hours (ADR 0017).
pub(super) async fn usage(
    State(st): S,
    Query(q): Query<UsageQuery>,
) -> Result<Json<Vec<api::UsageBucket>>, AppError> {
    let (from, to) =
        crate::usage::range(q.from.as_deref(), q.to.as_deref()).map_err(MError::Invalid)?;
    Ok(Json(st.mgr.usage_buckets(from, to, q.namespace).await?))
}

#[derive(Deserialize)]
pub(super) struct EventsQuery {
    since: Option<String>,
    #[serde(alias = "tenant")]
    namespace: Option<String>,
    machine: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    limit: Option<usize>,
    #[serde(default)]
    watch: bool,
}

/// The query's cursor and filter, checked: a seq (absent is 0), ids, a type.
fn events_query(q: EventsQuery) -> Result<(u64, Filter), MError> {
    let since = match q.since.as_deref() {
        None | Some("") => 0,
        Some(s) => s
            .parse()
            .map_err(|_| MError::Invalid(format!("since {s:?}: want a seq, a page's `next`")))?,
    };
    for id in [&q.namespace, &q.machine].into_iter().flatten() {
        if !api::valid_id(id) {
            return Err(MError::Invalid(format!("{id:?} is not an id")));
        }
    }
    if let Some(k) = &q.kind {
        if k != api::event::NORMAL && k != api::event::WARNING {
            return Err(MError::Invalid(format!(
                "type {k:?}: want \"normal\" or \"warning\""
            )));
        }
    }
    let f = Filter {
        namespace: q.namespace,
        machine: q.machine,
        kind: q.kind,
    };
    Ok((since, f))
}

/// Events after a cursor (ADR 0019); with `watch=true`, those and each new one, kept open as
/// NDJSON.
pub(super) async fn events(
    State(st): S,
    Query(q): Query<EventsQuery>,
) -> Result<Response, AppError> {
    let (watch, limit) = (q.watch, api::events_limit(q.limit));
    let (since, f) = events_query(q)?;
    if !watch {
        return Ok(Json(st.mgr.events_page(since, f, limit).await?).into_response());
    }
    let (tx, rx) = tokio::sync::mpsc::channel::<String>(16);
    st.mgr
        .events()
        .watch(since, f, tx)
        .await
        .map_err(crate::machine::gone)?;
    Ok(ndjson(rx))
}
