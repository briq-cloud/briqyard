//! A durable, sequential host drain built from namespace jobs.
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct HostEvacuation {
    pub host: String,
    pub namespaces: Vec<String>,
    pub completed: Vec<String>,
    pub current: Option<String>,
    pub to: Option<String>,
    pub drop_snapshots: bool,
    pub error: Option<String>,
}

pub(crate) async fn get_host(
    State(st): S,
    Path(id): Path<String>,
) -> Result<Json<HostEvacuation>, Refusal> {
    st.reg
        .lock()
        .unwrap()
        .host_evacuations
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or_else(|| {
            err(
                StatusCode::NOT_FOUND,
                "not_found",
                "host evacuation not found",
            )
        })
}

pub(crate) async fn start_host(
    State(st): S,
    Path(id): Path<String>,
    Json(request): Json<EvacuateRequest>,
) -> Result<(StatusCode, Json<HostEvacuation>), Refusal> {
    let guard = st.authority.write().await;
    let source = io::host(&st, &id)
        .map_err(|_| err(StatusCode::NOT_FOUND, "not_found", "host not found"))?;
    if !matches!(source.state.as_str(), "ready" | "draining") {
        return Err(err(
            StatusCode::CONFLICT,
            "host_unavailable",
            "host must be ready or draining",
        ));
    }
    io::capable(&st, &source).await.map_err(|e| {
        err(
            StatusCode::CONFLICT,
            "capability_unsupported",
            format!("{e:#}"),
        )
    })?;
    // Read the daemon, rather than trusting a possibly stale heartbeat's namespace list.
    let namespaces: Vec<api::Namespace> = serde_json::from_value(
        io::call(
            &st,
            &source,
            "",
            Method::GET,
            "/v1/namespaces",
            serde_json::Value::Null,
        )
        .await
        .map_err(registry_error)?,
    )
    .map_err(|e| err(StatusCode::BAD_GATEWAY, "host_unreachable", e.to_string()))?;
    let job = {
        let mut reg = st.reg.lock().unwrap();
        reg.hosts.get_mut(&id).unwrap().state = "draining".into();
        let job = reg
            .host_evacuations
            .entry(id.clone())
            .or_insert_with(|| HostEvacuation {
                host: id.clone(),
                namespaces: Vec::new(),
                completed: Vec::new(),
                current: None,
                to: request.to.clone(),
                drop_snapshots: request.drop_snapshots,
                error: None,
            });
        if job.to != request.to || job.drop_snapshots != request.drop_snapshots {
            return Err(err(
                StatusCode::CONFLICT,
                "conflict",
                "resume a host evacuation with the same placement and snapshot options",
            ));
        }
        for ns in namespaces {
            if !job.namespaces.contains(&ns.id) {
                job.namespaces.push(ns.id);
            }
        }
        job.namespaces.sort();
        job.error = None;
        job.clone()
    };
    st.save().await.map_err(registry_error)?;
    drop(guard);
    launch_host(st, id);
    Ok((StatusCode::ACCEPTED, Json(job)))
}

pub(crate) fn launch_host(st: Arc<AppState>, id: String) {
    let worker = format!("host:{id}");
    if !st.evacuation_workers.lock().unwrap().insert(worker.clone()) {
        return;
    }
    tokio::spawn(async move {
        if let Err(error) = run_host(&st, &id).await {
            if let Some(job) = st.reg.lock().unwrap().host_evacuations.get_mut(&id) {
                job.error = Some(format!("{error:#}"));
            }
            let _ = st.save().await;
        }
        st.evacuation_workers.lock().unwrap().remove(&worker);
    });
}

async fn run_host(st: &Arc<AppState>, id: &str) -> Result<()> {
    let job = st
        .reg
        .lock()
        .unwrap()
        .host_evacuations
        .get(id)
        .cloned()
        .ok_or_else(|| anyhow!("host journal missing"))?;
    for namespace in job
        .namespaces
        .iter()
        .filter(|ns| !job.completed.contains(ns))
    {
        st.reg
            .lock()
            .unwrap()
            .host_evacuations
            .get_mut(id)
            .unwrap()
            .current = Some(namespace.clone());
        st.save().await?;
        let existing = st.reg.lock().unwrap().evacuations.get(namespace).cloned();
        if let Some(existing) =
            existing.filter(|j| j.from == id && (j.active() || j.step == "done"))
        {
            if existing.active() {
                io::checkpoint(st, namespace, |j| j.error = None).await?;
                driver::launch(st.clone(), namespace.clone());
            }
        } else {
            let _accepted = routes::start(
                State(st.clone()),
                Path(namespace.clone()),
                Json(EvacuateRequest {
                    to: job.to.clone(),
                    drop_snapshots: job.drop_snapshots,
                }),
            )
            .await
            .map_err(|e| anyhow!("namespace {namespace}: {}", e.error))?;
        }
        loop {
            let changed = st.evacuation_changed.notified();
            // Register before observing state, so a checkpoint cannot be lost.
            tokio::pin!(changed);
            changed.as_mut().enable();
            let current = io::journal(st, namespace)?;
            if let Some(error) = current.error {
                return Err(anyhow!("namespace {namespace}: {error}"));
            }
            if current.step == "done" {
                break;
            }
            if !current.active() {
                return Err(anyhow!("namespace {namespace}: {}", current.step));
            }
            changed.await;
        }
        st.reg
            .lock()
            .unwrap()
            .host_evacuations
            .get_mut(id)
            .unwrap()
            .completed
            .push(namespace.clone());
        st.save().await?;
    }
    st.reg
        .lock()
        .unwrap()
        .host_evacuations
        .get_mut(id)
        .unwrap()
        .current = None;
    st.save().await
}
