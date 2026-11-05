use super::*;
use io::*;

#[derive(Default, Deserialize)]
pub(crate) struct EvacuateRequest {
    pub to: Option<String>,
    #[serde(default)]
    pub drop_snapshots: bool,
}

pub(crate) async fn list(State(st): S) -> Json<Vec<Evacuation>> {
    let mut jobs: Vec<_> = st
        .reg
        .lock()
        .unwrap()
        .evacuations
        .values()
        .cloned()
        .collect();
    jobs.sort_by_key(|j| j.started);
    Json(jobs)
}

pub(crate) async fn start(
    State(st): S,
    Path(namespace): Path<String>,
    Json(request): Json<EvacuateRequest>,
) -> Result<(StatusCode, Json<Evacuation>), Refusal> {
    if !api::valid_id(&namespace) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid", "invalid namespace"));
    }
    // Finish outstanding fleet mutations before observing the source. While this
    // guard is held no create, move, admission or listing can cross job planning.
    let guard = st.authority.write().await;
    let job = plan(&st, &namespace, request).await?;
    {
        let mut reg = st.reg.lock().unwrap();
        reg.namespaces.insert(namespace.clone(), job.from.clone());
        for m in &job.machines {
            reg.machines.insert(m.id.clone(), job.from.clone());
        }
        for e in &job.endpoints {
            reg.endpoints.insert(e.id.clone(), job.from.clone());
        }
        reg.evacuations.insert(namespace.clone(), job.clone());
        driver::reserve(&mut reg, &namespace);
    }
    st.save().await.map_err(registry_error)?;
    drop(guard);
    driver::launch(st, namespace);
    Ok((StatusCode::ACCEPTED, Json(job)))
}

async fn plan(
    st: &AppState,
    namespace: &str,
    request: EvacuateRequest,
) -> Result<Evacuation, Refusal> {
    let source = {
        let reg = st.reg.lock().unwrap();
        namespace_available(&reg, namespace)?;
        if reg.namespace_inflight(namespace)
            || reg
                .namespace_moves
                .values()
                .any(|m| m.namespace == namespace)
            || create_replay::namespace_unresolved(&reg, namespace)
            || sandbox_admissions::namespace_pending(&reg, namespace)
        {
            return Err(err(
                StatusCode::CONFLICT,
                "busy",
                "namespace has an operation in flight",
            ));
        }
        reg.host_of_namespace(namespace)
            .cloned()
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "not_found", "namespace not found"))?
    };
    let unsupported = |error: anyhow::Error| {
        err(
            StatusCode::CONFLICT,
            "capability_unsupported",
            format!("{error:#}"),
        )
    };
    capable(st, &source).await.map_err(unsupported)?;
    let ns: api::Namespace = serde_json::from_value(
        call(
            st,
            &source,
            "",
            Method::GET,
            &format!("/v1/namespaces/{namespace}"),
            serde_json::Value::Null,
        )
        .await
        .map_err(unsupported)?,
    )
    .map_err(|_| {
        err(
            StatusCode::BAD_GATEWAY,
            "host_unreachable",
            "unreadable namespace",
        )
    })?;
    if ns.gateway.is_some() {
        return Err(err(StatusCode::CONFLICT,"gateway","namespaces with a gateway cannot be evacuated in phase 1; its identity, configuration and data must travel together"));
    }
    let machines: Vec<api::Machine> = serde_json::from_value(
        call(
            st,
            &source,
            "",
            Method::GET,
            &format!("/v1/machines?namespace={namespace}"),
            serde_json::Value::Null,
        )
        .await
        .map_err(unsupported)?,
    )
    .map_err(|_| {
        err(
            StatusCode::BAD_GATEWAY,
            "host_unreachable",
            "unreadable machines",
        )
    })?;
    let mut copies = Vec::new();
    let mut endpoints = Vec::new();
    let mut disk_mb = 0u64;
    for m in &machines {
        if m.state != "stopped" {
            return Err(err(
                StatusCode::CONFLICT,
                if m.state == "running" {
                    "running"
                } else {
                    "bad_state"
                },
                format!(
                    "machine {} is {}; phase 1 requires stopped machines",
                    m.id, m.state
                ),
            ));
        }
        let manifest = call(
            st,
            &source,
            "",
            Method::GET,
            &format!("/v1/machines/{}/evacuation-manifest", m.id),
            serde_json::Value::Null,
        )
        .await
        .map_err(unsupported)?;
        if manifest["host_local"] == true {
            return Err(err(StatusCode::CONFLICT,"host_local","seeds, warm slots, templates and assigned clones must be built on the target instead"));
        }
        if !manifest["held"].is_null() {
            return Err(err(
                StatusCode::CONFLICT,
                "held",
                format!("machine {} is already held", m.id),
            ));
        }
        let snapshots: Vec<api::Snapshot> = serde_json::from_value(
            call(
                st,
                &source,
                "",
                Method::GET,
                &format!("/v1/machines/{}/snapshots", m.id),
                serde_json::Value::Null,
            )
            .await
            .map_err(unsupported)?,
        )
        .map_err(|_| {
            err(
                StatusCode::BAD_GATEWAY,
                "host_unreachable",
                "unreadable snapshots",
            )
        })?;
        if !snapshots.is_empty() && !request.drop_snapshots {
            return Err(err(
                StatusCode::CONFLICT,
                "snapshots",
                format!("machine {} has snapshots; use --drop-snapshots", m.id),
            ));
        }
        let bytes = manifest["root_bytes"]
            .as_u64()
            .and_then(|root| {
                manifest["data_bytes"]
                    .as_u64()
                    .and_then(|data| root.checked_add(data))
            })
            .ok_or_else(|| {
                err(
                    StatusCode::BAD_GATEWAY,
                    "host_unreachable",
                    "missing logical disk sizes",
                )
            })?;
        disk_mb = disk_mb
            .checked_add(bytes.div_ceil(1 << 20))
            .ok_or_else(|| {
                err(
                    StatusCode::BAD_REQUEST,
                    "invalid",
                    "namespace disks overflow capacity accounting",
                )
            })?;
        copies.push(MachineCopy {
            id: m.id.clone(),
            name: m.name.clone(),
            manifest,
            backup: None,
            restored: false,
            verified: false,
            ip: String::new(),
        });
        endpoints.extend(m.endpoints.clone());
    }
    // A dependency must exist before the daemon validates its consumer's restore.
    let mut ordered = Vec::new();
    let mut pending = machines.iter().collect::<Vec<_>>();
    while !pending.is_empty() {
        let before = pending.len();
        pending.retain(|m| {
            let via = m.egress.via.as_deref().unwrap_or_default();
            if machines
                .iter()
                .any(|dep| (dep.id == via || dep.name == via) && !ordered.contains(&dep.id))
            {
                return true;
            }
            ordered.push(m.id.clone());
            false
        });
        if pending.len() == before {
            return Err(err(
                StatusCode::CONFLICT,
                "egress",
                "namespace egress dependencies contain a cycle",
            ));
        }
    }
    copies.sort_by_key(|m| {
        ordered
            .iter()
            .position(|id| *id == m.id)
            .unwrap_or(usize::MAX)
    });
    let quota: api::NamespaceQuota = serde_json::from_value(
        call(
            st,
            &source,
            "",
            Method::GET,
            &format!("/v1/namespaces/{namespace}/quota"),
            serde_json::Value::Null,
        )
        .await
        .map_err(unsupported)?,
    )
    .map_err(|_| {
        err(
            StatusCode::BAD_GATEWAY,
            "host_unreachable",
            "unreadable quota",
        )
    })?;
    let mut candidates = st.reg.lock().unwrap().ready();
    candidates.retain(|h| {
        h.id != source.id
            && h.state == "ready"
            && h.region == source.region
            && request.to.as_ref().is_none_or(|to| to == &h.id)
    });
    candidates.sort_by_key(|h| std::cmp::Reverse(h.free_memory_mb()));
    let mut shortages = Vec::new();
    let mut chosen = None;
    for target in candidates {
        if target.pressure().is_some()
            || machines.iter().any(|m| {
                target.without_class(namespace, &m.runtime_class).is_some()
                    || (m.egress.siblings && !target.egress_siblings_v1)
            })
        {
            shortages.push(format!(
                "host {}: pressure or required runtime/egress capability missing",
                target.id
            ));
            continue;
        }
        let status = capable(st, &target).await.map_err(unsupported)?;
        let free = status.disk_free_mb.ok_or_else(|| {
            err(
                StatusCode::SERVICE_UNAVAILABLE,
                "no_room",
                format!("host {} does not report disk capacity", target.id),
            )
        })?;
        let accounted = target.disk_free_mb.unwrap_or(0).min(free);
        if accounted < disk_mb {
            shortages.push(format!("host {}: disk shortfall {} MB (need {disk_mb}, free {accounted}); stopped memory 0 MB, CPU 0",target.id,disk_mb-accounted));
            continue;
        }
        let existing = lookup(st, &target, &format!("/v1/namespaces/{namespace}"))
            .await
            .map_err(unsupported)?;
        if existing.is_some() {
            shortages.push(format!(
                "host {} already holds namespace {namespace}",
                target.id
            ));
            continue;
        }
        let mut collision = false;
        for m in &copies {
            if lookup(st, &target, &format!("/v1/machines/{}", m.id))
                .await
                .map_err(unsupported)?
                .is_some()
            {
                collision = true;
                break;
            }
        }
        for ep in &endpoints {
            if lookup(st, &target, &format!("/v1/endpoints/{}", ep.id))
                .await
                .map_err(unsupported)?
                .is_some()
            {
                collision = true;
                break;
            }
        }
        if collision {
            shortages.push(format!(
                "host {} already holds a machine or endpoint id",
                target.id
            ));
            continue;
        }
        chosen = Some(target);
        break;
    }
    let target = chosen.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_room",
            format!(
                "no eligible destination in region {:?} for namespace {namespace}; {}",
                source.region,
                shortages.join("; ")
            ),
        )
    })?;
    let job = format!(
        "ev_{}",
        rand::random::<[u8; 12]>()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    Ok(Evacuation {
        job,
        namespace: namespace.into(),
        from: source.id,
        to: target.id,
        step: "planned".into(),
        machines: copies,
        endpoints,
        quota: quota.quota,
        started: Utc::now(),
        error: None,
        cancel_requested: false,
        drop_snapshots: request.drop_snapshots,
        reservation: 0,
    })
}

pub(crate) async fn resume(
    State(st): S,
    Path(namespace): Path<String>,
) -> Result<StatusCode, Refusal> {
    if !st
        .reg
        .lock()
        .unwrap()
        .evacuations
        .get(&namespace)
        .is_some_and(Evacuation::active)
    {
        return Err(err(
            StatusCode::NOT_FOUND,
            "not_found",
            "no open evacuation",
        ));
    }
    driver::launch(st, namespace);
    Ok(StatusCode::ACCEPTED)
}

pub(crate) async fn cancel(
    State(st): S,
    Path(namespace): Path<String>,
) -> Result<StatusCode, Refusal> {
    let _guard = st.authority.write().await;
    {
        let mut reg = st.reg.lock().unwrap();
        let job = reg
            .evacuations
            .get_mut(&namespace)
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "not_found", "evacuation not found"))?;
        if job.switched() {
            return Err(err(
                StatusCode::CONFLICT,
                "switched",
                "cannot cancel after the authority switch",
            ));
        }
        if !job.active() {
            return Ok(StatusCode::NO_CONTENT);
        }
        job.cancel_requested = true;
    }
    st.save().await.map_err(registry_error)?;
    drop(_guard);
    driver::launch(st, namespace);
    Ok(StatusCode::ACCEPTED)
}
