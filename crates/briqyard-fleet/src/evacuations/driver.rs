use super::*;
use io::*;

/// Reinstall conservative reservations before serving after a fleet restart. Reports
/// reapply these holds until every restore has settled; restored bytes may be counted
/// twice during copying, which reduces placement rather than overcommitting the pool.
pub(crate) fn reserve(reg: &mut Registry, namespace: &str) {
    let Some(job) = reg.evacuations.get(namespace) else {
        return;
    };
    if !job.active() || job.switched() || job.machines.iter().all(|m| m.restored) {
        return;
    }
    let to = job.to.clone();
    let disk = job
        .machines
        .iter()
        .map(|m| {
            (m.manifest["root_bytes"].as_u64().unwrap_or(0)
                + m.manifest["data_bytes"].as_u64().unwrap_or(0))
            .div_ceil(1 << 20)
        })
        .sum();
    let reservation = reg.hold(&to, 0, disk, 0);
    reg.evacuations.get_mut(namespace).unwrap().reservation = reservation;
}

pub(crate) fn launch(st: Arc<AppState>, namespace: String) {
    if !st
        .evacuation_workers
        .lock()
        .unwrap()
        .insert(namespace.clone())
    {
        return;
    }
    tokio::spawn(async move {
        if let Err(error) = run(&st, &namespace).await {
            // Remote bodies may contain write-only values: only fixed operation context
            // and status codes from io::call enter the journal.
            let message = format!("{error:#}");
            let _ = checkpoint(&st, &namespace, |j| j.error = Some(message)).await;
        }
        st.evacuation_workers.lock().unwrap().remove(&namespace);
    });
}

async fn cancelled(st: &AppState, namespace: &str) -> Result<bool> {
    let job = journal(st, namespace)?;
    if job.cancel_requested && !job.switched() {
        rollback(st, namespace).await?;
        return Ok(true);
    }
    Ok(false)
}

pub(crate) async fn run(st: &AppState, namespace: &str) -> Result<()> {
    let mut job = journal(st, namespace)?;
    if !job.active() {
        return Ok(());
    }
    // A save that failed during switch may leave switched memory. No source removal
    // or destination release is allowed until the registry write succeeds again.
    st.save().await?;
    let source = host(st, &job.from)?;
    let target = host(st, &job.to)?;
    capable(st, &source).await?;
    capable(st, &target).await?;
    if !job.switched() {
        if cancelled(st, namespace).await? {
            return Ok(());
        }
        checkpoint(st, namespace, |j| {
            j.error = None;
            j.step = "holding".into();
        })
        .await?;
        for m in &job.machines {
            call(
                st,
                &source,
                &job.job,
                Method::POST,
                &format!("/v1/machines/{}/hold", m.id),
                serde_json::json!({"job":job.job}),
            )
            .await?;
        }
        checkpoint(st, namespace, |j| j.step = "held".into()).await?;
        for (index, m) in job.machines.iter_mut().enumerate() {
            if cancelled(st, namespace).await? {
                return Ok(());
            }
            if let Some(backup) = &m.backup {
                let listed = call(
                    st,
                    &source,
                    &job.job,
                    Method::GET,
                    &format!("/v1/machines/{}/backups", m.id),
                    serde_json::Value::Null,
                )
                .await?;
                let listed: Vec<api::Backup> = serde_json::from_value(listed)?;
                if !listed
                    .iter()
                    .any(|b| b.id == *backup && b.machine_id == m.id)
                {
                    return Err(anyhow!(
                        "source backup {} for {} is no longer listed",
                        backup,
                        m.id
                    ));
                }
            }
            if m.backup.is_none() {
                checkpoint(st, namespace, |j| j.step = "cold".into()).await?;
                let backup = call(
                    st,
                    &source,
                    &job.job,
                    Method::POST,
                    &format!("/v1/machines/{}/backups", m.id),
                    serde_json::json!({}),
                )
                .await?;
                let backup: api::Backup = serde_json::from_value(backup)?;
                if backup.machine_id != m.id {
                    return Err(anyhow!("backup identity mismatch"));
                }
                m.backup = Some(backup.id.clone());
                checkpoint(st, namespace, |j| {
                    j.machines[index].backup = Some(backup.id)
                })
                .await?;
            }
        }
        call(
            st,
            &target,
            &job.job,
            Method::PUT,
            &format!("/v1/namespaces/{namespace}/quota"),
            serde_json::to_value(job.quota)?,
        )
        .await?;
        // Stopped machines may name an egress sibling. The daemon validates this
        // during create, so put dependencies before their consumers.
        for (index, m) in job.machines.iter().enumerate() {
            if cancelled(st, namespace).await? {
                return Ok(());
            }
            if lookup(st, &target, &format!("/v1/machines/{}", m.id))
                .await?
                .is_none()
            {
                checkpoint(st, namespace, |j| j.step = "restoring".into()).await?;
                let rs = api::RestoreSpec {
                    same_id: true,
                    machine_id: m.id.clone(),
                    backup: m.backup.clone().ok_or_else(|| anyhow!("backup missing"))?,
                };
                let open = st.restores.open(&target.id, &rs, std::time::Instant::now());
                let result = call(
                    st,
                    &target,
                    &job.job,
                    Method::POST,
                    "/v1/machines",
                    serde_json::to_value(api::CreateMachineRequest {
                        namespace: namespace.into(),
                        name: m.name.clone(),
                        restore: Some(rs),
                        start: Some(false),
                        ..Default::default()
                    })?,
                )
                .await;
                st.restores.close(open);
                result?;
            }
            wait_stopped(st, &target, &m.id).await?;
            let manifest = call(
                st,
                &target,
                &job.job,
                Method::GET,
                &format!("/v1/machines/{}/evacuation-manifest", m.id),
                serde_json::Value::Null,
            )
            .await?;
            if manifest["held"] != job.job {
                return Err(anyhow!("destination {} is not owned by this job", m.id));
            }
            checkpoint(st, namespace, |j| j.machines[index].restored = true).await?;
        }
        for endpoint in &job.endpoints {
            if cancelled(st, namespace).await? {
                return Ok(());
            }
            let path = format!("/v1/endpoints/{}", endpoint.id);
            let found = lookup(st, &target, &path).await?;
            let actual = match found {
                Some(actual) => actual,
                None => call(st, &target, &job.job, Method::POST, &format!("/v1/machines/{}/endpoints", endpoint.machine_id), serde_json::json!({"id":endpoint.id,"port":endpoint.port,"protocol":endpoint.protocol,"host":endpoint.host})).await?,
            };
            let actual: api::Endpoint = serde_json::from_value(actual)?;
            if actual.id != endpoint.id
                || actual.machine_id != endpoint.machine_id
                || actual.port != endpoint.port
                || actual.protocol != endpoint.protocol
                || actual.host != endpoint.host
            {
                return Err(anyhow!("endpoint {} identity mismatch", endpoint.id));
            }
            checkpoint(st, namespace, |j| {
                if let Some(ep) = j.endpoints.iter_mut().find(|ep| ep.id == actual.id) {
                    *ep = actual;
                }
            })
            .await?;
        }
        if let Err(error) = verify(st, namespace, &job).await {
            checkpoint(st, namespace, |j| {
                j.cancel_requested = true;
                j.error = Some(format!("{error:#}"));
            })
            .await?;
            rollback(st, namespace).await?;
            return Err(error);
        }
        checkpoint(st, namespace, |j| j.step = "verified".into()).await?;
        if cancelled(st, namespace).await? {
            return Ok(());
        }
        {
            let _authority = st.authority.write().await;
            let job = journal(st, namespace)?;
            if job.cancel_requested {
                drop(_authority);
                rollback(st, namespace).await?;
                return Ok(());
            }
            {
                let mut reg = st.reg.lock().unwrap();
                reg.namespaces.insert(namespace.into(), job.to.clone());
                for m in &job.machines {
                    reg.machines.insert(m.id.clone(), job.to.clone());
                }
                for ep in &job.endpoints {
                    reg.endpoints.insert(ep.id.clone(), job.to.clone());
                }
                reg.evacuations.get_mut(namespace).unwrap().step = "switched".into();
            }
            st.save().await?;
        }
    }
    job = journal(st, namespace)?;
    // Commit is irreversible. A cleanup failure keeps source leftovers held and
    // never destroys or rolls back the verified destination.
    checkpoint(st, namespace, |j| j.step = "finishing".into()).await?;
    for m in &job.machines {
        call(
            st,
            &target,
            &job.job,
            Method::DELETE,
            &format!("/v1/machines/{}/hold", m.id),
            serde_json::json!({"job":job.job}),
        )
        .await?;
    }
    for m in &job.machines {
        call(
            st,
            &source,
            &job.job,
            Method::DELETE,
            &format!("/v1/machines/{}", m.id),
            serde_json::Value::Null,
        )
        .await?;
    }
    call(
        st,
        &source,
        &job.job,
        Method::DELETE,
        &format!("/v1/namespaces/{namespace}"),
        serde_json::Value::Null,
    )
    .await?;
    release_reservation(st, namespace).await?;
    checkpoint(st, namespace, |j| {
        j.step = "done".into();
        j.error = None;
    })
    .await
}

async fn verify(st: &AppState, namespace: &str, job: &Evacuation) -> Result<()> {
    let target = host(st, &job.to)?;
    for (index, m) in job.machines.iter().enumerate() {
        let actual = call(
            st,
            &target,
            &job.job,
            Method::GET,
            &format!("/v1/machines/{}/evacuation-manifest", m.id),
            serde_json::Value::Null,
        )
        .await?;
        for key in ["id", "config_digest", "root_bytes", "data_bytes"] {
            if actual[key] != m.manifest[key] {
                return Err(anyhow!("verification {}: {key} differs", m.id));
            }
        }
        if actual["state"] != "stopped" || actual["held"] != job.job {
            return Err(anyhow!(
                "verification {}: destination must remain stopped and held",
                m.id
            ));
        }
        checkpoint(st, namespace, |j| {
            j.machines[index].verified = true;
            j.machines[index].ip = actual["ip"].as_str().unwrap_or_default().into();
        })
        .await?;
    }
    Ok(())
}

async fn wait_stopped(st: &AppState, host: &HostRec, id: &str) -> Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(1200), async {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tick.tick().await;
            let m = lookup(st, host, &format!("/v1/machines/{id}"))
                .await?
                .ok_or_else(|| anyhow!("destination machine {id} disappeared"))?;
            match m["state"].as_str() {
                Some("stopped") => return Ok(()),
                Some("creating") => {}
                _ => return Err(anyhow!("destination {id}: restore did not settle stopped")),
            }
        }
    })
    .await
    .context("destination restore timed out")?
}

async fn rollback(st: &AppState, namespace: &str) -> Result<()> {
    let job = journal(st, namespace)?;
    if job.switched() {
        return Err(anyhow!("cannot cancel after the authority switch"));
    }
    checkpoint(st, namespace, |j| j.step = "cancelling".into()).await?;
    let source = host(st, &job.from)?;
    let target = host(st, &job.to)?;
    for m in &job.machines {
        if lookup(st, &target, &format!("/v1/machines/{}", m.id))
            .await?
            .is_some()
        {
            let holder = lookup(st, &target, &format!("/v1/machines/{}/hold", m.id))
                .await?
                .ok_or_else(|| anyhow!("destination hold is missing"))?;
            if holder["job"] != job.job {
                return Err(anyhow!(
                    "refusing cleanup of destination {} owned by another job",
                    m.id
                ));
            }
            call(
                st,
                &target,
                &job.job,
                Method::DELETE,
                &format!("/v1/machines/{}", m.id),
                serde_json::Value::Null,
            )
            .await?;
        }
    }
    call(
        st,
        &target,
        &job.job,
        Method::DELETE,
        &format!("/v1/namespaces/{namespace}"),
        serde_json::Value::Null,
    )
    .await?;
    for m in &job.machines {
        call(
            st,
            &source,
            &job.job,
            Method::DELETE,
            &format!("/v1/machines/{}/hold", m.id),
            serde_json::json!({"job":job.job}),
        )
        .await?;
    }
    release_reservation(st, namespace).await?;
    let _authority = st.authority.write().await;
    {
        let mut reg = st.reg.lock().unwrap();
        reg.namespaces.insert(namespace.into(), job.from.clone());
        for m in &job.machines {
            reg.machines.insert(m.id.clone(), job.from.clone());
        }
        for ep in &job.endpoints {
            reg.endpoints.insert(ep.id.clone(), job.from.clone());
        }
        let job = reg.evacuations.get_mut(namespace).unwrap();
        job.step = "cancelled".into();
    }
    st.save().await
}

async fn release_reservation(st: &AppState, namespace: &str) -> Result<()> {
    let job = journal(st, namespace)?;
    let target = host(st, &job.to)?;
    // Refresh before releasing the reservation, so new placement sees actual disks.
    refresh(st, &target).await;
    st.reg.lock().unwrap().release(&job.to, job.reservation);
    Ok(())
}
