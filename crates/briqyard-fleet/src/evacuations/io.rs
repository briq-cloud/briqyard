use super::*;

pub(super) async fn call(
    st: &AppState,
    host: &HostRec,
    job: &str,
    method: Method,
    path: &str,
    body: serde_json::Value,
) -> Result<serde_json::Value> {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if !job.is_empty() {
        headers.insert("x-briqyard-job", HeaderValue::from_str(job)?);
    }
    let resp = forward(
        st,
        host,
        method.clone(),
        path,
        &headers,
        Bytes::from(serde_json::to_vec(&body)?),
    )
    .await;
    let status = resp.status();
    if method == Method::DELETE && status == StatusCode::NOT_FOUND {
        return Ok(serde_json::Value::Null);
    }
    if !status.is_success() {
        return Err(anyhow!("host {}: {method} {path}: HTTP {status}", host.id));
    }
    let (_, data) = read(resp).await;
    if data.is_empty() {
        return Ok(serde_json::Value::Null);
    }
    serde_json::from_slice(&data).context("unreadable host response")
}

pub(super) fn host(st: &AppState, id: &str) -> Result<HostRec> {
    st.reg
        .lock()
        .unwrap()
        .hosts
        .get(id)
        .cloned()
        .ok_or_else(|| anyhow!("host {id} is no longer registered"))
}

pub(super) async fn capable(st: &AppState, host: &HostRec) -> Result<api::Status> {
    let status: api::Status = serde_json::from_value(
        call(
            st,
            host,
            "",
            Method::GET,
            "/v1/status",
            serde_json::Value::Null,
        )
        .await?,
    )?;
    if !status.evacuate_v1 {
        return Err(anyhow!(
            "host {} must be upgraded: evacuation capability evacuate_v1 is missing",
            host.id
        ));
    }
    Ok(status)
}

pub(super) async fn checkpoint(
    st: &AppState,
    namespace: &str,
    update: impl FnOnce(&mut Evacuation),
) -> Result<()> {
    {
        let mut reg = st.reg.lock().unwrap();
        let job = reg
            .evacuations
            .get_mut(namespace)
            .ok_or_else(|| anyhow!("evacuation journal missing"))?;
        update(job);
    }
    st.save().await
}

pub(super) fn journal(st: &AppState, namespace: &str) -> Result<Evacuation> {
    st.reg
        .lock()
        .unwrap()
        .evacuations
        .get(namespace)
        .cloned()
        .ok_or_else(|| anyhow!("evacuation journal missing"))
}

pub(super) async fn lookup(
    st: &AppState,
    host: &HostRec,
    path: &str,
) -> Result<Option<serde_json::Value>> {
    let resp = forward(st, host, Method::GET, path, &HeaderMap::new(), Bytes::new()).await;
    if resp.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(anyhow!(
            "host {}: GET {path}: HTTP {}",
            host.id,
            resp.status()
        ));
    }
    let (_, data) = read(resp).await;
    Ok(Some(serde_json::from_slice(&data)?))
}
