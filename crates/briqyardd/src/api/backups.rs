//! Backups and snapshots.

use super::*;

pub(super) async fn make_backup(
    State(st): S,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<api::Backup>), AppError> {
    let m = st.mgr.clone();
    let b = detached(async move { m.backup(&id).await }).await?;
    Ok((StatusCode::CREATED, Json(b)))
}

/// The backups of a machine id, which may be a machine this host never had: the store is
/// shared, so a restore can start from any host.
pub(super) async fn list_backups(
    State(st): S,
    Path(id): Path<String>,
) -> Result<Json<Vec<api::Backup>>, AppError> {
    Ok(Json(st.mgr.backups(&id).await?))
}

#[derive(Deserialize)]
pub(super) struct DeleteBackupQuery {
    #[serde(default)]
    chain: bool,
}

/// Deletes a backup of a machine of this host or of one destroyed here; with `chain`, the
/// backups that continue from it too.
pub(super) async fn delete_backup(
    State(st): S,
    Path((id, backup)): Path<(String, String)>,
    Query(q): Query<DeleteBackupQuery>,
) -> Result<StatusCode, AppError> {
    let m = st.mgr.clone();
    detached(async move { m.delete_backup(&id, &backup, q.chain).await }).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub(super) struct BackupsQuery {
    #[serde(alias = "tenant")]
    namespace: Option<String>,
    machine: Option<String>,
}

/// Every backup of the host's machines, destroyed ones' included, of a namespace or all, of a
/// machine or all.
pub(super) async fn all_backups(
    State(st): S,
    Query(q): Query<BackupsQuery>,
) -> Result<Json<Vec<api::Backup>>, AppError> {
    let (namespace, machine) = (q.namespace.as_deref(), q.machine.as_deref());
    Ok(Json(st.mgr.all_backups(namespace, machine).await?))
}

pub(super) async fn snapshot(
    State(st): S,
    Path(id): Path<String>,
    body: Option<Json<api::SnapshotRequest>>,
) -> Result<(StatusCode, Json<api::Snapshot>), AppError> {
    let req = body.map(|b| b.0).unwrap_or_default();
    let m = st.mgr.clone();
    let s = detached(async move { m.snapshot(&id, req).await }).await?;
    Ok((StatusCode::CREATED, Json(s)))
}

pub(super) async fn restore_snapshot(
    State(st): S,
    Path((id, snap)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<api::Machine>, AppError> {
    let at = if_match(&headers)?;
    let m = st.mgr.clone();
    Ok(Json(
        detached(async move { m.restore_snapshot(&id, &snap, at).await }).await?,
    ))
}

pub(super) async fn snapshots(
    State(st): S,
    Path(id): Path<String>,
) -> Result<Json<Vec<api::Snapshot>>, AppError> {
    Ok(Json(st.mgr.snapshots(&id).await?))
}

pub(super) async fn delete_snapshot(
    State(st): S,
    Path((id, snap)): Path<(String, String)>,
) -> Result<StatusCode, AppError> {
    let m = st.mgr.clone();
    detached(async move { m.delete_snapshot(&id, &snap).await }).await?;
    Ok(StatusCode::NO_CONTENT)
}
