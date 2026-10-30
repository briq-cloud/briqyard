//! Namespaces: listing, gateway and quota.

use super::*;

pub(super) async fn list_namespaces(State(st): S) -> Json<Vec<api::Namespace>> {
    Json(st.mgr.namespaces())
}

pub(super) async fn get_namespace(
    State(st): S,
    Path(id): Path<String>,
) -> Result<Json<api::Namespace>, AppError> {
    Ok(Json(st.mgr.namespace(&id)?))
}

pub(super) async fn delete_namespace(
    State(st): S,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let m = st.mgr.clone();
    detached(async move { m.delete_namespace(&id).await }).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn set_gateway(
    State(st): S,
    Path(id): Path<String>,
    Json(spec): Json<api::GatewaySpec>,
) -> Result<Json<api::Namespace>, AppError> {
    let m = st.mgr.clone();
    Ok(Json(
        detached(async move { m.set_gateway(&id, spec).await }).await?,
    ))
}

pub(super) async fn delete_gateway(
    State(st): S,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let m = st.mgr.clone();
    detached(async move { m.delete_gateway(&id).await }).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn get_quota(
    State(st): S,
    Path(id): Path<String>,
) -> Result<Json<api::NamespaceQuota>, AppError> {
    Ok(Json(st.mgr.quota(&id)?))
}

pub(super) async fn set_quota(
    State(st): S,
    Path(id): Path<String>,
    Json(q): Json<api::Quota>,
) -> Result<Json<api::NamespaceQuota>, AppError> {
    let m = st.mgr.clone();
    Ok(Json(
        detached(async move { m.set_quota(&id, q).await }).await?,
    ))
}
