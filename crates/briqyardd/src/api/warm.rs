use super::*;

pub(super) async fn warm_catalog(
    State(st): S,
    Path(namespace): Path<String>,
) -> Result<Json<api::WarmCatalogStatus>, AppError> {
    Ok(Json(st.mgr.warm_catalog(&namespace).await?))
}

pub(super) async fn put_warm_catalog(
    State(st): S,
    Path((namespace, id)): Path<(String, String)>,
    Json(request): Json<api::WarmDesiredRequest>,
) -> Result<Json<api::WarmPool>, AppError> {
    let m = st.mgr.clone();
    Ok(Json(
        detached(async move { m.put_warm_catalog(&namespace, &id, request).await }).await?,
    ))
}

pub(super) async fn warm_pools(
    State(st): S,
    Path(namespace): Path<String>,
) -> Result<Json<Vec<api::WarmPool>>, AppError> {
    Ok(Json(st.mgr.warm_pools(&namespace)?))
}

pub(super) async fn put_warm_pool(
    State(st): S,
    Path((namespace, name)): Path<(String, String)>,
    Json(request): Json<api::PutWarmPoolRequest>,
) -> Result<Json<api::WarmPool>, AppError> {
    let m = st.mgr.clone();
    Ok(Json(
        detached(async move { m.put_warm_pool(&namespace, &name, request).await }).await?,
    ))
}

pub(super) async fn delete_warm_pool(
    State(st): S,
    Path((namespace, name)): Path<(String, String)>,
) -> Result<StatusCode, AppError> {
    let m = st.mgr.clone();
    detached(async move { m.delete_warm_pool(&namespace, &name).await }).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn claim_warm_pool(
    State(st): S,
    Path((namespace, name)): Path<(String, String)>,
    Json(request): Json<api::ClaimWarmPoolRequest>,
) -> Result<Json<api::Machine>, AppError> {
    let m = st.mgr.clone();
    Ok(Json(
        detached(async move { m.claim_warm_pool(&namespace, &name, request).await }).await?,
    ))
}
