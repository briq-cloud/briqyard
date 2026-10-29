//! Endpoints.

use super::*;

pub(super) async fn create_endpoint(
    State(st): S,
    Path(id): Path<String>,
    Json(req): Json<api::CreateEndpointRequest>,
) -> Result<(StatusCode, Json<api::Endpoint>), AppError> {
    Ok((StatusCode::CREATED, Json(st.mgr.create_endpoint(&id, req)?)))
}

pub(super) async fn list_endpoints(State(st): S) -> Json<Vec<api::Endpoint>> {
    Json(
        st.mgr
            .all_endpoints()
            .iter()
            .map(|e| st.mgr.endpoint_view(e))
            .collect(),
    )
}

pub(super) async fn get_endpoint(
    State(st): S,
    Path(id): Path<String>,
) -> Result<Json<api::Endpoint>, AppError> {
    let ep = st.mgr.endpoint(&id).ok_or(MError::NotFound)?;
    Ok(Json(st.mgr.endpoint_view(&ep)))
}

pub(super) async fn delete_endpoint(
    State(st): S,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    st.mgr.delete_endpoint(&id)?;
    Ok(StatusCode::NO_CONTENT)
}
