//! Images.

use super::*;

pub(super) async fn list_images(State(st): S) -> Result<Json<Vec<api::Image>>, AppError> {
    Ok(Json(st.mgr.images().await?))
}

pub(super) async fn delete_image(
    State(st): S,
    Path(key): Path<String>,
) -> Result<StatusCode, AppError> {
    let m = st.mgr.clone();
    detached(async move { m.delete_image(&key).await }).await?;
    Ok(StatusCode::NO_CONTENT)
}
