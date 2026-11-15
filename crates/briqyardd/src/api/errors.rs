//! Every error response, as the API answers it.

use super::*;

/// Every error response's body, with the status it maps to.
pub struct AppError {
    pub(super) status: StatusCode,
    pub(super) code: &'static str,
    pub(super) error: String,
    /// With `boot_failed`: the machine left in `error`; with a stale `If-Match`, the machine.
    pub(super) machine: Option<Box<api::Machine>>,
    /// With `gone`: the oldest event seq kept.
    pub(super) oldest: Option<u64>,
    /// With `namespace_protected`: seconds until the protection ends, as `Retry-After`.
    pub(super) retry_after: Option<u64>,
}

/// The status and code of each manager error. `boot_failed` is a 409 like the other
/// "not in that state" answers; `capacity` stays a 503, which the control plane retries later.
fn status_of(e: &MError) -> (StatusCode, &'static str) {
    match e {
        MError::NotFound | MError::NoBackup(_) | MError::NoSnapshot(_) => {
            (StatusCode::NOT_FOUND, "not_found")
        }
        MError::ExecStreamUnsupported => (StatusCode::CONFLICT, "unsupported"),
        MError::PoolEmpty => (StatusCode::CONFLICT, "pool_empty"),
        MError::Invalid(_) => (StatusCode::BAD_REQUEST, "invalid"),
        MError::PathRefused(_) => (StatusCode::UNPROCESSABLE_ENTITY, "path_refused"),
        MError::Conflict(_) | MError::NameTaken(_) => (StatusCode::CONFLICT, "conflict"),
        MError::NotRunning(_) => (StatusCode::CONFLICT, "not_running"),
        MError::BadState(_) | MError::Refused(_) => (StatusCode::CONFLICT, "bad_state"),
        MError::BootFailed(_) => (StatusCode::CONFLICT, "boot_failed"),
        MError::PullFailed(_) => (StatusCode::CONFLICT, "pull_failed"),
        MError::CreateFailed(_) => (StatusCode::CONFLICT, "create_failed"),
        MError::Moved(_) => (StatusCode::CONFLICT, "conflict"),
        MError::NotReady(_) => (StatusCode::CONFLICT, "not_ready"),
        MError::Gone { .. } => (StatusCode::GONE, "gone"),
        MError::KeyUnavailable(_) => (StatusCode::CONFLICT, "key_unavailable"),
        MError::KeyUnreachable(_) => (StatusCode::SERVICE_UNAVAILABLE, "key_unreachable"),
        MError::Capacity(_) => (StatusCode::SERVICE_UNAVAILABLE, "capacity"),
        MError::Quota(_) => (StatusCode::FORBIDDEN, "quota"),
        MError::NamespaceInUse => (StatusCode::CONFLICT, "namespace_in_use"),
        MError::NamespaceProtected(_) => (StatusCode::CONFLICT, "namespace_protected"),
        MError::GatewayInUse => (StatusCode::CONFLICT, "gateway_in_use"),
        MError::Gateway(_) => (StatusCode::CONFLICT, "gateway"),
        MError::Other(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}

impl From<MError> for AppError {
    fn from(e: MError) -> Self {
        let (status, code) = status_of(&e);
        let error = match &e {
            MError::Other(err) => format!("{err:#}"),
            other => other.to_string(),
        };
        let oldest = match &e {
            MError::Gone { oldest, .. } => Some(*oldest),
            _ => None,
        };
        let retry_after = match &e {
            MError::NamespaceProtected(p) => Some(p.retry_after_ms.div_ceil(1000)),
            _ => None,
        };
        let machine = match e {
            MError::BootFailed(m) => {
                // The image's fault, not an operator's: a warning.
                tracing::warn!(machine = m.id, err = %error, "boot failed");
                Some(m)
            }
            // A create's failure was logged where it happened (ADR 0048); a `/wait` reads it.
            MError::Moved(m)
            | MError::NotReady(m)
            | MError::PullFailed(m)
            | MError::CreateFailed(m)
            | MError::NameTaken(m) => Some(m),
            MError::Other(_) => {
                tracing::error!(err = %error, "request failed");
                None
            }
            _ => None,
        };
        AppError {
            status,
            code,
            error,
            machine,
            oldest,
            retry_after,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let mut resp = (
            self.status,
            Json(api::ApiError {
                error: self.error,
                code: self.code.into(),
                request_id: String::new(),
                machine: self.machine,
                oldest: self.oldest,
            }),
        )
            .into_response();
        if let Some(secs) = self.retry_after {
            resp.headers_mut()
                .insert(axum::http::header::RETRY_AFTER, secs.into());
        }
        resp.extensions_mut().insert(IsError);
        resp
    }
}
