//! Durable dispatch intent is metadata, independent of live namespace/network placement.
use super::*;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct SandboxRoute {
    pub namespace: String,
    pub request_id: String,
    pub host: String,
    pub create_sha256: String,
    /// Missing state is conservatively unresolved, including after upgrade/restart.
    #[serde(default)]
    pub accepted: bool,
}
fn key(namespace: &str, request_id: &str) -> String {
    serde_json::to_string(&(namespace, request_id)).expect("tuple serializes")
}
pub(super) fn request_route(
    req: &api::CreateMachineRequest,
    host: String,
) -> Result<SandboxRoute, Refusal> {
    Ok(SandboxRoute {
        namespace: req.namespace.clone(),
        request_id: req
            .sandbox_seed
            .as_ref()
            .expect("seed route")
            .request_id
            .clone(),
        host,
        accepted: false,
        create_sha256: format!(
            "{:x}",
            Sha256::digest(req.sandbox_create_bytes().map_err(|_| err(
                StatusCode::BAD_REQUEST,
                "invalid",
                "sandbox request fingerprint failed"
            ))?)
        ),
    })
}
pub(super) fn existing_route(
    reg: &Registry,
    req: &api::CreateMachineRequest,
) -> Result<Option<SandboxRoute>, Refusal> {
    let expected = request_route(req, String::new())?;
    // Undeployed earlier formats are not migrated implicitly if encountered on disk.
    if reg.unknown.get("sandbox_namespaces").is_some_and(|old| {
        old.as_array()
            .is_none_or(|values| values.iter().any(|v| v.as_str() == Some(&req.namespace)))
    }) {
        return Err(err(
            StatusCode::CONFLICT,
            "conflict",
            "legacy sandbox routing fence requires operator reconciliation",
        ));
    }
    let Some(route) = reg
        .sandbox_requests
        .get(&key(&req.namespace, &expected.request_id))
        .cloned()
    else {
        return Ok(None);
    };
    if route.namespace != expected.namespace
        || route.request_id != expected.request_id
        || route.create_sha256 != expected.create_sha256
        || route.host.is_empty()
    {
        return Err(err(
            StatusCode::CONFLICT,
            "conflict",
            "sandbox request routing identity conflict",
        ));
    }
    Ok(Some(route))
}
pub(super) fn insert_route(reg: &mut Registry, route: SandboxRoute) {
    reg.sandbox_requests
        .insert(key(&route.namespace, &route.request_id), route);
}
/// Only validated acceptance settles dispatch. Absence cannot exclude a delayed POST.
pub(super) fn accept_route(reg: &mut Registry, route: &SandboxRoute) {
    if let Some(stored) = reg
        .sandbox_requests
        .get_mut(&key(&route.namespace, &route.request_id))
    {
        if stored.host == route.host && stored.create_sha256 == route.create_sha256 {
            stored.accepted = true;
        }
    }
}
pub(super) fn namespace_unresolved(reg: &Registry, namespace: &str) -> bool {
    reg.namespace_moves
        .values()
        .any(|m| m.namespace == namespace)
        || crate::sandbox_admissions::namespace_pending(reg, namespace)
        || reg
            .sandbox_requests
            .values()
            .any(|route| route.namespace == namespace && !route.accepted)
}
pub(super) fn host_unresolved(reg: &Registry, host: &str) -> bool {
    reg.namespace_moves.values().any(|m| m.host == host)
        || reg
            .sandbox_admissions
            .values()
            .any(|a| a.pending_seed() && a.host.as_deref() == Some(host))
        || reg
            .sandbox_requests
            .values()
            .any(|route| route.host == host && !route.accepted)
}
pub(super) fn relocation_unresolved(reg: &Registry, namespace: &str, host: Option<&str>) -> bool {
    reg.namespace_moves
        .values()
        .any(|m| m.namespace == namespace && Some(m.host.as_str()) != host)
        || reg
            .sandbox_admissions
            .values()
            .any(|a| a.namespace == namespace && a.pending_seed() && a.host.as_deref() != host)
        || reg.sandbox_requests.values().any(|route| {
            route.namespace == namespace && !route.accepted && Some(route.host.as_str()) != host
        })
}
pub(super) async fn sandbox_lookup(
    st: &Arc<AppState>,
    req: &api::CreateMachineRequest,
    headers: &HeaderMap,
    route: SandboxRoute,
) -> Result<Response, Refusal> {
    let host = st
        .reg
        .lock()
        .unwrap()
        .hosts
        .get(&route.host)
        .cloned()
        .ok_or_else(|| {
            err(
                StatusCode::SERVICE_UNAVAILABLE,
                "host_unreachable",
                "sandbox request host was removed or is unavailable",
            )
        })?;
    let query = api::SandboxRequestLookup {
        namespace: route.namespace.clone(),
        request_id: route.request_id.clone(),
        create_sha256: route.create_sha256.clone(),
    };
    let response = forward(
        st,
        &host,
        Method::POST,
        "/v1/sandbox-requests/lookup",
        headers,
        Bytes::from(serde_json::to_vec(&query).expect("lookup serializes")),
    )
    .await;
    let (parts, data) = read(response).await;
    if parts.status == StatusCode::OK {
        let machine: api::Machine = serde_json::from_slice(&data).map_err(|_| {
            err(
                StatusCode::BAD_GATEWAY,
                "host_unreachable",
                "malformed sandbox receipt response",
            )
        })?;
        if machine.namespace != req.namespace || !api::valid_id(&machine.id) {
            return Err(err(
                StatusCode::BAD_GATEWAY,
                "host_unreachable",
                "sandbox receipt returned a different destination",
            ));
        }
        accept_route(&mut st.reg.lock().unwrap(), &route);
        st.save().await.map_err(registry_error)?;
        // Returning an old receipt never changes a current namespace placement.
        return Ok(Response::from_parts(
            parts,
            Body::from(with_host(data, &host.id)),
        ));
    }
    if parts.status == StatusCode::CONFLICT && error_code(&data) == "conflict" {
        return Ok(Response::from_parts(parts, Body::from(data)));
    }
    if parts.status == StatusCode::NOT_FOUND && error_code(&data) == "sandbox_request_unknown" {
        return Err(err(StatusCode::CONFLICT, "conflict", "sandbox dispatch intent is consumed but acceptance is unconfirmed; request cannot be dispatched again"));
    }
    Err(err(
        StatusCode::SERVICE_UNAVAILABLE,
        "host_unreachable",
        "sandbox receipt lookup is unconfirmed; create was not forwarded",
    ))
}
