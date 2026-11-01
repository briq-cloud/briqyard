//! Fleet-local durable placement identity, established before a caller freezes its create.
use super::*;

pub(super) const HEADER: &str = "x-briqyard-placement-request-id";

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Selector {
    machine_id: String,
    snapshot: String,
    generation: String,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    region: String,
    size: api::Size,
    sandbox_seed: Selector,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Mode {
    Cold,
    SandboxSeed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Phase {
    Pending,
    Dispatched,
    Cancelled,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct Admission {
    pub namespace: String,
    request_id: String,
    fingerprint: String,
    request: Option<Request>,
    pub mode: Mode,
    pub host: Option<String>,
    phase: Phase,
}
impl Admission {
    pub fn pending_seed(&self) -> bool {
        self.phase == Phase::Pending && self.mode == Mode::SandboxSeed
    }
}
fn key(namespace: &str, id: &str) -> String {
    serde_json::to_string(&(namespace, id)).expect("tuple serializes")
}
fn conflict(message: &str) -> Refusal {
    err(StatusCode::CONFLICT, "conflict", message)
}
fn check_ids(namespace: &str, id: &str) -> Result<(), Refusal> {
    if !api::valid_id(namespace) || !api::valid_sandbox_request_id(id) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid",
            "invalid admission identity",
        ));
    }
    Ok(())
}
fn authenticated(st: &AppState) -> Result<(), Refusal> {
    // The router checks the configured bearer. An unauthenticated fleet cannot admit seeds.
    if st.cfg.token.is_empty() {
        return Err(err(
            StatusCode::CONFLICT,
            "capability_unsupported",
            "sandbox admission requires configured API authentication",
        ));
    }
    Ok(())
}
fn replay(
    reg: &Registry,
    namespace: &str,
    id: &str,
    fingerprint: &str,
) -> Result<Option<Mode>, Refusal> {
    let Some(a) = reg.sandbox_admissions.get(&key(namespace, id)) else {
        return Ok(None);
    };
    if a.phase == Phase::Cancelled {
        return Err(conflict("admission was cancelled"));
    }
    if a.fingerprint != fingerprint {
        return Err(conflict("admission request identity conflict"));
    }
    Ok(Some(a.mode))
}
fn response(mode: Mode) -> Json<serde_json::Value> {
    Json(serde_json::json!({"mode": mode}))
}
pub(super) async fn admit(
    State(st): S,
    Path((namespace, id)): Path<(String, String)>,
    Json(request): Json<Request>,
) -> Result<Json<serde_json::Value>, Refusal> {
    authenticated(&st)?;
    check_ids(&namespace, &id)?;
    request
        .size
        .check()
        .map_err(|why| err(StatusCode::BAD_REQUEST, "invalid", why))?;
    let selector = &request.sandbox_seed;
    if !api::valid_id(&selector.machine_id)
        || !api::valid_id(&selector.snapshot)
        || !api::valid_id(&selector.generation)
    {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid",
            "invalid sandbox selector",
        ));
    }
    // Struct serialization gives stable field order, independent of caller JSON key order.
    let fingerprint = serde_json::to_string(&request).expect("request serializes");
    let prior = replay(&st.reg.lock().unwrap(), &namespace, &id, &fingerprint)?;
    if let Some(mode) = prior {
        st.save().await.map_err(registry_error)?;
        return Ok(response(mode));
    }
    let seed = api::SandboxSeed {
        machine_id: selector.machine_id.clone(),
        snapshot: selector.snapshot.clone(),
        generation: selector.generation.clone(),
        request_id: id.clone(),
    };
    let validated_host = crate::create::check_sandbox_selector(&st, &seed, request.size).await?;
    let mode = {
        let mut reg = st.reg.lock().unwrap();
        if let Some(mode) = replay(&reg, &namespace, &id, &fingerprint)? {
            mode
        } else {
            let host = reg
                .host_of_machine(&selector.machine_id)
                .ok_or_else(|| conflict("sandbox source disappeared during admission"))?;
            if host.id != validated_host {
                return Err(conflict("sandbox source moved during admission"));
            }
            crate::create::require_memory_profile(host, st.policy.down_after, "sandbox-ready-v1")?;
            refuse_outside(&reg, Some(&host.id), &namespace, &request.region)?;
            let host = host.id.clone();
            refuse_outside(
                &reg,
                reg.namespaces.get(&namespace).map(String::as_str),
                &namespace,
                &request.region,
            )?;
            let mode = if reg.namespaces.get(&namespace).is_some_and(|p| *p != host) {
                Mode::Cold
            } else {
                Mode::SandboxSeed
            };
            if mode == Mode::SandboxSeed {
                reg.pin(&namespace, &host);
                reg.note_namespace_create(&namespace);
            }
            reg.sandbox_admissions.insert(
                key(&namespace, &id),
                Admission {
                    namespace,
                    request_id: id,
                    fingerprint,
                    request: Some(request),
                    mode,
                    host: (mode == Mode::SandboxSeed).then_some(host),
                    phase: Phase::Pending,
                },
            );
            mode
        }
    };
    st.save().await.map_err(registry_error)?;
    Ok(response(mode))
}
pub(super) async fn cancel(
    State(st): S,
    Path((namespace, id)): Path<(String, String)>,
) -> Result<StatusCode, Refusal> {
    authenticated(&st)?;
    check_ids(&namespace, &id)?;
    {
        let mut reg = st.reg.lock().unwrap();
        let a = reg
            .sandbox_admissions
            .entry(key(&namespace, &id))
            .or_insert_with(|| Admission {
                namespace: namespace.clone(),
                request_id: id.clone(),
                fingerprint: String::new(),
                request: None,
                mode: Mode::Cold,
                host: None,
                phase: Phase::Cancelled,
            });
        if a.phase == Phase::Dispatched {
            return Err(conflict("admission already dispatched"));
        }
        a.phase = Phase::Cancelled;
        // Keep both tombstone and namespace pin: a gateway or another member may use it.
    }
    st.save().await.map_err(registry_error)?;
    Ok(StatusCode::NO_CONTENT)
}
pub(super) fn namespace_pending(reg: &Registry, namespace: &str) -> bool {
    reg.sandbox_admissions
        .values()
        .any(|a| a.namespace == namespace && a.pending_seed())
}
pub(super) fn header_id(headers: &HeaderMap) -> Result<Option<String>, Refusal> {
    headers
        .get(HEADER)
        .map(|h| {
            h.to_str().map(str::to_owned).map_err(|_| {
                err(
                    StatusCode::BAD_REQUEST,
                    "invalid",
                    "invalid placement header",
                )
            })
        })
        .transpose()
}
pub(super) fn check_gateway(
    reg: &Registry,
    namespace: &str,
    region: &str,
    id: Option<&str>,
) -> Result<(), Refusal> {
    let Some(id) = id else { return Ok(()) };
    check_ids(namespace, id)?;
    let a = reg
        .sandbox_admissions
        .get(&key(namespace, id))
        .ok_or_else(|| conflict("placement admission missing"))?;
    let request = a
        .request
        .as_ref()
        .ok_or_else(|| conflict("admission cancelled"))?;
    if a.phase == Phase::Cancelled
        || request.region != region
        || (a.mode == Mode::SandboxSeed && reg.namespaces.get(namespace) != a.host.as_ref())
    {
        return Err(conflict("gateway placement admission mismatch"));
    }
    Ok(())
}
pub(super) fn effective_id(
    reg: &Registry,
    req: &api::CreateMachineRequest,
    header: Option<&str>,
) -> Option<String> {
    header.map(str::to_owned).or_else(|| {
        req.sandbox_seed.as_ref().and_then(|seed| {
            reg.sandbox_admissions
                .contains_key(&key(&req.namespace, &seed.request_id))
                .then(|| seed.request_id.clone())
        })
    })
}
pub(super) fn check_dispatch(
    reg: &Registry,
    req: &api::CreateMachineRequest,
    id: Option<&str>,
) -> Result<(), Refusal> {
    let Some(id) = id else { return Ok(()) }; // Existing accepted and legacy seed requests retain their contract.
    check_ids(&req.namespace, id)?;
    let a = reg
        .sandbox_admissions
        .get(&key(&req.namespace, id))
        .ok_or_else(|| conflict("placement admission missing"))?;
    let request = a
        .request
        .as_ref()
        .ok_or_else(|| conflict("admission cancelled"))?;
    if a.phase == Phase::Cancelled || request.region != req.region || request.size != req.size {
        return Err(conflict("create placement admission mismatch"));
    }
    match (&req.sandbox_seed, a.mode) {
        (None, Mode::Cold) => {}
        (Some(seed), Mode::SandboxSeed)
            if seed.request_id == id
                && seed.machine_id == request.sandbox_seed.machine_id
                && seed.snapshot == request.sandbox_seed.snapshot
                && seed.generation == request.sandbox_seed.generation =>
        {
            if a.phase == Phase::Pending && reg.namespaces.get(&req.namespace) != a.host.as_ref() {
                return Err(conflict("admitted namespace pin changed"));
            }
        }
        _ => return Err(conflict("create selector differs from admission")),
    }
    Ok(())
}
pub(super) fn dispatched(reg: &mut Registry, namespace: &str, id: Option<&str>) {
    if let Some(a) = id.and_then(|id| reg.sandbox_admissions.get_mut(&key(namespace, id))) {
        a.phase = Phase::Dispatched;
    }
}
