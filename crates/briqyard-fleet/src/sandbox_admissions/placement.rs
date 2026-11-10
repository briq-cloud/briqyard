//! Placement admission (ADR 0128): where a namespace's first dispatches go, across an ordered
//! list of regions. One decision, made under the registry lock before any host is asked, saved
//! before it is answered, and held to by the gateway `PUT` and the create that carry its id.
use super::*;
use chrono::{DateTime, Utc};

/// Seeds a consumer may offer: each is checked on its host before the walk.
const MAX_SEEDS: usize = 8;
const PROFILES: [&str; 3] = ["init-ready-v1", "sandbox-ready-v1", "service-ready-v1"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Role {
    Gateway,
    Consumer,
}
impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Role::Gateway => "gateway",
            Role::Consumer => "consumer",
        }
    }
}

/// What one of the namespace's first dispatches will ask for, with the fields its create or
/// `PUT` carries.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Requirement {
    role: Role,
    size: api::Size,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    volume_gb: Option<u32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    runtime_class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    memory_profile: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    egress_siblings: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    sandbox_seeds: Vec<Selector>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    regions: Vec<String>,
    requirements: Vec<Requirement>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum Binding {
    New,
    Existing,
}

/// What a region came to in the walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum Class {
    Placed,
    Unconfirmed,
    Full,
    Ineligible,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct Outcome {
    region: String,
    outcome: Class,
}

/// The answer, stored and replayed as it was.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct Decision {
    region: String,
    host: String,
    binding: Binding,
    mode: Mode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seed: Option<Selector>,
    regions: Vec<Outcome>,
}

/// A placement admission's body, its decision and the roles dispatched under it.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct Record {
    request: Request,
    decision: Decision,
    #[serde(default)]
    dispatched: Vec<Role>,
}
impl Record {
    /// Whether every requirement has been dispatched.
    pub(super) fn complete(&self) -> bool {
        self.request
            .requirements
            .iter()
            .all(|r| self.dispatched.contains(&r.role))
    }
    fn requirement(&self, role: Role) -> Option<&Requirement> {
        self.request.requirements.iter().find(|r| r.role == role)
    }
}

fn invalid(message: &str) -> Refusal {
    err(StatusCode::BAD_REQUEST, "invalid", message)
}

fn validate(request: &Request) -> Result<(), Refusal> {
    let regions = &request.regions;
    if regions.is_empty()
        || regions.len() > 16
        || regions.iter().any(|r| r.is_empty() || r.len() > 64)
    {
        return Err(invalid("regions: want 1 to 16 names"));
    }
    if regions
        .iter()
        .enumerate()
        .any(|(i, r)| regions[..i].contains(r))
    {
        return Err(invalid("regions: a region is listed once"));
    }
    let reqs = &request.requirements;
    if reqs.is_empty() || reqs.len() > 2 || (reqs.len() == 2 && reqs[0].role == reqs[1].role) {
        return Err(invalid(
            "requirements: want one gateway, one consumer, or both",
        ));
    }
    for r in reqs {
        r.size
            .check()
            .map_err(|why| err(StatusCode::BAD_REQUEST, "invalid", why))?;
        if r.memory_profile
            .as_deref()
            .is_some_and(|p| !PROFILES.contains(&p))
        {
            return Err(invalid("requested template profile is unsupported"));
        }
        match r.role {
            Role::Gateway => {
                if api::class_name(&r.runtime_class) != api::DEFAULT_CLASS
                    || r.memory_profile.is_some()
                    || r.egress_siblings
                    || !r.sandbox_seeds.is_empty()
                {
                    return Err(invalid("a gateway requirement takes a size and a volume"));
                }
            }
            Role::Consumer => {
                if r.sandbox_seeds.len() > MAX_SEEDS
                    || r.sandbox_seeds.iter().any(|s| {
                        !api::valid_id(&s.machine_id)
                            || !api::valid_id(&s.snapshot)
                            || !api::valid_id(&s.generation)
                    })
                {
                    return Err(invalid("invalid sandbox selector"));
                }
            }
        }
    }
    Ok(())
}

/// The policy a requirement asks of a host, as its create or `PUT` would.
fn requirement_policy(base: &Policy, r: &Requirement) -> Policy {
    Policy {
        require_egress_siblings: r.egress_siblings,
        require_named_memory: r.memory_profile.is_some(),
        named_memory_profile: r
            .memory_profile
            .clone()
            .unwrap_or_else(|| "init-ready-v1".into()),
        runtime_class: r.runtime_class.clone(),
        ..base.clone()
    }
}

/// What all the requirements ask of a host, as guest memory, CPU and disk.
struct Needs {
    memory_mb: u32,
    cpu_millis: u32,
    disk_mb: u64,
}
fn needs(reqs: &[Requirement]) -> Needs {
    Needs {
        memory_mb: reqs.iter().map(|r| r.size.memory_mb).sum(),
        cpu_millis: reqs.iter().map(|r| r.size.cpu_millis()).sum(),
        disk_mb: reqs.iter().map(|r| disk_need(r.volume_gb)).sum(),
    }
}
/// The memory the requirements reserve on `host`, with its own policy; `None`: one it cannot.
fn physical(host: &HostRec, reqs: &[Requirement]) -> Option<u32> {
    reqs.iter().try_fold(0u32, |sum, r| {
        host.reservation_mb(r.size.memory_mb)
            .map(|m| sum.saturating_add(m))
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostClass {
    Candidate,
    Full,
    Unknown,
    Ignored,
}

/// How a host counts for the requirements (ADR 0128). `new_namespace` holds it to the fill
/// ceiling too, as a placement does; a namespace already there only needs room and no pressure.
fn classify(
    host: &HostRec,
    reqs: &[Requirement],
    base: &Policy,
    now: DateTime<Utc>,
    new_namespace: bool,
) -> HostClass {
    if !reqs
        .iter()
        .all(|r| host.has_capabilities(&requirement_policy(base, r)))
    {
        return HostClass::Ignored;
    }
    match host.state.as_str() {
        "ready" => {
            // Tested before `full`: `pressure` includes the unresolved policy.
            if now - host.last_seen >= base.down_after || host.memory_policy_unresolved() {
                return HostClass::Unknown;
            }
            let n = needs(reqs);
            let admits = match new_namespace {
                true => host.takes_new_namespaces(base),
                false => host.pressure().is_none(),
            };
            let room =
                physical(host, reqs).is_some_and(|mb| host.has_room(mb, n.disk_mb, n.cpu_millis));
            match admits && room {
                true => HostClass::Candidate,
                false => HostClass::Full,
            }
        }
        "down" | "upgrading" => HostClass::Unknown,
        _ => HostClass::Ignored,
    }
}

fn region_class(classes: &[HostClass]) -> Class {
    let has = |c| classes.contains(&c);
    if has(HostClass::Candidate) {
        Class::Placed
    } else if has(HostClass::Unknown) {
        Class::Unconfirmed
    } else if has(HostClass::Full) {
        Class::Full
    } else {
        Class::Ineligible
    }
}

/// A seed checked on its host before the walk.
type Checked = (Selector, String);

struct Plan {
    host: String,
    region: String,
    binding: Binding,
    mode: Mode,
    seed: Option<Selector>,
    regions: Vec<Outcome>,
}

/// The 503 of a walk that placed nothing, with what each region came to.
fn refused(reason: &str, message: String, regions: &[Outcome]) -> Refusal {
    err(StatusCode::SERVICE_UNAVAILABLE, "capacity", message)
        .with_fields(serde_json::json!({"reason": reason, "regions": regions}))
}

/// Why the first region, which no host of counts, refuses: as a create in that region alone
/// would (ADR 0128).
fn refuse_first_region(
    st: &AppState,
    reg: &Registry,
    namespace: &str,
    region: &str,
    reqs: &[Requirement],
    ask: &Ask,
) -> Refusal {
    let why = (|| {
        for r in reqs {
            refuse_class(reg, None, namespace, &r.runtime_class, region)?;
        }
        if reqs.iter().any(|r| r.egress_siblings) {
            refuse_no_siblings(reg, region)?;
        }
        for profile in reqs.iter().filter_map(|r| r.memory_profile.as_deref()) {
            refuse_no_named_memory(reg, region, profile)?;
        }
        Ok(())
    })();
    match why {
        Err(refusal) => refusal,
        Ok(()) => no_room(st, reg, &Ask { region, ..*ask }),
    }
}

/// Counts a refusal in each region found full, once (ADR 0042).
fn count_full(st: &AppState, reg: &Registry, regions: &[Outcome], ask: &Ask) {
    for o in regions.iter().filter(|o| o.outcome == Class::Full) {
        let resource = reg.shortage(
            &o.region,
            ask.memory_mb,
            ask.disk_mb,
            ask.cpu_millis,
            &st.policy,
        );
        unschedulable(st, reg, &o.region, resource, ask, None);
    }
}

/// The decision for `request`, from the registry as it is: nothing is changed, so a refusal
/// leaves the registry as it was.
fn decide(
    st: &AppState,
    reg: &Registry,
    namespace: &str,
    request: &Request,
    seeds: &[Checked],
    now: DateTime<Utc>,
) -> Result<Plan, Refusal> {
    let reqs = &request.requirements;
    let n = needs(reqs);
    let ask = Ask {
        namespace,
        region: &request.regions[0],
        memory_mb: n.memory_mb,
        cpu_millis: n.cpu_millis,
        disk_mb: n.disk_mb,
        what: "placement",
    };
    // The seeds still where the check found them.
    let seeds: Vec<&Checked> = seeds
        .iter()
        .filter(|(s, host)| {
            reg.host_of_machine(&s.machine_id)
                .is_some_and(|h| h.id == *host)
        })
        .collect();
    let seeded = |h: &HostRec| {
        seeds.iter().any(|(_, host)| *host == h.id)
            && crate::create::require_memory_profile(h, st.policy.down_after, "sandbox-ready-v1")
                .is_ok()
    };
    let finish = |h: &HostRec, binding, regions: Vec<Outcome>| {
        let seed = seeded(h)
            .then(|| seeds.iter().find(|(_, host)| *host == h.id))
            .flatten()
            .map(|(s, _)| s.clone());
        Plan {
            host: h.id.clone(),
            region: h.region.clone(),
            binding,
            mode: if seed.is_some() {
                Mode::SandboxSeed
            } else {
                Mode::Cold
            },
            seed,
            regions,
        }
    };
    // A namespace already pinned: its host, if the requirements fit there. A stack is never
    // split.
    if let Some(pinned) = reg.namespaces.get(namespace) {
        let host = reg.hosts.get(pinned);
        if let Some(h) =
            host.filter(|h| classify(h, reqs, &st.policy, now, false) == HostClass::Candidate)
        {
            let regions = vec![Outcome {
                region: h.region.clone(),
                outcome: Class::Placed,
            }];
            return Ok(finish(h, Binding::Existing, regions));
        }
        let region = host.map_or("", |h| h.region.as_str());
        let resource = reg
            .host_shortage(pinned, n.memory_mb, n.disk_mb, n.cpu_millis)
            .unwrap_or(Resource::Pressure);
        unschedulable(st, reg, region, resource, &ask, Some(pinned));
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "capacity",
            format!(
                "host {pinned}, where namespace {namespace} is, has no room for these requirements"
            ),
        ));
    }
    let mut outcomes: Vec<Outcome> = Vec::new();
    for (i, region) in request.regions.iter().enumerate() {
        let hosts: Vec<(&HostRec, HostClass)> = reg
            .hosts
            .values()
            .filter(|h| h.region == *region)
            .map(|h| (h, classify(h, reqs, &st.policy, now, true)))
            .collect();
        let classes: Vec<HostClass> = hosts.iter().map(|(_, c)| *c).collect();
        let class = region_class(&classes);
        outcomes.push(Outcome {
            region: region.clone(),
            outcome: class,
        });
        match class {
            Class::Placed => {
                let all_default = reqs
                    .iter()
                    .all(|r| api::class_name(&r.runtime_class) == api::DEFAULT_CLASS);
                // A host with a validated seed first, then as `place`: a default machine
                // away from a host with a hypervisor of its own, then the most free memory.
                let key = |h: &HostRec| {
                    (
                        seeded(h),
                        !(all_default && h.serves_nested()),
                        h.free_memory_mb(),
                    )
                };
                let best = hosts
                    .iter()
                    .filter(|(_, c)| *c == HostClass::Candidate)
                    .map(|(h, _)| *h)
                    .max_by(|a, b| key(a).cmp(&key(b)).then_with(|| b.id.cmp(&a.id)))
                    .expect("a placed region has a candidate");
                return Ok(finish(best, Binding::New, outcomes));
            }
            Class::Unconfirmed => {
                count_full(st, reg, &outcomes, &ask);
                return Err(refused(
                    "region_unconfirmed",
                    format!("region {region} has a host that served these requirements and does not answer; no other region was tried"),
                    &outcomes,
                ));
            }
            Class::Ineligible if i == 0 => {
                return Err(refuse_first_region(st, reg, namespace, region, reqs, &ask));
            }
            Class::Full | Class::Ineligible => {}
        }
    }
    count_full(st, reg, &outcomes, &ask);
    Err(refused(
        "regions_full",
        "no listed region has room for these requirements".into(),
        &outcomes,
    ))
}

fn owner(k: &str, role: Role) -> String {
    format!("{k}#{}", role.as_str())
}

/// Takes the decision into the registry: the pin, a hold per requirement, the record.
#[allow(clippy::too_many_arguments)]
fn commit(
    st: &AppState,
    reg: &mut Registry,
    namespace: &str,
    id: &str,
    request: Request,
    fingerprint: String,
    plan: Plan,
    now: DateTime<Utc>,
) -> Decision {
    match plan.binding {
        Binding::New => reg.pin(namespace, &plan.host),
        Binding::Existing => reg.note_namespace_create(namespace),
    }
    let k = key(namespace, id);
    if let Some(host) = reg.hosts.get(&plan.host).cloned() {
        for r in &request.requirements {
            if let Some(mb) = host.reservation_mb(r.size.memory_mb) {
                let need = (mb, disk_need(r.volume_gb), r.size.cpu_millis());
                reg.hold_for(
                    &host.id,
                    need,
                    owner(&k, r.role),
                    now + st.policy.admission_hold,
                );
            }
        }
    }
    let decision = Decision {
        region: plan.region,
        host: plan.host,
        binding: plan.binding,
        mode: plan.mode,
        seed: plan.seed,
        regions: plan.regions,
    };
    reg.sandbox_admissions.insert(
        k,
        Admission {
            namespace: namespace.into(),
            request_id: id.into(),
            fingerprint,
            request: None,
            mode: decision.mode,
            host: Some(decision.host.clone()),
            phase: Phase::Pending,
            at: Some(now),
            kind: Kind::Placement,
            placement: Some(Record {
                request,
                decision: decision.clone(),
                dispatched: Vec::new(),
            }),
        },
    );
    decision
}

/// The stored decision for the same id and body; a different body or kind, or an id cancelled
/// or expired, is 409.
fn replay(
    reg: &Registry,
    namespace: &str,
    id: &str,
    fingerprint: &str,
) -> Result<Option<Decision>, Refusal> {
    let Some(a) = reg.sandbox_admissions.get(&key(namespace, id)) else {
        return Ok(None);
    };
    match a.phase {
        Phase::Cancelled => return Err(conflict("admission was cancelled")),
        Phase::Expired => return Err(conflict("admission expired")),
        _ => {}
    }
    match (&a.placement, a.fingerprint == fingerprint) {
        (Some(p), true) => Ok(Some(p.decision.clone())),
        _ => Err(conflict("admission request identity conflict")),
    }
}

/// `PUT /v1/namespaces/{ns}/admissions/{id}`: the placement decision for the namespace's first
/// requirements (ADR 0128).
pub(crate) async fn admit(
    State(st): S,
    Path((namespace, id)): Path<(String, String)>,
    Json(request): Json<Request>,
) -> Result<Json<Decision>, Refusal> {
    authenticated(&st)?;
    check_ids(&namespace, &id)?;
    validate(&request)?;
    // Struct serialization gives stable field order, independent of caller JSON key order.
    let fingerprint = serde_json::to_string(&request).expect("request serializes");
    let prior = replay(&st.reg.lock().unwrap(), &namespace, &id, &fingerprint)?;
    if let Some(decision) = prior {
        st.save().await.map_err(registry_error)?;
        return Ok(Json(decision));
    }
    // A seed is asked of its host over the network, so before the lock. One that fails is
    // left out: the placement is cold, never a refusal.
    let offered: &[Selector] = request
        .requirements
        .iter()
        .find(|r| r.role == Role::Consumer)
        .map_or(&[], |r| r.sandbox_seeds.as_slice());
    let size = request
        .requirements
        .iter()
        .find(|r| r.role == Role::Consumer)
        .map(|r| r.size)
        .unwrap_or_default();
    let checks = offered.iter().map(|selector| {
        let st = &st;
        let id = &id;
        async move {
            let seed = api::SandboxSeed {
                machine_id: selector.machine_id.clone(),
                snapshot: selector.snapshot.clone(),
                generation: selector.generation.clone(),
                request_id: id.clone(),
            };
            crate::create::check_sandbox_selector(st, &seed, size)
                .await
                .ok()
                .map(|host| (selector.clone(), host))
        }
    });
    let seeds: Vec<Checked> = futures::future::join_all(checks)
        .await
        .into_iter()
        .flatten()
        .collect();
    let decision = {
        let mut reg = st.reg.lock().unwrap();
        if let Some(decision) = replay(&reg, &namespace, &id, &fingerprint)? {
            decision
        } else {
            let now = Utc::now();
            let plan = decide(&st, &reg, &namespace, &request, &seeds, now)?;
            commit(
                &st,
                &mut reg,
                &namespace,
                &id,
                request,
                fingerprint,
                plan,
                now,
            )
        }
    };
    st.save().await.map_err(registry_error)?;
    Ok(Json(decision))
}

/// The record of a live admission: one cancelled or expired answers 409.
fn live(a: &Admission) -> Result<&Record, Refusal> {
    match a.phase {
        Phase::Cancelled => Err(conflict("admission cancelled")),
        Phase::Expired => Err(conflict("admission expired")),
        _ => a
            .placement
            .as_ref()
            .ok_or_else(|| conflict("admission cancelled")),
    }
}

/// Whether the create is the admitted `consumer` (ADR 0128), on the namespace's pin.
pub(super) fn check_create(
    reg: &Registry,
    a: &Admission,
    req: &api::CreateMachineRequest,
) -> Result<(), Refusal> {
    let record = live(a)?;
    let mismatch = || conflict("create placement admission mismatch");
    let want = record.requirement(Role::Consumer).ok_or_else(mismatch)?;
    let decision = &record.decision;
    let seeded = decision.seed.is_some();
    if req.region != decision.region
        || req.size != want.size
        || req.volume.as_ref().map(|v| v.size_gb) != want.volume_gb
        || api::class_name(&req.runtime_class) != api::class_name(&want.runtime_class)
        || req.egress.as_ref().is_some_and(|e| e.siblings) != want.egress_siblings
        || (!seeded && req.template_build.as_deref() != want.memory_profile.as_deref())
        || req.fork.is_some()
        || req.restore.is_some()
    {
        return Err(mismatch());
    }
    match (&req.sandbox_seed, &decision.seed) {
        (None, None) => {}
        (Some(seed), Some(admitted))
            if seed.request_id == a.request_id
                && seed.machine_id == admitted.machine_id
                && seed.snapshot == admitted.snapshot
                && seed.generation == admitted.generation => {}
        _ => return Err(conflict("create selector differs from admission")),
    }
    if reg.namespaces.get(&req.namespace) != Some(&decision.host) {
        return Err(conflict("admitted namespace pin changed"));
    }
    Ok(())
}

/// The role a gateway or quota `PUT` with a placement id dispatches, after the checks: the
/// admission is live, in the request's region, on the namespace's pin, and a gateway is the
/// admitted `gateway`. `None`: a quota, which ends cancellation and consumes no requirement.
/// `Ok(None)` for an id that is not a placement admission's.
pub(crate) fn check_namespace_put(
    reg: &Registry,
    namespace: &str,
    id: &str,
    region: &str,
    gateway: Option<&api::GatewaySpec>,
) -> Result<Option<Option<Role>>, Refusal> {
    let Some(a) = reg.sandbox_admissions.get(&key(namespace, id)) else {
        return Ok(None);
    };
    if a.kind != Kind::Placement {
        return Ok(None);
    }
    let record = live(a)?;
    let mismatch = || conflict("gateway placement admission mismatch");
    if region != record.decision.region
        || reg.namespaces.get(namespace) != Some(&record.decision.host)
    {
        return Err(mismatch());
    }
    let Some(spec) = gateway else {
        return Ok(Some(None));
    };
    let want = record.requirement(Role::Gateway).ok_or_else(mismatch)?;
    if spec.size() != want.size || spec.volume_gb != want.volume_gb {
        return Err(mismatch());
    }
    Ok(Some(Some(Role::Gateway)))
}

/// A dispatch under the admission, before the host is asked (ADR 0128): the requirement's own
/// hold is counted as free while the host's room is checked, so the room is not counted twice;
/// if it is not there the hold is put back and the answer is 503 `capacity`, with the role not
/// marked. `role` `None` is a quota, which only ends cancellation. A role dispatched before is
/// the caller's retry: no hold taken over, no check.
pub(crate) fn dispatch(
    st: &AppState,
    reg: &mut Registry,
    namespace: &str,
    id: &str,
    role: Option<Role>,
    host: &str,
    ask: &Ask,
) -> Result<(), Refusal> {
    let k = key(namespace, id);
    let done = reg
        .sandbox_admissions
        .get(&k)
        .and_then(|a| a.placement.as_ref())
        .zip(role)
        .is_some_and(|(p, role)| p.dispatched.contains(&role));
    if let (Some(role), false) = (role, done) {
        let taken = reg.take_over_hold(host, &owner(&k, role));
        let room = reg.hosts.get(host).is_some_and(|h| {
            h.reservation_mb(ask.memory_mb)
                .is_some_and(|mb| h.has_room(mb, ask.disk_mb, ask.cpu_millis))
        });
        if !room {
            if let Some(hold) = taken {
                reg.restore_hold(host, hold);
            }
            let resource = reg
                .host_shortage(host, ask.memory_mb, ask.disk_mb, ask.cpu_millis)
                .unwrap_or(Resource::Memory);
            let region = reg.hosts.get(host).map_or("", |h| h.region.as_str());
            unschedulable(st, reg, region, resource, ask, Some(host));
            return Err(err(
                StatusCode::SERVICE_UNAVAILABLE,
                "capacity",
                format!("host {host} has no room for this {}", ask.what),
            ));
        }
    }
    if let Some(a) = reg.sandbox_admissions.get_mut(&k) {
        a.phase = Phase::Dispatched;
        a.at = Some(Utc::now());
        if let (Some(p), Some(role)) = (a.placement.as_mut(), role) {
            if !p.dispatched.contains(&role) {
                p.dispatched.push(role);
            }
        }
    }
    Ok(())
}

/// Ends the pending admissions left alone for `window` since their last change: the fence and
/// the holds go, the id stays as a tombstone for another window (ADR 0128, ADR 0119). A role
/// already dispatched is not undone.
pub(super) fn expire(reg: &mut Registry, now: DateTime<Utc>, window: chrono::Duration) {
    let due: Vec<String> = reg
        .sandbox_admissions
        .iter()
        .filter(|(_, a)| a.pending() && a.at.is_some_and(|at| now - at >= window))
        .map(|(k, _)| k.clone())
        .collect();
    for k in due {
        if let Some(a) = reg.sandbox_admissions.get_mut(&k) {
            a.phase = Phase::Expired;
            a.at = Some(now);
        }
        reg.release_owned(&format!("{k}#"));
    }
}
