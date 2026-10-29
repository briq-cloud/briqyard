//! A namespace's quota (ADR 0025) and the host's committed memory.

use super::*;

/// Whether `need` MB more fit next to `used` on a host of `cap`.
pub(super) fn admit(used: u32, cap: u32, need: u32) -> Result<(), MError> {
    match used.checked_add(need) {
        Some(total) if total <= cap => Ok(()),
        _ => Err(MError::Capacity(format!("{used} MB used of {cap}"))),
    }
}

/// A limit of a namespace's quota that a create or a start would pass (ADR 0025).
#[derive(Debug, PartialEq)]
pub(super) struct Exceeded {
    pub(super) namespace: String,
    pub(super) resource: &'static str,
    pub(super) limit: u32,
    pub(super) used: u32,
    pub(super) need: u32,
}

impl std::fmt::Display for Exceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "namespace {}'s quota: {} {} of {} used, {} more asked",
            self.namespace, self.resource, self.used, self.limit, self.need
        )
    }
}

impl Exceeded {
    pub(super) fn event(&self, message: String) -> Ev {
        Ev::warning(reason::QUOTA_EXCEEDED, message).data(json!({
            "resource": self.resource, "limit": self.limit, "used": self.used, "need": self.need,
        }))
    }
}

/// The first limit of `quota` that `need` more would pass next to `used`; a resource the
/// request does not ask for is never refused, even past a limit lowered under the use.
pub(super) fn over_quota(
    namespace: &str,
    quota: &api::Quota,
    used: &api::QuotaUse,
    need: &api::QuotaUse,
) -> Option<Exceeded> {
    [
        ("machines", quota.machines, used.machines, need.machines),
        ("disk_gb", quota.disk_gb, used.disk_gb, need.disk_gb),
        ("memory_mb", quota.memory_mb, used.memory_mb, need.memory_mb),
        ("vcpus", quota.vcpus, used.vcpus, need.vcpus),
    ]
    .into_iter()
    .find_map(|(resource, limit, used, need)| {
        let limit = limit?;
        (need > 0 && used.saturating_add(need) > limit).then(|| Exceeded {
            namespace: namespace.into(),
            resource,
            limit,
            used,
            need,
        })
    })
}

/// What a machine of this record counts toward its namespace's quota: itself, its volume, and
/// its size while it holds memory, or when `starting` it is about to.
pub(super) fn quota_need(r: &Record, starting: bool) -> api::QuotaUse {
    let runs = starting || commits_memory(r);
    api::QuotaUse {
        machines: 1,
        memory_mb: if runs { r.size.memory_mb } else { 0 },
        vcpus: if runs { r.size.vcpus } else { 0 },
        disk_gb: r.volume.as_ref().map_or(0, |v| v.size_gb),
    }
}

/// What a namespace's machines hold, its gateway included: its quota's use.
pub(super) fn namespace_use(
    machines: &HashMap<String, Arc<Entry>>,
    namespace: &str,
) -> api::QuotaUse {
    let mut u = api::QuotaUse::default();
    for e in machines.values() {
        let r = e.rec.lock().unwrap();
        if r.namespace == namespace {
            let n = quota_need(&r, false);
            u.machines += n.machines;
            u.memory_mb += n.memory_mb;
            u.vcpus += n.vcpus;
            u.disk_gb += n.disk_gb;
        }
    }
    u
}

impl Manager {
    // --- quotas (ADR 0025) ---

    /// The namespace's quota and what it holds.
    pub fn quota(&self, namespace: &str) -> Result<api::NamespaceQuota, MError> {
        let quota = self
            .namespace_of(namespace)
            .ok_or(MError::NotFound)?
            .rec
            .quota;
        let used = namespace_use(&self.inner.machines.lock().unwrap(), namespace);
        Ok(api::NamespaceQuota {
            namespace: namespace.into(),
            quota,
            used,
        })
    }

    /// Puts the namespace's quota, the namespace made when it has nothing yet (as a gateway is), so
    /// its first create is held to it. A quota under the use stops nothing: what comes next
    /// is refused.
    pub async fn set_quota(
        &self,
        namespace: &str,
        quota: api::Quota,
    ) -> Result<api::NamespaceQuota, MError> {
        check_namespace_id(namespace)?;
        let mut t = self.ensure_namespace(namespace).await?;
        t.rec.quota = quota;
        self.inner
            .store
            .put(crate::store::NAMESPACES, namespace, &t.rec)?;
        if let Some(kept) = self.inner.namespaces.lock().unwrap().get_mut(namespace) {
            kept.rec.quota = quota;
        }
        self.quota(namespace)
    }
}

/// What the machines in the map hold now: memory and vCPUs committed (a create that will start
/// them included, ADR 0048), and how many are up.
pub(super) fn committed(machines: &HashMap<String, Arc<Entry>>) -> (api::Capacity, usize) {
    let mut used = api::Capacity::default();
    let mut up = 0;
    for e in machines.values() {
        let r = e.rec.lock().unwrap();
        if commits_memory(&r) {
            up += usize::from(holds_memory(&r.state));
            used.memory_mb += r.size.memory_mb;
            used.vcpus += r.size.vcpus;
        }
    }
    (used, up)
}
