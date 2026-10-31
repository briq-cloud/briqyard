//! Kernel observations, only for the explicitly supported official service lineage.
use super::{
    fs::{self, Dir, Owner},
    lock::DomainLock,
    unit, *,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

pub(super) struct Barrier {
    lock: Arc<DomainLock>,
    proc: Dir,
    start: u64,
    root: Dir,
    service: Dir,
    unit: unit::Identity,
    namespace: Arc<super::namespace::Namespace>,
}
impl Barrier {
    pub(super) async fn acquire() -> Result<Self> {
        let lock = Arc::new(DomainLock::acquire().context("exclusive VMM cgroup domain")?);
        let pid = std::process::id();
        let proc = Dir::absolute(Path::new(&format!("/proc/{pid}")))?;
        let start = unit::self_start(&proc.text(c"stat", 4096)?)?;
        unit::self_membership(&proc, start)?;
        let root = unit::root_cgroup()?;
        let service = unit::actual_group(&root)?;
        let namespace = Arc::new(super::namespace::Namespace::capture(
            &proc, start, &root, &service,
        )?);
        let (text, hooks) = unit::query().await?;
        let unit = unit::validate(&text, pid, &hooks).context("official effective daemon unit")?;
        Ok(Self {
            lock,
            proc,
            start,
            root,
            service,
            unit,
            namespace,
        })
    }

    pub(super) async fn finish(
        self,
        machines: &[RecoveryMachine],
        jailer: &Path,
        vmm: &str,
    ) -> Result<Recovered> {
        if machines.len() > 4096 {
            return Err(fs::invalid().into());
        }
        self.lock.check()?;
        self.namespace.check()?;
        let jailer = super::provenance::Jailer::verify(jailer, vmm).await?;
        let mut identities = BTreeMap::new();
        for machine in machines {
            let encoded = super::super::fc_id(&machine.id);
            if encoded.replacen("m-", "m_", 1) != machine.id
                || identities.insert(encoded, machine.id.clone()).is_some()
            {
                return Err(anyhow!("machine cgroup identity collision"));
            }
        }
        let parent = match self.root.child(c"firecracker") {
            Ok(parent) => Some(parent),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let mut ids: BTreeSet<String> = machines.iter().map(|m| m.id.clone()).collect();
        let mut leaf_names = BTreeSet::new();
        if let Some(parent) = &parent {
            parent.owned(Owner::ROOT, false)?;
            if !fs::pids(&parent.text(c"cgroup.procs", 65536)?)?.is_empty() {
                return Err(anyhow!("unclassified VMM domain member"));
            }
            for name in parent.children(4096)? {
                let name = name.to_str().map_err(|_| fs::invalid())?;
                // cgroup control files are regular files, never candidate subgroups.
                let child = std::ffi::CString::new(name)?;
                match parent.child(&child) {
                    Ok(dir) => {
                        dir.owned(Owner::ROOT, false)?;
                    }
                    Err(e) if e.raw_os_error() == Some(libc::ENOTDIR) => {
                        if !parent.regular(&child)? {
                            return Err(fs::invalid().into());
                        }
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                }
                if !name.starts_with("m-") {
                    return Err(anyhow!("unknown VMM cgroup candidate"));
                }
                let id = name.replacen("m-", "m_", 1);
                if super::super::fc_id(&id) != name || !leaf_names.insert(name.to_owned()) {
                    return Err(fs::invalid().into());
                }
                ids.insert(id);
            }
        }
        let mut observed = Vec::new();
        for id in ids {
            let leaf = super::super::retirement::Leaf::capture(&id)?;
            let members = leaf
                .as_ref()
                .map(|leaf| leaf.inventory(&id))
                .transpose()?
                .unwrap_or_default();
            // The supported jailer leaves one VMM process. A launcher/foreign member or
            // multiple potential creators remains unresolved; never infer it died.
            if members.len() > 1 {
                return Err(anyhow!("unsettled VMM cgroup candidates"));
            }
            let live = if let Some(pid) = members.first() {
                Some(Arc::new(
                    super::super::memory::ProcessIdentity::open(&id, *pid)
                        .context("unresolved VMM cgroup member")?,
                ))
            } else {
                None
            };
            if let (Some(live), Some(pid)) = (&live, members.first()) {
                live.confirm_group(&id, *pid)?;
            }
            observed.push((id, leaf, members, live));
        }
        // The last helper is fully reaped by query(). No subsequent helper or process
        // creator runs between this unit recheck and the service/leaf kernel checks.
        let (text, hooks) = unit::query().await?;
        let current = unit::validate(&text, std::process::id(), &hooks)?;
        if current != self.unit {
            return Err(anyhow!("daemon supervision changed during recovery"));
        }
        self.lock.check()?;
        self.namespace.check()?;
        unit::self_membership(&self.proc, self.start)?;
        if !self.root.same(&unit::root_cgroup()?)?
            || !self.service.same(&unit::actual_group(&self.root)?)?
        {
            return Err(anyhow!("daemon cgroup identity changed"));
        }
        unit::final_service_pids(
            &self.namespace.service_pids()?,
            std::process::id(),
            self.service.has_directories()?,
        )
        .context("daemon service still contains a possible launcher")?;
        if let Some(parent) = parent {
            if !parent.same(&self.root.child(c"firecracker")?)?
                || !fs::pids(&parent.text(c"cgroup.procs", 65536)?)?.is_empty()
            {
                return Err(fs::invalid().into());
            }
            let mut final_names = BTreeSet::new();
            for name in parent.children(4096)? {
                match parent.child(&name) {
                    Ok(_) => {
                        final_names.insert(name.to_str().map_err(|_| fs::invalid())?.to_owned());
                    }
                    Err(e) if e.raw_os_error() == Some(libc::ENOTDIR) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            if final_names != leaf_names {
                return Err(anyhow!("VMM cgroup inventory changed"));
            }
        } else {
            match self.root.child(c"firecracker") {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(fs::invalid().into()),
            }
        }
        let mut entries = Vec::new();
        for (id, leaf, members, live) in observed {
            match &leaf {
                Some(leaf) => {
                    if leaf.inventory(&id)? != members {
                        return Err(anyhow!("VMM membership changed during recovery"));
                    }
                    if let (Some(live), Some(pid)) = (&live, members.first()) {
                        live.confirm_group(&id, *pid)?;
                    } else {
                        leaf.check(&id)?;
                    }
                }
                None => {
                    if super::super::retirement::Leaf::capture(&id)?.is_some() {
                        return Err(fs::invalid().into());
                    }
                }
            }
            entries.push(RecoveredEntry {
                id,
                pid: members.first().copied(),
                live,
            });
        }
        Ok(Recovered {
            lock: self.lock,
            jailer,
            namespace: self.namespace,
            entries,
        })
    }
}
