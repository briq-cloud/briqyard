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
        let proc = Dir::absolute(Path::new(&format!("/proc/{pid}")))
            .with_context(|| format!("opening /proc/{pid}"))?;
        let start = unit::self_start(
            &proc
                .text(c"stat", 4096)
                .context("reading /proc/self/stat")?,
        )
        .context("parsing the start time in /proc/self/stat")?;
        unit::self_membership(&proc, start).context(
            "daemon is not the process of its unit: /proc/self/cgroup must read \
             0::/system.slice/briqyardd.service and its command line must be \
             /usr/local/bin/briqyardd --config /etc/briqyard/config.yaml",
        )?;
        let root = unit::root_cgroup().context("cgroup v2 root at /sys/fs/cgroup")?;
        let service = unit::actual_group(&root)
            .context("cgroup directory /sys/fs/cgroup/system.slice/briqyardd.service")?;
        let namespace = Arc::new(
            super::namespace::Namespace::capture(&proc, start, &root, &service)
                .context("capturing the service's namespaces")?,
        );
        let (text, hooks) = unit::query()
            .await
            .context("querying the unit with busctl and systemctl")?;
        let unit = unit::validate(&text, pid, &hooks)
            .context("the unit systemd reports is not the official briqyardd.service (Id, ControlGroup, FragmentPath, MainPID, ExecStart)")?;
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
        if machines.len() > MAX_LEAVES {
            return Err(anyhow!(
                "{} recorded machines exceed the recovery bound of {MAX_LEAVES}",
                machines.len()
            ));
        }
        self.lock
            .check()
            .context("domain lock /run/briqyard/cgroup-domain.lock changed")?;
        self.namespace
            .check()
            .context("service cgroup namespace changed (ownership, membership files or inodes)")?;
        let jailer = super::provenance::Jailer::verify(jailer, vmm)
            .await
            .context("verifying the configured jailer")?;
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
            Err(e) => {
                return Err(anyhow::Error::new(e).context("opening /sys/fs/cgroup/firecracker"))
            }
        };
        let mut ids: BTreeSet<String> = machines.iter().map(|m| m.id.clone()).collect();
        let mut leaf_names = BTreeSet::new();
        if let Some(parent) = &parent {
            parent.owned(Owner::ROOT, false).context(
                "/sys/fs/cgroup/firecracker must be root-owned and not group/other-writable",
            )?;
            if !fs::pids(
                &parent
                    .text(c"cgroup.procs", 65536)
                    .context("reading /sys/fs/cgroup/firecracker/cgroup.procs")?,
            )
            .context("parsing /sys/fs/cgroup/firecracker/cgroup.procs")?
            .is_empty()
            {
                return Err(anyhow!(
                    "unclassified VMM domain member: /sys/fs/cgroup/firecracker/cgroup.procs is not empty"
                ));
            }
            for name in parent
                .children(PARENT_ENTRIES)
                .context("listing /sys/fs/cgroup/firecracker")?
            {
                let name = name
                    .to_str()
                    .map_err(|_| anyhow!("non-UTF-8 name in /sys/fs/cgroup/firecracker"))?;
                // cgroup control files are regular files, never candidate subgroups.
                let child = std::ffi::CString::new(name)?;
                match parent.child(&child) {
                    Ok(dir) => {
                        dir.owned(Owner::ROOT, false).with_context(|| {
                            format!("/sys/fs/cgroup/firecracker/{name} must be root-owned and not group/other-writable")
                        })?;
                    }
                    Err(e) if e.raw_os_error() == Some(libc::ENOTDIR) => {
                        if !parent.regular(&child)? {
                            return Err(anyhow!(
                                "/sys/fs/cgroup/firecracker/{name} is neither a directory nor a regular file"
                            ));
                        }
                        continue;
                    }
                    Err(e) => {
                        return Err(anyhow::Error::new(e)
                            .context(format!("opening /sys/fs/cgroup/firecracker/{name}")))
                    }
                }
                if !name.starts_with("m-") {
                    return Err(anyhow!("unknown VMM cgroup candidate {name}"));
                }
                let id = name.replacen("m-", "m_", 1);
                if super::super::fc_id(&id) != name || !leaf_names.insert(name.to_owned()) {
                    return Err(anyhow!("VMM cgroup {name} is not a canonical machine name"));
                }
                ids.insert(id);
            }
        }
        // An idle leaf is remembered by inode alone: a long-lived host can hold thousands of
        // leaves left by machines that are gone, and a held leaf costs a dozen descriptors.
        let mut observed = Vec::new();
        for id in ids {
            let leaf = super::super::retirement::Leaf::capture(&id)
                .with_context(|| format!("opening the VMM cgroup of {id}"))?;
            let members = leaf
                .as_ref()
                .map(|leaf| leaf.inventory(&id))
                .transpose()
                .with_context(|| format!("VMM cgroup of {id} is not a settled leaf (shape, membership, populated or frozen)"))?
                .unwrap_or_default();
            // The supported jailer leaves one VMM process. A launcher/foreign member or
            // multiple potential creators remains unresolved; never infer it died.
            if members.len() > 1 {
                return Err(anyhow!("unsettled VMM cgroup candidates in {id}"));
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
            let held = match leaf {
                Some(leaf) if members.is_empty() => Held::Idle(leaf.identity()?),
                Some(leaf) => Held::Leaf(leaf),
                None => Held::Absent,
            };
            observed.push((id, held, members, live));
        }
        // The last helper is fully reaped by query(). No subsequent helper or process
        // creator runs between this unit recheck and the service/leaf kernel checks.
        let (text, hooks) = unit::query()
            .await
            .context("querying the unit with busctl and systemctl (recheck)")?;
        let current = unit::validate(&text, std::process::id(), &hooks)
            .context("the unit systemd reports is not the official briqyardd.service (recheck)")?;
        if current != self.unit {
            return Err(anyhow!("daemon supervision changed during recovery"));
        }
        self.lock
            .check()
            .context("domain lock /run/briqyard/cgroup-domain.lock changed (recheck)")?;
        self.namespace
            .check()
            .context("service cgroup namespace changed (recheck)")?;
        unit::self_membership(&self.proc, self.start)
            .context("daemon cgroup or command line changed (recheck)")?;
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
            if !parent.same(&self.root.child(c"firecracker")?)? {
                return Err(anyhow!(
                    "/sys/fs/cgroup/firecracker was replaced during recovery"
                ));
            }
            if !fs::pids(&parent.text(c"cgroup.procs", 65536)?)?.is_empty() {
                return Err(anyhow!(
                    "/sys/fs/cgroup/firecracker/cgroup.procs gained a member during recovery"
                ));
            }
            let mut final_names = BTreeSet::new();
            for name in parent
                .children(PARENT_ENTRIES)
                .context("listing /sys/fs/cgroup/firecracker (recheck)")?
            {
                match parent.child(&name) {
                    Ok(_) => {
                        final_names.insert(
                            name.to_str()
                                .map_err(|_| {
                                    anyhow!("non-UTF-8 name in /sys/fs/cgroup/firecracker")
                                })?
                                .to_owned(),
                        );
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
                _ => {
                    return Err(anyhow!(
                        "/sys/fs/cgroup/firecracker appeared during recovery"
                    ))
                }
            }
        }
        let mut entries = Vec::new();
        for (id, held, members, live) in observed {
            match held {
                Held::Leaf(leaf) => {
                    if leaf.inventory(&id)? != members {
                        return Err(anyhow!("VMM membership changed during recovery"));
                    }
                    if let (Some(live), Some(pid)) = (&live, members.first()) {
                        live.confirm_group(&id, *pid)?;
                    } else {
                        leaf.check(&id)?;
                    }
                }
                Held::Idle(identity) => {
                    let leaf = super::super::retirement::Leaf::capture(&id)?
                        .ok_or_else(|| anyhow!("VMM cgroup of {id} vanished during recovery"))?;
                    if leaf.identity()? != identity {
                        return Err(anyhow!("VMM cgroup of {id} was replaced during recovery"));
                    }
                    let members = leaf.inventory(&id).with_context(|| {
                        format!(
                            "VMM cgroup of {id} is no longer a settled leaf (shape, populated or frozen)"
                        )
                    })?;
                    if !members.is_empty() {
                        return Err(anyhow!(
                            "VMM cgroup of {id} gained a member during recovery"
                        ));
                    }
                }
                Held::Absent => {
                    if super::super::retirement::Leaf::capture(&id)?.is_some() {
                        return Err(anyhow!("VMM cgroup of {id} appeared during recovery"));
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

/// `MAX_LEAVES` plus the parent's own control files. Past it the listing is refused, never
/// truncated.
const PARENT_ENTRIES: usize = MAX_LEAVES + 1024;

/// What the barrier keeps of a machine's cgroup between its first look and its last.
enum Held {
    /// A leaf with a VMM process in it: held open, with its memberships.
    Leaf(super::super::retirement::Leaf),
    /// A leaf with no process: its inode, looked at again at the end.
    Idle((u64, u64)),
    /// No leaf yet.
    Absent,
}
