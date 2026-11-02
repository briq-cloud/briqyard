//! Factory-owned launch settlement. Unknown outcomes never become death receipts.

use super::*;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};

#[derive(Default)]
pub(crate) struct Launches {
    entries: Mutex<HashMap<String, Epoch>>,
    open: AtomicBool,
    initialized: AtomicBool,
    #[cfg(target_os = "linux")]
    domain: Mutex<Option<Arc<super::recovery::lock::DomainLock>>>,
    #[cfg(target_os = "linux")]
    jailer: Mutex<Option<super::recovery::provenance::Jailer>>,
    #[cfg(target_os = "linux")]
    namespace: Mutex<Option<Arc<super::recovery::namespace::Namespace>>>,
}
struct Epoch {
    done: watch::Receiver<bool>,
    #[cfg(target_os = "linux")]
    live: Option<Arc<super::memory::ProcessIdentity>>,
    pid: Option<u32>,
}
impl Epoch {
    fn empty() -> Self {
        let (_, done) = watch::channel(true);
        Self {
            done,
            pid: None,
            #[cfg(target_os = "linux")]
            live: None,
        }
    }
}

impl Launches {
    pub(super) fn initialize(&self, recovered: super::recovery::Recovered) -> Result<()> {
        if self.open.load(Ordering::SeqCst) || self.initialized.load(Ordering::SeqCst) {
            return Err(anyhow!("VMM recovery epoch already initialized"));
        }
        let mut entries = self.entries.lock().unwrap();
        if !entries.is_empty() {
            return Err(anyhow!("launches preceded recovery barrier"));
        }
        for entry in recovered.entries {
            let mut epoch = Epoch::empty();
            epoch.pid = entry.pid;
            #[cfg(target_os = "linux")]
            {
                if entry.live.is_some() {
                    let (_, done) = watch::channel(false);
                    epoch.done = done;
                }
                epoch.live = entry.live;
            }
            #[cfg(not(target_os = "linux"))]
            if entry.pid.is_some() {
                return Err(anyhow!("native process proof requires Linux"));
            }
            if entries.insert(entry.id, epoch).is_some() {
                return Err(anyhow!("duplicate recovery identity"));
            }
        }
        #[cfg(target_os = "linux")]
        {
            *self.domain.lock().unwrap() = Some(recovered.lock);
            *self.jailer.lock().unwrap() = Some(recovered.jailer);
            *self.namespace.lock().unwrap() = Some(recovered.namespace);
        }
        self.initialized.store(true, Ordering::SeqCst);
        Ok(())
    }
    pub(super) fn open(&self) -> Result<()> {
        if !self.initialized.load(Ordering::SeqCst) {
            return Err(anyhow!("VMM startup barrier unavailable"));
        }
        #[cfg(target_os = "linux")]
        if let Some(domain) = self.domain.lock().unwrap().as_ref() {
            domain.check()?;
        } else {
            return Err(anyhow!("VMM lifetime domain ownership unavailable"));
        }
        self.open.store(true, Ordering::SeqCst);
        Ok(())
    }
    #[cfg(test)]
    fn testing() -> Self {
        Self {
            open: AtomicBool::new(true),
            initialized: AtomicBool::new(true),
            ..Self::default()
        }
    }
    pub(super) fn ids(&self) -> Vec<String> {
        self.entries.lock().unwrap().keys().cloned().collect()
    }
    #[cfg(target_os = "linux")]
    pub(super) fn recovered_identity(
        &self,
        id: &str,
        pid: u32,
    ) -> Result<Arc<super::memory::ProcessIdentity>> {
        if self.open.load(Ordering::SeqCst) {
            return Err(anyhow!("recovery authority is startup-only"));
        }
        self.owner_check()?;
        let entries = self.entries.lock().unwrap();
        let entry = entries
            .get(id)
            .context("recovered process identity unavailable")?;
        if entry.pid != Some(pid) {
            return Err(anyhow!("recorded and recovered VMM identities differ"));
        }
        entry
            .live
            .clone()
            .context("recovered VMM handle unavailable")
    }
    #[cfg(target_os = "linux")]
    pub(super) fn adopt(&self, id: &str, pid: u32) -> Result<Attempt> {
        if self.open.load(Ordering::SeqCst) {
            return Err(anyhow!("recovery authority is startup-only"));
        }
        self.owner_check()?;
        let mut entries = self.entries.lock().unwrap();
        let entry = entries
            .get_mut(id)
            .context("recovered launch unavailable")?;
        if entry.pid != Some(pid) || entry.live.is_none() {
            return Err(anyhow!("recovered VMM identity mismatch"));
        }
        let (done, receiver) = watch::channel(false);
        entry.done = receiver;
        // Keep the exact handle for checked settlement if adoption later fails.
        Ok(Attempt {
            done,
            spawned: true,
            #[cfg(target_os = "linux")]
            jailer: None,
            namespace: self.namespace.lock().unwrap().clone(),
        })
    }
    #[cfg(target_os = "linux")]
    pub(super) async fn settle_recovered(&self, id: &str) -> Result<()> {
        if self.open.load(Ordering::SeqCst) {
            return Err(anyhow!("recovery settlement is startup-only"));
        }
        self.owner_check()?;
        let (live, pid) = {
            let entries = self.entries.lock().unwrap();
            let entry = entries.get(id).context("recovery epoch unavailable")?;
            (entry.live.clone(), entry.pid)
        };
        if let (Some(live), Some(pid)) = (live, pid) {
            let evidence = super::memory::OomEvidence::capture(id, pid);
            match live.signal_kill() {
                Ok(()) => {}
                Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
                Err(e) => return Err(e.into()),
            }
            tokio::time::timeout(Duration::from_secs(10), live.wait_dead())
                .await
                .context("recovered VMM death deadline")??;
            if let Some(evidence) = evidence {
                evidence.record(id);
            } else {
                tracing::warn!(
                    machine = id,
                    reason = "vmm_oom_evidence_unavailable",
                    "VMM local memory events baseline unavailable"
                );
            }
            self.owner_check()?;
            if let Some(leaf) = super::retirement::Leaf::capture(id)? {
                leaf.check(id)?;
            }
            let mut entries = self.entries.lock().unwrap();
            let entry = entries.get_mut(id).context("recovery epoch disappeared")?;
            if entry.pid != Some(pid)
                || !entry
                    .live
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &live))
                || self.open.load(Ordering::SeqCst)
            {
                return Err(anyhow!("recovery launch epoch changed"));
            }
            *entry = Epoch::empty();
        }
        self.check(id)
    }
    fn owner_check(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            if let Some(domain) = self.domain.lock().unwrap().as_ref() {
                domain.check()?;
            }
            if let Some(namespace) = self.namespace.lock().unwrap().as_ref() {
                namespace.check()?;
            }
            if let Some(jailer) = self.jailer.lock().unwrap().as_ref() {
                jailer.check()?;
            }
        }
        Ok(())
    }
    /// Called only when a new original machine identity is registered, before any spawn.
    pub(super) fn new_machine(&self, id: &str) -> Result<()> {
        if !self.open.load(Ordering::SeqCst) {
            return Err(anyhow!("managed spawning is closed during recovery"));
        }
        self.owner_check()?;
        let mut entries = self.entries.lock().unwrap();
        if entries.contains_key(id) {
            return Err(anyhow!("machine launch identity already registered"));
        }
        entries.insert(id.into(), Epoch::empty());
        Ok(())
    }

    pub(super) fn begin(&self, id: &str) -> Result<Attempt> {
        if !self.open.load(Ordering::SeqCst) {
            return Err(anyhow!("managed spawning is closed during recovery"));
        }
        self.owner_check()?;
        let mut entries = self.entries.lock().unwrap();
        if !entries.get(id).is_some_and(|entry| *entry.done.borrow()) {
            return Err(anyhow!(
                "registered VMM launch epoch is unavailable or unsettled"
            ));
        }
        #[cfg(target_os = "linux")]
        let jailer = self
            .jailer
            .lock()
            .unwrap()
            .as_ref()
            .map(|jailer| jailer.lease())
            .transpose()?;
        let (done, receiver) = watch::channel(false);
        entries.insert(
            id.into(),
            Epoch {
                done: receiver,
                pid: None,
                #[cfg(target_os = "linux")]
                live: None,
            },
        );
        Ok(Attempt {
            done,
            spawned: false,
            #[cfg(target_os = "linux")]
            jailer,
            #[cfg(target_os = "linux")]
            namespace: self.namespace.lock().unwrap().clone(),
        })
    }

    pub(super) fn check(&self, id: &str) -> Result<()> {
        self.owner_check()?;
        if self
            .entries
            .lock()
            .unwrap()
            .get(id)
            .is_some_and(|entry| *entry.done.borrow())
        {
            Ok(())
        } else {
            Err(anyhow!(
                "VMM death proof unavailable; retain machine for recovery"
            ))
        }
    }

    pub(super) fn forget(&self, id: &str) {
        self.entries.lock().unwrap().remove(id);
    }
}

pub(super) struct Attempt {
    done: watch::Sender<bool>,
    spawned: bool,
    #[cfg(target_os = "linux")]
    jailer: Option<super::recovery::provenance::LaunchExecutable>,
    #[cfg(target_os = "linux")]
    namespace: Option<Arc<super::recovery::namespace::Namespace>>,
}
impl Attempt {
    #[cfg(target_os = "linux")]
    pub(super) fn confirm_empty_scope(&self, id: &str) -> Result<()> {
        let namespace = self
            .namespace
            .as_ref()
            .context("launch namespace ownership unavailable")?;
        namespace.check()?;
        if let Some(leaf) = super::retirement::Leaf::capture(id)? {
            leaf.check(id)?;
        }
        namespace.check()?;
        Ok(())
    }
    #[cfg(target_os = "linux")]
    pub(super) fn jailer_program(&self, configured: &Path) -> Result<PathBuf> {
        self.jailer
            .as_ref()
            .context("approved jailer executable lease unavailable")?
            .program(configured)
            .map_err(Into::into)
    }
    pub(super) fn spawned(&mut self) {
        self.spawned = true;
    }
    pub(super) fn complete(&self) {
        self.done.send_replace(true);
    }
    pub(super) fn receiver(&self) -> watch::Receiver<bool> {
        self.done.subscribe()
    }
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if !self.spawned {
            self.complete();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn production_factory_is_closed_until_a_recovery_authority_is_installed() {
        let launches = Launches::default();
        assert!(launches.new_machine("m_owned").is_err());
        assert!(launches.begin("m_owned").is_err());
        assert!(launches.open().is_err());
        assert!(launches.check("m_owned").is_err());
    }
    #[test]
    fn unresolved_launches_survive_drop_and_cannot_be_replaced() {
        let launches = Launches::testing();
        launches.new_machine("m_owned").unwrap();
        launches.check("m_owned").unwrap();
        let mut attempt = launches.begin("m_owned").unwrap();
        attempt.spawned();
        drop(attempt);
        assert!(launches.check("m_owned").is_err());
        assert!(launches.begin("m_owned").is_err());
        assert!(launches.new_machine("m_owned").is_err());
        assert!(launches.check("m_recovered").is_err());
    }
    #[test]
    fn never_spawned_and_positive_completion_are_distinct() {
        let launches = Launches::testing();
        assert!(launches.begin("m_recovered").is_err());
        launches.new_machine("m_owned").unwrap();
        drop(launches.begin("m_owned").unwrap());
        launches.check("m_owned").unwrap();
        let mut attempt = launches.begin("m_owned").unwrap();
        attempt.spawned();
        assert!(launches.check("m_owned").is_err());
        attempt.complete();
        launches.check("m_owned").unwrap();
    }
}

#[cfg(test)]
mod epoch_tests {
    use super::*;
    #[test]
    fn old_receipt_cannot_settle_a_new_incarnation() {
        let launches = Launches::testing();
        launches.new_machine("m_owned").unwrap();
        let mut old = launches.begin("m_owned").unwrap();
        old.spawned();
        old.complete();
        let mut next = launches.begin("m_owned").unwrap();
        next.spawned();
        old.complete();
        drop(old);
        assert!(launches.check("m_owned").is_err());
        next.complete();
        launches.check("m_owned").unwrap();
    }
}
