use super::*;

impl Mock {
    pub(super) fn write_snapshot(&self, vm: &fc::Vm, durable: bool) -> Result<()> {
        let how = if durable { "synced" } else { "unsynced" };
        self.record(format!("snapshot {} {how}", vm.pid));
        let dir = vm.chroot.as_ref().unwrap_or(&vm.dir);
        std::fs::write(dir.join("snap.state"), b"state")?;
        std::fs::write(dir.join("snap.mem"), b"memory")?;
        Ok(())
    }

    pub(super) fn park_slot(&self, pid: u32) -> Result<()> {
        self.record(format!("pause {pid}"));
        self.paused.lock().unwrap().insert(pid);
        Ok(())
    }
    pub(super) fn resume_slot(&self, pid: u32) -> Result<()> {
        anyhow::ensure!(self.paused.lock().unwrap().remove(&pid), "not paused");
        self.record(format!("resume-paused {pid}"));
        Ok(())
    }
    pub(super) async fn adopt_pool_slot(
        &self,
        id: &str,
        dir: &Path,
        _jail: Option<&fc::Jail>,
        pid: u32,
        _disk_io: Arc<fc::DiskIo>,
    ) -> Option<fc::Vm> {
        self.record(format!("adopt {id} {pid}"));
        self.adopt_process(id, dir, pid, true)
    }

    pub(super) fn adopt_process(
        &self,
        id: &str,
        dir: &Path,
        pid: u32,
        paused: bool,
    ) -> Option<fc::Vm> {
        self.record(format!("adopt-state {id} {pid} paused={paused}"));
        if self.paused.lock().unwrap().contains(&pid) != paused {
            return None;
        }
        let procs = self.procs.lock().unwrap();
        let process = procs
            .iter()
            .find(|process| process.pid == pid && process.id == id && !*process.exited.borrow())?;
        let (api, _, _, _) = fc::paths(dir);
        Some(fc::Vm {
            #[cfg(target_os = "linux")]
            identity: None,
            pid,
            api,
            vsock: process.vsock.clone(),
            dir: dir.into(),
            chroot: None,
            resumed: paused,
            boot_identity: self
                .adoption_profile
                .lock()
                .unwrap()
                .as_ref()
                .map(|profile| fc::BootIdentity::ambiguous(profile))
                .or_else(|| {
                    process.boot_identity.as_ref().and_then(|identity| {
                        (identity.device_profile != fc::LEGACY_PROFILE)
                            .then(|| fc::BootIdentity::ambiguous(&identity.device_profile))
                    })
                }),
            incarnation: Some(mock_incarnation(pid)),
            exited: process.exited.subscribe(),
            exit: Self::exit_of(process),
            vmm_oom: process.vmm_oom.clone(),
        })
    }
}
