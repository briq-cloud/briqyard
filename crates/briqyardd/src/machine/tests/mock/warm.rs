use super::*;

impl Mock {
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
        jail: Option<&fc::Jail>,
        pid: u32,
        disk_io: Arc<fc::DiskIo>,
    ) -> Option<fc::Vm> {
        if !self.paused.lock().unwrap().contains(&pid) {
            return None;
        }
        let mut vm = <Self as fc::Vmm>::adopt(self, id, dir, jail, pid, disk_io).await?;
        vm.resumed = true;
        Some(vm)
    }
}
