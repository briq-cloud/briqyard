use super::*;

impl Mock {
    pub(super) fn settle_clone(&self, id: &str, saved: &fc::Incarnation) -> Result<bool> {
        self.record(format!("settle-clone {id} {}", saved.pid));
        if self.refuse_clone_exit.load(Relaxed) {
            return Ok(false);
        }
        if saved != &mock_incarnation(saved.pid) {
            return Ok(false);
        }
        let alive = self
            .procs
            .lock()
            .unwrap()
            .iter()
            .any(|p| p.pid == saved.pid && p.id == id && !*p.exited.borrow());
        if alive {
            <Self as fc::Vmm>::kill(self, saved.pid);
        }
        Ok(true)
    }
}
