//! Pending ownership is logical admission, never an additional physical allocation.
use super::*;

impl State {
    pub(super) fn reserve(&mut self, intent: &model::Intent) -> Result<()> {
        intent.check()?;
        if let Some(old) = self.targets.get(&intent.receipt.machine) {
            anyhow::ensure!(
                launch_identity::record_fingerprint(old)?
                    == launch_identity::record_fingerprint(&intent.target)?,
                "pending destination differs from its frozen reservation"
            );
        }
        self.remember(&intent.receipt, true)?;
        self.targets
            .insert(intent.receipt.machine.clone(), intent.target.clone());
        Ok(())
    }
}

impl Manager {
    // Admission callers hold machines before consulting assignments; publication uses that
    // same order. Startup reconstructs every intent before reconciling any one of them.
    pub(in crate::machine) fn assignment_targets(&self) -> Vec<Record> {
        self.inner
            .assignments
            .lock()
            .unwrap()
            .targets
            .values()
            .cloned()
            .collect()
    }

    pub(in crate::machine) fn assignment_name_held(
        &self,
        namespace: &str,
        name: &str,
        except: &str,
    ) -> bool {
        self.assignment_targets().iter().any(|target| {
            target.id != except && target.namespace == namespace && target.name == name
        })
    }

    pub(in crate::machine) fn assignment_namespace_held(&self, namespace: &str) -> bool {
        self.assignment_targets()
            .iter()
            .any(|target| target.namespace == namespace)
    }

    pub(in crate::machine) fn namespace_use(
        &self,
        machines: &HashMap<String, Arc<Entry>>,
        namespace: &str,
    ) -> api::QuotaUse {
        let targets = self.assignment_targets();
        if targets.is_empty() {
            return namespace_use(machines, namespace);
        }
        // Replace by machine ID, rather than add: pending ownership transfers the complete
        // logical charge once, while committed()/warm policy keep the one physical record.
        let mut effective = machines.clone();
        for target in targets {
            effective.insert(
                target.id.clone(),
                Entry::new(target, self.inner.events.clone()),
            );
        }
        namespace_use(&effective, namespace)
    }
}
