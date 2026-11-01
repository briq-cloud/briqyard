//! Private destination authority, separate from preparation/stage journals.
//! Publication is intentionally not connected to any public claim path yet.
use super::*;
use sha2::{Digest, Sha256};
mod bind;
mod live;
mod model;
mod recovery;
mod reservations;
#[cfg(test)]
mod tests;
const REQUESTS: &str = "unbound-requests";
const INTENTS: &str = "unbound-assignments";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: u8,
    namespace: String,
    request_id: String,
    create_sha256: String,
    machine: String,
}
impl Receipt {
    fn key(&self) -> String {
        key(&self.namespace, &self.request_id)
    }
    fn check(&self) -> Result<()> {
        anyhow::ensure!(
            self.schema == 1
                && api::valid_id(&self.namespace)
                && api::valid_id(&self.request_id)
                && api::valid_id(&self.machine)
                && self.create_sha256.len() == 64
                && self.create_sha256.bytes().all(|v| v.is_ascii_hexdigit()),
            "invalid destination assignment receipt"
        );
        Ok(())
    }
}
fn key(namespace: &str, request: &str) -> String {
    hex::encode(Sha256::digest(
        serde_json::to_vec(&(namespace, request)).unwrap(),
    ))
}

#[derive(Default)]
pub(super) struct State {
    receipts: BTreeMap<String, Receipt>,
    slots: BTreeMap<String, String>,
    pending: std::collections::HashSet<String>,
    targets: BTreeMap<String, Record>,
}
impl State {
    fn remember(&mut self, receipt: &Receipt, pending: bool) -> Result<()> {
        receipt.check()?;
        let key = receipt.key();
        anyhow::ensure!(
            self.receipts.get(&key).is_none_or(|old| old == receipt)
                && self
                    .slots
                    .get(&receipt.machine)
                    .is_none_or(|old| old == &key),
            "destination assignment request or slot identity conflict"
        );
        self.receipts.insert(key.clone(), receipt.clone());
        self.slots.insert(receipt.machine.clone(), key);
        if pending {
            self.pending.insert(receipt.machine.clone());
        }
        Ok(())
    }
}

impl Manager {
    fn destination_receipt(&self, namespace: &str, request: &str) -> Result<Option<Receipt>> {
        let key = key(namespace, request);
        let mut state = self.inner.assignments.lock().unwrap();
        if let Some(receipt) = self.inner.store.get::<Receipt>(REQUESTS, &key)? {
            anyhow::ensure!(
                receipt.key() == key,
                "destination receipt stored under another request key"
            );
            state.remember(&receipt, false)?;
        }
        if let Some(intent) = self.inner.store.get::<model::Intent>(INTENTS, &key)? {
            anyhow::ensure!(
                intent.receipt.key() == key,
                "destination intent stored under another request key"
            );
            intent.check()?;
            state.reserve(&intent)?;
        }
        Ok(state.receipts.get(&key).cloned())
    }

    pub(in crate::machine) fn resolve_destination_assignment(
        &self,
        namespace: &str,
        request: &str,
        digest: &str,
    ) -> Result<Option<Arc<Entry>>, MError> {
        let Some(receipt) = self.destination_receipt(namespace, request)? else {
            return Ok(None);
        };
        if receipt.namespace != namespace
            || receipt.request_id != request
            || receipt.create_sha256 != digest
        {
            return Err(MError::Conflict(
                "destination assignment request identity conflict".into(),
            ));
        }
        if self
            .inner
            .assignments
            .lock()
            .unwrap()
            .pending
            .contains(&receipt.machine)
        {
            return Err(MError::Conflict(
                "destination assignment is pending; its exact slot remains reserved".into(),
            ));
        }
        let entry = self.entry(&receipt.machine).map_err(|_| {
            MError::Conflict(
                "destination assignment was consumed; its machine is unavailable".into(),
            )
        })?;
        let record = entry.snapshot();
        if record.namespace != namespace
            || record.launch_identity.is_none()
            || record
                .warm_slot
                .as_ref()
                .and_then(|slot| slot.claimed.as_deref())
                != Some(request)
            || record
                .clone_origin
                .as_ref()
                .and_then(|origin| origin.sandbox.as_ref())
                .is_none_or(|binding| {
                    binding.request_id != request || binding.create_sha256 != digest
                })
        {
            return Err(MError::Conflict(
                "destination assignment ownership differs from its receipt".into(),
            ));
        }
        Ok(Some(entry))
    }

    pub(in crate::machine) fn destination_assignment_owns(&self, machine: &str) -> Result<bool> {
        if self
            .inner
            .assignments
            .lock()
            .unwrap()
            .slots
            .contains_key(machine)
        {
            return Ok(true);
        }
        // Also fail closed if durable authority exists before the cache was rebuilt.
        for receipt in self.inner.store.list::<Receipt>(REQUESTS)? {
            self.inner
                .assignments
                .lock()
                .unwrap()
                .remember(&receipt, false)?;
        }
        for intent in self.inner.store.list::<model::Intent>(INTENTS)? {
            intent.check()?;
            self.inner.assignments.lock().unwrap().reserve(&intent)?;
        }
        Ok(self
            .inner
            .assignments
            .lock()
            .unwrap()
            .slots
            .contains_key(machine))
    }
    pub(in crate::machine) fn destination_assignment_pending(&self, machine: &str) -> Result<bool> {
        let _ = self.destination_assignment_owns(machine)?;
        Ok(self
            .inner
            .assignments
            .lock()
            .unwrap()
            .pending
            .contains(machine))
    }
}
