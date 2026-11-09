use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Binding {
    pub request_id: String,
    pub create_sha256: String,
    pub receipt: String,
    /// The data drive the destination mounts; none when the seed has no third drive.
    pub device: Option<guest::SandboxDevice>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind: Option<guest::DestinationBind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_sha256: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
pub(in crate::machine) struct Index {
    namespace: String,
    request_id: String,
    machine: String,
    create_sha256: String,
}
fn key(namespace: &str, request: &str) -> String {
    hex::encode(Sha256::digest(
        serde_json::to_vec(&(namespace, request)).unwrap(),
    ))
}
pub(in crate::machine) fn request_digest(req: &api::CreateMachineRequest) -> Result<String> {
    Ok(hex::encode(Sha256::digest(req.sandbox_create_bytes()?)))
}

pub(in crate::machine) fn replay(
    manager: &Manager,
    req: &api::CreateMachineRequest,
) -> Result<Option<Arc<Entry>>, MError> {
    let Some(seed) = &req.sandbox_seed else {
        return Ok(None);
    };
    resolve(
        manager,
        &req.namespace,
        &seed.request_id,
        &request_digest(req)?,
    )
}
fn resolve(
    manager: &Manager,
    namespace: &str,
    request_id: &str,
    digest: &str,
) -> Result<Option<Arc<Entry>>, MError> {
    if let Some(entry) = manager.resolve_destination_assignment(namespace, request_id, digest)? {
        return Ok(Some(entry));
    }
    let saved = manager
        .inner
        .store
        .get::<Index>("sandbox-requests", &key(namespace, request_id))?;
    if let Some(index) = &saved {
        if index.namespace != namespace
            || index.request_id != request_id
            || index.create_sha256 != digest
        {
            return Err(MError::Conflict("sandbox request identity conflict".into()));
        }
    }
    for e in manager.inner.machines.lock().unwrap().values() {
        let r = e.snapshot();
        if r.namespace == namespace {
            if let Some(binding) = r
                .clone_origin
                .as_ref()
                .and_then(|o| o.sandbox.as_ref())
                .filter(|b| b.request_id == request_id)
            {
                if binding.create_sha256 != digest
                    || saved.as_ref().is_some_and(|index| index.machine != r.id)
                {
                    return Err(MError::Conflict(
                        "sandbox request already binds a different create specification or index"
                            .into(),
                    ));
                }
                return Ok(Some(e.clone()));
            }
        }
    }
    if let Some(index) = saved {
        return Err(MError::Conflict(format!(
            "sandbox request was consumed by {}; destination record is unavailable",
            index.machine
        )));
    }
    Ok(None)
}

impl Manager {
    /// Original accepted creation only. Cached authority adds no store reads to views.
    pub(in crate::machine) fn create_origin(
        &self,
        entry: &Entry,
        record: &Record,
    ) -> Option<api::CreateOrigin> {
        let binding = record.clone_origin.as_ref()?.sandbox.as_ref()?;
        if record.launch_identity.is_some()
            || record.warm_slot.is_some()
            || record.assigned_run.is_some()
            || self.cached_destination_assignment_owns(&record.id)
        {
            return self.cached_unbound_create_origin(record);
        }
        let cache = entry.sandbox_index.lock().unwrap();
        let index = cache.as_ref()?;
        (api::valid_sandbox_request_id(&index.request_id)
            && index.create_sha256.len() == 64
            && index.create_sha256.bytes().all(|v| v.is_ascii_hexdigit())
            && index.namespace == record.namespace
            && index.machine == record.id
            && index.request_id == binding.request_id
            && index.create_sha256 == binding.create_sha256)
            .then(|| api::CreateOrigin {
                kind: api::CreateOriginKind::SandboxSeed,
                request_id: index.request_id.clone(),
                create_sha256: index.create_sha256.clone(),
            })
    }

    pub async fn sandbox_request_lookup(
        &self,
        query: api::SandboxRequestLookup,
    ) -> Result<Option<api::Machine>, MError> {
        query.check().map_err(invalid)?;
        if self.inner.cfg.token.is_empty() {
            return Err(MError::Conflict(
                "sandbox lookup requires configured authentication".into(),
            ));
        }
        let _sandbox = self.inner.sandbox_create_lock.read().await;
        let _turn = self
            .inner
            .sandbox_turns
            .take(&query.namespace, &query.request_id)
            .await;
        Ok(resolve(
            self,
            &query.namespace,
            &query.request_id,
            &query.create_sha256,
        )?
        .map(|entry| self.view(&entry)))
    }
    pub(in crate::machine) fn check_sandbox_request_index(
        &self,
        namespace: &str,
        request_id: &str,
        digest: &str,
        machine: &str,
    ) -> Result<()> {
        if let Some(index) = self
            .inner
            .store
            .get::<Index>("sandbox-requests", &key(namespace, request_id))?
        {
            anyhow::ensure!(
                index.namespace == namespace
                    && index.request_id == request_id
                    && index.create_sha256 == digest
                    && index.machine == machine,
                "sandbox request index conflicts with destination assignment"
            );
        }
        Ok(())
    }

    pub(in crate::machine) fn freeze_sandbox_assignment(&self, e: &Entry) -> Result<()> {
        let r = e.snapshot();
        if r.clone_origin.as_ref().is_some_and(|o| o.sandbox.is_some()) {
            let mut hash = Sha256::new();
            hash.update(b"briqyard:sandbox-assignment-v1\0");
            hash.update(serde_json::to_vec(&r)?);
            e.rec
                .lock()
                .unwrap()
                .clone_origin
                .as_mut()
                .unwrap()
                .sandbox
                .as_mut()
                .unwrap()
                .receipt = hex::encode(hash.finalize());
            self.persist_sandbox_assignment(e)?;
        }
        Ok(())
    }
    pub(in crate::machine) fn recover_sandbox_assignments(&self) -> Result<()> {
        let entries: Vec<_> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        for e in entries {
            self.persist_sandbox_assignment(&e)?;
        }
        Ok(())
    }
    pub(in crate::machine) fn persist_sandbox_assignment(&self, e: &Entry) -> Result<()> {
        let r = e.snapshot();
        let Some(binding) = r.clone_origin.as_ref().and_then(|o| o.sandbox.as_ref()) else {
            return Ok(());
        };
        if let Some(previous) = self
            .inner
            .store
            .get::<Index>("sandbox-requests", &key(&r.namespace, &binding.request_id))?
        {
            anyhow::ensure!(
                previous.machine == r.id
                    && previous.namespace == r.namespace
                    && previous.request_id == binding.request_id
                    && previous.create_sha256 == binding.create_sha256,
                "sandbox assignment index conflict"
            );
        }
        self.inner.store.put_durable("machines", &r.id, &r)?;
        let index = Index {
            namespace: r.namespace.clone(),
            request_id: binding.request_id.clone(),
            machine: r.id.clone(),
            create_sha256: binding.create_sha256.clone(),
        };
        self.inner.store.put_durable(
            "sandbox-requests",
            &key(&r.namespace, &binding.request_id),
            &index,
        )?;
        *e.sandbox_index.lock().unwrap() = Some(index);
        Ok(())
    }
}
