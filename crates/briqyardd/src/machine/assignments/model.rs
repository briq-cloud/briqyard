use super::*;
use rand::RngCore;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Intent {
    pub(super) receipt: Receipt,
    pub(super) request: api::CreateMachineRequest,
    pub(super) source: Record,
    pub(super) source_reader: templates::CloneReader,
    pub(super) target: Record,
    pub(super) target_reader: templates::CloneReader,
}
impl Intent {
    pub(super) fn plan(
        manager: &Manager,
        request: api::CreateMachineRequest,
        entry: &Entry,
        host: u8,
    ) -> Result<Self> {
        request.check_sandbox_seed().map_err(anyhow::Error::msg)?;
        request.spec().check().map_err(anyhow::Error::msg)?;
        check_namespace_id(&request.namespace)?;
        anyhow::ensure!(api::valid_name(&request.name), "invalid destination name");
        let source = entry.snapshot();
        anyhow::ensure!(eligible(&source), "slot is not an unassigned unbound pause");
        let live = entry
            .live
            .lock()
            .unwrap()
            .clone()
            .context("owned paused process missing")?;
        manager.verify_live_launch(entry, &live)?;
        anyhow::ensure!(
            manager
                .inner
                .store
                .get::<serde_json::Value>("launch-transitions", &source.id)?
                .is_none(),
            "preparation transition must settle before destination assignment"
        );
        let seed = request.sandbox_seed.as_ref().unwrap();
        let origin = source.clone_origin.as_ref().unwrap();
        anyhow::ensure!(
            seed.machine_id == origin.source_machine
                && seed.snapshot == origin.snapshot
                && seed.generation == origin.artifact.generation
                && origin.artifact.source_host == manager.inner.host_id
                && request.image == origin.artifact.recipe.image
                && source.size.matches_sandbox_resources(&request.size)
                && serde_json::to_value(&request.volume)? == serde_json::to_value(&source.volume)?,
            "destination request differs from its exact source or capacity"
        );
        anyhow::ensure!(
            templates::sandbox::replay(manager, &request)?.is_none(),
            "request was already consumed"
        );
        let namespace = manager
            .namespace_of(&request.namespace)
            .context("destination namespace missing")?;
        let mut target = source.clone();
        target.namespace = request.namespace.clone();
        target.name = request.name.clone();
        target.subnet_index = namespace.rec.subnet_index;
        target.host_num = host;
        target.ip = namespace.subnet.host(host)?.to_string();
        target.size = request.size;
        target.entrypoint = request.entrypoint.clone();
        target.cmd = request.cmd.clone();
        target.env = request.env.clone();
        target.files = request.files.clone();
        target.ports = request.ports.clone();
        target.sleep = sleep_setting(&request.sleep);
        target.restart = request.restart.clone().unwrap_or_default();
        target.probes = request.probes.clone().unwrap_or_default();
        target.egress = request.egress.clone().unwrap_or_default();
        target.limits = request.limits.clone().unwrap_or_default();
        target.disk_limits = request.disk_limits.clone().unwrap_or_default();
        target.metadata = request.metadata.clone();
        target.created_at = Utc::now();
        target.updated_at = target.created_at;
        target.started_at = None;
        target.last_used_at = None;
        target.start = true;
        target.from_source = true;
        target.backup = backups::schedule_of(
            &request.backup,
            &manager.inner.cfg.backup,
            target.created_at,
        )?;
        target.warm_slot.as_mut().unwrap().claimed = Some(seed.request_id.clone());
        let digest = templates::sandbox::request_digest(&request)?;
        let receipt = Receipt {
            schema: 1,
            namespace: request.namespace.clone(),
            request_id: seed.request_id.clone(),
            create_sha256: digest.clone(),
            machine: source.id.clone(),
        };
        let target_origin = target.clone_origin.as_mut().unwrap();
        target_origin.configure.hostname = request.name.clone();
        target_origin.configure.ip = format!("{}/24", target.ip);
        target_origin.configure.gateway = namespace.subnet.gateway().to_string();
        target_origin.configure.dns = vec![namespace.subnet.gateway().to_string()];
        target_origin.configure.mac = templates::clone_mac(&target.ip)?;
        rand::rngs::OsRng
            .try_fill_bytes(&mut target_origin.configure.entropy)
            .map_err(|_| anyhow!("assignment entropy unavailable"))?;
        target_origin.configure.realtime_sec = Utc::now().timestamp().try_into()?;
        target_origin.sandbox = Some(templates::sandbox::Binding {
            request_id: seed.request_id.clone(),
            create_sha256: digest,
            receipt: String::new(),
            device: origin.artifact.recipe.config.sandbox_device.clone(),
            bind: None,
            ack_sha256: None,
        });
        let frozen = frozen_receipt(&target)?;
        target
            .clone_origin
            .as_mut()
            .unwrap()
            .sandbox
            .as_mut()
            .unwrap()
            .receipt = frozen;
        let source_reader = manager
            .inner
            .store
            .get::<templates::CloneReader>(templates::READERS, &source.id)?
            .context("source reader missing")?;
        let mut target_reader = source_reader.clone();
        target_reader.namespace.clone_from(&target.namespace);
        let intent = Self {
            receipt,
            request,
            source,
            source_reader,
            target,
            target_reader,
        };
        intent.check()?;
        // Complete workload/files/identity framing must fit before any reservation or
        // durable request authority consumes this pristine source slot.
        templates::sandbox::destination_bind(
            &intent.target,
            intent.target.clone_origin.as_ref().unwrap(),
        )?;
        manager.check_assignment_destination(&intent.target)?;
        Ok(intent)
    }

    pub(super) fn check(&self) -> Result<()> {
        self.receipt.check()?;
        self.request
            .check_sandbox_seed()
            .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(
            templates::sandbox::request_digest(&self.request)? == self.receipt.create_sha256
                && self.request.namespace == self.receipt.namespace
                && self.request.sandbox_seed.as_ref().unwrap().request_id
                    == self.receipt.request_id,
            "assignment request differs from immutable receipt"
        );
        let a = &self.source;
        let b = &self.target;
        anyhow::ensure!(
            eligible(a)
                && a.id == self.receipt.machine
                && b.id == a.id
                && a.launch_identity == b.launch_identity
                && a.boot_incarnation == b.boot_incarnation
                && a.boot_identity == b.boot_identity
                && a.pid == b.pid
                && a.size.matches_sandbox_resources(&b.size)
                && a.root_key == b.root_key
                && a.image_key == b.image_key
                && serde_json::to_value(&a.volume)? == serde_json::to_value(&b.volume)?
                && b.namespace == self.receipt.namespace
                && b.name == self.request.name,
            "assignment changes source identity, backing or capacity"
        );
        let origin = b
            .clone_origin
            .as_ref()
            .context("destination origin missing")?;
        let binding = origin
            .sandbox
            .as_ref()
            .context("destination binding missing")?;
        anyhow::ensure!(
            origin.stage == templates::CloneStage::UnboundPaused
                && origin.identity.is_none()
                && binding.request_id == self.receipt.request_id
                && binding.create_sha256 == self.receipt.create_sha256
                && binding.bind.is_none()
                && binding.ack_sha256.is_none()
                && b.warm_slot
                    .as_ref()
                    .and_then(|slot| slot.claimed.as_deref())
                    == Some(self.receipt.request_id.as_str()),
            "assignment target is not its exact unbound destination"
        );
        let artifact = &a.clone_origin.as_ref().unwrap().artifact;
        let seed = self.request.sandbox_seed.as_ref().unwrap();
        let source_origin = a.clone_origin.as_ref().unwrap();
        anyhow::ensure!(
            seed.machine_id == source_origin.source_machine
                && seed.snapshot == source_origin.snapshot
                && seed.generation == source_origin.artifact.generation,
            "assignment source selector differs"
        );
        anyhow::ensure!(
            b.image == self.request.image
                && b.image == artifact.recipe.image
                && a.size.matches_sandbox_resources(&artifact.recipe.size)
                && b.size.matches_sandbox_resources(&self.request.size)
                && serde_json::to_value(&b.volume)? == serde_json::to_value(&self.request.volume)?
                && b.sleep == sleep_setting(&self.request.sleep)
                && serde_json::to_value(&b.restart)?
                    == serde_json::to_value(self.request.restart.clone().unwrap_or_default())?
                && serde_json::to_value(&b.probes)?
                    == serde_json::to_value(self.request.probes.clone().unwrap_or_default())?
                && serde_json::to_value(&b.egress)?
                    == serde_json::to_value(self.request.egress.clone().unwrap_or_default())?
                && serde_json::to_value(&b.limits)?
                    == serde_json::to_value(self.request.limits.clone().unwrap_or_default())?
                && serde_json::to_value(&b.disk_limits)?
                    == serde_json::to_value(self.request.disk_limits.clone().unwrap_or_default())?,
            "assignment resolved target differs from requested create"
        );
        anyhow::ensure!(
            binding.receipt == frozen_receipt(b)?
                && binding.device == artifact.recipe.config.sandbox_device,
            "assignment frozen destination receipt or device differs"
        );
        anyhow::ensure!(
            origin.configure.hostname == b.name
                && origin.configure.ip == format!("{}/24", b.ip)
                && origin.configure.mac == templates::clone_mac(&b.ip)?
                && origin.configure.entropy.iter().any(|byte| *byte != 0)
                && origin.configure.entropy != a.clone_origin.as_ref().unwrap().configure.entropy,
            "assignment destination identity is not freshly bound"
        );
        launch_identity::check_launch_pair(a, Some(&self.source_reader))?;
        launch_identity::check_launch_pair(b, Some(&self.target_reader))?;
        anyhow::ensure!(
            b.env == self.request.env
                && b.files == self.request.files
                && b.metadata == self.request.metadata
                && b.entrypoint == self.request.entrypoint
                && b.cmd == self.request.cmd
                && b.ports == self.request.ports,
            "assignment target workload differs from requested create"
        );
        Ok(())
    }
}

fn frozen_receipt(target: &Record) -> Result<String> {
    let mut frozen = target.clone();
    frozen
        .clone_origin
        .as_mut()
        .context("destination origin missing")?
        .sandbox
        .as_mut()
        .context("destination binding missing")?
        .receipt
        .clear();
    let mut hash = Sha256::new();
    hash.update(b"briqyard:unbound-destination-v1\0");
    hash.update(serde_json::to_vec(&frozen)?);
    Ok(hex::encode(hash.finalize()))
}

pub(super) fn eligible(record: &Record) -> bool {
    record.state == state::STARTING
        && record.launch_identity.is_some()
        && record
            .warm_slot
            .as_ref()
            .is_some_and(|slot| slot.claimed.is_none())
        && record.clone_origin.as_ref().is_some_and(|origin| {
            origin.stage == templates::CloneStage::UnboundPaused
                && origin.sandbox.is_none()
                && origin.identity.is_none()
                && !origin.mapping_exited
        })
}

impl Manager {
    pub(super) fn persist_destination_receipt(&self, receipt: &Receipt) -> Result<()> {
        self.check_sandbox_request_index(
            &receipt.namespace,
            &receipt.request_id,
            &receipt.create_sha256,
            &receipt.machine,
        )?;
        if let Some(saved) = self.inner.store.get::<Receipt>(REQUESTS, &receipt.key())? {
            anyhow::ensure!(saved == *receipt, "permanent destination receipt conflict");
        }
        self.inner
            .store
            .put_durable(REQUESTS, &receipt.key(), receipt)
    }
}
