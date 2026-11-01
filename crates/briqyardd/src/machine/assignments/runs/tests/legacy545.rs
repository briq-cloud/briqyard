//! Independent wire declarations from 545db521 runs.rs (field order is deliberate).
//! Record/Receipt/CloneReader wire declarations did not change in the lifecycle slice.
//! Never obtain historical reader hashes from Current::reader/authority_sha256.
use super::*;

#[derive(Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct OldRunRef {
    schema: u8,
    sequence: u64,
    phase: OldPhase,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum OldPhase {
    Reserved,
    Observed,
}
#[derive(Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct OldDisk {
    dataset: String,
    guid: u64,
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum OldMode {
    Fresh {
        guest_generation: String,
        drive_base64: String,
        drive_sha256: String,
        expected_bundle_sha256: String,
    },
    Checkpoint {
        state: templates::ArtifactFile,
        memory: templates::ArtifactFile,
        config: templates::ArtifactFile,
        saved_generation: String,
        saved_init_sha256: String,
        saved_marker: String,
        saved_bind_sha256: String,
    },
}
#[derive(Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct OldCurrent {
    schema: u8,
    machine: String,
    host_generation: String,
    reference: OldRunRef,
    receipt: Receipt,
    prior_control_sha256: String,
    prior: Record,
    target: Record,
    creation_reader: templates::CloneReader,
    root: OldDisk,
    data: OldDisk,
    host_boot_id: String,
    expected_boot_identity: fc::BootIdentity,
    mode: OldMode,
    observed_guest: Option<guest::AssignedRunProof>,
    #[serde(default)]
    launch_started: bool,
    #[serde(default)]
    observed_main_pid: i32,
    #[serde(default)]
    observed_checkpoint: Option<guest::Response>,
}
#[derive(Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct OldReader {
    schema: u8,
    machine: String,
    host_generation: String,
    reference: OldRunRef,
    current_sha256: String,
    root: OldDisk,
    data: OldDisk,
    backing: String,
}
#[derive(Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct OldIntent {
    schema: u8,
    current: OldCurrent,
    reader: OldReader,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    predecessor: Option<OldCurrent>,
}

impl OldCurrent {
    fn observed(current: &Current) -> Self {
        let reference = OldRunRef {
            schema: 1,
            sequence: 1,
            phase: OldPhase::Observed,
        };
        let mut target = current.target.as_ref().clone();
        target.assigned_run = Some(RunRef {
            schema: 1,
            sequence: 1,
            phase: Phase::Observed,
        });
        let mode = match &current.mode {
            Mode::Fresh {
                guest_generation,
                drive_base64,
                drive_sha256,
                expected_bundle_sha256,
            } => OldMode::Fresh {
                guest_generation: guest_generation.clone(),
                drive_base64: drive_base64.clone(),
                drive_sha256: drive_sha256.clone(),
                expected_bundle_sha256: expected_bundle_sha256.clone(),
            },
            Mode::Checkpoint {
                state,
                memory,
                config,
                saved_generation,
                saved_init_sha256,
                saved_marker,
                saved_bind_sha256,
                assigned_lineage,
            } => {
                assert!(assigned_lineage.is_none());
                OldMode::Checkpoint {
                    state: state.clone(),
                    memory: memory.clone(),
                    config: config.clone(),
                    saved_generation: saved_generation.clone(),
                    saved_init_sha256: saved_init_sha256.clone(),
                    saved_marker: saved_marker.clone(),
                    saved_bind_sha256: saved_bind_sha256.clone(),
                }
            }
        };
        Self {
            schema: 1,
            machine: current.machine.clone(),
            host_generation: current.host_generation.clone(),
            reference,
            receipt: current.receipt.clone(),
            prior_control_sha256: launch_identity::record_fingerprint(&current.prior).unwrap(),
            prior: current.prior.as_ref().clone(),
            target,
            creation_reader: current.creation_reader.clone(),
            root: OldDisk {
                dataset: current.root.dataset.clone(),
                guid: current.root.guid,
            },
            data: OldDisk {
                dataset: current.data.dataset.clone(),
                guid: current.data.guid,
            },
            host_boot_id: current.host_boot_id.clone(),
            expected_boot_identity: current.expected_boot_identity.clone(),
            mode,
            observed_guest: current.observed_guest.clone(),
            launch_started: true,
            observed_main_pid: current.observed_main_pid,
            observed_checkpoint: current.observed_checkpoint.clone(),
        }
    }
    fn attempted(&self) -> Self {
        let mut prior = self.clone();
        prior.reference.phase = OldPhase::Reserved;
        prior.target = prior.prior.clone();
        prior.target.assigned_run = Some(RunRef {
            schema: 1,
            sequence: 1,
            phase: Phase::Reserved,
        });
        prior.target.state = state::STARTING.into();
        prior.target.pid = 0;
        prior.target.suspended = matches!(prior.mode, OldMode::Checkpoint { .. });
        prior.observed_guest = None;
        prior.observed_checkpoint = None;
        prior.observed_main_pid = 0;
        prior
    }
    fn reader(&self) -> OldReader {
        OldReader {
            schema: 1,
            machine: self.machine.clone(),
            host_generation: self.host_generation.clone(),
            reference: self.reference.clone(),
            // Exact 545 implementation: Serialize the ordered struct directly.
            current_sha256: sha(&serde_json::to_vec(self).unwrap()),
            root: self.root.clone(),
            data: self.data.clone(),
            backing: if matches!(self.mode, OldMode::Fresh { .. }) {
                "current_disks"
            } else {
                "current_checkpoint"
            }
            .into(),
        }
    }
    fn check_current_wire(&self) {
        let historical_bytes = serde_json::to_vec(self).unwrap();
        let parsed: Current = serde_json::from_slice(&historical_bytes).unwrap();
        parsed.check().unwrap();
        assert_eq!(
            serde_json::to_vec(&parsed).unwrap(),
            historical_bytes,
            "Box/default/optional fields and declaration order must preserve schema1 bytes"
        );
        assert_eq!(
            parsed.authority_sha256().unwrap(),
            self.reader().current_sha256
        );
        assert_ne!(
            self.reader().current_sha256,
            sha(&serde_json::to_vec(&serde_json::to_value(&parsed).unwrap()).unwrap()),
            "this fixture must distinguish the rejected sorted-Value hash"
        );
    }
}

#[tokio::test]
async fn independent_545_reader_and_interrupted_observation_recover_then_upgrade_exactly() {
    for checkpoint in [false, true] {
        for boundary in 0..4 {
            let (h, entry) = stopped(checkpoint).await;
            h.m.launch_assigned_run(&entry, checkpoint).await.unwrap();
            let live = entry.live.lock().unwrap().clone().unwrap();
            let id = entry.snapshot().id;
            let current: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
            let observed = Box::new(OldCurrent::observed(&current));
            let attempted = Box::new(observed.attempted());
            observed.check_current_wire();
            attempted.check_current_wire();
            let intent = Box::new(OldIntent {
                schema: 1,
                current: observed.as_ref().clone(),
                reader: observed.reader(),
                predecessor: Some(attempted.as_ref().clone()),
            });
            // All persisted run/reader/intent bytes below come from independent 545
            // declarations. New Current helpers cannot regenerate a falsely matching hash.
            h.m.inner.store.put_durable(RUNS, &id, &attempted).unwrap();
            h.m.inner
                .store
                .put_durable("machines", &id, &attempted.target)
                .unwrap();
            h.m.inner
                .store
                .put_durable(READERS, &id, &attempted.reader())
                .unwrap();
            h.m.inner.store.put_durable(INTENTS, &id, &intent).unwrap();
            if boundary >= 1 {
                h.m.inner.store.put_durable(RUNS, &id, &observed).unwrap();
            }
            if boundary >= 2 {
                h.m.inner
                    .store
                    .put_durable("machines", &id, &observed.target)
                    .unwrap();
            }
            if boundary >= 3 {
                h.m.inner
                    .store
                    .put_durable(READERS, &id, &intent.reader)
                    .unwrap();
            }
            h.host_calls();
            restart(&h).unwrap();
            assert!(
                h.host_calls().is_empty(),
                "journal recovery cannot launch or publish"
            );
            assert!(h.m.inner.store.list::<Intent>(INTENTS).unwrap().is_empty());
            let recovered: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
            assert_eq!(
                recovered.authority_sha256().unwrap(),
                observed.reader().current_sha256
            );
            let reader: Reader = h.m.inner.store.get(READERS, &id).unwrap().unwrap();
            assert_eq!(
                serde_json::to_value(reader).unwrap(),
                serde_json::to_value(observed.reader()).unwrap()
            );
            let entry = h.m.entry(&id).unwrap();
            assert!(!entry.identity_trusted.load(Relaxed));
            assert_eq!(
                h.m.quota("destination").unwrap().used.memory_mb,
                recovered.target.size.memory_mb
            );
            *entry.live.lock().unwrap() = Some(live.clone());
            h.m.inner.vmm.kill(live.pid);
            h.m.settle_assigned_run(&entry, super::super::terminal::Disposition::Stopped)
                .await
                .unwrap();
            let terminal: Current = h.m.inner.store.get(RUNS, &id).unwrap().unwrap();
            assert_eq!(terminal.schema, 3);
            assert_eq!(terminal.reference.phase, Phase::Settled);
            assert_eq!(terminal.receipt, recovered.receipt);
            assert_eq!(terminal.creation_reader, recovered.creation_reader);
            assert_eq!(
                terminal.target.launch_identity,
                recovered.target.launch_identity
            );
            assert_eq!(h.m.quota("destination").unwrap().used.memory_mb, 0);
            h.m.plan_assigned_run(&entry, false).await.unwrap();
        }
    }
}
