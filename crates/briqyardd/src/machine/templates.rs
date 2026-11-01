//! Named snapshot memory backing and its durable readers. No public build policy is
//! enabled here: publication must be reached only after reviewed builder enforcement.
use super::*;
use sha2::{Digest, Sha256};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

const READERS: &str = "clone-readers";

mod policy;
pub(super) use policy::*;
mod create;
mod start;
pub(super) use create::clone_mac;
mod recovery;
mod sealing;

/// The resolved workload held by a named memory artifact, independent of later edits.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CloneRecipe {
    pub image: String,
    pub image_digest: String,
    #[serde(default)]
    pub image_config_digest: String,
    pub image_key: String,
    pub size: api::Size,
    #[serde(default)]
    pub root_disk_gb: u32,
    pub config: guest::Config,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ArtifactFile {
    pub bytes: u64,
    pub sha256: String,
    pub device: u64,
    pub inode: u64,
}

/// Kept on the existing SnapshotRec, additive to the legacy memory-spec digest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CloneArtifact {
    pub schema: u32,
    pub generation: String,
    pub profile: String,
    #[serde(default)]
    pub ram_marker: String,
    pub namespace: String,
    pub source_host: String,
    pub init_sha256: String,
    pub init_protocol: u32,
    pub cpu_fingerprint: String,
    pub boot_identity: fc::BootIdentity,
    pub recipe: CloneRecipe,
    pub state: ArtifactFile,
    pub memory: ArtifactFile,
}
// SnapshotRec equality is used for compatibility tests; resolved config has no Eq.
impl PartialEq for CloneArtifact {
    fn eq(&self, other: &Self) -> bool {
        serde_json::to_value(self).ok() == serde_json::to_value(other).ok()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloneStage {
    Reserved,
    Loading,
    Configuring,
    IdentityDone,
    Paused,
    Active,
}

impl CloneStage {
    pub(super) fn as_str(&self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Loading => "loading",
            Self::Configuring => "configuring",
            Self::IdentityDone => "identity_done",
            Self::Paused => "paused",
            Self::Active => "active",
        }
    }
}

/// Reserved before disk/jail/load work, retained for every possible live mapping.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct CloneReader {
    pub source_machine: String,
    pub snapshot: String,
    pub generation: String,
    pub destination: String,
    pub namespace: String,
    pub stage: CloneStage,
}

impl Manager {
    pub(super) fn clone_readers(&self) -> Result<Vec<CloneReader>> {
        self.inner.store.list(READERS)
    }

    /// Caller holds the source entry lock, shared with reserve_named_clone. Missing or
    /// corrupt reference records refuse cleanup rather than treating uncertainty as zero.
    pub(super) fn check_clone_readers(
        &self,
        source: &str,
        snapshot: Option<&str>,
    ) -> Result<(), MError> {
        if self
            .clone_readers()?
            .iter()
            .any(|r| r.source_machine == source && snapshot.is_none_or(|s| r.snapshot == s))
        {
            return Err(MError::Conflict(
                "named memory snapshot still has clone readers".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn artifact_files(
        &self,
        source: &str,
        snapshot: &str,
        generation: &str,
    ) -> Result<[PathBuf; 2]> {
        for id in [source, snapshot, generation] {
            anyhow::ensure!(api::valid_id(id), "invalid memory artifact identity");
        }
        let dir = self
            .inner
            .cfg
            .jail_base()
            .join("memory-artifacts")
            .join(source)
            .join(snapshot);
        Ok(["state", "mem"].map(|ext| dir.join(format!("{generation}.{ext}"))))
    }

    /// Validates only metadata/identity on the hot path: file bytes were checked once at
    /// publication or daemon startup. Never hash RAM per clone or fall back to a copy.
    pub(super) async fn reserve_named_clone(
        &self,
        source: &str,
        snapshot: &str,
        destination: &str,
        namespace: &str,
    ) -> Result<(CloneArtifact, [PathBuf; 2]), MError> {
        if !self
            .named_memory_profiles()
            .iter()
            .any(|p| p == guest::INIT_READY_V1)
        {
            return Err(invalid(
                "reviewed named memory profile is disabled or unavailable",
            ));
        }
        if !api::valid_id(destination) {
            return Err(invalid("invalid clone destination"));
        }
        let e = self.own_entry(source)?;
        let _source_lock = e.lock.lock().await;
        let r = e.snapshot();
        if r.namespace != namespace {
            return Err(invalid("memory clone requires the same namespace owner"));
        }
        if r.state == state::DESTROYING {
            return Err(MError::BadState(r.state));
        }
        let s = r
            .snapshots
            .iter()
            .find(|s| s.id == snapshot || s.name.as_deref() == Some(snapshot))
            .ok_or_else(|| MError::NoSnapshot(snapshot.into()))?;
        let a = s
            .clone_artifact
            .as_ref()
            .ok_or_else(|| invalid("snapshot is not a sealed memory template"))?;
        if s.memory.is_none()
            || a.schema != 1
            || a.profile != guest::INIT_READY_V1
            || a.init_protocol != 1
            || a.recipe.root_disk_gb == 0
            || a.recipe.root_disk_gb != self.inner.cfg.root_disk_gb
            || a.ram_marker.len() != 32
            || a.recipe.image != ALPINE
            || a.recipe.image_digest != ALPINE.split('@').nth(1).unwrap_or("")
            || a.recipe.image_config_digest != ALPINE_CONFIG_DIGEST
            || a.namespace != namespace
            || a.source_host != self.inner.host_id
            || a.init_sha256 != self.inner.images.init_sha256()
            || self.inner.vmm.cpu_fingerprint().as_deref() != Some(a.cpu_fingerprint.as_str())
        {
            return Err(invalid(
                "memory template provenance/profile is incompatible",
            ));
        }
        if !self.inner.verified_templates.lock().unwrap().contains(&(
            r.id.clone(),
            s.id.clone(),
            a.generation.clone(),
        )) {
            return Err(invalid(
                "memory template has not passed artifact recovery verification",
            ));
        }
        let current = self
            .inner
            .vmm
            .boot_identity(a.boot_identity.device_profile == fc::REPORTING_PROFILE);
        if current.as_ref() != Some(&a.boot_identity) {
            return Err(invalid("memory template boot identity is incompatible"));
        }
        let files = self.artifact_files(source, &s.id, &a.generation)?;
        check_inode(&files[0], &a.state)?;
        check_inode(&files[1], &a.memory)?;
        let reader = CloneReader {
            source_machine: source.into(),
            snapshot: s.id.clone(),
            generation: a.generation.clone(),
            destination: destination.into(),
            namespace: namespace.into(),
            stage: CloneStage::Reserved,
        };
        if let Some(old) = self.inner.store.get::<CloneReader>(READERS, destination)? {
            if old.source_machine != reader.source_machine
                || old.snapshot != reader.snapshot
                || old.generation != reader.generation
                || old.namespace != reader.namespace
            {
                return Err(MError::Conflict(
                    "clone destination already holds a different memory reference".into(),
                ));
            }
        } else {
            self.inner
                .store
                .put_durable(READERS, destination, &reader)?;
        }
        Ok((a.clone(), files))
    }

    /// Recovery verifies bytes before enabling clone reads. Corruption retains its files
    /// and readers, while leaving the artifact unavailable; unrelated machines can recover.
    pub(super) fn verify_clone_artifacts(&self) {
        let entries: Vec<_> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        for e in entries {
            let r = e.snapshot();
            for s in &r.snapshots {
                let Some(a) = &s.clone_artifact else {
                    continue;
                };
                let checked = (|| -> Result<()> {
                    let files = self.artifact_files(&r.id, &s.id, &a.generation)?;
                    anyhow::ensure!(
                        fingerprint(&files[0])? == a.state,
                        "template state differs from manifest"
                    );
                    anyhow::ensure!(
                        fingerprint(&files[1])? == a.memory,
                        "template memory differs from manifest"
                    );
                    Ok(())
                })();
                match checked {
                    Ok(()) => {
                        self.inner.verified_templates.lock().unwrap().insert((
                            r.id.clone(),
                            s.id.clone(),
                            a.generation.clone(),
                        ));
                    }
                    Err(error) => {
                        tracing::error!(machine = r.id, snapshot = s.id, err = %error, "memory template unavailable; backing retained")
                    }
                }
            }
        }
    }

    /// A closed watcher channel is not proof of process exit. Backing references survive
    /// until verified exit AND the caller's local disk/jail cleanup have completed.
    pub(super) fn release_clone_reader(
        &self,
        destination: &str,
        exited: &tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        anyhow::ensure!(
            *exited.borrow(),
            "clone VMM exit is unconfirmed; retaining memory reader"
        );
        anyhow::ensure!(
            !self.inner.cfg.run_dir().join(destination).exists()
                && !fc::jail_root(&self.inner.cfg.jail_base(), destination).exists(),
            "clone local backing cleanup is incomplete; retaining memory reader"
        );
        self.inner.store.delete_durable(READERS, destination)
    }
}

fn check_inode(path: &Path, expected: &ArtifactFile) -> Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        meta.is_file()
            && meta.len() == expected.bytes
            && meta.dev() == expected.device
            && meta.ino() == expected.inode
            && meta.permissions().mode() & 0o222 == 0,
        "immutable memory artifact metadata changed"
    );
    Ok(())
}
fn fingerprint(path: &Path) -> Result<ArtifactFile> {
    use std::io::Read;
    let meta = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(meta.is_file(), "memory artifact is not a regular file");
    let mut f = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buf = [0u8; 256 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        digest.update(&buf[..n]);
    }
    Ok(ArtifactFile {
        bytes: meta.len(),
        sha256: hex::encode(digest.finalize()),
        device: meta.dev(),
        inode: meta.ino(),
    })
}

#[cfg(test)]
mod tests;
