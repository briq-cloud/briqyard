//! Read-only observations used when preparing host-local template catalogs.
use super::*;

/// The exact validated input, not a later read of the configuration path.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum LoadedConfigIdentity {
    #[default]
    Unobserved,
    Defaults,
    File {
        sha256: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeObservation {
    pub host_id: String,
    pub version: String,
    /// The host boot at observation, not the artifact's immutable boot identity.
    pub host_boot_id: Option<String>,
    /// Fresh for each manager; a new process must not reuse an old observation.
    pub incarnation: String,
    pub config: LoadedConfigIdentity,
}

/// A validated sandbox template recipe, with no guest configuration or credentials.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedSandboxRecipe {
    pub observation: RuntimeObservation,
    pub source_machine: String,
    pub namespace: String,
    pub snapshot: String,
    pub generation: String,
    pub profile: String,
    pub source_host: String,
    pub image: String,
    pub image_digest: String,
    pub image_config_digest: String,
    pub init_sha256: String,
    pub boot_identity_sha256: String,
    pub size: Size,
    pub root_disk_gb: u32,
    pub data_device: Option<crate::guest::SandboxDevice>,
}
