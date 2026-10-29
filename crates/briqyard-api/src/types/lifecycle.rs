//! Backups, spec changes, moves, updates, stops and snapshots.

use super::*;

/// Which backup to restore: a machine's latest, or one by id.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RestoreSpec {
    /// The backed-up machine (it may no longer exist).
    pub machine_id: String,
    /// A backup id from `GET /machines/{id}/backups`; empty or "latest" for the newest.
    #[serde(default)]
    pub backup: String,
}

/// A backup of a machine's disks in the object store.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Backup {
    /// A timestamp to the millisecond, `20261019T231500.123Z`; later ids sort later.
    pub id: String,
    pub machine_id: String,
    #[serde(alias = "tenant")]
    pub namespace: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    /// Bytes sent to the store for this backup.
    pub bytes: u64,
    /// Sent as a change since the previous backup, or whole.
    pub incremental: bool,
    pub disks: Vec<BackupDisk>,
    /// The id of the pool key its streams are encrypted under (raw sends, ADR 0035): a hash,
    /// never the key. Absent: streams in clear, made before ADR 0035.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// The machine as it was: what a restore makes. In the store's record only, and in clear
    /// only in a backup made before ADR 0035.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<serde_json::Value>,
    /// The machine as it was, sealed under the pool key of `key_id` (ADR 0035): its env and
    /// files are a namespace's secrets. In the store's record only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<String>,
    /// For a destroyed machine's backup: when the host deletes it (ADR 0023). Not stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletes_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupDisk {
    /// `root` or `data`.
    pub disk: String,
    /// The object holding this disk's stream.
    pub key: String,
    pub bytes: u64,
    /// The backup id this stream continues from, when incremental.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

/// What a machine runs, as a PATCH changes it (ADR 0024): each field set replaces the whole
/// value at the next start; absent keeps it. Create's fields of the same names, checked the
/// same way.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecChange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmd: Option<Vec<String>>,
    /// Write-only, as at create.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<BTreeMap<String, String>>,
    /// Write-only, as at create.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<File>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<Size>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<u16>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart: Option<RestartPolicy>,
    /// A larger data volume (ADR 0040): the disk grows at once, the guest's filesystem at the
    /// next start, cold. Never smaller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume: Option<VolumeSize>,
}

impl SpecChange {
    /// The one check of a spec, a create's or a PATCH's: the first field refused, named.
    pub fn check(&self) -> Result<(), String> {
        if self.image.as_deref() == Some("") {
            return Err("image must not be empty".into());
        }
        for k in self.env.iter().flat_map(|env| env.keys()) {
            if k.is_empty() || k.contains('=') {
                return Err(format!("env {k:?}: a name is not empty and holds no \"=\""));
            }
        }
        for f in self.files.iter().flatten() {
            if !f.path.starts_with('/') {
                return Err(format!("file {:?}: path must be absolute", f.path));
            }
            crate::guest::base64_decode(&f.base64)
                .map_err(|e| format!("file {:?}: {e}", f.path))?;
            if let Some(m) = f.mode.as_deref().filter(|m| !m.is_empty()) {
                if u32::from_str_radix(m, 8).is_err() {
                    return Err(format!("file {:?}: mode {m:?}: want octal digits", f.path));
                }
            }
        }
        if let Some(size) = &self.size {
            size.check()?;
        }
        if self.ports.iter().flatten().any(|p| *p == 0) {
            return Err("ports: 0 is not a port".into());
        }
        if let Some(r) = &self.restart {
            if !["no", "on-failure", "always"].contains(&r.policy.as_str()) {
                return Err("restart.policy must be no, on-failure or always".into());
            }
        }
        if self.volume.is_some_and(|v| v.size_gb < 1) {
            return Err("volume.size_gb must be 1 or more".into());
        }
        Ok(())
    }

    /// Each field: its name, whether it is set here, and whether `other` has the same.
    fn each(&self, other: &Self) -> [(&'static str, bool, bool); 9] {
        [
            ("image", self.image.is_some(), self.image == other.image),
            (
                "entrypoint",
                self.entrypoint.is_some(),
                self.entrypoint == other.entrypoint,
            ),
            ("cmd", self.cmd.is_some(), self.cmd == other.cmd),
            ("env", self.env.is_some(), self.env == other.env),
            ("files", self.files.is_some(), self.files == other.files),
            ("size", self.size.is_some(), self.size == other.size),
            ("ports", self.ports.is_some(), self.ports == other.ports),
            (
                "restart",
                self.restart.is_some(),
                self.restart == other.restart,
            ),
            ("volume", self.volume.is_some(), self.volume == other.volume),
        ]
    }

    /// The fields it sets, in the order of the struct.
    pub fn fields(&self) -> Vec<&'static str> {
        self.each(self)
            .into_iter()
            .filter_map(|(f, set, _)| set.then_some(f))
            .collect()
    }

    /// The fields whose value is not `was`'s, set or unset.
    pub fn changed_from(&self, was: &Self) -> Vec<&'static str> {
        self.each(was)
            .into_iter()
            .filter_map(|(f, _, same)| (!same).then_some(f))
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Whether a memory snapshot of the machine holds what it changes: everything but the
    /// ports and the restart policy, which are the daemon's (a volume's size is its block
    /// device's, as the guest read it at boot).
    pub fn touches_snapshot(&self) -> bool {
        self.fields()
            .iter()
            .any(|f| !matches!(*f, "ports" | "restart"))
    }

    /// As the machine's view shows it: every field by name, the values the view shows.
    pub fn view(&self) -> Pending {
        Pending {
            fields: self.fields().into_iter().map(String::from).collect(),
            image: self.image.clone(),
            size: self.size,
            ports: self.ports.clone(),
            restart: self.restart.clone(),
            volume: self.volume,
        }
    }
}

/// A change a PATCH left for the next start (ADR 0024): the fields it changes, with the new
/// values of those a machine's view shows (env, files, cmd and entrypoint by name only). A
/// volume's disk has grown already; its filesystem grows at that start (ADR 0040).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<Size>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<u16>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart: Option<RestartPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume: Option<VolumeSize>,
}

/// Moves a machine into another namespace of the host it is on (ADR 0056).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MoveRequest {
    /// The namespace it joins: made when it does not exist.
    pub namespace: String,
}

/// What a move did.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoveResult {
    /// The machine in its namespace. Its `ip` is the address it has now.
    pub machine: Machine,
    /// The namespace it left.
    pub from: String,
    /// The address it had. Equal to `machine.ip` when the namespace was renamed.
    pub previous_ip: String,
    /// A running machine was stopped and started on the namespace's network: its programs
    /// began again, on a new address. False for a rename and for a machine that was not running.
    pub restarted: bool,
}

/// Changes a machine: the sleep window, metadata, egress, limits, disk limits and probes at
/// once; what it runs (`spec`) at its next start.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UpdateMachineRequest {
    /// A new sleep window ("30m", "never"); absent keeps the current one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sleep: Option<String>,
    /// Replaces the metadata; absent keeps it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BTreeMap<String, String>>,
    /// A new egress policy, applied at once to a running machine; absent keeps the current one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<Egress>,
    /// The limits it names, applied at once; the others stay as they are.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<EgressLimits>,
    /// The disk limits it names, applied at once to a running machine; the others stay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_limits: Option<DiskLimits>,
    /// A new backup schedule; `null` removes it, absent keeps it.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub backup: Option<Option<BackupPolicy>>,
    /// Replaces the probes; a running machine's start over at once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probes: Option<Probes>,
    /// The image, command, env, files, size, ports and restart policy, at the next start; a
    /// larger volume (ADR 0040).
    #[serde(flatten)]
    pub spec: SpecChange,
}

/// Stops a machine.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StopRequest {
    /// A memory snapshot instead of a stop (falls back to a stop when unsupported).
    #[serde(default)]
    pub suspend: bool,
    /// How long the process gets after SIGTERM (default 10).
    #[serde(default)]
    pub timeout_sec: u64,
}

/// A snapshot to take now (ADR 0031).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SnapshotRequest {
    /// A name to find it by again (`before-migration`), unique among the machine's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Its memory too, on a running machine: a restore resumes its processes where they were.
    #[serde(default)]
    pub memory: bool,
}

/// A point-in-time copy of a machine's disks, and of its memory when taken with it (ADR 0031).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: String,
    pub machine_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    /// The disks it holds: `root`, and `data` on a machine with a volume. A new image drops
    /// `root`: the root disk follows the image (ADR 0024).
    #[serde(default)]
    pub disks: Vec<String>,
    #[serde(default)]
    pub memory: bool,
}

/// A snapshot's name: an id's characters, and not the shape of a snapshot id (`s_…`), so a
/// path segment names one snapshot whichever it is.
pub fn check_snapshot_name(name: &str) -> Result<(), String> {
    if !valid_id(name) || name.starts_with("s_") {
        return Err(format!(
            "name {name:?}: a-z, 0-9, _ and -, at most 64, not starting with s_"
        ));
    }
    Ok(())
}
