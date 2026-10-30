//! A machine: its create request, its record, its endpoints, exec, files and logs.

use super::*;

/// Makes a machine: recorded at once in `creating`, its image pulled (when the host has not
/// seen it), its disks made and its start done in the background (ADR 0048).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CreateMachineRequest {
    /// Owns the machine and its network; any string, a team id for briq.
    #[serde(alias = "tenant")]
    pub namespace: String,
    /// A DNS label, unique in the namespace: `<name>.internal` resolves to the machine.
    pub name: String,
    #[serde(default)]
    pub image: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmd: Option<Vec<String>>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub files: Vec<File>,
    pub size: Size,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume: Option<VolumeSpec>,
    #[serde(default)]
    pub ports: Vec<u16>,
    /// How long without use before the machine stops: "30m", "2h", "7d", or "never"/"".
    #[serde(default)]
    pub sleep: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart: Option<RestartPolicy>,
    /// Kept and returned as is (a briq id, a stack name); the labels `?label=` selects on.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    /// Through a fleet: a new namespace is placed on a host of this region, and a namespace's
    /// machines stay in its host's (ADR 0025). Empty: any region. A daemon ignores it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub region: String,
    /// Where its traffic may go; absent is `open` (a restore takes the backup's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<Egress>,
    /// Limits on its internet traffic, over the host's defaults (a restore takes the backup's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<EgressLimits>,
    /// Limits on each of its disks, over the host's defaults for its size (a restore takes
    /// the backup's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_limits: Option<DiskLimits>,
    /// Its backup schedule: absent is the host's default (none unless configured), `null` none.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub backup: Option<Option<BackupPolicy>>,
    /// Startup, readiness and liveness checks (ADR 0022); a restore takes the backup's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probes: Option<Probes>,
    /// Start right after creating (default true).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<bool>,
    /// Make the disks from a snapshot of another machine, taken now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fork: Option<ForkSpec>,
    /// Make the machine from a backup instead of an image: its disks as they were, its
    /// image, command, env, files, size and volume as the backed-up machine had them unless
    /// the request sets them. The backup may come from another host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore: Option<RestoreSpec>,
}

impl CreateMachineRequest {
    /// What it runs, as `SpecChange::check` reads it: the image when it names one.
    pub fn spec(&self) -> SpecChange {
        SpecChange {
            image: (!self.image.is_empty()).then(|| self.image.clone()),
            entrypoint: self.entrypoint.clone(),
            cmd: self.cmd.clone(),
            env: Some(self.env.clone()),
            files: Some(self.files.clone()),
            size: Some(self.size),
            ports: Some(self.ports.clone()),
            restart: self.restart.clone(),
            volume: self
                .volume
                .as_ref()
                .map(|v| VolumeSize { size_gb: v.size_gb }),
        }
    }
}

/// The source of a fork.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForkSpec {
    pub machine_id: String,
    /// "disk" (both disks, the default) or "config" (nothing: a fresh image).
    #[serde(default)]
    pub copy: String,
}

/// How the main process last ended on its own.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Exit {
    pub code: i32,
    pub oom_killed: bool,
    pub at: DateTime<Utc>,
    pub restarting: bool,
}

/// Machine states.
pub mod state {
    /// Recorded, its spec checked, its name, address and (when it starts) memory taken: its
    /// image pulled and its disks made in the background, then started (ADR 0048).
    pub const CREATING: &str = "creating";
    pub const CREATED: &str = "created";
    pub const STARTING: &str = "starting";
    pub const RUNNING: &str = "running";
    pub const STOPPING: &str = "stopping";
    pub const STOPPED: &str = "stopped";
    pub const DESTROYING: &str = "destroying";
    pub const ERROR: &str = "error";
}

/// Why a machine is stopped.
pub mod stop {
    /// Asked through the API.
    pub const USER: &str = "user";
    /// The sleep window ran out.
    pub const IDLE: &str = "idle";
    /// Its process ended and the restart policy let it.
    pub const EXIT: &str = "exit";
    /// The daemon stopped it on its own: a shutdown, or a previous daemon's leftover found
    /// at start. Wakeable, like `idle`.
    pub const HOST: &str = "host";
}

/// A machine as the API returns it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Machine {
    pub id: String,
    #[serde(alias = "tenant")]
    pub namespace: String,
    pub name: String,
    pub image: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub image_digest: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub stopped_reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<Exit>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// Why it is in `error`, the event that put it there: `pull_failed` or `create_failed`
    /// (its create, ADR 0048), `boot_failed`, `start_failed`. Empty for a record from before.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error_reason: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ip: String,
    pub hostname: String,
    pub machine_host: String,
    pub size: Size,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume: Option<VolumeSpec>,
    #[serde(default)]
    pub ports: Vec<u16>,
    pub sleep: String,
    pub restart: RestartPolicy,
    /// Restarts in a row by the restart policy.
    #[serde(default)]
    pub restarts: u32,
    /// When the restart policy starts it again, while it waits to (ADR 0022's backoff).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restarting_at: Option<DateTime<Utc>>,
    /// Running, and its probes say it serves: true without a startup or readiness probe.
    #[serde(default)]
    pub ready: bool,
    #[serde(default, skip_serializing_if = "Probes::is_empty")]
    pub probes: Probes,
    /// The last result of each probe in the current run.
    #[serde(default, skip_serializing_if = "ProbesStatus::is_empty")]
    pub probes_status: ProbesStatus,
    #[serde(default)]
    pub egress: Egress,
    /// The limits in force: the machine's own values over the host's.
    #[serde(default)]
    pub limits: EgressLimits,
    #[serde(default)]
    pub egress_drops: EgressDrops,
    /// The limits on each of its disks in force: its own values over the host's for its size.
    #[serde(default, skip_serializing_if = "DiskLimits::is_empty")]
    pub disk_limits: DiskLimits,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    #[serde(default)]
    pub endpoints: Vec<Endpoint>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// When `state` last changed. `updated_at` moves on every write (a touch, a metadata
    /// change); this moves only with the state.
    pub state_changed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stopped_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
    /// When the machine stops if nothing uses it; absent when running with no window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sleeps_at: Option<DateTime<Utc>>,
    /// Stopped with a memory snapshot: the next start resumes where it was.
    #[serde(default)]
    pub suspended: bool,
    /// Its backup schedule (ADR 0023); absent: none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<BackupPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_backup_at: Option<DateTime<Utc>>,
    /// When the daemon backs it up next, with a schedule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_backup_at: Option<DateTime<Utc>>,
    /// The seq of the last event about it (ADR 0019): what `If-Match` compares.
    #[serde(default)]
    pub version: u64,
    /// What a PATCH changes at its next start (ADR 0024).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<Pending>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_since: Option<DateTime<Utc>>,
    /// The init its root disk carries, as it said at the last boot (ADR 0027); empty before
    /// its first boot, or from an init older than the report.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub init_version: String,
    /// What ran it at its last boot: Firecracker's version and the host kernel's release,
    /// `v1.17.0/6.8.0-45-generic`. A memory snapshot resumes only under the same (ADR 0027).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vmm_version: String,
    /// The briqyardd that runs it (set by the fleet).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
}

/// A way in from outside the namespace's network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Endpoint {
    pub id: String,
    pub machine_id: String,
    /// Port inside the machine.
    pub port: u16,
    /// "tcp" or "http".
    pub protocol: String,
    /// The host port a TCP endpoint listens on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_port: Option<u16>,
    /// The HTTP endpoint's host name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    /// Where to connect: "<ip>:<host_port>" or "http://<host>".
    pub address: String,
    pub created_at: DateTime<Utc>,
}

/// Opens a port of a machine to the outside.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CreateEndpointRequest {
    pub port: u16,
    #[serde(default)]
    pub protocol: String,
    /// For http endpoints: the label before the domain; random when empty.
    #[serde(default)]
    pub host: String,
}

/// Runs a command inside a machine.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExecRequest {
    pub cmd: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub stdin: String,
    #[serde(default)]
    pub timeout_ms: u64,
    /// Wake a sleeping machine for the command (the default); `false` answers 409 when it is
    /// not running.
    #[serde(default = "default_true")]
    pub wake: bool,
}

fn default_true() -> bool {
    true
}

/// The command's output.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub timed_out: bool,
}

/// Writes a file into a running machine.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PutFileRequest {
    pub path: String,
    pub base64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

/// A file read from a machine.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileResponse {
    pub path: String,
    pub base64: String,
}

/// One line of the serial console.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogLine {
    pub ts: DateTime<Utc>,
    pub line: String,
}

/// A page of the console log; `next` continues after the last line returned.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LogsResponse {
    pub lines: Vec<LogLine>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub next: String,
}
