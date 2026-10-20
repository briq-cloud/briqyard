//! The HTTP API's JSON types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A machine's compute.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Size {
    pub vcpus: u32,
    pub memory_mb: u32,
}

/// A data volume mounted in the machine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeSpec {
    pub size_gb: u32,
    pub mount: String,
}

/// A boot file: written before the process starts, and again at every cold start.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct File {
    pub path: String,
    pub base64: String,
    /// Mode in octal digits ("0644"); empty is 0644.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

/// What the daemon does when the main process ends on its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestartPolicy {
    /// "no", "on-failure" or "always" (default "on-failure").
    #[serde(default = "default_policy")]
    pub policy: String,
    /// Default 3: a request that names the policy alone must not end up with no retries.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
}

fn default_policy() -> String {
    "on-failure".into()
}

fn default_max_retries() -> u32 {
    3
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            policy: default_policy(),
            max_retries: default_max_retries(),
        }
    }
}

/// A machine's backup schedule (ADR 0023): a backup every `every`, the newest `keep` kept with
/// what they continue from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupPolicy {
    /// "6h", "1d": at least an hour.
    pub every: String,
    /// At least 1.
    pub keep: u32,
}

impl BackupPolicy {
    /// The shortest `every`.
    pub const MIN_EVERY: std::time::Duration = std::time::Duration::from_secs(3600);

    /// `every` as a duration, checked with `keep`; the message names the field under `backup`.
    pub fn check(&self) -> Result<std::time::Duration, String> {
        let every =
            duration(self.every.trim(), r#"want "6h", "1d""#).map_err(|e| format!("every {e}"))?;
        if every < Self::MIN_EVERY {
            return Err(format!("every {:?}: at least 1h", self.every));
        }
        if self.keep < 1 {
            return Err("keep: at least 1".into());
        }
        Ok(every)
    }
}

/// A field that is there, `null` included, as `Some`: with `#[serde(default)]`, absent is
/// `None` and `null` is `Some(None)`. For a field where `null` removes what absent keeps.
fn present<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(d).map(Some)
}

/// Egress modes.
pub mod egress {
    /// The tenant, and the internet through NAT (the default).
    pub const OPEN: &str = "open";
    /// One machine of the tenant and the gateway's DNS, nothing else.
    pub const VIA: &str = "via";
    /// The tenant, no internet.
    pub const NONE: &str = "none";
    /// What `via` takes to name the tenant's gateway (ADR 0016) rather than a machine.
    pub const GATEWAY: &str = "gateway";
}

/// Where a machine's traffic may go: enforced on the host, never by the guest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Egress {
    /// "open" (default), "via" or "none".
    #[serde(default = "default_egress_mode")]
    pub mode: String,
    /// For `via`: the machine of the same tenant that is the only one this machine reaches,
    /// or `"gateway"` for the tenant's gateway, which then runs while this machine does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
}

fn default_egress_mode() -> String {
    egress::OPEN.into()
}

impl Default for Egress {
    fn default() -> Self {
        Self {
            mode: default_egress_mode(),
            via: None,
        }
    }
}

impl Egress {
    /// Sends through the tenant's gateway.
    pub fn via_gateway(&self) -> bool {
        self.mode == egress::VIA && self.via.as_deref() == Some(egress::GATEWAY)
    }

    /// The mode is one of the three, and `via` names a machine (or `"gateway"`) exactly when
    /// the mode is `via`.
    pub fn check(&self) -> Result<(), String> {
        match (self.mode.as_str(), &self.via) {
            (egress::OPEN | egress::NONE, None) => Ok(()),
            (egress::OPEN | egress::NONE, Some(_)) => {
                Err("egress.via goes with mode \"via\" only".into())
            }
            (egress::VIA, Some(id)) if valid_id(id) => Ok(()),
            (egress::VIA, _) => Err("egress.via must name a machine of the tenant".into()),
            (other, _) => Err(format!(
                "egress.mode {other:?}: want \"open\", \"via\" or \"none\""
            )),
        }
    }
}

/// Limits on a machine's internet traffic, through the host's NAT (ADR 0018). In a request an
/// absent field keeps what the machine has (on create: the host's default); in a machine's
/// view every field is there, the values in force.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressLimits {
    /// Destination ports refused, TCP and UDP; `[]` refuses none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_ports: Option<Vec<u16>>,
    /// New connections a minute, as many at once; 0 is no limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_connections_per_minute: Option<u32>,
    /// Mbit/s, in and out together; 0 is no limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bandwidth_mbit: Option<u32>,
}

impl EgressLimits {
    /// The highest bandwidth: the kernel's byte limit overflows past about 147 Gbit/s.
    pub const MAX_MBIT: u32 = 100_000;

    /// Every port is a port and the bandwidth is within `MAX_MBIT`; the message names the
    /// field under `limits`.
    pub fn check(&self) -> Result<(), String> {
        if self.blocked_ports.iter().flatten().any(|p| *p == 0) {
            return Err("blocked_ports: 0 is not a port".into());
        }
        if self.bandwidth_mbit.unwrap_or(0) > Self::MAX_MBIT {
            return Err(format!("bandwidth_mbit: at most {}", Self::MAX_MBIT));
        }
        Ok(())
    }

    /// This one's fields, and `under`'s where this one has none.
    pub fn over(&self, under: &EgressLimits) -> EgressLimits {
        EgressLimits {
            blocked_ports: self
                .blocked_ports
                .clone()
                .or_else(|| under.blocked_ports.clone()),
            new_connections_per_minute: self
                .new_connections_per_minute
                .or(under.new_connections_per_minute),
            bandwidth_mbit: self.bandwidth_mbit.or(under.bandwidth_mbit),
        }
    }
}

/// Packets a machine's egress limits dropped since it started, by limit (ADR 0018).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressDrops {
    pub blocked_port: u64,
    pub rate: u64,
    pub bandwidth: u64,
}

impl EgressDrops {
    pub fn total(&self) -> u64 {
        self.blocked_port + self.rate + self.bandwidth
    }
}

/// Makes a machine. The image is pulled if the host has not seen it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CreateMachineRequest {
    /// Owns the machine and its network; any string, a team id for briq.
    pub tenant: String,
    /// A DNS label, unique in the tenant: `<name>.internal` resolves to the machine.
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
    /// Kept and returned as is (a briq id, a stack name).
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    /// Where its traffic may go; absent is `open` (a restore takes the backup's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<Egress>,
    /// Limits on its internet traffic, over the host's defaults (a restore takes the backup's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<EgressLimits>,
    /// Its backup schedule: absent is the host's default (none unless configured), `null` none.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub backup: Option<Option<BackupPolicy>>,
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
    pub tenant: String,
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
    #[serde(default)]
    pub egress: Egress,
    /// The limits in force: the machine's own values over the host's.
    #[serde(default)]
    pub limits: EgressLimits,
    #[serde(default)]
    pub egress_drops: EgressDrops,
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
    /// The briqyardd that runs it (set by the fleet).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
}

/// A way in from outside the tenant's network.
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
    pub tenant: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    /// Bytes sent to the store for this backup.
    pub bytes: u64,
    /// Sent as a change since the previous backup, or whole.
    pub incremental: bool,
    pub disks: Vec<BackupDisk>,
    /// The machine as it was: what a restore makes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<serde_json::Value>,
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

/// Changes what can change on a live machine without a restart.
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
    /// A new backup schedule; `null` removes it, absent keeps it.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub backup: Option<Option<BackupPolicy>>,
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

/// A point-in-time copy of a machine's disks.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: String,
    pub machine_id: String,
    pub created_at: DateTime<Utc>,
}

/// A tenant's network on a host.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tenant {
    pub id: String,
    #[serde(default)]
    pub subnet: String,
    /// The host's address on the tenant's network (`.1`): the machines' route and DNS.
    #[serde(default)]
    pub router: String,
    /// The tenant's machines, its gateway not counted.
    #[serde(default)]
    pub machines: usize,
    pub created_at: DateTime<Utc>,
    /// The host the tenant lives on (fleet).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<GatewayView>,
}

/// `PUT /v1/tenants/{id}/gateway`: the tenant's gateway, a machine the daemon runs while a
/// machine of the tenant sends `via: "gateway"` (ADR 0016).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GatewaySpec {
    pub image: String,
    /// Replaces the image's command, as a machine's `cmd`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmd: Option<Vec<String>>,
    /// Write-only, like a machine's.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Default 1 vCPU, 256 MB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<Size>,
    /// The port the program listens on: a start waits for it.
    pub port: u16,
    /// A data volume at `/data`, fixed for the gateway's life.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_gb: Option<u32>,
    /// Start it now and answer once its port accepts (a running one is left as is), for a
    /// program that must run once before any machine uses it.
    #[serde(default)]
    pub start: bool,
}

impl GatewaySpec {
    /// The size it runs at: the spec's, or 1 vCPU and 256 MB.
    pub fn size(&self) -> Size {
        self.size.unwrap_or(Size {
            vcpus: 1,
            memory_mb: 256,
        })
    }
}

/// The tenant's gateway as `GET /v1/tenants/{id}` shows it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GatewayView {
    pub state: String,
    pub ip: String,
    pub port: u16,
    /// Its machine: `GET /v1/machines/{id}` and its logs answer for it.
    pub machine_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

/// What a running machine uses, from its cgroup (jailed hosts only).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MachineStats {
    pub state: String,
    /// CPU time used since the machine started, in microseconds.
    pub cpu_usec: u64,
    /// Memory the machine's process holds now, in bytes (guest memory touched plus Firecracker's).
    pub memory_bytes: u64,
    /// Seconds since the current run started.
    pub uptime_sec: u64,
    /// Disk the machine's datasets take, in bytes.
    pub disk_bytes: u64,
}

/// What one machine used in one UTC hour (ADR 0017): measures, never a price. `GET /v1/usage`.
/// One flat object: every name says its group and its unit already.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct UsageBucket {
    /// The hour's start.
    pub hour: DateTime<Utc>,
    pub machine_id: String,
    pub tenant: String,
    /// `gateway` for a tenant's gateway (ADR 0016); absent for the tenant's own machines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// The machine's metadata (the briq id), as it was last in the hour.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    pub size: Size,
    #[serde(flatten)]
    pub usage: Usage,
    /// The hour is over: the bucket will not change again.
    pub closed: bool,
    /// The briqyardd that measured it (set by the fleet).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
}

/// The measures of a bucket. GB is 2^30 bytes, as disk sizes are.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Usage {
    /// With a process: from the start's reservation to the process's end (`starting`,
    /// `running`, `stopping`).
    pub running_seconds: f64,
    /// Stopped with a memory snapshot.
    pub suspended_seconds: f64,
    /// CPU time the machine's cgroup used (jailed hosts).
    pub cpu_seconds: f64,
    /// `size.memory_mb` × running seconds: what was reserved.
    pub memory_mb_seconds: f64,
    /// The root disk's allocated size × hours.
    pub root_gb_hours: f64,
    /// The data volume's allocated size × hours.
    pub volume_gb_hours: f64,
    /// What the disks take on the pool × hours.
    pub disk_used_gb_hours: f64,
    /// What local snapshots take, memory snapshots included, × hours.
    pub snapshot_gb_hours: f64,
    /// What the machine's backups take in the object store × hours.
    pub backup_gb_hours: f64,
    /// Through the host's NAT.
    pub internet_out_bytes: u64,
    pub internet_in_bytes: u64,
    /// Through the host's endpoints; out is to the client.
    pub ingress_out_bytes: u64,
    pub ingress_in_bytes: u64,
    /// Packets its egress limits dropped (ADR 0018); absent in the hours stored before them.
    #[serde(default)]
    pub egress_dropped_packets: u64,
}

impl Usage {
    /// Adds another measure of the same machine and hour.
    pub fn add(&mut self, o: &Usage) {
        self.running_seconds += o.running_seconds;
        self.suspended_seconds += o.suspended_seconds;
        self.cpu_seconds += o.cpu_seconds;
        self.memory_mb_seconds += o.memory_mb_seconds;
        self.root_gb_hours += o.root_gb_hours;
        self.volume_gb_hours += o.volume_gb_hours;
        self.disk_used_gb_hours += o.disk_used_gb_hours;
        self.snapshot_gb_hours += o.snapshot_gb_hours;
        self.backup_gb_hours += o.backup_gb_hours;
        self.internet_out_bytes += o.internet_out_bytes;
        self.internet_in_bytes += o.internet_in_bytes;
        self.ingress_out_bytes += o.ingress_out_bytes;
        self.ingress_in_bytes += o.ingress_in_bytes;
        self.egress_dropped_packets += o.egress_dropped_packets;
    }
}

/// Event types, as Kubernetes's.
pub mod event {
    pub const NORMAL: &str = "normal";
    pub const WARNING: &str = "warning";
}

/// Why an event happened: a closed list (ADR 0019).
pub mod reason {
    pub const CREATED: &str = "created";
    pub const FORKED: &str = "forked";
    pub const RESTORED: &str = "restored";
    pub const STARTING: &str = "starting";
    pub const STARTED: &str = "started";
    pub const RESUMED: &str = "resumed";
    /// For probes: defined, not emitted yet.
    pub const READY: &str = "ready";
    pub const STOPPING: &str = "stopping";
    pub const STOPPED: &str = "stopped";
    pub const SUSPENDED: &str = "suspended";
    pub const EXITED: &str = "exited";
    pub const RESTARTING: &str = "restarting";
    pub const BOOT_FAILED: &str = "boot_failed";
    pub const START_FAILED: &str = "start_failed";
    pub const UPDATED: &str = "updated";
    pub const EGRESS_CHANGED: &str = "egress_changed";
    pub const BACKED_UP: &str = "backed_up";
    pub const BACKUP_FAILED: &str = "backup_failed";
    pub const BACKUP_DELETED: &str = "backup_deleted";
    pub const DESTROYED: &str = "destroyed";
    pub const GATEWAY_STARTED: &str = "gateway_started";
    pub const GATEWAY_STOPPED: &str = "gateway_stopped";
    pub const IMAGE_PULLED: &str = "image_pulled";
    pub const HOST_STARTED: &str = "host_started";
    pub const ADOPTED: &str = "adopted";
    /// A host condition changed (ADR 0021).
    pub const HOST_CONDITION: &str = "host_condition";
    pub const IMAGE_REMOVED: &str = "image_removed";
    pub const ALL: &[&str] = &[
        CREATED,
        FORKED,
        RESTORED,
        STARTING,
        STARTED,
        RESUMED,
        READY,
        STOPPING,
        STOPPED,
        SUSPENDED,
        EXITED,
        RESTARTING,
        BOOT_FAILED,
        START_FAILED,
        UPDATED,
        EGRESS_CHANGED,
        BACKED_UP,
        BACKUP_FAILED,
        BACKUP_DELETED,
        DESTROYED,
        GATEWAY_STARTED,
        GATEWAY_STOPPED,
        IMAGE_PULLED,
        HOST_STARTED,
        ADOPTED,
        HOST_CONDITION,
        IMAGE_REMOVED,
    ];
}

/// Something that happened on a host (ADR 0019). `GET /v1/events`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// One more per event on its host, never reused.
    pub seq: u64,
    pub at: DateTime<Utc>,
    /// `normal` or `warning`.
    #[serde(rename = "type")]
    pub kind: String,
    /// One of `reason::ALL`.
    pub reason: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub machine_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tenant: String,
    /// The host it happened on (set by the fleet on a fleet-wide read).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// A page of events, oldest first, and the cursor to read on from.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EventsPage {
    pub events: Vec<Event>,
    /// What to send as `since` next: a host's seq, or the fleet's `<host>:<seq>,…`.
    pub next: String,
}

/// Events a page holds: 500 unless asked, 5000 at most.
pub fn events_limit(asked: Option<usize>) -> usize {
    match asked {
        None | Some(0) => 500,
        Some(n) => n.min(5000),
    }
}

/// An image built on a host.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Image {
    pub key: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub digest: String,
    pub size_gb: u32,
    pub built_at: DateTime<Utc>,
    /// Machines whose root disk clones it.
    pub machines: usize,
}

/// Compute a host has or uses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capacity {
    pub memory_mb: u32,
    pub vcpus: u32,
}

/// Host condition types (ADR 0021), as Kubernetes's node conditions. Each is a pressure:
/// true is trouble, and the fleet places nothing new on the host while one is.
pub mod condition {
    /// Committed memory over `conditions.memory_pct` of capacity.
    pub const MEMORY_PRESSURE: &str = "memory_pressure";
    /// The pool's free space under `conditions.disk_free_pct` of its size.
    pub const DISK_PRESSURE: &str = "disk_pressure";
    pub const ALL: &[&str] = &[MEMORY_PRESSURE, DISK_PRESSURE];
}

/// A host condition as the daemon's tick last found it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Condition {
    /// One of `condition::ALL`.
    #[serde(rename = "type")]
    pub kind: String,
    pub status: bool,
    /// When `status` last changed (the daemon's start, until it does).
    pub since: DateTime<Utc>,
    /// The figures it was decided on.
    pub message: String,
}

/// The first condition that is true, if any.
pub fn under_pressure(conditions: &[Condition]) -> Option<&Condition> {
    conditions.iter().find(|c| c.status)
}

/// A running machine's use over the tick's last window (ADR 0021). `GET /v1/top`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TopMachine {
    pub machine_id: String,
    pub tenant: String,
    pub name: String,
    /// `gateway` for a tenant's gateway; absent for the tenant's machines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// CPU time over the window, in percent of one CPU.
    pub cpu_percent: f64,
    pub memory_bytes: u64,
    /// Its size's memory.
    pub memory_limit_bytes: u64,
    pub disk_used_bytes: u64,
    pub internet_in_bytes_per_sec: f64,
    pub internet_out_bytes_per_sec: f64,
    pub ingress_in_bytes_per_sec: f64,
    pub ingress_out_bytes_per_sec: f64,
    /// The seconds between the two measures the rates are taken from; 0 until there are two.
    pub window_sec: f64,
    /// The host it runs on (fleet).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
}

/// A briqyardd as the fleet sees it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Host {
    pub id: String,
    pub url: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub provider: String,
    /// ready, draining, down, provisioning, bootstrapped, failed, dry-run
    pub state: String,
    pub capacity: Capacity,
    pub used: Capacity,
    pub machines: usize,
    #[serde(default)]
    pub tenants: Vec<String>,
    pub last_seen: DateTime<Utc>,
    #[serde(default)]
    pub version: String,
    /// The last thing the provisioner or the bootstrap said about this host.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    /// The SHA-256 of the host's API certificate, pinned by the fleet; empty for a host on
    /// plain HTTP (ADR 0020).
    #[serde(default)]
    pub tls_fingerprint: String,
    /// What its last heartbeat said (ADR 0021).
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

/// POST /v1/hosts/order (fleet only).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OrderHostRequest {
    /// Why; kept in the host's note.
    #[serde(default)]
    pub reason: String,
}

/// What a daemon sends the fleet every 15 s, with its own API token as the bearer: the fleet
/// accepts it for the host record that expects that token at that address.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterHostRequest {
    /// The daemon's own id, for the fleet's log; the fleet keeps the host under its own.
    pub id: String,
    pub url: String,
    #[serde(default)]
    pub region: String,
    pub capacity: Capacity,
    pub used: Capacity,
    pub machines: usize,
    #[serde(default)]
    pub tenants: Vec<String>,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub disk_free_mb: u64,
    /// The SHA-256 of the API's certificate; empty when the API is plain HTTP. The fleet
    /// refuses a heartbeat whose fingerprint is not the one it pinned (ADR 0020).
    #[serde(default)]
    pub tls_fingerprint: String,
    /// The host's conditions (ADR 0021): the fleet places nothing new while one is true.
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

/// GET /v1/status.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Status {
    pub version: String,
    pub host_id: String,
    pub capacity: Capacity,
    pub used: Capacity,
    pub machines: usize,
    pub running: usize,
    /// Free space for disks, in MB.
    #[serde(default)]
    pub disk_free_mb: u64,
    /// The SHA-256 of the API's certificate; empty when the API is plain HTTP (ADR 0020).
    #[serde(default)]
    pub tls_fingerprint: String,
    /// Memory and disk pressure, as the tick last found them (ADR 0021).
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

/// Every error response's body.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
    pub code: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub request_id: String,
    /// With `boot_failed`: the machine, in state `error`, kept so the caller can read its
    /// console and destroy it. With `conflict` on a stale `If-Match`: the machine as it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<Box<Machine>>,
    /// With `gone`: the oldest event seq the host still keeps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oldest: Option<u64>,
}

/// Parses a sleep window: "30m", "2h", "7d", "never" or "". `None` is never.
pub fn parse_sleep(s: &str) -> Result<Option<std::time::Duration>, String> {
    let s = s.trim();
    if s.is_empty() || s == "never" {
        return Ok(None);
    }
    duration(s, r#"want "30m", "2h", "7d" or "never""#)
        .map(Some)
        .map_err(|e| format!("sleep {e}"))
}

/// A duration as the API writes one: a positive count and a unit, `s`, `m`, `h` or `d`. The
/// error starts with the value, for the caller to put its field before; `want` says what a
/// malformed one should look like.
fn duration(s: &str, want: &str) -> Result<std::time::Duration, String> {
    let bad = || format!("{s:?}: {want}");
    // The unit is the last character, not the last byte: splitting inside a multi-byte
    // character would panic.
    let (num, unit) = match s.char_indices().last() {
        Some((i, _)) => s.split_at(i),
        None => return Err(bad()),
    };
    let n: u64 = num.parse().map_err(|_| bad())?;
    if n == 0 {
        return Err(format!("{s:?}: must be positive"));
    }
    let per_unit = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return Err(bad()),
    };
    let secs = n
        .checked_mul(per_unit)
        .ok_or_else(|| format!("{s:?}: too long"))?;
    Ok(std::time::Duration::from_secs(secs))
}

/// An id the API takes from a caller (a tenant, a machine id in a path or a restore): a-z,
/// 0-9, `_` and `-`, 1 to 64 characters. Ids become file and object names on the host, so
/// nothing else gets in.
pub fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

/// A DNS label: a-z, 0-9, hyphens inside, at most 63 characters.
pub fn valid_name(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 63 || b[0] == b'-' || b[b.len() - 1] == b'-' {
        return false;
    }
    b.iter()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    /// Parses `input` as a `T`, then checks it serializes to exactly `expected`: the field
    /// names the API description promises, the defaults filled in, the skipped ones absent.
    fn round_trip<T>(input: Value, expected: Value) -> T
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        let v: T = serde_json::from_value(input.clone()).unwrap_or_else(|e| panic!("{input}: {e}"));
        assert_eq!(serde_json::to_value(&v).unwrap(), expected);
        v
    }

    /// `input` round-trips to itself.
    fn same<T>(input: Value) -> T
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        round_trip(input.clone(), input)
    }

    fn ts() -> DateTime<Utc> {
        "2026-01-02T03:04:05Z".parse().unwrap()
    }

    #[test]
    fn size_and_capacity() {
        let s: Size = same(json!({"vcpus": 2, "memory_mb": 1024}));
        assert_eq!(s.vcpus, 2);
        assert_eq!(s.memory_mb, 1024);
        // Both fields are required: a size with no memory is refused.
        assert!(serde_json::from_value::<Size>(json!({"vcpus": 2})).is_err());
        let c: Capacity = same(json!({"memory_mb": 65536, "vcpus": 16}));
        assert_eq!(
            c,
            Capacity {
                memory_mb: 65536,
                vcpus: 16
            }
        );
        assert_eq!(
            Capacity::default(),
            Capacity {
                memory_mb: 0,
                vcpus: 0
            }
        );
    }

    #[test]
    fn volume_spec() {
        let v: VolumeSpec = same(json!({"size_gb": 10, "mount": "/data"}));
        assert_eq!(v.mount, "/data");
        assert!(serde_json::from_value::<VolumeSpec>(json!({"size_gb": 10})).is_err());
    }

    #[test]
    fn file() {
        // The mode is optional and absent from the output when not given.
        let f: File = same(json!({"path": "/etc/app.conf", "base64": "aGk="}));
        assert_eq!(f.mode, None);
        let f: File = same(json!({"path": "/bin/run", "base64": "", "mode": "0755"}));
        assert_eq!(f.mode.as_deref(), Some("0755"));
        assert!(serde_json::from_value::<File>(json!({"path": "/x"})).is_err());
    }

    #[test]
    fn restart_policy_defaults() {
        // The description promises on-failure with 3 retries for whatever is left out.
        let r: RestartPolicy = round_trip(
            json!({"policy": "always"}),
            json!({"policy": "always", "max_retries": 3}),
        );
        assert_eq!(r.max_retries, 3);
        let r: RestartPolicy = round_trip(
            json!({"max_retries": 0}),
            json!({"policy": "on-failure", "max_retries": 0}),
        );
        assert_eq!(r.policy, "on-failure");
        let r: RestartPolicy =
            round_trip(json!({}), json!({"policy": "on-failure", "max_retries": 3}));
        assert_eq!(r, RestartPolicy::default());
        let r: RestartPolicy = same(json!({"policy": "no", "max_retries": 5}));
        assert_eq!(r.max_retries, 5);
    }

    #[test]
    fn fork_spec() {
        let f: ForkSpec = round_trip(
            json!({"machine_id": "m1"}),
            json!({"machine_id": "m1", "copy": ""}),
        );
        assert_eq!(f.copy, "");
        let f: ForkSpec = same(json!({"machine_id": "m1", "copy": "config"}));
        assert_eq!(f.copy, "config");
        assert!(serde_json::from_value::<ForkSpec>(json!({"copy": "disk"})).is_err());
    }

    #[test]
    fn exit() {
        let e: Exit = same(json!({
            "code": 137, "oom_killed": true, "at": "2026-01-02T03:04:05Z", "restarting": false
        }));
        assert_eq!(e.code, 137);
        assert!(e.oom_killed);
        assert_eq!(e.at, ts());
    }

    #[test]
    fn create_machine_request_minimal() {
        // tenant, name and size are enough; the collections come back empty and the
        // optional parts stay out of the output.
        let r: CreateMachineRequest = round_trip(
            json!({"tenant": "t1", "name": "db", "size": {"vcpus": 1, "memory_mb": 256}}),
            json!({
                "tenant": "t1", "name": "db", "image": "",
                "env": {}, "files": [], "size": {"vcpus": 1, "memory_mb": 256},
                "ports": [], "sleep": "", "metadata": {}
            }),
        );
        assert_eq!(r.entrypoint, None);
        assert_eq!(r.cmd, None);
        assert_eq!(r.volume, None);
        assert_eq!(r.restart, None);
        assert_eq!(r.start, None);
        assert!(r.fork.is_none());
        for missing in [
            json!({"name": "db", "size": {"vcpus": 1, "memory_mb": 256}}),
            json!({"tenant": "t1", "size": {"vcpus": 1, "memory_mb": 256}}),
            json!({"tenant": "t1", "name": "db"}),
        ] {
            assert!(
                serde_json::from_value::<CreateMachineRequest>(missing.clone()).is_err(),
                "{missing}"
            );
        }
    }

    #[test]
    fn create_machine_request_full() {
        let input = json!({
            "tenant": "t1", "name": "web", "image": "docker.io/library/nginx:1.27",
            "entrypoint": ["/docker-entrypoint.sh"], "cmd": ["nginx", "-g", "daemon off;"],
            "env": {"A": "1", "B": "2"},
            "files": [{"path": "/etc/motd", "base64": "aGk=", "mode": "0600"}],
            "size": {"vcpus": 2, "memory_mb": 1024},
            "volume": {"size_gb": 5, "mount": "/data"},
            "ports": [80, 443], "sleep": "30m",
            "restart": {"policy": "always", "max_retries": 0},
            "metadata": {"briq": "bq_1"}, "egress": {"mode": "via", "via": "m_gw"},
            "limits": {"blocked_ports": [25, 465], "new_connections_per_minute": 600},
            "start": false,
            "fork": {"machine_id": "m0", "copy": "disk"}
        });
        let r: CreateMachineRequest = same(input);
        assert_eq!(
            r.egress.as_ref().and_then(|e| e.via.as_deref()),
            Some("m_gw")
        );
        let l = r.limits.as_ref().unwrap();
        assert_eq!(l.blocked_ports.as_deref(), Some(&[25, 465][..]));
        assert_eq!(l.bandwidth_mbit, None, "absent: the host's");
        assert_eq!(
            r.cmd.as_deref(),
            Some(&["nginx", "-g", "daemon off;"].map(String::from)[..])
        );
        assert_eq!(r.env.get("B").map(String::as_str), Some("2"));
        assert_eq!(r.files[0].mode.as_deref(), Some("0600"));
        assert_eq!(r.ports, vec![80, 443]);
        assert_eq!(r.start, Some(false));
        assert_eq!(r.fork.as_ref().map(|f| f.machine_id.as_str()), Some("m0"));
    }

    #[test]
    fn machine_minimal() {
        let input = json!({
            "id": "m1", "tenant": "t1", "name": "db", "image": "postgres:17",
            "state": "running", "hostname": "db.internal", "machine_host": "m1.vm.internal",
            "size": {"vcpus": 1, "memory_mb": 512}, "sleep": "never",
            "restart": {"policy": "no", "max_retries": 0},
            "created_at": "2026-01-02T03:04:05Z", "updated_at": "2026-01-02T03:04:05Z",
            "state_changed_at": "2026-01-02T03:04:05Z"
        });
        let mut expected = input.clone();
        // What a reader always gets, even when nothing was set.
        expected["ports"] = json!([]);
        expected["metadata"] = json!({});
        expected["endpoints"] = json!([]);
        expected["suspended"] = json!(false);
        expected["egress"] = json!({"mode": "open"});
        expected["version"] = json!(0);
        expected["limits"] = json!({});
        expected["egress_drops"] = json!({"blocked_port": 0, "rate": 0, "bandwidth": 0});
        let m: Machine = round_trip(input, expected);
        assert_eq!(m.state, state::RUNNING);
        assert_eq!(m.egress, Egress::default());
        assert_eq!(m.image_digest, "");
        assert!(m.exit.is_none());
        assert_eq!(m.started_at, None);
        assert_eq!(m.sleeps_at, None);
        assert_eq!(m.host, "");
    }

    #[test]
    fn machine_full() {
        let input = json!({
            "id": "m1", "tenant": "t1", "name": "db", "image": "postgres:17",
            "image_digest": "sha256:abc", "state": "stopped", "stopped_reason": "exit",
            "exit": {"code": 1, "oom_killed": false, "at": "2026-01-02T03:04:05Z", "restarting": true},
            "error": "boom", "ip": "10.64.0.2",
            "hostname": "db.internal", "machine_host": "m1.vm.internal",
            "size": {"vcpus": 1, "memory_mb": 512},
            "volume": {"size_gb": 5, "mount": "/var/lib/postgresql/data"},
            "ports": [5432], "sleep": "30m",
            "restart": {"policy": "on-failure", "max_retries": 3},
            "egress": {"mode": "none"},
            "limits": {"blocked_ports": [25], "new_connections_per_minute": 0, "bandwidth_mbit": 100},
            "egress_drops": {"blocked_port": 3, "rate": 0, "bandwidth": 12},
            "metadata": {"stack": "s1"},
            "endpoints": [{
                "id": "e1", "machine_id": "m1", "port": 5432, "protocol": "tcp",
                "host_port": 20001, "address": "1.2.3.4:20001", "created_at": "2026-01-02T03:04:05Z"
            }],
            "created_at": "2026-01-02T03:04:05Z", "updated_at": "2026-01-02T03:04:05Z",
            "state_changed_at": "2026-01-02T03:04:05Z",
            "started_at": "2026-01-02T03:04:05Z", "stopped_at": "2026-01-02T03:04:05Z",
            "last_used_at": "2026-01-02T03:04:05Z", "sleeps_at": "2026-01-02T03:34:05Z",
            "suspended": true, "backup": {"every": "6h", "keep": 4},
            "last_backup_at": "2026-01-02T03:04:05Z", "next_backup_at": "2026-01-02T09:04:05Z",
            "version": 812, "host": "h1"
        });
        let m: Machine = same(input);
        assert_eq!(m.backup.as_ref().map(|b| b.keep), Some(4));
        assert_eq!(
            m.next_backup_at
                .zip(m.last_backup_at)
                .map(|(n, l)| (n - l).num_hours()),
            Some(6)
        );
        assert_eq!(m.version, 812);
        assert_eq!(m.stopped_reason, stop::EXIT);
        assert_eq!(m.egress.mode, egress::NONE);
        assert_eq!(m.limits.bandwidth_mbit, Some(100));
        assert_eq!(m.egress_drops.total(), 15);
        assert_eq!(m.exit.as_ref().map(|e| e.code), Some(1));
        assert_eq!(m.endpoints[0].host_port, Some(20001));
        assert_eq!(m.sleeps_at.map(|t| (t - ts()).num_minutes()), Some(30));
        assert!(m.suspended);
    }

    #[test]
    fn endpoint() {
        // A TCP endpoint carries host_port and no host; an HTTP one the reverse.
        let e: Endpoint = same(json!({
            "id": "e1", "machine_id": "m1", "port": 5432, "protocol": "tcp",
            "host_port": 20001, "address": "1.2.3.4:20001", "created_at": "2026-01-02T03:04:05Z"
        }));
        assert_eq!(e.host, "");
        let e: Endpoint = same(json!({
            "id": "e2", "machine_id": "m1", "port": 8080, "protocol": "http",
            "host": "app-ab12.example.test", "address": "http://app-ab12.example.test",
            "created_at": "2026-01-02T03:04:05Z"
        }));
        assert_eq!(e.host_port, None);
    }

    #[test]
    fn create_endpoint_request() {
        let r: CreateEndpointRequest = round_trip(
            json!({"port": 80}),
            json!({"port": 80, "protocol": "", "host": ""}),
        );
        assert_eq!(r.port, 80);
        let r: CreateEndpointRequest = same(json!({"port": 80, "protocol": "http", "host": "app"}));
        assert_eq!(r.host, "app");
        assert!(
            serde_json::from_value::<CreateEndpointRequest>(json!({"protocol": "tcp"})).is_err()
        );
        // A port is 16 bits.
        assert!(serde_json::from_value::<CreateEndpointRequest>(json!({"port": 70000})).is_err());
    }

    #[test]
    fn exec_request_defaults() {
        let r: ExecRequest = round_trip(
            json!({"cmd": ["ls", "-l"]}),
            json!({
                "cmd": ["ls", "-l"], "env": {}, "cwd": "", "stdin": "",
                "timeout_ms": 0, "wake": true
            }),
        );
        assert!(r.wake, "wake defaults to true");
        assert_eq!(r.timeout_ms, 0);
        let r: ExecRequest = same(json!({
            "cmd": ["cat"], "env": {"X": "1"}, "cwd": "/tmp", "stdin": "hi",
            "timeout_ms": 5000, "wake": false
        }));
        assert!(!r.wake);
        assert_eq!(r.stdin, "hi");
        assert!(serde_json::from_value::<ExecRequest>(json!({"wake": true})).is_err());
        // ExecRequest::default() is not what the wire gives: the derive leaves wake false, so
        // code that builds one by hand must set it.
        assert!(!ExecRequest::default().wake);
    }

    #[test]
    fn exec_result() {
        let r: ExecResult = same(json!({
            "stdout": "ok\n", "stderr": "", "exit_code": 0, "timed_out": false
        }));
        assert_eq!(r.exit_code, 0);
        assert!(serde_json::from_value::<ExecResult>(json!({"stdout": "x"})).is_err());
    }

    #[test]
    fn files() {
        let p: PutFileRequest = same(json!({"path": "/etc/x", "base64": "aGk="}));
        assert_eq!(p.mode, None);
        let p: PutFileRequest = same(json!({"path": "/etc/x", "base64": "aGk=", "mode": "0600"}));
        assert_eq!(p.mode.as_deref(), Some("0600"));
        let f: FileResponse = same(json!({"path": "/etc/x", "base64": "aGk="}));
        assert_eq!(f.base64, "aGk=");
    }

    #[test]
    fn logs() {
        let l: LogsResponse = round_trip(
            json!({"lines": [{"ts": "2026-01-02T03:04:05Z", "line": "[briqyard] started pid=1"}]}),
            json!({"lines": [{"ts": "2026-01-02T03:04:05Z", "line": "[briqyard] started pid=1"}]}),
        );
        assert_eq!(l.next, "");
        assert_eq!(l.lines[0].ts, ts());
        let l: LogsResponse = same(json!({"lines": [], "next": "42"}));
        assert_eq!(l.next, "42");
    }

    #[test]
    fn update_machine_request() {
        // Absent keeps the current value, so absent must stay absent on the wire.
        let u: UpdateMachineRequest = same(json!({}));
        assert_eq!(u.sleep, None);
        assert_eq!(u.metadata, None);
        let u: UpdateMachineRequest = same(json!({"sleep": "3h"}));
        assert_eq!(u.sleep.as_deref(), Some("3h"));
        assert_eq!(u.metadata, None);
        let u: UpdateMachineRequest = same(json!({"metadata": {}}));
        assert_eq!(u.metadata, Some(BTreeMap::new()));
        let u: UpdateMachineRequest = same(json!({"egress": {"mode": "via", "via": "m_gw"}}));
        assert_eq!(
            u.egress.as_ref().and_then(|e| e.via.as_deref()),
            Some("m_gw")
        );
        assert_eq!(u.limits, None);
        // Only the limits it names change: 0 lifts one.
        let u: UpdateMachineRequest = same(json!({"limits": {"new_connections_per_minute": 0}}));
        assert_eq!(
            u.limits,
            Some(EgressLimits {
                new_connections_per_minute: Some(0),
                ..Default::default()
            })
        );
    }

    #[test]
    fn egress_policy() {
        // Absent fields are the default: open, no gateway; `via` stays off the wire then.
        let e: Egress = round_trip(json!({}), json!({"mode": "open"}));
        assert_eq!(e, Egress::default());
        assert_eq!(e.check(), Ok(()));
        let e: Egress = same(json!({"mode": "none"}));
        assert_eq!(e.check(), Ok(()));
        let e: Egress = same(json!({"mode": "via", "via": "m_gw"}));
        assert_eq!(e.check(), Ok(()));
        assert!(!e.via_gateway());
        // The tenant's gateway, by the word that names it.
        let e: Egress = same(json!({"mode": "via", "via": "gateway"}));
        assert_eq!(e.check(), Ok(()));
        assert!(e.via_gateway());
        assert!(!Egress::default().via_gateway());
        // The checks name the field and what it wants.
        let bad = |v: serde_json::Value| serde_json::from_value::<Egress>(v).unwrap().check();
        assert_eq!(
            bad(json!({"mode": "all"})).unwrap_err(),
            "egress.mode \"all\": want \"open\", \"via\" or \"none\""
        );
        assert_eq!(
            bad(json!({"mode": "open", "via": "m_gw"})).unwrap_err(),
            "egress.via goes with mode \"via\" only"
        );
        for v in [
            json!({"mode": "via"}),
            json!({"mode": "via", "via": "../x"}),
        ] {
            assert_eq!(
                bad(v).unwrap_err(),
                "egress.via must name a machine of the tenant"
            );
        }
    }

    #[test]
    fn egress_limits() {
        // Absent fields stay absent: a request that names none changes none.
        let l: EgressLimits = same(json!({}));
        assert_eq!(l, EgressLimits::default());
        assert_eq!(l.check(), Ok(()));
        let own: EgressLimits = same(json!({"blocked_ports": [], "bandwidth_mbit": 100}));
        assert_eq!(own.check(), Ok(()));
        // A machine's own fields over the host's, one by one; `[]` and 0 are values.
        let host: EgressLimits = same(json!({
            "blocked_ports": [25], "new_connections_per_minute": 0, "bandwidth_mbit": 0
        }));
        assert_eq!(
            own.over(&host),
            EgressLimits {
                blocked_ports: Some(vec![]),
                new_connections_per_minute: Some(0),
                bandwidth_mbit: Some(100),
            }
        );
        assert_eq!(EgressLimits::default().over(&host), host);
        // The checks name the field under `limits` and what it wants.
        let bad = |v: serde_json::Value| serde_json::from_value::<EgressLimits>(v).unwrap().check();
        assert_eq!(
            bad(json!({"blocked_ports": [25, 0]})).unwrap_err(),
            "blocked_ports: 0 is not a port"
        );
        assert_eq!(
            bad(json!({"bandwidth_mbit": 100_001})).unwrap_err(),
            "bandwidth_mbit: at most 100000"
        );
        assert_eq!(bad(json!({"bandwidth_mbit": 100_000})), Ok(()));
        assert!(serde_json::from_value::<EgressLimits>(json!({"blocked_ports": [70000]})).is_err());
        let d: EgressDrops = same(json!({"blocked_port": 1, "rate": 2, "bandwidth": 3}));
        assert_eq!(d.total(), 6);
    }

    #[test]
    fn stop_request() {
        let s: StopRequest = round_trip(json!({}), json!({"suspend": false, "timeout_sec": 0}));
        assert!(!s.suspend);
        let s: StopRequest = same(json!({"suspend": true, "timeout_sec": 30}));
        assert_eq!(s.timeout_sec, 30);
    }

    #[test]
    fn snapshot_and_tenant() {
        let s: Snapshot = same(json!({
            "id": "snap1", "machine_id": "m1", "created_at": "2026-01-02T03:04:05Z"
        }));
        assert_eq!(s.machine_id, "m1");
        let t: Tenant = round_trip(
            json!({"id": "t1", "created_at": "2026-01-02T03:04:05Z"}),
            json!({
                "id": "t1", "subnet": "", "router": "", "machines": 0,
                "created_at": "2026-01-02T03:04:05Z"
            }),
        );
        assert_eq!(t.host, "");
        assert!(t.gateway.is_none(), "no gateway: none on the wire");
        let t: Tenant = same(json!({
            "id": "t1", "subnet": "10.64.1.0/24", "router": "10.64.1.1", "machines": 2,
            "created_at": "2026-01-02T03:04:05Z", "host": "h1",
            "gateway": {"state": "running", "ip": "10.64.1.2", "port": 3128, "machine_id": "m_1"}
        }));
        assert_eq!(t.machines, 2);
        assert_eq!(t.gateway.as_ref().map(|g| g.port), Some(3128));
        let g: GatewayView = same(json!({
            "state": "error", "ip": "10.64.1.2", "port": 3128, "machine_id": "m_1",
            "error": "port 3128 did not answer"
        }));
        assert_eq!(g.error, "port 3128 did not answer");
    }

    #[test]
    fn gateway_spec() {
        // An image and a port are enough; env comes back empty, not started, the rest out.
        let s: GatewaySpec = round_trip(
            json!({"image": "ghcr.io/x/proxy:1", "port": 3128}),
            json!({"image": "ghcr.io/x/proxy:1", "env": {}, "port": 3128, "start": false}),
        );
        assert!(s.size.is_none() && s.volume_gb.is_none() && s.cmd.is_none());
        assert_eq!(
            s.size(),
            Size {
                vcpus: 1,
                memory_mb: 256
            }
        );
        let s: GatewaySpec = same(json!({
            "image": "ghcr.io/x/proxy:1", "cmd": ["proxy", "-v"], "env": {"TOKEN": "t"},
            "size": {"vcpus": 1, "memory_mb": 512}, "port": 3128, "volume_gb": 1, "start": true
        }));
        assert_eq!(s.env["TOKEN"], "t");
        assert_eq!(s.size().memory_mb, 512);
        assert!(s.start);
        for missing in [json!({"image": "x"}), json!({"port": 3128})] {
            assert!(
                serde_json::from_value::<GatewaySpec>(missing.clone()).is_err(),
                "{missing}"
            );
        }
    }

    #[test]
    fn machine_stats() {
        let s: MachineStats = same(json!({
            "state": "running", "cpu_usec": 123456, "memory_bytes": 104857600,
            "uptime_sec": 60, "disk_bytes": 2147483648u64
        }));
        assert_eq!(s.disk_bytes, 2 << 30);
    }

    #[test]
    fn image_ref_field() {
        // The reference is `ref` on the wire (a keyword in Rust, hence the rename).
        let i: Image = same(json!({
            "key": "k", "ref": "docker.io/library/postgres:17", "digest": "sha256:abc",
            "size_gb": 2, "built_at": "2026-01-02T03:04:05Z", "machines": 1
        }));
        assert_eq!(i.reference, "docker.io/library/postgres:17");
        assert!(serde_json::from_value::<Image>(json!({
            "key": "k", "reference": "x", "digest": "d", "size_gb": 2,
            "built_at": "2026-01-02T03:04:05Z", "machines": 1
        }))
        .is_err());
    }

    #[test]
    fn host() {
        let input = json!({
            "id": "h1", "url": "http://10.0.0.5:7420", "state": "ready",
            "capacity": {"memory_mb": 65536, "vcpus": 16}, "used": {"memory_mb": 1024, "vcpus": 2},
            "machines": 2, "last_seen": "2026-01-02T03:04:05Z"
        });
        let mut expected = input.clone();
        expected["region"] = json!("");
        expected["provider"] = json!("");
        expected["tenants"] = json!([]);
        expected["version"] = json!("");
        expected["tls_fingerprint"] = json!("");
        expected["conditions"] = json!([]);
        let h: Host = round_trip(input, expected);
        assert_eq!(h.note, "");
        let h: Host = same(json!({
            "id": "h1", "url": "http://10.0.0.5:7420", "region": "fsn1", "provider": "hetzner-robot",
            "state": "draining", "capacity": {"memory_mb": 65536, "vcpus": 16},
            "used": {"memory_mb": 1024, "vcpus": 2}, "machines": 2, "tenants": ["t1", "t2"],
            "last_seen": "2026-01-02T03:04:05Z", "version": "0.1.0", "note": "ordered",
            "tls_fingerprint": "ab01",
            "conditions": [{"type": "disk_pressure", "status": true,
                "since": "2026-01-02T03:04:05Z", "message": "pool 4% free"}]
        }));
        assert_eq!(h.tenants, vec!["t1", "t2"]);
        assert_eq!(
            under_pressure(&h.conditions).map(|c| c.kind.as_str()),
            Some(condition::DISK_PRESSURE)
        );
    }

    #[test]
    fn host_requests() {
        let o: OrderHostRequest = round_trip(json!({}), json!({"reason": ""}));
        assert_eq!(o.reason, "");
        let r: RegisterHostRequest = round_trip(
            json!({
                "id": "h1", "url": "http://10.0.0.5:7420",
                "capacity": {"memory_mb": 65536, "vcpus": 16}, "used": {"memory_mb": 0, "vcpus": 0},
                "machines": 0
            }),
            json!({
                "id": "h1", "url": "http://10.0.0.5:7420", "region": "",
                "capacity": {"memory_mb": 65536, "vcpus": 16}, "used": {"memory_mb": 0, "vcpus": 0},
                "machines": 0, "tenants": [], "version": "", "disk_free_mb": 0,
                "tls_fingerprint": "", "conditions": []
            }),
        );
        assert_eq!(r.region, "");
        let r: RegisterHostRequest = same(json!({
            "id": "h1", "url": "http://10.0.0.5:7420", "region": "fsn1",
            "capacity": {"memory_mb": 65536, "vcpus": 16}, "used": {"memory_mb": 512, "vcpus": 1},
            "machines": 1, "tenants": ["t1"], "version": "0.1.0", "disk_free_mb": 100000,
            "tls_fingerprint": "ab01",
            "conditions": [{"type": "memory_pressure", "status": false,
                "since": "2026-01-02T03:04:05Z", "message": "512 MB of 65536 committed (0%)"}]
        }));
        assert_eq!(r.disk_free_mb, 100000);
        assert_eq!(r.tls_fingerprint, "ab01");
        assert!(serde_json::from_value::<RegisterHostRequest>(json!({"id": "h1"})).is_err());
    }

    #[test]
    fn status() {
        let s: Status = round_trip(
            json!({
                "version": "0.1.0", "host_id": "h1",
                "capacity": {"memory_mb": 65536, "vcpus": 16}, "used": {"memory_mb": 0, "vcpus": 0},
                "machines": 3, "running": 1
            }),
            json!({
                "version": "0.1.0", "host_id": "h1",
                "capacity": {"memory_mb": 65536, "vcpus": 16}, "used": {"memory_mb": 0, "vcpus": 0},
                "machines": 3, "running": 1, "disk_free_mb": 0, "tls_fingerprint": "",
                "conditions": []
            }),
        );
        assert_eq!(s.running, 1);
        let s: Status = same(json!({
            "version": "0.1.0", "host_id": "h1",
            "capacity": {"memory_mb": 1000, "vcpus": 16}, "used": {"memory_mb": 990, "vcpus": 2},
            "machines": 3, "running": 3, "disk_free_mb": 10, "tls_fingerprint": "",
            "conditions": [
                {"type": "memory_pressure", "status": true, "since": "2026-01-02T03:04:05Z",
                 "message": "990 MB of 1000 committed (99%), over 95%"},
                {"type": "disk_pressure", "status": false, "since": "2026-01-02T03:04:05Z",
                 "message": "pool 50% free"}
            ]
        }));
        assert_eq!(
            under_pressure(&s.conditions).map(|c| c.kind.as_str()),
            Some(condition::MEMORY_PRESSURE)
        );
        // A condition without its status or time is refused, not read as fine.
        assert!(serde_json::from_value::<Condition>(
            json!({"type": "disk_pressure", "message": ""})
        )
        .is_err());
        assert_eq!(condition::ALL, ["memory_pressure", "disk_pressure"]);
    }

    #[test]
    fn top_machine() {
        let t: TopMachine = same(json!({
            "machine_id": "m_1", "tenant": "t1", "name": "db", "cpu_percent": 12.5,
            "memory_bytes": 104857600, "memory_limit_bytes": 536870912,
            "disk_used_bytes": 2147483648u64, "internet_in_bytes_per_sec": 10.0,
            "internet_out_bytes_per_sec": 2.5, "ingress_in_bytes_per_sec": 0.0,
            "ingress_out_bytes_per_sec": 1000.0, "window_sec": 15.0
        }));
        assert_eq!((t.role, t.host.as_str()), (None, ""));
        let g: TopMachine = same(json!({
            "machine_id": "m_2", "tenant": "t1", "name": "gateway", "role": "gateway",
            "cpu_percent": 0.0, "memory_bytes": 0, "memory_limit_bytes": 268435456,
            "disk_used_bytes": 0, "internet_in_bytes_per_sec": 0.0,
            "internet_out_bytes_per_sec": 0.0, "ingress_in_bytes_per_sec": 0.0,
            "ingress_out_bytes_per_sec": 0.0, "window_sec": 0.0, "host": "h1"
        }));
        assert_eq!(g.role.as_deref(), Some("gateway"));
    }

    #[test]
    fn usage_bucket() {
        // Flat: the identity, every measure by its ADR name, `closed`; no role for a tenant's
        // own machine, no host from a daemon.
        let b: UsageBucket = same(json!({
            "hour": "2026-10-20T14:00:00Z", "machine_id": "m_1", "tenant": "t1",
            "metadata": {"briq_id": "bq_1"}, "size": {"vcpus": 1, "memory_mb": 512},
            "running_seconds": 3600.0, "suspended_seconds": 0.0, "cpu_seconds": 12.5,
            "memory_mb_seconds": 1843200.0, "root_gb_hours": 8.0, "volume_gb_hours": 2.0,
            "disk_used_gb_hours": 0.5, "snapshot_gb_hours": 0.25, "backup_gb_hours": 0.75,
            "internet_out_bytes": 100, "internet_in_bytes": 2000,
            "ingress_out_bytes": 300, "ingress_in_bytes": 40, "egress_dropped_packets": 7,
            "closed": true
        }));
        assert_eq!(b.usage.cpu_seconds, 12.5);
        assert_eq!(b.usage.ingress_in_bytes, 40);
        assert_eq!(b.role, None);
        let g: UsageBucket = same(json!({
            "hour": "2026-10-20T15:00:00Z", "machine_id": "m_2", "tenant": "t1",
            "role": "gateway", "metadata": {}, "size": {"vcpus": 1, "memory_mb": 256},
            "running_seconds": 1.5, "suspended_seconds": 0.0, "cpu_seconds": 0.0,
            "memory_mb_seconds": 384.0, "root_gb_hours": 0.0, "volume_gb_hours": 0.0,
            "disk_used_gb_hours": 0.0, "snapshot_gb_hours": 0.0, "backup_gb_hours": 0.0,
            "internet_out_bytes": 0, "internet_in_bytes": 0,
            "ingress_out_bytes": 0, "ingress_in_bytes": 0, "egress_dropped_packets": 2,
            "closed": false, "host": "h1"
        }));
        assert_eq!(
            (g.role.as_deref(), g.host.as_str()),
            (Some("gateway"), "h1")
        );
        // A measure left out is refused, not read as zero.
        assert!(serde_json::from_value::<UsageBucket>(json!({
            "hour": "2026-10-20T15:00:00Z", "machine_id": "m_2", "tenant": "t1",
            "size": {"vcpus": 1, "memory_mb": 256}, "closed": false
        }))
        .is_err());
        // Except the drops: an hour stored before ADR 0018 has none, read as zero.
        let mut old = serde_json::to_value(&b).unwrap();
        old.as_object_mut()
            .unwrap()
            .remove("egress_dropped_packets");
        let old: UsageBucket = serde_json::from_value(old).unwrap();
        assert_eq!(old.usage.egress_dropped_packets, 0);
        // Two measures of a machine's hour add up, field by field.
        let mut u = b.usage;
        u.add(&g.usage);
        assert_eq!(u.running_seconds, 3601.5);
        assert_eq!(u.memory_mb_seconds, 1843584.0);
        assert_eq!(u.internet_in_bytes, 2000);
        assert_eq!(u.egress_dropped_packets, 9);
    }

    #[test]
    fn api_error() {
        // request_id is left out when the error has none.
        let e: ApiError = same(json!({"error": "no such machine", "code": "not_found"}));
        assert_eq!(e.request_id, "");
        let e: ApiError = same(json!({"error": "boom", "code": "internal", "request_id": "r1"}));
        assert_eq!(e.request_id, "r1");
        // A boot failure carries the machine it left in `error`.
        let e: ApiError = same(json!({
            "error": "the guest did not come up", "code": "boot_failed",
            "machine": {
                "id": "m1", "tenant": "t1", "name": "db", "image": "postgres:17",
                "state": "error", "error": "the guest did not come up",
                "hostname": "db.internal", "machine_host": "m1.vm.internal",
                "size": {"vcpus": 1, "memory_mb": 512}, "ports": [], "sleep": "never",
                "restart": {"policy": "no", "max_retries": 0}, "egress": {"mode": "open"},
                "limits": {}, "egress_drops": {"blocked_port": 0, "rate": 0, "bandwidth": 0},
                "metadata": {}, "endpoints": [],
                "created_at": "2026-01-02T03:04:05Z", "updated_at": "2026-01-02T03:04:05Z",
                "state_changed_at": "2026-01-02T03:04:05Z", "suspended": false, "version": 3
            }
        }));
        assert_eq!(e.machine.as_ref().map(|m| m.state.as_str()), Some("error"));
        // A cursor too old for the log names the oldest seq kept.
        let e: ApiError = same(json!({"error": "since 3 is gone", "code": "gone", "oldest": 120}));
        assert_eq!(e.oldest, Some(120));
    }

    #[test]
    fn event() {
        // `type` on the wire (a keyword in Rust); a host event has no machine, tenant or data.
        let e: Event = same(json!({
            "seq": 1, "at": "2026-10-20T14:00:00Z", "type": "normal", "reason": "host_started",
            "message": "daemon started"
        }));
        assert_eq!(
            (e.kind.as_str(), e.machine_id.as_str()),
            (event::NORMAL, "")
        );
        let e: Event = same(json!({
            "seq": 812, "at": "2026-10-20T14:03:11.204Z", "type": "warning", "reason": "exited",
            "message": "exited with code 7", "machine_id": "m_1", "tenant": "t1", "host": "h1",
            "data": {"code": 7, "oom": false, "restarting": true}
        }));
        assert_eq!(e.reason, reason::EXITED);
        assert_eq!(e.data.as_ref().map(|d| d["code"].clone()), Some(json!(7)));
        // The seq is required: an event is nothing without its place in the log.
        assert!(serde_json::from_value::<Event>(json!({
            "at": "2026-10-20T14:00:00Z", "type": "normal", "reason": "created", "message": ""
        }))
        .is_err());
        let p: EventsPage = same(json!({"events": [], "next": "h1:12,h2:40"}));
        assert_eq!(p.next, "h1:12,h2:40");
    }

    #[test]
    fn reasons_and_page_limits() {
        // A closed list, each once, each a snake_case word.
        let mut all = reason::ALL.to_vec();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), reason::ALL.len());
        assert_eq!(all.len(), 27);
        assert!(all
            .iter()
            .all(|r| r.bytes().all(|c| c.is_ascii_lowercase() || c == b'_')));
        assert_eq!((event::NORMAL, event::WARNING), ("normal", "warning"));
        assert_eq!(events_limit(None), 500);
        assert_eq!(events_limit(Some(0)), 500);
        assert_eq!(events_limit(Some(20)), 20);
        assert_eq!(events_limit(Some(usize::MAX)), 5000);
    }

    #[test]
    fn state_and_stop_constants() {
        // What the description enumerates, byte for byte.
        assert_eq!(
            [
                state::CREATED,
                state::STARTING,
                state::RUNNING,
                state::STOPPING,
                state::STOPPED,
                state::DESTROYING,
                state::ERROR
            ],
            [
                "created",
                "starting",
                "running",
                "stopping",
                "stopped",
                "destroying",
                "error"
            ]
        );
        assert_eq!(
            [stop::USER, stop::IDLE, stop::EXIT, stop::HOST],
            ["user", "idle", "exit", "host"]
        );
    }

    #[test]
    fn backup_policies() {
        let p: BackupPolicy = same(json!({"every": "6h", "keep": 4}));
        assert_eq!(p.check(), Ok(std::time::Duration::from_secs(6 * 3600)));
        let every = |e: &str| BackupPolicy {
            every: e.into(),
            keep: 1,
        };
        assert_eq!(every("1d").check().unwrap().as_secs(), 86400);
        assert_eq!(every(" 1h ").check().unwrap().as_secs(), 3600);
        // Each refusal names its field, for the caller to put `backup.` before.
        assert_eq!(
            every("59m").check().unwrap_err(),
            r#"every "59m": at least 1h"#
        );
        assert_eq!(
            every("never").check().unwrap_err(),
            r#"every "never": want "6h", "1d""#
        );
        assert_eq!(
            every("0h").check().unwrap_err(),
            r#"every "0h": must be positive"#
        );
        assert!(every("").check().unwrap_err().starts_with("every "));
        let none = BackupPolicy {
            every: "6h".into(),
            keep: 0,
        };
        assert_eq!(none.check().unwrap_err(), "keep: at least 1");
        // Both fields are required.
        assert!(serde_json::from_value::<BackupPolicy>(json!({"every": "6h"})).is_err());
    }

    #[test]
    fn a_backup_policy_absent_is_kept_and_null_removes_it() {
        let c: CreateMachineRequest = serde_json::from_value(json!({
            "tenant": "t1", "name": "db", "size": {"vcpus": 1, "memory_mb": 256}
        }))
        .unwrap();
        assert_eq!(c.backup, None, "absent: the host's default");
        let c: CreateMachineRequest = serde_json::from_value(json!({
            "tenant": "t1", "name": "db", "size": {"vcpus": 1, "memory_mb": 256}, "backup": null
        }))
        .unwrap();
        assert_eq!(c.backup, Some(None), "null: none");
        assert_eq!(serde_json::to_value(&c).unwrap()["backup"], Value::Null);
        let u: UpdateMachineRequest = same(json!({"backup": {"every": "1d", "keep": 5}}));
        assert_eq!(u.backup.flatten().map(|p| p.keep), Some(5));
        let u: UpdateMachineRequest = same(json!({"backup": null}));
        assert_eq!(u.backup, Some(None));
        let u: UpdateMachineRequest = same(json!({}));
        assert_eq!(u.backup, None);
    }

    #[test]
    fn backups() {
        let b: Backup = same(json!({
            "id": "20261021T101500.123Z", "machine_id": "m1", "tenant": "t1", "name": "db",
            "created_at": "2026-01-02T03:04:05Z", "bytes": 30, "incremental": true,
            "disks": [
                {"disk": "root", "key": "backups/m1/root/20261021T101500.123Z.zfs", "bytes": 10,
                 "from": "20261021T091500.001Z"},
                {"disk": "data", "key": "backups/m1/data/20261021T101500.123Z.zfs", "bytes": 20}
            ],
            "deletes_at": "2026-01-02T03:04:05Z"
        }));
        assert_eq!(b.disks[0].from.as_deref(), Some("20261021T091500.001Z"));
        assert_eq!(b.disks[1].from, None);
        assert_eq!(b.deletes_at, Some(ts()));
        // A stored record carries the machine and no deletion time.
        let r: Backup = same(json!({
            "id": "a", "machine_id": "m1", "tenant": "t1", "name": "db",
            "created_at": "2026-01-02T03:04:05Z", "bytes": 0, "incremental": false,
            "disks": [], "machine": {"id": "m1"}
        }));
        assert_eq!(r.deletes_at, None);
        let rs: RestoreSpec = round_trip(
            json!({"machine_id": "m1"}),
            json!({"machine_id": "m1", "backup": ""}),
        );
        assert_eq!(rs.backup, "");
    }

    #[test]
    fn sleep_windows() {
        assert_eq!(parse_sleep("").unwrap(), None);
        assert_eq!(parse_sleep("   ").unwrap(), None);
        assert_eq!(parse_sleep("never").unwrap(), None);
        assert_eq!(parse_sleep(" never ").unwrap(), None);
        let secs = |s: &str| parse_sleep(s).unwrap().unwrap().as_secs();
        assert_eq!(secs("45s"), 45);
        assert_eq!(secs("30m"), 1800);
        assert_eq!(secs("2h"), 7200);
        assert_eq!(secs("7d"), 7 * 86400);
        assert_eq!(secs(" 1m "), 60);
        for bad in [
            "0m", "0s", "0d", "x", "m", "1", "1y", "-1h", "1.5h", "30 m", "1h30m", "NEVER", "1M",
        ] {
            assert!(parse_sleep(bad).is_err(), "{bad}");
        }
        assert!(parse_sleep("0m").unwrap_err().contains("positive"));
        assert!(parse_sleep("1y").unwrap_err().contains("\"30m\""));
    }

    #[test]
    fn sleep_windows_do_not_panic() {
        // A unit that is not one byte long used to split the string inside a character.
        for bad in ["1é", "é", "30\u{200b}", "1時"] {
            assert!(parse_sleep(bad).is_err(), "{bad}");
        }
        // A count past u64 is refused; one whose seconds would overflow too, instead of
        // wrapping to a short window in release builds.
        assert!(parse_sleep("99999999999999999999s").is_err());
        assert_eq!(
            parse_sleep(&format!("{}s", u64::MAX))
                .unwrap()
                .unwrap()
                .as_secs(),
            u64::MAX
        );
        assert!(parse_sleep(&format!("{}m", u64::MAX))
            .unwrap_err()
            .contains("too long"));
        assert!(parse_sleep(&format!("{}d", u64::MAX / 86400 + 1)).is_err());
        assert_eq!(
            secs_of(&format!("{}d", u64::MAX / 86400)),
            (u64::MAX / 86400) * 86400
        );
    }

    fn secs_of(s: &str) -> u64 {
        parse_sleep(s).unwrap().unwrap().as_secs()
    }

    #[test]
    fn names() {
        for ok in [
            "db",
            "my-app",
            "a1",
            "x",
            "0",
            "a-b-c",
            "a--b",
            &"a".repeat(63),
        ] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in [
            "",
            "-a",
            "a-",
            "-",
            "A",
            "aB",
            "a.b",
            "a_b",
            "a b",
            "é",
            "a/b",
            &"a".repeat(64),
        ] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn ids() {
        for ok in [
            "t1",
            "m_abcdef123456",
            "team-x",
            "_",
            "-",
            "0",
            &"a".repeat(64),
        ] {
            assert!(valid_id(ok), "{ok}");
        }
        // What would leave the state directory, or name a file nothing expects.
        for bad in [
            "",
            "../../etc/cron.d/x",
            "a/b",
            "..",
            ".hidden",
            "a.b",
            "A",
            "a b",
            "é",
            "a\0b",
            &"a".repeat(65),
        ] {
            assert!(!valid_id(bad), "{bad}");
        }
    }
}
