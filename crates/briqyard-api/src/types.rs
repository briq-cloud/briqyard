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
    /// "no", "on-failure" or "always".
    pub policy: String,
    #[serde(default)]
    pub max_retries: u32,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            policy: "on-failure".into(),
            max_retries: 3,
        }
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
    pub metadata: BTreeMap<String, String>,
    #[serde(default)]
    pub endpoints: Vec<Endpoint>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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
    /// A timestamp, `20261019T231500Z`; later ids sort later.
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
    #[serde(default)]
    pub gateway: String,
    #[serde(default)]
    pub machines: usize,
    pub created_at: DateTime<Utc>,
    /// The host the tenant lives on (fleet).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
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
}

/// POST /v1/hosts/order (fleet only).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OrderHostRequest {
    /// Why; kept in the host's note.
    #[serde(default)]
    pub reason: String,
}

/// What a daemon sends the fleet on start and as heartbeats.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterHostRequest {
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
    /// The daemon's own API token, so the fleet can forward requests to it.
    #[serde(default)]
    pub api_token: String,
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
}

/// Every error response's body.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
    pub code: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub request_id: String,
}

/// Parses a sleep window: "30m", "2h", "7d", "never" or "". `None` is never.
pub fn parse_sleep(s: &str) -> Result<Option<std::time::Duration>, String> {
    let s = s.trim();
    if s.is_empty() || s == "never" {
        return Ok(None);
    }
    let (num, unit) = s.split_at(s.len() - 1);
    let n: u64 = num
        .parse()
        .map_err(|_| format!("sleep {s:?}: want \"30m\", \"2h\", \"7d\" or \"never\""))?;
    if n == 0 {
        return Err(format!("sleep {s:?}: must be positive"));
    }
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86400,
        _ => {
            return Err(format!(
                "sleep {s:?}: want \"30m\", \"2h\", \"7d\" or \"never\""
            ))
        }
    };
    Ok(Some(std::time::Duration::from_secs(secs)))
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

    #[test]
    fn sleep_windows() {
        assert_eq!(parse_sleep("").unwrap(), None);
        assert_eq!(parse_sleep("never").unwrap(), None);
        assert_eq!(parse_sleep("30m").unwrap().unwrap().as_secs(), 1800);
        assert_eq!(parse_sleep("7d").unwrap().unwrap().as_secs(), 7 * 86400);
        for bad in ["0m", "x", "1y", "-1h"] {
            assert!(parse_sleep(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn names() {
        for ok in ["db", "my-app", "a1", "x"] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in ["", "-a", "a-", "A", "a.b", "a_b"] {
            assert!(!valid_name(bad), "{bad}");
        }
    }
}
