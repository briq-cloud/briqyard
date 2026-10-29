//! The host: its images, capacity, conditions, status, registration and errors.

use super::*;

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
    /// A `zfs` command of the daemon's running for over a minute: the pool may be hung.
    pub const STORAGE_STALLED: &str = "storage_stalled";
    pub const ALL: &[&str] = &[MEMORY_PRESSURE, DISK_PRESSURE, STORAGE_STALLED];
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
    #[serde(alias = "tenant")]
    pub namespace: String,
    pub name: String,
    /// `gateway` for a namespace's gateway; absent for the namespace's machines.
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
    /// Where the fleet reaches the server over SSH, when not at the API's address (a host
    /// whose API is on a private network, added with `POST /v1/hosts`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ssh: String,
    #[serde(default)]
    pub region: String,
    /// How the host came: `static` (the fleet's `hosts:`) or `manual` (`POST /v1/hosts`).
    #[serde(default)]
    pub provider: String,
    /// ready, draining, retiring, upgrading, down, provisioning, bootstrapped, failed; `retired`
    /// in the answer to a retire that forgot it
    pub state: String,
    pub capacity: Capacity,
    pub used: Capacity,
    pub machines: usize,
    #[serde(default, alias = "tenants")]
    pub namespaces: Vec<String>,
    pub last_seen: DateTime<Utc>,
    #[serde(default)]
    pub version: String,
    /// The last thing the bootstrap or an upgrade said about this host.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    /// The SHA-256 of the host's API certificate, pinned by the fleet; empty for a host on
    /// plain HTTP (ADR 0020).
    #[serde(default)]
    pub tls_fingerprint: String,
    /// The ports its public interface takes besides SSH, from its bootstrap (ADR 0028).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_tcp_ports: Vec<u16>,
    /// What its last heartbeat said (ADR 0021).
    #[serde(default)]
    pub conditions: Vec<Condition>,
    /// Its daemon's last start, from its heartbeat; absent from a daemon older than ADR 0027.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started: Option<DaemonStart>,
}

/// When a daemon started and what it did with the machines the previous one left running
/// (ADR 0027): an upgrade waits for a start after its install, and fails one that stopped a
/// machine instead of taking it over. Each one stopped is booted again when its sleep window
/// had not run out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonStart {
    pub at: DateTime<Utc>,
    /// Left running and taken over.
    pub adopted: usize,
    /// Left running, its process still there but not answering for it: ended and marked
    /// stopped. What an upgrade fails on.
    pub stopped: usize,
    /// Left running and found without its process (it exited while no daemon ran): marked
    /// stopped.
    #[serde(default)]
    pub gone: usize,
}

/// POST /v1/hosts/{id}/upgrade (fleet only, ADR 0027).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UpgradeHostRequest {
    /// A release URL (where `briqyardd-linux-<arch>` and its siblings are), or a version
    /// (`0.2.0`, `v0.2.0`) of the project's releases.
    pub release: String,
}

/// POST /v1/hosts (fleet only): a server bought by hand, for the fleet to bootstrap.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AddHostRequest {
    /// The server's address for SSH (its public address).
    pub ssh: String,
    /// The API's address, an IP: on the fleet's private network when the server has one (its
    /// vRack address). Empty: the SSH address.
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub region: String,
    /// The host's id; empty: `h_` and the address.
    #[serde(default)]
    pub id: String,
    /// Ports its public interface takes besides SSH (an edge's on it); absent: the fleet's
    /// `bootstrap.public_tcp_ports`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_tcp_ports: Option<Vec<u16>>,
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
    #[serde(default, alias = "tenants")]
    pub namespaces: Vec<String>,
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
    /// The daemon's start; absent from a daemon older than ADR 0027.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started: Option<DaemonStart>,
}

/// `POST /v1/hosts/key` (fleet only): a host asks for its pool's key, with its own API token
/// as the bearer, for the record at the address it advertises (ADR 0026). With `key_id` and
/// `restore`, the key of that id instead, whichever host's it is or was: the key a backup's
/// streams are encrypted under, for a restore the fleet forwarded to the host (ADR 0035).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostKeyRequest {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// With `key_id`: the restore the key is for, as the fleet forwarded it to this host; a
    /// backup's key is served only for one, once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore: Option<RestoreSpec>,
}

/// The answer: a pool's key, 64 hex digits (ZFS's `hex` key format).
#[derive(Clone, Serialize, Deserialize)]
pub struct HostKey {
    pub key: String,
}

/// Never printed: a `{:?}` of it would put the key in a log.
impl std::fmt::Debug for HostKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HostKey { .. }")
    }
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
    /// The daemon's start; absent from a daemon older than ADR 0027.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started: Option<DaemonStart>,
    /// What a machine booted now runs under: Firecracker's version and the host kernel's
    /// release (ADR 0027).
    #[serde(default)]
    pub vmm_version: String,
    /// A fleet's only: the room in each region, what an external scaler reads (ADR 0042).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regions: Vec<RegionRoom>,
}

/// A region's room, as a fleet sees it (ADR 0042). Free space counts the hosts that take a new
/// namespace: `ready`, under the fill ceiling, no condition true.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionRoom {
    /// The hosts' `region`; empty for hosts with none, and for refusals of creates that asked
    /// for none. `other` counts refusals in a region no host is in.
    pub region: String,
    /// Free on those hosts, summed. Absent for a region no host is in (`other`, or empty when
    /// every host has a region): it has refusals only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub free: Option<Room>,
    /// The most free on one of them: the largest machine (memory) or volume plus headroom
    /// (disk) the region still takes. Absent as `free` is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub largest_slot: Option<Room>,
    /// Creates refused 503 `capacity` since the fleet started, by what ran out.
    pub unschedulable: Unschedulable,
}

/// Memory and disk, in MB.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Room {
    pub memory_mb: u64,
    pub disk_mb: u64,
}

/// Creates refused for want of room, by what ran out (ADR 0042).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unschedulable {
    /// No host of the region had the memory free under its fill ceiling, or those that had it
    /// and the disk are under `memory_pressure`. A new host fixes it.
    pub memory: u64,
    /// Hosts had the memory, none the disk, or those that had both are under `disk_pressure`.
    /// A new host fixes it.
    pub disk: u64,
    /// The host the create is bound to (the namespace's, a fork's source's) is under a condition
    /// (ADR 0021). A new host does not fix it: that host must be freed.
    pub pressure: u64,
}

/// Every error response's body.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
    pub code: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub request_id: String,
    /// With `boot_failed`: the machine, in state `error`, kept so the caller can read its
    /// console and destroy it. With `conflict` on a stale `If-Match`, and with `not_ready` from
    /// a `/wait`: the machine as it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<Box<Machine>>,
    /// With `gone`: the oldest event seq the host still keeps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oldest: Option<u64>,
}
