//! Namespaces, quotas, gateways, stats and usage.

use super::*;

/// A namespace's network on a host.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Namespace {
    pub id: String,
    #[serde(default)]
    pub subnet: String,
    /// The host's address on the namespace's network (`.1`): the machines' route and DNS.
    #[serde(default)]
    pub router: String,
    /// The namespace's machines, its gateway not counted.
    #[serde(default)]
    pub machines: usize,
    pub created_at: DateTime<Utc>,
    /// The host the namespace lives on (fleet).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    /// Its host's region: the namespace's (fleet, ADR 0025).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub region: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<GatewayView>,
}

/// `PUT /v1/namespaces/{id}/quota` (ADR 0025): what the namespace may hold. A limit left out is no
/// limit; set by the control plane, the daemon has no defaults.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quota {
    /// Machines, its gateway included.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machines: Option<u32>,
    /// Memory of the machines starting, running or stopping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<u32>,
    /// vCPUs of the same.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vcpus: Option<u32>,
    /// CPU budget in millicores; legacy records use vcpus × 1000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_millis: Option<u32>,
    /// The volumes' sizes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_gb: Option<u32>,
}

impl Quota {
    pub fn cpu_millis(&self) -> Option<u32> {
        let legacy = self.vcpus.map(|n| n.saturating_mul(1000));
        match (self.cpu_millis, legacy) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

/// What a namespace holds now, counted as its quota counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaUse {
    pub machines: u32,
    pub memory_mb: u32,
    pub vcpus: u32,
    /// CPU budget in millicores; legacy records use vcpus × 1000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_millis: Option<u32>,
    pub disk_gb: u32,
}

impl QuotaUse {
    pub fn cpu_millis(&self) -> u32 {
        self.cpu_millis
            .unwrap_or_else(|| self.vcpus.saturating_mul(1000))
    }
}

/// `GET /v1/namespaces/{id}/quota`: the limits and the use.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceQuota {
    #[serde(alias = "tenant")]
    pub namespace: String,
    pub quota: Quota,
    pub used: QuotaUse,
}

/// `PUT /v1/namespaces/{id}/gateway`: the namespace's gateway, a machine the daemon runs while a
/// machine of the namespace sends `via: "gateway"` (ADR 0016).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GatewaySpec {
    pub image: String,
    /// Replaces the image's command, as a machine's `cmd`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmd: Option<Vec<String>>,
    /// Write-only, like a machine's.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Boot files, as a machine's: a stock proxy reads its configuration and its CA from
    /// files. Write-only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<File>,
    /// Default 1 vCPU, 256 MB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<Size>,
    /// The port the program listens on: a start waits for it.
    pub port: u16,
    /// A data volume at `/data`, fixed for the gateway's life.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_gb: Option<u32>,
    /// As a machine's; with a startup or readiness probe, a start that needs the gateway waits
    /// for its `ready` instead of its port.
    #[serde(default, skip_serializing_if = "Probes::is_empty")]
    pub probes: Probes,
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
            cpu_millis: None,
        })
    }
}

/// The namespace's gateway as `GET /v1/namespaces/{id}` shows it.
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
    #[serde(alias = "tenant")]
    pub namespace: String,
    /// `gateway` for a namespace's gateway (ADR 0016); absent for the namespace's own machines.
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
