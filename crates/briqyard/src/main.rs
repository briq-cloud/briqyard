//! briqyard is the CLI: it talks to a briqyardd or a briqyard-fleet over HTTP.

use anyhow::{anyhow, bail, Context, Result};
use briqyard_api as api;
use clap::{Args, Parser, Subcommand};
use std::collections::BTreeMap;
use std::io::Write;
use std::ops::ControlFlow;
use std::time::Duration;

mod session;

#[derive(Parser)]
#[command(name = "briqyard", version = api::VERSION, about = "Machines in Firecracker microVMs")]
struct Cli {
    /// The daemon or fleet to talk to.
    #[arg(
        long,
        env = "BRIQYARD_URL",
        default_value = "http://127.0.0.1:7420",
        global = true
    )]
    url: String,
    /// Bearer token.
    #[arg(long, env = "BRIQYARD_TOKEN", global = true, hide_env_values = true)]
    token: Option<String>,
    /// A daemon's API certificate (`tls_fingerprint` in its status, `briqyardd
    /// tls-fingerprint` on the host): trusted alone, no CA. Without it, an https URL is
    /// checked against the web PKI, as a fleet's is.
    #[arg(long, env = "BRIQYARD_TLS_FINGERPRINT", global = true, value_parser = fingerprint_arg)]
    tls_fingerprint: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// The host's status
    Status,
    /// The API description
    Openapi,
    /// Machines
    #[command(subcommand, alias = "m")]
    Machine(Box<MachineCmd>),
    /// Endpoints: ways in from outside
    #[command(subcommand, alias = "ep")]
    Endpoint(EndpointCmd),
    /// Tenants: one private network each
    #[command(subcommand)]
    Tenant(TenantCmd),
    /// Images built on the host
    #[command(subcommand)]
    Image(ImageCmd),
    /// Hosts, when talking to a fleet
    #[command(subcommand)]
    Host(HostCmd),
    /// Backups in the store: delete one
    #[command(subcommand)]
    Backup(BackupCmd),
    /// Every backup of the host's machines, destroyed ones' included: briqyard backups [--tenant T]
    Backups {
        #[arg(long)]
        tenant: Option<String>,
    },
    /// What each machine used, per hour: briqyard usage --from 2026-10-20T14:00:00Z --to 2026-10-20T15:00:00Z
    Usage {
        /// The first hour, RFC 3339
        #[arg(long, value_parser = hour_arg)]
        from: chrono::DateTime<chrono::Utc>,
        /// The hour after the last (at most 31 days after --from)
        #[arg(long, value_parser = hour_arg)]
        to: chrono::DateTime<chrono::Utc>,
        #[arg(long)]
        tenant: Option<String>,
        /// Every field, as JSON
        #[arg(long)]
        json: bool,
    },
    /// What happened, oldest first: briqyard events [--tenant T] [--machine ID] [--since CURSOR] [--watch]
    Events {
        #[arg(long)]
        tenant: Option<String>,
        #[arg(long)]
        machine: Option<String>,
        /// Read on from a previous read's cursor (printed at the end)
        #[arg(long)]
        since: Option<String>,
        /// Stay connected and print each new event
        #[arg(long)]
        watch: bool,
    },
    /// Running machines by CPU, over the daemon's last 15 s: briqyard top [--tenant T]
    Top {
        #[arg(long)]
        tenant: Option<String>,
        /// Every field, as JSON
        #[arg(long)]
        json: bool,
    },
    /// Check this machine as a briqyard host: KVM, ZFS, nftables, Firecracker, the kernel
    Doctor,
}

#[derive(Subcommand)]
enum MachineCmd {
    /// List machines: briqyard machine ls [--tenant T] [-l app=web] [-l tier]
    Ls {
        #[arg(long)]
        tenant: Option<String>,
        /// A label selector, repeatable, all ANDed: KEY=VALUE or KEY (has it)
        #[arg(short = 'l', long = "label")]
        labels: Vec<String>,
    },
    /// Create and start a machine
    Run(Box<RunArgs>),
    /// Show a machine
    Get {
        id: String,
    },
    /// A machine as a person reads it, with its last 20 events
    Describe {
        id: String,
    },
    Start {
        id: String,
    },
    /// Stop; with --suspend, keep a memory snapshot so the next start resumes
    Stop {
        #[arg(long)]
        suspend: bool,
        id: String,
    },
    /// Stop and start again: what `set` left pending applies now
    Restart {
        id: String,
    },
    Wake {
        id: String,
    },
    Touch {
        id: String,
    },
    /// Wait until ready (its probes pass), or until running with --for running
    Wait {
        #[arg(long = "for", default_value = "ready", value_parser = ["ready", "running"])]
        until: String,
        id: String,
    },
    /// Destroy a machine and its disks
    #[command(alias = "destroy")]
    Rm {
        id: String,
    },
    /// Run a command inside: briqyard machine exec [-it] ID -- cmd... (wakes a sleeping machine)
    Exec {
        /// Fail when the machine is not running instead of waking it
        #[arg(long)]
        no_wake: bool,
        /// The command's deadline: 5m by default, none for a session (-i, -t)
        #[arg(long)]
        timeout: Option<humantime::Duration>,
        /// A session: stdin streamed to the command as it comes
        #[arg(short, long)]
        interactive: bool,
        /// A session on a terminal: the local one raw, its size followed
        #[arg(short, long)]
        tty: bool,
        id: String,
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// The serial console; with -f, stay connected and print each new line
    Logs {
        #[arg(long)]
        since: Option<String>,
        #[arg(long, default_value_t = 500)]
        limit: usize,
        #[arg(short, long)]
        follow: bool,
        id: String,
    },
    /// A new machine from a snapshot of this one, taken now
    Fork {
        #[arg(long)]
        name: Option<String>,
        id: String,
    },
    /// Write a local file into the machine
    Put {
        id: String,
        local: String,
        guest_path: String,
    },
    /// Read a file from the machine to stdout
    GetFile {
        id: String,
        guest_path: String,
    },
    /// Snapshots of both disks, kept on the host
    #[command(subcommand)]
    Snapshot(SnapshotCmd),
    /// CPU, memory and disk the machine uses now
    Stats {
        id: String,
    },
    /// Send the machine's disks to the backup store (whole, then what changed)
    Backup {
        id: String,
    },
    /// The backups of a machine id in the store, oldest first
    Backups {
        id: String,
    },
    /// A new machine from a backup: briqyard machine restore --from MACHINE_ID [--backup ID] --tenant T --name N
    Restore {
        #[arg(long)]
        from: String,
        #[arg(long, default_value = "latest")]
        backup: String,
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "")]
        sleep: String,
    },
    /// Change what it runs, at its next start (restart to apply now): briqyard machine set ID --image python:3.13-alpine -e V=2 -- cmd...; --volume-gb grows the volume
    Set(Box<SetArgs>),
    /// Change the backup schedule: briqyard machine set-backup ID --every 6h --keep 4, or --off
    SetBackup {
        id: String,
        #[arg(long, requires = "keep", conflicts_with = "off")]
        every: Option<String>,
        #[arg(long, requires = "every")]
        keep: Option<u32>,
        /// No schedule; the backups made stay
        #[arg(long, required_unless_present = "every")]
        off: bool,
    },
    /// Change the sleep window: briqyard machine set-sleep ID 30m|never
    SetSleep {
        id: String,
        #[arg(value_parser = sleep_arg)]
        sleep: String,
    },
    /// Change where its traffic may go, at once: briqyard machine set-egress ID open|none|via:MACHINE_ID|via:gateway
    SetEgress {
        id: String,
        #[arg(value_parser = egress_arg)]
        egress: api::Egress,
    },
    /// Change the limits it names on its internet traffic, at once: briqyard machine set-limits ID --conn-per-min 0
    SetLimits {
        id: String,
        #[command(flatten)]
        limits: LimitArgs,
    },
    /// Change the limits it names on each of its disks, at once: briqyard machine set-disk-limits ID --disk-bw 8
    SetDiskLimits {
        id: String,
        #[command(flatten)]
        limits: DiskArgs,
    },
}

/// Limits on a machine's internet traffic; each one left out is the machine's (on a run, the
/// host's).
#[derive(Args)]
struct LimitArgs {
    /// A destination port refused, TCP and UDP, repeatable (the host's default: 25)
    #[arg(long = "block-port")]
    block_ports: Vec<u16>,
    /// New connections a minute; 0: no limit
    #[arg(long)]
    conn_per_min: Option<u32>,
    /// Mbit/s, in and out together; 0: no limit
    #[arg(long)]
    bandwidth: Option<u32>,
}

impl LimitArgs {
    /// The request's `limits`, checked as the daemon checks them; none when nothing is named.
    fn request(&self) -> Result<Option<api::EgressLimits>> {
        let l = api::EgressLimits {
            blocked_ports: (!self.block_ports.is_empty()).then(|| self.block_ports.clone()),
            new_connections_per_minute: self.conn_per_min,
            bandwidth_mbit: self.bandwidth,
        };
        if let Err(e) = l.check() {
            bail!("limits.{e}");
        }
        Ok((l != api::EgressLimits::default()).then_some(l))
    }
}

/// Limits on each of a machine's disks (the root disk and the volume); each one left out is
/// the machine's (on a run, the host's for its size).
#[derive(Args)]
struct DiskArgs {
    /// MB a second, reads and writes together; 0: no limit
    #[arg(long)]
    disk_bw: Option<u32>,
    /// Requests a second; 0: no limit
    #[arg(long)]
    disk_iops: Option<u32>,
    /// Seconds at the rates let through at full speed once, after a start or a change
    #[arg(long)]
    disk_burst: Option<u32>,
}

impl DiskArgs {
    /// The request's `disk_limits`, checked as the daemon checks them; none when nothing is
    /// named.
    fn request(&self) -> Result<Option<api::DiskLimits>> {
        let l = api::DiskLimits {
            bandwidth_mb: self.disk_bw,
            iops: self.disk_iops,
            burst_sec: self.disk_burst,
        };
        if let Err(e) = l.check() {
            bail!("disk_limits.{e}");
        }
        Ok((l != api::DiskLimits::default()).then_some(l))
    }
}

#[derive(Args)]
struct RunArgs {
    #[arg(long)]
    image: String,
    /// A DNS label; made from the image when absent
    #[arg(long)]
    name: Option<String>,
    #[arg(long, default_value = "default")]
    tenant: String,
    /// Through a fleet: place a new tenant on a host of this region
    #[arg(long, default_value = "")]
    region: String,
    /// K=V, repeatable: its metadata, what `machine ls -l` selects on
    #[arg(short = 'l', long = "label")]
    labels: Vec<String>,
    #[arg(long, default_value_t = 1)]
    vcpus: u32,
    /// Memory in MB
    #[arg(long, default_value_t = 512)]
    memory: u32,
    /// Sleep window: 30m, 2h, never
    #[arg(long, default_value = "", value_parser = sleep_arg)]
    sleep: String,
    /// Where its traffic may go: open (default), none (its tenant only), via:MACHINE_ID, via:gateway (the tenant's)
    #[arg(long, value_parser = egress_arg)]
    egress: Option<api::Egress>,
    #[command(flatten)]
    limits: LimitArgs,
    #[command(flatten)]
    disk: DiskArgs,
    #[command(flatten)]
    backup: BackupArgs,
    /// Checked before readiness and liveness run; failing, the boot fails: http:PORT[/PATH], tcp:PORT, exec:CMD ARGS
    #[arg(long, value_parser = probe_arg)]
    startup: Option<api::Probe>,
    /// Decides `ready`, which the ingress and `wait` follow: http:PORT[/PATH], tcp:PORT, exec:CMD ARGS
    #[arg(long, value_parser = probe_arg)]
    readiness: Option<api::Probe>,
    /// Failing, the machine is restarted under its restart policy: http:PORT[/PATH], tcp:PORT, exec:CMD ARGS
    #[arg(long, value_parser = probe_arg)]
    liveness: Option<api::Probe>,
    /// Data volume, SIZE:MOUNT (10G:/data)
    #[arg(long)]
    volume: Option<String>,
    /// K=V, repeatable
    #[arg(long = "env", short = 'e')]
    envs: Vec<String>,
    /// A port the image listens on, repeatable
    #[arg(long = "port", short = 'p')]
    ports: Vec<u16>,
    /// /guest/path=local/path, repeatable
    #[arg(long = "file")]
    files: Vec<String>,
    /// Entrypoint argv, repeatable
    #[arg(long = "entrypoint")]
    entrypoint: Vec<String>,
    #[arg(long)]
    no_start: bool,
    /// The command, after --
    #[arg(last = true)]
    cmd: Vec<String>,
}

/// What `machine set` changes; each one left out stays as it is.
#[derive(Args)]
struct SetArgs {
    id: String,
    #[arg(long)]
    image: Option<String>,
    #[arg(long)]
    vcpus: Option<u32>,
    /// Memory in MB
    #[arg(long)]
    memory: Option<u32>,
    /// K=V, repeatable: the whole env, what it had replaced
    #[arg(long = "env", short = 'e')]
    envs: Vec<String>,
    /// /guest/path=local/path, repeatable: all the boot files, what it had replaced
    #[arg(long = "file")]
    files: Vec<String>,
    /// A port the image listens on, repeatable: all of them
    #[arg(long = "port", short = 'p')]
    ports: Vec<u16>,
    /// Entrypoint argv, repeatable
    #[arg(long = "entrypoint")]
    entrypoint: Vec<String>,
    /// no, always, on-failure or on-failure:MAX_RETRIES
    #[arg(long, value_parser = restart_arg)]
    restart: Option<api::RestartPolicy>,
    /// A larger volume, in GB: its disk at once, its filesystem at the next start
    #[arg(long)]
    volume_gb: Option<u32>,
    /// The command, after --
    #[arg(last = true)]
    cmd: Vec<String>,
}

impl SetArgs {
    /// The PATCH, checked as the daemon checks it. `size_now` fills the half of the size the
    /// flags leave out.
    fn request(&self, size_now: Option<api::Size>) -> Result<api::UpdateMachineRequest> {
        let size = match (self.vcpus, self.memory, size_now) {
            (None, None, _) => None,
            (Some(vcpus), Some(memory_mb), _) => Some(api::Size { vcpus, memory_mb }),
            (vcpus, memory, Some(now)) => Some(api::Size {
                vcpus: vcpus.unwrap_or(now.vcpus),
                memory_mb: memory.unwrap_or(now.memory_mb),
            }),
            (_, _, None) => bail!("--vcpus or --memory alone needs the machine's size"),
        };
        let spec = api::SpecChange {
            image: self.image.clone(),
            entrypoint: (!self.entrypoint.is_empty()).then(|| self.entrypoint.clone()),
            cmd: (!self.cmd.is_empty()).then(|| self.cmd.clone()),
            env: (!self.envs.is_empty())
                .then(|| env_args(&self.envs))
                .transpose()?,
            files: (!self.files.is_empty())
                .then(|| file_args(&self.files))
                .transpose()?,
            size,
            ports: (!self.ports.is_empty()).then(|| self.ports.clone()),
            restart: self.restart.clone(),
            volume: self.volume_gb.map(|size_gb| api::VolumeSize { size_gb }),
        };
        if spec.is_empty() {
            bail!("name a change: --image, --vcpus, --memory, -e, --file, -p, --entrypoint, --restart, --volume-gb or a command after --");
        }
        if let Err(e) = spec.check() {
            bail!("{e}");
        }
        Ok(api::UpdateMachineRequest {
            spec,
            ..Default::default()
        })
    }
}

#[derive(Subcommand)]
enum BackupCmd {
    /// Delete a backup; --chain also the backups that continue from it
    Rm {
        machine: String,
        backup: String,
        #[arg(long)]
        chain: bool,
        /// The machine's tenant, for a destroyed machine's backup through a fleet
        #[arg(long)]
        tenant: Option<String>,
    },
}

/// A backup schedule on a run: both or neither, checked as the daemon checks them.
#[derive(Args)]
struct BackupArgs {
    /// Back it up this often: 6h, 1d (at least 1h)
    #[arg(long, requires = "backup_keep")]
    backup_every: Option<String>,
    /// Backups kept, with what they continue from
    #[arg(long, requires = "backup_every")]
    backup_keep: Option<u32>,
    /// No schedule, whatever the host's default
    #[arg(long, conflicts_with = "backup_every")]
    no_backup: bool,
}

impl BackupArgs {
    /// The request's `backup`: absent for the host's default.
    fn request(&self) -> Result<Option<Option<api::BackupPolicy>>> {
        if self.no_backup {
            return Ok(Some(None));
        }
        policy(self.backup_every.as_deref(), self.backup_keep)
    }
}

/// `--every` and `--keep` as a policy, checked here before the request leaves.
fn policy(every: Option<&str>, keep: Option<u32>) -> Result<Option<Option<api::BackupPolicy>>> {
    let (Some(every), Some(keep)) = (every, keep) else {
        return Ok(None);
    };
    let p = api::BackupPolicy {
        every: every.to_string(),
        keep,
    };
    if let Err(e) = p.check() {
        bail!("backup.{e}");
    }
    Ok(Some(Some(p)))
}

#[derive(Subcommand)]
enum SnapshotCmd {
    /// Snapshot both disks now; --memory keeps a running machine's memory too
    Create {
        /// A name to find it by again (before-migration)
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        memory: bool,
        id: String,
    },
    /// List a machine's snapshots
    Ls { id: String },
    /// Take the disks back to a snapshot (an id or a name); a running machine boots again
    Restore { id: String, snap: String },
    /// Delete a snapshot (an id or a name)
    Rm { id: String, snap: String },
}

#[derive(Subcommand)]
enum EndpointCmd {
    /// Open a machine's port: briqyard endpoint add ID PORT
    Add {
        /// An HTTP endpoint on the shared listener
        #[arg(long)]
        http: bool,
        /// Host label for an HTTP endpoint
        #[arg(long)]
        host: Option<String>,
        id: String,
        port: u16,
    },
    Ls,
    Rm {
        id: String,
    },
}

#[derive(Subcommand)]
enum TenantCmd {
    Ls,
    /// Show a tenant, its gateway included
    Get {
        id: String,
    },
    Rm {
        id: String,
    },
    /// The tenant's gateway: a machine the daemon runs while a machine sends via:gateway
    #[command(subcommand)]
    Gateway(GatewayCmd),
    /// Release a tenant from its host (fleet): its next machine is placed afresh
    Unpin {
        id: String,
    },
    /// Show the tenant's quota and use; with a limit, put the quota, exactly those limits:
    /// briqyard tenant quota T [--machines N] [--memory-mb N] [--vcpus N] [--disk-gb N]
    Quota {
        id: String,
        #[arg(long)]
        machines: Option<u32>,
        #[arg(long)]
        memory_mb: Option<u32>,
        #[arg(long)]
        vcpus: Option<u32>,
        #[arg(long)]
        disk_gb: Option<u32>,
        /// Through a fleet: where to place a tenant that has no host yet
        #[arg(long)]
        region: Option<String>,
    },
}

#[derive(Subcommand)]
enum GatewayCmd {
    /// Make or replace it: briqyard tenant gateway set TENANT --image I --port P [-e K=V] [--file /path=local] [--start] [-- cmd...]
    Set(Box<GatewaySetArgs>),
    /// Stop and remove it, once no machine runs through it
    Rm { tenant: String },
}

/// What `tenant gateway set` puts.
#[derive(Args)]
struct GatewaySetArgs {
    tenant: String,
    /// Through a fleet: where to place a tenant that has no host yet
    #[arg(long)]
    region: Option<String>,
    /// Start it now and wait for its port (a running one is left as is)
    #[arg(long)]
    start: bool,
    #[arg(long)]
    image: String,
    /// The port its program listens on
    #[arg(long)]
    port: u16,
    /// A start that needs it waits for this probe instead of its port: http:PORT[/PATH], tcp:PORT, exec:CMD ARGS
    #[arg(long, value_parser = probe_arg)]
    readiness: Option<api::Probe>,
    /// K=V, repeatable
    #[arg(long = "env", short = 'e')]
    envs: Vec<String>,
    /// /guest/path=local/path, repeatable
    #[arg(long = "file")]
    files: Vec<String>,
    /// The command, after --
    #[arg(last = true)]
    cmd: Vec<String>,
}

#[derive(Subcommand)]
enum ImageCmd {
    Ls,
    /// Remove an image no machine uses
    Rm {
        key: String,
    },
}

#[derive(Subcommand)]
enum HostCmd {
    Ls,
    /// Add a server bought by hand; the fleet bootstraps it over SSH and pins its keys:
    /// briqyard host add 51.68.1.2 --address 10.42.0.11 --region gra
    Add {
        /// The server's SSH address (its public one)
        ssh: String,
        /// The API's IPv4 address, on the fleet's private network (its vRack address); default: the SSH address
        #[arg(long, default_value = "")]
        address: String,
        #[arg(long, default_value = "")]
        region: String,
        /// The host's id; default: h_ and the address
        #[arg(long, default_value = "")]
        id: String,
        /// Ports its public interface takes besides SSH, comma-separated (an edge's on it:
        /// 80,443,5432,...), or none; default: the fleet's public_tcp_ports
        #[arg(long)]
        public_tcp_ports: Option<String>,
    },
    /// Place no new tenant on a host
    Drain {
        id: String,
    },
    /// Place new tenants on a drained or retiring host again
    Undrain {
        id: String,
    },
    /// Install another release on a host, its machines running: drained, installed, back
    /// once its daemon heartbeats with the new version (ADR 0027)
    Upgrade {
        /// The host; with --all, every ready or draining host, one at a time
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        id: Option<String>,
        #[arg(long)]
        all: bool,
        /// A release URL, or a version of the project's releases (0.2.0)
        #[arg(long)]
        release: String,
    },
    /// Take no new tenant on a host and forget it once nothing runs on it (the server is yours
    /// to give back)
    Retire {
        id: String,
    },
    /// Forget a host (its machines are not touched). A host with a pool key is refused unless
    /// --force: the key leaves the record, kept only for its backups (ADR 0035), and its pool is
    /// unreadable at its next restart
    Rm {
        id: String,
        #[arg(long)]
        force: bool,
    },
}

struct Client {
    base: String,
    token: Option<String>,
    http: reqwest::Client,
}

/// A call's deadline: a create may pull an image for minutes. A watch has none.
const CALL_TIMEOUT: Duration = Duration::from_secs(900);
/// A watch with no line this long is gone: the server sends one every 30 s.
const WATCH_SILENCE: Duration = Duration::from_secs(90);
/// A host upgrade: the bootstrap script's half hour, then the host's return.
const UPGRADE_TIMEOUT: Duration = Duration::from_secs(2400);

impl Client {
    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&impl serde::Serialize>,
    ) -> Result<T> {
        let text = self.raw(method, path, body).await?;
        if text.is_empty() {
            return serde_json::from_str("null").map_err(|_| anyhow!("empty response"));
        }
        Ok(serde_json::from_str(&text)?)
    }

    async fn raw(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&impl serde::Serialize>,
    ) -> Result<String> {
        let resp = self.send(method, path, body, Some(CALL_TIMEOUT)).await?;
        Ok(resp.text().await?)
    }

    /// Sends a request; an answer that is not a success is the error it carries.
    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&impl serde::Serialize>,
        timeout: Option<Duration>,
    ) -> Result<reqwest::Response> {
        let mut req = self.http.request(method, format!("{}{}", self.base, path));
        if let Some(t) = &self.token {
            req = req.bearer_auth(t);
        }
        if let Some(b) = body {
            req = req.json(b);
        }
        if let Some(t) = timeout {
            req = req.timeout(t);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("request {}", self.base))?;
        if resp.status().is_success() {
            return Ok(resp);
        }
        Err(refusal(resp).await)
    }

    /// Every event of a read, page after page, and the cursor after the last.
    async fn events(&self, path: &str, since: Option<String>) -> Result<(Vec<api::Event>, String)> {
        let (mut all, mut cursor) = (Vec::new(), since.unwrap_or_default());
        loop {
            let page: api::EventsPage = self
                .call(reqwest::Method::GET, &with_since(path, &cursor), NONE)
                .await?;
            let full = page.events.len() == api::events_limit(None);
            all.extend(page.events);
            cursor = page.next;
            if !full {
                return Ok((all, cursor));
            }
        }
    }

    /// A watch: each event as it comes, until the server ends it (with the reason, an error).
    async fn watch(&self, path: &str, mut each: impl FnMut(&api::Event)) -> Result<()> {
        self.stream(path, |line| {
            if let Some(e) = watch_line(line)? {
                each(&e);
            }
            Ok(ControlFlow::Continue(()))
        })
        .await
    }

    /// An NDJSON stream (a watch, a logs follow): each line as it comes, until `each` breaks
    /// or fails, or the server ends it.
    async fn stream(
        &self,
        path: &str,
        mut each: impl FnMut(&str) -> Result<ControlFlow<()>>,
    ) -> Result<()> {
        let mut resp = self.send(reqwest::Method::GET, path, NONE, None).await?;
        let mut buf = Vec::new();
        loop {
            let chunk = tokio::time::timeout(WATCH_SILENCE, resp.chunk())
                .await
                .map_err(|_| anyhow!("no word from {} in {WATCH_SILENCE:?}", self.base))??;
            let Some(chunk) = chunk else {
                bail!("the stream ended");
            };
            buf.extend_from_slice(&chunk);
            while let Some(i) = buf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = buf.drain(..=i).collect();
                if each(&String::from_utf8_lossy(&line))?.is_break() {
                    return Ok(());
                }
            }
        }
    }
}

/// The error an answer that is not a success carries: its `ApiError`, else its status and body.
async fn refusal(resp: reqwest::Response) -> anyhow::Error {
    let status = resp.status();
    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return e.into(),
    };
    match serde_json::from_str::<api::ApiError>(&text) {
        Ok(e) if e.request_id.is_empty() => anyhow!("{} ({})", e.error, e.code),
        Ok(e) => anyhow!("{} ({}, request {})", e.error, e.code, e.request_id),
        Err(_) => anyhow!("{status}: {}", text.trim()),
    }
}

/// A line of a logs follow: a console line, a heartbeat (`{}`: nothing), or the end: a
/// destroyed machine ends it (`Break`), anything else is the error that ends it.
fn follow_line(line: &str) -> Result<ControlFlow<String, Option<api::LogLine>>> {
    let v: serde_json::Value =
        serde_json::from_str(line).with_context(|| format!("follow line {:?}", line.trim()))?;
    if v.get("ts").is_some() {
        return Ok(ControlFlow::Continue(Some(serde_json::from_value(v)?)));
    }
    match serde_json::from_value::<api::ApiError>(v) {
        Ok(e) if e.code == "destroyed" => Ok(ControlFlow::Break(e.error)),
        Ok(e) => bail!("{} ({})", e.error, e.code),
        Err(_) => Ok(ControlFlow::Continue(None)),
    }
}

/// `GET /v1/machines` for a tenant or every one, with label selectors.
fn machines_path(tenant: Option<&str>, labels: &[String]) -> String {
    let mut u = reqwest::Url::parse("http://briqyard/v1/machines").expect("a URL");
    {
        let mut q = u.query_pairs_mut();
        if let Some(t) = tenant {
            q.append_pair("tenant", t);
        }
        for l in labels {
            q.append_pair("label", l);
        }
    }
    match u.query() {
        Some(q) if !q.is_empty() => format!("/v1/machines?{q}"),
        _ => "/v1/machines".into(),
    }
}

/// A tenant's PUT route, with where a fleet places a tenant that has no host yet.
fn tenant_put_path(tenant: &str, what: &str, region: Option<&str>) -> String {
    match region {
        Some(r) => format!("/v1/tenants/{tenant}/{what}?region={r}"),
        None => format!("/v1/tenants/{tenant}/{what}"),
    }
}

/// A line of a watch: an event, a heartbeat (`{}`: nothing), or the error that ends it.
fn watch_line(line: &str) -> Result<Option<api::Event>> {
    let v: serde_json::Value =
        serde_json::from_str(line).with_context(|| format!("watch line {:?}", line.trim()))?;
    if v.get("seq").is_some() {
        return Ok(Some(serde_json::from_value(v)?));
    }
    if let Ok(e) = serde_json::from_value::<api::ApiError>(v) {
        bail!("{} ({})", e.error, e.code);
    }
    Ok(None)
}

fn fingerprint_arg(s: &str) -> Result<String, String> {
    api::tls::parse_fingerprint(s)
}

/// The HTTP client: pinned to a daemon's certificate (https only), or the web PKI's.
fn http_client(tls_fingerprint: Option<&str>) -> Result<reqwest::Client> {
    // Each call has its own deadline (`CALL_TIMEOUT`); a watch has none.
    let b = reqwest::Client::builder().connect_timeout(Duration::from_secs(10));
    let b = match tls_fingerprint {
        Some(fp) => b
            .use_preconfigured_tls(api::tls::pinned_client(fp))
            .https_only(true),
        None => b,
    };
    Ok(b.build()?)
}

fn print_json<T: serde::Serialize>(v: &T) {
    println!("{}", serde_json::to_string_pretty(v).unwrap());
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let http = match http_client(cli.tls_fingerprint.as_deref()) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(1);
        }
    };
    let c = Client {
        base: cli.url.trim_end_matches('/').to_string(),
        token: cli.token.clone(),
        http,
    };
    if let Err(e) = run(&c, cli.cmd).await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

const NONE: Option<&()> = None;

async fn run(c: &Client, cmd: Cmd) -> Result<()> {
    use reqwest::Method;
    const GET: Method = Method::GET;
    const POST: Method = Method::POST;
    const PUT: Method = Method::PUT;
    const DELETE: Method = Method::DELETE;
    match cmd {
        Cmd::Status => print_json(&c.call::<api::Status>(GET, "/v1/status", NONE).await?),
        Cmd::Openapi => print!("{}", c.raw(GET, "/v1/openapi.yaml", NONE).await?),
        Cmd::Machine(m) => match *m {
            MachineCmd::Ls { tenant, labels } => {
                let path = machines_path(tenant.as_deref(), &labels);
                let ms: Vec<api::Machine> = c.call(GET, &path, NONE).await?;
                print!("{}", machine_table(&ms));
            }
            MachineCmd::Run(a) => {
                let name = a.name.clone().unwrap_or_else(|| {
                    let base = a.image.rsplit('/').next().unwrap_or(&a.image);
                    let base = base.split([':', '@']).next().unwrap_or(base);
                    format!("{base}-{}", suffix())
                });
                let env = env_args(&a.envs)?;
                let files = file_args(&a.files)?;
                let volume = match &a.volume {
                    Some(v) => {
                        let (size, mount) = v.split_once(':').ok_or_else(|| {
                            anyhow!("--volume {v:?}: want SIZE:MOUNT, like 10G:/data")
                        })?;
                        let gb: u32 = size
                            .trim_end_matches("GB")
                            .trim_end_matches('G')
                            .parse()
                            .map_err(|_| anyhow!("--volume {v:?}: bad size"))?;
                        Some(api::VolumeSpec {
                            size_gb: gb,
                            mount: mount.to_string(),
                        })
                    }
                    None => None,
                };
                let req = api::CreateMachineRequest {
                    tenant: a.tenant.clone(),
                    name,
                    image: a.image.clone(),
                    entrypoint: if a.entrypoint.is_empty() {
                        None
                    } else {
                        Some(a.entrypoint.clone())
                    },
                    cmd: if a.cmd.is_empty() {
                        None
                    } else {
                        Some(a.cmd.clone())
                    },
                    env,
                    files,
                    size: api::Size {
                        vcpus: a.vcpus,
                        memory_mb: a.memory,
                    },
                    volume,
                    ports: a.ports.clone(),
                    sleep: a.sleep.clone(),
                    restart: None,
                    metadata: label_args(&a.labels)?,
                    region: a.region.clone(),
                    egress: a.egress.clone(),
                    limits: a.limits.request()?,
                    disk_limits: a.disk.request()?,
                    backup: a.backup.request()?,
                    probes: Some(api::Probes {
                        startup: a.startup.clone(),
                        readiness: a.readiness.clone(),
                        liveness: a.liveness.clone(),
                    })
                    .filter(|p| !p.is_empty()),
                    start: if a.no_start { Some(false) } else { None },
                    fork: None,
                    restore: None,
                };
                let m: api::Machine = c.call(POST, "/v1/machines", Some(&req)).await?;
                print_json(&m);
                if m.state == api::state::ERROR {
                    bail!("{}", m.error);
                }
            }
            MachineCmd::Get { id } => print_json(
                &c.call::<api::Machine>(GET, &format!("/v1/machines/{id}"), NONE)
                    .await?,
            ),
            MachineCmd::Describe { id } => {
                let m: api::Machine = c.call(GET, &format!("/v1/machines/{id}"), NONE).await?;
                // By its tenant: through a fleet, that is the machine's host.
                let path = events_path(Some(&m.tenant), Some(&m.id), false);
                let (mut evs, _) = c.events(&path, None).await?;
                let keep = evs.len().saturating_sub(20);
                print!("{}", describe(&m, &evs.split_off(keep)));
            }
            MachineCmd::Start { id } => print_json(
                &c.call::<api::Machine>(POST, &format!("/v1/machines/{id}/start"), NONE)
                    .await?,
            ),
            MachineCmd::Stop { suspend, id } => {
                let req = api::StopRequest {
                    suspend,
                    timeout_sec: 0,
                };
                print_json(
                    &c.call::<api::Machine>(POST, &format!("/v1/machines/{id}/stop"), Some(&req))
                        .await?,
                )
            }
            MachineCmd::Restart { id } => print_json(
                &c.call::<api::Machine>(POST, &format!("/v1/machines/{id}/restart"), NONE)
                    .await?,
            ),
            MachineCmd::Wake { id } => print_json(
                &c.call::<api::Machine>(POST, &format!("/v1/machines/{id}/wake"), NONE)
                    .await?,
            ),
            MachineCmd::Touch { id } => {
                c.raw(POST, &format!("/v1/machines/{id}/touch"), NONE)
                    .await?;
            }
            MachineCmd::Wait { until, id } => print_json(
                &c.call::<api::Machine>(
                    POST,
                    &format!("/v1/machines/{id}/wait?timeout=120&for={until}"),
                    NONE,
                )
                .await?,
            ),
            MachineCmd::Rm { id } => {
                c.raw(DELETE, &format!("/v1/machines/{id}"), NONE).await?;
            }
            MachineCmd::Exec {
                no_wake,
                timeout,
                interactive,
                tty,
                id,
                cmd,
            } => {
                // 0 is the daemon's default: 5 minutes for a command, none for a session.
                let timeout_ms = timeout.map_or(0, |t| t.as_millis() as u64);
                if interactive || tty {
                    let req = api::session::ExecSession {
                        cmd,
                        wake: !no_wake,
                        timeout_ms,
                        tty,
                        ..Default::default()
                    };
                    let code = session::run(c, &id, req, interactive).await?;
                    if code != 0 {
                        std::process::exit(code);
                    }
                    return Ok(());
                }
                let req = api::ExecRequest {
                    cmd,
                    wake: !no_wake,
                    timeout_ms,
                    ..Default::default()
                };
                let res: api::ExecResult = c
                    .call(POST, &format!("/v1/machines/{id}/exec"), Some(&req))
                    .await?;
                print!("{}", res.stdout);
                eprint!("{}", res.stderr);
                std::io::stdout().flush()?;
                if res.timed_out {
                    eprintln!("(timed out)");
                }
                if res.exit_code != 0 {
                    std::process::exit(res.exit_code);
                }
            }
            MachineCmd::Logs {
                since,
                limit,
                follow,
                id,
            } => {
                let since = since.unwrap_or_default();
                let print =
                    |l: &api::LogLine| println!("{} {}", l.ts.format("%H:%M:%S%.3f"), l.line);
                if follow {
                    let path = format!("/v1/machines/{id}/logs?since={since}&follow=true");
                    c.stream(&path, |line| match follow_line(line)? {
                        ControlFlow::Continue(l) => {
                            l.iter().for_each(print);
                            Ok(ControlFlow::Continue(()))
                        }
                        ControlFlow::Break(why) => {
                            eprintln!("({why})");
                            Ok(ControlFlow::Break(()))
                        }
                    })
                    .await?;
                } else {
                    let res: api::LogsResponse = c
                        .call(
                            GET,
                            &format!("/v1/machines/{id}/logs?since={since}&limit={limit}"),
                            NONE,
                        )
                        .await?;
                    res.lines.iter().for_each(print);
                    if !res.next.is_empty() {
                        eprintln!("(next: --since {})", res.next);
                    }
                }
            }
            MachineCmd::Fork { name, id } => {
                let src: api::Machine = c.call(GET, &format!("/v1/machines/{id}"), NONE).await?;
                let req = api::CreateMachineRequest {
                    tenant: src.tenant.clone(),
                    name: name.unwrap_or_else(|| format!("{}-fork", src.name)),
                    size: src.size,
                    ports: src.ports.clone(),
                    sleep: src.sleep.clone(),
                    metadata: src.metadata.clone(),
                    egress: Some(src.egress.clone()),
                    limits: Some(src.limits.clone()),
                    disk_limits: Some(src.disk_limits.clone()),
                    fork: Some(api::ForkSpec {
                        machine_id: id,
                        copy: String::new(),
                    }),
                    ..Default::default()
                };
                print_json(
                    &c.call::<api::Machine>(POST, "/v1/machines", Some(&req))
                        .await?,
                );
            }
            MachineCmd::Put {
                id,
                local,
                guest_path,
            } => {
                let data = std::fs::read(&local).with_context(|| local.clone())?;
                let req = api::PutFileRequest {
                    path: guest_path,
                    base64: api::guest::base64_encode(&data),
                    mode: None,
                };
                c.raw(PUT, &format!("/v1/machines/{id}/files"), Some(&req))
                    .await?;
            }
            MachineCmd::GetFile { id, guest_path } => {
                let res: api::FileResponse = c
                    .call(
                        GET,
                        &format!("/v1/machines/{id}/files?path={guest_path}"),
                        NONE,
                    )
                    .await?;
                let data = api::guest::base64_decode(&res.base64).map_err(|e| anyhow!(e))?;
                std::io::stdout().write_all(&data)?;
            }
            MachineCmd::Set(a) => {
                let half = a.vcpus.is_some() != a.memory.is_some();
                let size_now = match half {
                    true => {
                        let m: api::Machine =
                            c.call(GET, &format!("/v1/machines/{}", a.id), NONE).await?;
                        Some(m.pending.and_then(|p| p.size).unwrap_or(m.size))
                    }
                    false => None,
                };
                let req = a.request(size_now)?;
                print_json(
                    &c.call::<api::Machine>(
                        reqwest::Method::PATCH,
                        &format!("/v1/machines/{}", a.id),
                        Some(&req),
                    )
                    .await?,
                )
            }
            MachineCmd::SetSleep { id, sleep } => {
                let req = api::UpdateMachineRequest {
                    sleep: Some(sleep),
                    ..Default::default()
                };
                print_json(
                    &c.call::<api::Machine>(
                        reqwest::Method::PATCH,
                        &format!("/v1/machines/{id}"),
                        Some(&req),
                    )
                    .await?,
                )
            }
            MachineCmd::SetBackup {
                id,
                every,
                keep,
                off,
            } => {
                let req = api::UpdateMachineRequest {
                    backup: match off {
                        true => Some(None),
                        false => policy(every.as_deref(), keep)?,
                    },
                    ..Default::default()
                };
                print_json(
                    &c.call::<api::Machine>(
                        reqwest::Method::PATCH,
                        &format!("/v1/machines/{id}"),
                        Some(&req),
                    )
                    .await?,
                )
            }
            MachineCmd::SetEgress { id, egress } => {
                let req = api::UpdateMachineRequest {
                    egress: Some(egress),
                    ..Default::default()
                };
                print_json(
                    &c.call::<api::Machine>(
                        reqwest::Method::PATCH,
                        &format!("/v1/machines/{id}"),
                        Some(&req),
                    )
                    .await?,
                )
            }
            MachineCmd::SetDiskLimits { id, limits } => {
                let Some(limits) = limits.request()? else {
                    bail!("name a limit: --disk-bw, --disk-iops or --disk-burst");
                };
                let req = api::UpdateMachineRequest {
                    disk_limits: Some(limits),
                    ..Default::default()
                };
                print_json(
                    &c.call::<api::Machine>(
                        reqwest::Method::PATCH,
                        &format!("/v1/machines/{id}"),
                        Some(&req),
                    )
                    .await?,
                )
            }
            MachineCmd::SetLimits { id, limits } => {
                let Some(limits) = limits.request()? else {
                    bail!("name a limit: --block-port, --conn-per-min or --bandwidth");
                };
                let req = api::UpdateMachineRequest {
                    limits: Some(limits),
                    ..Default::default()
                };
                print_json(
                    &c.call::<api::Machine>(
                        reqwest::Method::PATCH,
                        &format!("/v1/machines/{id}"),
                        Some(&req),
                    )
                    .await?,
                )
            }
            MachineCmd::Backup { id } => print_json(
                &c.call::<api::Backup>(POST, &format!("/v1/machines/{id}/backups"), NONE)
                    .await?,
            ),
            MachineCmd::Backups { id } => print_json(
                &c.call::<Vec<api::Backup>>(GET, &format!("/v1/machines/{id}/backups"), NONE)
                    .await?,
            ),
            MachineCmd::Restore {
                from,
                backup,
                tenant,
                name,
                sleep,
            } => {
                let req = api::CreateMachineRequest {
                    tenant,
                    name,
                    sleep,
                    restore: Some(api::RestoreSpec {
                        machine_id: from,
                        backup,
                    }),
                    ..Default::default()
                };
                print_json(
                    &c.call::<api::Machine>(POST, "/v1/machines", Some(&req))
                        .await?,
                )
            }
            MachineCmd::Stats { id } => print_json(
                &c.call::<api::MachineStats>(GET, &format!("/v1/machines/{id}/stats"), NONE)
                    .await?,
            ),
            MachineCmd::Snapshot(s) => match s {
                SnapshotCmd::Create { name, memory, id } => {
                    let req = api::SnapshotRequest { name, memory };
                    print_json(
                        &c.call::<api::Snapshot>(
                            POST,
                            &format!("/v1/machines/{id}/snapshots"),
                            Some(&req),
                        )
                        .await?,
                    )
                }
                SnapshotCmd::Ls { id } => {
                    let path = format!("/v1/machines/{id}/snapshots");
                    let ss: Vec<api::Snapshot> = c.call(GET, &path, NONE).await?;
                    print!("{}", snapshot_table(&ss));
                }
                SnapshotCmd::Restore { id, snap } => print_json(
                    &c.call::<api::Machine>(
                        POST,
                        &format!("/v1/machines/{id}/snapshots/{snap}/restore"),
                        NONE,
                    )
                    .await?,
                ),
                SnapshotCmd::Rm { id, snap } => {
                    c.raw(DELETE, &format!("/v1/machines/{id}/snapshots/{snap}"), NONE)
                        .await?;
                }
            },
        },
        Cmd::Endpoint(e) => match e {
            EndpointCmd::Add {
                http,
                host,
                id,
                port,
            } => {
                let req = api::CreateEndpointRequest {
                    port,
                    protocol: if http { "http".into() } else { String::new() },
                    host: host.unwrap_or_default(),
                };
                print_json(
                    &c.call::<api::Endpoint>(
                        POST,
                        &format!("/v1/machines/{id}/endpoints"),
                        Some(&req),
                    )
                    .await?,
                );
            }
            EndpointCmd::Ls => {
                let eps: Vec<api::Endpoint> = c.call(GET, "/v1/endpoints", NONE).await?;
                print!("{}", endpoint_table(&eps));
            }
            EndpointCmd::Rm { id } => {
                c.raw(DELETE, &format!("/v1/endpoints/{id}"), NONE).await?;
            }
        },
        Cmd::Tenant(t) => match t {
            TenantCmd::Ls => {
                print_json(&c.call::<Vec<api::Tenant>>(GET, "/v1/tenants", NONE).await?)
            }
            TenantCmd::Get { id } => print_json(
                &c.call::<api::Tenant>(GET, &format!("/v1/tenants/{id}"), NONE)
                    .await?,
            ),
            TenantCmd::Rm { id } => {
                c.raw(DELETE, &format!("/v1/tenants/{id}"), NONE).await?;
            }
            TenantCmd::Gateway(GatewayCmd::Set(a)) => {
                let GatewaySetArgs {
                    tenant,
                    region,
                    start,
                    image,
                    port,
                    readiness,
                    envs,
                    files,
                    cmd,
                } = *a;
                let spec = api::GatewaySpec {
                    image,
                    cmd: if cmd.is_empty() { None } else { Some(cmd) },
                    env: env_args(&envs)?,
                    files: file_args(&files)?,
                    port,
                    probes: api::Probes {
                        readiness,
                        ..Default::default()
                    },
                    start,
                    ..Default::default()
                };
                print_json(
                    &c.call::<api::Tenant>(
                        PUT,
                        &tenant_put_path(&tenant, "gateway", region.as_deref()),
                        Some(&spec),
                    )
                    .await?,
                )
            }
            TenantCmd::Gateway(GatewayCmd::Rm { tenant }) => {
                c.raw(DELETE, &format!("/v1/tenants/{tenant}/gateway"), NONE)
                    .await?;
            }
            TenantCmd::Unpin { id } => {
                c.raw(POST, &format!("/v1/tenants/{id}/unpin"), NONE)
                    .await?;
            }
            TenantCmd::Quota {
                id,
                machines,
                memory_mb,
                vcpus,
                disk_gb,
                region,
            } => {
                let q = api::Quota {
                    machines,
                    memory_mb,
                    vcpus,
                    disk_gb,
                };
                let shown: api::TenantQuota = if q == api::Quota::default() {
                    c.call(GET, &format!("/v1/tenants/{id}/quota"), NONE)
                        .await?
                } else {
                    let path = tenant_put_path(&id, "quota", region.as_deref());
                    c.call(PUT, &path, Some(&q)).await?
                };
                print_json(&shown)
            }
        },
        Cmd::Backup(BackupCmd::Rm {
            machine,
            backup,
            chain,
            tenant,
        }) => {
            c.raw(
                DELETE,
                &backup_rm_path(&machine, &backup, chain, tenant.as_deref()),
                NONE,
            )
            .await?;
        }
        Cmd::Backups { tenant } => {
            let path = match tenant {
                Some(t) => format!("/v1/backups?tenant={t}"),
                None => "/v1/backups".into(),
            };
            print_json(&c.call::<Vec<api::Backup>>(GET, &path, NONE).await?)
        }
        Cmd::Doctor => doctor(),
        Cmd::Events {
            tenant,
            machine,
            since,
            watch,
        } => {
            let path = events_path(tenant.as_deref(), machine.as_deref(), watch);
            print!("{}", events_table(&[]));
            if watch {
                let path = with_since(&path, since.as_deref().unwrap_or(""));
                c.watch(&path, |e| print!("{}", event_row(e))).await?;
            } else {
                let (evs, next) = c.events(&path, since).await?;
                for e in &evs {
                    print!("{}", event_row(e));
                }
                eprintln!("(next: --since {next})");
            }
        }
        Cmd::Top { tenant, json } => {
            let path = match &tenant {
                Some(t) => format!("/v1/top?tenant={t}"),
                None => "/v1/top".into(),
            };
            let ms: Vec<api::TopMachine> = c.call(GET, &path, NONE).await?;
            if json {
                print_json(&ms);
            } else {
                print!("{}", top_table(ms));
            }
        }
        Cmd::Usage {
            from,
            to,
            tenant,
            json,
        } => {
            let bs: Vec<api::UsageBucket> = c
                .call(GET, &usage_path(from, to, tenant.as_deref()), NONE)
                .await?;
            if json {
                print_json(&bs);
            } else {
                print!("{}", usage_table(&bs));
            }
        }
        Cmd::Image(i) => match i {
            ImageCmd::Ls => {
                let ims: Vec<api::Image> = c.call(GET, "/v1/images", NONE).await?;
                print!("{}", image_table(&ims));
            }
            ImageCmd::Rm { key } => {
                c.raw(DELETE, &format!("/v1/images/{key}"), NONE).await?;
            }
        },
        Cmd::Host(h) => match h {
            HostCmd::Ls => {
                let hs: Vec<api::Host> = c.call(GET, "/v1/hosts", NONE).await?;
                let st: api::Status = c.call(GET, "/v1/status", NONE).await?;
                print!("{}", host_table(&hs));
                print!("{}", region_table(&st.regions));
            }
            HostCmd::Add {
                ssh,
                address,
                region,
                id,
                public_tcp_ports,
            } => {
                let req = api::AddHostRequest {
                    ssh,
                    address,
                    region,
                    id,
                    public_tcp_ports: public_tcp_ports.as_deref().map(port_list).transpose()?,
                };
                print_json(&c.call::<api::Host>(POST, "/v1/hosts", Some(&req)).await?)
            }
            HostCmd::Drain { id } => {
                c.raw(POST, &format!("/v1/hosts/{id}/drain"), NONE).await?;
            }
            HostCmd::Undrain { id } => {
                c.raw(POST, &format!("/v1/hosts/{id}/undrain"), NONE)
                    .await?;
            }
            HostCmd::Upgrade { id, all, release } => {
                let ids = match (id, all) {
                    (Some(id), _) => vec![id],
                    (None, _) => {
                        let hs: Vec<api::Host> = c.call(GET, "/v1/hosts", NONE).await?;
                        let (ids, skipped) = upgrade_order(&hs);
                        for (id, state) in skipped {
                            eprintln!("{id}: {state}, not upgraded");
                        }
                        ids
                    }
                };
                let req = api::UpgradeHostRequest { release };
                for (i, id) in ids.iter().enumerate() {
                    eprintln!("{id}: upgrading");
                    let path = format!("/v1/hosts/{id}/upgrade");
                    match c.send(POST, &path, Some(&req), Some(UPGRADE_TIMEOUT)).await {
                        Ok(resp) => {
                            let h: api::Host = resp.json().await?;
                            println!("{id}: {}", h.note);
                        }
                        Err(e) => {
                            let left = &ids[i + 1..];
                            match left.is_empty() {
                                true => bail!("{id}: {e:#}"),
                                false => bail!("{id}: {e:#}; not upgraded: {}", left.join(", ")),
                            }
                        }
                    }
                }
            }
            HostCmd::Retire { id } => print_json(
                &c.call::<api::Host>(POST, &format!("/v1/hosts/{id}/retire"), NONE)
                    .await?,
            ),
            HostCmd::Rm { id, force } => {
                let q = if force { "?force=true" } else { "" };
                c.raw(DELETE, &format!("/v1/hosts/{id}{q}"), NONE).await?;
                if force {
                    eprintln!("host {id} forgotten: a pool key it held went with its record, and its pool is unreadable at its next restart");
                }
            }
        },
    }
    Ok(())
}

/// `backup rm`'s request.
fn backup_rm_path(machine: &str, backup: &str, chain: bool, tenant: Option<&str>) -> String {
    let mut q = Vec::new();
    if chain {
        q.push("chain=true".to_string());
    }
    if let Some(t) = tenant {
        q.push(format!("tenant={t}"));
    }
    let path = format!("/v1/machines/{machine}/backups/{backup}");
    match q.is_empty() {
        true => path,
        false => format!("{path}?{}", q.join("&")),
    }
}

/// `-e K=V` flags as an env map; a value may hold `=`.
fn env_args(kvs: &[String]) -> Result<BTreeMap<String, String>> {
    let mut env = BTreeMap::new();
    for kv in kvs {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| anyhow!("--env {kv:?}: want K=V"))?;
        env.insert(k.to_string(), v.to_string());
    }
    Ok(env)
}

/// `--label K=V`: metadata that `machine ls -l` selects on, so checked as a label is.
fn label_args(kvs: &[String]) -> Result<BTreeMap<String, String>> {
    kvs.iter()
        .map(|kv| match api::Label::parse(kv) {
            Ok(api::Label {
                key,
                value: Some(v),
            }) => Ok((key, v)),
            Ok(_) => bail!("--label {kv:?}: want K=V"),
            Err(e) => bail!("--label: {e}"),
        })
        .collect()
}

/// `--file /guest/path=local/path` flags as boot files, read now.
fn file_args(specs: &[String]) -> Result<Vec<api::File>> {
    let mut files = Vec::new();
    for f in specs {
        let (guest_path, local) = f
            .split_once('=')
            .ok_or_else(|| anyhow!("--file {f:?}: want /guest/path=local/path"))?;
        let data = std::fs::read(local).with_context(|| local.to_string())?;
        files.push(api::File {
            path: guest_path.to_string(),
            base64: api::guest::base64_encode(&data),
            mode: None,
        });
    }
    Ok(files)
}

/// A restart policy, Docker's way: `no`, `always`, `on-failure`, `on-failure:N` (3 retries
/// when no N is given, as the API's default).
fn restart_arg(s: &str) -> Result<api::RestartPolicy, String> {
    let (policy, retries) = match s.split_once(':') {
        Some(("on-failure", n)) => (
            "on-failure",
            n.parse()
                .map_err(|_| format!("{s:?}: want on-failure:MAX_RETRIES"))?,
        ),
        Some(_) => return Err(format!("{s:?}: only on-failure takes :MAX_RETRIES")),
        None => (s, api::RestartPolicy::default().max_retries),
    };
    if !["no", "on-failure", "always"].contains(&policy) {
        return Err(format!(
            "{s:?}: want no, always, on-failure or on-failure:N"
        ));
    }
    Ok(api::RestartPolicy {
        policy: policy.into(),
        max_retries: retries,
    })
}

/// A sleep window as the daemon reads it, refused here before the request leaves.
fn sleep_arg(s: &str) -> Result<String, String> {
    api::parse_sleep(s)?;
    Ok(s.to_string())
}

/// A probe with the API's timings: `http:PORT[/PATH]`, `tcp:PORT` or `exec:CMD ARGS` (the
/// command split on spaces), checked as the daemon checks it.
fn probe_arg(s: &str) -> Result<api::Probe, String> {
    let bad = || format!("{s:?}: want http:PORT[/PATH], tcp:PORT or exec:CMD ARGS");
    let port = |p: &str| p.parse::<u16>().map_err(|_| bad());
    let mut p = api::Probe::default();
    match s.split_once(':').ok_or_else(bad)? {
        ("exec", cmd) => p.exec = Some(cmd.split_whitespace().map(String::from).collect()),
        ("tcp", at) => p.tcp = Some(port(at)?),
        ("http", at) => {
            let (at, path) = match at.find('/') {
                Some(i) => at.split_at(i),
                None => (at, "/"),
            };
            p.http = Some(api::HttpProbe {
                port: port(at)?,
                path: path.into(),
            });
        }
        _ => return Err(bad()),
    }
    p.check("probe", false)?;
    Ok(p)
}

/// An egress policy, `open`, `none` or `via:MACHINE_ID` (`via:gateway`), checked as the daemon
/// checks it.
fn egress_arg(s: &str) -> Result<api::Egress, String> {
    let e = match s.split_once(':') {
        Some((api::egress::VIA, id)) => api::Egress {
            mode: api::egress::VIA.into(),
            via: Some(id.into()),
        },
        _ => api::Egress {
            mode: s.into(),
            via: None,
        },
    };
    e.check()?;
    Ok(e)
}

/// A moment in RFC 3339, as UTC; whether it is on the hour is the server's to say.
fn hour_arg(s: &str) -> Result<chrono::DateTime<chrono::Utc>, String> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&chrono::Utc))
        .map_err(|_| format!("{s:?}: want RFC 3339, like 2026-10-20T14:00:00Z"))
}

/// `GET /v1/usage` for a range, in UTC so the query needs no escaping.
fn usage_path(
    from: chrono::DateTime<chrono::Utc>,
    to: chrono::DateTime<chrono::Utc>,
    tenant: Option<&str>,
) -> String {
    let utc = |t: chrono::DateTime<chrono::Utc>| t.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let mut p = format!("/v1/usage?from={}&to={}", utc(from), utc(to));
    if let Some(t) = tenant {
        p.push_str(&format!("&tenant={t}"));
    }
    p
}

/// `GET /v1/events` for a tenant, a machine, both or neither.
fn events_path(tenant: Option<&str>, machine: Option<&str>, watch: bool) -> String {
    let mut q = Vec::new();
    if let Some(t) = tenant {
        q.push(format!("tenant={t}"));
    }
    if let Some(m) = machine {
        q.push(format!("machine={m}"));
    }
    if watch {
        q.push("watch=true".into());
    }
    match q.is_empty() {
        true => "/v1/events".into(),
        false => format!("/v1/events?{}", q.join("&")),
    }
}

/// A path with `since` added; none when the cursor is empty.
fn with_since(path: &str, since: &str) -> String {
    match (since.is_empty(), path.contains('?')) {
        (true, _) => path.into(),
        (false, true) => format!("{path}&since={since}"),
        (false, false) => format!("{path}?since={since}"),
    }
}

/// An egress policy as `egress_arg` reads it.
fn egress_label(e: &api::Egress) -> String {
    match &e.via {
        Some(id) => format!("{}:{id}", e.mode),
        None => e.mode.clone(),
    }
}

/// The limits in force, short: the blocked ports, the rate, the cap (`25,465 600/min
/// 100Mbit`); `-` when nothing is limited.
fn limits_label(l: &api::EgressLimits) -> String {
    let mut parts = Vec::new();
    let ports = l.blocked_ports.as_deref().unwrap_or_default();
    if !ports.is_empty() {
        let ports: Vec<String> = ports.iter().map(u16::to_string).collect();
        parts.push(ports.join(","));
    }
    if let Some(n) = l.new_connections_per_minute.filter(|n| *n > 0) {
        parts.push(format!("{n}/min"));
    }
    if let Some(n) = l.bandwidth_mbit.filter(|n| *n > 0) {
        parts.push(format!("{n}Mbit"));
    }
    if parts.is_empty() {
        "-".into()
    } else {
        parts.join(" ")
    }
}

/// The disk limits in force, short: `32MB/s 4000io` (the burst in `describe`); `-` when
/// nothing is limited.
fn disk_label(l: &api::DiskLimits) -> String {
    let mut parts = Vec::new();
    if let Some(n) = l.bandwidth_mb.filter(|n| *n > 0) {
        parts.push(format!("{n}MB/s"));
    }
    if let Some(n) = l.iops.filter(|n| *n > 0) {
        parts.push(format!("{n}io"));
    }
    if parts.is_empty() {
        "-".into()
    } else {
        parts.join(" ")
    }
}

/// A backup schedule in a table: `6h/4` (every, keep), `-` for none.
fn backup_label(p: Option<&api::BackupPolicy>) -> String {
    match p {
        Some(p) => format!("{}/{}", p.every, p.keep),
        None => "-".into(),
    }
}

// --- tables ---

/// `machine ls`.
fn machine_table(ms: &[api::Machine]) -> String {
    let mut out = format!(
        "{:<16} {:<10} {:<14} {:<24} {:<18} {:<5} {:<12} {:<9} {:<6} {:<18} {:<24} {:<16} {:<8} {:<12} HOST\n",
        "ID",
        "TENANT",
        "NAME",
        "IMAGE",
        "STATE",
        "READY",
        "IP",
        "SIZE",
        "SLEEP",
        "EGRESS",
        "LIMITS",
        "DISK",
        "BACKUP",
        "PENDING"
    );
    for m in ms {
        let state = if m.stopped_reason.is_empty() {
            m.state.clone()
        } else {
            format!("{} ({})", m.state, m.stopped_reason)
        };
        let pending = match &m.pending {
            Some(p) => p.fields.join(","),
            None => "-".into(),
        };
        out.push_str(&format!(
            "{:<16} {:<10} {:<14} {:<24} {:<18} {:<5} {:<12} {:<9} {:<6} {:<18} {:<24} {:<16} {:<8} {:<12} {}\n",
            m.id,
            m.tenant,
            m.name,
            m.image,
            state,
            if m.ready { "yes" } else { "no" },
            m.ip,
            format!("{}c/{}M", m.size.vcpus, m.size.memory_mb),
            m.sleep,
            egress_label(&m.egress),
            limits_label(&m.limits),
            disk_label(&m.disk_limits),
            backup_label(m.backup.as_ref()),
            pending,
            m.host
        ));
    }
    out
}

/// `machine snapshot ls`.
fn snapshot_table(ss: &[api::Snapshot]) -> String {
    let mut out = format!(
        "{:<16} {:<20} {:<21} {:<10} MEMORY\n",
        "ID", "NAME", "CREATED", "DISKS"
    );
    for s in ss {
        out.push_str(&format!(
            "{:<16} {:<20} {:<21} {:<10} {}\n",
            s.id,
            s.name.as_deref().unwrap_or("-"),
            s.created_at.format("%Y-%m-%d %H:%M:%S"),
            s.disks.join(","),
            if s.memory { "yes" } else { "no" }
        ));
    }
    out
}

/// `endpoint ls`.
fn endpoint_table(eps: &[api::Endpoint]) -> String {
    let mut out = format!(
        "{:<18} {:<16} {:<6} {:<9} ADDRESS\n",
        "ID", "MACHINE", "PORT", "PROTOCOL"
    );
    for e in eps {
        out.push_str(&format!(
            "{:<18} {:<16} {:<6} {:<9} {}\n",
            e.id, e.machine_id, e.port, e.protocol, e.address
        ));
    }
    out
}

/// `image ls`.
fn image_table(ims: &[api::Image]) -> String {
    let mut out = format!(
        "{:<22} {:<40} {:<9} {:<21} DIGEST\n",
        "KEY", "REF", "MACHINES", "BUILT"
    );
    for i in ims {
        out.push_str(&format!(
            "{:<22} {:<40} {:<9} {:<21} {}\n",
            i.key,
            i.reference,
            i.machines,
            i.built_at.format("%Y-%m-%d %H:%M:%S"),
            &i.digest[..i.digest.len().min(19)]
        ));
    }
    out
}

/// `--public-tcp-ports`: `80,443,5432`, or `none` for no port.
fn port_list(s: &str) -> Result<Vec<u16>> {
    if s == "none" {
        return Ok(vec![]);
    }
    s.split(',')
        .map(|p| {
            p.trim()
                .parse::<u16>()
                .ok()
                .filter(|&p| p > 0)
                .ok_or_else(|| {
                    anyhow!("--public-tcp-ports {s:?}: want ports, comma-separated, or none")
                })
        })
        .collect()
}

/// What `host upgrade --all` upgrades, in order: the ready and draining hosts by id; and the
/// others, with their state, which it leaves.
fn upgrade_order(hs: &[api::Host]) -> (Vec<String>, Vec<(String, String)>) {
    let mut hs: Vec<&api::Host> = hs.iter().collect();
    hs.sort_by(|a, b| a.id.cmp(&b.id));
    let (up, left): (Vec<&api::Host>, Vec<&api::Host>) = hs
        .into_iter()
        .partition(|h| matches!(h.state.as_str(), "ready" | "draining"));
    (
        up.into_iter().map(|h| h.id.clone()).collect(),
        left.into_iter()
            .map(|h| (h.id.clone(), h.state.clone()))
            .collect(),
    )
}

/// `host ls`: a line per host, and under it its SSH address when it is not the API's, its pin,
/// each condition that is true and its note when the bootstrap or an upgrade left one.
fn host_table(hs: &[api::Host]) -> String {
    let mut out = format!(
        "{:<16} {:<28} {:<12} {:<8} {:<14} {:<10} {:<9} {:<8} {:<20} LAST SEEN\n",
        "ID", "URL", "STATE", "REGION", "MEMORY MB", "VCPUS", "MACHINES", "TENANTS", "VERSION"
    );
    for h in hs {
        out.push_str(&format!(
            "{:<16} {:<28} {:<12} {:<8} {:<14} {:<10} {:<9} {:<8} {:<20} {}\n",
            h.id,
            if h.url.is_empty() { "-" } else { &h.url },
            h.state,
            if h.region.is_empty() { "-" } else { &h.region },
            format!("{}/{}", h.used.memory_mb, h.capacity.memory_mb),
            format!("{}/{}", h.used.vcpus, h.capacity.vcpus),
            h.machines,
            h.tenants.len(),
            if h.version.is_empty() {
                "-"
            } else {
                &h.version
            },
            h.last_seen.to_rfc3339()
        ));
        if !h.ssh.is_empty() {
            out.push_str(&format!("{:<16} ssh: {}\n", "", h.ssh));
        }
        if !h.tls_fingerprint.is_empty() {
            out.push_str(&format!("{:<16} tls: {}\n", "", h.tls_fingerprint));
        }
        if !h.public_tcp_ports.is_empty() {
            let ports: Vec<String> = h.public_tcp_ports.iter().map(u16::to_string).collect();
            out.push_str(&format!("{:<16} public tcp: {}\n", "", ports.join(",")));
        }
        for c in h.conditions.iter().filter(|c| c.status) {
            out.push_str(&format!(
                "{:<16} {} since {}: {}\n",
                "",
                c.kind,
                c.since.format("%Y-%m-%d %H:%M:%S"),
                c.message
            ));
        }
        if !h.note.is_empty() {
            out.push_str(&format!("{:<16} note: {}\n", "", h.note));
        }
    }
    out
}

/// `host ls`'s summary: each region's room and the creates refused for want of it (ADR 0042).
/// A region no host is in has refusals only: `-` for its room.
fn region_table(rs: &[api::RegionRoom]) -> String {
    let room = |r: Option<api::Room>| match r {
        Some(r) => format!("{}/{}", r.memory_mb, r.disk_mb),
        None => "-".into(),
    };
    if rs.is_empty() {
        return String::new();
    }
    let mut out = format!(
        "\n{:<8} {:<20} {:<20} UNSCHEDULABLE MEM/DISK/PRESSURE\n",
        "REGION", "FREE MB MEM/DISK", "LARGEST MB MEM/DISK"
    );
    for r in rs {
        let u = r.unschedulable;
        out.push_str(&format!(
            "{:<8} {:<20} {:<20} {}/{}/{}\n",
            if r.region.is_empty() { "-" } else { &r.region },
            room(r.free),
            room(r.largest_slot),
            u.memory,
            u.disk,
            u.pressure
        ));
    }
    out
}

/// `usage`: a line per machine and hour. Disk is the allocated root and volume; `--json` has
/// every measure.
fn usage_table(bs: &[api::UsageBucket]) -> String {
    let mut out = format!(
        "{:<17} {:<16} {:<10} {:>7} {:>8} {:>9} {:>10} {:>12} {:>21} {:>21} HOST\n",
        "HOUR",
        "MACHINE",
        "TENANT",
        "RUN H",
        "CPU S",
        "MEM GB·H",
        "DISK GB·H",
        "BACKUP GB·H",
        "INTERNET OUT/IN",
        "INGRESS OUT/IN"
    );
    for b in bs {
        let u = &b.usage;
        out.push_str(&format!(
            "{:<17} {:<16} {:<10} {:>7.2} {:>8.1} {:>9.2} {:>10.2} {:>12.2} {:>21} {:>21} {}\n",
            b.hour.format("%Y-%m-%d %H:00"),
            b.machine_id,
            b.tenant,
            u.running_seconds / 3600.0,
            u.cpu_seconds,
            u.memory_mb_seconds / 1024.0 / 3600.0,
            u.root_gb_hours + u.volume_gb_hours,
            u.backup_gb_hours,
            format!("{}/{}", u.internet_out_bytes, u.internet_in_bytes),
            format!("{}/{}", u.ingress_out_bytes, u.ingress_in_bytes),
            b.host
        ));
    }
    out
}

/// `top`: the busiest first. Memory is used/limit in MB, disk in MB, network in KB/s.
fn top_table(mut ms: Vec<api::TopMachine>) -> String {
    ms.sort_by(|a, b| {
        b.cpu_percent
            .total_cmp(&a.cpu_percent)
            .then_with(|| (&a.tenant, &a.name).cmp(&(&b.tenant, &b.name)))
    });
    let mb = |b: u64| b >> 20;
    let kb = |r: f64| r / 1024.0;
    let mut out = format!(
        "{:<16} {:<10} {:<14} {:>6} {:>13} {:>9} {:>17} {:>17} HOST\n",
        "MACHINE",
        "TENANT",
        "NAME",
        "CPU %",
        "MEMORY MB",
        "DISK MB",
        "INTERNET IN/OUT",
        "INGRESS IN/OUT"
    );
    for m in &ms {
        out.push_str(&format!(
            "{:<16} {:<10} {:<14} {:>6.1} {:>13} {:>9} {:>17} {:>17} {}\n",
            m.machine_id,
            m.tenant,
            m.name,
            m.cpu_percent,
            format!("{}/{}", mb(m.memory_bytes), mb(m.memory_limit_bytes)),
            mb(m.disk_used_bytes),
            format!(
                "{:.1}/{:.1}",
                kb(m.internet_in_bytes_per_sec),
                kb(m.internet_out_bytes_per_sec)
            ),
            format!(
                "{:.1}/{:.1}",
                kb(m.ingress_in_bytes_per_sec),
                kb(m.ingress_out_bytes_per_sec)
            ),
            m.host
        ));
    }
    out
}

/// `events`: the header, then `event_row` per event.
fn events_table(evs: &[api::Event]) -> String {
    let mut out = format!(
        "{:<19}  {:<7}  {:<15}  {:<14}  MESSAGE\n",
        "TIME", "TYPE", "REASON", "MACHINE"
    );
    for e in evs {
        out.push_str(&event_row(e));
    }
    out
}

fn event_row(e: &api::Event) -> String {
    format!(
        "{:<19}  {:<7}  {:<15}  {:<14}  {}\n",
        e.at.format("%Y-%m-%d %H:%M:%S"),
        e.kind,
        e.reason,
        if e.machine_id.is_empty() {
            "-"
        } else {
            &e.machine_id
        },
        e.message
    )
}

/// `machine describe`: the machine as `kubectl describe` shows a pod, then its events.
fn describe(m: &api::Machine, evs: &[api::Event]) -> String {
    let mut lines: Vec<(&str, String)> = vec![
        ("Name", m.name.clone()),
        ("ID", m.id.clone()),
        ("Tenant", m.tenant.clone()),
    ];
    if !m.host.is_empty() {
        lines.push(("Host", m.host.clone()));
    }
    lines.push(("Image", m.image.clone()));
    lines.push(("State", m.state.clone()));
    lines.push(("Ready", if m.ready { "yes" } else { "no" }.into()));
    if !m.stopped_reason.is_empty() {
        lines.push(("Reason", m.stopped_reason.clone()));
    }
    if let Some(x) = &m.exit {
        let mut exit = format!("code {} at {}", x.code, x.at.format("%Y-%m-%d %H:%M:%S"));
        if x.oom_killed {
            exit.push_str(", out of memory");
        }
        if x.restarting {
            exit.push_str(", restarting");
        }
        lines.push(("Exit", exit));
    }
    if m.restarts > 0 || m.restarting_at.is_some() {
        let mut restarts = m.restarts.to_string();
        if let Some(t) = m.restarting_at {
            restarts.push_str(&format!(", next at {}", t.format("%Y-%m-%d %H:%M:%S")));
        }
        lines.push(("Restarts", restarts));
    }
    if !m.error.is_empty() {
        lines.push(("Error", m.error.clone()));
    }
    let probes: Vec<String> = [
        ("startup", &m.probes.startup, &m.probes_status.startup),
        ("readiness", &m.probes.readiness, &m.probes_status.readiness),
        ("liveness", &m.probes.liveness, &m.probes_status.liveness),
    ]
    .into_iter()
    .filter_map(|(name, p, st)| p.as_ref().map(|p| probe_line(name, p, st.as_ref())))
    .collect();
    if !probes.is_empty() {
        lines.push(("Probes", probes.join(&format!("\n{:15}", ""))));
    }
    lines.push(("IP", m.ip.clone()));
    lines.push((
        "Size",
        format!("{} vCPU, {} MB", m.size.vcpus, m.size.memory_mb),
    ));
    if let Some(v) = &m.volume {
        lines.push(("Volume", format!("{} GB at {}", v.size_gb, v.mount)));
    }
    let d = &m.disk_limits;
    let disk = match disk_label(d).as_str() {
        "-" => "none".to_string(),
        l => format!("{l} each, {}s burst", d.burst_sec.unwrap_or(0)),
    };
    lines.push(("Disk limits", disk));
    lines.push(("Egress", egress_label(&m.egress)));
    // What runs it (ADR 0027): the init its root disk carries, the VMM of its last boot.
    if !m.init_version.is_empty() || !m.vmm_version.is_empty() {
        let or_unknown = |v: &str| {
            if v.is_empty() {
                "unknown".to_string()
            } else {
                v.to_string()
            }
        };
        lines.push((
            "Runs on",
            format!(
                "init {}, vmm {}",
                or_unknown(&m.init_version),
                or_unknown(&m.vmm_version)
            ),
        ));
    }
    let endpoints: Vec<String> = m
        .endpoints
        .iter()
        .map(|e| format!("{} {} {} -> {}", e.id, e.protocol, e.port, e.address))
        .collect();
    lines.push((
        "Endpoints",
        match endpoints.is_empty() {
            true => "none".into(),
            false => endpoints.join(&format!("\n{:15}", "")),
        },
    ));
    let sleep = match m.sleeps_at {
        Some(t) => format!("{}, sleeps at {}", m.sleep, t.format("%Y-%m-%d %H:%M:%S")),
        None => m.sleep.clone(),
    };
    lines.push(("Sleep", sleep));
    let at = |t: Option<chrono::DateTime<chrono::Utc>>| match t {
        Some(t) => t.format("%Y-%m-%d %H:%M:%S").to_string(),
        None => "none".into(),
    };
    let backup = match (&m.backup, m.last_backup_at) {
        (Some(p), last) => format!(
            "every {}, keep {}; last {}, next {}",
            p.every,
            p.keep,
            at(last),
            at(m.next_backup_at)
        ),
        (None, Some(last)) => format!("none; last {}", at(Some(last))),
        (None, None) => "none".into(),
    };
    lines.push(("Backup", backup));
    if let Some(p) = &m.pending {
        // Each field, with its new value when the view shows one.
        let changes: Vec<String> = p
            .fields
            .iter()
            .map(|f| match (f.as_str(), &p.image, p.size, p.volume) {
                ("image", Some(image), _, _) => format!("image {image}"),
                ("size", _, Some(s), _) => format!("size {} vCPU, {} MB", s.vcpus, s.memory_mb),
                ("volume", _, _, Some(v)) => format!("volume's filesystem to {} GB", v.size_gb),
                _ => f.clone(),
            })
            .collect();
        let mut pending = format!("{}, at the next start", changes.join(", "));
        if let Some(t) = m.pending_since {
            pending.push_str(&format!(" (since {})", t.format("%Y-%m-%d %H:%M:%S")));
        }
        lines.push(("Pending", pending));
    }
    lines.push(("Version", m.version.to_string()));
    lines.push((
        "Created",
        m.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
    ));
    let mut out = String::new();
    for (k, v) in lines {
        out.push_str(&format!("{:<15}{v}\n", format!("{k}:")));
    }
    out.push_str("Events:\n");
    if evs.is_empty() {
        out.push_str("  none\n");
    }
    for e in evs {
        out.push_str(&format!(
            "  {}  {:<7}  {:<15}  {}\n",
            e.at.format("%Y-%m-%d %H:%M:%S"),
            e.kind,
            e.reason,
            e.message
        ));
    }
    out
}

/// A probe as `describe` shows it: what it checks, how often, and its last result.
fn probe_line(name: &str, p: &api::Probe, st: Option<&api::ProbeStatus>) -> String {
    let last = match st {
        None => "not run yet".to_string(),
        Some(s) if s.passed => format!("passed ({})", s.message),
        Some(s) => format!("failed {} in a row ({})", s.failures, s.message),
    };
    format!("{name} {}, every {} s: {last}", p.target(), p.period_sec)
}

/// What a host needs, checked where this runs; prints one line per check.
fn doctor() {
    let mut bad = 0;
    let mut check = |name: &str, ok: bool, hint: &str| {
        println!(
            "{} {name}{}",
            if ok { "ok  " } else { "MISS" },
            if ok {
                String::new()
            } else {
                format!(": {hint}")
            }
        );
        if !ok {
            bad += 1;
        }
    };
    check(
        "linux",
        cfg!(target_os = "linux"),
        "briqyardd runs on Linux",
    );
    check(
        "/dev/kvm",
        std::path::Path::new("/dev/kvm").exists(),
        "no KVM: a bare-metal server, or a VM with nested virtualization",
    );
    let exists = |p: &str| std::path::Path::new(p).exists();
    let on_path = |b: &str| {
        std::env::var("PATH")
            .unwrap_or_default()
            .split(':')
            .any(|d| std::path::Path::new(d).join(b).exists())
    };
    // `zvol_id` names a zvol's device: the daemon checks every disk with it (ADR 0046).
    check(
        "zfs",
        on_path("zfs") && on_path("zpool") && exists("/usr/lib/udev/zvol_id"),
        "apt install zfsutils-linux",
    );
    check("nft", on_path("nft"), "apt install nftables");
    check("mkfs.ext4", on_path("mkfs.ext4"), "apt install e2fsprogs");
    check("ip", on_path("ip"), "apt install iproute2");
    check(
        "firecracker",
        exists("/usr/local/bin/firecracker"),
        "hack/bootstrap-host.sh downloads it",
    );
    check(
        "jailer",
        exists("/usr/local/bin/jailer"),
        "hack/bootstrap-host.sh downloads it; without it machines run as root",
    );
    check(
        "guest kernel",
        exists("/var/lib/briqyard/vmlinux"),
        "hack/bootstrap-host.sh downloads one",
    );
    check(
        "briqyard-init",
        exists("/usr/local/bin/briqyard-init"),
        "make init; install the static binary",
    );
    check(
        "cgroup v2",
        exists("/sys/fs/cgroup/cgroup.controllers"),
        "the jailer needs the unified cgroup hierarchy",
    );
    check(
        "ip_forward",
        std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .map(|s| s.trim() == "1")
            .unwrap_or(false),
        "the daemon turns it on at start",
    );
    let pool = std::process::Command::new("zpool")
        .args(["list", "-H", "-o", "name"])
        .output();
    let (pool_ok, pool_hint) = match &pool {
        Ok(o) if o.status.success() => (
            !String::from_utf8_lossy(&o.stdout).trim().is_empty(),
            "zpool create byard <device>",
        ),
        Ok(_) => (
            true,
            "zpool needs root to answer: `sudo briqyard doctor` checks the pool",
        ),
        Err(_) => (false, "apt install zfsutils-linux"),
    };
    check("a zfs pool", pool_ok, pool_hint);
    if bad > 0 {
        eprintln!("{bad} missing");
        std::process::exit(1);
    }
}

fn suffix() -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:04}", n % 10000)
}

#[cfg(test)]
mod tests;

/// A test binary ends with its parent, and in bounded time (briqyard-testing).
#[cfg(test)]
#[ctor::ctor(unsafe)]
fn exit_with_parent() {
    briqyard_testing::exit_with_parent();
}
