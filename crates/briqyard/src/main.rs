//! briqyard is the CLI: it talks to a briqyardd or a briqyard-fleet over HTTP.

use anyhow::{anyhow, bail, Context, Result};
use briqyard_api as api;
use clap::{Args, Parser, Subcommand};
use std::collections::BTreeMap;
use std::io::Write;
use std::ops::ControlFlow;
use std::time::Duration;

mod client;
mod doctor;
mod helpers;
mod run;
mod session;
mod tables;

use client::*;
use doctor::*;
use helpers::*;
use run::*;
use tables::*;

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
    /// Namespaces: one private network each
    #[command(subcommand, alias = "tenant")]
    Namespace(NamespaceCmd),
    /// Images built on the host
    #[command(subcommand)]
    Image(ImageCmd),
    /// Hosts, when talking to a fleet
    #[command(subcommand)]
    Host(HostCmd),
    /// Backups in the store: delete one
    #[command(subcommand)]
    Backup(BackupCmd),
    /// Every backup of the host's machines, destroyed ones' included: briqyard backups [--namespace NAME] [--machine ID]
    Backups {
        #[arg(long, alias = "tenant")]
        namespace: Option<String>,
        #[arg(long)]
        machine: Option<String>,
    },
    /// What each machine used, per hour: briqyard usage --from 2026-10-20T14:00:00Z --to 2026-10-20T15:00:00Z
    Usage {
        /// The first hour, RFC 3339
        #[arg(long, value_parser = hour_arg)]
        from: chrono::DateTime<chrono::Utc>,
        /// The hour after the last (at most 31 days after --from)
        #[arg(long, value_parser = hour_arg)]
        to: chrono::DateTime<chrono::Utc>,
        #[arg(long, alias = "tenant")]
        namespace: Option<String>,
        /// Every field, as JSON
        #[arg(long)]
        json: bool,
    },
    /// What happened, oldest first: briqyard events [--namespace NAME] [--machine ID] [--since CURSOR] [--watch]
    Events {
        #[arg(long, alias = "tenant")]
        namespace: Option<String>,
        #[arg(long)]
        machine: Option<String>,
        /// Read on from a previous read's cursor (printed at the end)
        #[arg(long)]
        since: Option<String>,
        /// Stay connected and print each new event
        #[arg(long)]
        watch: bool,
    },
    /// Running machines by CPU, over the daemon's last 15 s: briqyard top [--namespace NAME]
    Top {
        #[arg(long, alias = "tenant")]
        namespace: Option<String>,
        /// Every field, as JSON
        #[arg(long)]
        json: bool,
    },
    /// Check this machine as a briqyard host: KVM, ZFS, nftables, Firecracker, the kernel
    Doctor,
}

#[derive(Subcommand)]
enum MachineCmd {
    /// List machines: briqyard machine ls [--namespace NAME] [-l app=web] [-l tier]
    Ls {
        #[arg(long, alias = "tenant")]
        namespace: Option<String>,
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
    /// A new machine from a snapshot of this one, taken now: briqyard machine fork ID [--name N] [--namespace T]
    Fork {
        #[arg(long)]
        name: Option<String>,
        /// The namespace the copy joins: this machine's by default (made when it does not exist)
        #[arg(long)]
        namespace: Option<String>,
        id: String,
    },
    /// Put the machine in another namespace: briqyard machine move ID --namespace T. Alone in its
    /// namespace and into a new one: the namespace is renamed, nothing restarts. Into one that
    /// exists: the machine restarts on its network, with a new address. Through a fleet, into
    /// a namespace on another host: refused (not supported yet)
    Move {
        #[arg(long)]
        namespace: String,
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
    /// A new machine from a backup: briqyard machine restore --from MACHINE_ID [--backup ID] --namespace T --name N
    Restore {
        #[arg(long)]
        from: String,
        #[arg(long, default_value = "latest")]
        backup: String,
        #[arg(long, alias = "tenant")]
        namespace: String,
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
    #[arg(long, alias = "tenant", default_value = "default")]
    namespace: String,
    /// Through a fleet: place a new namespace on a host of this region
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
    /// Where its traffic may go: open (default), none (its namespace only), via:MACHINE_ID, via:gateway (the namespace's)
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
    /// Answer once the machine is recorded (`creating`), without waiting for its image and boot
    #[arg(long)]
    detach: bool,
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
        /// The machine's namespace, for a destroyed machine's backup through a fleet
        #[arg(long, alias = "tenant")]
        namespace: Option<String>,
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
enum NamespaceCmd {
    Ls,
    /// Show a namespace, its gateway included
    Get {
        id: String,
    },
    Rm {
        id: String,
    },
    /// The namespace's gateway: a machine the daemon runs while a machine sends via:gateway
    #[command(subcommand)]
    Gateway(GatewayCmd),
    /// Release a namespace from its host (fleet): its next machine is placed afresh
    Unpin {
        id: String,
    },
    /// Show the namespace's quota and use; with a limit, put the quota, exactly those limits:
    /// briqyard namespace quota T [--machines N] [--memory-mb N] [--vcpus N] [--disk-gb N]
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
        /// Through a fleet: where to place a namespace that has no host yet
        #[arg(long)]
        region: Option<String>,
    },
}

#[derive(Subcommand)]
enum GatewayCmd {
    /// Make or replace it: briqyard namespace gateway set NAMESPACE --image I --port P [-e K=V] [--file /path=local] [--start] [-- cmd...]
    Set(Box<GatewaySetArgs>),
    /// Stop and remove it, once no machine runs through it
    Rm { namespace: String },
}

/// What `namespace gateway set` puts.
#[derive(Args)]
struct GatewaySetArgs {
    namespace: String,
    /// Through a fleet: where to place a namespace that has no host yet
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
    /// Place no new namespace on a host
    Drain {
        id: String,
    },
    /// Place new namespaces on a drained or retiring host again
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
    /// Take no new namespace on a host and forget it once nothing runs on it (the server is yours
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

#[cfg(test)]
mod tests;

/// A test binary ends with its parent, and in bounded time (briqyard-testing).
#[cfg(test)]
#[ctor::ctor(unsafe)]
fn exit_with_parent() {
    briqyard_testing::exit_with_parent();
}
