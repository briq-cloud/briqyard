//! briqyard is the CLI: it talks to a briqyardd or a briqyard-fleet over HTTP.

use anyhow::{anyhow, bail, Context, Result};
use briqyard_api as api;
use clap::{Args, Parser, Subcommand};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::time::Duration;

#[derive(Parser)]
#[command(name = "briqyard", version, about = "Machines in Firecracker microVMs")]
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
    /// Check this machine as a briqyard host: KVM, ZFS, nftables, Firecracker, the kernel
    Doctor,
}

#[derive(Subcommand)]
enum MachineCmd {
    /// List machines
    Ls {
        #[arg(long)]
        tenant: Option<String>,
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
    Wake {
        id: String,
    },
    Touch {
        id: String,
    },
    /// Wait until running
    Wait {
        id: String,
    },
    /// Destroy a machine and its disks
    #[command(alias = "destroy")]
    Rm {
        id: String,
    },
    /// Run a command inside: briqyard machine exec ID -- cmd... (wakes a sleeping machine)
    Exec {
        /// Fail when the machine is not running instead of waking it
        #[arg(long)]
        no_wake: bool,
        #[arg(long, default_value = "5m")]
        timeout: humantime::Duration,
        /// Send stdin to the command
        #[arg(long)]
        stdin: bool,
        id: String,
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// The serial console
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

#[derive(Args)]
struct RunArgs {
    #[arg(long)]
    image: String,
    /// A DNS label; made from the image when absent
    #[arg(long)]
    name: Option<String>,
    #[arg(long, default_value = "default")]
    tenant: String,
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
    backup: BackupArgs,
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
    /// Snapshot both disks now
    Create { id: String },
    /// List a machine's snapshots
    Ls { id: String },
    /// Remove a snapshot
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
}

#[derive(Subcommand)]
enum GatewayCmd {
    /// Make or replace it: briqyard tenant gateway set TENANT --image I --port P [-e K=V] [--start] [-- cmd...]
    Set {
        tenant: String,
        /// Start it now and wait for its port (a running one is left as is)
        #[arg(long)]
        start: bool,
        #[arg(long)]
        image: String,
        /// The port its program listens on
        #[arg(long)]
        port: u16,
        /// K=V, repeatable
        #[arg(long = "env", short = 'e')]
        envs: Vec<String>,
        /// The command, after --
        #[arg(last = true)]
        cmd: Vec<String>,
    },
    /// Stop and remove it, once no machine runs through it
    Rm { tenant: String },
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
    /// Order a host from the fleet's provisioner now (dry-run unless the fleet says otherwise)
    Order {
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// Place no new tenant on a host
    Drain {
        id: String,
    },
    /// Drain a host and release it at its provider once nothing runs on it
    Retire {
        id: String,
    },
    /// Forget a host (its machines are not touched)
    Rm {
        id: String,
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
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let text = resp.text().await?;
        if let Ok(e) = serde_json::from_str::<api::ApiError>(&text) {
            if e.request_id.is_empty() {
                bail!("{} ({})", e.error, e.code);
            }
            bail!("{} ({}, request {})", e.error, e.code, e.request_id);
        }
        bail!("{status}: {}", text.trim());
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
        let mut resp = self.send(reqwest::Method::GET, path, NONE, None).await?;
        let mut buf = Vec::new();
        loop {
            let chunk = tokio::time::timeout(WATCH_SILENCE, resp.chunk())
                .await
                .map_err(|_| anyhow!("no word from {} in {WATCH_SILENCE:?}", self.base))??;
            let Some(chunk) = chunk else {
                bail!("the watch ended");
            };
            buf.extend_from_slice(&chunk);
            while let Some(i) = buf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = buf.drain(..=i).collect();
                if let Some(e) = watch_line(&String::from_utf8_lossy(&line))? {
                    each(&e);
                }
            }
        }
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
            MachineCmd::Ls { tenant } => {
                let path = match tenant {
                    Some(t) => format!("/v1/machines?tenant={t}"),
                    None => "/v1/machines".into(),
                };
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
                let mut files = Vec::new();
                for f in &a.files {
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
                    metadata: BTreeMap::new(),
                    egress: a.egress.clone(),
                    limits: a.limits.request()?,
                    backup: a.backup.request()?,
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
            MachineCmd::Wake { id } => print_json(
                &c.call::<api::Machine>(POST, &format!("/v1/machines/{id}/wake"), NONE)
                    .await?,
            ),
            MachineCmd::Touch { id } => {
                c.raw(POST, &format!("/v1/machines/{id}/touch"), NONE)
                    .await?;
            }
            MachineCmd::Wait { id } => print_json(
                &c.call::<api::Machine>(POST, &format!("/v1/machines/{id}/wait?timeout=120"), NONE)
                    .await?,
            ),
            MachineCmd::Rm { id } => {
                c.raw(DELETE, &format!("/v1/machines/{id}"), NONE).await?;
            }
            MachineCmd::Exec {
                no_wake,
                timeout,
                stdin,
                id,
                cmd,
            } => {
                let mut req = api::ExecRequest {
                    cmd,
                    wake: !no_wake,
                    timeout_ms: timeout.as_millis() as u64,
                    ..Default::default()
                };
                if stdin {
                    let mut s = String::new();
                    std::io::stdin().read_to_string(&mut s)?;
                    req.stdin = s;
                }
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
                let mut cursor = since.unwrap_or_default();
                loop {
                    let res: api::LogsResponse = c
                        .call(
                            GET,
                            &format!("/v1/machines/{id}/logs?since={cursor}&limit={limit}"),
                            NONE,
                        )
                        .await?;
                    for l in &res.lines {
                        println!("{} {}", l.ts.format("%H:%M:%S%.3f"), l.line);
                    }
                    if !follow {
                        if !res.next.is_empty() {
                            eprintln!("(next: --since {})", res.next);
                        }
                        break;
                    }
                    if !res.next.is_empty() {
                        cursor = res.next;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
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
                SnapshotCmd::Create { id } => print_json(
                    &c.call::<api::Snapshot>(POST, &format!("/v1/machines/{id}/snapshots"), NONE)
                        .await?,
                ),
                SnapshotCmd::Ls { id } => print_json(
                    &c.call::<Vec<api::Snapshot>>(
                        GET,
                        &format!("/v1/machines/{id}/snapshots"),
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
            TenantCmd::Gateway(GatewayCmd::Set {
                tenant,
                start,
                image,
                port,
                envs,
                cmd,
            }) => {
                let spec = api::GatewaySpec {
                    image,
                    cmd: if cmd.is_empty() { None } else { Some(cmd) },
                    env: env_args(&envs)?,
                    port,
                    start,
                    ..Default::default()
                };
                print_json(
                    &c.call::<api::Tenant>(
                        PUT,
                        &format!("/v1/tenants/{tenant}/gateway"),
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
                print!("{}", host_table(&hs));
            }
            HostCmd::Order { reason } => {
                let req = api::OrderHostRequest { reason };
                print_json(
                    &c.call::<api::Host>(POST, "/v1/hosts/order", Some(&req))
                        .await?,
                )
            }
            HostCmd::Drain { id } => {
                c.raw(POST, &format!("/v1/hosts/{id}/drain"), NONE).await?;
            }
            HostCmd::Retire { id } => print_json(
                &c.call::<api::Host>(POST, &format!("/v1/hosts/{id}/retire"), NONE)
                    .await?,
            ),
            HostCmd::Rm { id } => {
                c.raw(DELETE, &format!("/v1/hosts/{id}"), NONE).await?;
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

/// A sleep window as the daemon reads it, refused here before the request leaves.
fn sleep_arg(s: &str) -> Result<String, String> {
    api::parse_sleep(s)?;
    Ok(s.to_string())
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
        "{:<16} {:<10} {:<14} {:<24} {:<18} {:<12} {:<9} {:<6} {:<18} {:<24} {:<8} HOST\n",
        "ID",
        "TENANT",
        "NAME",
        "IMAGE",
        "STATE",
        "IP",
        "SIZE",
        "SLEEP",
        "EGRESS",
        "LIMITS",
        "BACKUP"
    );
    for m in ms {
        let state = if m.stopped_reason.is_empty() {
            m.state.clone()
        } else {
            format!("{} ({})", m.state, m.stopped_reason)
        };
        out.push_str(&format!(
            "{:<16} {:<10} {:<14} {:<24} {:<18} {:<12} {:<9} {:<6} {:<18} {:<24} {:<8} {}\n",
            m.id,
            m.tenant,
            m.name,
            m.image,
            state,
            m.ip,
            format!("{}c/{}M", m.size.vcpus, m.size.memory_mb),
            m.sleep,
            egress_label(&m.egress),
            limits_label(&m.limits),
            backup_label(m.backup.as_ref()),
            m.host
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

/// `host ls`: a line per host, and its note under it when the provisioner or the bootstrap
/// left one.
fn host_table(hs: &[api::Host]) -> String {
    let mut out = format!(
        "{:<16} {:<28} {:<12} {:<14} {:<10} {:<9} {:<8} LAST SEEN\n",
        "ID", "URL", "STATE", "MEMORY MB", "VCPUS", "MACHINES", "TENANTS"
    );
    for h in hs {
        out.push_str(&format!(
            "{:<16} {:<28} {:<12} {:<14} {:<10} {:<9} {:<8} {}\n",
            h.id,
            if h.url.is_empty() { "-" } else { &h.url },
            h.state,
            format!("{}/{}", h.used.memory_mb, h.capacity.memory_mb),
            format!("{}/{}", h.used.vcpus, h.capacity.vcpus),
            h.machines,
            h.tenants.len(),
            h.last_seen.to_rfc3339()
        ));
        if !h.tls_fingerprint.is_empty() {
            out.push_str(&format!("{:<16} tls: {}\n", "", h.tls_fingerprint));
        }
        if !h.note.is_empty() {
            out.push_str(&format!("{:<16} note: {}\n", "", h.note));
        }
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
    if !m.error.is_empty() {
        lines.push(("Error", m.error.clone()));
    }
    lines.push(("IP", m.ip.clone()));
    lines.push((
        "Size",
        format!("{} vCPU, {} MB", m.size.vcpus, m.size.memory_mb),
    ));
    if let Some(v) = &m.volume {
        lines.push(("Volume", format!("{} GB at {}", v.size_gb, v.mount)));
    }
    lines.push(("Egress", egress_label(&m.egress)));
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
    check(
        "zfs",
        on_path("zfs") && on_path("zpool"),
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
