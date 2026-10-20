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
    Run(RunArgs),
    /// Show a machine
    Get {
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
    /// Change the sleep window: briqyard machine set-sleep ID 30m|never
    SetSleep {
        id: String,
        #[arg(value_parser = sleep_arg)]
        sleep: String,
    },
    /// Change where its traffic may go, at once: briqyard machine set-egress ID open|none|via:MACHINE_ID
    SetEgress {
        id: String,
        #[arg(value_parser = egress_arg)]
        egress: api::Egress,
    },
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
    /// Where its traffic may go: open (default), none (its tenant only), via:MACHINE_ID
    #[arg(long, value_parser = egress_arg)]
    egress: Option<api::Egress>,
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
    Rm {
        id: String,
    },
    /// Release a tenant from its host (fleet): its next machine is placed afresh
    Unpin {
        id: String,
    },
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
        let mut req = self.http.request(method, format!("{}{}", self.base, path));
        if let Some(t) = &self.token {
            req = req.bearer_auth(t);
        }
        if let Some(b) = body {
            req = req.json(b);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("request {}", self.base))?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            if let Ok(e) = serde_json::from_str::<api::ApiError>(&text) {
                if e.request_id.is_empty() {
                    bail!("{} ({})", e.error, e.code);
                }
                bail!("{} ({}, request {})", e.error, e.code, e.request_id);
            }
            bail!("{status}: {}", text.trim());
        }
        Ok(text)
    }
}

fn print_json<T: serde::Serialize>(v: &T) {
    println!("{}", serde_json::to_string_pretty(v).unwrap());
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let c = Client {
        base: cli.url.trim_end_matches('/').to_string(),
        token: cli.token.clone(),
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(900))
            .build()
            .unwrap(),
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
                let mut env = BTreeMap::new();
                for kv in &a.envs {
                    let (k, v) = kv
                        .split_once('=')
                        .ok_or_else(|| anyhow!("--env {kv:?}: want K=V"))?;
                    env.insert(k.to_string(), v.to_string());
                }
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
            TenantCmd::Rm { id } => {
                c.raw(DELETE, &format!("/v1/tenants/{id}"), NONE).await?;
            }
            TenantCmd::Unpin { id } => {
                c.raw(POST, &format!("/v1/tenants/{id}/unpin"), NONE)
                    .await?;
            }
        },
        Cmd::Doctor => doctor(),
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

/// A sleep window as the daemon reads it, refused here before the request leaves.
fn sleep_arg(s: &str) -> Result<String, String> {
    api::parse_sleep(s)?;
    Ok(s.to_string())
}

/// An egress policy, `open`, `none` or `via:MACHINE_ID`, checked as the daemon checks it.
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

/// An egress policy as `egress_arg` reads it.
fn egress_label(e: &api::Egress) -> String {
    match &e.via {
        Some(id) => format!("{}:{id}", e.mode),
        None => e.mode.clone(),
    }
}

// --- tables ---

/// `machine ls`.
fn machine_table(ms: &[api::Machine]) -> String {
    let mut out = format!(
        "{:<16} {:<10} {:<14} {:<24} {:<18} {:<12} {:<9} {:<6} {:<18} HOST\n",
        "ID", "TENANT", "NAME", "IMAGE", "STATE", "IP", "SIZE", "SLEEP", "EGRESS"
    );
    for m in ms {
        let state = if m.stopped_reason.is_empty() {
            m.state.clone()
        } else {
            format!("{} ({})", m.state, m.stopped_reason)
        };
        out.push_str(&format!(
            "{:<16} {:<10} {:<14} {:<24} {:<18} {:<12} {:<9} {:<6} {:<18} {}\n",
            m.id,
            m.tenant,
            m.name,
            m.image,
            state,
            m.ip,
            format!("{}c/{}M", m.size.vcpus, m.size.memory_mb),
            m.sleep,
            egress_label(&m.egress),
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
        if !h.note.is_empty() {
            out.push_str(&format!("{:<16} note: {}\n", "", h.note));
        }
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
