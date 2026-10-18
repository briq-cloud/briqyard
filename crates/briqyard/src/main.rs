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
    Machine(MachineCmd),
    /// Endpoints: ways in from outside
    #[command(subcommand, alias = "ep")]
    Endpoint(EndpointCmd),
    /// Tenants: one private network each
    #[command(subcommand)]
    Tenant(TenantCmd),
    /// Hosts, when talking to a fleet
    #[command(subcommand)]
    Host(HostCmd),
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
    /// Run a command inside: briqyard machine exec ID -- cmd...
    Exec {
        #[arg(long)]
        wake: bool,
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
    /// Snapshot both disks
    Snapshot {
        id: String,
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
    #[arg(long, default_value = "")]
    sleep: String,
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
    Rm { id: String },
}

#[derive(Subcommand)]
enum HostCmd {
    Ls,
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
        Cmd::Machine(m) => match m {
            MachineCmd::Ls { tenant } => {
                let path = match tenant {
                    Some(t) => format!("/v1/machines?tenant={t}"),
                    None => "/v1/machines".into(),
                };
                let ms: Vec<api::Machine> = c.call(GET, &path, NONE).await?;
                println!(
                    "{:<16} {:<10} {:<14} {:<24} {:<18} {:<12} {:<9} {:<6} HOST",
                    "ID", "TENANT", "NAME", "IMAGE", "STATE", "IP", "SIZE", "SLEEP"
                );
                for m in ms {
                    let state = if m.stopped_reason.is_empty() {
                        m.state.clone()
                    } else {
                        format!("{} ({})", m.state, m.stopped_reason)
                    };
                    println!(
                        "{:<16} {:<10} {:<14} {:<24} {:<18} {:<12} {:<9} {:<6} {}",
                        m.id,
                        m.tenant,
                        m.name,
                        m.image,
                        state,
                        m.ip,
                        format!("{}c/{}M", m.size.vcpus, m.size.memory_mb),
                        m.sleep,
                        m.host
                    );
                }
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
                    start: if a.no_start { Some(false) } else { None },
                    fork: None,
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
                wake,
                timeout,
                stdin,
                id,
                cmd,
            } => {
                let mut req = api::ExecRequest {
                    cmd,
                    wake,
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
            MachineCmd::Snapshot { id } => print_json(
                &c.call::<api::Snapshot>(POST, &format!("/v1/machines/{id}/snapshots"), NONE)
                    .await?,
            ),
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
                println!(
                    "{:<18} {:<16} {:<6} {:<9} ADDRESS",
                    "ID", "MACHINE", "PORT", "PROTOCOL"
                );
                for e in eps {
                    println!(
                        "{:<18} {:<16} {:<6} {:<9} {}",
                        e.id, e.machine_id, e.port, e.protocol, e.address
                    );
                }
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
        },
        Cmd::Host(h) => match h {
            HostCmd::Ls => {
                let hs: Vec<api::Host> = c.call(GET, "/v1/hosts", NONE).await?;
                println!(
                    "{:<16} {:<28} {:<12} {:<14} {:<10} {:<9} {:<8} LAST SEEN",
                    "ID", "URL", "STATE", "MEMORY MB", "VCPUS", "MACHINES", "TENANTS"
                );
                for h in hs {
                    println!(
                        "{:<16} {:<28} {:<12} {:<14} {:<10} {:<9} {:<8} {}",
                        h.id,
                        h.url,
                        h.state,
                        format!("{}/{}", h.used.memory_mb, h.capacity.memory_mb),
                        format!("{}/{}", h.used.vcpus, h.capacity.vcpus),
                        h.machines,
                        h.tenants.len(),
                        h.last_seen.to_rfc3339()
                    );
                }
            }
        },
    }
    Ok(())
}

fn suffix() -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:04}", n % 10000)
}
