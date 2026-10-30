//! Turns a server into a host (Kubernetes's `kubeadm join`): one added with `POST /v1/hosts`,
//! its SSH and API addresses given. Runs `hack/bootstrap-host.sh` on it over SSH with this
//! fleet's details, every two minutes until it works or the attempts run out. The host turns
//! `ready` on its first heartbeat.
//!
//! A host's API may live on a private network (OVH's vRack, `private_network`) while SSH
//! reaches its public address: the script is told its private address, binds the API and the
//! endpoints there and closes the public interface to all but SSH (ADR 0028).
//!
//! The server's SSH host key: the fleet is given none with the server, so the key seen at the first connect is pinned in `<state_dir>/known_hosts` once the bootstrap
//! has succeeded, its fingerprint written into the host's note for the operator to check; a
//! later connect (an upgrade) is strict against it.
//!
//! The host's API certificate (ADR 0020): once the script has succeeded and the SSH key is
//! pinned, a second, strict connection reads its fingerprint (`briqyardd tls-fingerprint`),
//! recorded with the state `bootstrapped`, before the host's first heartbeat can be taken.
//!
//! An upgrade (ADR 0027, `upgrade.rs`) runs the same script with another release: one way to
//! install a host.

use crate::registry::url_host;
use crate::AppState;
use chrono::Utc;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const SCRIPT: &str = include_str!("../../../../hack/bootstrap-host.sh");

/// Prints the host's API certificate fingerprint, from the configuration the script wrote.
const FINGERPRINT_CMD: &str = "briqyardd --config /etc/briqyard/config.yaml tls-fingerprint";

/// Prints the installed daemon's version, `briqyardd 0.1.0+fdad892eeefa`.
const VERSION_CMD: &str = "briqyardd --version";

/// The script to run: the one this build ships, or `bootstrap.script`'s. The fleet serves it
/// to a host that joins (`join.rs`), as it sends it over SSH.
pub fn script(b: &crate::config::Bootstrap) -> std::io::Result<String> {
    if b.script.as_os_str().is_empty() {
        Ok(SCRIPT.to_string())
    } else {
        std::fs::read_to_string(&b.script)
    }
}

/// Where the project's releases are, `<RELEASES>/v<version>/briqyardd-linux-<arch>`.
const RELEASES: &str = "https://github.com/briq-cloud/briqyard/releases/download";

/// What `BRIQYARD_RELEASE` is for a release asked as a URL (as it is) or as a version of the
/// project's releases (`0.2.0`, `v0.2.0`); None for anything else.
pub fn release_url(release: &str) -> Option<String> {
    if release.contains("://") {
        return Some(release.trim_end_matches('/').to_string());
    }
    let v = release.strip_prefix('v').unwrap_or(release);
    let ok = !v.is_empty()
        && v.split('.').count() == 3
        && v.split('.')
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    ok.then(|| format!("{RELEASES}/v{v}"))
}

/// An added host's API URL: TLS, with the certificate the bootstrap pins.
pub fn host_url(ip: &str) -> String {
    format!("https://{ip}:7420")
}

/// A fresh token for a host's own API; the bootstrap writes it into the host's configuration
/// and the fleet keeps it to forward requests and to accept the host's heartbeats.
pub fn new_token() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub async fn run(st: Arc<AppState>) {
    loop {
        tokio::time::sleep(Duration::from_secs(120)).await;
        let pending = to_install(&st.reg.lock().unwrap());
        for h in pending {
            let b = &st.cfg.bootstrap;
            if !b.enabled {
                continue;
            }
            let ip = ssh_address(&h).to_string();
            let env = bootstrap_env(b, &st.cfg.own_url(), &h, &b.release);
            let outcome = match install(&st, &h.id, &ip, &env).await {
                Ok(note) => api_fingerprint(&st, &ip).await.map(|fp| (note, fp)),
                Err(e) => Err(e),
            };
            {
                let mut reg = st.reg.lock().unwrap();
                if let Some(r) = reg.hosts.get_mut(&h.id) {
                    match outcome {
                        Ok((note, fingerprint)) => {
                            bootstrapped(r, note, fingerprint);
                            tracing::info!(
                                host = h.id,
                                ip,
                                note = r.note,
                                "host bootstrapped; waiting for its heartbeat"
                            );
                        }
                        Err(e) => {
                            r.bootstrap_attempts += 1;
                            r.note = format!("bootstrap attempt {}: {e}", r.bootstrap_attempts);
                            if r.bootstrap_attempts >= b.max_attempts {
                                r.state = "failed".into();
                                tracing::error!(host = h.id, ip, attempts = r.bootstrap_attempts, err = %e, "bootstrap gave up");
                            } else {
                                tracing::warn!(host = h.id, ip, attempt = r.bootstrap_attempts, err = %e, "bootstrap");
                            }
                        }
                    }
                }
            }
            let _ = st.save().await;
        }
    }
}

/// The hosts the bootstrap works on: `provisioning`, with the address `host add` gave.
pub fn to_install(reg: &crate::registry::Registry) -> Vec<crate::registry::HostRec> {
    reg.hosts
        .values()
        .filter(|h| h.state == "provisioning" && !h.url.is_empty())
        .cloned()
        .collect()
}

/// Where the bootstrap connects: the host's SSH address when it has one of its own, else its
/// API's.
pub fn ssh_address(h: &crate::registry::HostRec) -> &str {
    if h.ssh.is_empty() {
        url_host(&h.url)
    } else {
        &h.ssh
    }
}

/// An IPv4 network, `a.b.c.d/n`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Network {
    pub addr: std::net::Ipv4Addr,
    pub prefix: u8,
}

impl Network {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let bad = || anyhow::anyhow!("{s:?}: want an IPv4 network, a.b.c.d/n");
        let (a, n) = s.split_once('/').ok_or_else(bad)?;
        let addr: std::net::Ipv4Addr = a.parse().map_err(|_| bad())?;
        let prefix: u8 = n.parse().map_err(|_| bad())?;
        if prefix > 32 {
            return Err(bad());
        }
        Ok(Self { addr, prefix })
    }

    pub fn contains(&self, ip: std::net::Ipv4Addr) -> bool {
        let mask = u32::MAX.checked_shl(32 - self.prefix as u32).unwrap_or(0);
        u32::from(ip) & mask == u32::from(self.addr) & mask
    }
}

/// The host's private address with the network's prefix (`10.42.0.11/16`), when its API is
/// on the fleet's private network; `None` for a host on a public address.
pub fn private_address(b: &crate::config::Bootstrap, url: &str) -> Option<String> {
    let net = Network::parse(&b.private_network).ok()?;
    let ip: std::net::Ipv4Addr = url_host(url).parse().ok()?;
    net.contains(ip).then(|| format!("{ip}/{}", net.prefix))
}

/// Records a bootstrap that succeeded: the API certificate pinned in the same write as the
/// state, so the host's first heartbeat is checked against it.
pub fn bootstrapped(r: &mut crate::registry::HostRec, note: String, fingerprint: String) {
    r.state = "bootstrapped".into();
    r.note = format!("{note}; api certificate {fingerprint} pinned");
    r.tls_fingerprint = fingerprint;
}

/// The host's API certificate fingerprint, read over SSH against the key just pinned. A host
/// that answers none serves plain HTTP: not one the fleet forwards secrets to.
async fn api_fingerprint(st: &AppState, ip: &str) -> anyhow::Result<String> {
    let b = &st.cfg.bootstrap;
    let known_hosts = st.cfg.state_dir.join("known_hosts");
    let mut args = ssh_base(b, ip, &known_hosts, true);
    args.push(FINGERPRINT_CMD.into());
    let out = ssh(&args, b"", Duration::from_secs(60)).await?;
    if !out.status.success() {
        anyhow::bail!(
            "read the api certificate: ssh exited {}: {}",
            out.status.code().unwrap_or(-1),
            tail(&out.stderr)
        );
    }
    parse_api_fingerprint(&String::from_utf8_lossy(&out.stdout))
}

/// The daemon's version installed on the host, read over the pinned SSH key.
pub async fn installed_version(st: &AppState, ip: &str) -> anyhow::Result<String> {
    let b = &st.cfg.bootstrap;
    let known_hosts = st.cfg.state_dir.join("known_hosts");
    let mut args = ssh_base(b, ip, &known_hosts, true);
    args.push(VERSION_CMD.into());
    let out = ssh(&args, b"", Duration::from_secs(60)).await?;
    let text = String::from_utf8_lossy(&out.stdout);
    match (out.status.success(), parse_version(&text)) {
        (true, Some(v)) => Ok(v),
        _ => anyhow::bail!(
            "read the installed version: ssh exited {}: {} {}",
            out.status.code().unwrap_or(-1),
            text.trim(),
            tail(&out.stderr)
        ),
    }
}

/// The version `briqyardd --version` printed (`briqyardd 0.1.0+fdad892eeefa`).
fn parse_version(out: &str) -> Option<String> {
    let v = out.trim().strip_prefix("briqyardd ")?.trim();
    (!v.is_empty() && !v.contains(char::is_whitespace)).then(|| v.to_string())
}

/// What `briqyardd tls-fingerprint` printed: the fingerprint, or nothing for a plain API.
fn parse_api_fingerprint(out: &str) -> anyhow::Result<String> {
    if out.trim().is_empty() {
        anyhow::bail!(
            "the host's API serves plain HTTP (a loopback listen or api_tls: false): an added host must serve TLS"
        );
    }
    briqyard_api::tls::parse_fingerprint(out)
        .map_err(|e| anyhow::anyhow!("read the api certificate: {e}"))
}

/// Runs `ssh` with these arguments, `input` on its stdin, for at most `limit`.
async fn ssh(
    args: &[String],
    input: &[u8],
    limit: Duration,
) -> anyhow::Result<std::process::Output> {
    let mut child = tokio::process::Command::new("ssh")
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    {
        use tokio::io::AsyncWriteExt;
        let mut stdin = child.stdin.take().expect("piped");
        stdin.write_all(input).await?;
        stdin.shutdown().await?;
    }
    tokio::time::timeout(limit, child.wait_with_output())
        .await
        .map_err(|_| anyhow::anyhow!("ssh ran over {} s", limit.as_secs()))?
        .map_err(Into::into)
}

/// What a failed run said last: its stderr's last lines, else its stdout's (the bootstrap
/// script says why it stops on its stdout).
fn said(out: &std::process::Output) -> String {
    match tail(&out.stderr) {
        e if e.trim().is_empty() => tail(&out.stdout),
        e => e,
    }
}

/// The last three lines of an output, on one line.
fn tail(b: &[u8]) -> String {
    let s = String::from_utf8_lossy(b);
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(3)..].join(" | ")
}

/// Runs the bootstrap script on the server through `ssh`, the script on stdin, `env` its
/// settings ([`bootstrap_env`], [`upgrade_env`]). Nothing of it is on a command line the
/// server's other users could see. Answers the note for the host: when it was bootstrapped,
/// and the host key pinned.
pub async fn install(st: &AppState, host: &str, ip: &str, env: &str) -> anyhow::Result<String> {
    let b = &st.cfg.bootstrap;
    let script = script(b)?;
    // A host whose key is pinned is checked against it. A new one connects to whatever key it
    // presents, into a file of its own: the key is pinned only once the bootstrap has succeeded,
    // so an attempt made while the server is still installing its OS pins nothing.
    let pinned_file = st.cfg.state_dir.join("known_hosts");
    let pinned = has_host(
        &std::fs::read_to_string(&pinned_file).unwrap_or_default(),
        ip,
    );
    let known_hosts = if pinned {
        pinned_file.clone()
    } else {
        st.cfg.state_dir.join(format!("known_hosts.{ip}"))
    };
    let args = ssh_args(b, ip, env, &known_hosts, pinned);
    let out = ssh(&args, script.as_bytes(), Duration::from_secs(1800)).await?;
    let seen = if pinned {
        None
    } else {
        let lines = std::fs::read_to_string(&known_hosts).unwrap_or_default();
        let _ = std::fs::remove_file(&known_hosts);
        Some(lines)
    };
    let key = seen
        .as_deref()
        .map(|l| fingerprints(l).join(", "))
        .unwrap_or_default();
    if !out.status.success() {
        let seen = if key.is_empty() {
            String::new()
        } else {
            format!(" (host key {key} seen, not pinned)")
        };
        return Err(anyhow::anyhow!(
            "ssh exited {}: {}{seen}",
            out.status.code().unwrap_or(-1),
            said(&out)
        ));
    }
    tracing::info!(host, ip, out = tail(&out.stdout), "bootstrap output");
    let when = Utc::now().to_rfc3339();
    match seen {
        Some(lines) if !key.is_empty() => {
            use std::io::Write;
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&pinned_file)
                .and_then(|mut f| f.write_all(lines.as_bytes()))
                .map_err(|e| {
                    anyhow::anyhow!("pin the host key in {}: {e}", pinned_file.display())
                })?;
            Ok(format!(
                "bootstrapped at {when}; ssh host key {key} pinned at first connect: check it on the server (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub)"
            ))
        }
        Some(_) => Ok(format!("bootstrapped at {when}; no ssh host key recorded")),
        None => Ok(format!(
            "bootstrapped at {when}; ssh host key already pinned"
        )),
    }
}

/// Whether a `known_hosts` text has a line for the address.
fn has_host(known_hosts: &str, ip: &str) -> bool {
    known_hosts
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_whitespace().next())
        .any(|hosts| hosts.split(',').any(|h| h == ip))
}

/// The fingerprints of the keys in a `known_hosts` text, as `ssh-keygen -l` prints them:
/// `SHA256:<base64 of the key's SHA-256, unpadded> <type>`.
fn fingerprints(known_hosts: &str) -> Vec<String> {
    use base64::prelude::*;
    use sha2::{Digest, Sha256};
    known_hosts
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let (_, kind, key) = (f.next()?, f.next()?, f.next()?);
            let blob = BASE64_STANDARD.decode(key).ok()?;
            let digest = BASE64_STANDARD_NO_PAD.encode(Sha256::digest(&blob));
            Some(format!(
                "SHA256:{digest} {}",
                kind.strip_prefix("ssh-").unwrap_or(kind)
            ))
        })
        .collect()
}

/// A new host's settings for the script, by their environment names (empty ones too; the SSH
/// bootstrap sends them all, a join drops them). `own_url` is the fleet's own when `fleet_url`
/// is not set. From the host's record: its API's URL (what it advertises), its token and its
/// public ports, its own or else the fleet's (a record from before they were kept), so a re-run
/// never takes another host's edge ports away, or adds them.
pub fn bootstrap_settings(
    b: &crate::config::Bootstrap,
    own_url: &str,
    h: &crate::registry::HostRec,
    release: &str,
) -> Vec<(&'static str, String)> {
    let (url, token) = (h.url.as_str(), h.token.as_str());
    let public_tcp_ports = h.public_tcp_ports.as_deref().unwrap_or(&b.public_tcp_ports);
    let fleet_url = if b.fleet_url.is_empty() {
        own_url
    } else {
        &b.fleet_url
    };
    let mut env = vec![
        ("FLEET_URL", fleet_url.to_string()),
        ("ADVERTISE", url.to_string()),
        ("BRIQYARD_TOKEN", token.to_string()),
        ("BRIQYARD_RELEASE", release.to_string()),
        ("BRIQYARD_RELEASE_TOKEN", b.release_token.clone()),
        ("BRIQYARD_POOL_DEVICE", b.pool_device.clone()),
        ("ALLOWED_CLIENTS", b.allowed_clients.join(",")),
    ];
    if let Some(private) = private_address(b, url) {
        let ports: Vec<String> = public_tcp_ports.iter().map(|p| p.to_string()).collect();
        env.extend([
            ("PRIVATE_ADDRESS", private),
            ("PRIVATE_INTERFACE", b.private_interface.clone()),
            ("PUBLIC_TCP_PORTS", ports.join(",")),
            ("FLEET_ADDRESS", b.fleet_address.clone()),
        ]);
    }
    env
}

/// [`bootstrap_settings`] as the `NAME='value' …` the remote shell reads, every value
/// single-quoted.
pub fn bootstrap_env(
    b: &crate::config::Bootstrap,
    own_url: &str,
    h: &crate::registry::HostRec,
    release: &str,
) -> String {
    bootstrap_settings(b, own_url, h, release)
        .iter()
        .map(|(k, v)| format!("{k}={}", shq(v)))
        .collect::<Vec<_>>()
        .join(" ")
}

/// An upgrade's settings (ADR 0027): the release, and the token that reads it when it is a
/// private repository's. The host's configuration says the rest (its fleet, its token, its
/// pool's key), and is not written again.
pub fn upgrade_env(release: &str, release_token: &str) -> String {
    let mut env = format!("BRIQYARD_RELEASE={}", shq(release));
    if !release_token.is_empty() {
        env += &format!(" BRIQYARD_RELEASE_TOKEN={}", shq(release_token));
    }
    env
}

/// The bootstrap's `ssh` arguments: [`ssh_base`], then the remote command, which puts `env`
/// in the environment of `bash -s` (the script arrives on stdin).
fn ssh_args(
    b: &crate::config::Bootstrap,
    ip: &str,
    env: &str,
    known_hosts: &Path,
    pinned: bool,
) -> Vec<String> {
    let mut args = ssh_base(b, ip, known_hosts, pinned);
    args.push(format!("env {env} bash -s"));
    args
}

/// Options, the key and `user@ip`. The host key is checked against `known_hosts`: strictly
/// when it is pinned there, else the key the server presents is written there, unhashed.
fn ssh_base(
    b: &crate::config::Bootstrap,
    ip: &str,
    known_hosts: &Path,
    pinned: bool,
) -> Vec<String> {
    vec![
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "ConnectTimeout=20".into(),
        "-o".into(),
        format!(
            "StrictHostKeyChecking={}",
            if pinned { "yes" } else { "accept-new" }
        ),
        "-o".into(),
        format!("UserKnownHostsFile={}", known_hosts.display()),
        "-o".into(),
        "HashKnownHosts=no".into(),
        "-i".into(),
        b.ssh_key.to_string_lossy().into_owned(),
        format!("{}@{ip}", b.ssh_user),
    ]
}

fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests;
