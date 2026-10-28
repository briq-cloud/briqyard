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

const SCRIPT: &str = include_str!("../../../hack/bootstrap-host.sh");

/// Prints the host's API certificate fingerprint, from the configuration the script wrote.
const FINGERPRINT_CMD: &str = "briqyardd --config /etc/briqyard/config.yaml tls-fingerprint";

/// Prints the installed daemon's version, `briqyardd 0.1.0+fdad892eeefa`.
const VERSION_CMD: &str = "briqyardd --version";

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
    let script = if b.script.as_os_str().is_empty() {
        SCRIPT.to_string()
    } else {
        std::fs::read_to_string(&b.script)?
    };
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

/// A new host's settings for the script, every value single-quoted for the remote shell.
/// `own_url` is the fleet's own when `fleet_url` is not set. From the host's record: its API's
/// URL (what it advertises), its token and its public ports, its own or else the fleet's (a
/// record from before they were kept), so a re-run never takes another host's edge ports away,
/// or adds them.
pub fn bootstrap_env(
    b: &crate::config::Bootstrap,
    own_url: &str,
    h: &crate::registry::HostRec,
    release: &str,
) -> String {
    let (url, token) = (h.url.as_str(), h.token.as_str());
    let public_tcp_ports = h.public_tcp_ports.as_deref().unwrap_or(&b.public_tcp_ports);
    let fleet_url = if b.fleet_url.is_empty() {
        own_url
    } else {
        &b.fleet_url
    };
    let mut env = format!(
        "FLEET_URL={} ADVERTISE={} BRIQYARD_TOKEN={} BRIQYARD_RELEASE={} BRIQYARD_RELEASE_TOKEN={} BRIQYARD_POOL_DEVICE={} ALLOWED_CLIENTS={}",
        shq(fleet_url),
        shq(url),
        shq(token),
        shq(release),
        shq(&b.release_token),
        shq(&b.pool_device),
        shq(&b.allowed_clients.join(","))
    );
    if let Some(private) = private_address(b, url) {
        let ports: Vec<String> = public_tcp_ports.iter().map(|p| p.to_string()).collect();
        env += &format!(
            " PRIVATE_ADDRESS={} PRIVATE_INTERFACE={} PUBLIC_TCP_PORTS={} FLEET_ADDRESS={}",
            shq(&private),
            shq(&b.private_interface),
            shq(&ports.join(",")),
            shq(&b.fleet_address)
        );
    }
    env
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
mod tests {
    use super::*;

    const ED25519: &str = "10.0.0.9 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF+69ms8S2QZ+nIzDuFQDaK1FztcJQuI5HGeuZIneF4y\n";

    #[test]
    fn quoting() {
        assert_eq!(shq("plain"), "'plain'");
        assert_eq!(shq("it's"), "'it'\\''s'");
        assert_eq!(shq(""), "''");
    }

    /// A host's record as the bootstrap reads it.
    fn rec(url: &str, token: &str, public_tcp_ports: Option<Vec<u16>>) -> crate::registry::HostRec {
        crate::registry::HostRec {
            url: url.into(),
            token: token.into(),
            public_tcp_ports,
            ..Default::default()
        }
    }

    #[test]
    fn ssh_command() {
        let b = crate::config::Bootstrap {
            ssh_user: "root".into(),
            ssh_key: "/etc/briqyard/key".into(),
            release: "https://x/v1".into(),
            pool_device: "/dev/nvme1n1".into(),
            allowed_clients: vec!["10.0.0.0/8".into(), "192.168.0.0/16".into()],
            ..Default::default()
        };
        let kh = Path::new("/var/lib/briqyard-fleet/known_hosts");
        let env = bootstrap_env(
            &b,
            "http://0.0.0.0:7430",
            &rec(&host_url("10.0.0.9"), "t0k'en", None),
            &b.release,
        );
        let args = ssh_args(&b, "10.0.0.9", &env, kh, true);
        assert_eq!(
            args[5], "StrictHostKeyChecking=yes",
            "a pinned key is checked"
        );
        assert_eq!(
            args[7],
            "UserKnownHostsFile=/var/lib/briqyard-fleet/known_hosts"
        );
        assert_eq!(args[9], "HashKnownHosts=no");
        assert_eq!(args[11], "/etc/briqyard/key");
        assert_eq!(args[12], "root@10.0.0.9");
        let remote = &args[13];
        assert!(remote.starts_with("env FLEET_URL='http://0.0.0.0:7430' ADVERTISE='https://10.0.0.9:7420' BRIQYARD_TOKEN='t0k'\\''en' "), "{remote}");
        assert!(
            remote.ends_with(
                "BRIQYARD_RELEASE='https://x/v1' BRIQYARD_RELEASE_TOKEN='' BRIQYARD_POOL_DEVICE='/dev/nvme1n1' ALLOWED_CLIENTS='10.0.0.0/8,192.168.0.0/16' bash -s"
            ),
            "{remote}"
        );
        assert!(
            !remote.contains("PRIVATE_ADDRESS"),
            "no private network configured: {remote}"
        );
        assert!(
            !remote.contains("FLEET_TOKEN"),
            "no shared secret: {remote}"
        );
        assert!(args.contains(&"BatchMode=yes".to_string()));
        let named = crate::config::Bootstrap {
            fleet_url: "https://fleet.example".into(),
            ..Default::default()
        };
        let env = bootstrap_env(
            &named,
            "https://0.0.0.0:7430",
            &rec("https://10.0.0.9:7420", "t", Some(vec![80, 443])),
            "",
        );
        let args = ssh_args(&named, "10.0.0.9", &env, kh, false);
        assert_eq!(
            args[5], "StrictHostKeyChecking=accept-new",
            "a new host's key is taken, into the file given"
        );
        assert!(args[13].contains("FLEET_URL='https://fleet.example'"));
        // An upgrade gives the release alone: the host's configuration says the rest, and the
        // fleet's own address (`0.0.0.0` in development) is never offered as its fleet.
        let args = ssh_args(&b, "10.0.0.9", &upgrade_env("file:///r/it's", ""), kh, true);
        assert_eq!(
            args[13],
            "env BRIQYARD_RELEASE='file:///r/it'\\''s' bash -s"
        );
        // A private repository's release: its token too, and still nothing of the host's.
        assert_eq!(
            upgrade_env("https://github.com/o/r/releases/download/v1", "gh-t"),
            "BRIQYARD_RELEASE='https://github.com/o/r/releases/download/v1' BRIQYARD_RELEASE_TOKEN='gh-t'"
        );
    }

    #[test]
    fn a_host_on_the_private_network_is_told_its_address() {
        let b = crate::config::Bootstrap {
            pool_device: "/dev/nvme0n1,/dev/nvme1n1".into(),
            release_token: "gh-t".into(),
            private_network: "10.42.0.0/16".into(),
            private_interface: "enp3s0f1".into(),
            public_tcp_ports: vec![7430, 80],
            fleet_address: "10.42.0.11".into(),
            allowed_clients: vec!["10.42.0.0/16".into()],
            ..Default::default()
        };
        let kh = Path::new("/kh");
        // SSH to the public address, the API on the vRack; the host's own ports, not the
        // fleet's default.
        let env = bootstrap_env(
            &b,
            "https://fleet.example",
            &rec("https://10.42.0.11:7420", "t", Some(vec![80, 443])),
            "",
        );
        let args = ssh_args(&b, "51.68.1.2", &env, kh, false);
        assert_eq!(args[12], "root@51.68.1.2");
        let remote = &args[13];
        assert!(
            remote.contains("ADVERTISE='https://10.42.0.11:7420'"),
            "{remote}"
        );
        assert!(remote.contains("BRIQYARD_RELEASE_TOKEN='gh-t'"), "{remote}");
        assert!(
            remote.contains("BRIQYARD_POOL_DEVICE='/dev/nvme0n1,/dev/nvme1n1'"),
            "{remote}"
        );
        assert!(
            remote.ends_with(
                " PRIVATE_ADDRESS='10.42.0.11/16' PRIVATE_INTERFACE='enp3s0f1' PUBLIC_TCP_PORTS='80,443' FLEET_ADDRESS='10.42.0.11' bash -s"
            ),
            "{remote}"
        );
        // A record from before hosts kept their ports: the fleet's.
        let env = bootstrap_env(
            &b,
            "https://fleet.example",
            &rec("https://10.42.0.11:7420", "t", None),
            "",
        );
        let args = ssh_args(&b, "51.68.1.2", &env, kh, false);
        assert!(
            args[13].ends_with(" PUBLIC_TCP_PORTS='7430,80' FLEET_ADDRESS='10.42.0.11' bash -s"),
            "{}",
            args[13]
        );
        // An API outside the private network (a host on its public address): no
        // private settings, the public interface stays as it is.
        let env = bootstrap_env(
            &b,
            "https://fleet.example",
            &rec("https://51.68.1.2:7420", "t", Some(vec![80, 443])),
            "",
        );
        let args = ssh_args(&b, "51.68.1.2", &env, kh, false);
        assert!(!args[13].contains("PRIVATE_"), "{}", args[13]);
        assert_eq!(
            private_address(&b, "https://10.42.255.1:7420").as_deref(),
            Some("10.42.255.1/16")
        );
        assert_eq!(private_address(&b, "https://10.43.0.1:7420"), None);
        assert_eq!(
            private_address(&Default::default(), "https://10.42.0.11:7420"),
            None,
            "no private network configured"
        );
    }

    #[test]
    fn networks() {
        let n = Network::parse("10.42.0.0/16").unwrap();
        assert!(n.contains("10.42.0.1".parse().unwrap()));
        assert!(n.contains("10.42.255.255".parse().unwrap()));
        assert!(!n.contains("10.43.0.0".parse().unwrap()));
        let all = Network::parse("0.0.0.0/0").unwrap();
        assert!(all.contains("203.0.113.5".parse().unwrap()));
        let one = Network::parse("10.0.0.5/32").unwrap();
        assert!(one.contains("10.0.0.5".parse().unwrap()));
        assert!(!one.contains("10.0.0.6".parse().unwrap()));
        for bad in ["10.0.0.0", "10.0.0.0/33", "10.0.0/8", "fd00::/8", "/8", ""] {
            let err = Network::parse(bad).unwrap_err().to_string();
            assert!(err.contains("want an IPv4 network"), "{bad}: {err}");
        }
    }

    #[test]
    fn added_hosts_are_installed() {
        let now = Utc::now();
        let rec = |id: &str, state: &str, url: &str, ssh: &str| {
            let mut r = crate::static_host(
                &crate::config::StaticHost {
                    id: id.into(),
                    url: url.into(),
                    ..Default::default()
                },
                now,
            );
            r.state = state.into();
            r.ssh = ssh.into();
            r
        };
        let mut reg = crate::registry::Registry::default();
        for r in [
            rec(
                "added",
                "provisioning",
                "https://10.42.0.11:7420",
                "51.68.1.2",
            ),
            rec("public", "provisioning", "https://51.68.1.3:7420", ""),
            rec("nothing", "provisioning", "", ""),
            rec("ready", "ready", "https://10.42.0.12:7420", ""),
            rec("failed", "failed", "https://10.42.0.13:7420", ""),
        ] {
            reg.hosts.insert(r.id.clone(), r);
        }
        let mut ids: Vec<String> = to_install(&reg).into_iter().map(|h| h.id).collect();
        ids.sort();
        assert_eq!(ids, ["added", "public"]);
        assert_eq!(ssh_address(&reg.hosts["added"]), "51.68.1.2");
        assert_eq!(
            ssh_address(&reg.hosts["ready"]),
            "10.42.0.12",
            "no SSH address of its own: the API's"
        );
    }

    #[test]
    fn the_api_certificate_is_read_over_the_pinned_key() {
        let b = crate::config::Bootstrap {
            ssh_key: "/etc/briqyard/key".into(),
            ..Default::default()
        };
        let kh = Path::new("/var/lib/briqyard-fleet/known_hosts");
        let mut args = ssh_base(&b, "10.0.0.9", kh, true);
        args.push(FINGERPRINT_CMD.into());
        assert_eq!(args[5], "StrictHostKeyChecking=yes");
        assert_eq!(
            args[7],
            "UserKnownHostsFile=/var/lib/briqyard-fleet/known_hosts"
        );
        assert_eq!(args[12], "root@10.0.0.9");
        assert_eq!(
            args[13],
            "briqyardd --config /etc/briqyard/config.yaml tls-fingerprint"
        );
        let fp = "ab".repeat(32);
        assert_eq!(parse_api_fingerprint(&format!("{fp}\n")).unwrap(), fp);
        let err = parse_api_fingerprint("\n").unwrap_err().to_string();
        assert!(err.contains("serves plain HTTP"), "{err}");
        let err = parse_api_fingerprint("briqyardd: not found")
            .unwrap_err()
            .to_string();
        assert!(err.contains("64 hex digits"), "{err}");
    }

    #[test]
    fn a_bootstrap_pins_the_certificate_with_the_state() {
        let mut r = crate::static_host(
            &crate::config::StaticHost {
                url: host_url("10.0.0.9"),
                ..Default::default()
            },
            Utc::now(),
        );
        let fp = "ab".repeat(32);
        bootstrapped(&mut r, "bootstrapped at now".into(), fp.clone());
        assert_eq!(r.state, "bootstrapped");
        assert_eq!(r.tls_fingerprint, fp);
        assert_eq!(r.url, "https://10.0.0.9:7420");
        assert_eq!(
            r.note,
            format!("bootstrapped at now; api certificate {fp} pinned")
        );
    }

    #[test]
    fn a_release_is_a_url_or_a_version() {
        assert_eq!(
            release_url("https://example.test/r/v0.2.0/").as_deref(),
            Some("https://example.test/r/v0.2.0")
        );
        assert_eq!(
            release_url("file:///var/lib/briqyard-fleet/release").as_deref(),
            Some("file:///var/lib/briqyard-fleet/release")
        );
        let v = "https://github.com/briq-cloud/briqyard/releases/download/v0.2.0";
        assert_eq!(release_url("0.2.0").as_deref(), Some(v));
        assert_eq!(release_url("v0.2.0").as_deref(), Some(v));
        for bad in [
            "",
            "v",
            "0.2",
            "latest",
            "0.2.0; rm -rf /",
            "0..1",
            "1.2.3.4",
        ] {
            assert_eq!(release_url(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_installed_version_is_read_from_the_daemon() {
        assert_eq!(
            parse_version("briqyardd 0.1.0+fdad892eeefa\n").as_deref(),
            Some("0.1.0+fdad892eeefa")
        );
        assert_eq!(parse_version("briqyard-fleet 0.1.0\n"), None);
        assert_eq!(parse_version("briqyardd \n"), None);
        assert_eq!(parse_version("bash: briqyardd: command not found"), None);
        let b = crate::config::Bootstrap::default();
        let kh = Path::new("/var/lib/briqyard-fleet/known_hosts");
        let mut args = ssh_base(&b, "10.0.0.9", kh, true);
        args.push(VERSION_CMD.into());
        assert_eq!(args[5], "StrictHostKeyChecking=yes");
        assert_eq!(args[13], "briqyardd --version");
    }

    #[test]
    fn a_failed_run_says_its_stderr_else_its_stdout() {
        use std::os::unix::process::ExitStatusExt;
        let out = |stdout: &[u8], stderr: &[u8]| std::process::Output {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        };
        assert_eq!(
            said(&out(b"== binaries\n   refused\n", b"ssh: oops\n")),
            "ssh: oops"
        );
        assert_eq!(
            said(&out(b"== binaries\n   refused\n", b"")),
            "== binaries |    refused"
        );
    }

    #[test]
    fn output_tails_are_the_last_three_lines() {
        assert_eq!(tail(b"a\nb\nc\nd\n"), "b | c | d");
        assert_eq!(tail(b"only"), "only");
        assert_eq!(tail(b""), "");
    }

    #[test]
    fn tokens_are_hex() {
        let t = new_token();
        assert_eq!(t.len(), 32);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(t, new_token());
    }

    #[test]
    fn host_keys_are_found_and_fingerprinted_as_ssh_keygen_does() {
        let text = format!("# comment\n10.0.0.1,10.0.0.2 ssh-rsa AAAA\n{ED25519}");
        assert!(has_host(&text, "10.0.0.9"));
        assert!(has_host(&text, "10.0.0.2"));
        assert!(!has_host(&text, "10.0.0.90"));
        assert!(!has_host("", "10.0.0.9"));
        // `ssh-keygen -lf` on this key prints SHA256:JPfy4eVG2/mo9HkWVFx8Y7rNHJ3puLDsE67/vjpHmLg.
        assert_eq!(
            fingerprints(ED25519),
            ["SHA256:JPfy4eVG2/mo9HkWVFx8Y7rNHJ3puLDsE67/vjpHmLg ed25519"]
        );
        assert_eq!(
            fingerprints("# only a comment\nbroken line\n"),
            Vec::<String>::new()
        );
        assert_eq!(
            fingerprints("h ssh-rsa not-base64!\n"),
            Vec::<String>::new()
        );
    }
}
