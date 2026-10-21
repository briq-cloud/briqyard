//! Turns a server the provisioner delivered into a host: finds its address, then runs
//! `hack/bootstrap-host.sh` on it over SSH with this fleet's details, every two minutes until
//! it works or the attempts run out. The host turns `ready` on its first heartbeat.
//!
//! The server's SSH host key: no provider the fleet orders from gives it through its API, so
//! the key seen at the first connect is pinned in `<state_dir>/known_hosts` once the bootstrap
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

/// An ordered host's API URL: TLS, with the certificate the bootstrap pins.
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
        let pending: Vec<_> = st
            .reg
            .lock()
            .unwrap()
            .hosts
            .values()
            .filter(|h| h.state == "provisioning" && !h.provider_id.is_empty())
            .cloned()
            .collect();
        for h in pending {
            // 1. The address, once the provider has one.
            if h.url.is_empty() {
                match st.prov.lookup(&h.provider_id).await {
                    Ok(Some(ip)) => {
                        tracing::info!(host = h.id, ip, "server delivered");
                        if let Some(r) = st.reg.lock().unwrap().hosts.get_mut(&h.id) {
                            r.url = host_url(&ip);
                            r.note = format!("delivered at {ip}");
                        }
                        let _ = st.save();
                    }
                    Ok(None) => {}
                    Err(e) => tracing::warn!(host = h.id, err = %e, "lookup"),
                }
                continue;
            }
            // 2. The install.
            let b = &st.cfg.provisioner.bootstrap;
            if !b.enabled {
                continue;
            }
            let ip = url_host(&h.url).to_string();
            let outcome = match install(&st, &h.id, &ip, &h.url, &h.token, &b.release).await {
                Ok(note) => api_fingerprint(&st, &ip).await.map(|fp| (note, fp)),
                Err(e) => Err(e),
            };
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
            drop(reg);
            let _ = st.save();
        }
    }
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
    let b = &st.cfg.provisioner.bootstrap;
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
    let b = &st.cfg.provisioner.bootstrap;
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
            "the host's API serves plain HTTP (a loopback listen or api_tls: false): an ordered host must serve TLS"
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

/// The last three lines of an output, on one line.
fn tail(b: &[u8]) -> String {
    let s = String::from_utf8_lossy(b);
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(3)..].join(" | ")
}

/// Runs the bootstrap script on the server through `ssh`, the script on stdin, the settings
/// in its environment, the binaries from `release`. Nothing of it is on a command line the
/// server's other users could see. Answers the note for the host: when it was bootstrapped,
/// and the host key pinned.
pub async fn install(
    st: &AppState,
    host: &str,
    ip: &str,
    url: &str,
    token: &str,
    release: &str,
) -> anyhow::Result<String> {
    let b = &st.cfg.provisioner.bootstrap;
    let script = if b.script.as_os_str().is_empty() {
        SCRIPT.to_string()
    } else {
        std::fs::read_to_string(&b.script)?
    };
    // A host whose key is pinned is checked against it. A new one connects to whatever key it
    // presents, into a file of its own: the key is pinned only once the bootstrap has succeeded,
    // so an attempt made while the provider is still installing the OS pins nothing.
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
    let args = ssh_args(
        b,
        &st.cfg.own_url(),
        ip,
        url,
        token,
        release,
        &known_hosts,
        pinned,
    );
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
            tail(&out.stderr)
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
                "bootstrapped at {when}; ssh host key {key} pinned at first connect: check it against the provider's console"
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

/// The bootstrap's `ssh` arguments: [`ssh_base`], then the remote command, which puts the
/// settings in the environment of `bash -s` (the script arrives on stdin). Every value is
/// single-quoted for the remote shell. `own_url` is the fleet's own when `fleet_url` is not set;
/// `url` is the host's API, what it advertises.
#[allow(clippy::too_many_arguments)]
fn ssh_args(
    b: &crate::config::Bootstrap,
    own_url: &str,
    ip: &str,
    url: &str,
    token: &str,
    release: &str,
    known_hosts: &Path,
    pinned: bool,
) -> Vec<String> {
    let fleet_url = if b.fleet_url.is_empty() {
        own_url
    } else {
        &b.fleet_url
    };
    let env = format!(
        "FLEET_URL={} ADVERTISE={} BRIQYARD_TOKEN={} BRIQYARD_RELEASE={} BRIQYARD_POOL_DEVICE={} ALLOWED_CLIENTS={}",
        shq(fleet_url),
        shq(url),
        shq(token),
        shq(release),
        shq(&b.pool_device),
        shq(&b.allowed_clients.join(","))
    );
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
        let args = ssh_args(
            &b,
            "http://0.0.0.0:7430",
            "10.0.0.9",
            &host_url("10.0.0.9"),
            "t0k'en",
            &b.release,
            kh,
            true,
        );
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
                "BRIQYARD_RELEASE='https://x/v1' BRIQYARD_POOL_DEVICE='/dev/nvme1n1' ALLOWED_CLIENTS='10.0.0.0/8,192.168.0.0/16' bash -s"
            ),
            "{remote}"
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
        let args = ssh_args(
            &named,
            "https://0.0.0.0:7430",
            "10.0.0.9",
            "https://10.0.0.9:7420",
            "t",
            "",
            kh,
            false,
        );
        assert_eq!(
            args[5], "StrictHostKeyChecking=accept-new",
            "a new host's key is taken, into the file given"
        );
        assert!(args[13].contains("FLEET_URL='https://fleet.example'"));
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
