//! Turns a server the provisioner delivered into a host: finds its address, then runs
//! `hack/bootstrap-host.sh` on it over SSH with this fleet's details, every two minutes until
//! it works or the attempts run out. The host turns `ready` on its first heartbeat.
//!
//! The server's SSH host key: no provider the fleet orders from gives it through its API, so
//! the key seen at the first connect is pinned in `<state_dir>/known_hosts` once the bootstrap
//! has succeeded, its fingerprint written into the host's note for the operator to check; a
//! later connect (an upgrade) is strict against it.

use crate::registry::url_host;
use crate::AppState;
use chrono::Utc;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const SCRIPT: &str = include_str!("../../../hack/bootstrap-host.sh");

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
                            r.url = format!("http://{ip}:7420");
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
            let outcome = install(&st, &h.id, &ip, &h.token).await;
            let mut reg = st.reg.lock().unwrap();
            if let Some(r) = reg.hosts.get_mut(&h.id) {
                match outcome {
                    Ok(note) => {
                        r.state = "bootstrapped".into();
                        r.note = note;
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

/// Runs the bootstrap script on the server through `ssh`, the script on stdin, the settings
/// in its environment. Nothing of it is on a command line the server's other users could see.
/// Answers the note for the host: when it was bootstrapped, and the host key pinned.
async fn install(st: &AppState, host: &str, ip: &str, token: &str) -> anyhow::Result<String> {
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
    let args = ssh_args(b, &st.cfg.listen, ip, token, &known_hosts, pinned);
    let mut cmd = tokio::process::Command::new("ssh");
    cmd.args(&args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn()?;
    {
        use tokio::io::AsyncWriteExt;
        let mut stdin = child.stdin.take().expect("piped");
        stdin.write_all(script.as_bytes()).await?;
        stdin.shutdown().await?;
    }
    let out = tokio::time::timeout(Duration::from_secs(1800), child.wait_with_output())
        .await
        .map_err(|_| anyhow::anyhow!("bootstrap ran over 30 minutes"))??;
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
    let tail = |b: &[u8]| {
        let s = String::from_utf8_lossy(b);
        s.lines()
            .rev()
            .take(3)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join(" | ")
    };
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

/// The `ssh` arguments: options, the key, `user@ip`, and the remote command, which puts the
/// settings in the environment of `bash -s` (the script arrives on stdin). Every value is
/// single-quoted for the remote shell. The host key is checked against `known_hosts`: strictly
/// when it is pinned there, else the key the server presents is written there, unhashed.
fn ssh_args(
    b: &crate::config::Bootstrap,
    listen: &str,
    ip: &str,
    token: &str,
    known_hosts: &Path,
    pinned: bool,
) -> Vec<String> {
    let fleet_url = if b.fleet_url.is_empty() {
        format!("http://{listen}")
    } else {
        b.fleet_url.clone()
    };
    let env = format!(
        "FLEET_URL={} ADVERTISE={} BRIQYARD_TOKEN={} BRIQYARD_RELEASE={} BRIQYARD_POOL_DEVICE={}",
        shq(&fleet_url),
        shq(&format!("http://{ip}:7420")),
        shq(token),
        shq(&b.release),
        shq(&b.pool_device)
    );
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
        format!("env {env} bash -s"),
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
            ..Default::default()
        };
        let kh = Path::new("/var/lib/briqyard-fleet/known_hosts");
        let args = ssh_args(&b, "0.0.0.0:7430", "10.0.0.9", "t0k'en", kh, true);
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
        assert!(remote.starts_with("env FLEET_URL='http://0.0.0.0:7430' ADVERTISE='http://10.0.0.9:7420' BRIQYARD_TOKEN='t0k'\\''en' "), "{remote}");
        assert!(
            remote.ends_with(
                "BRIQYARD_RELEASE='https://x/v1' BRIQYARD_POOL_DEVICE='/dev/nvme1n1' bash -s"
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
        let args = ssh_args(&named, "0.0.0.0:7430", "10.0.0.9", "t", kh, false);
        assert_eq!(
            args[5], "StrictHostKeyChecking=accept-new",
            "a new host's key is taken, into the file given"
        );
        assert!(args[13].contains("FLEET_URL='https://fleet.example'"));
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
