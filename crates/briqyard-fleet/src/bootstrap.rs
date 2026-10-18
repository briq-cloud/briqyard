//! Turns a server the provisioner delivered into a host: finds its address, then runs
//! `hack/bootstrap-host.sh` on it over SSH with this fleet's details, every two minutes until
//! it works or the attempts run out. The host turns `ready` on its first heartbeat.

use crate::registry::url_host;
use crate::AppState;
use chrono::Utc;
use std::sync::Arc;
use std::time::Duration;

const SCRIPT: &str = include_str!("../../../hack/bootstrap-host.sh");

/// A fresh token for a host's own API; the bootstrap writes it into the host's configuration
/// and the fleet keeps it to forward requests.
pub fn new_token() -> String {
    let mut b = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut b);
    }
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
                        st.save();
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
                    Ok(()) => {
                        r.state = "bootstrapped".into();
                        r.note = format!("bootstrapped at {}", Utc::now().to_rfc3339());
                        tracing::info!(
                            host = h.id,
                            ip,
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
            st.save();
        }
    }
}

/// Runs the bootstrap script on the server through `ssh`, the script on stdin, the settings
/// in its environment. Nothing of it is on a command line the server's other users could see.
async fn install(st: &AppState, host: &str, ip: &str, token: &str) -> anyhow::Result<()> {
    let b = &st.cfg.provisioner.bootstrap;
    let script = if b.script.as_os_str().is_empty() {
        SCRIPT.to_string()
    } else {
        std::fs::read_to_string(&b.script)?
    };
    let fleet_url = if b.fleet_url.is_empty() {
        format!("http://{}", st.cfg.listen)
    } else {
        b.fleet_url.clone()
    };
    let env = format!(
        "FLEET_URL={} FLEET_TOKEN={} ADVERTISE=http://{ip}:7420 BRIQYARD_TOKEN={} BRIQYARD_RELEASE={} BRIQYARD_POOL_DEVICE={}",
        shq(&fleet_url),
        shq(&st.cfg.host_token),
        shq(token),
        shq(&b.release),
        shq(&b.pool_device)
    );
    let mut cmd = tokio::process::Command::new("ssh");
    cmd.args([
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=20",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-i",
    ])
    .arg(&b.ssh_key)
    .arg(format!("{}@{ip}", b.ssh_user))
    .arg(format!("env {env} bash -s"))
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
    if out.status.success() {
        tracing::info!(host, ip, out = tail(&out.stdout), "bootstrap output");
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "ssh exited {}: {}",
            out.status.code().unwrap_or(-1),
            tail(&out.stderr)
        ))
    }
}

fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
