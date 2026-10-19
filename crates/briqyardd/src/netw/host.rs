//! Bridges, TAPs, forwarding and the egress interface, through iproute2: this is the host,
//! where `ip` always exists, and its output is what an operator reads when something is off.

use super::{bridge_name, tap_name, Subnet};
use anyhow::{anyhow, Context, Result};
use tokio::process::Command;

async fn ip(args: &[&str]) -> Result<String> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .await
        .context("run ip")?;
    if !out.status.success() {
        return Err(anyhow!(
            "ip {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

async fn link_exists(name: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", "dev", name])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Makes the tenant's bridge with the gateway address, up.
pub async fn ensure_bridge(s: &Subnet) -> Result<String> {
    let name = bridge_name(s.index);
    if !link_exists(&name).await {
        ip(&["link", "add", &name, "type", "bridge"]).await?;
    }
    let gw = format!("{}/24", s.gateway());
    let addrs = ip(&["-4", "-o", "addr", "show", "dev", &name]).await?;
    if !addrs.contains(&gw) {
        ip(&["addr", "add", &gw, "dev", &name]).await?;
    }
    ip(&["link", "set", &name, "up"]).await?;
    Ok(name)
}

/// Removes the tenant's bridge. Missing is success.
pub async fn delete_bridge(index: u32) -> Result<()> {
    let name = bridge_name(index);
    if link_exists(&name).await {
        ip(&["link", "del", &name]).await?;
    }
    Ok(())
}

/// Makes the machine's TAP, attached to the bridge and up. Firecracker opens it by name.
pub async fn ensure_tap(machine_id: &str, bridge: &str) -> Result<String> {
    let name = tap_name(machine_id);
    if !link_exists(&name).await {
        ip(&["tuntap", "add", "dev", &name, "mode", "tap", "vnet_hdr"]).await?;
    }
    ip(&["link", "set", &name, "master", bridge]).await?;
    ip(&["link", "set", &name, "up"]).await?;
    Ok(name)
}

/// Removes the machine's TAP. Missing is success.
pub async fn delete_tap(machine_id: &str) -> Result<()> {
    let name = tap_name(machine_id);
    if link_exists(&name).await {
        ip(&["link", "del", &name]).await?;
    }
    Ok(())
}

pub fn enable_forwarding() -> Result<()> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1\n").context("ip_forward")
}

/// The interface of the host's default route.
pub async fn default_egress_interface() -> Result<String> {
    let out = ip(&["-4", "route", "show", "default"]).await?;
    default_route_device(&out)
}

/// The device of the first default route in `ip -4 route show default` output.
fn default_route_device(out: &str) -> Result<String> {
    for line in out.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if let Some(i) = f.iter().position(|w| *w == "dev") {
            if let Some(dev) = f.get(i + 1) {
                return Ok(dev.to_string());
            }
        }
    }
    Err(anyhow!("no default route"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_route() {
        assert_eq!(
            default_route_device(
                "default via 192.168.64.1 dev eth0 proto dhcp src 192.168.64.3 metric 100 \n"
            )
            .unwrap(),
            "eth0"
        );
        // Several default routes: the first one, which the kernel prefers (lowest metric first).
        let two = "default via 10.0.0.1 dev enp5s0 proto static metric 100\ndefault via 10.0.1.1 dev wlan0 proto dhcp metric 600\n";
        assert_eq!(default_route_device(two).unwrap(), "enp5s0");
        // A line without a device (a blackhole) does not count; the next one does.
        let hole = "blackhole default\ndefault via 10.0.0.1 dev br0\n";
        assert_eq!(default_route_device(hole).unwrap(), "br0");
    }

    #[test]
    fn no_default_route() {
        for out in ["", "\n", "default via 10.0.0.1 dev"] {
            let err = default_route_device(out).unwrap_err();
            assert_eq!(err.to_string(), "no default route", "{out:?}");
        }
    }
}
