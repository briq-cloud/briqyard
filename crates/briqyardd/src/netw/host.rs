//! Bridges, TAPs, forwarding and the egress interface, through iproute2: this is the host,
//! where `ip` always exists, and its output is what an operator reads when something is off.

use super::{bridge_name, nft, tap_name, Subnet, TAP_PREFIX};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::process::Command;

/// The host network as the manager drives it: the bridges, TAPs, pins and egress policies
/// below on the host, a mock in the manager's tests.
#[async_trait]
pub trait Net: Send + Sync {
    async fn ensure_bridge(&self, s: &Subnet) -> Result<String>;
    async fn delete_bridge(&self, index: u32) -> Result<()>;
    async fn ensure_tap(&self, machine_id: &str, bridge: &str, ip: &str) -> Result<String>;
    async fn delete_tap(&self, machine_id: &str, ip: &str) -> Result<()>;
    async fn delete_link(&self, name: &str) -> Result<()>;
    async fn list_taps(&self) -> Result<Vec<String>>;
    async fn set_policy(&self, p: &nft::Policy) -> Result<()>;
    async fn unset_policy(&self, p: &nft::Policy) -> Result<()>;
    async fn swap_policy(&self, old: &nft::Policy, new: &nft::Policy) -> Result<()>;
    /// Counts the internet traffic of a machine's address (ADR 0017) and what its egress
    /// limits drop (ADR 0018), from zero.
    async fn count(&self, ip: &str) -> Result<()>;
    /// Ends the count. Missing is success.
    async fn uncount(&self, ip: &str) -> Result<()>;
    /// The counters of every counted address since it was counted.
    async fn counters(&self) -> Result<HashMap<String, nft::Counters>>;
    /// Returns once a TCP connection to `ip:port` from the host is accepted, or fails at
    /// `timeout`.
    async fn wait_port(&self, ip: Ipv4Addr, port: u16, timeout: Duration) -> Result<()>;
    /// One TCP connect to `ip:port` within `timeout`: a TCP probe (ADR 0022).
    async fn probe_tcp(&self, ip: Ipv4Addr, port: u16, timeout: Duration) -> Result<()>;
    /// One HTTP GET of `path` on `ip:port` within `timeout`: its status code.
    async fn probe_http(
        &self,
        ip: Ipv4Addr,
        port: u16,
        path: &str,
        timeout: Duration,
    ) -> Result<u16>;
}

/// iproute2 and nftables on this host.
pub struct HostNet;

#[async_trait]
impl Net for HostNet {
    async fn ensure_bridge(&self, s: &Subnet) -> Result<String> {
        ensure_bridge(s).await
    }
    async fn delete_bridge(&self, index: u32) -> Result<()> {
        delete_bridge(index).await
    }
    async fn ensure_tap(&self, machine_id: &str, bridge: &str, ip: &str) -> Result<String> {
        ensure_tap(machine_id, bridge, ip).await
    }
    async fn delete_tap(&self, machine_id: &str, ip: &str) -> Result<()> {
        delete_tap(machine_id, ip).await
    }
    async fn delete_link(&self, name: &str) -> Result<()> {
        delete_link(name).await
    }
    async fn list_taps(&self) -> Result<Vec<String>> {
        list_taps().await
    }
    async fn set_policy(&self, p: &nft::Policy) -> Result<()> {
        nft::set_policy(p).await
    }
    async fn unset_policy(&self, p: &nft::Policy) -> Result<()> {
        nft::unset_policy(p).await
    }
    async fn swap_policy(&self, old: &nft::Policy, new: &nft::Policy) -> Result<()> {
        nft::swap_policy(old, new).await
    }
    async fn count(&self, ip: &str) -> Result<()> {
        nft::count(ip).await
    }
    async fn uncount(&self, ip: &str) -> Result<()> {
        nft::uncount(ip).await
    }
    async fn counters(&self) -> Result<HashMap<String, nft::Counters>> {
        nft::counters().await
    }
    async fn wait_port(&self, ip: Ipv4Addr, port: u16, timeout: Duration) -> Result<()> {
        wait_port(SocketAddr::from((ip, port)), timeout).await
    }
    async fn probe_tcp(&self, ip: Ipv4Addr, port: u16, timeout: Duration) -> Result<()> {
        connect_once(SocketAddr::from((ip, port)), timeout).await
    }
    async fn probe_http(
        &self,
        ip: Ipv4Addr,
        port: u16,
        path: &str,
        timeout: Duration,
    ) -> Result<u16> {
        http_status(SocketAddr::from((ip, port)), path, timeout).await
    }
}

/// One connect, accepted within `timeout`, then closed.
pub async fn connect_once(addr: SocketAddr, timeout: Duration) -> Result<()> {
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(anyhow!("{addr}: {e}")),
        Err(_) => Err(anyhow!("{addr}: no answer within {timeout:?}")),
    }
}

/// The status code of `GET path` on `addr`, the whole exchange within `timeout`: an HTTP/1.1
/// request that asks the server to close, and its status line, read up to 1 KB. Nothing else
/// of the answer is read.
pub async fn http_status(addr: SocketAddr, path: &str, timeout: Duration) -> Result<u16> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let exchange = async {
        let mut s = tokio::net::TcpStream::connect(addr).await?;
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {addr}\r\nUser-Agent: briqyard-probe\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await?;
        let mut head = Vec::with_capacity(128);
        let mut buf = [0u8; 256];
        while !head.contains(&b'\n') && head.len() < 1024 {
            let n = s.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            head.extend_from_slice(&buf[..n]);
        }
        anyhow::Ok(head)
    };
    let head = match tokio::time::timeout(timeout, exchange).await {
        Ok(r) => r.map_err(|e| anyhow!("{addr}: {e:#}"))?,
        Err(_) => return Err(anyhow!("{addr}: no answer within {timeout:?}")),
    };
    status_code(&head).ok_or_else(|| anyhow!("{addr}: not an HTTP answer"))
}

/// The code of an HTTP/1.x status line: `HTTP/1.1 200 OK`.
fn status_code(head: &[u8]) -> Option<u16> {
    let line = head.split(|b| *b == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?;
    let mut parts = line.split_whitespace();
    if !parts.next()?.starts_with("HTTP/1.") {
        return None;
    }
    let code: u16 = parts.next()?.parse().ok()?;
    (100..=599).contains(&code).then_some(code)
}

/// Connects until the port accepts: nothing on the host says when a guest's program listens.
pub async fn wait_port(addr: SocketAddr, timeout: Duration) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let last =
            match tokio::time::timeout_at(deadline, tokio::net::TcpStream::connect(addr)).await {
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(e)) => e.to_string(),
                Err(_) => "no answer".to_string(),
            };
        if tokio::time::Instant::now() + Duration::from_millis(200) > deadline {
            return Err(anyhow!("{addr} did not accept within {timeout:?}: {last}"));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

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
        // Two callers may pass the check together; the second add is then "File exists".
        match ip(&["link", "add", &name, "type", "bridge"]).await {
            Ok(_) => {}
            Err(e) if e.to_string().contains("File exists") => {}
            Err(e) => return Err(e),
        }
    }
    let gw = format!("{}/24", s.gateway());
    let addrs = ip(&["-4", "-o", "addr", "show", "dev", &name]).await?;
    if !addrs.contains(&gw) {
        ip(&["addr", "add", &gw, "dev", &name]).await?;
    }
    ip(&["link", "set", &name, "up"]).await?;
    // Frames switched inside the bridge stay out of the IP hooks (what br_netfilter would
    // feed them to), so the forward chain sees routed traffic only. A kernel without
    // bridge netfilter has no knob and nothing to switch off.
    for knob in ["nf_call_iptables", "nf_call_ip6tables", "nf_call_arptables"] {
        let path = format!("/sys/class/net/{name}/bridge/{knob}");
        match tokio::fs::write(&path, "0\n").await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(anyhow!("{path}: {e}")),
        }
    }
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

/// Makes the machine's TAP, attached to the bridge, up and pinned to the machine's address.
/// Firecracker opens it by name. A TAP lives for one boot: one of that name already there
/// is a leftover (a start that failed after making it) and is replaced, never shared.
pub async fn ensure_tap(machine_id: &str, bridge: &str, ip_addr: &str) -> Result<String> {
    let name = tap_name(machine_id);
    delete_link(&name).await?;
    ip(&["tuntap", "add", "dev", &name, "mode", "tap", "vnet_hdr"]).await?;
    ip(&["link", "set", &name, "master", bridge]).await?;
    ip(&["link", "set", &name, "up"]).await?;
    nft::pin_source(&name, ip_addr).await?;
    Ok(name)
}

/// Removes the machine's TAP and its pin. Missing is success.
pub async fn delete_tap(machine_id: &str, ip_addr: &str) -> Result<()> {
    let name = tap_name(machine_id);
    delete_link(&name).await?;
    nft::unpin_source(&name, ip_addr).await
}

/// Removes a link by name. Missing is success.
pub async fn delete_link(name: &str) -> Result<()> {
    if link_exists(name).await {
        ip(&["link", "del", name]).await?;
    }
    Ok(())
}

/// The daemon's TAPs on the host: every `tun` link named with its prefix.
pub async fn list_taps() -> Result<Vec<String>> {
    let out = ip(&["-o", "link", "show", "type", "tun"]).await?;
    Ok(tap_names(&out))
}

fn tap_names(ip_link_out: &str) -> Vec<String> {
    ip_link_out
        .lines()
        .filter_map(|l| l.split(": ").nth(1))
        .map(|n| n.split('@').next().unwrap_or(n).to_string())
        .filter(|n| n.starts_with(TAP_PREFIX))
        .collect()
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
    fn only_our_taps_are_listed() {
        // `ip -o link show type tun`: two of ours, a VPN's tun, another tool's tap. Only the
        // prefix decides.
        let out =
            "7: btabcdef123456: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq master by0 state UP\n\
                   8: tun0: <POINTOPOINT,MULTICAST,NOARP,UP> mtu 1420 qdisc fq state UNKNOWN\n\
                   9: tap-docker@NONE: <BROADCAST> mtu 1500 qdisc noop state DOWN\n\
                   10: bt0123456789ab@if3: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq state UP\n";
        assert_eq!(tap_names(out), ["btabcdef123456", "bt0123456789ab"]);
        assert!(tap_names("").is_empty());
    }

    #[tokio::test]
    async fn a_port_is_waited_for_until_it_listens() {
        // A socket bound and not listening holds its port and refuses connections, so no
        // other test can take the port while this one counts on it being quiet.
        let bound = || {
            let s = tokio::net::TcpSocket::new_v4().unwrap();
            s.bind("127.0.0.1:0".parse().unwrap()).unwrap();
            s
        };
        // It listens a moment later: the wait ends once it accepts.
        let sock = bound();
        let addr = sock.local_addr().unwrap();
        let late = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let ln = sock.listen(8).unwrap();
            let _ = ln.accept().await;
        });
        wait_port(addr, Duration::from_secs(5)).await.unwrap();
        late.await.unwrap();
        // It never listens: an error at the deadline, naming the address.
        let quiet = bound();
        let addr = quiet.local_addr().unwrap();
        let t0 = std::time::Instant::now();
        let err = wait_port(addr, Duration::from_millis(500))
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .starts_with(&format!("{addr} did not accept")),
            "{err}"
        );
        assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
    }

    #[test]
    fn status_lines() {
        assert_eq!(status_code(b"HTTP/1.1 200 OK\r\nServer: x\r\n"), Some(200));
        assert_eq!(
            status_code(b"HTTP/1.0 503 Service Unavailable\r\n"),
            Some(503)
        );
        assert_eq!(status_code(b"HTTP/1.1 302\r\n"), Some(302));
        for bad in [
            &b""[..],
            b"SSH-2.0-OpenSSH\r\n",
            b"HTTP/1.1 OK\r\n",
            b"HTTP/1.1 9999 x\r\n",
        ] {
            assert_eq!(status_code(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
    }

    /// A server on loopback that answers each connection with `answer` once it read a request
    /// head, and hands the head it read to the test.
    async fn serve(answer: &'static [u8]) -> (SocketAddr, tokio::sync::mpsc::Receiver<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            while let Ok((mut c, _)) = ln.accept().await {
                let mut head = Vec::new();
                let mut buf = [0u8; 512];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut buf).await {
                        Ok(n) if n > 0 => head.extend_from_slice(&buf[..n]),
                        _ => break,
                    }
                }
                let _ = tx.send(String::from_utf8_lossy(&head).into_owned()).await;
                let _ = c.write_all(answer).await;
            }
        });
        (addr, rx)
    }

    #[tokio::test]
    async fn an_http_probe_reads_the_status_line_alone() {
        let (addr, mut heads) =
            serve(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await;
        assert_eq!(
            http_status(addr, "/healthz?full=1", Duration::from_secs(5))
                .await
                .unwrap(),
            204
        );
        let head = heads.recv().await.unwrap();
        assert!(
            head.starts_with("GET /healthz?full=1 HTTP/1.1\r\n"),
            "{head}"
        );
        assert!(head.contains(&format!("\r\nHost: {addr}\r\n")), "{head}");
        assert!(head.contains("\r\nConnection: close\r\n"), "{head}");
        // A server that answers something else is a failure that says so.
        let (addr, _) = serve(b"220 smtp ready\r\n").await;
        let err = http_status(addr, "/", Duration::from_secs(5))
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), format!("{addr}: not an HTTP answer"));
    }

    #[tokio::test]
    async fn a_probe_that_gets_no_answer_fails_at_its_timeout() {
        // A listener that accepts and never answers: the HTTP probe waits for its line.
        let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        let _held = tokio::spawn(async move {
            let mut conns = Vec::new();
            while let Ok((c, _)) = ln.accept().await {
                conns.push(c);
            }
        });
        let t0 = std::time::Instant::now();
        let err = http_status(addr, "/", Duration::from_millis(300))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no answer within"), "{err}");
        assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
        // The TCP probe is the connect alone: accepted is a pass.
        connect_once(addr, Duration::from_secs(5)).await.unwrap();
        // A port bound and not listening refuses: a failure naming the address.
        let s = tokio::net::TcpSocket::new_v4().unwrap();
        s.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let quiet = s.local_addr().unwrap();
        let err = connect_once(quiet, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(err.to_string().starts_with(&format!("{quiet}: ")), "{err}");
        let err = http_status(quiet, "/", Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(err.to_string().starts_with(&format!("{quiet}: ")), "{err}");
    }

    #[test]
    fn no_default_route() {
        for out in ["", "\n", "default via 10.0.0.1 dev"] {
            let err = default_route_device(out).unwrap_err();
            assert_eq!(err.to_string(), "no default route", "{out:?}");
        }
    }
}
