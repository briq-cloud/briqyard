//! Privileged identity reset, before any workload or exec can run.
use super::*;
use futures::TryStreamExt;
use guest::{CloneConfigure, CloneIdentity};
use netlink_packet_route::route::RouteAttribute;

/// Keep the builder unaddressed and identity-free. Host TAP quarantine is also required.
pub(super) async fn prepare_builder() -> Result<()> {
    reset_network(None).await?;
    remove_identity_files()?;
    replace("/etc/machine-id", b"")?;
    Ok(())
}

pub(super) async fn configure(c: &CloneConfigure) -> Result<CloneIdentity> {
    c.validate().map_err(|e| anyhow!(e))?;
    reset_network(Some(c.mac)).await?;
    reseed(&c.entropy)?;
    set_clock(c.realtime_sec)?;
    remove_identity_files()?;
    let machine_id = hex::encode(random_id()?);
    replace("/etc/machine-id", format!("{machine_id}\n").as_bytes())?;
    // dbus may use either a link or a separate file. Reconcile both to the fresh identity.
    if Path::new("/var/lib/dbus").is_dir() {
        replace(
            "/var/lib/dbus/machine-id",
            format!("{machine_id}\n").as_bytes(),
        )?;
    }
    nix::unistd::sethostname(&c.hostname).context("clone hostname")?;
    replace("/etc/hostname", format!("{}\n", c.hostname).as_bytes())?;
    let cfg = Config {
        hostname: c.hostname.clone(),
        ip: c.ip.clone(),
        gateway: c.gateway.clone(),
        dns: c.dns.clone(),
        ..Default::default()
    };
    replace("/etc/hosts", hosts_text(&cfg).as_bytes())?;
    replace("/etc/resolv.conf", resolv_text(&cfg).as_bytes())?;
    setup_network(&cfg).await?;
    let effective = fs::read_to_string("/sys/class/net/eth0/address")?;
    let wanted = c
        .mac
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    anyhow::ensure!(effective.trim() == wanted, "effective clone MAC mismatch");
    // This profile permits no SSH listener or inherited keys. SSH recipes must add a
    // qualified key-generation step before their activation can be supported.
    Ok(CloneIdentity {
        generation: c.generation.clone(),
        hostname: c.hostname.clone(),
        ip: c.ip.clone(),
        mac: c.mac,
        machine_id,
    })
}

async fn reset_network(mac: Option<[u8; 6]>) -> Result<()> {
    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);
    let eth = handle
        .link()
        .get()
        .match_name("eth0".into())
        .execute()
        .try_next()
        .await?
        .ok_or_else(|| anyhow!("eth0 missing at clone barrier"))?;
    let index = eth.header.index;
    handle
        .link()
        .set(index)
        .down()
        .execute()
        .await
        .context("quarantine eth0")?;
    // Avoid generating an IPv6 link-local identity between reset and activation.
    fs::write("/proc/sys/net/ipv6/conf/eth0/disable_ipv6", b"1")
        .context("disable inherited/autoconfigured IPv6")?;
    for family in [rtnetlink::IpVersion::V4, rtnetlink::IpVersion::V6] {
        let routes: Vec<_> = handle.route().get(family).execute().try_collect().await?;
        for route in routes {
            if route
                .attributes
                .iter()
                .any(|a| matches!(a, RouteAttribute::Oif(i) if *i == index))
            {
                handle
                    .route()
                    .del(route)
                    .execute()
                    .await
                    .context("remove inherited route")?;
            }
        }
    }
    let neighbours: Vec<_> = handle.neighbours().get().execute().try_collect().await?;
    for neighbour in neighbours {
        if neighbour.header.ifindex == index {
            handle
                .neighbours()
                .del(neighbour)
                .execute()
                .await
                .context("remove inherited neighbour")?;
        }
    }
    let addresses: Vec<_> = handle
        .address()
        .get()
        .set_link_index_filter(index)
        .execute()
        .try_collect()
        .await?;
    for address in addresses {
        handle
            .address()
            .del(address)
            .execute()
            .await
            .context("remove inherited address")?;
    }
    if let Some(mac) = mac {
        handle
            .link()
            .set(index)
            .address(mac.to_vec())
            .execute()
            .await
            .context("unique effective MAC")?;
    }
    Ok(())
}

/// Linux random(4) privileged APIs: credit trusted host entropy, then force CRNG reseed.
fn reseed(entropy: &[u8; 32]) -> Result<()> {
    #[repr(C)]
    struct RandomPoolInfo {
        entropy_count: libc::c_int,
        buf_size: libc::c_int,
        bytes: [u8; 32],
    }
    let random = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/random")?;
    let info = RandomPoolInfo {
        entropy_count: 256,
        buf_size: 32,
        bytes: *entropy,
    };
    // _IOW('R', 0x03, int[2]); fixed Linux UAPI size, not sizeof(RandomPoolInfo).
    if unsafe { libc::ioctl(random.as_raw_fd(), 0x4008_5203, &info) } < 0 {
        return Err(std::io::Error::last_os_error()).context("credit host entropy");
    }
    if unsafe { libc::ioctl(random.as_raw_fd(), 0x5207) } < 0 {
        return Err(std::io::Error::last_os_error()).context("force kernel CRNG reseed");
    }
    Ok(())
}

fn random_id() -> Result<[u8; 16]> {
    let mut bytes = [0u8; 16];
    let mut filled = 0;
    while filled < bytes.len() {
        let n = unsafe {
            libc::getrandom(bytes[filled..].as_mut_ptr().cast(), bytes.len() - filled, 0)
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e).context("fresh machine ID randomness");
        }
        anyhow::ensure!(n > 0, "getrandom returned zero");
        filled += n as usize;
    }
    Ok(bytes)
}

fn set_clock(seconds: u64) -> Result<()> {
    let time = libc::timespec {
        tv_sec: seconds as _,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &time) } != 0 {
        return Err(std::io::Error::last_os_error()).context("clone realtime clock");
    }
    Ok(())
}

fn remove_identity_files() -> Result<()> {
    for path in [
        "/etc/machine-id",
        "/var/lib/dbus/machine-id",
        "/var/lib/systemd/random-seed",
        "/var/lib/urandom/random-seed",
    ] {
        remove_if_present(Path::new(path))?;
    }
    match fs::read_dir("/etc/ssh") {
        Ok(entries) => {
            for entry in entries {
                let entry = entry?;
                if entry
                    .file_name()
                    .to_str()
                    .is_some_and(|s| s.starts_with("ssh_host_"))
                {
                    remove_if_present(&entry.path())?;
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
fn remove_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("remove identity {}", path.display())),
    }
}
fn replace(path: &str, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = Path::new(path);
    let tmp = path.with_extension("briqyard-identity");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    fs::File::open(
        path.parent()
            .ok_or_else(|| anyhow!("identity path has no parent"))?,
    )?
    .sync_all()?;
    Ok(())
}
