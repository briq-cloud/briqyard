use super::*;

pub(super) fn setup_names(cfg: &Config) {
    if !cfg.hostname.is_empty() {
        let _ = nix::unistd::sethostname(&cfg.hostname);
        let _ = fs::write("/etc/hostname", format!("{}\n", cfg.hostname));
    }
    let _ = fs::write("/etc/hosts", hosts_text(cfg));
    let _ = fs::write("/etc/resolv.conf", resolv_text(cfg));
}

/// /etc/hosts: loopback, the machine's own name on its address, then the config's entries.
pub(super) fn hosts_text(cfg: &Config) -> String {
    let mut hosts =
        String::from("127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n");
    if let Some((ip, _)) = cfg.ip.split_once('/') {
        if !cfg.hostname.is_empty() {
            hosts.push_str(&format!("{ip}\t{}\n", cfg.hostname));
        }
    }
    for (name, addr) in &cfg.hosts {
        hosts.push_str(&format!("{addr}\t{name}\n"));
    }
    hosts
}

/// /etc/resolv.conf: the config's servers, `.internal` as the search domain.
pub(super) fn resolv_text(cfg: &Config) -> String {
    let mut resolv = String::new();
    for d in &cfg.dns {
        resolv.push_str(&format!("nameserver {d}\n"));
    }
    resolv.push_str("search internal\noptions ndots:1\n");
    resolv
}

pub(super) async fn setup_network(cfg: &Config) -> Result<()> {
    use futures::TryStreamExt;
    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);
    if let Some(lo) = handle
        .link()
        .get()
        .match_name("lo".into())
        .execute()
        .try_next()
        .await?
    {
        let _ = handle.link().set(lo.header.index).up().execute().await;
    }
    if cfg.ip.is_empty() {
        return Ok(());
    }
    let mut eth = None;
    for _ in 0..50 {
        eth = handle
            .link()
            .get()
            .match_name("eth0".into())
            .execute()
            .try_next()
            .await
            .ok()
            .flatten();
        if eth.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let eth = eth.ok_or_else(|| anyhow!("eth0 did not appear"))?;
    let index = eth.header.index;
    let (ip, prefix) = cfg
        .ip
        .split_once('/')
        .ok_or_else(|| anyhow!("ip {:?}: want CIDR", cfg.ip))?;
    let ip: std::net::Ipv4Addr = ip.parse()?;
    let prefix: u8 = prefix.parse()?;
    if let Err(e) = handle
        .address()
        .add(index, ip.into(), prefix)
        .execute()
        .await
    {
        if !e.to_string().contains("exists") {
            return Err(anyhow!("address: {e}"));
        }
    }
    handle
        .link()
        .set(index)
        .up()
        .execute()
        .await
        .context("eth0 up")?;
    if !cfg.gateway.is_empty() {
        let gw: std::net::Ipv4Addr = cfg.gateway.parse()?;
        if let Err(e) = handle
            .route()
            .add()
            .v4()
            .gateway(gw)
            .output_interface(index)
            .execute()
            .await
        {
            if !e.to_string().contains("exists") {
                return Err(anyhow!("default route: {e}"));
            }
        }
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    // --- names ---

    #[test]
    fn hosts_file() {
        let mut cfg = Config {
            hostname: "db".into(),
            ip: "10.64.1.2/24".into(),
            ..Default::default()
        };
        cfg.hosts
            .insert("cache.internal".into(), "10.64.1.3".into());
        cfg.hosts.insert("api.internal".into(), "10.64.1.4".into());
        assert_eq!(
            hosts_text(&cfg),
            "127.0.0.1\tlocalhost\n\
             ::1\tlocalhost ip6-localhost ip6-loopback\n\
             10.64.1.2\tdb\n\
             10.64.1.4\tapi.internal\n\
             10.64.1.3\tcache.internal\n"
        );
        // No address, or no name: the machine's own line is left out.
        let cfg = Config {
            hostname: "db".into(),
            ..Default::default()
        };
        assert_eq!(
            hosts_text(&cfg),
            "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n"
        );
        let cfg = Config {
            ip: "10.64.1.2/24".into(),
            ..Default::default()
        };
        assert!(!hosts_text(&cfg).contains("10.64.1.2"));
    }

    #[test]
    fn resolv_conf() {
        let cfg = Config {
            dns: vec!["10.64.1.1".into(), "1.1.1.1".into()],
            ..Default::default()
        };
        assert_eq!(
            resolv_text(&cfg),
            "nameserver 10.64.1.1\nnameserver 1.1.1.1\nsearch internal\noptions ndots:1\n"
        );
        assert_eq!(
            resolv_text(&Config::default()),
            "search internal\noptions ndots:1\n"
        );
    }
}
