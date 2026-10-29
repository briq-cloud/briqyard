use super::*;

impl Config {
    pub(super) fn validate(&self) -> Result<()> {
        if self.storage.backend != "zfs" {
            bail!(
                "storage.backend: {:?} is not supported (zfs)",
                self.storage.backend
            );
        }
        if self.storage.pool.is_empty() {
            bail!("storage.pool is required");
        }
        self.key_source()?;
        self.mirrors()?;
        if self.root_disk_gb < 1 {
            bail!("root_disk_gb must be at least 1");
        }
        if self.usage_keep_days < 1 {
            bail!("usage_keep_days must be at least 1");
        }
        if self.events_keep_days < 1 {
            bail!("events_keep_days must be at least 1");
        }
        if self.console_max_mb < 1 {
            bail!("console_max_mb must be at least 1");
        }
        if !(1..=100).contains(&self.conditions.memory_pct) {
            bail!("conditions.memory_pct: a share of capacity, 1 to 100");
        }
        if self.conditions.disk_free_pct > 99 {
            bail!("conditions.disk_free_pct: a share of the pool, 0 to 99");
        }
        for (name, p) in [
            ("firecracker", &self.firecracker),
            ("kernel", &self.kernel),
            ("init", &self.init),
        ] {
            if !p.is_absolute() {
                bail!("{name} must be an absolute path");
            }
        }
        for c in &self.ingress.allowed_clients {
            netw::cidr(c).with_context(|| format!("ingress.allowed_clients {c:?}"))?;
        }
        self.check_host_ports()?;
        if let Err(e) = self.egress_limits.view().check() {
            bail!("egress_limits.{e}");
        }
        // The largest size's limits must be ones a machine could ask for.
        let largest = self.disk_limits.with(32, &api::DiskLimits::default());
        if let Err(e) = largest.view().check() {
            bail!("disk_limits: for 32 vCPUs, {e}");
        }
        self.backup.check()?;
        self.check_fleet_url()?;
        self.check_exposure()?;
        self.check_advertise()
    }

    /// A host port is a service of the host's own: never one of the daemon's, which machines
    /// must not reach, nor the gateway's DNS, which they reach already.
    pub(super) fn check_host_ports(&self) -> Result<()> {
        let daemon =
            netw::nft::daemon_ports(&self.listen, &self.ingress.http, &self.ingress.tcp_ports)?;
        let daemons = |p: u16| {
            daemon.iter().any(|d| {
                let (lo, hi) = d.split_once('-').unwrap_or((d, d));
                (lo.parse().unwrap_or(0)..=hi.parse().unwrap_or(0)).contains(&p)
            })
        };
        for &p in &self.network.host_ports {
            let why = match p {
                0 => "not a port",
                53 => "the gateway's DNS",
                _ if daemons(p) => "one of the daemon's",
                _ => continue,
            };
            bail!("network.host_ports: {p} is {why}: list ports of the host's own services");
        }
        Ok(())
    }

    /// The host's token goes to `fleet.url` with every heartbeat, and the pool's key comes back
    /// from it (ADR 0026): plain HTTP only to a loopback or private address.
    pub(super) fn check_fleet_url(&self) -> Result<()> {
        let Some(url) = self.fleet.as_ref().map(|f| f.url.as_str()) else {
            return Ok(());
        };
        let Some(rest) = url.strip_prefix("http://") else {
            return Ok(());
        };
        let host = rest.split(['/', '?']).next().unwrap_or("");
        let host = match host.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => h,
            _ => host,
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        match host.parse::<IpAddr>() {
            Ok(ip) if netw::is_private(ip) => Ok(()),
            _ => bail!(
                "fleet.url: {url} is plain HTTP to an address the internet could reach: the \
                 host's token and its pool's key would cross it in clear. Write https://, or a \
                 loopback or private address"
            ),
        }
    }

    /// The fleet dials `fleet.advertise` as written: its scheme must be the API's.
    pub(super) fn check_advertise(&self) -> Result<()> {
        let Some(f) = &self.fleet else { return Ok(()) };
        if f.advertise.is_empty() {
            return Ok(());
        }
        let want = if self.serves_tls() { "https" } else { "http" };
        if !f.advertise.starts_with(&format!("{want}://")) {
            bail!(
                "fleet.advertise: {} but the API serves {} on {}: write {want}://…",
                f.advertise,
                if self.serves_tls() {
                    "TLS"
                } else {
                    "plain HTTP"
                },
                self.listen
            );
        }
        Ok(())
    }

    /// Refuses an address the internet could reach when nothing says who may connect
    /// (ADR 0012): `ingress.allowed_clients` becomes the firewall, or `ingress.allow_public`
    /// says the operator has one.
    pub(super) fn check_exposure(&self) -> Result<()> {
        let listen: SocketAddr = self
            .listen
            .parse()
            .with_context(|| format!("listen {:?}: want address:port", self.listen))?;
        let bind: IpAddr =
            self.ingress.bind.parse().with_context(|| {
                format!("ingress.bind {:?}: want an address", self.ingress.bind)
            })?;
        let mut binds = vec![("listen", listen.ip()), ("ingress.bind", bind)];
        if !self.ingress.http.is_empty() {
            let http: SocketAddr = self.ingress.http.parse().with_context(|| {
                format!("ingress.http {:?}: want address:port", self.ingress.http)
            })?;
            binds.push(("ingress.http", http.ip()));
        }
        if !self.ingress.allowed_clients.is_empty() || self.ingress.allow_public {
            return Ok(());
        }
        for (field, ip) in binds {
            if !netw::is_private(ip) {
                bail!(
                    "{field}: {ip} is reachable from outside the host: set ingress.allowed_clients \
                     to the networks that may connect, or ingress.allow_public: true if a \
                     firewall of your own keeps the daemon's ports from the internet"
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::config::testutil::load;

    /// The token and the pool's key never cross the internet in clear (ADR 0026).
    #[test]
    fn a_plain_fleet_url_is_private_or_loopback() {
        for ok in [
            "https://fleet.example",
            "http://127.0.0.1:7430",
            "http://10.0.0.2:7430/",
            "http://192.168.64.1:7430",
            "http://[::1]:7430",
        ] {
            load(&format!("fleet:\n  url: {ok}\n")).unwrap_or_else(|e| panic!("{ok}: {e:#}"));
        }
        for bad in [
            "http://203.0.113.5:7430",
            "http://fleet.example",
            "http://8.8.8.8",
        ] {
            let err = load(&format!("fleet:\n  url: {bad}\n")).unwrap_err();
            assert!(
                format!("{err:#}").contains("plain HTTP to an address"),
                "{bad}: {err:#}"
            );
        }
    }

    #[test]
    fn validation() {
        let err = load("storage:\n  backend: btrfs\n").unwrap_err();
        assert!(err.to_string().contains("storage.backend"), "{err}");
        assert!(err.to_string().contains("btrfs"), "{err}");

        let err = load("storage:\n  pool: \"\"\n").unwrap_err();
        assert!(
            err.to_string().contains("storage.pool is required"),
            "{err}"
        );

        let err = load("root_disk_gb: 0\n").unwrap_err();
        assert!(err.to_string().contains("root_disk_gb"), "{err}");
        let err = load("usage_keep_days: 0\n").unwrap_err();
        assert_eq!(err.to_string(), "usage_keep_days must be at least 1");
        let err = load("events_keep_days: 0\n").unwrap_err();
        assert_eq!(err.to_string(), "events_keep_days must be at least 1");
        let err = load("console_max_mb: 0\n").unwrap_err();
        assert_eq!(err.to_string(), "console_max_mb must be at least 1");
        for yaml in [
            "conditions:\n  memory_pct: 0\n",
            "conditions:\n  memory_pct: 101\n",
        ] {
            let err = load(yaml).unwrap_err();
            assert_eq!(
                err.to_string(),
                "conditions.memory_pct: a share of capacity, 1 to 100"
            );
        }
        let err = load("conditions:\n  disk_free_pct: 100\n").unwrap_err();
        assert_eq!(
            err.to_string(),
            "conditions.disk_free_pct: a share of the pool, 0 to 99"
        );
        // One threshold set keeps the other's default.
        let c = load("conditions:\n  disk_free_pct: 0\n").unwrap();
        assert_eq!(
            (c.conditions.memory_pct, c.conditions.disk_free_pct),
            (95, 0)
        );
        let err = load("egress_limits:\n  blocked_ports: [0]\n").unwrap_err();
        assert_eq!(
            err.to_string(),
            "egress_limits.blocked_ports: 0 is not a port"
        );
        let err = load("egress_limits:\n  bandwidth_mbit: 200000\n").unwrap_err();
        assert_eq!(
            err.to_string(),
            "egress_limits.bandwidth_mbit: at most 100000"
        );

        for (field, yaml) in [
            ("firecracker", "firecracker: bin/firecracker\n"),
            ("kernel", "kernel: vmlinux\n"),
            ("init", "init: ./briqyard-init\n"),
        ] {
            let err = load(yaml).unwrap_err();
            assert_eq!(err.to_string(), format!("{field} must be an absolute path"));
        }
        // The jailer may stay empty (no jail) and is not checked for an absolute path here.
        load("jailer: \"\"\n").unwrap();

        for (yaml, want) in [
            (
                "registry_mirrors:\n  docker.io: 10.0.0.2:7440\n",
                "registry_mirrors.docker.io: \"10.0.0.2:7440\": want http:// or https://",
            ),
            (
                "registry_mirrors:\n  docker.io: https://m.internal/docker\n",
                "registry_mirrors.docker.io: \"https://m.internal/docker\": a mirror is a host and a port, with no path",
            ),
            (
                "registry_mirrors:\n  https://docker.io: https://m.internal\n",
                "registry_mirrors.https://docker.io: \"https://docker.io\" is not a registry name (docker.io, ghcr.io)",
            ),
        ] {
            assert_eq!(format!("{:#}", load(yaml).unwrap_err()), want);
        }
        let m = load("registry_mirrors:\n  ghcr.io: https://m.internal:5000/\n").unwrap();
        assert_eq!(
            m.mirrors().unwrap()[0],
            crate::image::Mirror {
                registry: "ghcr.io".into(),
                host: "m.internal:5000".into(),
                plain_http: false,
            }
        );
    }

    #[test]
    fn host_ports_are_never_the_daemons() {
        for (yaml, why) in [
            ("network:\n  host_ports: [0]\n", "0 is not a port"),
            ("network:\n  host_ports: [53]\n", "53 is the gateway's DNS"),
            (
                "network:\n  host_ports: [443, 7420]\n",
                "7420 is one of the daemon's",
            ),
            (
                "ingress:\n  http: 127.0.0.1:8080\nnetwork:\n  host_ports: [8080]\n",
                "8080 is one of the daemon's",
            ),
            (
                "network:\n  host_ports: [31000]\n",
                "31000 is one of the daemon's",
            ),
            // The endpoint range before ADR 0028 held MongoDB's port, an edge's listener.
            (
                "ingress:\n  tcp_ports: 20000-29999\nnetwork:\n  host_ports: [443, 27017]\n",
                "27017 is one of the daemon's",
            ),
        ] {
            let err = load(yaml).unwrap_err().to_string();
            assert_eq!(
                err,
                format!("network.host_ports: {why}: list ports of the host's own services"),
                "{yaml:?}"
            );
        }
        // 8080 is the HTTP ingress's only when it is on.
        let c = load("network:\n  host_ports: [80, 443, 8080, 5432, 27017]\n").unwrap();
        assert_eq!(c.network.host_ports, [80, 443, 8080, 5432, 27017]);
    }

    #[test]
    fn a_public_bind_is_refused_unless_someone_says_who_may_connect() {
        // Endpoints are the entry to every namespace: `bind: 0.0.0.0` alone is refused.
        let err = load("ingress:\n  bind: 0.0.0.0\n").unwrap_err().to_string();
        assert!(
            err.starts_with("ingress.bind: 0.0.0.0 is reachable"),
            "{err}"
        );
        assert!(err.contains("ingress.allowed_clients"), "{err}");
        assert!(err.contains("ingress.allow_public"), "{err}");

        for (yaml, field) in [
            (
                "listen: 0.0.0.0:7420\ningress:\n  bind: 127.0.0.1\n",
                "listen: 0.0.0.0",
            ),
            (
                "listen: \"[::]:7420\"\ningress:\n  bind: 127.0.0.1\n",
                "listen: ::",
            ),
            (
                "listen: 203.0.113.5:7420\ningress:\n  bind: 10.0.0.5\n",
                "listen: 203.0.113.5",
            ),
            (
                "ingress:\n  bind: 203.0.113.5\n",
                "ingress.bind: 203.0.113.5",
            ),
            (
                "ingress:\n  bind: 10.0.0.5\n  http: 0.0.0.0:8080\n",
                "ingress.http: 0.0.0.0",
            ),
        ] {
            let err = load(yaml).unwrap_err().to_string();
            assert!(err.starts_with(field), "{yaml:?}: {err}");
        }
        // Private addresses need nothing: loopback, RFC 1918, carrier-grade NAT.
        for bind in [
            "127.0.0.1",
            "10.0.0.5",
            "172.16.0.5",
            "192.168.64.3",
            "100.64.0.1",
        ] {
            load(&format!("ingress:\n  bind: {bind}\n  http: {bind}:8080\n")).unwrap();
        }
        // Either field lifts the refusal.
        load("ingress:\n  allowed_clients: [10.0.0.0/8]\n").unwrap();
        load("listen: 0.0.0.0:7420\ningress:\n  http: 0.0.0.0:8080\n  allow_public: true\n")
            .unwrap();
    }

    #[test]
    fn addresses_and_client_networks_are_checked_by_name() {
        for (yaml, msg) in [
            (
                "listen: localhost:7420\n",
                "listen \"localhost:7420\": want address:port",
            ),
            (
                "ingress:\n  bind: \"\"\n",
                "ingress.bind \"\": want an address",
            ),
            (
                "ingress:\n  bind: 127.0.0.1\n  http: 8080\n",
                "ingress.http \"8080\": want address:port",
            ),
            (
                "ingress:\n  allowed_clients: [10.0.0.0/33]\n",
                "ingress.allowed_clients \"10.0.0.0/33\"",
            ),
            (
                "ingress:\n  allowed_clients: [fd00::/8]\n",
                "ingress.allowed_clients \"fd00::/8\"",
            ),
        ] {
            let err = format!("{:#}", load(yaml).unwrap_err());
            assert!(err.contains(msg), "{yaml:?}: {err}");
        }
    }

    #[test]
    fn fleet_advertise_has_the_apis_scheme() {
        let base = "listen: 10.0.0.5:7420\n";
        load(&format!(
            "{base}fleet:\n  url: https://fleet\n  advertise: https://10.0.0.5:7420\n"
        ))
        .unwrap();
        let err = load(&format!(
            "{base}fleet:\n  url: https://fleet\n  advertise: http://10.0.0.5:7420\n"
        ))
        .unwrap_err()
        .to_string();
        assert_eq!(
            err,
            "fleet.advertise: http://10.0.0.5:7420 but the API serves TLS on 10.0.0.5:7420: write https://…"
        );
        // A plain API (loopback, a host forwarded by its operator) advertises http.
        let err = load("fleet:\n  advertise: https://192.168.64.1:27420\n")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("serves plain HTTP on 127.0.0.1:7420: write http://"),
            "{err}"
        );
        load("fleet:\n  advertise: http://192.168.64.1:27420\n").unwrap();
        load("listen: 10.0.0.5:7420\napi_tls: false\nfleet:\n  advertise: http://10.0.0.5:7420\n")
            .unwrap();
    }
}
