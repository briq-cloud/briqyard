use super::*;

#[test]
fn bootstrap_config_creation_preserves_existing_operator_warm_policy() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.yaml");
    let original =
        "templates:\n  warm_pools: true\n  warm_policy:\n    max_fills: 1\n    catalog: []\n";
    std::fs::write(&config, original).unwrap();
    let block = SCRIPT
        .split("echo \"== config\"")
        .nth(1)
        .unwrap()
        .split("echo \"== api certificate\"")
        .next()
        .unwrap()
        .replace("/etc/briqyard", dir.path().to_str().unwrap());
    let staged = dir.path().join("staged");
    std::fs::create_dir(&staged).unwrap();
    let daemon = staged.join("briqyardd");
    std::fs::write(
        &daemon,
        "#!/bin/bash\nset -eu\ntest \"$1\" = --config\ncmp -s \"$EXPECTED\" \"$2\"\nprintf '%s' \"$2\" > \"$VALIDATED\"\ntest \"$REJECT\" = 0\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o755)).unwrap();
    let expected = dir.path().join("expected.yaml");
    std::fs::write(&expected, original).unwrap();
    let installed = dir.path().join("installed");
    std::fs::create_dir(&installed).unwrap();
    for name in ["briqyard", "briqyard-fleet", "briqyardd"] {
        std::fs::write(installed.join(name), "original executable").unwrap();
    }
    let validated = dir.path().join("validated");
    let run = |script: &str, reject: &str| {
        std::process::Command::new("bash")
            .args([
                "-c",
                &format!(
                    "set -eu\nruntime_config() {{ cmp -s \"$EXPECTED\" \"$1\"; }}\nfail() {{ exit 1; }}\n{script}"
                ),
            ])
            .env("new", &staged)
            .env("config_path", &config)
            .env("binary_dir", &installed)
            .env("EXPECTED", &expected)
            .env("VALIDATED", &validated)
            .env("REJECT", reject)
            .env("firecracker", "/test/firecracker")
            .env("jailer", "/test/jailer")
            .env("kernel", "/test/kernel")
            .env("init", "/test/init")
            .status()
            .unwrap()
    };
    // Exercise candidate creation and the staged daemon's validation. Runtime path
    // rewriting itself is covered by hack/test_bootstrap.py's real installer fixture.
    let preparation = block
        .split("# Retain a complete rollback set")
        .next()
        .unwrap();
    assert!(run(preparation, "0").success());
    let candidate = std::fs::read_to_string(&validated).unwrap();
    assert_ne!(std::path::Path::new(&candidate), config);
    assert_eq!(std::fs::read_to_string(&candidate).unwrap(), original);
    assert_eq!(std::fs::read_to_string(&config).unwrap(), original);
    std::fs::remove_file(&validated).unwrap();
    // Run the entire switch block with validation rejected: neither the live
    // configuration nor any installed executable may be replaced or retained.
    assert!(!run(&block, "1").success());
    assert!(
        validated.exists(),
        "the staged daemon must reject the candidate"
    );
    assert_eq!(std::fs::read_to_string(&config).unwrap(), original);
    for name in ["briqyard", "briqyard-fleet", "briqyardd"] {
        assert_eq!(
            std::fs::read_to_string(installed.join(name)).unwrap(),
            "original executable"
        );
    }
    assert!(std::fs::read_dir(dir.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("rollback.")
    }));
}

const ED25519: &str =
    "10.0.0.9 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF+69ms8S2QZ+nIzDuFQDaK1FztcJQuI5HGeuZIneF4y\n";

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
