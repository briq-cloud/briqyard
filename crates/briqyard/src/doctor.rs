//! `doctor`: what a host needs, checked where this runs.

/// What a host needs, checked where this runs; prints one line per check.
pub(super) fn doctor() {
    let mut bad = 0;
    let mut check = |name: &str, ok: bool, hint: &str| {
        println!(
            "{} {name}{}",
            if ok { "ok  " } else { "MISS" },
            if ok {
                String::new()
            } else {
                format!(": {hint}")
            }
        );
        if !ok {
            bad += 1;
        }
    };
    check(
        "linux",
        cfg!(target_os = "linux"),
        "briqyardd runs on Linux",
    );
    check(
        "/dev/kvm",
        std::path::Path::new("/dev/kvm").exists(),
        "no KVM: a bare-metal server, or a VM with nested virtualization",
    );
    let exists = |p: &str| std::path::Path::new(p).exists();
    let on_path = |b: &str| {
        std::env::var("PATH")
            .unwrap_or_default()
            .split(':')
            .any(|d| std::path::Path::new(d).join(b).exists())
    };
    // `zvol_id` names a zvol's device: the daemon checks every disk with it (ADR 0046).
    check(
        "zfs",
        on_path("zfs") && on_path("zpool") && exists("/usr/lib/udev/zvol_id"),
        "apt install zfsutils-linux",
    );
    check("nft", on_path("nft"), "apt install nftables");
    check("mkfs.ext4", on_path("mkfs.ext4"), "apt install e2fsprogs");
    check("ip", on_path("ip"), "apt install iproute2");
    check(
        "firecracker",
        exists("/usr/local/bin/firecracker"),
        "hack/bootstrap-host.sh downloads it",
    );
    check(
        "jailer",
        exists("/usr/local/bin/jailer"),
        "hack/bootstrap-host.sh downloads it; without it machines run as root",
    );
    check(
        "guest kernel",
        exists("/var/lib/briqyard/vmlinux"),
        "hack/bootstrap-host.sh downloads one",
    );
    check(
        "briqyard-init",
        exists("/usr/local/bin/briqyard-init"),
        "make init; install the static binary",
    );
    check(
        "cgroup v2",
        exists("/sys/fs/cgroup/cgroup.controllers"),
        "the jailer needs the unified cgroup hierarchy",
    );
    check(
        "ip_forward",
        std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .map(|s| s.trim() == "1")
            .unwrap_or(false),
        "the daemon turns it on at start",
    );
    let pool = std::process::Command::new("zpool")
        .args(["list", "-H", "-o", "name"])
        .output();
    let (pool_ok, pool_hint) = match &pool {
        Ok(o) if o.status.success() => (
            !String::from_utf8_lossy(&o.stdout).trim().is_empty(),
            "zpool create byard <device>",
        ),
        Ok(_) => (
            true,
            "zpool needs root to answer: `sudo briqyard doctor` checks the pool",
        ),
        Err(_) => (false, "apt install zfsutils-linux"),
    };
    check("a zfs pool", pool_ok, pool_hint);
    // What would restart the daemon or the host outside a planned upgrade (ADR 0050): a
    // warning, the host works.
    let warn = |name: &str, ok: bool, hint: &str| {
        if ok {
            println!("ok   {name}");
        } else {
            println!("warn {name}: {hint}");
        }
    };
    if exists("/usr/sbin/needrestart") {
        warn(
            "needrestart spares briqyardd",
            needrestart_spares_daemon(&needrestart_confs(std::path::Path::new("/etc/needrestart"))),
            "after a library update it restarts briqyardd, which suspends every machine: \
             hack/bootstrap-host.sh writes /etc/needrestart/conf.d/briqyard.conf",
        );
    }
    if let Ok(o) = std::process::Command::new("apt-config")
        .args(["shell", "R", "Unattended-Upgrade::Automatic-Reboot/b"])
        .output()
    {
        warn(
            "no automatic reboot",
            !reboots_on_its_own(&String::from_utf8_lossy(&o.stdout)),
            "unattended-upgrades reboots the host, machines and all: \
             set Unattended-Upgrade::Automatic-Reboot \"false\" and reboot after a drain",
        );
    }
    if bad > 0 {
        eprintln!("{bad} missing");
        std::process::exit(1);
    }
}

/// needrestart's configuration in the order it evaluates it: `needrestart.conf`, then each
/// `conf.d/*.conf` by name.
pub(super) fn needrestart_confs(dir: &std::path::Path) -> Vec<String> {
    let mut snippets: Vec<_> = std::fs::read_dir(dir.join("conf.d"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "conf"))
        .collect();
    snippets.sort();
    std::iter::once(dir.join("needrestart.conf"))
        .chain(snippets)
        .map(|p| std::fs::read_to_string(p).unwrap_or_default())
        .collect()
}

/// Whether needrestart's configuration (its file, then each `conf.d` snippet in name order)
/// keeps it from restarting the daemon: the last `override_rc` entry whose pattern matches
/// `briqyardd.service` is 0, as `$nrconf{override_rc}{qr(^briqyardd\.service$)} = 0;` or, in
/// the file's hash, `qr(^briqyard) => 0,`. A hash assigned again forgets the entries before it.
pub(super) fn needrestart_spares_daemon(confs: &[String]) -> bool {
    let mut spared = None;
    let mut in_hash = false;
    for l in confs.iter().flat_map(|c| c.lines()).map(str::trim_start) {
        if l.starts_with('#') {
            continue;
        }
        if l.starts_with("$nrconf{override_rc}") && l.contains("= {") {
            (in_hash, spared) = (true, None);
            continue;
        }
        if in_hash && l.starts_with('}') {
            in_hash = false;
            continue;
        }
        if !in_hash && !l.starts_with("$nrconf{override_rc}{") {
            continue;
        }
        let Some((pattern, rest)) = l.split_once("qr(").and_then(|(_, r)| r.split_once(')')) else {
            continue;
        };
        let value = rest.rsplit('=').next().unwrap_or("");
        let value = value.trim_start_matches('>').trim_start();
        if pattern_matches_daemon(pattern) && value.starts_with(|c: char| c.is_ascii_digit()) {
            spared = Some(value.starts_with('0'));
        }
    }
    spared == Some(true)
}

/// Whether a needrestart pattern (inside `qr(...)`) matches `briqyardd.service`. Literal
/// patterns only, with `^`, `$` and `.` or `\.`; any other regex is not counted as a match.
pub(super) fn pattern_matches_daemon(pattern: &str) -> bool {
    let unit = "briqyardd.service";
    let (start, p) = pattern
        .strip_prefix('^')
        .map_or((false, pattern), |p| (true, p));
    let (end, p) = p.strip_suffix('$').map_or((false, p), |p| (true, p));
    let p = p.replace("\\.", ".");
    if p.contains(|c: char| "\\^$*+?()[]{}|".contains(c)) {
        return false;
    }
    match (start, end) {
        (true, true) => unit == p,
        (true, false) => unit.starts_with(&p),
        (false, true) => unit.ends_with(&p),
        (false, false) => unit.contains(&p),
    }
}

/// Whether `apt-config shell R Unattended-Upgrade::Automatic-Reboot/b` says unattended-upgrades
/// reboots the host after an update. Unset prints nothing: false, its default.
pub(super) fn reboots_on_its_own(apt_config: &str) -> bool {
    apt_config.trim() == "R='true'"
}
