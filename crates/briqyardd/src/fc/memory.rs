//! Per-incarnation memory policy. A failed update never invalidates positive adoption.

use briqyard_api::host_process::OomClass;

#[derive(Clone, Debug)]
pub struct MemoryProtection {
    pub charge_mb: u32,
    pub degraded: Option<&'static str>,
    pub contained: bool,
}

impl MemoryProtection {
    pub fn verified(charge_mb: u32) -> Self {
        Self {
            charge_mb,
            degraded: None,
            contained: true,
        }
    }
}

/// No record-supplied path is trusted: only one canonical leaf below the fixed parent.
#[cfg(any(target_os = "linux", test))]
fn leaf(id: &str) -> Option<String> {
    (!id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
    .then(|| format!("/{}/{}", super::CGROUP_PARENT, super::fc_id(id)))
}

/// Apply only after process ownership is established. Read the live ceiling before writes;
/// never lower it. An unknown ceiling reserves all remaining capacity and blocks admission.
pub fn enforce(
    id: &str,
    pid: u32,
    jailed: bool,
    expected_mb: u32,
    class: OomClass,
) -> MemoryProtection {
    #[cfg(target_os = "linux")]
    {
        enforce_at(
            id,
            Path::new(&format!("/proc/{pid}")),
            Path::new("/sys/fs/cgroup"),
            jailed,
            expected_mb,
            class,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (id, pid, jailed, class);
        MemoryProtection {
            charge_mb: expected_mb,
            degraded: None,
            contained: false,
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn enforce_at(
    id: &str,
    process_dir: &Path,
    cgroup_root: &Path,
    jailed: bool,
    expected_mb: u32,
    class: OomClass,
) -> MemoryProtection {
    let mut report = MemoryProtection {
        charge_mb: u32::MAX,
        degraded: Some("process_identity_unverified"),
        contained: false,
    };
    let Some(leaf) = leaf(id) else {
        return report;
    };
    let Ok(process) = ProcessRef::open(process_dir, id) else {
        return report;
    };
    if !jailed {
        report.charge_mb = expected_mb;
        report.degraded = process.score(class).err().map(|_| "oom_score_unavailable");
        return report;
    }
    report.degraded = Some("memory_policy_unavailable");
    let Ok(group) = Directory::open(&cgroup_root.join(leaf.trim_start_matches('/'))) else {
        return report;
    };
    if !process.in_group(&leaf) {
        return report;
    }
    let charge = group
        .read(c"memory.max")
        .ok()
        .and_then(|value| ceiling_mb(&value));
    report.charge_mb = charge.map_or(u32::MAX, |live| expected_mb.max(live));
    if process.score(class).is_err()
        || group.write(c"memory.oom.group", b"1").is_err()
        || group.write(c"memory.swap.max", b"0").is_err()
        || group
            .read(c"memory.oom.group")
            .ok()
            .as_deref()
            .map(str::trim)
            != Some("1")
        || group
            .read(c"memory.swap.max")
            .ok()
            .as_deref()
            .map(str::trim)
            != Some("0")
        || !process.in_group(&leaf)
    {
        return report;
    }
    let confirmed = group
        .read(c"memory.max")
        .ok()
        .and_then(|value| ceiling_mb(&value));
    report.charge_mb = match (charge, confirmed) {
        (Some(a), Some(b)) => expected_mb.max(a).max(b),
        _ => u32::MAX,
    };
    report.contained = true;
    report.degraded = if charge.is_none() || confirmed.is_none() {
        Some("live_ceiling_unverified")
    } else if group
        .read(c"memory.events.local")
        .ok()
        .and_then(|s| OomEvents::parse(&s))
        .is_none()
    {
        Some("local_oom_evidence_unavailable")
    } else if charge != Some(expected_mb) || confirmed != Some(expected_mb) {
        Some("live_ceiling_differs")
    } else if group
        .read(c"memory.swap.current")
        .ok()
        .as_deref()
        .map(str::trim)
        != Some("0")
    {
        Some("live_swap_unresolved")
    } else {
        None
    };
    report
}

#[cfg(any(target_os = "linux", test))]
fn ceiling_mb(value: &str) -> Option<u32> {
    let bytes = value.trim().parse::<u64>().ok()?;
    u32::try_from(bytes.div_ceil(1 << 20))
        .ok()
        .filter(|n| *n > 0)
}

#[cfg(any(target_os = "linux", test))]
use std::{
    ffi::CStr,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::OpenOptionsExt,
    },
    path::Path,
};

/// Directory-relative opens retain the original process even if its numeric PID is reused.
#[cfg(any(target_os = "linux", test))]
struct Directory(File);
#[cfg(any(target_os = "linux", test))]
impl Directory {
    fn open(path: &Path) -> std::io::Result<Self> {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map(Self)
    }
    fn file(&self, name: &CStr, flags: i32) -> std::io::Result<File> {
        // SAFETY: a live directory descriptor and a static, NUL-terminated relative filename.
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: openat returned a new, exclusively owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn bytes(&self, name: &CStr) -> std::io::Result<Vec<u8>> {
        let mut data = Vec::new();
        self.file(name, libc::O_RDONLY)?
            .take(16_385)
            .read_to_end(&mut data)?;
        if data.len() > 16_384 {
            return Err(std::io::Error::from_raw_os_error(libc::EOVERFLOW));
        }
        Ok(data)
    }
    fn read(&self, name: &CStr) -> std::io::Result<String> {
        String::from_utf8(self.bytes(name)?)
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))
    }
    fn write(&self, name: &CStr, value: &[u8]) -> std::io::Result<()> {
        self.file(name, libc::O_WRONLY)?.write_all(value)
    }
}

#[cfg(any(target_os = "linux", test))]
struct ProcessRef {
    dir: Directory,
    start: u64,
    id: String,
}
#[cfg(any(target_os = "linux", test))]
impl ProcessRef {
    fn open(path: &Path, id: &str) -> std::io::Result<Self> {
        let dir = Directory::open(path)?;
        if super::vmm::firecracker_id(&dir.bytes(c"cmdline")?).as_deref() != Some(id) {
            return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
        }
        let start = start_time(&dir.read(c"stat")?)
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ESRCH))?;
        Ok(Self {
            dir,
            start,
            id: id.to_string(),
        })
    }
    fn same(&self) -> bool {
        self.dir.read(c"stat").ok().and_then(|s| start_time(&s)) == Some(self.start)
            && self
                .dir
                .bytes(c"cmdline")
                .ok()
                .and_then(|s| super::vmm::firecracker_id(&s))
                .as_deref()
                == Some(self.id.as_str())
    }
    fn in_group(&self, leaf: &str) -> bool {
        self.same()
            && self
                .dir
                .read(c"cgroup")
                .is_ok_and(|s| s.lines().any(|l| l.strip_prefix("0::") == Some(leaf)))
    }
    fn score(&self, class: OomClass) -> std::io::Result<()> {
        if !self.same() {
            return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
        }
        self.dir
            .write(c"oom_score_adj", class.score().to_string().as_bytes())?;
        if !self.same() || self.dir.read(c"oom_score_adj")?.trim() != class.score().to_string() {
            return Err(std::io::Error::from_raw_os_error(libc::EIO));
        }
        Ok(())
    }
}
#[cfg(any(target_os = "linux", test))]
fn start_time(stat: &str) -> Option<u64> {
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn process(path: &Path, start: u64) {
        fs::create_dir_all(path).unwrap();
        fs::write(
            path.join("cmdline"),
            b"/usr/bin/firecracker\0--id\0m-owned\0",
        )
        .unwrap();
        fs::write(
            path.join("stat"),
            format!("1 (name with spaces) S {} {start}", "0 ".repeat(18)),
        )
        .unwrap();
        fs::write(path.join("oom_score_adj"), "000").unwrap();
        fs::write(path.join("cgroup"), "0::/firecracker/m-owned\n").unwrap();
    }
    #[test]
    fn paths_ceilings_and_start_identity_fail_closed() {
        assert_eq!(leaf("../other"), None);
        assert_eq!(ceiling_mb("max"), None);
        assert_eq!(ceiling_mb("0"), None);
        assert_eq!(ceiling_mb("402653184"), Some(384));
        assert_eq!(ceiling_mb("402653185"), Some(385));
        let tmp = tempfile::tempdir().unwrap();
        process(tmp.path(), 7);
        let p = ProcessRef::open(tmp.path(), "m_owned").unwrap();
        assert!(p.in_group("/firecracker/m-owned"));
        assert!(!p.in_group("/firecracker/m-other"));
        assert!(ProcessRef::open(tmp.path(), "m_other").is_err());
        fs::write(tmp.path().join("stat"), "1 (reuse) S 0").unwrap();
        assert!(p.score(OomClass::Machine).is_err());
        assert_eq!(
            fs::read_to_string(tmp.path().join("oom_score_adj")).unwrap(),
            "000"
        );
    }
    #[test]
    fn retained_proc_directory_never_writes_a_replacement_pid() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("123");
        process(&path, 7);
        let p = ProcessRef::open(&path, "m_owned").unwrap();
        fs::rename(&path, tmp.path().join("old")).unwrap();
        process(&path, 9);
        p.score(OomClass::Machine).unwrap();
        assert_eq!(
            fs::read_to_string(path.join("oom_score_adj")).unwrap(),
            "000"
        );
        assert_eq!(
            fs::read_to_string(tmp.path().join("old/oom_score_adj")).unwrap(),
            "500"
        );
    }
    fn cgroup(root: &Path) -> std::path::PathBuf {
        let path = root.join("firecracker/m-owned");
        fs::create_dir_all(&path).unwrap();
        for (name, value) in [
            ("memory.max", "536870912"),
            ("memory.oom.group", "0"),
            ("memory.swap.max", "0"),
            ("memory.swap.current", "0"),
            (
                "memory.events.local",
                "oom 0\noom_kill 0\noom_group_kill 0\n",
            ),
        ] {
            fs::write(path.join(name), value).unwrap();
        }
        path
    }

    #[test]
    fn leaf_controls_are_verified_and_live_ceilings_never_lowered() {
        let temp = tempfile::tempdir().unwrap();
        let proc = temp.path().join("proc");
        process(&proc, 7);
        let group = cgroup(temp.path());
        let apply = || enforce_at("m_owned", &proc, temp.path(), true, 512, OomClass::Machine);
        let healthy = apply();
        assert_eq!(healthy.charge_mb, 512);
        assert_eq!(healthy.degraded, None);
        assert!(healthy.contained);
        assert_eq!(
            fs::read_to_string(group.join("memory.oom.group")).unwrap(),
            "1"
        );
        assert_eq!(
            fs::read_to_string(group.join("memory.swap.max")).unwrap(),
            "0"
        );
        fs::write(group.join("memory.max"), "805306368").unwrap();
        let larger = apply();
        assert_eq!(larger.charge_mb, 768);
        assert_eq!(larger.degraded, Some("live_ceiling_differs"));
        assert_eq!(
            fs::read_to_string(group.join("memory.max")).unwrap(),
            "805306368"
        );
        fs::write(group.join("memory.max"), "max").unwrap();
        assert_eq!(apply().charge_mb, u32::MAX);
        assert_eq!(fs::read_to_string(group.join("memory.max")).unwrap(), "max");
        fs::write(group.join("memory.max"), "536870912").unwrap();
        fs::write(group.join("memory.swap.current"), "1").unwrap();
        assert_eq!(apply().degraded, Some("live_swap_unresolved"));
    }

    #[test]
    fn wrong_membership_missing_controls_and_write_failure_degrade_without_escape() {
        let temp = tempfile::tempdir().unwrap();
        let proc = temp.path().join("proc");
        process(&proc, 7);
        let group = cgroup(temp.path());
        let apply = || enforce_at("m_owned", &proc, temp.path(), true, 512, OomClass::Machine);
        fs::write(proc.join("cgroup"), "0::/firecracker/m-other\n").unwrap();
        assert!(apply().degraded.is_some());
        assert_eq!(
            fs::read_to_string(group.join("memory.oom.group")).unwrap(),
            "0"
        );
        assert_eq!(
            fs::read_to_string(proc.join("oom_score_adj")).unwrap(),
            "000"
        );
        fs::write(proc.join("cgroup"), "0::/firecracker/m-owned\n").unwrap();
        fs::remove_file(group.join("memory.oom.group")).unwrap();
        assert!(apply().degraded.is_some());
        fs::create_dir(group.join("memory.oom.group")).unwrap();
        assert!(apply().degraded.is_some());
        assert_eq!(
            fs::read_to_string(group.join("memory.max")).unwrap(),
            "536870912"
        );
        assert!(
            enforce_at("../other", &proc, temp.path(), true, 512, OomClass::Machine)
                .degraded
                .is_some()
        );
        let dev = enforce_at("m_owned", &proc, temp.path(), false, 512, OomClass::Machine);
        assert_eq!(dev.degraded, None);
        assert!(!dev.contained);
    }
}

/// A pidfd pins the exact incarnation for an owned-launch abort; no numeric-PID signal race.
#[cfg(target_os = "linux")]
pub struct ProcessIdentity {
    process: ProcessRef,
    pidfd: File,
}
#[cfg(target_os = "linux")]
impl ProcessIdentity {
    pub fn open(id: &str, pid: u32) -> std::io::Result<Self> {
        let process = ProcessRef::open(Path::new(&format!("/proc/{pid}")), id)?;
        // SAFETY: pidfd_open creates an owned descriptor and touches no process state.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the successful syscall returned a new descriptor.
        let pidfd = unsafe { File::from_raw_fd(fd as i32) };
        if !process.same() {
            return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
        }
        Ok(Self { process, pidfd })
    }
    pub fn kill(&self) {
        if self.process.same() {
            // SAFETY: the descriptor names only the positively identified incarnation.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
        }
    }
}

/// Abort only positively identified members of this new launch's canonical leaf.
/// A missing pidfile never authorizes an unqualified cgroup.kill or a numeric-PID signal.
#[cfg(target_os = "linux")]
pub fn abort_owned_leaf(id: &str) {
    let Some(leaf) = leaf(id) else { return };
    let Ok(group) =
        Directory::open(&Path::new("/sys/fs/cgroup").join(leaf.trim_start_matches('/')))
    else {
        return;
    };
    let Ok(members) = group.read(c"cgroup.procs") else {
        return;
    };
    for pid in members
        .split_whitespace()
        .filter_map(|s| s.parse::<u32>().ok())
    {
        if let Ok(identity) = ProcessIdentity::open(id, pid) {
            if identity.process.in_group(&leaf) {
                identity.kill();
            }
        }
    }
}

/// Local kernel counters, not a guest exit code or proof of a global OOM event.
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OomEvents {
    oom: u64,
    killed: u64,
    group_killed: u64,
}
#[cfg(any(target_os = "linux", test))]
impl OomEvents {
    fn parse(text: &str) -> Option<Self> {
        let value = |key: &str| {
            text.lines().find_map(|line| {
                let (name, value) = line.split_once(' ')?;
                (name == key).then(|| value.trim().parse().ok()).flatten()
            })
        };
        Some(Self {
            oom: value("oom")?,
            killed: value("oom_kill")?,
            group_killed: value("oom_group_kill")?,
        })
    }
    fn delta(self, before: Self) -> Option<Self> {
        Some(Self {
            oom: self.oom.checked_sub(before.oom)?,
            killed: self.killed.checked_sub(before.killed)?,
            group_killed: self.group_killed.checked_sub(before.group_killed)?,
        })
    }
    fn reason(self) -> &'static str {
        if self.oom > 0 && self.killed > 0 && self.group_killed > 0 {
            "vmm_cgroup_oom_evidence"
        } else if self.killed > 0 {
            "vmm_oom_kill_unclassified"
        } else {
            "no_local_vmm_oom_kill_observed"
        }
    }
}

/// Held from admission/adoption until exit, before lifecycle code removes the leaf.
#[cfg(target_os = "linux")]
pub struct OomEvidence {
    group: Directory,
    baseline: OomEvents,
}
#[cfg(target_os = "linux")]
impl OomEvidence {
    pub fn capture(id: &str, pid: u32) -> Option<Self> {
        let leaf = leaf(id)?;
        let process = ProcessRef::open(Path::new(&format!("/proc/{pid}")), id).ok()?;
        if !process.in_group(&leaf) {
            return None;
        }
        let group =
            Directory::open(&Path::new("/sys/fs/cgroup").join(leaf.trim_start_matches('/')))
                .ok()?;
        let baseline = OomEvents::parse(&group.read(c"memory.events.local").ok()?)?;
        process.in_group(&leaf).then_some(Self { group, baseline })
    }
    pub fn record(&self, id: &str) {
        match self
            .group
            .read(c"memory.events.local")
            .ok()
            .and_then(|s| OomEvents::parse(&s))
            .and_then(|n| n.delta(self.baseline))
        {
            Some(delta) => tracing::info!(
                machine = id,
                reason = delta.reason(),
                oom_delta = delta.oom,
                oom_kill_delta = delta.killed,
                oom_group_kill_delta = delta.group_killed,
                "VMM local memory events"
            ),
            None => tracing::warn!(
                machine = id,
                reason = "vmm_oom_evidence_unavailable",
                "VMM local memory events unreadable or reset"
            ),
        }
    }
}

#[cfg(test)]
mod event_tests {
    use super::*;
    #[test]
    fn local_evidence_is_per_incarnation_and_never_infers_guest_oom() {
        let old = OomEvents::parse("oom 5\noom_kill 3\noom_group_kill 1\n").unwrap();
        let now = OomEvents::parse("oom 6\noom_kill 5\noom_group_kill 2\n").unwrap();
        assert_eq!(now.delta(old).unwrap().reason(), "vmm_cgroup_oom_evidence");
        assert!(old.delta(now).is_none());
        let global = OomEvents {
            oom: 0,
            killed: 1,
            group_killed: 0,
        };
        assert_eq!(global.reason(), "vmm_oom_kill_unclassified");
        assert_eq!(
            global.delta(global).unwrap().reason(),
            "no_local_vmm_oom_kill_observed"
        );
        assert!(OomEvents::parse("oom_kill 2\n").is_none());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod identity_tests {
    use super::*;
    use std::os::unix::process::CommandExt;

    #[test]
    fn pidfd_abort_requires_the_exact_owned_command_and_keeps_siblings_alive() {
        let launch = || {
            let mut command = briqyard_api::host_process::command("sh");
            command
                .arg0("firecracker")
                .args(["-c", "read -r line", "--id", "m-owned"])
                .stdin(std::process::Stdio::piped());
            command.spawn().unwrap()
        };
        let mut owned = launch();
        let mut sibling = launch();
        // Ensure cleanup even if an assertion fails; Child::kill names our unreaped children.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert!(ProcessIdentity::open("m_other", owned.id()).is_err());
            let identity = ProcessIdentity::open("m_owned", owned.id()).unwrap();
            identity.kill();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while owned.try_wait().unwrap().is_none() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "owned pidfd abort timed out"
                );
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            assert!(sibling.try_wait().unwrap().is_none());
        }));
        let _ = owned.kill();
        let _ = owned.wait();
        let _ = sibling.kill();
        let _ = sibling.wait();
        if let Err(error) = result {
            std::panic::resume_unwind(error);
        }
    }
}
