//! Read-only host prerequisites. Never drain swap, unmerge KSM or alter host services here.
use super::*;

/// A configured budget cannot manufacture RAM after system and ARC reservations.
pub(super) fn capacity_valid(physical: u32, capacity: u32, reserved: u32, arc: u32) -> bool {
    capacity > 0
        && capacity
            .checked_add(reserved)
            .and_then(|n| n.checked_add(arc))
            .is_some_and(|n| n <= physical)
}

fn swap_clear(text: &str) -> bool {
    let mut lines = text.lines();
    lines.next().is_some_and(|header| {
        header
            .split_whitespace()
            .eq(["Filename", "Type", "Size", "Used", "Priority"])
    }) && lines.all(|line| line.trim().is_empty())
}
fn ksm_clear(run: &str, shared: &str, sharing: &str) -> bool {
    [run, shared, sharing]
        .into_iter()
        .all(|s| s.trim().parse::<u64>() == Ok(0))
}
fn oomd_disabled(text: &str) -> bool {
    let lines: Vec<_> = text.lines().filter(|s| !s.trim().is_empty()).collect();
    lines.len() == 2
        && lines
            .iter()
            .all(|line| matches!(*line, "masked" | "not-found"))
}

fn ancestor_policy_safe(text: &str, units: usize) -> bool {
    let values: Vec<_> = text.lines().filter(|s| !s.trim().is_empty()).collect();
    values.len() == units && values.iter().all(|s| *s == "auto")
}

impl Manager {
    pub(super) async fn refresh_memory_host(&self) {
        if !self.inner.vmm.host_memory_checks() {
            return;
        }
        let cfg = &self.inner.cfg;
        let physical = std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|s| meminfo_total_mb(&s));
        let c = cfg.capacity;
        let reason = match physical {
            Some(mb)
                if capacity_valid(
                    mb,
                    self.capacity().memory_mb,
                    c.reserved_memory_mb,
                    arc_max_mb(),
                ) =>
            {
                None
            }
            _ => Some("physical_capacity_unverified"),
        };
        let reason = if reason.is_none() && !cfg.jailer.as_os_str().is_empty() {
            if arc_max_mb() == 0 {
                Some("arc_ceiling_unverified")
            } else {
                prerequisites().await.err()
            }
        } else {
            reason
        };
        *self.inner.memory_host.lock().unwrap() = reason;
    }

    pub(super) fn memory_condition(&self) -> api::Condition {
        let host = *self.inner.memory_host.lock().unwrap();
        let live_degraded = self.inner.machines.lock().unwrap().values().any(|e| {
            commits_memory(&e.snapshot())
                && e.memory_protection
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_some_and(|p| p.degraded.is_some())
        });
        let unjailed =
            self.inner.vmm.host_memory_checks() && self.inner.cfg.jailer.as_os_str().is_empty();
        let message = if live_degraded {
            "live_vmm_policy_unresolved"
        } else {
            host.unwrap_or(if unjailed {
                "unjailed_containment_unavailable"
            } else {
                "memory_policy_ready"
            })
        };
        let status = live_degraded || host.is_some() || unjailed;
        let mut cached = self.inner.memory_condition.lock().unwrap();
        let since = cached
            .as_ref()
            .filter(|c| c.status == status && c.message == message)
            .map_or_else(Utc::now, |c| c.since);
        let current = api::Condition {
            kind: api::condition::MEMORY_PROTECTION.into(),
            status,
            since,
            message: message.into(),
        };
        *cached = Some(current.clone());
        current
    }
}

async fn prerequisites() -> Result<(), &'static str> {
    #[cfg(target_os = "linux")]
    {
        // Verify the kernel primitive without signaling or changing any process.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) };
        if fd < 0 {
            return Err("pidfd_unavailable");
        }
        unsafe {
            libc::close(fd as i32);
        }
    }
    fn read(p: impl AsRef<Path>) -> Result<String, &'static str> {
        std::fs::read_to_string(p).map_err(|_| "host_prerequisite_unreadable")
    }
    if read("/proc/self/oom_score_adj")?.trim() != "-900" {
        return Err("supervisor_oom_preference_unset");
    }
    if !read("/sys/fs/cgroup/cgroup.controllers")?
        .split_whitespace()
        .any(|s| s == "memory")
    {
        return Err("cgroup_memory_unavailable");
    }
    if !swap_clear(&read("/proc/swaps")?) {
        return Err("host_swap_enabled");
    }
    let ksm = Path::new("/sys/kernel/mm/ksm");
    if ksm
        .try_exists()
        .map_err(|_| "host_prerequisite_unreadable")?
        && !ksm_clear(
            &read(ksm.join("run"))?,
            &read(ksm.join("pages_shared"))?,
            &read(ksm.join("pages_sharing"))?,
        )
    {
        return Err("ksm_merging_or_shared_pages");
    }
    if Path::new("/run/systemd/system")
        .try_exists()
        .map_err(|_| "host_prerequisite_unreadable")?
    {
        let states = systemd_values(
            "LoadState",
            &["systemd-oomd.service".into(), "systemd-oomd.socket".into()],
        )
        .await?;
        if !oomd_disabled(&states) {
            return Err("oomd_not_masked");
        }
        let cgroup = read("/proc/self/cgroup")?;
        let path = cgroup
            .lines()
            .find_map(|s| s.strip_prefix("0::"))
            .ok_or("cgroup_v2_unavailable")?;
        let mut units = vec!["-.slice".into()];
        for part in path
            .split('/')
            .filter(|s| s.ends_with(".slice") || s.ends_with(".service") || s.ends_with(".scope"))
        {
            if part.len() > 256 || units.len() >= 32 {
                return Err("oom_ancestor_policy_unverified");
            }
            units.push(part.to_string());
        }
        for property in ["ManagedOOMSwap", "ManagedOOMMemoryPressure"] {
            let values = systemd_values(property, &units).await?;
            if !ancestor_policy_safe(&values, units.len()) {
                return Err("oom_ancestor_policy_unresolved");
            }
        }
    } else if Path::new("/usr/lib/systemd/systemd-oomd")
        .try_exists()
        .map_err(|_| "host_prerequisite_unreadable")?
        || Path::new("/lib/systemd/systemd-oomd")
            .try_exists()
            .map_err(|_| "host_prerequisite_unreadable")?
    {
        return Err("oomd_state_unverified");
    }
    Ok(())
}

/// Fixed property names, argv units, bounded output and one deadline covering child exit.
async fn systemd_values(property: &str, units: &[String]) -> Result<String, &'static str> {
    let mut command = crate::host_process::command("systemctl");
    command
        .args(["show", "--value", &format!("--property={property}"), "--"])
        .args(units)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        use tokio::io::AsyncReadExt;
        let mut child = command.spawn().map_err(|_| "systemd_policy_unavailable")?;
        let mut out = Vec::new();
        child
            .stdout
            .take()
            .ok_or("systemd_policy_unavailable")?
            .take(8193)
            .read_to_end(&mut out)
            .await
            .map_err(|_| "systemd_policy_unavailable")?;
        let status = child
            .wait()
            .await
            .map_err(|_| "systemd_policy_unavailable")?;
        if out.len() > 8192 || (!status.success() && property != "LoadState") {
            return Err("systemd_policy_unavailable");
        }
        String::from_utf8(out).map_err(|_| "systemd_policy_unavailable")
    })
    .await;
    result.unwrap_or(Err("systemd_policy_timeout"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn physical_reservations_and_host_prerequisites_fail_closed() {
        assert!(capacity_valid(4096, 1024, 2048, 1024));
        assert!(!capacity_valid(4096, 1025, 2048, 1024));
        assert!(!capacity_valid(512, 1024, 2048, 0));
        assert!(!capacity_valid(u32::MAX, u32::MAX, 1, 0));
        assert!(!capacity_valid(4096, 0, 2048, 0));
        assert!(swap_clear("Filename Type Size Used Priority\n"));
        assert!(!swap_clear(""));
        assert!(!swap_clear("unverified header\n"));
        assert!(!swap_clear(
            "Filename Type Size Used Priority\n/swap file 100 0 -2\n"
        ));
        assert!(ksm_clear("0", "0", "0"));
        assert!(!ksm_clear("0", "0", "1"));
        assert!(!ksm_clear("1", "0", "0"));
        assert!(oomd_disabled("masked\nnot-found\n"));
        assert!(!oomd_disabled("loaded\nmasked\n"));
        assert!(!oomd_disabled("masked\n"));
        assert!(ancestor_policy_safe("auto\nauto\n", 2));
        assert!(!ancestor_policy_safe("auto\nkill\n", 2));
        assert!(!ancestor_policy_safe("auto\n", 2));
        assert!(!ancestor_policy_safe("auto\nunknown\n", 2));
    }
}
