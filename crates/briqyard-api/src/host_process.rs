//! Host child-process OOM inheritance. Not part of the guest protocol.

#[cfg(target_os = "linux")]
use nix::libc;
use std::{ffi::OsStr, process::Command as StdCommand};

/// Fixed runtime-owned roles; callers cannot supply an arbitrary score.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OomClass {
    Helper,
    Machine,
    Gateway,
}

impl OomClass {
    pub const fn score(self) -> i16 {
        match self {
            Self::Helper => 0,
            Self::Machine => 500,
            Self::Gateway => 250,
        }
    }

    #[cfg(target_os = "linux")]
    const fn bytes(self) -> &'static [u8] {
        match self {
            Self::Helper => b"0",
            Self::Machine => b"500",
            Self::Gateway => b"250",
        }
    }
}

/// Ordinary host helpers must not inherit the supervisor's protected score.
pub fn command(program: impl AsRef<OsStr>) -> StdCommand {
    let mut command = StdCommand::new(program);
    set_class(&mut command, OomClass::Helper);
    command
}

/// Install before spawning: the jailer forks the VMM and drops credentials afterward.
/// Failure aborts exec. Only static bytes and async-signal-safe syscalls run after fork.
pub fn set_class(command: &mut StdCommand, class: OomClass) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        let bytes = class.bytes();
        // SAFETY: no allocation, locks, formatting or logging in the child.
        unsafe {
            command.pre_exec(move || {
                let fd = libc::open(
                    c"/proc/self/oom_score_adj".as_ptr(),
                    libc::O_WRONLY | libc::O_CLOEXEC,
                );
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let mut offset = 0;
                let result = loop {
                    let n =
                        libc::write(fd, bytes.as_ptr().add(offset).cast(), bytes.len() - offset);
                    if n < 0 {
                        let error = std::io::Error::last_os_error();
                        if error.raw_os_error() == Some(libc::EINTR) {
                            continue;
                        }
                        break Err(error);
                    }
                    if n == 0 {
                        break Err(std::io::Error::from_raw_os_error(libc::EIO));
                    }
                    offset += n as usize;
                    if offset == bytes.len() {
                        break Ok(());
                    }
                };
                libc::close(fd);
                result
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (command, class);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_helper_unit_has_no_supervisor_protection() {
        let bootstrap = include_str!("../../../hack/bootstrap-host.sh");
        let firewall = bootstrap
            .split("cat > /etc/systemd/system/briqyard-firewall.service <<'EOF'\n")
            .nth(1)
            .unwrap()
            .split("\nEOF")
            .next()
            .unwrap();
        assert!(firewall.contains("ExecStart=/usr/sbin/nft"));
        assert!(!firewall.contains("OOMScoreAdjust=-900"));
        assert!(!firewall.contains("OOMPolicy=continue"));
    }

    #[test]
    fn bootstrap_checks_stop_results_and_positive_inactive_evidence() {
        let bootstrap = include_str!("../../../hack/bootstrap-host.sh");
        let start =
            "for unit in systemd-oomd.service systemd-oomd.socket ksm.service ksmtuned.service; do";
        let block = bootstrap
            .split(start)
            .nth(1)
            .unwrap()
            .split("\nif [ -e /sys/kernel/mm/ksm/run ]; then")
            .next()
            .unwrap();
        // Execute the actual bootstrap block with a local shell function in place of systemctl.
        // No host systemd call, filesystem change or privileged operation is possible here.
        let standin = r#"
set -eu
scenario=$1
stopped=no
systemctl() {
  action=$1
  case "$action" in
    show)
      property=${3#--property=}
      unit=$5
      missing=no
      case "$unit" in ksm.service|ksmtuned.service) missing=yes ;; esac
      [ "$scenario" != absent ] || missing=yes
      case "$property" in
        LoadState) if [ "$missing" = yes ]; then printf 'not-found\n'; else printf 'masked\n'; fi ;;
        ActiveState)
          if [ "$scenario" = unknown ]; then printf 'unknown\n'
          elif [ "$scenario" = still-active ]; then printf 'active\n'
          elif [ "$stopped" = yes ] || [ "$missing" = yes ]; then printf 'inactive\n'
          else printf 'active\n'; fi ;;
        MainPID) if [ "$scenario" = stale-pid ]; then printf '123\n'; else printf '0\n'; fi ;;
        *) return 99 ;;
      esac
      [ "$missing" = no ] || return 4
      ;;
    stop) [ "$scenario" != stop-failed ] || return 1; stopped=yes ;;
    disable|mask) ;;
    *) return 99 ;;
  esac
}
fail() { printf '%s\n' "$*" >&2; exit 1; }
"#;
        for scenario in [
            "stops",
            "absent",
            "stop-failed",
            "still-active",
            "unknown",
            "stale-pid",
        ] {
            let script = format!("{standin}\n{start}{block}\nprintf 'verified\\n'");
            let output = command("bash")
                .args(["-c", &script, "bootstrap-test", scenario])
                .output()
                .unwrap();
            assert_eq!(
                output.status.success(),
                matches!(scenario, "stops" | "absent"),
                "{scenario}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            if output.status.success() {
                assert_eq!(output.stdout, b"verified\n");
            }
        }
    }

    #[test]
    fn roles_are_fixed() {
        assert_eq!(OomClass::Helper.score(), 0);
        assert_eq!(OomClass::Machine.score(), 500);
        assert_eq!(OomClass::Gateway.score(), 250);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn child_and_fork_inherit_the_selected_score_without_changing_parent() {
        let before = std::fs::read_to_string("/proc/self/oom_score_adj").unwrap();
        for class in [OomClass::Helper, OomClass::Machine, OomClass::Gateway] {
            let mut command = command("sh");
            set_class(&mut command, class);
            let out = command
                .args(["-c", "(cat /proc/self/oom_score_adj)"])
                .output()
                .unwrap();
            assert!(out.status.success());
            assert_eq!(
                String::from_utf8(out.stdout).unwrap().trim(),
                class.score().to_string()
            );
        }
        assert_eq!(
            std::fs::read_to_string("/proc/self/oom_score_adj").unwrap(),
            before
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an exclusive disposable Linux host with CAP_SYS_RESOURCE"]
    fn protected_parent_resets_helper_scores() {
        use std::{
            os::unix::process::CommandExt,
            process::Stdio,
            time::{Duration, Instant},
        };
        let mut child = StdCommand::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "host_process::tests::protected_parent_child",
                "--ignored",
            ])
            .env("BRIQYARD_TEST_PROTECTED_PARENT", "1")
            .stdout(Stdio::null());
        // SAFETY: only async-signal-safe operations; this changes the child, never the test supervisor.
        unsafe {
            child.pre_exec(|| {
                let fd = libc::open(
                    c"/proc/self/oom_score_adj".as_ptr(),
                    libc::O_WRONLY | libc::O_CLOEXEC,
                );
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let written = libc::write(fd, b"-900".as_ptr().cast(), 4);
                let error = std::io::Error::last_os_error();
                libc::close(fd);
                if written == 4 {
                    Ok(())
                } else {
                    Err(error)
                }
            });
        }
        let before = std::fs::read_to_string("/proc/self/oom_score_adj").unwrap();
        let mut child = child.spawn().unwrap();
        let end = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= end {
                child.kill().unwrap();
                let _ = child.wait();
                panic!("protected child timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(status.success());
        assert_eq!(
            std::fs::read_to_string("/proc/self/oom_score_adj").unwrap(),
            before
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "subprocess fixture for protected_parent_resets_helper_scores"]
    fn protected_parent_child() {
        if std::env::var("BRIQYARD_TEST_PROTECTED_PARENT").as_deref() != Ok("1") {
            return;
        }
        assert_eq!(
            std::fs::read_to_string("/proc/self/oom_score_adj")
                .unwrap()
                .trim(),
            "-900"
        );
        child_and_fork_inherit_the_selected_score_without_changing_parent();
    }
}
