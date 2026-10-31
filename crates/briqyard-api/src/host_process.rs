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
