use super::*;

impl Zfs {
    pub(super) async fn get(&self, name: &str, property: &str) -> Result<String> {
        self.get_ds(&self.ds(name), property).await
    }

    pub(super) async fn get_ds(&self, ds: &str, property: &str) -> Result<String> {
        let out = self
            .run(&["get", "-H", "-o", "value", property, ds])
            .await?;
        Ok(out.trim().to_string())
    }

    pub(super) fn ds(&self, name: &str) -> String {
        format!("{}/{}", self.pool, name)
    }

    pub(super) fn dev(&self, name: &str) -> PathBuf {
        self.dev_root.join(self.ds(name))
    }

    pub(super) async fn run(&self, args: &[&str]) -> Result<String> {
        self.call(args, None).await
    }

    /// `run` with `input` on the command's stdin.
    pub(super) async fn run_input(&self, args: &[&str], input: &[u8]) -> Result<String> {
        self.call(args, Some(input.to_vec())).await
    }

    /// Runs a `zfs` command, counted as running until it exits: one that never does (stuck in
    /// the kernel) is the host's `storage_stalled` (ADR 0046). It is not timed out: a command
    /// stuck in the kernel cannot be killed, and one that is only slow finishes what it started.
    pub(super) async fn call(&self, args: &[&str], input: Option<Vec<u8>>) -> Result<String> {
        use std::process::Stdio;
        use tokio::io::AsyncWriteExt;
        let mut command = self.tools.zfs.command();
        command
            .args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped());
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let what = format!("zfs {}", args.join(" "));
        let out = self
            .owned(command, what.clone(), false, move |child| {
                let stdin = child.stdin.take();
                let stdout = child.stdout.take().expect("piped stdout");
                async move {
                    if let (Some(mut stdin), Some(input)) = (stdin, input) {
                        let _ = stdin.write_all(&input).await;
                    }
                    owned::read_answer(stdout).await
                }
            })
            .await?;
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    pub(super) fn begin(&self, what: &str) -> Call {
        let mut r = self.running.lock().unwrap();
        r.next += 1;
        let id = r.next;
        r.calls.insert(id, (Instant::now(), what.to_string()));
        Call(self.running.clone(), id)
    }

    /// The oldest `zfs` command running for longer than `after`: how long, and what. Real time,
    /// whatever clock a test pauses.
    pub fn stalled(&self, after: Duration) -> Option<(Duration, String)> {
        let r = self.running.lock().unwrap();
        let (since, what) = r.calls.values().min_by_key(|(t, _)| *t)?;
        let ran = since.elapsed();
        (ran > after).then(|| (ran, what.clone()))
    }

    pub(super) fn is_missing(err: &anyhow::Error) -> bool {
        err.to_string().contains("does not exist")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zfs::fake::{Fake, Scripts};
    use std::time::Instant;

    /// A `zfs` command is counted as running until it exits: past the time given, it is the
    /// host's stalled command (ADR 0046).
    #[tokio::test]
    async fn a_command_running_past_its_time_is_stalled() {
        let f = Fake::open("byard").await.unwrap();
        f.zfs.create("m/x/root", 1 << 20).await.unwrap();
        assert_eq!(f.zfs.stalled(Duration::ZERO), None);
        let hold = f.dev().join("hold.snapshot");
        std::fs::write(&hold, "").unwrap();
        let z = f.zfs.clone();
        let snap = tokio::spawn(async move { z.snapshot("m/x/root", "s_1").await });
        let stalled = loop {
            if let Some(s) = f.zfs.stalled(Duration::ZERO) {
                break s;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        assert_eq!(stalled.1, "zfs snapshot byard/m/x/root@s_1");
        assert_eq!(f.zfs.stalled(Duration::from_secs(3600)), None);
        std::fs::remove_file(&hold).unwrap();
        snap.await.unwrap().unwrap();
        assert_eq!(f.zfs.stalled(Duration::ZERO), None);
    }

    /// A request no longer observing a command does not prove that command exited.
    #[tokio::test]
    async fn cancelled_command_keeps_its_running_owner_until_actual_exit() {
        struct Hold(PathBuf);
        impl Drop for Hold {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let f = Fake::open("byard").await.unwrap();
        let hold = Hold(f.dev().join("hold.snapshot"));
        std::fs::write(&hold.0, "").unwrap();
        let z = f.zfs.clone();
        let task = tokio::spawn(async move { z.snapshot("m/x/root", "s_1").await });
        tokio::time::timeout(Duration::from_secs(5), async {
            while f.zfs.stalled(Duration::ZERO).is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(
            f.zfs.stalled(Duration::ZERO).is_some(),
            "dropping the waiter cannot erase an actual running command"
        );
        drop(hold);
        tokio::time::timeout(Duration::from_secs(5), async {
            while f.zfs.stalled(Duration::ZERO).is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    /// Waits until the fake has logged its call: past that line, it waits on its hold.
    fn held_from_now(s: &Scripts) {
        let calls = s.dev.parent().unwrap().join("calls");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !std::fs::read_to_string(&calls).is_ok_and(|c| c.contains("snapshot")) {
            assert!(Instant::now() < deadline, "the command never started");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// A command its test holds ends once the test is gone, by a panic too: the test's state
    /// goes with its destructors, and the hold with it.
    #[test]
    fn a_held_command_ends_with_its_test_a_panic_included() {
        let s = Scripts::new();
        std::fs::write(s.dev.join("hold.snapshot"), "").unwrap();
        let mut held = std::process::Command::new("sh")
            .arg(&s.zfs)
            .args(["snapshot", "byard/x@s"])
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        held_from_now(&s);
        let test = std::thread::spawn(move || {
            let _state = s;
            panic!("a test that fails while its command is held (expected)");
        });
        assert!(test.join().is_err());
        let deadline = Instant::now() + Duration::from_secs(5);
        while held.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "the held command still runs");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// A command held by a test binary that exited ends too, though no destructor ran and the
    /// hold is still there: it ends with its parent.
    #[test]
    fn a_held_command_ends_once_its_parent_is_gone() {
        let s = Scripts::new();
        std::fs::write(s.dev.join("hold.snapshot"), "").unwrap();
        // Its parent starts it and exits at once, as a test binary killed mid-test would.
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(r#"sh "$0" snapshot byard/x@s >/dev/null 2>&1 & echo $!"#)
            .arg(&s.zfs)
            .output()
            .unwrap();
        let pid: i32 = String::from_utf8(out.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        held_from_now(&s);
        let deadline = Instant::now() + Duration::from_secs(5);
        // Reparented, it is reaped by init (launchd) once it exits.
        while unsafe { libc::kill(pid, 0) } == 0 {
            assert!(Instant::now() < deadline, "the held command still runs");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(s.dev.join("hold.snapshot").exists());
    }

    #[tokio::test]
    async fn a_missing_binary_is_an_error() {
        let tools = Tools {
            zfs: Tool::program("/nonexistent/zfs"),
            udevadm: Tool::program("/nonexistent/udevadm"),
            zvol_id: Tool::program("/nonexistent/zvol_id"),
        };
        let err = Zfs::with_paths("byard", &tools, Path::new("/dev/zvol"))
            .await
            .err()
            .unwrap();
        assert!(format!("{err:#}").contains("run zfs"), "{err:#}");
        // The device wait needs udevadm as much as it needs zfs.
        let s = Scripts::new();
        let udevadm = s.udevadm.clone();
        let f = s.open("byard").await.unwrap();
        std::fs::remove_file(&udevadm).unwrap();
        let err = f.zfs.create("m/x/root", 1 << 20).await.unwrap_err();
        assert!(format!("{err:#}").contains("udevadm"), "{err:#}");
    }
}
