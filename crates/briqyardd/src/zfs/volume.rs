use super::*;

impl Zfs {
    pub async fn exists(&self, name: &str) -> Result<bool> {
        match self
            .run(&["list", "-H", "-o", "name", &self.ds(name)])
            .await
        {
            Ok(_) => Ok(true),
            Err(e) if Self::is_missing(&e) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Makes the parent dataset of a name (`m/<id>` for `m/<id>/root`), for a receive.
    pub async fn create_parent(&self, name: &str) -> Result<()> {
        self.ensure_parent(name).await
    }

    /// Removes one snapshot. Missing is success.
    pub async fn destroy_snapshot(&self, name: &str, snap: &str) -> Result<()> {
        match self
            .run(&["destroy", &format!("{}@{snap}", self.ds(name))])
            .await
        {
            Ok(_) => Ok(()),
            Err(e) if Self::is_missing(&e) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub(super) async fn ensure_parent(&self, name: &str) -> Result<()> {
        if let Some(parent) = Path::new(name).parent() {
            let p = parent.to_string_lossy();
            if !p.is_empty() {
                self.run(&["create", "-p", &self.ds(&p)]).await?;
            }
        }
        Ok(())
    }

    /// Makes a thin volume and returns its device. An existing one is returned as is.
    pub async fn create(&self, name: &str, size_bytes: u64) -> Result<PathBuf> {
        if !self.exists(name).await? {
            self.ensure_parent(name).await?;
            self.run(&[
                "create",
                "-s",
                "-V",
                &size_bytes.to_string(),
                "-b",
                "16K",
                "-o",
                "compression=lz4",
                &self.ds(name),
            ])
            .await?;
        }
        self.wait_device(name).await
    }

    /// A volume's device (`/dev/zdN`), checked to be that volume now: never another's. ZFS
    /// makes, renames and removes a zvol's device after `zfs` returned, and udev may drop the
    /// event that moves its link (ADR 0046), so the link at the volume's name can be missing a
    /// while, or name the device of a disk renamed or destroyed under it. Each device the link
    /// names is asked its dataset (`zvol_id`); a wrong one gets a change event of its own,
    /// which moves its links. Every zvol's event is replayed, once, when the link is still not
    /// right after that (the volume's own event was lost too) or at the end of the wait.
    pub(super) async fn wait_device(&self, name: &str) -> Result<PathBuf> {
        let until = Instant::now() + LINK_WAIT;
        self.settle(until).await?;
        let deadline = tokio::time::Instant::now() + LINK_WAIT;
        let (mut mended, mut replayed) = (false, false);
        loop {
            let (last, wrong) = match self.link(name, until).await {
                Link::Right(dev) => return Ok(dev),
                Link::Wrong(dev, other) => {
                    (format!("names {} ({other})", dev.display()), Some(dev))
                }
                Link::Missing => ("is missing".to_string(), None),
            };
            let over = tokio::time::Instant::now() > deadline || Instant::now() > until;
            // A replay was worked when it returns: still not right after one of the wrong
            // device, the volume's own event was lost too.
            if !replayed && (over || mended) {
                self.replay(None, until).await?;
                replayed = true;
                continue;
            }
            if over {
                return Err(anyhow!(
                    "zvol device of {}: {} {last} after {} s",
                    self.ds(name),
                    self.dev(name).display(),
                    LINK_WAIT.as_secs()
                ));
            }
            let pause = match wrong {
                Some(dev) => {
                    self.replay(Some(&dev), until).await?;
                    mended = true;
                    500
                }
                None => 100,
            };
            tokio::time::sleep(Duration::from_millis(pause)).await;
        }
    }

    /// What the link at a volume's name says now.
    pub(super) async fn link(&self, name: &str, until: Instant) -> Link {
        let Ok(dev) = tokio::fs::canonicalize(self.dev(name)).await else {
            return Link::Missing;
        };
        match self.zvol_name(&dev, until).await {
            Ok(n) if n == self.ds(name) => Link::Right(dev),
            Ok(n) => Link::Wrong(dev, n),
            Err(err) => Link::Wrong(dev, err),
        }
    }

    /// The dataset a zvol device is now, as the kernel says; a device being removed has none.
    pub(super) async fn zvol_name(&self, dev: &Path, until: Instant) -> Result<String, String> {
        let mut cmd = self.tools.zvol_id.command();
        cmd.arg(dev);
        match bounded(cmd, until).await {
            Some(Ok(o)) if o.status.success() => {
                Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
            }
            Some(Ok(o)) => Err(String::from_utf8_lossy(&o.stderr).trim().to_string()),
            Some(Err(e)) => Err(format!("run zvol_id: {e}")),
            None => Err("zvol_id: no answer".into()),
        }
    }

    /// Waits for the events udev holds, 5 s at most: the link is polled for after it, so a udevd
    /// slow to settle leaves the rest of the wait to that.
    pub(super) async fn settle(&self, until: Instant) -> Result<()> {
        let until = until.min(Instant::now() + SETTLE_WAIT);
        self.udevadm(&["settle", "--timeout=5"], until).await
    }

    /// Sends a change event for one zvol device, or for every zvol device, and waits for it to
    /// be worked: udev's rule then links each device at the name `zvol_id` gives it now.
    pub(super) async fn replay(&self, dev: Option<&Path>, until: Instant) -> Result<()> {
        let mut args = vec!["trigger", "--action=change", "--settle"];
        let dev = dev.map(|d| d.display().to_string());
        match &dev {
            Some(d) => args.push(d),
            None => args.extend(["--subsystem-match=block", "--sysname-match=zd*"]),
        }
        self.udevadm(&args, until).await
    }

    /// Runs `udevadm` until `until`. One that has not answered by then (a udevd wedged, as a
    /// stalled pool can leave it) is killed and counts as done: the link the caller reads next
    /// says whether it worked.
    pub(super) async fn udevadm(&self, args: &[&str], until: Instant) -> Result<()> {
        let mut cmd = self.tools.udevadm.command();
        cmd.args(args);
        let Some(out) = bounded(cmd, until).await else {
            return Ok(());
        };
        let out = out.context("run udevadm")?;
        if !out.status.success() {
            return Err(anyhow!(
                "udevadm {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(())
    }

    /// A volume's size, in bytes.
    pub async fn volsize(&self, name: &str) -> Result<u64> {
        let out = self
            .run(&["get", "-H", "-p", "-o", "value", "volsize", &self.ds(name)])
            .await?;
        out.trim()
            .parse()
            .map_err(|_| anyhow!("zfs get volsize {name}: {:?}", out.trim()))
    }

    /// Grows a volume to `bytes` (ADR 0040). Never called smaller: ZFS would cut the volume's
    /// end off, and the filesystem with it.
    pub async fn grow(&self, name: &str, bytes: u64) -> Result<()> {
        self.run(&["set", &format!("volsize={bytes}"), &self.ds(name)])
            .await?;
        Ok(())
    }

    pub async fn device(&self, name: &str) -> Result<PathBuf> {
        if !self.exists(name).await? {
            return Err(anyhow!("volume {name} does not exist"));
        }
        self.wait_device(name).await
    }
}

/// Runs a command until `until`, real time: past it the command is killed (`kill_on_drop`) and
/// the answer is `None`. Not tokio's clock, which a test can pause: a paused clock jumps to the
/// next timer whenever the runtime waits, and a command would time out at once.
async fn bounded(
    mut cmd: Command,
    until: Instant,
) -> Option<std::io::Result<std::process::Output>> {
    use std::sync::mpsc::RecvTimeoutError;
    let (cancel, cancelled) = std::sync::mpsc::channel::<()>();
    let (fire, fired) = tokio::sync::oneshot::channel::<()>();
    let left = until.saturating_duration_since(Instant::now());
    std::thread::spawn(move || {
        if cancelled.recv_timeout(left) == Err(RecvTimeoutError::Timeout) {
            let _ = fire.send(());
        }
    });
    let out = tokio::select! {
        out = cmd.kill_on_drop(true).output() => Some(out),
        _ = fired => None,
    };
    drop(cancel);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zfs::fake::{device_of, Fake, Scripts, SETTLE};

    #[tokio::test]
    async fn exists_reads_the_missing_answer_only() {
        let f = Fake::open("byard").await.unwrap();
        f.calls();
        assert!(!f.zfs.exists("m/x/root").await.unwrap());
        assert_eq!(f.calls(), vec!["list -H -o name byard/m/x/root"]);
        std::fs::create_dir_all(f.dev().join("byard/m/x")).unwrap();
        std::fs::write(f.dev().join("byard/m/x/root"), b"").unwrap();
        assert!(f.zfs.exists("m/x/root").await.unwrap());
        // Any other failure is an error, not "missing".
        let err = f.zfs.exists("boom").await.unwrap_err();
        assert!(err.to_string().contains("permission denied"), "{err}");
        assert!(
            err.to_string()
                .starts_with("zfs list -H -o name byard/boom"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn create_makes_the_parent_and_returns_the_device() {
        let f = Fake::open("byard").await.unwrap();
        f.calls();
        let dev = f.zfs.create("m/x/data", 2 << 30).await.unwrap();
        assert!(device_of(&dev, f.dev().join("byard/m/x/data")), "{dev:?}");
        // The node is looked for once udev has settled.
        assert_eq!(
            f.calls(),
            vec![
                "list -H -o name byard/m/x/data",
                "create -p byard/m/x",
                "create -s -V 2147483648 -b 16K -o compression=lz4 byard/m/x/data",
                SETTLE,
            ]
        );
        // An existing volume is returned as is: no second create.
        let again = f.zfs.create("m/x/data", 2 << 30).await.unwrap();
        assert_eq!(again, dev);
        assert_eq!(f.calls(), vec!["list -H -o name byard/m/x/data", SETTLE]);
    }

    #[tokio::test]
    async fn a_volume_grows_and_its_snapshots_and_clones_keep_their_size() {
        let f = Fake::open("byard").await.unwrap();
        f.zfs.create("m/x/data", 1 << 30).await.unwrap();
        f.zfs.snapshot("m/x/data", "a").await.unwrap();
        f.calls();
        f.zfs.grow("m/x/data", 2 << 30).await.unwrap();
        assert_eq!(f.calls(), vec!["set volsize=2147483648 byard/m/x/data"]);
        assert_eq!(f.zfs.volsize("m/x/data").await.unwrap(), 2 << 30);
        assert_eq!(f.calls(), vec!["get -H -p -o value volsize byard/m/x/data"]);
        // A snapshot from before the grow, and a clone of it, are the old size.
        f.zfs
            .clone_snapshot("m/x/data", "a", "m/y/data")
            .await
            .unwrap();
        assert_eq!(f.zfs.volsize("m/y/data").await.unwrap(), 1 << 30);
        let err = f.zfs.grow("m/z/data", 2 << 30).await.unwrap_err();
        assert!(err.to_string().contains("does not exist"), "{err}");
        let err = f.zfs.volsize("m/z/data").await.unwrap_err();
        assert!(err.to_string().contains("does not exist"), "{err}");
    }

    #[tokio::test]
    async fn parents_follow_the_name() {
        let f = Fake::open("byard").await.unwrap();
        f.calls();
        f.zfs.create("m/a/b/c/data", 1 << 20).await.unwrap();
        assert_eq!(f.calls()[1], "create -p byard/m/a/b/c");
        // A name at the top of the pool has no parent to make.
        f.zfs.create("flat", 1 << 20).await.unwrap();
        assert_eq!(
            f.calls(),
            vec![
                "list -H -o name byard/flat",
                "create -s -V 1048576 -b 16K -o compression=lz4 byard/flat",
                SETTLE,
            ]
        );
    }

    #[tokio::test]
    async fn device_of_a_missing_volume_is_an_error() {
        let f = Fake::open("byard").await.unwrap();
        let err = f.zfs.device("m/x/root").await.unwrap_err();
        assert_eq!(err.to_string(), "volume m/x/root does not exist");
        f.zfs.create("m/x/root", 1 << 20).await.unwrap();
        let dev = f.zfs.device("m/x/root").await.unwrap();
        assert!(device_of(&dev, f.dev().join("byard/m/x/root")), "{dev:?}");
    }

    /// A restore's swap (ADR 0046): udev dropped the events of both renames, so the link at the
    /// disk's name still names the old disk's device. The renamed devices are given events of
    /// their own, and the disk's device is the clone's, never the retired disk's.
    #[tokio::test]
    async fn a_rename_moves_the_link_udev_missed() {
        let f = Fake::open("byard").await.unwrap();
        let old = f.zfs.create("m/x/root", 1 << 20).await.unwrap();
        f.zfs.snapshot("m/x/root", "s_1").await.unwrap();
        let clone = f
            .zfs
            .clone_snapshot("m/x/root", "s_1", "m/x/root.next")
            .await
            .unwrap();
        std::fs::write(f.dev().join("udev.drop"), "").unwrap();
        f.zfs.rename("m/x/root", "m/x/root.r_1").await.unwrap();
        f.zfs.rename("m/x/root.next", "m/x/root").await.unwrap();
        let dev = f.zfs.device("m/x/root").await.unwrap();
        assert_eq!(dev, clone);
        assert!(device_of(&dev, f.dev().join("byard/m/x/root")));
        assert_eq!(f.zfs.device("m/x/root.r_1").await.unwrap(), old);
        assert!(!f.links().join("byard/m/x/root.next").exists());
    }

    /// A link udev left on the device of a destroyed volume, at the name of a volume made since
    /// (ADR 0046): that device is never answered, the new volume's is.
    #[tokio::test(start_paused = true)]
    async fn a_link_left_on_a_destroyed_volume_is_never_its_device() {
        let f = Fake::open("byard").await.unwrap();
        let gone = f.zfs.create("m/x/root", 1 << 20).await.unwrap();
        std::fs::write(f.dev().join("udev.drop"), "").unwrap();
        f.zfs.destroy("m/x/root").await.unwrap();
        let made = f.zfs.create("m/x/root", 1 << 20).await.unwrap();
        assert_ne!(made, gone);
        assert!(device_of(&made, f.dev().join("byard/m/x/root")));
        // The destroyed volume's device went with the event the daemon sent for it.
        assert!(!gone.exists());
    }

    /// A volume whose link udev never made: every zvol's event is replayed once the wait is
    /// over, and the link is there.
    #[tokio::test(start_paused = true)]
    async fn a_link_udev_never_made_is_replayed() {
        let f = Fake::open("byard").await.unwrap();
        std::fs::write(f.dev().join("udev.drop"), "").unwrap();
        f.calls();
        let dev = f.zfs.create("m/x/data", 1 << 20).await.unwrap();
        assert!(device_of(&dev, f.dev().join("byard/m/x/data")));
        let calls = f.calls();
        assert_eq!(
            calls.last().unwrap(),
            "udevadm trigger --action=change --settle --subsystem-match=block --sysname-match=zd*"
        );
    }

    /// A link whose device never says it is the volume, after the replay too, is an error that
    /// names what it found.
    #[tokio::test(start_paused = true)]
    async fn a_device_that_is_never_the_volume_is_an_error() {
        let s = Scripts::new();
        let zvol_id = s.zvol_id.clone();
        let f = s.open("byard").await.unwrap();
        f.zfs.create("m/x/data", 1 << 20).await.unwrap();
        std::fs::write(&zvol_id, "echo 'No such device or address' >&2; exit 1\n").unwrap();
        let err = f.zfs.device("m/x/data").await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.starts_with("zvol device of byard/m/x/data: "), "{msg}");
        assert!(
            msg.contains("(No such device or address) after 15 s"),
            "{msg}"
        );
    }

    /// A udevd wedged, as a stalled pool can leave it, and a `zvol_id` that never answers: the
    /// wait still ends by its deadline, with an error, and the commands are killed.
    #[tokio::test]
    async fn a_wedged_udev_ends_the_wait_by_its_deadline() {
        let f = Fake::open("byard").await.unwrap();
        f.zfs.create("m/x/root", 1 << 20).await.unwrap();
        std::fs::write(f.dev().join("hang.udevadm"), "").unwrap();
        std::fs::write(f.dev().join("hang.zvol_id"), "").unwrap();
        let t0 = Instant::now();
        let err = f.zfs.device("m/x/root").await.unwrap_err();
        assert!(
            t0.elapsed() < LINK_WAIT + Duration::from_secs(3),
            "{:?}",
            t0.elapsed()
        );
        assert!(
            format!("{err:#}").contains("(zvol_id: no answer) after 15 s"),
            "{err:#}"
        );
        // A rename: its device found once udev's settle was given up, then the new link
        // never made.
        std::fs::remove_file(f.dev().join("hang.zvol_id")).unwrap();
        let t0 = Instant::now();
        let err = f.zfs.rename("m/x/root", "m/x/root.r_1").await.unwrap_err();
        assert!(
            t0.elapsed() < 2 * LINK_WAIT + Duration::from_secs(3),
            "{:?}",
            t0.elapsed()
        );
        assert!(format!("{err:#}").contains("not linked at"), "{err:#}");
    }

    /// Against the kernel and udev, on a Linux host with ZFS, as root (ADR 0046):
    /// `BRIQYARD_ZFS_TEST_POOL=byard cargo test -p briqyardd -- --ignored real_pool`. A
    /// restore's renames, then the links RISE-M was left with set by hand: the link at the disk's
    /// name on the retired disk's device, the retired disk's link gone. Datasets under
    /// `<pool>/zvtest-<pid>`, destroyed after.
    #[tokio::test]
    #[ignore = "needs ZFS and root"]
    async fn real_pool_links_follow_renames_and_wrong_ones_are_mended() {
        let pool = std::env::var("BRIQYARD_ZFS_TEST_POOL").expect("BRIQYARD_ZFS_TEST_POOL");
        let z = Zfs::new(&pool).await.unwrap();
        let base = format!("zvtest-{}", std::process::id());
        let (live, next, retired) = (
            format!("{base}/root"),
            format!("{base}/root.next"),
            format!("{base}/root.r_1"),
        );
        let old = z.create(&live, 64 << 20).await.unwrap();
        z.snapshot(&live, "s_1").await.unwrap();
        let clone = z.clone_snapshot(&live, "s_1", &next).await.unwrap();
        z.rename(&live, &retired).await.unwrap();
        z.rename(&next, &live).await.unwrap();
        assert_eq!(z.device(&live).await.unwrap(), clone);
        assert_eq!(z.device(&retired).await.unwrap(), old);
        let link = |n: &str| z.dev(n);
        assert_eq!(std::fs::canonicalize(link(&live)).unwrap(), clone);
        assert!(!link(&next).exists(), "the clone's old link went");
        // udev's events lost: the disk's link on the retired disk's device, the retired
        // disk's link gone.
        std::fs::remove_file(link(&live)).unwrap();
        std::os::unix::fs::symlink(&old, link(&live)).unwrap();
        std::fs::remove_file(link(&retired)).unwrap();
        assert_eq!(z.device(&live).await.unwrap(), clone);
        assert_eq!(std::fs::canonicalize(link(&retired)).unwrap(), old);
        z.destroy(&base).await.unwrap();
    }
}
