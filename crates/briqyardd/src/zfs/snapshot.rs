use super::*;

impl Zfs {
    pub async fn snapshot(&self, name: &str, snap: &str) -> Result<()> {
        match self
            .run(&["snapshot", &format!("{}@{snap}", self.ds(name))])
            .await
        {
            Ok(_) => Ok(()),
            Err(e) if e.to_string().contains("already exists") => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// One snapshot of several datasets, taken at the same instant (one `zfs snapshot`).
    pub async fn snapshot_all(&self, names: &[String], snap: &str) -> Result<()> {
        let targets: Vec<String> = names
            .iter()
            .map(|n| format!("{}@{snap}", self.ds(n)))
            .collect();
        let mut args = vec!["snapshot"];
        args.extend(targets.iter().map(String::as_str));
        self.run(&args).await?;
        Ok(())
    }

    /// Renames a volume in place: its snapshots and its clones' origins follow it, and so does
    /// its device's link. ZFS renames the device after `zfs rename` returned and udev may drop
    /// the event that moves the link (ADR 0046): the device, found before, is waited for until
    /// the kernel names it `to`, then given a change event until the link at `to` names it.
    pub async fn rename(&self, name: &str, to: &str) -> Result<()> {
        let dev = self.device(name).await?;
        self.run(&["rename", &self.ds(name), &self.ds(to)]).await?;
        let want = self.ds(to);
        let until = Instant::now() + LINK_WAIT;
        let deadline = tokio::time::Instant::now() + LINK_WAIT;
        let mut named = false;
        loop {
            if !named {
                named = self.zvol_name(&dev, until).await.as_deref() == Ok(want.as_str());
            }
            if named {
                self.replay(Some(&dev), until).await?;
                if matches!(self.link(to, until).await, Link::Right(at) if at == dev) {
                    return Ok(());
                }
            }
            if tokio::time::Instant::now() > deadline || Instant::now() > until {
                return Err(anyhow!(
                    "rename {} to {want}: {} {} after {} s",
                    self.ds(name),
                    dev.display(),
                    match named {
                        true => format!("not linked at {}", self.dev(to).display()),
                        false => "not renamed by the kernel".into(),
                    },
                    LINK_WAIT.as_secs()
                ));
            }
            // Polled until the kernel renamed it; then each replay was worked when it returned.
            let pause = if named { 500 } else { 50 };
            tokio::time::sleep(Duration::from_millis(pause)).await;
        }
    }

    /// Takes a dataset back to its newest snapshot: what was written since is freed.
    pub async fn rollback(&self, name: &str, snap: &str) -> Result<()> {
        self.run(&["rollback", &format!("{}@{snap}", self.ds(name))])
            .await?;
        Ok(())
    }

    /// Makes a writable volume from a snapshot, sharing unchanged blocks with it.
    pub async fn clone_snapshot(&self, name: &str, snap: &str, dest: &str) -> Result<PathBuf> {
        if !self.exists(dest).await? {
            self.ensure_parent(dest).await?;
            self.run(&[
                "clone",
                &format!("{}@{snap}", self.ds(name)),
                &self.ds(dest),
            ])
            .await?;
        }
        self.wait_device(dest).await
    }

    /// Removes a volume with its snapshots and children. Missing is success.
    /// Removes a volume with its snapshots and children. Missing is success. A zvol stays
    /// "busy" for a moment after its last user closes it (Firecracker exiting), so a busy
    /// answer is retried for a few seconds.
    pub async fn destroy(&self, name: &str) -> Result<()> {
        let mut tries = 0;
        loop {
            match self.run(&["destroy", "-r", &self.ds(name)]).await {
                Ok(_) => return Ok(()),
                Err(e) if Self::is_missing(&e) => return Ok(()),
                Err(e) if e.to_string().contains("busy") && tries < 40 => {
                    tries += 1;
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    pub async fn snapshots(&self, name: &str) -> Result<Vec<String>> {
        let out = self
            .run(&[
                "list",
                "-H",
                "-t",
                "snapshot",
                "-o",
                "name",
                "-s",
                "createtxg",
                "-r",
                &self.ds(name),
            ])
            .await?;
        let prefix = format!("{}@", self.ds(name));
        Ok(out
            .lines()
            .filter_map(|l| l.strip_prefix(&prefix))
            .map(String::from)
            .collect())
    }

    /// The snapshot a clone was made from, as (dataset, snapshot) relative to the pool;
    /// `None` for a volume that is nobody's clone.
    pub async fn origin(&self, name: &str) -> Result<Option<(String, String)>> {
        let out = self
            .run(&["get", "-H", "-o", "value", "origin", &self.ds(name)])
            .await?;
        let v = out.trim();
        if v.is_empty() || v == "-" {
            return Ok(None);
        }
        let rel = v.strip_prefix(&format!("{}/", self.pool)).unwrap_or(v);
        let (ds, snap) = rel
            .split_once('@')
            .ok_or_else(|| anyhow!("origin of {name}: {v:?}, want dataset@snapshot"))?;
        Ok(Some((ds.to_string(), snap.to_string())))
    }

    /// Every snapshot under a dataset with what clones it, oldest first, in one call; names
    /// relative to the pool.
    pub async fn snapshot_tree(&self, name: &str) -> Result<Vec<SnapshotOf>> {
        let out = self
            .run(&[
                "list",
                "-H",
                "-t",
                "snapshot",
                "-o",
                "name,clones",
                "-s",
                "createtxg",
                "-r",
                &self.ds(name),
            ])
            .await?;
        let prefix = format!("{}/", self.pool);
        let rel = |s: &str| s.strip_prefix(&prefix).unwrap_or(s).to_string();
        out.lines()
            .filter(|l| !l.is_empty())
            .map(|l| {
                let (full, clones) = l.split_once('\t').unwrap_or((l, "-"));
                let (dataset, snap) = full
                    .split_once('@')
                    .ok_or_else(|| anyhow!("zfs list of {name}: {l:?}, want dataset@snapshot"))?;
                let clones = match clones.trim() {
                    "" | "-" => vec![],
                    c => c.split(',').map(rel).collect(),
                };
                Ok(SnapshotOf {
                    dataset: rel(dataset),
                    snap: snap.to_string(),
                    clones,
                })
            })
            .collect()
    }

    /// The clones of a snapshot (datasets that still share its blocks).
    pub async fn clones(&self, name: &str, snap: &str) -> Result<Vec<String>> {
        let out = self
            .run(&[
                "get",
                "-H",
                "-p",
                "-o",
                "value",
                "clones",
                &format!("{}@{snap}", self.ds(name)),
            ])
            .await?;
        let v = out.trim();
        if v.is_empty() || v == "-" {
            return Ok(vec![]);
        }
        Ok(v.split(',').map(String::from).collect())
    }

    /// The datasets right under a dataset, as names relative to the pool (`m/<id>`).
    pub async fn children(&self, name: &str) -> Result<Vec<String>> {
        let out = self
            .run(&[
                "list",
                "-H",
                "-o",
                "name",
                "-t",
                "filesystem,volume",
                "-d",
                "1",
                &self.ds(name),
            ])
            .await?;
        let prefix = format!("{}/", self.ds(name));
        Ok(out
            .lines()
            .filter(|l| l.starts_with(&prefix))
            .filter_map(|l| l.strip_prefix(&format!("{}/", self.pool)))
            .map(String::from)
            .collect())
    }

    /// The volumes under a dataset, as names relative to the pool (`m/<id>/root`).
    pub async fn volumes_under(&self, name: &str) -> Result<Vec<String>> {
        let out = self
            .run(&[
                "list",
                "-H",
                "-o",
                "name",
                "-t",
                "volume",
                "-r",
                &self.ds(name),
            ])
            .await?;
        let prefix = format!("{}/", self.pool);
        Ok(out
            .lines()
            .filter_map(|l| l.strip_prefix(&prefix))
            .map(String::from)
            .collect())
    }

    /// Makes a clone the owner of the snapshot it was made from: the origin's snapshot moves to
    /// the clone and the origin becomes the dependent, so the origin can be destroyed.
    pub async fn promote(&self, name: &str) -> Result<()> {
        self.run(&["promote", &self.ds(name)]).await?;
        Ok(())
    }

    /// Promotes every clone outside `name` of a snapshot under it, until none is left, so
    /// that destroying `name` is not refused for "dependent clones": a machine's forks outlive
    /// it. A promoted clone takes its origin's origin, which may be under `name` too (a fork
    /// of a disk that was itself cloned there): hence the rounds. The clones promoted.
    pub async fn release_clones(&self, name: &str) -> Result<Vec<String>> {
        let inside = format!("{name}/");
        let mut promoted: Vec<String> = Vec::new();
        loop {
            let outside: Vec<String> = self
                .snapshot_tree(name)
                .await?
                .into_iter()
                .flat_map(|s| s.clones)
                .filter(|c| !c.starts_with(&inside))
                .collect();
            if outside.is_empty() {
                return Ok(promoted);
            }
            for c in outside {
                self.promote(&c).await?;
                if !promoted.contains(&c) {
                    promoted.push(c);
                }
            }
        }
    }
}

/// A snapshot and the datasets cloned from it, relative to the pool.
#[derive(Clone, Debug, PartialEq)]
pub struct SnapshotOf {
    pub dataset: String,
    pub snap: String,
    pub clones: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zfs::fake::{device_of, Fake, SETTLE};

    #[tokio::test]
    async fn snapshot_twice_is_fine() {
        let f = Fake::open("byard").await.unwrap();
        f.zfs.create("m/x/root", 1 << 20).await.unwrap();
        f.calls();
        f.zfs.snapshot("m/x/root", "base").await.unwrap();
        assert!(f.dev().join("byard/m/x/root@base").is_file());
        f.zfs.snapshot("m/x/root", "base").await.unwrap();
        assert_eq!(
            f.calls(),
            vec![
                "snapshot byard/m/x/root@base",
                "snapshot byard/m/x/root@base"
            ]
        );
        assert_eq!(
            f.zfs.snapshots("m/x/root").await.unwrap(),
            vec!["base".to_string()]
        );
        f.zfs.snapshot("m/x/root", "s_1").await.unwrap();
        assert_eq!(
            f.zfs.snapshots("m/x/root").await.unwrap(),
            vec!["base".to_string(), "s_1".to_string()]
        );
        assert_eq!(
            f.calls().last().unwrap(),
            "list -H -t snapshot -o name -s createtxg -r byard/m/x/root"
        );
    }

    #[tokio::test]
    async fn clone_from_a_snapshot() {
        let f = Fake::open("byard").await.unwrap();
        let err = f
            .zfs
            .clone_snapshot("images/abc", "base", "m/y/root")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("does not exist"), "{err}");

        f.zfs.create("images/abc", 1 << 20).await.unwrap();
        f.zfs.snapshot("images/abc", "base").await.unwrap();
        f.calls();
        let dev = f
            .zfs
            .clone_snapshot("images/abc", "base", "m/y/root")
            .await
            .unwrap();
        assert!(device_of(&dev, f.dev().join("byard/m/y/root")), "{dev:?}");
        assert_eq!(
            f.calls(),
            vec![
                "list -H -o name byard/m/y/root",
                "create -p byard/m/y",
                "clone byard/images/abc@base byard/m/y/root",
                SETTLE,
            ]
        );
        // The clone exists: nothing is cloned again.
        f.zfs
            .clone_snapshot("images/abc", "base", "m/y/root")
            .await
            .unwrap();
        assert_eq!(f.calls(), vec!["list -H -o name byard/m/y/root", SETTLE]);
    }

    #[tokio::test]
    async fn destroy_retries_busy_and_accepts_missing() {
        let f = Fake::open("byard").await.unwrap();
        f.zfs.create("m/x/root", 1 << 20).await.unwrap();
        f.zfs.create("m/x/data", 1 << 20).await.unwrap();
        std::fs::write(f.dev().join("busy"), "2").unwrap();
        f.calls();
        let t0 = std::time::Instant::now();
        f.zfs.destroy("m/x").await.unwrap();
        assert!(
            t0.elapsed() >= Duration::from_millis(500),
            "{:?}",
            t0.elapsed()
        );
        assert_eq!(f.calls(), vec!["destroy -r byard/m/x"; 3]);
        assert!(!f.dev().join("byard/m/x").exists());
        // Gone already: success, one call.
        f.zfs.destroy("m/x").await.unwrap();
        assert_eq!(f.calls(), vec!["destroy -r byard/m/x"]);
        // Any other refusal is an error.
        let err = f.zfs.destroy("boom").await.unwrap_err();
        assert!(err.to_string().contains("permission denied"), "{err}");
    }

    #[tokio::test]
    async fn volumes_under_a_dataset() {
        let f = Fake::open("byard").await.unwrap();
        f.zfs.create("m/x/root", 1 << 20).await.unwrap();
        f.zfs.create("m/x/data", 1 << 20).await.unwrap();
        f.zfs.create("m/y/root", 1 << 20).await.unwrap();
        f.zfs.snapshot("m/y/root", "s_1").await.unwrap();
        f.calls();
        // Names relative to the pool, volumes only: a snapshot is not one.
        assert_eq!(
            f.zfs.volumes_under("m").await.unwrap(),
            vec!["m/x/data", "m/x/root", "m/y/root"]
        );
        assert_eq!(f.calls(), vec!["list -H -o name -t volume -r byard/m"]);
        assert!(f.zfs.volumes_under("images").await.unwrap().is_empty());
        let err = f.zfs.volumes_under("nope").await.unwrap_err();
        assert!(err.to_string().contains("does not exist"), "{err}");
    }

    #[tokio::test]
    async fn releasing_clones_promotes_each_one() {
        let f = Fake::open("byard").await.unwrap();
        f.zfs.create("m/x/root", 1 << 20).await.unwrap();
        f.zfs.snapshot("m/x/root", "fork-y").await.unwrap();
        f.zfs.snapshot("m/x/root", "fork-z").await.unwrap();
        f.zfs
            .clone_snapshot("m/x/root", "fork-y", "m/y/root")
            .await
            .unwrap();
        f.zfs
            .clone_snapshot("m/x/root", "fork-z", "m/z/root")
            .await
            .unwrap();
        f.calls();
        let promoted = f.zfs.release_clones("m/x").await.unwrap();
        assert_eq!(promoted, ["m/y/root", "m/z/root"]);
        let calls = f.calls();
        let promotes: Vec<&String> = calls.iter().filter(|c| c.starts_with("promote ")).collect();
        assert_eq!(
            promotes,
            ["promote byard/m/y/root", "promote byard/m/z/root"],
            "{calls:?}"
        );
        // Promoted: each fork owns the snapshot it was made from, and nothing clones the
        // source's snapshots any more, so the source can go.
        assert_eq!(f.zfs.origin("m/y/root").await.unwrap(), None);
        assert_eq!(f.zfs.snapshots("m/y/root").await.unwrap(), ["fork-y"]);
        assert!(f.zfs.snapshots("m/x/root").await.unwrap().is_empty());
        // No snapshot, nothing to promote.
        f.zfs.create("m/w/root", 1 << 20).await.unwrap();
        f.calls();
        assert!(f.zfs.release_clones("m/w").await.unwrap().is_empty());
        assert!(f.calls().iter().all(|c| !c.starts_with("promote")));
    }

    #[tokio::test]
    async fn a_swap_renames_clones_promotes_and_rolls_back() {
        let f = Fake::open("byard").await.unwrap();
        let z = &f.zfs;
        z.create("m/a/root", 1 << 20).await.unwrap();
        z.create("m/a/data", 1 << 20).await.unwrap();
        f.calls();
        // Both disks at one instant; one already there refuses the whole call.
        let both = ["m/a/root".to_string(), "m/a/data".to_string()];
        z.snapshot_all(&both, "s_1").await.unwrap();
        assert_eq!(
            f.calls(),
            ["snapshot byard/m/a/root@s_1 byard/m/a/data@s_1"]
        );
        z.snapshot("m/a/data", "s_2").await.unwrap();
        assert!(z.snapshot_all(&both, "s_2").await.is_err());
        assert_eq!(z.snapshots("m/a/root").await.unwrap(), ["s_1"]);
        z.snapshot("m/a/root", "s_2").await.unwrap();
        z.clone_snapshot("m/a/root", "s_2", "m/f/root")
            .await
            .unwrap();
        // A rename carries the snapshots and the clones' origins.
        z.rename("m/a/root", "m/a/root.r_1").await.unwrap();
        assert!(!z.exists("m/a/root").await.unwrap());
        assert_eq!(z.snapshots("m/a/root.r_1").await.unwrap(), ["s_1", "s_2"]);
        assert_eq!(
            z.origin("m/f/root").await.unwrap(),
            Some(("m/a/root.r_1".into(), "s_2".into()))
        );
        // A clone of the older one, promoted: it holds that one, the other keeps the newer.
        z.clone_snapshot("m/a/root.r_1", "s_1", "m/a/root")
            .await
            .unwrap();
        z.promote("m/a/root").await.unwrap();
        assert_eq!(z.snapshots("m/a/root").await.unwrap(), ["s_1"]);
        assert_eq!(z.snapshots("m/a/root.r_1").await.unwrap(), ["s_2"]);
        assert_eq!(
            z.origin("m/a/root.r_1").await.unwrap(),
            Some(("m/a/root".into(), "s_1".into()))
        );
        assert_eq!(z.origin("m/a/root").await.unwrap(), None);
        // Back to the newest snapshot only.
        z.rollback("m/a/root.r_1", "s_2").await.unwrap();
        z.snapshot("m/a/root.r_1", "s_3").await.unwrap();
        assert!(z.rollback("m/a/root.r_1", "s_2").await.is_err());
        // A dataset something outside clones is not destroyed; the whole machine is, once
        // its fork is released.
        assert!(z.destroy("m/a/root.r_1").await.is_err());
        assert_eq!(z.release_clones("m/a").await.unwrap(), ["m/f/root"]);
        z.destroy("m/a").await.unwrap();
        assert!(z.exists("m/f/root").await.unwrap());
    }

    #[tokio::test]
    async fn origins_and_clones_follow_the_clones() {
        let f = Fake::open("byard").await.unwrap();
        f.zfs.create("m/s/root", 1 << 20).await.unwrap();
        assert_eq!(f.zfs.origin("m/s/root").await.unwrap(), None);
        f.zfs.snapshot("m/s/root", "fork-a").await.unwrap();
        assert!(f.zfs.clones("m/s/root", "fork-a").await.unwrap().is_empty());
        f.zfs
            .clone_snapshot("m/s/root", "fork-a", "m/a/root")
            .await
            .unwrap();
        f.zfs
            .clone_snapshot("m/s/root", "fork-a", "m/b/root")
            .await
            .unwrap();
        f.calls();
        // The origin names the snapshot, relative to the pool; the clones name themselves.
        assert_eq!(
            f.zfs.origin("m/a/root").await.unwrap(),
            Some(("m/s/root".to_string(), "fork-a".to_string()))
        );
        assert_eq!(
            f.zfs.clones("m/s/root", "fork-a").await.unwrap(),
            ["byard/m/a/root", "byard/m/b/root"]
        );
        assert_eq!(
            f.calls(),
            [
                "get -H -o value origin byard/m/a/root",
                "get -H -p -o value clones byard/m/s/root@fork-a"
            ]
        );
        // A clone destroyed is a clone no more.
        f.zfs.destroy("m/a").await.unwrap();
        assert_eq!(
            f.zfs.clones("m/s/root", "fork-a").await.unwrap(),
            ["byard/m/b/root"]
        );
        // Every snapshot under a dataset with its clones, oldest first, in one call.
        f.zfs.snapshot("m/b/root", "s_1").await.unwrap();
        let of = |ds: &str, snap: &str, clones: &[&str]| SnapshotOf {
            dataset: ds.into(),
            snap: snap.into(),
            clones: clones.iter().map(|c| c.to_string()).collect(),
        };
        assert_eq!(
            f.zfs.snapshot_tree("m").await.unwrap(),
            [
                of("m/s/root", "fork-a", &["m/b/root"]),
                of("m/b/root", "s_1", &[])
            ]
        );
        assert_eq!(
            f.calls().last().unwrap(),
            "list -H -t snapshot -o name,clones -s createtxg -r byard/m"
        );
        let err = f.zfs.origin("m/nope/root").await.unwrap_err();
        assert!(err.to_string().contains("does not exist"), "{err}");
        // What is not a snapshot name is an error, not a clone of nothing.
        f.answer("origin", "byard/m/s/root\n");
        let err = f.zfs.origin("m/b/root").await.unwrap_err();
        assert!(err.to_string().contains("want dataset@snapshot"), "{err}");
    }

    #[tokio::test]
    async fn clones_of_a_snapshot() {
        let f = Fake::open("byard").await.unwrap();
        f.answer("clones", "-\n");
        assert!(f.zfs.clones("images/abc", "base").await.unwrap().is_empty());
        f.answer("clones", "");
        assert!(f.zfs.clones("images/abc", "base").await.unwrap().is_empty());
        f.answer("clones", "byard/m/a/root,byard/m/b/root\n");
        assert_eq!(
            f.zfs.clones("images/abc", "base").await.unwrap(),
            vec!["byard/m/a/root".to_string(), "byard/m/b/root".to_string()]
        );
        assert_eq!(
            f.calls().last().unwrap(),
            "get -H -p -o value clones byard/images/abc@base"
        );
    }
}
