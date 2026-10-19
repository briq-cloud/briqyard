//! The ZFS storage backend: one zvol per disk, in one pool. Names are paths under the pool
//! ("images/abc", "m/<id>/root"). Every method is idempotent where it can be.

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;

#[derive(Clone)]
pub struct Zfs {
    pool: String,
    /// The `zfs` command; a fake one in tests.
    binary: PathBuf,
    /// Where the kernel exposes zvols (`/dev/zvol/<dataset>`).
    dev_root: PathBuf,
}

impl Zfs {
    /// Opens the pool and makes the parent datasets the layout needs.
    pub async fn new(pool: &str) -> Result<Self> {
        Self::with_paths(pool, Path::new("zfs"), Path::new("/dev/zvol")).await
    }

    /// `new` with the `zfs` binary and the zvol device root given, so tests can stand in for
    /// both without ZFS on the machine.
    pub async fn with_paths(pool: &str, binary: &Path, dev_root: &Path) -> Result<Self> {
        let z = Self {
            pool: pool.to_string(),
            binary: binary.to_path_buf(),
            dev_root: dev_root.to_path_buf(),
        };
        z.run(&["list", "-H", "-o", "name", pool])
            .await
            .with_context(|| format!("zfs pool {pool}"))?;
        for d in ["images", "m"] {
            z.run(&["create", "-p", &z.ds(d)]).await?;
        }
        Ok(z)
    }

    fn ds(&self, name: &str) -> String {
        format!("{}/{}", self.pool, name)
    }

    fn dev(&self, name: &str) -> PathBuf {
        self.dev_root.join(self.ds(name))
    }

    async fn run(&self, args: &[&str]) -> Result<String> {
        let out = Command::new(&self.binary)
            .args(args)
            .output()
            .await
            .context("run zfs")?;
        if !out.status.success() {
            let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return Err(anyhow!(
                "zfs {}: {}",
                args.join(" "),
                if msg.is_empty() {
                    out.status.to_string()
                } else {
                    msg
                }
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn is_missing(err: &anyhow::Error) -> bool {
        err.to_string().contains("does not exist")
    }

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

    async fn ensure_parent(&self, name: &str) -> Result<()> {
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

    /// Waits for udev to make the device node (asynchronous after a create or clone).
    async fn wait_device(&self, name: &str) -> Result<PathBuf> {
        let dev = self.dev(name);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            if tokio::fs::metadata(&dev).await.is_ok() {
                return Ok(dev);
            }
            if tokio::time::Instant::now() > deadline {
                return Err(anyhow!("zvol device {} did not appear", dev.display()));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub async fn device(&self, name: &str) -> Result<PathBuf> {
        if !self.exists(name).await? {
            return Err(anyhow!("volume {name} does not exist"));
        }
        self.wait_device(name).await
    }

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
                "creation",
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

    pub async fn used(&self, name: &str) -> Result<u64> {
        let out = self
            .run(&["get", "-H", "-p", "-o", "value", "used", &self.ds(name)])
            .await?;
        Ok(out.trim().parse().unwrap_or(0))
    }

    pub async fn free(&self) -> Result<u64> {
        let out = self
            .run(&["get", "-H", "-p", "-o", "value", "available", &self.pool])
            .await?;
        Ok(out.trim().parse().unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in for `zfs`, with the fake device root as its state: a directory per parent
    /// dataset, a file per volume or snapshot. Every call is appended to `calls`, one line
    /// each; `get` answers come from `answer.<property>` files; `busy` holds how many
    /// destroys still answer "dataset is busy". Error texts are the real ones, since the
    /// code matches on them.
    const FAKE: &str = r#"#!/bin/sh
DEV="__DEV__"
printf '%s\n' "$*" >> "__LOG__"
for a in "$@"; do last="$a"; done
missing() { echo "cannot open '$1': dataset does not exist" >&2; exit 1; }
case "$1" in
  list)
    if [ "$3" = "-t" ]; then
      [ -e "$DEV/$last" ] || missing "$last"
      ls "$DEV/$last"@* 2>/dev/null | sed "s|^$DEV/||"
      exit 0
    fi
    case "$last" in *boom*) echo "cannot open '$last': permission denied" >&2; exit 1;; esac
    if [ "$last" = "__POOL__" ] || [ -e "$DEV/$last" ]; then echo "$last"; exit 0; fi
    missing "$last";;
  create)
    if [ "$2" = "-p" ]; then mkdir -p "$DEV/$last"; exit 0; fi
    mkdir -p "$(dirname "$DEV/$last")"; : > "$DEV/$last"; exit 0;;
  clone)
    [ -e "$DEV/$2" ] || missing "$2"
    mkdir -p "$(dirname "$DEV/$3")"; : > "$DEV/$3"; exit 0;;
  snapshot)
    if [ -e "$DEV/$2" ]; then echo "cannot create snapshot '$2': dataset already exists" >&2; exit 1; fi
    : > "$DEV/$2"; exit 0;;
  destroy)
    if [ -f "$DEV/busy" ] && [ "$(cat "$DEV/busy")" -gt 0 ]; then
      echo $(($(cat "$DEV/busy") - 1)) > "$DEV/busy"
      echo "cannot destroy '$last': dataset is busy" >&2; exit 1
    fi
    case "$last" in *boom*) echo "cannot destroy '$last': permission denied" >&2; exit 1;; esac
    [ -e "$DEV/$last" ] || missing "$last"
    rm -rf "$DEV/$last"; exit 0;;
  get)
    cat "$DEV/answer.$6"; exit 0;;
esac
exit 0
"#;

    struct Fake {
        dir: tempfile::TempDir,
        zfs: Zfs,
    }

    impl Fake {
        async fn open(pool: &str) -> Result<Fake> {
            let dir = tempfile::tempdir().unwrap();
            let dev = dir.path().join("dev");
            std::fs::create_dir_all(&dev).unwrap();
            let bin = dir.path().join("zfs");
            let script = FAKE
                .replace("__DEV__", dev.to_str().unwrap())
                .replace("__LOG__", dir.path().join("calls").to_str().unwrap())
                .replace("__POOL__", "byard");
            std::fs::write(&bin, script).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
            let zfs = Zfs::with_paths(pool, &bin, &dev).await?;
            Ok(Fake { dir, zfs })
        }

        fn dev(&self) -> PathBuf {
            self.dir.path().join("dev")
        }

        /// The calls so far, then forgets them.
        fn calls(&self) -> Vec<String> {
            let path = self.dir.path().join("calls");
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            let _ = std::fs::remove_file(&path);
            text.lines().map(String::from).collect()
        }

        fn answer(&self, prop: &str, value: &str) {
            std::fs::write(self.dev().join(format!("answer.{prop}")), value).unwrap();
        }
    }

    #[tokio::test]
    async fn opening_checks_the_pool_and_makes_the_layout() {
        let f = Fake::open("byard").await.unwrap();
        assert_eq!(
            f.calls(),
            vec![
                "list -H -o name byard",
                "create -p byard/images",
                "create -p byard/m"
            ]
        );
        assert!(f.dev().join("byard/images").is_dir());
        assert!(f.dev().join("byard/m").is_dir());

        let err = Fake::open("nope").await.err().unwrap();
        let msg = format!("{err:#}");
        assert!(msg.contains("zfs pool nope"), "{msg}");
        assert!(msg.contains("does not exist"), "{msg}");
    }

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
        assert_eq!(dev, f.dev().join("byard/m/x/data"));
        assert!(dev.is_file());
        assert_eq!(
            f.calls(),
            vec![
                "list -H -o name byard/m/x/data",
                "create -p byard/m/x",
                "create -s -V 2147483648 -b 16K -o compression=lz4 byard/m/x/data"
            ]
        );
        // An existing volume is returned as is: no second create.
        let again = f.zfs.create("m/x/data", 2 << 30).await.unwrap();
        assert_eq!(again, dev);
        assert_eq!(f.calls(), vec!["list -H -o name byard/m/x/data"]);
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
                "create -s -V 1048576 -b 16K -o compression=lz4 byard/flat"
            ]
        );
    }

    #[tokio::test]
    async fn device_of_a_missing_volume_is_an_error() {
        let f = Fake::open("byard").await.unwrap();
        let err = f.zfs.device("m/x/root").await.unwrap_err();
        assert_eq!(err.to_string(), "volume m/x/root does not exist");
        f.zfs.create("m/x/root", 1 << 20).await.unwrap();
        assert_eq!(
            f.zfs.device("m/x/root").await.unwrap(),
            f.dev().join("byard/m/x/root")
        );
    }

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
            "list -H -t snapshot -o name -s creation -r byard/m/x/root"
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
        assert_eq!(dev, f.dev().join("byard/m/y/root"));
        assert_eq!(
            f.calls(),
            vec![
                "list -H -o name byard/m/y/root",
                "create -p byard/m/y",
                "clone byard/images/abc@base byard/m/y/root"
            ]
        );
        // The clone exists: nothing is cloned again.
        f.zfs
            .clone_snapshot("images/abc", "base", "m/y/root")
            .await
            .unwrap();
        assert_eq!(f.calls(), vec!["list -H -o name byard/m/y/root"]);
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

    #[tokio::test]
    async fn used_and_free_parse_bytes() {
        let f = Fake::open("byard").await.unwrap();
        f.answer("used", "123456789\n");
        f.answer("available", "  42 \n");
        f.calls();
        assert_eq!(f.zfs.used("m/x").await.unwrap(), 123_456_789);
        assert_eq!(f.zfs.free().await.unwrap(), 42);
        assert_eq!(
            f.calls(),
            vec![
                "get -H -p -o value used byard/m/x",
                "get -H -p -o value available byard"
            ]
        );
        // What does not parse reads as zero rather than failing a status page.
        f.answer("used", "-\n");
        assert_eq!(f.zfs.used("m/x").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_missing_binary_is_an_error() {
        let err = Zfs::with_paths(
            "byard",
            Path::new("/nonexistent/zfs"),
            Path::new("/dev/zvol"),
        )
        .await
        .err()
        .unwrap();
        assert!(format!("{err:#}").contains("run zfs"), "{err:#}");
    }
}
