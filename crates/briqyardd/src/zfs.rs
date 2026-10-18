//! The ZFS storage backend: one zvol per disk, in one pool. Names are paths under the pool
//! ("images/abc", "m/<id>/root"). Every method is idempotent where it can be.

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;

#[derive(Clone)]
pub struct Zfs {
    pool: String,
}

impl Zfs {
    /// Opens the pool and makes the parent datasets the layout needs.
    pub async fn new(pool: &str) -> Result<Self> {
        let z = Self {
            pool: pool.to_string(),
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
        PathBuf::from(format!("/dev/zvol/{}", self.ds(name)))
    }

    async fn run(&self, args: &[&str]) -> Result<String> {
        let out = Command::new("zfs")
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

    #[allow(dead_code)] // for the status page
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
