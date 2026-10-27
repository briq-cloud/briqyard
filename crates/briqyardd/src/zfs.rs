//! The ZFS storage backend: one zvol per disk, in one pool. Names are paths under the pool
//! ("images/abc", "m/<id>/root"). Every method is idempotent where it can be.

use anyhow::{anyhow, Context, Result};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;

/// A command the backend runs: a program and the arguments that come before the backend's own.
/// On a host it is the program alone; a test's stand-in is `sh <script>`, so the script is read,
/// never executed: Linux refuses to execute a file another thread's fork still holds open for
/// writing ("Text file busy"), and a test writes its scripts while other tests fork.
#[derive(Clone, Debug)]
pub struct Tool {
    program: PathBuf,
    leading: Vec<OsString>,
}

impl Tool {
    pub fn program(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            leading: Vec::new(),
        }
    }

    /// A shell script, run by `sh`.
    #[cfg(test)]
    pub fn script(path: &Path) -> Self {
        Self {
            program: "sh".into(),
            leading: vec![path.into()],
        }
    }

    fn command(&self) -> Command {
        let mut c = Command::new(&self.program);
        c.args(&self.leading);
        c
    }
}

#[derive(Clone)]
pub struct Zfs {
    pool: String,
    /// The `zfs` command; a fake one in tests.
    binary: Tool,
    /// The `udevadm` command; a fake one in tests.
    udevadm: Tool,
    /// Where the kernel exposes zvols (`/dev/zvol/<dataset>`).
    dev_root: PathBuf,
}

/// Whether the pool is encrypted and its key loaded (ADR 0026).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Key {
    /// Not encrypted: refused, every host's pool is.
    None,
    Loaded,
    /// Encrypted, the key not loaded yet: `load_key` on `root`, the encryption root.
    Locked {
        root: String,
    },
}

impl Zfs {
    /// Opens the pool. Nothing is made or mounted: its key may not be loaded yet (`key`,
    /// `load_key`, then `layout`).
    pub async fn new(pool: &str) -> Result<Self> {
        Self::with_paths(
            pool,
            &Tool::program("zfs"),
            &Tool::program("udevadm"),
            Path::new("/dev/zvol"),
        )
        .await
    }

    /// `new` with the `zfs` and `udevadm` binaries and the zvol device root given, so tests
    /// can stand in for all three without ZFS on the machine.
    pub async fn with_paths(
        pool: &str,
        binary: &Tool,
        udevadm: &Tool,
        dev_root: &Path,
    ) -> Result<Self> {
        let z = Self {
            pool: pool.to_string(),
            binary: binary.clone(),
            udevadm: udevadm.clone(),
            dev_root: dev_root.to_path_buf(),
        };
        z.run(&["list", "-H", "-o", "name", pool])
            .await
            .with_context(|| format!("zfs pool {pool}"))?;
        Ok(z)
    }

    /// Makes the datasets the disks go under and mounts each filesystem of `mounts` (a name
    /// under the pool, a directory) there: everything the daemon writes about its machines
    /// lands on the pool, not on `/` (ADR 0014, 0026). Needs the key loaded.
    pub async fn layout(&self, mounts: &[(&str, &Path)]) -> Result<()> {
        self.run(&["create", "-p", &self.ds("m")]).await?;
        for (name, dir) in mounts {
            self.mount(name, dir).await?;
        }
        Ok(())
    }

    /// The pool's encryption: none, its key loaded, or locked with the root to unlock.
    pub async fn key(&self) -> Result<Key> {
        let status = self.get_ds(&self.pool, "keystatus").await?;
        match status.as_str() {
            "-" => Ok(Key::None),
            "available" => Ok(Key::Loaded),
            "unavailable" => Ok(Key::Locked {
                root: self.get_ds(&self.pool, "encryptionroot").await?,
            }),
            other => Err(anyhow!("zfs keystatus of {}: {other:?}", self.pool)),
        }
    }

    /// Loads the key of an encryption root (`Key::Locked`), given on stdin: never on a
    /// command line, never in a file.
    pub async fn load_key(&self, root: &str, key: &str) -> Result<()> {
        self.run_input(
            &["load-key", "-L", "prompt", root],
            format!("{key}\n").as_bytes(),
        )
        .await?;
        Ok(())
    }

    /// Checks that `key` is the one the pool is encrypted under, without loading anything
    /// (`load-key -n`, which works while the key is loaded): what a backup names and seals with
    /// must be what its raw streams are wrapped with (ADR 0035).
    pub async fn check_key(&self, key: &str) -> Result<()> {
        self.run_input(
            &["load-key", "-n", "-L", "prompt", &self.pool],
            format!("{key}\n").as_bytes(),
        )
        .await?;
        Ok(())
    }

    /// Opens a dataset received from raw streams, its own encryption root under the key it
    /// was sent with (`key`, the source host's), and makes it inherit the pool's key: from
    /// then on it opens with the pool, like every other dataset (ADR 0035).
    pub async fn inherit_key(&self, name: &str, key: &str) -> Result<()> {
        let ds = self.ds(name);
        self.load_key(&ds, key).await?;
        self.run(&["change-key", "-i", &ds]).await?;
        Ok(())
    }

    /// Makes `name` a filesystem mounted at `dir`, whatever it was before: made, moved or
    /// mounted as needed, nothing when it is already there. Never over files: a directory
    /// that holds some while the dataset is not mounted there is refused, since mounting
    /// would hide them (records, a machine's files) from the daemon.
    async fn mount(&self, name: &str, dir: &Path) -> Result<()> {
        let ds = self.ds(name);
        let want = format!("mountpoint={}", dir.display());
        let exists = self.exists(name).await?;
        let (at, mounted) = if exists {
            (
                self.get(name, "mountpoint").await? == dir.display().to_string(),
                self.get(name, "mounted").await? == "yes",
            )
        } else {
            (false, false)
        };
        if at && mounted {
            return Ok(());
        }
        if std::fs::read_dir(dir).is_ok_and(|mut d| d.next().is_some()) {
            return Err(anyhow!(
                "{} holds files and {ds} is not mounted there: they would be hidden. Move them \
                 onto {ds} (mount it elsewhere, copy, empty the directory) or remove them",
                dir.display()
            ));
        }
        if !exists {
            self.run(&["create", "-o", &want, &ds]).await?;
            return Ok(());
        }
        // Setting the mountpoint of a mounted filesystem moves it there.
        if !at {
            self.run(&["set", &want, &ds]).await?;
        }
        if !mounted {
            self.run(&["mount", &ds]).await?;
        }
        Ok(())
    }

    async fn get(&self, name: &str, property: &str) -> Result<String> {
        self.get_ds(&self.ds(name), property).await
    }

    async fn get_ds(&self, ds: &str, property: &str) -> Result<String> {
        let out = self
            .run(&["get", "-H", "-o", "value", property, ds])
            .await?;
        Ok(out.trim().to_string())
    }

    fn ds(&self, name: &str) -> String {
        format!("{}/{}", self.pool, name)
    }

    fn dev(&self, name: &str) -> PathBuf {
        self.dev_root.join(self.ds(name))
    }

    async fn run(&self, args: &[&str]) -> Result<String> {
        let out = self
            .binary
            .command()
            .args(args)
            .output()
            .await
            .context("run zfs")?;
        Self::answer(args, out)
    }

    /// `run` with `input` on the command's stdin.
    async fn run_input(&self, args: &[&str], input: &[u8]) -> Result<String> {
        use tokio::io::AsyncWriteExt;
        let mut child = self
            .binary
            .command()
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context("run zfs")?;
        let mut stdin = child.stdin.take().expect("piped");
        // A command that exits without reading its input is answered by its status.
        let _ = stdin.write_all(input).await;
        drop(stdin);
        let out = child.wait_with_output().await.context("run zfs")?;
        Self::answer(args, out)
    }

    fn answer(args: &[&str], out: std::process::Output) -> Result<String> {
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

    /// The device node of a volume, once udev has made it. `udevadm settle` waits for the
    /// events udev holds, bounded. A poll follows because the kernel may register the block
    /// device after `zfs` returned, so udev may not hold the event yet (ZFS's own `zvol_wait`
    /// polls for this); where it does, the loop runs once.
    async fn wait_device(&self, name: &str) -> Result<PathBuf> {
        let dev = self.dev(name);
        let out = self
            .udevadm
            .command()
            .args(["settle", "--timeout=15"])
            .output()
            .await
            .context("run udevadm")?;
        if !out.status.success() {
            return Err(anyhow!(
                "udevadm settle: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
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

    /// Renames a dataset in place: its snapshots and its clones' origins follow it.
    pub async fn rename(&self, name: &str, to: &str) -> Result<()> {
        self.run(&["rename", &self.ds(name), &self.ds(to)]).await?;
        Ok(())
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

    /// Starts `zfs send` of a snapshot (incremental from `from` when given), raw: the blocks
    /// as the pool holds them, encrypted under its key and compressed (ADR 0035); the caller
    /// reads the stream from the child's stdout and waits for it.
    pub fn send(
        &self,
        name: &str,
        snap: &str,
        from: Option<&str>,
    ) -> Result<tokio::process::Child> {
        let target = format!("{}@{snap}", self.ds(name));
        let mut cmd = self.binary.command();
        cmd.arg("send").arg("-w");
        if let Some(f) = from {
            cmd.arg("-i").arg(format!("@{f}"));
        }
        cmd.arg(&target)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        cmd.spawn().with_context(|| format!("zfs send {target}"))
    }

    /// Starts `zfs receive` into a dataset (made or overwritten); the caller writes the stream
    /// to the child's stdin and waits for it.
    pub fn receive(&self, name: &str) -> Result<tokio::process::Child> {
        let mut cmd = self.binary.command();
        cmd.args(["receive", "-F", "-u", &self.ds(name)])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        cmd.spawn()
            .with_context(|| format!("zfs receive {}", self.ds(name)))
    }

    /// Waits for a send or receive child and turns a failure into its stderr.
    pub async fn finish(child: tokio::process::Child, what: &str) -> Result<()> {
        let out = child.wait_with_output().await.context(what.to_string())?;
        if !out.status.success() {
            return Err(anyhow!(
                "{what}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(())
    }

    /// What each filesystem and volume under `name` takes, in one call.
    pub async fn space_under(&self, name: &str) -> Result<Vec<Space>> {
        let out = self
            .run(&[
                "list",
                "-H",
                "-p",
                "-o",
                "name,volsize,usedbydataset,usedbysnapshots",
                "-r",
                "-t",
                "filesystem,volume",
                &self.ds(name),
            ])
            .await?;
        space_lines(&out, &format!("{}/", self.pool))
    }

    /// What was written to a dataset since one of its snapshots (`written@<snap>`), in bytes.
    pub async fn written_since(&self, name: &str, snap: &str) -> Result<u64> {
        let out = self
            .run(&[
                "get",
                "-H",
                "-p",
                "-o",
                "value",
                &format!("written@{snap}"),
                &self.ds(name),
            ])
            .await?;
        out.trim()
            .parse()
            .map_err(|_| anyhow!("zfs written@{snap} of {name}: {:?}", out.trim()))
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

    /// The pool's used and free space, in one call. Unlike `free`, a value that does not
    /// parse is an error: the host's conditions are decided on it (ADR 0021).
    pub async fn pool(&self) -> Result<Pool> {
        let out = self
            .run(&[
                "get",
                "-H",
                "-p",
                "-o",
                "value",
                "used,available",
                &self.pool,
            ])
            .await?;
        let v: Vec<u64> = out
            .split_whitespace()
            .map(|v| v.parse())
            .collect::<Result<_, _>>()
            .map_err(|_| anyhow!("zfs get used,available {}: {out:?}", self.pool))?;
        match v[..] {
            [used, free] => Ok(Pool { used, free }),
            _ => Err(anyhow!("zfs get used,available {}: {out:?}", self.pool)),
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

/// The pool's space, in bytes: what its datasets take and what is left for them.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Pool {
    pub used: u64,
    pub free: u64,
}

impl Pool {
    pub fn size(&self) -> u64 {
        self.used + self.free
    }
}

/// What one dataset takes.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Space {
    /// Relative to the pool (`m/<id>/root`).
    pub name: String,
    /// A volume's allocated size; 0 for a filesystem.
    pub volsize: u64,
    /// What its own blocks take (`usedbydataset`).
    pub data: u64,
    /// What only its snapshots hold (`usedbysnapshots`).
    pub snapshots: u64,
}

/// `zfs list -H -p -o name,volsize,usedbydataset,usedbysnapshots` output; `-` is 0.
fn space_lines(out: &str, prefix: &str) -> Result<Vec<Space>> {
    let num = |v: &str| -> Result<u64> {
        match v {
            "-" => Ok(0),
            v => v
                .parse()
                .map_err(|_| anyhow!("zfs list: {v:?} is not a size")),
        }
    };
    let mut all = Vec::new();
    for line in out.lines().filter(|l| !l.trim().is_empty()) {
        let f: Vec<&str> = line.split('\t').collect();
        let [name, volsize, data, snapshots] = f[..] else {
            return Err(anyhow!("zfs list: {line:?}: want four fields"));
        };
        all.push(Space {
            name: name.strip_prefix(prefix).unwrap_or(name).to_string(),
            volsize: num(volsize)?,
            data: num(data)?,
            snapshots: num(snapshots)?,
        });
    }
    Ok(all)
}

/// A `zfs` that is a shell script over a directory: what the manager's tests run on too.
#[cfg(test)]
pub(crate) mod fake {
    use super::*;

    /// A stand-in for `zfs`, with the fake device root as its state: a directory per parent
    /// dataset, a file per volume or snapshot, and `<clone>.origin` naming the snapshot a
    /// clone was made from (a filesystem, made with a mountpoint, is a directory; `promote` moves that snapshot and the source's older ones, in the
    /// order `snapshots.order` keeps, to the clone and makes the source the clone's clone, as
    /// ZFS does). Every call is appended to `calls`, one line each;
    /// `get` answers come from `answer.<property>` files when there is one, else `origin` and
    /// `clones` from the `.origin` files, and `list -p` (space) from `answer.space`; `busy` holds how many destroys still answer
    /// "dataset is busy". A stream is one line naming its snapshot and its base, sent once no
    /// `hold.send` file is there; a receive makes the dataset and the snapshot, and refuses
    /// an increment whose base the dataset lacks, as ZFS does; `load-key` takes the line on its
    /// stdin when it is the `key` file's and answers `keystatus` `available` from then on;
    /// `change-key` needs the dataset.
    /// Error texts are the real ones,
    /// since the code matches on them.
    const FAKE: &str = r#"#!/bin/sh
DEV="__DEV__"
printf '%s\n' "$*" >> "__LOG__"
for a in "$@"; do last="$a"; done
missing() { echo "cannot open '$1': dataset does not exist" >&2; exit 1; }
# Renames the entries of the creation order that start with $1 to start with $2.
reorder() {
  [ -f "$DEV/snapshots.order" ] || return 0
  awk -v a="$1" -v b="$2" 'index($0, a) == 1 { $0 = b substr($0, length(a) + 1) } 1' \
    "$DEV/snapshots.order" > "$DEV/order.tmp" && mv "$DEV/order.tmp" "$DEV/snapshots.order"
}
# The clones of snapshot $1, comma-separated, or nothing.
clones_of() {
  find "$DEV" -name '*.origin' -exec grep -lxF "$1" {} + 2>/dev/null | sed "s|^$DEV/||; s|\.origin$||" | sort | paste -sd, -
}
case "$1" in
  list)
    if [ "$3" = "-t" ] && [ "$6" = "name,clones" ]; then
      [ -e "$DEV/$last" ] || missing "$last"
      [ -f "$DEV/snapshots.order" ] || exit 0
      awk '!seen[$0]++' "$DEV/snapshots.order" | while read -r s; do
        [ -e "$DEV/$s" ] || continue
        case "$s" in "$last"@*|"$last"/*) ;; *) continue;; esac
        c=$(clones_of "$s")
        printf '%s\t%s\n' "$s" "${c:--}"
      done
      exit 0
    fi
    if [ "$3" = "-p" ]; then
      [ -f "$DEV/answer.space" ] && cat "$DEV/answer.space"
      exit 0
    fi
    if [ "$3" = "-t" ]; then
      [ -e "$DEV/$last" ] || missing "$last"
      { ls -d "$DEV/$last"@* 2>/dev/null; [ -d "$DEV/$last" ] && find "$DEV/$last" -name '*@*'; } | sed "s|^$DEV/||" | sort
      exit 0
    fi
    if [ "$6" = "volume" ]; then
      [ -e "$DEV/$last" ] || missing "$last"
      find "$DEV/$last" -type f -not -name '*@*' -not -name '*.origin' | sed "s|^$DEV/||" | sort
      exit 0
    fi
    case "$last" in *boom*) echo "cannot open '$last': permission denied" >&2; exit 1;; esac
    if [ "$last" = "__POOL__" ] || [ -e "$DEV/$last" ]; then echo "$last"; exit 0; fi
    missing "$last";;
  create)
    case "$*" in *mountpoint=*) mkdir -p "$DEV/$last"; exit 0;; esac
    if [ "$2" = "-p" ]; then mkdir -p "$DEV/$last"; exit 0; fi
    mkdir -p "$(dirname "$DEV/$last")"; : > "$DEV/$last"; exit 0;;
  clone)
    [ -e "$DEV/$2" ] || missing "$2"
    mkdir -p "$(dirname "$DEV/$3")"; : > "$DEV/$3"; echo "$2" > "$DEV/$3.origin"; exit 0;;
  snapshot)
    shift
    for t in "$@"; do
      if [ -e "$DEV/$t" ]; then echo "cannot create snapshot '$t': dataset already exists" >&2; echo "no snapshots were created" >&2; exit 1; fi
    done
    for t in "$@"; do : > "$DEV/$t"; echo "$t" >> "$DEV/snapshots.order"; done; exit 0;;
  rename)
    [ -e "$DEV/$2" ] || missing "$2"
    if [ -e "$DEV/$3" ]; then echo "cannot create '$3': dataset already exists" >&2; exit 1; fi
    mkdir -p "$(dirname "$DEV/$3")"; mv "$DEV/$2" "$DEV/$3"
    [ -f "$DEV/$2.origin" ] && mv "$DEV/$2.origin" "$DEV/$3.origin"
    for f in "$DEV/$2"@*; do [ -e "$f" ] && mv "$f" "$DEV/$3@${f##*@}"; done
    find "$DEV" -name '*.origin' | while read -r f; do
      o=$(cat "$f"); case "$o" in "$2"@*) echo "$3@${o#*@}" > "$f";; esac
    done
    reorder "$2@" "$3@"; exit 0;;
  rollback)
    [ -e "$DEV/$2" ] || missing "$2"
    ds="${2%@*}"; seen=0
    while read -r s; do
      [ "$s" = "$2" ] && { seen=1; continue; }
      case "$s" in "$ds"@*) if [ $seen = 1 ] && [ -e "$DEV/$s" ]; then
        echo "cannot rollback to '$2': more recent snapshots or bookmarks exist" >&2; exit 1; fi;; esac
    done < "$DEV/snapshots.order"
    exit 0;;
  promote)
    [ -e "$DEV/$2" ] || missing "$2"
    if [ -f "$DEV/$2.origin" ]; then
      o=$(cat "$DEV/$2.origin"); src="${o%@*}"; snap="${o#*@}"
      # The origin snapshot and every snapshot of the source made before it move to the
      # clone, as in ZFS; clones of those follow them.
      for s in $(awk '!seen[$0]++' "$DEV/snapshots.order" 2>/dev/null); do
        case "$s" in "$src"@*) ;; *) continue;; esac
        [ -e "$DEV/$s" ] || continue
        mv "$DEV/$s" "$DEV/$2@${s#*@}"; reorder "$s" "$2@${s#*@}"
        find "$DEV" -name '*.origin' -exec grep -lxF "$s" {} + | while read -r c; do echo "$2@${s#*@}" > "$c"; done
        [ "$s" = "$o" ] && break
      done
      # The clone takes the source's origin; the source becomes the clone's clone.
      if [ -f "$DEV/$src.origin" ]; then mv "$DEV/$src.origin" "$DEV/$2.origin"; else rm -f "$DEV/$2.origin"; fi
      echo "$2@$snap" > "$DEV/$src.origin"
    fi
    exit 0;;
  destroy)
    if [ -f "$DEV/busy" ] && [ "$(cat "$DEV/busy")" -gt 0 ]; then
      echo $(($(cat "$DEV/busy") - 1)) > "$DEV/busy"
      echo "cannot destroy '$last': dataset is busy" >&2; exit 1
    fi
    case "$last" in *boom*) echo "cannot destroy '$last': permission denied" >&2; exit 1;; esac
    [ -e "$DEV/$last" ] || missing "$last"
    # Refused while a clone outside what goes depends on it, as in ZFS.
    for f in $(find "$DEV" -name '*.origin'); do
      o=$(cat "$f"); c="${f%.origin}"
      case "$o" in "$last"|"$last"@*|"$last"/*) ;; *) continue;; esac
      case "$c" in "$DEV/$last"/*) continue;; esac
      echo "cannot destroy '$last': it has dependent clones" >&2; exit 1
    done
    rm -rf "${DEV:?}/${last:?}" "$DEV/$last.origin" "$DEV/$last"@*; exit 0;;
  send)
    while [ -f "$DEV/hold.send" ]; do sleep 0.02; done
    base=-; [ "$3" = "-i" ] && base="${4#@}"
    if [ "$base" != - ] && [ ! -e "$DEV/${last%@*}@$base" ]; then
      echo "cannot send '$last': incremental source $base is not a snapshot of it" >&2; exit 1
    fi
    echo "stream ${last#*@} $base"; exit 0;;
  receive)
    read -r _ snap base
    if [ "$base" != - ] && [ ! -e "$DEV/$last@$base" ]; then
      echo "cannot receive incremental stream: most recent snapshot of $last does not match incremental source" >&2; exit 1
    fi
    mkdir -p "$(dirname "$DEV/$last")"; : > "$DEV/$last"; : > "$DEV/$last@$snap"
    echo "$last@$snap" >> "$DEV/snapshots.order"; exit 0;;
  load-key)
    read -r key
    if [ "$key" != "$(cat "$DEV/key" 2>/dev/null)" ]; then
      echo "Key load error: Incorrect key provided for '$last'." >&2; exit 255
    fi
    [ "$2" = -n ] || echo available > "$DEV/answer.keystatus"; exit 0;;
  change-key)
    [ -e "$DEV/$last" ] || missing "$last"; exit 0;;
  get)
    for a in "$@"; do prop="$last_but_one"; last_but_one="$a"; done
    if [ -f "$DEV/answer.$prop" ]; then cat "$DEV/answer.$prop"; exit 0; fi
    case "$prop" in
      origin)
        [ -e "$DEV/$last" ] || missing "$last"
        if [ -f "$DEV/$last.origin" ]; then cat "$DEV/$last.origin"; else echo "-"; fi; exit 0;;
      clones)
        [ -e "$DEV/$last" ] || missing "$last"
        find "$DEV" -name '*.origin' -exec grep -lx "$last" {} + 2>/dev/null | sed "s|^$DEV/||; s|\.origin$||" | sort | paste -sd, -
        exit 0;;
    esac
    exit 0;;
esac
exit 0
"#;

    /// A stand-in for `udevadm`: nothing to settle, the call is logged.
    const FAKE_UDEVADM: &str = "#!/bin/sh\nprintf 'udevadm %s\\n' \"$*\" >> \"__LOG__\"\n";

    pub(crate) struct Fake {
        dir: tempfile::TempDir,
        pub(crate) zfs: Zfs,
    }

    /// The fake binaries and the device root, before the pool is opened.
    pub(crate) struct Scripts {
        dir: tempfile::TempDir,
        pub(crate) zfs: PathBuf,
        pub(crate) udevadm: PathBuf,
        pub(crate) dev: PathBuf,
        pub(crate) jail: PathBuf,
    }

    impl Scripts {
        pub(crate) fn new() -> Scripts {
            let dir = tempfile::tempdir().unwrap();
            let dev = dir.path().join("dev");
            std::fs::create_dir_all(&dev).unwrap();
            let log = dir.path().join("calls");
            let zfs = dir.path().join("zfs");
            let udevadm = dir.path().join("udevadm");
            for (bin, script) in [(&zfs, FAKE), (&udevadm, FAKE_UDEVADM)] {
                let script = script
                    .replace("__DEV__", dev.to_str().unwrap())
                    .replace("__LOG__", log.to_str().unwrap())
                    .replace("__POOL__", "byard");
                std::fs::write(bin, script).unwrap();
            }
            let jail = dir.path().join("jail");
            Scripts {
                dir,
                zfs,
                udevadm,
                dev,
                jail,
            }
        }

        /// The pool opened, its layout made: the image and jail filesystems in the temp dir.
        pub(crate) async fn open(self, pool: &str) -> Result<Fake> {
            let zfs = self.pool(pool).await?;
            zfs.layout(&[
                ("images", &self.dir.path().join("images")),
                ("jail", &self.jail),
            ])
            .await?;
            Ok(Fake { dir: self.dir, zfs })
        }

        /// The pool opened, nothing made.
        pub(crate) async fn pool(&self, pool: &str) -> Result<Zfs> {
            Zfs::with_paths(
                pool,
                &Tool::script(&self.zfs),
                &Tool::script(&self.udevadm),
                &self.dev,
            )
            .await
        }

        pub(crate) fn answer(&self, prop: &str, value: &str) {
            std::fs::write(self.dev.join(format!("answer.{prop}")), value).unwrap();
        }
    }

    impl Fake {
        pub(crate) async fn open(pool: &str) -> Result<Fake> {
            Scripts::new().open(pool).await
        }

        pub(crate) fn dev(&self) -> PathBuf {
            self.dir.path().join("dev")
        }

        pub(crate) fn jail(&self) -> String {
            self.dir.path().join("jail").display().to_string()
        }

        pub(crate) fn images(&self) -> String {
            self.dir.path().join("images").display().to_string()
        }

        /// The calls so far, then forgets them.
        pub(crate) fn calls(&self) -> Vec<String> {
            let path = self.dir.path().join("calls");
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            let _ = std::fs::remove_file(&path);
            text.lines().map(String::from).collect()
        }

        pub(crate) fn answer(&self, prop: &str, value: &str) {
            std::fs::write(self.dev().join(format!("answer.{prop}")), value).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::{Fake, Scripts};
    use super::*;

    const SETTLE: &str = "udevadm settle --timeout=15";

    #[tokio::test]
    async fn opening_checks_the_pool_and_makes_the_layout() {
        let f = Fake::open("byard").await.unwrap();
        assert_eq!(
            f.calls(),
            vec![
                "list -H -o name byard".to_string(),
                "create -p byard/m".to_string(),
                "list -H -o name byard/images".to_string(),
                format!("create -o mountpoint={} byard/images", f.images()),
                "list -H -o name byard/jail".to_string(),
                format!("create -o mountpoint={} byard/jail", f.jail()),
            ]
        );
        assert!(f.dev().join("byard/images").is_dir());
        assert!(f.dev().join("byard/m").is_dir());

        let err = Fake::open("nope").await.err().unwrap();
        let msg = format!("{err:#}");
        assert!(msg.contains("zfs pool nope"), "{msg}");
        assert!(msg.contains("does not exist"), "{msg}");
    }

    /// `<pool>/jail` is mounted where `jail_dir` says: left alone when it already is, moved
    /// when the config changed, mounted when it is not.
    #[tokio::test]
    async fn the_jail_dataset_follows_the_config() {
        let jail = |s: &Scripts| {
            std::fs::create_dir_all(s.dev.join("byard")).unwrap();
            std::fs::create_dir_all(s.dev.join("byard/jail")).unwrap();
        };
        let s = Scripts::new();
        jail(&s);
        s.answer("mountpoint", &format!("{}\n", s.jail.display()));
        s.answer("mounted", "yes\n");
        let f = s.open("byard").await.unwrap();
        let calls = f.calls();
        assert_eq!(
            &calls[calls.len() - 3..],
            [
                "list -H -o name byard/jail",
                "get -H -o value mountpoint byard/jail",
                "get -H -o value mounted byard/jail",
            ]
        );

        let s = Scripts::new();
        jail(&s);
        s.answer("mountpoint", "/var/lib/briqyard/jail\n");
        s.answer("mounted", "no\n");
        let f = s.open("byard").await.unwrap();
        let calls = f.calls();
        assert_eq!(
            &calls[calls.len() - 5..],
            [
                "list -H -o name byard/jail".to_string(),
                "get -H -o value mountpoint byard/jail".to_string(),
                "get -H -o value mounted byard/jail".to_string(),
                format!("set mountpoint={} byard/jail", f.jail()),
                "mount byard/jail".to_string(),
            ]
        );
    }

    /// A filesystem is never mounted over files (ADR 0026): the records of a host whose state
    /// is still on `/` would vanish under an empty dataset, and the daemon would read every
    /// machine as gone. Where it is already mounted, what it holds is its own.
    #[tokio::test]
    async fn a_filesystem_is_never_mounted_over_files() {
        let s = Scripts::new();
        let state = s.jail.with_file_name("state");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join("machines"), b"").unwrap();
        let zfs = s.pool("byard").await.unwrap();
        let err = zfs.layout(&[("state", &state)]).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&format!("{} holds files", state.display()))
                && msg.contains("byard/state"),
            "{msg}"
        );
        assert!(!s.dev.join("byard/state").exists(), "nothing was made");

        // Mounted there already: nothing to do, whatever it holds.
        std::fs::create_dir_all(s.dev.join("byard/state")).unwrap();
        s.answer("mountpoint", &format!("{}\n", state.display()));
        s.answer("mounted", "yes\n");
        zfs.layout(&[("state", &state)]).await.unwrap();
    }

    /// The pool's key status, read from `keystatus` and, when locked, `encryptionroot`; the
    /// key goes on stdin and a wrong one is the error ZFS gives.
    #[tokio::test]
    async fn the_key_is_read_and_loaded() {
        let s = Scripts::new();
        let zfs = s.pool("byard").await.unwrap();
        s.answer("keystatus", "-\n");
        assert_eq!(zfs.key().await.unwrap(), Key::None);
        s.answer("keystatus", "available\n");
        assert_eq!(zfs.key().await.unwrap(), Key::Loaded);
        s.answer("keystatus", "unavailable\n");
        s.answer("encryptionroot", "byard\n");
        assert_eq!(
            zfs.key().await.unwrap(),
            Key::Locked {
                root: "byard".into()
            }
        );
        s.answer("keystatus", "\n");
        assert!(zfs.key().await.is_err(), "an answer it cannot read");

        s.answer("keystatus", "unavailable\n");
        let good = "ab".repeat(32);
        std::fs::write(s.dev.join("key"), &good).unwrap();
        let err = zfs.load_key("byard", &"cd".repeat(32)).await.unwrap_err();
        assert!(format!("{err:#}").contains("Incorrect key"), "{err:#}");
        assert!(
            !format!("{err:#}").contains(&"cd".repeat(32)),
            "the key is not in the error"
        );
        zfs.load_key("byard", &good).await.unwrap();
        assert_eq!(zfs.key().await.unwrap(), Key::Loaded);
        let log = std::fs::read_to_string(s.dev.parent().unwrap().join("calls")).unwrap();
        assert!(log.contains("load-key -L prompt byard"), "{log}");
        assert!(!log.contains(&good), "never on a command line: {log}");
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
        assert_eq!(dev, f.dev().join("byard/m/y/root"));
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

    #[tokio::test]
    async fn written_since_a_snapshot_is_a_count_or_an_error() {
        let f = Fake::open("byard").await.unwrap();
        f.answer("written@bk-1", "0\n");
        f.calls();
        assert_eq!(f.zfs.written_since("m/x/root", "bk-1").await.unwrap(), 0);
        assert_eq!(
            f.calls(),
            vec!["get -H -p -o value written@bk-1 byard/m/x/root"]
        );
        f.answer("written@bk-1", "8192\n");
        assert_eq!(f.zfs.written_since("m/x/root", "bk-1").await.unwrap(), 8192);
        // Unreadable is not "nothing written": the caller backs up rather than skip.
        f.answer("written@bk-1", "-\n");
        assert!(f.zfs.written_since("m/x/root", "bk-1").await.is_err());
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
    async fn the_pool_is_read_in_one_call_and_never_guessed() {
        let f = Fake::open("byard").await.unwrap();
        f.answer("used,available", "300\n700\n");
        f.calls();
        let p = f.zfs.pool().await.unwrap();
        assert_eq!((p.used, p.free, p.size()), (300, 700, 1000));
        assert_eq!(f.calls(), vec!["get -H -p -o value used,available byard"]);
        // What does not parse is an error, not an empty pool under pressure.
        for bad in ["-\n700\n", "300\n", ""] {
            f.answer("used,available", bad);
            let err = f.zfs.pool().await.unwrap_err();
            assert!(err.to_string().contains("used,available byard"), "{err}");
        }
    }

    #[tokio::test]
    async fn space_is_read_for_every_dataset_at_once() {
        let f = Fake::open("byard").await.unwrap();
        f.answer(
            "space",
            "byard/m\t-\t24576\t0\n\
             byard/m/m_1\t-\t12288\t0\n\
             byard/m/m_1/root\t8589934592\t52428800\t1048576\n",
        );
        f.calls();
        assert_eq!(
            f.zfs.space_under("m").await.unwrap(),
            [
                Space {
                    name: "m".into(),
                    volsize: 0,
                    data: 24576,
                    snapshots: 0
                },
                Space {
                    name: "m/m_1".into(),
                    volsize: 0,
                    data: 12288,
                    snapshots: 0
                },
                Space {
                    name: "m/m_1/root".into(),
                    volsize: 8 << 30,
                    data: 50 << 20,
                    snapshots: 1 << 20
                },
            ]
        );
        assert_eq!(
            f.calls(),
            ["list -H -p -o name,volsize,usedbydataset,usedbysnapshots -r -t filesystem,volume byard/m"]
        );
        // What is not a size is an error, not a zero: a wrong figure would be billed.
        assert!(space_lines("byard/m\tx\t0\t0\n", "byard/").is_err());
        assert!(space_lines("byard/m\t0\t0\n", "byard/").is_err());
        assert!(space_lines("", "byard/").unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_missing_binary_is_an_error() {
        let err = Zfs::with_paths(
            "byard",
            &Tool::program("/nonexistent/zfs"),
            &Tool::program("/nonexistent/udevadm"),
            Path::new("/dev/zvol"),
        )
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
