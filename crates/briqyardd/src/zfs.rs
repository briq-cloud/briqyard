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

/// The filesystem dataset the jails live on (ADR 0014).
const JAIL_DATASET: &str = "jail";

impl Zfs {
    /// Opens the pool, makes the parent datasets the layout needs, and mounts `<pool>/jail`
    /// at `jail_dir`: every chroot and memory snapshot then lands on the pool, not on `/`.
    pub async fn new(pool: &str, jail_dir: &Path) -> Result<Self> {
        Self::with_paths(
            pool,
            &Tool::program("zfs"),
            &Tool::program("udevadm"),
            Path::new("/dev/zvol"),
            jail_dir,
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
        jail_dir: &Path,
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
        for d in ["images", "m"] {
            z.run(&["create", "-p", &z.ds(d)]).await?;
        }
        z.mount(JAIL_DATASET, jail_dir).await?;
        Ok(z)
    }

    /// Makes `name` a filesystem mounted at `dir`, whatever it was before: made, moved or
    /// mounted as needed, nothing when it is already there.
    async fn mount(&self, name: &str, dir: &Path) -> Result<()> {
        let ds = self.ds(name);
        let want = format!("mountpoint={}", dir.display());
        if !self.exists(name).await? {
            self.run(&["create", "-o", &want, &ds]).await?;
            return Ok(());
        }
        if self.get(name, "mountpoint").await? != dir.display().to_string() {
            self.run(&["set", &want, &ds]).await?;
        }
        if self.get(name, "mounted").await? != "yes" {
            self.run(&["mount", &ds]).await?;
        }
        Ok(())
    }

    async fn get(&self, name: &str, property: &str) -> Result<String> {
        let out = self
            .run(&["get", "-H", "-o", "value", property, &self.ds(name)])
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

    /// Every snapshot under a dataset, as `name@snap` relative to the pool.
    pub async fn snapshots_under(&self, name: &str) -> Result<Vec<String>> {
        let out = self
            .run(&[
                "list",
                "-H",
                "-t",
                "snapshot",
                "-o",
                "name",
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

    /// Promotes every clone of every snapshot of a dataset, so that destroying the dataset is
    /// not refused for "dependent clones": a machine's forks outlive it.
    pub async fn release_clones(&self, name: &str) -> Result<()> {
        let prefix = format!("{}/", self.pool);
        for snap in self.snapshots(name).await? {
            for clone in self.clones(name, &snap).await? {
                let rel = clone.strip_prefix(&prefix).unwrap_or(&clone);
                self.promote(rel).await?;
            }
        }
        Ok(())
    }

    /// Starts `zfs send` of a snapshot (incremental from `from` when given), compressed as
    /// stored; the caller reads the stream from the child's stdout and waits for it.
    pub fn send(
        &self,
        name: &str,
        snap: &str,
        from: Option<&str>,
    ) -> Result<tokio::process::Child> {
        let target = format!("{}@{snap}", self.ds(name));
        let mut cmd = self.binary.command();
        cmd.arg("send").arg("-c");
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

/// A `zfs` that is a shell script over a directory: what the manager's tests run on too.
#[cfg(test)]
pub(crate) mod fake {
    use super::*;

    /// A stand-in for `zfs`, with the fake device root as its state: a directory per parent
    /// dataset, a file per volume or snapshot, and `<clone>.origin` naming the snapshot a
    /// clone was made from (`promote` moves that snapshot to the clone and makes the source
    /// the clone's clone, as ZFS does). Every call is appended to `calls`, one line each;
    /// `get` answers come from `answer.<property>` files when there is one, else `origin` and
    /// `clones` from the `.origin` files; `busy` holds how many destroys still answer
    /// "dataset is busy". Error texts are the real ones, since the code matches on them.
    const FAKE: &str = r#"#!/bin/sh
DEV="__DEV__"
printf '%s\n' "$*" >> "__LOG__"
for a in "$@"; do last="$a"; done
missing() { echo "cannot open '$1': dataset does not exist" >&2; exit 1; }
case "$1" in
  list)
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
    if [ "$2" = "-p" ]; then mkdir -p "$DEV/$last"; exit 0; fi
    mkdir -p "$(dirname "$DEV/$last")"; : > "$DEV/$last"; exit 0;;
  clone)
    [ -e "$DEV/$2" ] || missing "$2"
    mkdir -p "$(dirname "$DEV/$3")"; : > "$DEV/$3"; echo "$2" > "$DEV/$3.origin"; exit 0;;
  snapshot)
    if [ -e "$DEV/$2" ]; then echo "cannot create snapshot '$2': dataset already exists" >&2; exit 1; fi
    : > "$DEV/$2"; exit 0;;
  promote)
    [ -e "$DEV/$2" ] || missing "$2"
    if [ -f "$DEV/$2.origin" ]; then
      o=$(cat "$DEV/$2.origin"); src="${o%@*}"; snap="${o#*@}"
      mv "$DEV/$o" "$DEV/$2@$snap"; echo "$2@$snap" > "$DEV/$src.origin"; rm "$DEV/$2.origin"
    fi
    exit 0;;
  destroy)
    if [ -f "$DEV/busy" ] && [ "$(cat "$DEV/busy")" -gt 0 ]; then
      echo $(($(cat "$DEV/busy") - 1)) > "$DEV/busy"
      echo "cannot destroy '$last': dataset is busy" >&2; exit 1
    fi
    case "$last" in *boom*) echo "cannot destroy '$last': permission denied" >&2; exit 1;; esac
    [ -e "$DEV/$last" ] || missing "$last"
    rm -rf "${DEV:?}/${last:?}" "$DEV/$last.origin"; exit 0;;
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

        pub(crate) async fn open(self, pool: &str) -> Result<Fake> {
            let zfs = Zfs::with_paths(
                pool,
                &Tool::script(&self.zfs),
                &Tool::script(&self.udevadm),
                &self.dev,
                &self.jail,
            )
            .await?;
            Ok(Fake { dir: self.dir, zfs })
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
                "create -p byard/images".to_string(),
                "create -p byard/m".to_string(),
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
        let s = Scripts::new();
        std::fs::create_dir_all(s.dev.join("byard")).unwrap();
        std::fs::write(s.dev.join("byard/jail"), b"").unwrap();
        s.answer("mountpoint", &format!("{}\n", s.jail.display()));
        s.answer("mounted", "yes\n");
        let f = s.open("byard").await.unwrap();
        let calls = f.calls();
        assert_eq!(
            &calls[3..],
            [
                "list -H -o name byard/jail",
                "get -H -o value mountpoint byard/jail",
                "get -H -o value mounted byard/jail",
            ]
        );

        let s = Scripts::new();
        std::fs::create_dir_all(s.dev.join("byard")).unwrap();
        std::fs::write(s.dev.join("byard/jail"), b"").unwrap();
        s.answer("mountpoint", "/var/lib/briqyard/jail\n");
        s.answer("mounted", "no\n");
        let f = s.open("byard").await.unwrap();
        let calls = f.calls();
        assert_eq!(
            &calls[3..],
            [
                "list -H -o name byard/jail".to_string(),
                "get -H -o value mountpoint byard/jail".to_string(),
                format!("set mountpoint={} byard/jail", f.jail()),
                "get -H -o value mounted byard/jail".to_string(),
                "mount byard/jail".to_string(),
            ]
        );
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
        f.zfs.release_clones("m/x/root").await.unwrap();
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
        f.zfs.release_clones("m/w/root").await.unwrap();
        assert!(f.calls().iter().all(|c| !c.starts_with("promote")));
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
        // Every snapshot under a dataset, by its full relative name.
        f.zfs.snapshot("m/b/root", "s_1").await.unwrap();
        assert_eq!(
            f.zfs.snapshots_under("m").await.unwrap(),
            ["m/b/root@s_1", "m/s/root@fork-a"]
        );
        assert_eq!(
            f.calls().last().unwrap(),
            "list -H -t snapshot -o name -r byard/m"
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
            &Tool::program("/nonexistent/zfs"),
            &Tool::program("/nonexistent/udevadm"),
            Path::new("/dev/zvol"),
            Path::new("/var/lib/briqyard/jail"),
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
