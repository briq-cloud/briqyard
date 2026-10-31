//! The ZFS storage backend: one zvol per disk, in one pool. Names are paths under the pool
//! ("images/abc", "m/<id>/root"). Every method is idempotent where it can be.

use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::process::Command;

mod pool;
mod run;
mod snapshot;
mod volume;

pub use pool::{Pool, Space};
pub use snapshot::SnapshotOf;

/// A `zfs` command that runs this long makes the host `storage_stalled` (ADR 0046).
pub const STALL_AFTER: Duration = Duration::from_secs(60);
/// How long a volume's device link may take to be right (ADR 0046).
const LINK_WAIT: Duration = Duration::from_secs(15);
/// The part of it `udevadm settle` may take.
const SETTLE_WAIT: Duration = Duration::from_secs(5);

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
        let mut c = crate::host_process::command(&self.program);
        c.args(&self.leading);
        c
    }
}

/// The commands the backend runs; fake ones in tests.
#[derive(Clone, Debug)]
pub struct Tools {
    pub zfs: Tool,
    pub udevadm: Tool,
    /// Names the dataset a zvol device is now (the program udev's own rule runs).
    pub zvol_id: Tool,
}

impl Tools {
    pub fn host() -> Self {
        Self {
            zfs: Tool::program("zfs"),
            udevadm: Tool::program("udevadm"),
            zvol_id: Tool::program("/usr/lib/udev/zvol_id"),
        }
    }
}

#[derive(Clone)]
pub struct Zfs {
    pool: String,
    tools: Tools,
    /// Where udev links zvols (`/dev/zvol/<dataset>`).
    dev_root: PathBuf,
    /// The `zfs` commands running now (ADR 0046).
    running: Arc<Mutex<Running>>,
}

/// The `zfs` commands running, each with when it started and what it is.
#[derive(Default)]
struct Running {
    next: u64,
    calls: HashMap<u64, (Instant, String)>,
}

/// One running command's entry, removed when the command ends.
struct Call(Arc<Mutex<Running>>, u64);

impl Drop for Call {
    fn drop(&mut self) {
        self.0.lock().unwrap().calls.remove(&self.1);
    }
}

/// What a volume's link says now.
enum Link {
    /// The device it names, which is that volume.
    Right(PathBuf),
    /// The device it names, which is another dataset or none (`zvol_id`'s answer).
    Wrong(PathBuf, String),
    Missing,
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
        Self::with_paths(pool, &Tools::host(), Path::new("/dev/zvol")).await
    }

    /// `new` with the commands and the link root given, so tests can stand in for them
    /// without ZFS on the machine.
    pub async fn with_paths(pool: &str, tools: &Tools, dev_root: &Path) -> Result<Self> {
        let z = Self {
            pool: pool.to_string(),
            tools: tools.clone(),
            dev_root: dev_root.to_path_buf(),
            running: Arc::default(),
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
        let root = self.get_ds(&self.pool, "encryptionroot").await?;
        self.run_input(
            &["load-key", "-n", "-L", "prompt", &root],
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
}

/// A `zfs` that is a shell script over a directory: what the manager's tests run on too.
#[cfg(test)]
pub(crate) mod fake;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zfs::fake::{Fake, Scripts};

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
}
