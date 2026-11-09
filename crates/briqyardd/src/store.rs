//! State on disk: one JSON file per record, written atomically. Small, readable, no database.
//! Records hold namespace secrets (a machine's env), so the files are the daemon's alone.

use anyhow::{anyhow, Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The directory of the namespaces' records. It keeps its name from before namespaces were
/// called tenants (ADR 0055): hosts already hold records there.
pub const NAMESPACES: &str = "tenants";

#[derive(Clone)]
pub struct Store {
    root: PathBuf,
    #[cfg(test)]
    pub(crate) fail_next_sync: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// A shared limit for a read-only inspection, not an I/O cancellation guarantee.
pub(crate) struct InspectionBudget {
    entries: usize,
    bytes: usize,
    deadline: tokio::time::Instant,
}

impl InspectionBudget {
    pub(crate) fn new(deadline: tokio::time::Instant) -> Self {
        Self {
            entries: 4096,
            bytes: 32 * 1024 * 1024,
            deadline,
        }
    }

    fn check(&self) -> Result<()> {
        anyhow::ensure!(
            tokio::time::Instant::now() < self.deadline,
            "state inspection deadline"
        );
        Ok(())
    }
}

/// Makes a directory the daemon's user alone can enter (0700), existing or not.
pub fn private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("make {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("mode of {}", path.display()))
}

/// Writes a file readable by the daemon's user alone (0600), whole: through a temp file next
/// to it, renamed over the old one, so a crash leaves the previous file or none.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    let tmp = path.with_file_name(name);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("write {}", tmp.display()))?;
    f.write_all(data)
        .with_context(|| format!("write {}", tmp.display()))?;
    f.sync_all()
        .with_context(|| format!("sync {}", tmp.display()))?;
    drop(f);
    std::fs::rename(&tmp, path).with_context(|| format!("rename {}", path.display()))?;
    Ok(())
}

impl Store {
    pub fn open(root: &Path) -> Result<Self> {
        let assignment_required = crate::assignment_compatibility::requirement(root)?;
        private_dir(root)?;
        for d in [
            "machines",
            NAMESPACES,
            "endpoints",
            "meta",
            "usage",
            "events",
            "holders",
            "backup-attempts",
            "clone-readers",
            "warm-pools",
            "sandbox-requests",
            "launch-holds",
            "launch-transitions",
            "unbound-requests",
            "unbound-assignments",
            "assigned-run-intents",
            "assigned-runs",
            "assigned-run-readers",
            "assigned-run-updates",
            "execution-idle-protection",
            "execution-namespace-fence",
        ] {
            private_dir(&root.join(d))?;
        }
        std::fs::File::open(root)?.sync_all()?;
        if assignment_required != crate::assignment_compatibility::Requirement::None {
            crate::assignment_compatibility::ensure_floor_at(root, assignment_required)?;
        }
        Ok(Self {
            root: root.to_path_buf(),
            #[cfg(test)]
            fail_next_sync: Default::default(),
        })
    }

    /// The directory of a kind, for a log that is not one record per file (events).
    pub fn dir(&self, kind: &str) -> PathBuf {
        self.root.join(kind)
    }

    /// The file of a record. A key is one file name, never a path: the API validates ids,
    /// and this refuses anything that would leave the kind's directory.
    fn path(&self, kind: &str, key: &str) -> Result<PathBuf> {
        if key.is_empty() || key.starts_with('.') || key.contains(['/', '\\']) || key.contains("..")
        {
            return Err(anyhow!("{kind} key {key:?} is not a file name"));
        }
        Ok(self.root.join(kind).join(format!("{key}.json")))
    }

    pub fn put<T: Serialize>(&self, kind: &str, key: &str, v: &T) -> Result<()> {
        anyhow::ensure!(
            kind != "meta" || key != "required-assignment-protocol",
            "permanent assignment floor cannot be overwritten"
        );
        let path = self.path(kind, key)?;
        let bytes = serde_json::to_vec_pretty(v)?;
        let mut minimum = crate::assignment_compatibility::record_requirement(
            kind,
            &serde_json::from_slice(&bytes)?,
        )?;
        // Replacing the last machine link must not erase evidence after marker loss.
        if kind == "machines"
            || kind == "assigned-run-updates"
            || crate::assignment_compatibility::RUN_COLLECTIONS.contains(&kind)
        {
            if let Some(previous) = self.get::<serde_json::Value>(kind, key)? {
                minimum = minimum.max(crate::assignment_compatibility::record_requirement(
                    kind, &previous,
                )?);
            }
        }
        if minimum != crate::assignment_compatibility::Requirement::None {
            crate::assignment_compatibility::ensure_floor_at(&self.root, minimum)?;
        }
        write_private(&path, &bytes)
    }

    /// Raise the durable downgrade fence before reserving incompatible lifecycle work.
    /// An error is uncertain durability and must retain all existing reservations.
    pub fn ensure_assigned_run_lifecycle_floor(&self) -> Result<()> {
        crate::assignment_compatibility::ensure_assigned_run_lifecycle_floor(&self.root)
    }

    pub(crate) fn sync_dir(&self, kind: &str) -> Result<()> {
        #[cfg(test)]
        if self
            .fail_next_sync
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            anyhow::bail!("injected directory sync failure");
        }
        let dir = self.dir(kind);
        std::fs::File::open(&dir)
            .and_then(|d| d.sync_all())
            .with_context(|| format!("sync {}", dir.display()))
    }

    /// Crash-durable record boundary for immutable snapshot publication and read intents.
    pub fn put_durable<T: Serialize>(&self, kind: &str, key: &str, v: &T) -> Result<()> {
        self.put_durable_published(kind, key, v, || {})
    }

    /// Publish the renamed record to its owner before directory sync can fail. The owner
    /// must retain it on an uncertain sync and fence later persistence until durable.
    pub(crate) fn put_durable_published<T: Serialize>(
        &self,
        kind: &str,
        key: &str,
        v: &T,
        published: impl FnOnce(),
    ) -> Result<()> {
        self.put(kind, key, v)?;
        published();
        self.sync_dir(kind)
    }

    pub fn delete_durable(&self, kind: &str, key: &str) -> Result<()> {
        self.delete(kind, key)?;
        self.sync_dir(kind)
    }

    #[allow(dead_code)]
    pub fn get<T: DeserializeOwned>(&self, kind: &str, key: &str) -> Result<Option<T>> {
        let path = self.path(kind, key)?;
        match std::fs::read(&path) {
            Ok(data) => Ok(Some(
                serde_json::from_slice(&data).with_context(|| format!("{kind}/{key}"))?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
        }
    }

    pub fn delete(&self, kind: &str, key: &str) -> Result<()> {
        anyhow::ensure!(
            kind != "unbound-requests"
                && !(kind == "meta" && key == "required-assignment-protocol"),
            "permanent assignment authority cannot be deleted"
        );
        // Preserve evidence before deleting its last surviving copy after marker loss.
        if matches!(
            kind,
            "machines" | "unbound-assignments" | "assigned-run-updates"
        ) || crate::assignment_compatibility::RUN_COLLECTIONS.contains(&kind)
        {
            if let Some(value) = self.get::<serde_json::Value>(kind, key)? {
                let required = crate::assignment_compatibility::record_requirement(kind, &value)?;
                if required != crate::assignment_compatibility::Requirement::None {
                    crate::assignment_compatibility::ensure_floor_at(&self.root, required)?;
                }
            }
        }
        let path = self.path(kind, key)?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("remove {}", path.display())),
        }
    }

    /// Every record of a kind. A record deleted while the directory is being read (a clone's
    /// reader released, a hold dropped by another request) is gone, not an error: it is left out.
    pub fn list<T: DeserializeOwned>(&self, kind: &str) -> Result<Vec<T>> {
        self.list_with(kind, |_| {})
    }

    /// Inspect complete keyed records within one shared budget. Unlike a normal live
    /// listing, disappearance is unknown, not absence. Never follows record symlinks.
    pub(crate) fn inspect<T: DeserializeOwned>(
        &self,
        kind: &str,
        budget: &mut InspectionBudget,
    ) -> Result<std::collections::BTreeMap<String, T>> {
        use std::io::Read;
        budget.check()?;
        anyhow::ensure!(
            std::fs::symlink_metadata(self.dir(kind))?
                .file_type()
                .is_dir(),
            "state inspection requires a directory"
        );
        let mut out = std::collections::BTreeMap::new();
        for entry in std::fs::read_dir(self.dir(kind))? {
            budget.check()?;
            budget.entries = budget
                .entries
                .checked_sub(1)
                .context("state inspection entry limit")?;
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().context("state inspection filename")?;
            let Some(key) = name.strip_suffix(".json") else {
                continue;
            };
            anyhow::ensure!(
                entry.file_type()?.is_file(),
                "state inspection requires regular files"
            );
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(self.path(kind, key)?)?;
            anyhow::ensure!(
                file.metadata()?.is_file(),
                "state inspection requires regular files"
            );
            let mut data = Vec::new();
            file.take(budget.bytes as u64 + 1).read_to_end(&mut data)?;
            budget.bytes = budget
                .bytes
                .checked_sub(data.len())
                .context("state inspection byte limit")?;
            budget.check()?;
            out.insert(key.into(), serde_json::from_slice(&data)?);
        }
        budget.check()?;
        Ok(out)
    }

    /// [`Self::list`], with `between` called on each record's path after the directory entry
    /// is read and before the file is, where a concurrent delete lands.
    fn list_with<T: DeserializeOwned>(
        &self,
        kind: &str,
        between: impl Fn(&Path),
    ) -> Result<Vec<T>> {
        let mut out = Vec::new();
        let dir = self.root.join(kind);
        for entry in std::fs::read_dir(&dir).with_context(|| format!("list {}", dir.display()))? {
            let entry = entry.with_context(|| format!("list {}", dir.display()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".json") {
                continue;
            }
            let path = entry.path();
            between(&path);
            let data = match std::fs::read(&path) {
                Ok(data) => data,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
            };
            out.push(serde_json::from_slice(&data).with_context(|| format!("{kind}/{name}"))?);
        }
        Ok(out)
    }

    /// The keys of a kind, sorted.
    pub fn keys(&self, kind: &str) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        let dir = self.root.join(kind);
        for entry in std::fs::read_dir(&dir).with_context(|| format!("list {}", dir.display()))? {
            let name = entry
                .with_context(|| format!("list {}", dir.display()))?
                .file_name()
                .to_string_lossy()
                .into_owned();
            if let Some(k) = name.strip_suffix(".json") {
                keys.push(k.to_string());
            }
        }
        keys.sort();
        Ok(keys)
    }

    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        let path = self.path("meta", key)?;
        match std::fs::read_to_string(&path) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
        }
    }

    pub fn put_meta(&self, key: &str, value: &str) -> Result<()> {
        anyhow::ensure!(
            key != "required-assignment-protocol",
            "permanent assignment floor cannot be overwritten"
        );
        write_private(&self.path("meta", key)?, value.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    struct Rec {
        id: String,
        n: u32,
    }

    fn open() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("state")).unwrap();
        (dir, store)
    }

    fn rec(id: &str, n: u32) -> Rec {
        Rec { id: id.into(), n }
    }

    #[test]
    fn maintenance_inspection_limits_are_shared_and_expiry_never_means_empty() {
        let (_dir, store) = open();
        store.put("machines", "one", &rec("one", 1)).unwrap();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut budget = InspectionBudget::new(deadline);
        budget.entries = 1;
        assert_eq!(
            store.inspect::<Rec>("machines", &mut budget).unwrap().len(),
            1
        );
        assert!(store.inspect::<Rec>("machines", &mut budget).is_err());
        let mut budget = InspectionBudget::new(deadline);
        budget.bytes = 1;
        assert!(store.inspect::<Rec>("machines", &mut budget).is_err());
        let mut budget = InspectionBudget::new(tokio::time::Instant::now());
        assert!(store.inspect::<Rec>("warm-pools", &mut budget).is_err());
    }

    #[test]
    fn maintenance_inspection_refuses_symlinks_and_malformed_records_without_changes() {
        let (_dir, store) = open();
        store.put("machines", "one", &rec("one", 1)).unwrap();
        let link = store.dir("warm-pools").join("link.json");
        std::os::unix::fs::symlink(store.dir("machines").join("one.json"), &link).unwrap();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        assert!(store
            .inspect::<Rec>("warm-pools", &mut InspectionBudget::new(deadline))
            .is_err());
        std::fs::remove_file(link).unwrap();
        let bad = store.dir("warm-pools").join("bad.json");
        std::fs::write(&bad, b"invalid").unwrap();
        assert!(store
            .inspect::<Rec>("warm-pools", &mut InspectionBudget::new(deadline))
            .is_err());
        assert_eq!(std::fs::read(bad).unwrap(), b"invalid");
    }

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn open_makes_the_kinds() {
        let (dir, _) = open();
        for d in [
            "machines",
            NAMESPACES,
            "endpoints",
            "meta",
            "usage",
            "events",
            "holders",
            "clone-readers",
            "warm-pools",
            "sandbox-requests",
            "launch-holds",
            "launch-transitions",
            "unbound-requests",
            "unbound-assignments",
            "assigned-run-intents",
            "assigned-runs",
            "assigned-run-readers",
        ] {
            assert!(dir.path().join("state").join(d).is_dir(), "{d}");
        }
        assert_eq!(store_dir(&dir), dir.path().join("state/events"));
        // Opening again over an existing state dir is fine.
        Store::open(&dir.path().join("state")).unwrap();
    }

    #[test]
    fn put_get_list_delete() {
        let (dir, store) = open();
        let (a, b) = (rec("m_a", 1), rec("m_b", 2));
        store.put("machines", &a.id, &a).unwrap();
        store.put("machines", &b.id, &b).unwrap();
        assert_eq!(
            store.get::<Rec>("machines", "m_a").unwrap(),
            Some(a.clone())
        );
        assert!(dir.path().join("state/machines/m_a.json").is_file());

        let mut all: Vec<Rec> = store.list("machines").unwrap();
        all.sort_by(|x, y| x.id.cmp(&y.id));
        assert_eq!(all, vec![a.clone(), b.clone()]);

        // A put over an existing key replaces it.
        let a2 = rec("m_a", 10);
        store.put("machines", &a.id, &a2).unwrap();
        assert_eq!(store.get::<Rec>("machines", "m_a").unwrap(), Some(a2));

        store.delete("machines", "m_a").unwrap();
        assert_eq!(store.get::<Rec>("machines", "m_a").unwrap(), None);
        let all: Vec<Rec> = store.list("machines").unwrap();
        assert_eq!(all, vec![b]);
    }

    #[test]
    fn missing_key_is_none_and_delete_is_idempotent() {
        let (_dir, store) = open();
        assert_eq!(store.get::<Rec>("machines", "nope").unwrap(), None);
        store.delete("machines", "nope").unwrap();
        let none: Vec<Rec> = store.list(NAMESPACES).unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn a_key_is_a_file_name_not_a_path() {
        let (dir, store) = open();
        let r = rec("x", 1);
        for key in [
            "",
            "../../etc/cron.d/x",
            "..",
            "a/b",
            "a\\b",
            "/etc/passwd",
            ".hidden",
            "a..b",
        ] {
            let err = store.put(NAMESPACES, key, &r).unwrap_err();
            assert!(
                err.to_string().contains("not a file name"),
                "{key:?}: {err}"
            );
            assert!(store.get::<Rec>(NAMESPACES, key).is_err(), "{key:?}");
            assert!(store.delete(NAMESPACES, key).is_err(), "{key:?}");
            assert!(store.get_meta(key).is_err(), "{key:?}");
            assert!(store.put_meta(key, "v").is_err(), "{key:?}");
        }
        // Nothing landed outside the kind's directory, and the kind is still empty.
        assert!(!dir.path().join("etc").exists());
        assert!(!dir.path().join("state/etc").exists());
        let none: Vec<Rec> = store.list(NAMESPACES).unwrap();
        assert!(none.is_empty());
        // Ids as the API makes them are fine.
        store.put(NAMESPACES, "t_abc-123", &r).unwrap();
        assert_eq!(store.get::<Rec>(NAMESPACES, "t_abc-123").unwrap(), Some(r));
    }

    #[test]
    fn writes_are_atomic() {
        let (dir, store) = open();
        let r = rec("m_a", 1);
        store.put("machines", &r.id, &r).unwrap();
        store.put_meta("host_id", "h_1").unwrap();
        let leftovers: Vec<String> = walk(dir.path())
            .into_iter()
            .filter(|p| p.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        // The file is the record, pretty-printed, so an operator can read it.
        let text = std::fs::read_to_string(dir.path().join("state/machines/m_a.json")).unwrap();
        assert!(text.contains("\"id\": \"m_a\""), "{text}");
    }

    #[test]
    fn files_are_the_daemons_alone() {
        let (dir, store) = open();
        let r = rec("m_a", 1);
        store.put("machines", &r.id, &r).unwrap();
        store.put_meta("host_id", "h_1").unwrap();
        let state = dir.path().join("state");
        assert_eq!(mode(&state), 0o700);
        for d in [
            "machines",
            NAMESPACES,
            "endpoints",
            "meta",
            "usage",
            "events",
            "holders",
            "clone-readers",
            "warm-pools",
            "sandbox-requests",
            "launch-holds",
            "launch-transitions",
            "unbound-requests",
            "unbound-assignments",
            "assigned-run-intents",
            "assigned-runs",
            "assigned-run-readers",
        ] {
            assert_eq!(mode(&state.join(d)), 0o700, "{d}");
        }
        assert_eq!(mode(&state.join("machines/m_a.json")), 0o600);
        assert_eq!(mode(&state.join("meta/host_id.json")), 0o600);
        // A directory that existed wider is tightened on open.
        let wide = dir.path().join("wide");
        std::fs::create_dir(&wide).unwrap();
        std::fs::set_permissions(&wide, std::fs::Permissions::from_mode(0o755)).unwrap();
        Store::open(&wide).unwrap();
        assert_eq!(mode(&wide), 0o700);
    }

    #[test]
    fn list_skips_what_is_not_a_record() {
        let (dir, store) = open();
        let r = rec("m_a", 1);
        store.put("machines", &r.id, &r).unwrap();
        // A temp file a crash left behind, and a stray file: neither is a record.
        std::fs::write(dir.path().join("state/machines/m_b.json.tmp"), b"{").unwrap();
        std::fs::write(dir.path().join("state/machines/README"), b"x").unwrap();
        let all: Vec<Rec> = store.list("machines").unwrap();
        assert_eq!(all, vec![r.clone()]);
        // Keys too, sorted.
        store.put("machines", "m_0", &r).unwrap();
        assert_eq!(store.keys("machines").unwrap(), ["m_0", "m_a"]);
    }

    #[test]
    fn list_skips_a_record_deleted_while_it_is_read() {
        let (_dir, store) = open();
        for (id, n) in [("m_a", 1), ("m_b", 2), ("m_c", 3)] {
            store.put("machines", id, &rec(id, n)).unwrap();
        }
        // Another request deletes m_b after the directory entry is read, before the file is.
        let all: Vec<Rec> = store
            .list_with("machines", |path| {
                if path.ends_with("m_b.json") {
                    std::fs::remove_file(path).unwrap();
                }
            })
            .unwrap();
        let mut ids: Vec<_> = all.iter().map(|r| r.id.as_str()).collect();
        ids.sort();
        assert_eq!(ids, ["m_a", "m_c"]);
    }

    #[test]
    fn io_errors_name_the_operation_and_path() {
        let (dir, store) = open();
        // A directory where a record file should be: the read fails, not with NotFound.
        std::fs::create_dir(dir.path().join("state/machines/m_dir.json")).unwrap();
        let err = store.list::<Rec>("machines").unwrap_err();
        let text = format!("{err:#}");
        assert!(
            text.contains("read ") && text.contains("m_dir.json"),
            "{text}"
        );
        let err = store.keys("nope").unwrap_err();
        assert!(format!("{err:#}").contains("list "), "{err:#}");
    }

    #[test]
    fn a_broken_record_is_an_error_with_its_name() {
        let (dir, store) = open();
        std::fs::write(dir.path().join("state/machines/m_bad.json"), b"{not json").unwrap();
        let err = store.get::<Rec>("machines", "m_bad").unwrap_err();
        assert!(err.to_string().contains("machines/m_bad"), "{err:#}");
        let err = store.list::<Rec>("machines").unwrap_err();
        assert!(err.to_string().contains("machines/m_bad.json"), "{err:#}");
    }

    #[test]
    fn meta_is_a_plain_string() {
        let (dir, store) = open();
        assert_eq!(store.get_meta("host_id").unwrap(), None);
        store.put_meta("host_id", "h_abc").unwrap();
        assert_eq!(store.get_meta("host_id").unwrap().as_deref(), Some("h_abc"));
        store.put_meta("host_id", "h_def").unwrap();
        assert_eq!(store.get_meta("host_id").unwrap().as_deref(), Some("h_def"));
        assert!(dir.path().join("state/meta/host_id.json").is_file());
        assert!(!dir.path().join("state/meta/host_id.json.tmp").exists());
    }

    fn store_dir(dir: &tempfile::TempDir) -> PathBuf {
        Store::open(&dir.path().join("state"))
            .unwrap()
            .dir("events")
    }

    fn walk(dir: &Path) -> Vec<String> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p.to_string_lossy().into_owned());
            }
        }
        out
    }
}
