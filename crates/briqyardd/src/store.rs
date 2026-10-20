//! State on disk: one JSON file per record, written atomically. Small, readable, no database.
//! Records hold tenant secrets (a machine's env), so the files are the daemon's alone.

use anyhow::{anyhow, Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct Store {
    root: PathBuf,
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
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path).with_context(|| format!("rename {}", path.display()))?;
    Ok(())
}

impl Store {
    pub fn open(root: &Path) -> Result<Self> {
        private_dir(root)?;
        for d in ["machines", "tenants", "endpoints", "meta"] {
            private_dir(&root.join(d))?;
        }
        Ok(Self {
            root: root.to_path_buf(),
        })
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
        write_private(&self.path(kind, key)?, &serde_json::to_vec_pretty(v)?)
    }

    #[allow(dead_code)]
    pub fn get<T: DeserializeOwned>(&self, kind: &str, key: &str) -> Result<Option<T>> {
        match std::fs::read(self.path(kind, key)?) {
            Ok(data) => Ok(Some(
                serde_json::from_slice(&data).with_context(|| format!("{kind}/{key}"))?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn delete(&self, kind: &str, key: &str) -> Result<()> {
        match std::fs::remove_file(self.path(kind, key)?) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn list<T: DeserializeOwned>(&self, kind: &str) -> Result<Vec<T>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(self.root.join(kind))? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".json") {
                continue;
            }
            let data = std::fs::read(entry.path())?;
            out.push(serde_json::from_slice(&data).with_context(|| format!("{kind}/{name}"))?);
        }
        Ok(out)
    }

    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        match std::fs::read_to_string(self.path("meta", key)?) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn put_meta(&self, key: &str, value: &str) -> Result<()> {
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

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn open_makes_the_kinds() {
        let (dir, _) = open();
        for d in ["machines", "tenants", "endpoints", "meta"] {
            assert!(dir.path().join("state").join(d).is_dir(), "{d}");
        }
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
        let none: Vec<Rec> = store.list("tenants").unwrap();
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
            let err = store.put("tenants", key, &r).unwrap_err();
            assert!(
                err.to_string().contains("not a file name"),
                "{key:?}: {err}"
            );
            assert!(store.get::<Rec>("tenants", key).is_err(), "{key:?}");
            assert!(store.delete("tenants", key).is_err(), "{key:?}");
            assert!(store.get_meta(key).is_err(), "{key:?}");
            assert!(store.put_meta(key, "v").is_err(), "{key:?}");
        }
        // Nothing landed outside the kind's directory, and the kind is still empty.
        assert!(!dir.path().join("etc").exists());
        assert!(!dir.path().join("state/etc").exists());
        let none: Vec<Rec> = store.list("tenants").unwrap();
        assert!(none.is_empty());
        // Ids as the API makes them are fine.
        store.put("tenants", "t_abc-123", &r).unwrap();
        assert_eq!(store.get::<Rec>("tenants", "t_abc-123").unwrap(), Some(r));
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
        for d in ["machines", "tenants", "endpoints", "meta"] {
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
        assert_eq!(all, vec![r]);
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
