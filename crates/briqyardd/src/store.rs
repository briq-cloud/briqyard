//! State on disk: one JSON file per record, written atomically. Small, readable, no database.

use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn open(root: &Path) -> Result<Self> {
        for d in ["machines", "tenants", "endpoints", "meta"] {
            std::fs::create_dir_all(root.join(d))
                .with_context(|| format!("state dir {}", root.display()))?;
        }
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    fn path(&self, kind: &str, key: &str) -> PathBuf {
        self.root.join(kind).join(format!("{key}.json"))
    }

    pub fn put<T: Serialize>(&self, kind: &str, key: &str, v: &T) -> Result<()> {
        let path = self.path(kind, key);
        let tmp = path.with_extension("json.tmp");
        let data = serde_json::to_vec_pretty(v)?;
        std::fs::write(&tmp, data).with_context(|| format!("write {}", tmp.display()))?;
        std::fs::rename(&tmp, &path).with_context(|| format!("rename {}", path.display()))?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn get<T: DeserializeOwned>(&self, kind: &str, key: &str) -> Result<Option<T>> {
        match std::fs::read(self.path(kind, key)) {
            Ok(data) => Ok(Some(
                serde_json::from_slice(&data).with_context(|| format!("{kind}/{key}"))?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn delete(&self, kind: &str, key: &str) -> Result<()> {
        match std::fs::remove_file(self.path(kind, key)) {
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
        match std::fs::read_to_string(self.path("meta", key)) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn put_meta(&self, key: &str, value: &str) -> Result<()> {
        let path = self.path("meta", key);
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, value)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }
}
