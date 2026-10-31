//! File-backed memory cloning never changes shared inode ownership or permissions.
use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[derive(Clone, Debug)]
pub struct MemoryClone {
    pub state: PathBuf,
    pub memory: PathBuf,
}

/// Deliberately distinct from ResumeFailed: legacy cold fallback must not catch this.
#[derive(Debug, thiserror::Error)]
#[error("named memory clone failed: {0}")]
pub struct MemoryCloneFailed(pub String);

pub(super) fn shared_backing(root: &Path, host: &Path, name: &str) -> Result<PathBuf> {
    anyhow::ensure!(
        matches!(name, "clone.state" | "clone.mem"),
        "invalid clone backing name"
    );
    let before = std::fs::symlink_metadata(host)?;
    anyhow::ensure!(before.is_file() && before.permissions().mode() & 0o777 == 0o444,
        "shared clone artifact must be an immutable world-readable regular file inside its private directory");
    // Production publication requires root. Unprivileged source tests preserve the same
    // daemon-owned inode rule without granting a caller ownership of another user's RAM.
    anyhow::ensure!(
        before.uid() == unsafe { libc::geteuid() },
        "shared artifact has foreign ownership"
    );
    let inside = root.join(name);
    match std::fs::symlink_metadata(&inside) {
        Ok(existing) => anyhow::ensure!(
            existing.is_file() && existing.dev() == before.dev() && existing.ino() == before.ino(),
            "clone backing path already names a different inode"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::hard_link(host, &inside)
                .context("link immutable clone backing; copying is forbidden")?;
            std::fs::File::open(root)?.sync_all()?;
        }
        Err(e) => return Err(e.into()),
    }
    let after = std::fs::symlink_metadata(&inside)?;
    anyhow::ensure!(
        after.dev() == before.dev()
            && after.ino() == before.ino()
            && after.uid() == before.uid()
            && after.mode() == before.mode(),
        "shared artifact identity changed while linking"
    );
    Ok(Path::new("/").join(name))
}

/// Conservative same-host CPU identity: any visible feature/model/microcode change
/// invalidates the artifact. Never infer compatibility from host architecture alone.
pub fn cpu_fingerprint() -> Result<String> {
    use sha2::{Digest, Sha256};
    let text = std::fs::read_to_string("/proc/cpuinfo")?;
    let keys = [
        "vendor_id",
        "cpu family",
        "model",
        "model name",
        "stepping",
        "microcode",
        "flags",
        "Features",
        "CPU implementer",
        "CPU architecture",
        "CPU variant",
        "CPU part",
        "CPU revision",
    ];
    let lines: std::collections::BTreeSet<_> = text
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            keys.contains(&key.trim())
                .then(|| format!("{}:{}", key.trim(), value.trim()))
        })
        .collect();
    anyhow::ensure!(
        lines
            .iter()
            .any(|s| s.starts_with("flags:") || s.starts_with("Features:")),
        "CPU feature fingerprint is unavailable"
    );
    Ok(hex::encode(Sha256::digest(format!(
        "{}\n{}",
        std::env::consts::ARCH,
        lines.into_iter().collect::<Vec<_>>().join("\n")
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_links_keep_exact_inode_owner_mode_and_refuse_writable_or_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        let host = dir.path().join("sealed.mem");
        let jail = dir.path().join("jail");
        std::fs::create_dir(&jail).unwrap();
        std::fs::write(&host, b"shared marker").unwrap();
        assert!(shared_backing(&jail, &host, "clone.mem").is_err());
        std::fs::set_permissions(&host, std::fs::Permissions::from_mode(0o444)).unwrap();
        let before = std::fs::metadata(&host).unwrap();
        assert_eq!(
            shared_backing(&jail, &host, "clone.mem").unwrap(),
            Path::new("/clone.mem")
        );
        shared_backing(&jail, &host, "clone.mem").unwrap();
        let after = std::fs::metadata(jail.join("clone.mem")).unwrap();
        assert_eq!(
            (before.dev(), before.ino(), before.uid(), before.mode()),
            (after.dev(), after.ino(), after.uid(), after.mode())
        );
        std::fs::write(jail.join("clone.state"), b"unrelated").unwrap();
        assert!(shared_backing(&jail, &host, "clone.state").is_err());
        assert!(shared_backing(&jail, &host, "../outside").is_err());
    }
}
