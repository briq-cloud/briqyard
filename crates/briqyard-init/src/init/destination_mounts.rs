//! Strict volume installation for the one-way sandbox destination transaction.
use super::*;

pub(super) fn setup(cfg: &Config) -> Result<()> {
    sandbox_device::prepare(
        cfg.sandbox_device
            .as_ref()
            .context("sandbox data topology missing")?,
    )?;
    for volume in &cfg.mounts {
        let path = Path::new(&volume.path);
        let seed = stage(path)?;
        mount(
            Some(volume.device.as_str()),
            path,
            Some(volume.fstype.as_str()),
            MsFlags::MS_NOATIME,
            Some("discard"),
        )
        .with_context(|| format!("mount destination {}", volume.path))?;
        grow_filesystem(&volume.device, path)?;
        seed_with(path, seed, copy)?;
    }
    Ok(())
}

struct Seed {
    metadata: Option<fs::Metadata>,
    staging: Option<PathBuf>,
}
fn stage(path: &Path) -> Result<Seed> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(meta) => {
            anyhow::ensure!(meta.is_dir(), "destination mount source is not a directory");
            Some(meta)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).context("inspect destination mount source"),
    };
    let staging = if metadata.is_some() {
        let directory = PathBuf::from(format!("{}.briqyard-seed", path.display()));
        // Exclusive directory creation prevents overwriting any earlier staged source.
        fs::create_dir(&directory).context("reserve destination seed staging")?;
        fs::rename(path, directory.join("content")).context("stage destination mount source")?;
        Some(directory)
    } else {
        None
    };
    fs::create_dir_all(path).context("create destination mount point")?;
    Ok(Seed { metadata, staging })
}
fn metadata(path: &Path, meta: &fs::Metadata) -> Result<()> {
    nix::unistd::chown(path, Some(meta.uid().into()), Some(meta.gid().into()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(meta.mode() & 0o7777))?;
    Ok(())
}
fn seed_with(path: &Path, seed: Seed, copy: impl FnOnce(&Path, &Path) -> Result<()>) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        anyhow::ensure!(
            entry.file_name() == "lost+found",
            "destination volume is not fresh"
        );
    }
    match fs::remove_dir(path.join("lost+found")) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context("remove destination lost+found"),
    }
    if let Some(meta) = &seed.metadata {
        metadata(path, meta)?;
    }
    if let Some(directory) = seed.staging {
        copy(&directory.join("content"), path)?;
        // Never discard the staged source after a failed copy or metadata operation.
        fs::remove_dir_all(directory).context("remove installed destination seed")?;
    }
    Ok(())
}
fn copy(source: &Path, destination: &Path) -> Result<()> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source = entry.path();
        let target = destination.join(entry.file_name());
        let meta = fs::symlink_metadata(&source)?;
        if meta.is_dir() {
            fs::create_dir(&target)?;
            copy(&source, &target)?;
            metadata(&target, &meta)?;
        } else if meta.is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(source)?, &target)?;
            std::os::unix::fs::lchown(target, Some(meta.uid()), Some(meta.gid()))?;
        } else if meta.is_file() {
            fs::copy(source, &target)?;
            metadata(&target, &meta)?;
        } else {
            return Err(anyhow!("unsupported destination seed file type"));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn injected_seed_failure(source: &Path, destination: &Path) -> Result<()> {
    let seed = stage(source)?;
    seed_with(destination, seed, |_, target| {
        fs::write(target.join("partial"), b"partial copy")?;
        Err(std::io::Error::from_raw_os_error(libc::ENOSPC).into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_seed_preserves_symlinks_and_rejects_existing_staging() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("work");
        let destination = root.path().join("disk");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(source.join("file"), b"content").unwrap();
        std::os::unix::fs::symlink("file", source.join("link")).unwrap();
        let seed = stage(&source).unwrap();
        assert!(stage(&source).is_err());
        seed_with(&destination, seed, copy).unwrap();
        assert_eq!(fs::read(destination.join("file")).unwrap(), b"content");
        assert_eq!(
            fs::read_link(destination.join("link")).unwrap(),
            Path::new("file")
        );
    }
}
