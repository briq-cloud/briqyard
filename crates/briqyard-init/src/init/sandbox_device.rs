//! Exclusive, checked cache invalidation for the fixed pristine sandbox data device.
//! No workload, automounter or guest command can produce I/O while this runs.
use super::*;
use std::os::unix::fs::OpenOptionsExt;

pub(super) fn prepare(expected: &guest::SandboxDevice) -> Result<()> {
    expected.check().map_err(|e| anyhow!(e))?;
    let sys = Path::new("/sys/class/block/vdc");
    check_no_partitions(sys)?;
    anyhow::ensure!(
        fs::read_dir(sys.join("holders"))?.next().is_none(),
        "sandbox data has holders"
    );
    let number = fs::read_to_string(sys.join("dev"))?;
    let number = number.trim();
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    anyhow::ensure!(
        !mounts
            .lines()
            .any(|line| line.split_whitespace().nth(2) == Some(number)),
        "sandbox data is mounted"
    );
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/dev/vdc")?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.mode() & libc::S_IFMT == libc::S_IFBLK,
        "sandbox data is not block storage"
    );
    anyhow::ensure!(
        format!(
            "{}:{}",
            libc::major(metadata.rdev()),
            libc::minor(metadata.rdev())
        ) == number,
        "sandbox data device identity mismatch"
    );
    for line in fs::read_to_string("/proc/swaps")?.lines().skip(1) {
        let path = line
            .split_whitespace()
            .next()
            .context("invalid swap entry")?;
        anyhow::ensure!(
            fs::metadata(path)?.rdev() != metadata.rdev(),
            "sandbox data is swap"
        );
    }
    let mut bytes: u64 = 0;
    let mut logical: libc::c_int = 0;
    // Linux block UAPI. Every result is checked before cache invalidation or mount.
    for (request, pointer) in [
        (
            0x8008_1272 as libc::c_ulong,
            (&mut bytes as *mut u64).cast::<libc::c_void>(),
        ),
        (0x1268, (&mut logical as *mut libc::c_int).cast()),
    ] {
        if unsafe { libc::ioctl(file.as_raw_fd(), request as _, pointer) } < 0 {
            return Err(std::io::Error::last_os_error()).context("sandbox data geometry");
        }
    }
    anyhow::ensure!(
        bytes == expected.bytes && logical as u32 == expected.logical_sector_bytes,
        "sandbox data geometry mismatch"
    );
    reset_cache(&file, || {
        fs::read_to_string(sys.join("inflight")).map_err(Into::into)
    })?;
    // Close exclusive ownership before mount or builder-ready. No later builder operation
    // accesses this device; seal/load queue behavior still requires native qualification.
    drop(file);
    Ok(())
}
// Sysfs mixes ordinary attributes with directories and directory symlinks.
// Follow symlinks when classifying candidates, and propagate metadata failures.
fn check_no_partitions(sys: &Path) -> Result<()> {
    anyhow::ensure!(
        !sys.join("partition").try_exists()?,
        "sandbox data must be a whole device"
    );
    for entry in fs::read_dir(sys)? {
        let path = entry?.path();
        if fs::metadata(&path)?.is_dir() {
            anyhow::ensure!(
                !path.join("partition").try_exists()?,
                "sandbox data has partitions"
            );
        }
    }
    Ok(())
}
pub(super) fn reset_cache(
    file: &fs::File,
    mut inflight: impl FnMut() -> Result<String>,
) -> Result<()> {
    check_inflight(&inflight()?)?;
    file.sync_all().context("drain sandbox data device")?;
    if unsafe { libc::ioctl(file.as_raw_fd(), 0x1261 as _) } < 0 {
        return Err(std::io::Error::last_os_error()).context("invalidate sandbox data cache");
    }
    check_inflight(&inflight()?)?;
    Ok(())
}
fn check_inflight(value: &str) -> Result<()> {
    let counts = value
        .split_whitespace()
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    anyhow::ensure!(counts == [0, 0], "sandbox data I/O is not quiescent");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordinary_sysfs_attributes_are_not_partition_directories() {
        let sys = tempfile::tempdir().unwrap();
        for attribute in ["dev", "size", "inflight", "uevent"] {
            let path = sys.path().join(attribute);
            fs::write(&path, "0\n").unwrap();
            // Reproduce the old probe's failure on real sysfs attribute shapes.
            assert_eq!(
                path.join("partition")
                    .try_exists()
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::ENOTDIR)
            );
        }
        fs::create_dir(sys.path().join("holders")).unwrap();
        fs::create_dir(sys.path().join("queue")).unwrap();
        std::os::unix::fs::symlink("queue", sys.path().join("subsystem")).unwrap();
        check_no_partitions(sys.path()).unwrap();
    }

    #[test]
    fn partition_directories_and_directory_symlinks_are_rejected() {
        for symlink in [false, true] {
            let sys = tempfile::tempdir().unwrap();
            let partition = tempfile::tempdir().unwrap();
            let candidate = sys.path().join("vdc1");
            if symlink {
                fs::write(partition.path().join("partition"), "1\n").unwrap();
                std::os::unix::fs::symlink(partition.path(), &candidate).unwrap();
            } else {
                fs::create_dir(&candidate).unwrap();
                fs::write(candidate.join("partition"), "1\n").unwrap();
            }
            assert!(check_no_partitions(sys.path())
                .unwrap_err()
                .to_string()
                .contains("has partitions"));
        }
    }

    #[test]
    fn partition_scan_errors_fail_closed() {
        let sys = tempfile::tempdir().unwrap();
        fs::write(sys.path().join("partition"), "1\n").unwrap();
        assert!(check_no_partitions(sys.path())
            .unwrap_err()
            .to_string()
            .contains("whole device"));
        fs::remove_file(sys.path().join("partition")).unwrap();
        std::os::unix::fs::symlink("missing", sys.path().join("broken")).unwrap();
        assert!(check_no_partitions(sys.path()).is_err());
        fs::remove_file(sys.path().join("broken")).unwrap();
        std::os::unix::fs::symlink("loop", sys.path().join("loop")).unwrap();
        assert!(check_no_partitions(sys.path()).is_err());
        assert!(check_no_partitions(&sys.path().join("missing")).is_err());
    }

    #[test]
    fn failed_block_invalidation_is_terminal() {
        let file = tempfile::tempfile().unwrap();
        let mut samples = 0;
        let result = reset_cache(&file, || {
            samples += 1;
            Ok("0 0".into())
        });
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalidate sandbox data cache"));
        assert_eq!(
            samples, 1,
            "failed ioctl must not qualify a post-invalidation sample"
        );
    }
    #[test]
    fn outstanding_or_unknown_io_never_qualifies() {
        assert!(check_inflight("0 0\n").is_ok());
        for value in ["1 0", "0 1", "", "0", "0 0 0", "unknown"] {
            assert!(check_inflight(value).is_err());
        }
    }
}
