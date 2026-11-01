//! Exclusive, checked cache invalidation for the fixed pristine sandbox data device.
//! No workload, automounter or guest command can produce I/O while this runs.
use super::*;
use std::os::unix::fs::OpenOptionsExt;

pub(super) fn prepare(expected: &guest::SandboxDevice) -> Result<()> {
    expected.check().map_err(|e| anyhow!(e))?;
    let sys = Path::new("/sys/class/block/vdc");
    anyhow::ensure!(
        !sys.join("partition").try_exists()?,
        "sandbox data must be a whole device"
    );
    for entry in fs::read_dir(sys)? {
        anyhow::ensure!(
            !entry?.path().join("partition").try_exists()?,
            "sandbox data has partitions"
        );
    }
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
