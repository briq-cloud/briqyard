use super::*;
impl Manager {
    pub(in crate::machine) fn check_sandbox_disk(&self, r: &Record, path: &Path) -> Result<()> {
        let expected = self.sandbox_recipe(&r.image, r.size)?.device();
        check_geometry(path, &expected)
    }
}
#[cfg(target_os = "linux")]
fn check_geometry(path: &Path, expected: &guest::SandboxDevice) -> Result<()> {
    use std::os::fd::AsRawFd;
    let file = std::fs::File::open(path)?;
    let mut bytes = 0u64;
    if unsafe { libc::ioctl(file.as_raw_fd(), 0x8008_1272u64 as _, &mut bytes) } < 0 {
        return Err(std::io::Error::last_os_error()).context("sandbox data capacity");
    }
    anyhow::ensure!(bytes == expected.bytes, "sandbox data capacity mismatch");
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn check_geometry(_: &Path, _: &guest::SandboxDevice) -> Result<()> {
    bail!("sandbox data geometry requires Linux block devices")
}
