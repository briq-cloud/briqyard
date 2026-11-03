//! KVM's `nested` parameter, which the daemon logs and `doctor` checks (ADR 0087).

use std::path::Path;

/// Where the kernel exposes a loaded module's parameters.
pub const SYS_MODULE: &str = "/sys/module";

/// Whether the loaded `kvm_amd` or `kvm_intel` lets guests run a hypervisor of their own;
/// none when neither is loaded (no KVM, or another architecture).
pub fn nested(sys_module: &Path) -> Option<bool> {
    ["kvm_amd", "kvm_intel"].iter().find_map(|module| {
        let path = sys_module.join(module).join("parameters/nested");
        let value = std::fs::read_to_string(path).ok()?;
        Some(matches!(value.trim(), "Y" | "y" | "1"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(root: &Path, name: &str, value: &str) {
        let dir = root.join(name).join("parameters");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("nested"), value).unwrap();
    }

    #[test]
    fn reads_either_module() {
        let amd = tempfile::tempdir().unwrap();
        assert_eq!(nested(amd.path()), None);
        module(amd.path(), "kvm_amd", "1\n");
        assert_eq!(nested(amd.path()), Some(true));
        module(amd.path(), "kvm_amd", "0\n");
        assert_eq!(nested(amd.path()), Some(false));
        let intel = tempfile::tempdir().unwrap();
        module(intel.path(), "kvm_intel", "Y\n");
        assert_eq!(nested(intel.path()), Some(true));
        module(intel.path(), "kvm_intel", "N\n");
        assert_eq!(nested(intel.path()), Some(false));
    }
}
