//! Runtime classes (ADR 0088): the kernels a host serves besides its own.

use super::*;

/// One class: the kernel its machines boot, the modules that go with it, and whether they see
/// the CPU's virtualization extensions.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClass {
    /// The uncompressed guest kernel.
    pub kernel: PathBuf,
    /// An ext4 image of one `lib/modules/<release>` tree, attached read-only and mounted at
    /// `/lib/modules/<release>`. Needs `release`.
    pub modules: Option<PathBuf>,
    /// The kernel's release, the name of the modules directory (`uname -r` in the guest).
    pub release: String,
    /// The `versions.json` that came with the kernel; its OpenZFS version is shown in the
    /// host's status.
    pub versions: Option<PathBuf>,
    /// Its machines boot without ADR 0087's CPU template, so they see VMX or SVM and can run
    /// a hypervisor of their own; they take no memory snapshot.
    pub nested: bool,
}

/// What the host says about itself, for a class to be served on it.
#[derive(Clone, Copy)]
pub struct ClassHost<'a> {
    pub x86_64: bool,
    /// KVM's `nested` parameter (`briqyard_api::kvm::nested`); none: no KVM module.
    pub kvm_nested: Option<bool>,
    pub exists: &'a dyn Fn(&Path) -> bool,
}

impl ClassHost<'static> {
    /// This host as the daemon reads it.
    pub fn read() -> Self {
        Self {
            x86_64: cfg!(target_arch = "x86_64"),
            kvm_nested: api::kvm::nested(Path::new(api::kvm::SYS_MODULE)),
            exists: &|p| p.is_file(),
        }
    }
}

impl Config {
    /// The shape of `runtime_classes`, on any host: what a file says about itself.
    pub(super) fn check_runtime_class_shapes(&self) -> Result<()> {
        for (name, c) in &self.runtime_classes {
            let at = |what: &str| format!("runtime_classes.{name}: {what}");
            if name == api::DEFAULT_CLASS {
                bail!(
                    "{}",
                    at("default is the host's own kernel: it is never written")
                );
            }
            if !api::valid_class_name(name) {
                bail!(
                    "{}",
                    at("a class name is a DNS label (a-z, 0-9, hyphens inside)")
                );
            }
            let mut paths = vec![("kernel", Some(&c.kernel))];
            paths.push(("modules", c.modules.as_ref()));
            paths.push(("versions", c.versions.as_ref()));
            for (field, p) in paths {
                if let Some(p) = p {
                    if !p.is_absolute() {
                        bail!("{}", at(&format!("{field} must be an absolute path")));
                    }
                }
            }
            if c.kernel.as_os_str().is_empty() {
                bail!("{}", at("kernel is required"));
            }
            match (&c.modules, c.release.as_str()) {
                (Some(_), "") => bail!("{}", at("modules needs release")),
                (None, r) if !r.is_empty() => bail!(
                    "{}",
                    at("release is the modules' directory: it needs modules")
                ),
                (_, r) if r.contains('/') || r == "." || r == ".." => {
                    bail!("{}", at("release is a directory name"))
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// What the host must have to serve the classes: their files, and for a `nested` one an
    /// x86_64 CPU with KVM's `nested` on. A pure function of what it is given.
    pub fn check_runtime_classes(&self, host: &ClassHost) -> Result<()> {
        for (name, c) in &self.runtime_classes {
            let at = |what: String| format!("runtime_classes.{name}: {what}");
            let files = [
                Some(("kernel", &c.kernel)),
                c.modules.as_ref().map(|p| ("modules", p)),
                c.versions.as_ref().map(|p| ("versions", p)),
            ];
            for (field, p) in files.into_iter().flatten() {
                if !(host.exists)(p) {
                    bail!("{}", at(format!("{field} {} is not a file", p.display())));
                }
            }
            if c.nested {
                if !host.x86_64 {
                    bail!(
                        "{}",
                        at("nested needs an x86_64 host: Firecracker gives an aarch64 guest no virtualization extensions".into())
                    );
                }
                match host.kvm_nested {
                    Some(true) => {}
                    Some(false) => bail!(
                        "{}",
                        at("nested needs KVM's nested parameter on, and it is off: \
                            hack/bootstrap-host.sh writes it on for a host that serves the class, \
                            applied at the next boot"
                            .into())
                    ),
                    None => bail!(
                        "{}",
                        at("nested needs KVM (kvm_intel or kvm_amd), and none is loaded".into())
                    ),
                }
            }
        }
        Ok(())
    }
}

/// What a class's `versions.json` says that the host shows (the file `hack/kernel/build.sh`
/// writes; other fields are for people).
#[derive(Debug, Default, Deserialize)]
pub struct ClassVersions {
    #[serde(default)]
    pub kernel_release: String,
    #[serde(default)]
    pub openzfs: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::testutil::load;

    const NESTED: &str = "runtime_classes:\n  nested:\n    kernel: /c/vmlinux\n    modules: /c/modules.ext4\n    release: 6.18.54-briqyard-nested\n    versions: /c/versions.json\n    nested: true\n";

    fn host(x86_64: bool, kvm_nested: Option<bool>, exists: &dyn Fn(&Path) -> bool) -> Result<()> {
        load(NESTED).unwrap().check_runtime_classes(&ClassHost {
            x86_64,
            kvm_nested,
            exists,
        })
    }

    #[test]
    fn none_by_default_and_a_class_reads() {
        assert!(load("").unwrap().runtime_classes.is_empty());
        let c = &load(NESTED).unwrap().runtime_classes["nested"];
        assert!(c.nested);
        assert_eq!(c.kernel, PathBuf::from("/c/vmlinux"));
        assert_eq!(c.release, "6.18.54-briqyard-nested");
        let plain = load("runtime_classes:\n  alt: {kernel: /c/vmlinux}\n").unwrap();
        assert!(!plain.runtime_classes["alt"].nested);
    }

    #[test]
    fn shapes_are_refused() {
        for (what, yaml) in [
            ("default", "runtime_classes:\n  default: {kernel: /c/v}\n"),
            ("name", "runtime_classes:\n  Nested: {kernel: /c/v}\n"),
            ("no kernel", "runtime_classes:\n  a: {nested: true}\n"),
            ("relative", "runtime_classes:\n  a: {kernel: v}\n"),
            (
                "modules need a release",
                "runtime_classes:\n  a: {kernel: /c/v, modules: /c/m}\n",
            ),
            (
                "a release needs modules",
                "runtime_classes:\n  a: {kernel: /c/v, release: r}\n",
            ),
            (
                "release is a name",
                "runtime_classes:\n  a: {kernel: /c/v, modules: /c/m, release: ../r}\n",
            ),
            (
                "unknown field",
                "runtime_classes:\n  a: {kernel: /c/v, vmm: x}\n",
            ),
        ] {
            assert!(load(yaml).is_err(), "{what}");
        }
    }

    #[test]
    fn a_host_serves_what_it_has() {
        let all = |_: &Path| true;
        host(true, Some(true), &all).unwrap();
        let missing = host(true, Some(true), &|p| !p.ends_with("modules.ext4")).unwrap_err();
        assert!(
            missing.to_string().contains("modules /c/modules.ext4"),
            "{missing}"
        );
        let off = host(true, Some(false), &all).unwrap_err().to_string();
        assert!(off.contains("nested parameter on"), "{off}");
        let none = host(true, None, &all).unwrap_err().to_string();
        assert!(none.contains("none is loaded"), "{none}");
        let arm = host(false, Some(true), &all).unwrap_err().to_string();
        assert!(arm.contains("x86_64"), "{arm}");
    }

    #[test]
    fn a_class_without_nested_asks_nothing_of_kvm() {
        let c = load("runtime_classes:\n  alt: {kernel: /c/vmlinux}\n").unwrap();
        let all = |_: &Path| true;
        c.check_runtime_classes(&ClassHost {
            x86_64: false,
            kvm_nested: None,
            exists: &all,
        })
        .unwrap();
    }
}
