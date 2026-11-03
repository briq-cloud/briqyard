//! Runtime classes (ADR 0088): which a host serves, what a machine of one boots, and what it
//! refuses.

use super::*;
use crate::config::{ClassVersions, RuntimeClass};

/// The text of the 400 for a class the host does not serve.
pub(super) fn not_served(class: &str) -> String {
    format!("runtime class {class} is not served by this host")
}

/// A requested class as a record keeps it: `default` is the empty one.
pub(super) fn normalized(class: &str) -> &str {
    if class == api::DEFAULT_CLASS {
        ""
    } else {
        class
    }
}

/// The class of a fork or a restore: its source's. A request naming another is refused.
pub(super) fn inherited(
    requested: &str,
    source: &str,
    what: &str,
    whose: &str,
) -> Result<String, MError> {
    if !requested.is_empty() && requested != source {
        return Err(invalid(format!(
            "{what} keeps {whose} runtime class ({}), and the request says {requested}",
            api::class_name(source)
        )));
    }
    Ok(source.to_string())
}

/// The boot identity of each configured class: its own kernel's digest and, unless its
/// machines see the virtualization extensions, the host's CPU template.
pub(super) fn identities(
    cfg: &Config,
    cpu_template: Option<&serde_json::Value>,
) -> Result<BTreeMap<String, fc::BootIdentity>> {
    cfg.runtime_classes
        .iter()
        .map(|(name, c)| {
            let template = if c.nested { None } else { cpu_template };
            let identity =
                fc::BootIdentity::read(&c.kernel, &cfg.firecracker, cfg.pci, fc::digest(template))
                    .with_context(|| format!("runtime class {name}"))?;
            Ok((name.clone(), identity))
        })
        .collect()
}

/// What `versions` says of a class, when it names a file.
fn versions(c: &RuntimeClass) -> Result<ClassVersions> {
    let Some(path) = &c.versions else {
        return Ok(ClassVersions::default());
    };
    let text = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
    serde_json::from_str(&text).with_context(|| path.display().to_string())
}

/// The classes a host serves, for its status and heartbeat.
pub fn infos(cfg: &Config) -> Result<Vec<api::RuntimeClassInfo>> {
    cfg.runtime_classes
        .iter()
        .map(|(name, c)| {
            let v = versions(c).with_context(|| format!("runtime class {name}"))?;
            Ok(api::RuntimeClassInfo {
                name: name.clone(),
                nested: c.nested,
                kernel_release: if c.release.is_empty() {
                    v.kernel_release
                } else {
                    c.release.clone()
                },
                openzfs: v.openzfs,
            })
        })
        .collect()
}

impl Manager {
    /// The classes this host serves besides `default`.
    pub fn runtime_classes(&self) -> Vec<api::RuntimeClassInfo> {
        // A file that was there at the start and is gone or broken now shows the class
        // without its versions: the status still answers.
        infos(&self.inner.cfg).unwrap_or_else(|err| {
            tracing::warn!(err = %format!("{err:#}"), "runtime class versions unreadable");
            self.inner
                .cfg
                .runtime_classes
                .iter()
                .map(|(name, c)| api::RuntimeClassInfo {
                    name: name.clone(),
                    nested: c.nested,
                    ..Default::default()
                })
                .collect()
        })
    }

    /// The class a request names, if this host serves it; none for `default`.
    pub(super) fn served_class(&self, class: &str) -> Result<Option<&RuntimeClass>, MError> {
        match class {
            "" | api::DEFAULT_CLASS => Ok(None),
            name => self
                .inner
                .cfg
                .runtime_classes
                .get(name)
                .map(Some)
                .ok_or_else(|| invalid(not_served(name))),
        }
    }

    /// The class a record runs under, for a boot: none for `default`. A record of a class
    /// the configuration no longer lists cannot boot.
    pub(super) fn class_of(&self, rec: &Record) -> Result<Option<&RuntimeClass>> {
        self.served_class(&rec.runtime_class)
            .map_err(|err| anyhow!("{err}: the machine cannot start until the class is back"))
    }

    /// Why this machine takes no memory snapshot, when its class forbids one.
    pub(super) fn memory_refusal(&self, rec: &Record) -> Option<String> {
        let class = self.inner.cfg.runtime_classes.get(&rec.runtime_class)?;
        class
            .nested
            .then(|| format!("runtime class {}", rec.runtime_class))
    }

    /// The guest's mount of the class's modules: the next drive after the volume, if any.
    pub(super) fn modules_mount(&self, rec: &Record) -> Option<guest::Mount> {
        let class = self.inner.cfg.runtime_classes.get(&rec.runtime_class)?;
        class.modules.as_ref()?;
        Some(guest::Mount {
            device: modules_device(rec.volume.is_some()).into(),
            path: format!("/lib/modules/{}", class.release),
            fstype: "ext4".into(),
            read_only: true,
        })
    }
}

/// Firecracker names virtio disks in the order it is given them: the root disk, the config
/// drive, the volume if the machine has one, then the modules.
pub(super) fn modules_device(has_volume: bool) -> &'static str {
    if has_volume {
        "/dev/vdd"
    } else {
        "/dev/vdc"
    }
}
