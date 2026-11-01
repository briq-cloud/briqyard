//! Complete destination configuration for a pristine sandbox guest.
use super::{CloneConfigure, Config};
use serde::{Deserialize, Serialize};

pub const SANDBOX_READY_V1: &str = "sandbox-ready-v1";

/// Trusted host operation. Authorization, image/size provenance, probes, ownership,
/// egress and disk allocation remain host responsibilities, never guest assertions.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationBind {
    pub identity: CloneConfigure,
    pub config: Config,
    pub files: Vec<DestinationFile>,
    /// Host receipt identity, tied to destination ownership and complete machine spec.
    pub receipt: String,
}
impl std::fmt::Debug for DestinationBind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DestinationBind").finish_non_exhaustive()
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationFile {
    pub path: String,
    pub mode: u32,
    #[serde(with = "super::b64")]
    pub data: Vec<u8>,
}
impl DestinationBind {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.identity.validate()?;
        let c = &self.config;
        if self.receipt.len() != 64
            || !self
                .receipt
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("invalid destination receipt digest");
        }
        if c.template_profile.is_some()
            || c.hostname != self.identity.hostname
            || c.ip != self.identity.ip
            || c.gateway != self.identity.gateway
            || c.dns != self.identity.dns
        {
            return Err("destination identity/config mismatch");
        }
        // One fresh host-attached ext4 data disk; no arbitrary device or mount selection.
        if c.mounts.len() != 1
            || c.mounts[0].device != "/dev/vdc"
            || c.mounts[0].path != "/work"
            || c.mounts[0].fstype != "ext4"
        {
            return Err("sandbox destination requires fresh ext4 /dev/vdc at /work");
        }
        if c.entrypoint.is_empty() && c.cmd.is_empty() {
            return Err("destination requires a main command");
        }
        if !c.files.is_empty() || self.files.len() > 256 {
            return Err("destination files must be supplied exactly once");
        }
        let mut paths = std::collections::BTreeSet::new();
        for file in &self.files {
            if !file.path.starts_with('/')
                || file
                    .path
                    .split('/')
                    .skip(1)
                    .any(|p| p.is_empty() || p == "." || p == "..")
                || !paths.insert(&file.path)
                || file.mode & !0o777 != 0
            {
                return Err("invalid or duplicate destination file");
            }
            // Identity and durable receipt paths cannot be replaced through boot files.
            if [
                "/proc",
                "/sys",
                "/dev",
                "/run",
                "/etc/machine-id",
                "/etc/hostname",
                "/etc/hosts",
                "/etc/resolv.conf",
                "/etc/ssh",
                "/var/lib/dbus/machine-id",
                "/var/lib/systemd/random-seed",
                "/var/lib/urandom/random-seed",
                "/.briqyard-destination-binding-v1.json",
            ]
            .iter()
            .any(|p| file.path == *p || file.path.starts_with(&format!("{p}/")))
            {
                return Err("destination file overlaps runtime state");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> DestinationBind {
        let identity = CloneConfigure {
            generation: "sandbox-1".into(),
            hostname: "sandbox-1".into(),
            ip: "10.64.1.2/24".into(),
            gateway: "10.64.1.1".into(),
            dns: vec!["10.64.1.1".into()],
            mac: [2, 1, 2, 3, 4, 5],
            entropy: [42; 32],
            realtime_sec: 1_793_404_800,
        };
        DestinationBind {
            config: Config {
                hostname: identity.hostname.clone(),
                ip: identity.ip.clone(),
                gateway: identity.gateway.clone(),
                dns: identity.dns.clone(),
                cmd: vec!["sh".into(), "-ec".into(), "cd /work; sleep infinity".into()],
                env: [("PORT".into(), "8080".into())].into(),
                mounts: vec![super::super::Mount {
                    device: "/dev/vdc".into(),
                    path: "/work".into(),
                    fstype: "ext4".into(),
                }],
                ..Default::default()
            },
            identity,
            files: vec![DestinationFile {
                path: "/work/start.sh".into(),
                mode: 0o600,
                data: b"secret".to_vec(),
            }],
            receipt: "a".repeat(64),
        }
    }
    #[test]
    fn destination_roundtrip_preserves_application_and_identity() {
        let r = request();
        assert!(r.validate().is_ok());
        let bytes = serde_json::to_vec(&r).unwrap();
        let restored: DestinationBind = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(restored.files[0].data, b"secret");
        assert_eq!(restored.config.env["PORT"], "8080");
        assert_eq!(restored.config.cmd, r.config.cmd);
        assert_eq!(restored.identity, r.identity);
        assert!(!format!("{r:?}").contains("secret"));
        assert!(!format!("{r:?}").contains("42"));
    }
    #[test]
    fn rejects_identity_mismatch_mount_overrides_and_ambiguous_files() {
        let mut r = request();
        r.config.hostname = "other".into();
        assert!(r.validate().is_err());
        let mut r = request();
        r.config.mounts[0].device = "/dev/vda".into();
        assert!(r.validate().is_err());
        let mut r = request();
        r.files.push(r.files[0].clone());
        assert!(r.validate().is_err());
        for path in [
            "/work/../etc/hosts",
            "/etc/machine-id",
            "/proc/x",
            "/etc/ssh/ssh_host_rsa_key",
            "/var/lib/dbus/machine-id",
            "/.briqyard-destination-binding-v1.json",
        ] {
            let mut r = request();
            r.files[0].path = path.into();
            assert!(r.validate().is_err(), "{path}");
        }
    }
}
