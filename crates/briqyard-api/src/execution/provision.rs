//! Explicit, default-off host-service provisioning. Files are read once at startup.
use super::{KeyRole, VerificationKey};
use serde::Deserialize;
use std::{
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub journal: PathBuf,
    pub credentials: PathBuf,
    pub verification_keys: PathBuf,
    pub central_issuer: String,
    pub authority_issuer: String,
    pub audience: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub host_installer: String,
    pub host_execution: String,
    pub central_installer: String,
    pub gateway: String,
    pub host_administrator: String,
    pub fleet_administrator: String,
}
impl Credentials {
    pub fn validate(&self) -> Result<(), &'static str> {
        let roles = [
            &self.host_installer,
            &self.host_execution,
            &self.central_installer,
            &self.gateway,
        ];
        if roles
            .iter()
            .any(|v| v.is_empty() || v.len() > 4096 || v.bytes().any(|b| !b.is_ascii_graphic()))
            || roles.iter().enumerate().any(|(i, v)| {
                roles[i + 1..].contains(v)
                    || *v == &self.host_administrator
                    || *v == &self.fleet_administrator
            })
        {
            return Err("invalid execution credentials");
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Key {
    kid: String,
    role: KeyRole,
    issuer: String,
    authority: Option<String>,
    public_key: [u8; 32],
}
pub fn read(path: &Path, secret: bool, limit: u64) -> Result<Vec<u8>, &'static str> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "execution file unavailable")?;
    let meta = file.metadata().map_err(|_| "execution file unavailable")?;
    if !meta.is_file()
        || meta.uid() != unsafe { nix::libc::geteuid() }
        || meta.mode() & 0o022 != 0
        || meta.len() > limit
        || (secret
            && (meta.uid() != unsafe { nix::libc::geteuid() }
                || meta.mode() & 0o077 != 0
                || meta.nlink() != 1))
    {
        return Err("invalid execution file");
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "execution file unavailable")?;
    if bytes.len() as u64 > limit {
        return Err("execution file too large");
    }
    Ok(bytes)
}
impl Config {
    pub fn validate(&self, administrator_listen: &str) -> Result<(), &'static str> {
        if self.listen.port() == 0
            || administrator_listen
                .parse::<SocketAddr>()
                .ok()
                .is_some_and(|admin| admin.port() == self.listen.port())
            || [
                &self.cert,
                &self.key,
                &self.journal,
                &self.credentials,
                &self.verification_keys,
            ]
            .iter()
            .any(|p| !p.is_absolute())
            || [&self.central_issuer, &self.authority_issuer, &self.audience]
                .iter()
                .any(|v| v.is_empty() || v.len() > 256)
        {
            return Err("invalid execution configuration");
        }
        Ok(())
    }
    pub fn load(
        &self,
    ) -> Result<(Credentials, Vec<VerificationKey>, rustls::ServerConfig), &'static str> {
        let credentials: Credentials =
            serde_json::from_slice(&read(&self.credentials, true, 32 * 1024)?)
                .map_err(|_| "invalid execution credentials")?;
        credentials.validate()?;
        let keys: Vec<Key> =
            serde_json::from_slice(&read(&self.verification_keys, false, 64 * 1024)?)
                .map_err(|_| "invalid execution keys")?;
        if keys.is_empty() || keys.len() > 32 {
            return Err("invalid execution keys");
        }
        let keys = keys
            .into_iter()
            .map(|k| VerificationKey {
                kid: k.kid,
                role: k.role,
                issuer: k.issuer,
                authority: k.authority,
                public_key: k.public_key,
            })
            .collect();
        let tls = crate::tls::server_config(
            &read(&self.cert, false, 256 * 1024)?,
            &read(&self.key, true, 64 * 1024)?,
        )
        .map_err(|_| "invalid execution TLS")?;
        Ok((credentials, keys, tls))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_tls_paths_and_dedicated_port_are_required() {
        let c = Config {
            listen: "127.0.0.1:7441".parse().unwrap(),
            cert: "/cert".into(),
            key: "/key".into(),
            journal: "/journal".into(),
            credentials: "/credentials".into(),
            verification_keys: "/keys".into(),
            central_issuer: "central".into(),
            authority_issuer: "authority".into(),
            audience: "runtime".into(),
        };
        assert!(c.validate("0.0.0.0:7420").is_ok());
        assert!(c.validate("0.0.0.0:7441").is_err());
        assert!(
            serde_json::from_str::<Config>(r#"{"listen":"127.0.0.1:7441","tls":"off"}"#).is_err()
        );
        assert!(c.load().is_err());
    }
    #[test]
    fn all_four_roles_are_distinct_from_each_other_and_both_admins() {
        let mut c = Credentials {
            host_installer: "hi".into(),
            host_execution: "he".into(),
            central_installer: "ci".into(),
            gateway: "gw".into(),
            host_administrator: "ha".into(),
            fleet_administrator: "fa".into(),
        };
        assert!(c.validate().is_ok());
        c.gateway = c.host_execution.clone();
        assert!(c.validate().is_err());
        c.gateway = c.fleet_administrator.clone();
        assert!(c.validate().is_err());
    }
}
