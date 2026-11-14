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
/// SHA-256 of a bearer. Administrator bearers are compared only by digest.
pub type Digest = [u8; 32];

pub fn digest(bearer: &str) -> Digest {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(bearer.as_bytes()).into()
}

/// Constant-time equality of two digests.
pub fn same(a: &Digest, b: &Digest) -> bool {
    // Accumulates every byte difference: no early exit on the first mismatch.
    std::hint::black_box(a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y))) == 0
}

/// Strict digest text: exactly 64 lowercase hexadecimal characters.
pub fn parse_digest(text: &str) -> Result<Digest, &'static str> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 || !bytes.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err("invalid administrator digest");
    }
    let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    let mut out = [0u8; 32];
    for (i, pair) in bytes.chunks(2).enumerate() {
        out[i] = nibble(pair[0]) << 4 | nibble(pair[1]);
    }
    // The digest of the empty bearer is never an administrator.
    if same(&out, &digest("")) {
        return Err("invalid administrator digest");
    }
    Ok(out)
}

/// One administrator role: the plaintext bearer or its digest, never both, never neither.
pub fn administrator(
    plaintext: Option<&str>,
    sha256: Option<&str>,
) -> Result<Digest, &'static str> {
    match (plaintext, sha256) {
        (Some(_), Some(_)) => Err("administrator given as both plaintext and digest"),
        (Some(bearer), None) => {
            if bearer.is_empty() || bearer.bytes().any(|b| !b.is_ascii_graphic()) {
                return Err("invalid administrator bearer");
            }
            Ok(digest(bearer))
        }
        (None, Some(text)) => parse_digest(text),
        (None, None) => Err("administrator missing"),
    }
}

/// The administrator roles are given as a plaintext bearer or as its SHA-256 digest
/// (`*_sha256`, lowercase hexadecimal). A process that never presents an administrator
/// bearer needs only the digests.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub host_installer: String,
    pub host_execution: String,
    pub central_installer: String,
    pub gateway: String,
    #[serde(default)]
    pub host_administrator: Option<String>,
    #[serde(default)]
    pub fleet_administrator: Option<String>,
    #[serde(default)]
    pub host_administrator_sha256: Option<String>,
    #[serde(default)]
    pub fleet_administrator_sha256: Option<String>,
}
impl Credentials {
    /// Digests of the host and fleet administrators, whichever form each was given in.
    pub fn administrators(&self) -> Result<(Digest, Digest), &'static str> {
        Ok((
            administrator(
                self.host_administrator.as_deref(),
                self.host_administrator_sha256.as_deref(),
            )?,
            administrator(
                self.fleet_administrator.as_deref(),
                self.fleet_administrator_sha256.as_deref(),
            )?,
        ))
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        let roles = [
            &self.host_installer,
            &self.host_execution,
            &self.central_installer,
            &self.gateway,
        ];
        let (host, fleet) = self
            .administrators()
            .map_err(|_| "invalid execution credentials")?;
        if roles
            .iter()
            .any(|v| v.is_empty() || v.len() > 4096 || v.bytes().any(|b| !b.is_ascii_graphic()))
            || roles.iter().enumerate().any(|(i, v)| {
                let d = digest(v);
                roles[i + 1..].contains(v) || same(&d, &host) || same(&d, &fleet)
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
            host_administrator: Some("ha".into()),
            fleet_administrator: Some("fa".into()),
            host_administrator_sha256: None,
            fleet_administrator_sha256: None,
        };
        assert!(c.validate().is_ok());
        c.gateway = c.host_execution.clone();
        assert!(c.validate().is_err());
        c.gateway = "fa".into();
        assert!(c.validate().is_err());
    }
    fn hex(bearer: &str) -> String {
        digest(bearer).iter().map(|b| format!("{b:02x}")).collect()
    }
    fn digests_only() -> Credentials {
        Credentials {
            host_installer: "hi".into(),
            host_execution: "he".into(),
            central_installer: "ci".into(),
            gateway: "gw".into(),
            host_administrator: None,
            fleet_administrator: None,
            host_administrator_sha256: Some(hex("ha")),
            fleet_administrator_sha256: Some(hex("fa")),
        }
    }
    #[test]
    fn digests_replace_administrator_plaintext() {
        let c = digests_only();
        assert!(c.validate().is_ok());
        assert_eq!(c.administrators().unwrap(), (digest("ha"), digest("fa")));
        let json = format!(
            r#"{{"host_installer":"a","host_execution":"b","central_installer":"c","gateway":"d","host_administrator_sha256":"{}","fleet_administrator_sha256":"{}"}}"#,
            hex("ha"),
            hex("fa")
        );
        assert!(serde_json::from_str::<Credentials>(&json)
            .unwrap()
            .validate()
            .is_ok());
    }
    #[test]
    fn a_scoped_credential_equal_to_an_administrator_is_refused_by_digest() {
        for administrator in ["ha", "fa"] {
            let mut c = digests_only();
            c.gateway = administrator.into();
            assert!(c.validate().is_err(), "{administrator}");
        }
    }
    #[test]
    fn plaintext_administrators_must_be_non_empty_graphic() {
        for bad in ["", "a b", "a\n", "é"] {
            let mut c = digests_only();
            c.host_administrator_sha256 = None;
            c.host_administrator = Some(bad.into());
            assert!(c.validate().is_err(), "{bad:?}");
        }
    }
    #[test]
    fn both_or_neither_form_and_malformed_digests_are_refused() {
        let mut c = digests_only();
        c.host_administrator = Some("ha".into());
        assert!(c.validate().is_err());
        let mut c = digests_only();
        c.fleet_administrator_sha256 = None;
        assert!(c.validate().is_err());
        for bad in [
            "".to_string(),
            hex(""),
            "ab".repeat(31),
            "ab".repeat(33),
            hex("ha").to_uppercase(),
            format!("{} ", &hex("ha")[..63]),
            format!("g{}", &hex("ha")[1..]),
            format!("0x{}", &hex("ha")[2..]),
        ] {
            let mut c = digests_only();
            c.host_administrator_sha256 = Some(bad.clone());
            assert!(c.validate().is_err(), "{bad:?}");
        }
    }
}
