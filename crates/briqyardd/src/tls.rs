//! The API's certificate (ADR 0020): self-signed, ECDSA P-256, made once and kept in
//! `data_dir`. The fleet trusts it by its SHA-256, so it must not change while the host lives.

use crate::store;
use anyhow::{bail, Context, Result};
use briqyard_api::tls;
use chrono::Datelike;
use std::path::Path;

/// The certificate at `cert` (and its key at `key`), made with `names` when there is none.
/// Answers its fingerprint. A certificate without its key is refused, never replaced: a new
/// pair is a new fingerprint for the fleet to pin.
pub fn ensure(cert: &Path, key: &Path, names: &[String]) -> Result<String> {
    if cert.exists() {
        if !key.exists() {
            bail!(
                "{} has no key at {}: remove the certificate to make a new pair, then pin its fingerprint in the fleet",
                cert.display(),
                key.display()
            );
        }
        return fingerprint(cert);
    }
    let (cert_pem, key_pem) = make(names)?;
    // The key first: a certificate on disk always has its key next to it.
    store::write_private(key, key_pem.as_bytes())?;
    store::write_private(cert, cert_pem.as_bytes())?;
    tracing::info!(cert = %cert.display(), names = ?names, "api certificate made");
    fingerprint(cert)
}

/// The fingerprint of the certificate file.
pub fn fingerprint(cert: &Path) -> Result<String> {
    let pem = std::fs::read(cert).with_context(|| format!("read {}", cert.display()))?;
    tls::pem_fingerprint(&pem).with_context(|| format!("certificate {}", cert.display()))
}

/// The server configuration from the two files.
pub fn server_config(cert: &Path, key: &Path) -> Result<tls::ServerConfig> {
    let c = std::fs::read(cert).with_context(|| format!("read {}", cert.display()))?;
    let k = std::fs::read(key).with_context(|| format!("read {}", key.display()))?;
    tls::server_config(&c, &k).with_context(|| format!("{} and {}", cert.display(), key.display()))
}

/// A self-signed certificate for `names`, valid from the first of this month for a century:
/// the pin is the trust, an expiry would only be an outage.
fn make(names: &[String]) -> Result<(String, String)> {
    let mut params = rcgen::CertificateParams::new(names.to_vec())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "briqyardd");
    let now = chrono::Utc::now();
    let month = now.month() as u8;
    params.not_before = rcgen::date_time_ymd(now.year(), month, 1);
    params.not_after = rcgen::date_time_ymd(now.year() + 100, month, 1);
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let cert = params.self_signed(&key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn the_certificate_is_made_once_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = (
            dir.path().join("api-cert.pem"),
            dir.path().join("api-key.pem"),
        );
        let names = vec!["10.0.0.5".to_string()];
        let first = ensure(&cert, &key, &names).unwrap();
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the key is root's alone");
        // A restart, even with other names: the same certificate.
        let pem = std::fs::read(&cert).unwrap();
        assert_eq!(ensure(&cert, &key, &["10.0.0.6".into()]).unwrap(), first);
        assert_eq!(std::fs::read(&cert).unwrap(), pem);
        // The fingerprint is the certificate's, and the pair serves.
        let der = der_of(&pem);
        assert_eq!(first, briqyard_api::tls::fingerprint(&der));
        server_config(&cert, &key).unwrap();
        assert!(!dir.path().join("api-key.pem.tmp").exists());
    }

    #[test]
    fn a_certificate_without_its_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = (
            dir.path().join("api-cert.pem"),
            dir.path().join("api-key.pem"),
        );
        ensure(&cert, &key, &[]).unwrap();
        std::fs::remove_file(&key).unwrap();
        let err = ensure(&cert, &key, &[]).unwrap_err().to_string();
        assert!(err.contains("has no key"), "{err}");
        assert!(!key.exists(), "nothing was made in its place");
        // Removing the certificate too makes a new pair, with a new fingerprint.
        let old = fingerprint(&cert).unwrap();
        std::fs::remove_file(&cert).unwrap();
        assert_ne!(ensure(&cert, &key, &[]).unwrap(), old);
    }

    /// The DER of the PEM's certificate, decoded here rather than by the code under test.
    fn der_of(pem: &[u8]) -> Vec<u8> {
        use base64::prelude::*;
        let text = std::str::from_utf8(pem).unwrap();
        let body: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
        BASE64_STANDARD.decode(body).unwrap()
    }
}
