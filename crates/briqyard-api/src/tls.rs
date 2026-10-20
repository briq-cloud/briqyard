//! TLS on the API (ADR 0020). A host's certificate is trusted by its SHA-256 fingerprint
//! alone: no CA, no host name, no expiry. The fleet and the CLI dial a daemon with
//! [`pinned_client`]; the daemon and the fleet serve with [`server_config`].

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, OtherError, SignatureScheme};
use sha2::{Digest, Sha256};
use std::io;
use std::sync::Arc;

pub use rustls::{ClientConfig, ServerConfig};

/// `ring`, the provider `reqwest` uses too.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The SHA-256 of a certificate's DER, as 64 lowercase hex digits.
pub fn fingerprint(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

/// The fingerprint of the first certificate in a PEM text.
pub fn pem_fingerprint(cert_pem: &[u8]) -> io::Result<String> {
    let der = CertificateDer::from_pem_slice(cert_pem).map_err(invalid)?;
    Ok(fingerprint(&der))
}

/// A fingerprint as written by hand or by `openssl x509 -noout -fingerprint -sha256`: hex,
/// colons and case ignored. Answers it as [`fingerprint`] writes it.
pub fn parse_fingerprint(s: &str) -> Result<String, String> {
    let hex: String = s
        .trim()
        .chars()
        .filter(|c| *c != ':')
        .collect::<String>()
        .to_ascii_lowercase();
    if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(hex)
    } else {
        Err(format!(
            "{s:?} is not a SHA-256 fingerprint: 64 hex digits, colons allowed"
        ))
    }
}

/// A client that accepts exactly the server certificate with this fingerprint.
pub fn pinned_client(fingerprint: &str) -> ClientConfig {
    let provider = provider();
    ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned {
            fingerprint: fingerprint.to_string(),
            provider,
        }))
        .with_no_client_auth()
}

/// A server with this certificate chain and key, both PEM.
pub fn server_config(cert_pem: &[u8], key_pem: &[u8]) -> io::Result<ServerConfig> {
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(invalid)?;
    if certs.is_empty() {
        return Err(invalid("no certificate in the PEM text"));
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(invalid)?;
    ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(invalid)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(invalid)
}

fn invalid(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

/// Trusts the leaf whose SHA-256 is the pin. The handshake's signature is still checked
/// against that certificate's key: the certificate is public, holding its key is the proof.
#[derive(Debug)]
struct Pinned {
    fingerprint: String,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let seen = fingerprint(end_entity);
        if seen == self.fingerprint {
            return Ok(ServerCertVerified::assertion());
        }
        Err(rustls::Error::InvalidCertificate(CertificateError::Other(
            OtherError(Arc::new(io::Error::other(format!(
                "certificate {seen} is not the pinned {}",
                self.fingerprint
            )))),
        )))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    fn cert() -> rcgen::CertifiedKey {
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap()
    }

    /// A TLS server on loopback with `served`, answering "pong" to "ping", and a client
    /// pinned to `pin`: what the client got, or why the handshake failed.
    fn exchange(served: &rcgen::CertifiedKey, pin: &str) -> io::Result<Vec<u8>> {
        let cfg = server_config(
            served.cert.pem().as_bytes(),
            served.key_pair.serialize_pem().as_bytes(),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(Arc::new(cfg)).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, sock);
            let mut ping = [0u8; 4];
            // A refused handshake ends here, on the client's alert.
            if tls.read_exact(&mut ping).is_ok() {
                tls.write_all(b"pong").unwrap();
                tls.flush().unwrap();
            }
        });
        let name = ServerName::from(addr.ip());
        let conn = rustls::ClientConnection::new(Arc::new(pinned_client(pin)), name).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, TcpStream::connect(addr).unwrap());
        let got = tls.write_all(b"ping").and_then(|_| {
            let mut pong = vec![0u8; 4];
            tls.read_exact(&mut pong).map(|_| pong)
        });
        drop(tls);
        server.join().unwrap();
        got
    }

    #[test]
    fn the_pinned_certificate_is_accepted_and_another_is_refused() {
        let host = cert();
        let pin = fingerprint(host.cert.der());
        assert_eq!(exchange(&host, &pin).unwrap(), b"pong");
        // Another certificate, however valid, at the same address.
        let other = cert();
        let err = exchange(&other, &pin).unwrap_err().to_string();
        assert!(err.contains("is not the pinned"), "{err}");
        assert!(err.contains(&pin), "{err}");
    }

    #[test]
    fn fingerprints_are_the_sha256_of_the_der() {
        let c = cert();
        let fp = fingerprint(c.cert.der());
        assert_eq!(fp.len(), 64);
        assert_eq!(fp, hex::encode(Sha256::digest(c.cert.der())));
        assert_eq!(pem_fingerprint(c.cert.pem().as_bytes()).unwrap(), fp);
        assert!(pem_fingerprint(b"not pem").is_err());
    }

    #[test]
    fn a_fingerprint_is_read_as_openssl_prints_it() {
        let fp = "ab".repeat(32);
        assert_eq!(parse_fingerprint(&fp).unwrap(), fp);
        let openssl = vec!["AB"; 32].join(":");
        assert_eq!(parse_fingerprint(&openssl).unwrap(), fp);
        assert_eq!(parse_fingerprint(&format!(" {fp}\n")).unwrap(), fp);
        for bad in ["", "ab", &"zz".repeat(32), &"ab".repeat(33)] {
            let err = parse_fingerprint(bad).unwrap_err();
            assert!(err.contains("64 hex digits"), "{bad:?}: {err}");
        }
    }

    #[test]
    fn a_server_needs_a_certificate_and_its_key() {
        let c = cert();
        let key = c.key_pair.serialize_pem();
        assert!(server_config(b"", key.as_bytes()).is_err());
        assert!(server_config(c.cert.pem().as_bytes(), b"").is_err());
        // A key that is not the certificate's.
        let other = cert().key_pair.serialize_pem();
        assert!(server_config(c.cert.pem().as_bytes(), other.as_bytes()).is_err());
    }
}
