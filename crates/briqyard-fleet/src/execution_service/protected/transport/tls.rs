//! Strict, in-memory rustls configurations. TLS 1.3 only, one signature scheme, no session
//! resumption or early data, no ambient or system trust, no intermediates and no OCSP.
//! Certificates are trusted by exact enrolled digest alone, then profile, name and
//! qualified-time checks; the handshake signature proves possession of the key.

use super::{
    cert::{self, CertError, Usage},
    Actor, ConfigError, Inventory, LocalIdentity, Name, Pair, PeerRow,
};
use briqyard_api::execution::{clock::ClockSource, sealed::prim::HexDigest};
use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        Resumption,
    },
    crypto::{
        ring::default_provider, verify_tls13_signature, CryptoProvider, WebPkiSupportedAlgorithms,
    },
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    server::{
        danger::{ClientCertVerified, ClientCertVerifier},
        NoServerSessionStorage,
    },
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, Error as TlsError,
    OtherError, ServerConfig, SignatureScheme,
};
use std::{net::IpAddr, sync::Arc};

pub(super) const ALPN: &[u8] = b"http/1.1";

fn provider() -> Arc<CryptoProvider> {
    Arc::new(default_provider())
}

fn refuse(error: CertError) -> TlsError {
    TlsError::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(error))))
}

fn scheme(dss: &DigitallySignedStruct) -> Result<(), TlsError> {
    if dss.scheme == SignatureScheme::ECDSA_NISTP256_SHA256 {
        return Ok(());
    }
    Err(TlsError::PeerIncompatible(
        rustls::PeerIncompatible::NoSignatureSchemesInCommon,
    ))
}

/// The client's view of one fixed server: a single enrolled leaf and the one name it was
/// enrolled for.
struct PinnedServer {
    pin: Pair,
    name: Name,
    clock: Arc<dyn ClockSource>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl std::fmt::Debug for PinnedServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedServer").finish_non_exhaustive()
    }
}

impl ServerCertVerifier for PinnedServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if !intermediates.is_empty() || !ocsp_response.is_empty() {
            return Err(refuse(CertError::Profile));
        }
        let asked = match server_name {
            ServerName::DnsName(name) => Name::Dns(name.as_ref().to_owned()),
            ServerName::IpAddress(ip) => Name::Ip(IpAddr::from(*ip)),
            _ => return Err(refuse(CertError::Name)),
        };
        if asked != self.name {
            return Err(refuse(CertError::Name));
        }
        let leaf = cert::verify(end_entity, &self.pin, Usage::Server).map_err(refuse)?;
        if leaf.name != self.name {
            return Err(refuse(CertError::Name));
        }
        leaf.valid_at(self.clock.as_ref()).map_err(refuse)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        scheme(dss)?;
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

/// The server's view of its callers: only the enrolled client leaves of the listed actors.
struct PinnedClients {
    pins: Vec<Pair>,
    clock: Arc<dyn ClockSource>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl std::fmt::Debug for PinnedClients {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedClients").finish_non_exhaustive()
    }
}

impl ClientCertVerifier for PinnedClients {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        if !intermediates.is_empty() {
            return Err(refuse(CertError::Profile));
        }
        let leaf = HexDigest::of(end_entity);
        let pin = self
            .pins
            .iter()
            .find(|pin| pin.leaf == leaf)
            .ok_or(refuse(CertError::Pin))?;
        cert::verify(end_entity, pin, Usage::Client)
            .and_then(|leaf| leaf.valid_at(self.clock.as_ref()))
            .map_err(refuse)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        scheme(dss)?;
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

fn key(material: &super::Material) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(material.key.to_vec()))
}

/// The listener's configuration: its own server identity and the client leaves of `callers`.
pub(super) fn server_config(
    local: &LocalIdentity,
    inventory: &Inventory,
    callers: &[Actor],
    clock: Arc<dyn ClockSource>,
) -> Result<Arc<ServerConfig>, ConfigError> {
    let provider = provider();
    let verifier = PinnedClients {
        pins: inventory
            .rows()
            .filter(|row| callers.contains(&row.peer.actor))
            .map(|row| row.client.clone())
            .collect(),
        clock,
        algorithms: provider.signature_verification_algorithms,
    };
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| ConfigError("tls versions"))?
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(
            vec![CertificateDer::from(local.server.cert.clone())],
            key(&local.server),
        )
        .map_err(|_| ConfigError("server identity"))?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.max_early_data_size = 0;
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    Ok(Arc::new(config))
}

/// A client for exactly one enrolled server, presenting this service's client identity.
pub(super) fn client_config(
    local: &LocalIdentity,
    target: &PeerRow,
    clock: Arc<dyn ClockSource>,
) -> Result<Arc<ClientConfig>, ConfigError> {
    let provider = provider();
    let verifier = PinnedServer {
        pin: target.server.clone(),
        name: target.server_name.clone(),
        clock,
        algorithms: provider.signature_verification_algorithms,
    };
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| ConfigError("tls versions"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(
            vec![CertificateDer::from(local.client.cert.clone())],
            key(&local.client),
        )
        .map_err(|_| ConfigError("client identity"))?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    Ok(Arc::new(config))
}
