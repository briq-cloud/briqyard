use super::{pki::*, *};
use crate::execution_service::protected::transport::{
    cert::Usage,
    tls::{client_config, server_config},
    Actor, LocalIdentity, Name,
};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::ring::{default_provider, sign::any_ecdsa_type},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    sign::CertifiedKey,
    ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme,
};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[derive(Debug)]
struct AcceptAny;

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn der(issued: &Issued) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    (
        vec![CertificateDer::from(issued.cert.clone())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(issued.key.clone())),
    )
}

/// A client that trusts any server and presents `chain` with `key`, or nothing.
fn lax_client(
    identity: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> Arc<ClientConfig> {
    let builder = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny));
    #[derive(Debug)]
    struct Unchecked(Arc<CertifiedKey>);
    impl rustls::client::ResolvesClientCert for Unchecked {
        fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
            Some(self.0.clone())
        }
        fn has_certs(&self) -> bool {
            true
        }
    }
    Arc::new(match identity {
        Some((chain, key)) => builder.with_client_cert_resolver(Arc::new(Unchecked(Arc::new(
            CertifiedKey::new(chain, any_ecdsa_type(&key).unwrap()),
        )))),
        None => builder.with_no_client_auth(),
    })
}

/// A server that presents `chain` signed by `key` and asks for no client certificate.
fn lax_server(
    chain: Vec<CertificateDer<'static>>,
    key: &PrivateKeyDer<'static>,
) -> Arc<ServerConfig> {
    #[derive(Debug)]
    struct One(Arc<CertifiedKey>);
    impl rustls::server::ResolvesServerCert for One {
        fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(self.0.clone())
        }
    }
    let signer = any_ecdsa_type(key).unwrap();
    Arc::new(
        ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(One(Arc::new(CertifiedKey::new(chain, signer))))),
    )
}

/// What each side saw: the client's view and the server's.
struct Outcome {
    client: Result<(), String>,
    server: Result<Vec<u8>, String>,
}

/// One handshake and one byte each way, so a late rejection reaches the side that sent
/// the certificate.
async fn handshake(
    server: Arc<ServerConfig>,
    client: Arc<ClientConfig>,
    name: ServerName<'static>,
) -> Outcome {
    let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server);
    let serving = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.map_err(|e| e.to_string())?;
        let mut byte = [0u8; 1];
        tls.read_exact(&mut byte).await.map_err(|e| e.to_string())?;
        tls.write_all(b"k").await.map_err(|e| e.to_string())?;
        tls.flush().await.map_err(|e| e.to_string())?;
        Ok(tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first().map(|leaf| leaf.to_vec()))
            .unwrap_or_default())
    });
    let connector = TlsConnector::from(client);
    let client = async {
        let tcp = TcpStream::connect(address)
            .await
            .map_err(|e| e.to_string())?;
        let mut tls = connector
            .connect(name, tcp)
            .await
            .map_err(|e| e.to_string())?;
        tls.write_all(b"x").await.map_err(|e| e.to_string())?;
        tls.flush().await.map_err(|e| e.to_string())?;
        let mut byte = [0u8; 1];
        tls.read_exact(&mut byte).await.map_err(|e| e.to_string())
    }
    .await
    .map(|_| ());
    let server = tokio::time::timeout(std::time::Duration::from_secs(5), serving)
        .await
        .unwrap()
        .unwrap();
    Outcome { client, server }
}

fn ip_name() -> ServerName<'static> {
    ServerName::IpAddress(LOOPBACK.into())
}

struct Pairing {
    net: Net,
    server_actor: Actor,
}

impl Pairing {
    fn new() -> Self {
        Self {
            net: Net::new(),
            server_actor: Actor::H,
        }
    }

    fn server(&self, callers: &[Actor]) -> Arc<ServerConfig> {
        let local = self.net.local(self.server_actor);
        server_config(&local, &self.net.inventory, callers, self.net.clock.clone()).unwrap()
    }

    fn client(&self, actor: Actor) -> Arc<ClientConfig> {
        let local = self.net.local(actor);
        client_config(
            &local,
            self.net.row(self.server_actor),
            self.net.clock.clone(),
        )
        .unwrap()
    }
}

#[tokio::test]
async fn the_pinned_pair_completes_and_the_server_sees_the_enrolled_client_leaf() {
    let pairing = Pairing::new();
    let outcome = handshake(
        pairing.server(&[Actor::A, Actor::R, Actor::B]),
        pairing.client(Actor::A),
        ip_name(),
    )
    .await;
    outcome.client.unwrap();
    assert_eq!(
        outcome.server.unwrap(),
        pairing.net.peers[&Actor::A].client.cert
    );
}

#[tokio::test]
async fn a_server_that_is_not_the_exact_pinned_leaf_is_refused_by_the_client() {
    let pairing = Pairing::new();
    let other = issue(&Name::Ip(LOOPBACK), Usage::Server);
    let (chain, key) = der(&other);
    let outcome = handshake(lax_server(chain, &key), pairing.client(Actor::A), ip_name()).await;
    assert!(outcome.client.is_err());

    let pinned = &pairing.net.peers[&Actor::H].server;
    let (chain, _) = der(pinned);
    let (_, foreign_key) = der(&other);
    let outcome = handshake(
        lax_server(chain, &foreign_key),
        pairing.client(Actor::A),
        ip_name(),
    )
    .await;
    assert!(
        outcome.client.is_err(),
        "the pinned bytes without their key"
    );

    let (mut chain, key) = der(pinned);
    chain.push(CertificateDer::from(other.cert.clone()));
    let outcome = handshake(lax_server(chain, &key), pairing.client(Actor::A), ip_name()).await;
    assert!(outcome.client.is_err(), "any intermediate is refused");

    let client_leaf = &pairing.net.peers[&Actor::H].client;
    let (chain, key) = der(client_leaf);
    let outcome = handshake(lax_server(chain, &key), pairing.client(Actor::A), ip_name()).await;
    assert!(
        outcome.client.is_err(),
        "a client identity as a server identity"
    );
}

#[tokio::test]
async fn the_server_name_the_client_asks_for_is_the_pinned_one_only() {
    let pairing = Pairing::new();
    let server = pairing.server(&[Actor::A]);
    for name in [
        ServerName::try_from("localhost").unwrap(),
        ServerName::IpAddress("127.0.0.2".parse::<std::net::IpAddr>().unwrap().into()),
    ] {
        let outcome = handshake(server.clone(), pairing.client(Actor::A), name).await;
        assert!(outcome.client.is_err());
    }
}

#[tokio::test]
async fn an_unqualified_clock_or_an_out_of_validity_time_refuses_both_directions() {
    let pairing = Pairing::new();
    let server = pairing.server(&[Actor::A]);
    let client = pairing.client(Actor::A);
    handshake(server.clone(), client.clone(), ip_name())
        .await
        .client
        .unwrap();
    for now in [None, Some(1_000), Some(2_000_000_000)] {
        pairing.net.clock.set(now);
        let outcome = handshake(server.clone(), client.clone(), ip_name()).await;
        assert!(outcome.client.is_err(), "{now:?}");
        assert!(outcome.server.is_err(), "{now:?}");
    }
}

#[tokio::test]
async fn only_enrolled_client_leaves_of_a_listed_actor_complete_a_handshake() {
    let pairing = Pairing::new();
    let server = pairing.server(&[Actor::A, Actor::R, Actor::B]);

    let outcome = handshake(server.clone(), lax_client(None), ip_name()).await;
    assert!(outcome.server.is_err() || outcome.client.is_err());
    assert!(outcome.server.is_err(), "no client certificate");

    let stranger = issue(&Name::dns("a-1.peer.test").unwrap(), Usage::Client);
    let outcome = handshake(server.clone(), lax_client(Some(der(&stranger))), ip_name()).await;
    assert!(outcome.server.is_err(), "an unpinned client certificate");

    let outcome = handshake(server.clone(), pairing.client(Actor::Installer), ip_name()).await;
    assert!(
        outcome.server.is_err(),
        "an enrolled actor the listener does not serve"
    );

    let server_identity = &pairing.net.peers[&Actor::A].server;
    let outcome = handshake(
        server.clone(),
        lax_client(Some(der(server_identity))),
        ip_name(),
    )
    .await;
    assert!(
        outcome.server.is_err(),
        "a server identity presented as a client identity"
    );

    let own = &pairing.net.peers[&Actor::A].client;
    let other = &pairing.net.peers[&Actor::B].client;
    let (chain, _) = der(own);
    let (_, key) = der(other);
    let outcome = handshake(server.clone(), lax_client(Some((chain, key))), ip_name()).await;
    assert!(
        outcome.server.is_err(),
        "the pinned client bytes without their key"
    );

    let (mut chain, key) = der(own);
    chain.push(CertificateDer::from(other.cert.clone()));
    let outcome = handshake(server, lax_client(Some((chain, key))), ip_name()).await;
    assert!(outcome.server.is_err(), "a chain behind the leaf");
}

#[tokio::test]
async fn tls_12_and_plaintext_never_reach_a_route() {
    let pairing = Pairing::new();
    let server = pairing.server(&[Actor::A]);
    let (chain, key) = der(&pairing.net.peers[&Actor::A].client);
    let tls12 = Arc::new(
        ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAny))
            .with_client_auth_cert(chain, key)
            .unwrap(),
    );
    let outcome = handshake(server.clone(), tls12, ip_name()).await;
    assert!(outcome.client.is_err() && outcome.server.is_err());

    let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server);
    let serving = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        acceptor.accept(tcp).await.map(|_| ())
    });
    let mut plain = TcpStream::connect(address).await.unwrap();
    plain
        .write_all(b"POST /internal/execution/v2/transition/read HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    assert!(serving.await.unwrap().is_err());
}

#[test]
fn a_local_identity_of_another_service_cannot_build_a_server_for_this_row() {
    let net = Net::new();
    let local: LocalIdentity = net.local(Actor::H);
    assert!(server_config(&local, &net.inventory, &[Actor::A], net.clock.clone()).is_ok());
}
