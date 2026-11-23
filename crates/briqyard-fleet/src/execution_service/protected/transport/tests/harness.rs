use super::pki::*;
use crate::execution_service::protected::{
    transport::{
        routes::{Caller, HostService, Mount, PrivateServer, Scope},
        tls::client_config,
        Actor,
    },
    Error,
};
use briqyard_api::execution::sealed::{
    objects::{HostClockBody, Proc, ProofQuery, Q, X},
    prim::{BootId, Build, Env, HexDigest, Ident, Nonce, PosInt, Uint},
    sig::{Sig, Signer, Tag},
    transition::{HRead, HostClock, RegisterRequest},
};
use futures::future::BoxFuture;
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use rustls::pki_types::ServerName;
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Instant,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;

pub(crate) struct TestKey(Ed25519KeyPair);

impl TestKey {
    pub(crate) fn new() -> Self {
        let bytes = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Self(Ed25519KeyPair::from_pkcs8(bytes.as_ref()).unwrap())
    }

    pub(crate) fn kid(&self) -> HexDigest {
        HexDigest::of(&self.public_key())
    }
}

impl Signer for TestKey {
    fn public_key(&self) -> [u8; 32] {
        self.0.public_key().as_ref().try_into().unwrap()
    }
    fn sign(&self, bytes: &[u8]) -> [u8; 64] {
        self.0.sign(bytes).as_ref().try_into().unwrap()
    }
}

pub(crate) struct Keys {
    pub hk: TestKey,
    pub ak: TestKey,
    pub bk: TestKey,
    pub rk: TestKey,
}

impl Keys {
    pub(crate) fn new() -> Self {
        Self {
            hk: TestKey::new(),
            ak: TestKey::new(),
            bk: TestKey::new(),
            rk: TestKey::new(),
        }
    }

    pub(crate) fn scope(&self) -> Scope {
        Scope {
            x: x(),
            plan: HexDigest::of(b"plan"),
            hk: self.hk.kid(),
            ak: self.ak.kid(),
            bk: self.bk.kid(),
            rk: self.rk.kid(),
        }
    }
}

pub(crate) fn x() -> X {
    X {
        aud: Env::Staging,
        host: Ident::new("host-1").unwrap(),
        op: HexDigest::of(b"op"),
        serial: PosInt::new(1).unwrap(),
    }
}

pub(crate) fn proc() -> Proc {
    Proc {
        boot: BootId::new("00000000-0000-4000-8000-000000000001").unwrap(),
        pid: PosInt::new(20).unwrap(),
        start: PosInt::new(2000).unwrap(),
        exe: HexDigest::of(b"exe"),
        build: Build::new("test-build").unwrap(),
    }
}

pub(crate) fn query(tag: Tag, signer: &TestKey, nonce: u8) -> Sig<ProofQuery> {
    Sig::sign(
        tag,
        ProofQuery {
            q: Q {
                x: x(),
                nonce: Nonce::from_array([nonce; 32]),
            },
            plan: HexDigest::of(b"plan"),
            preview: None,
        },
        signer,
    )
    .unwrap()
}

/// An H that signs clocks and counts every call that reached it.
pub(crate) struct FakeHost {
    pub hk: TestKey,
    pub calls: AtomicUsize,
}

impl FakeHost {
    pub(crate) fn new(hk: TestKey) -> Arc<Self> {
        Arc::new(Self {
            hk,
            calls: AtomicUsize::new(0),
        })
    }

    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl HostService for FakeHost {
    fn read(
        &self,
        _: Caller,
        _: Sig<ProofQuery>,
        _: Instant,
    ) -> BoxFuture<'_, Result<HRead, Error>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(Error::Binding) })
    }

    fn clock(
        &self,
        _: Caller,
        query: Sig<ProofQuery>,
        _: Instant,
    ) -> BoxFuture<'_, Result<HostClock, Error>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            Ok(Sig::sign(
                Tag::HostClock,
                HostClockBody {
                    q: query.body.q,
                    plan: query.body.plan,
                    proc: proc(),
                    instance: Ident::new("host-instance").unwrap(),
                    now: Uint::new(1_795_000_000).unwrap(),
                    uncertainty: Uint::new(1).unwrap(),
                },
                &self.hk,
            )
            .unwrap())
        })
    }

    fn register(
        &self,
        _: Caller,
        _: RegisterRequest,
        _: Instant,
    ) -> BoxFuture<'_, Result<(), Error>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}

pub(crate) fn host_server(net: &Net, keys: &Keys, service: Arc<FakeHost>) -> PrivateServer {
    PrivateServer::start(
        &net.local(Actor::H),
        net.inventory.clone(),
        keys.scope(),
        Mount::Host(service),
        net.listener(Actor::H),
        net.clock.clone(),
    )
    .unwrap()
}

/// A well-formed request with `extra` header lines and `body`.
pub(crate) fn request(net: &Net, to: Actor, path: &str, extra: &[&str], body: &[u8]) -> Vec<u8> {
    let mut head = format!(
        "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        net.row(to).endpoint.authority(),
        body.len()
    );
    for line in extra {
        head.push_str(line);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// Send exactly `bytes` as `from` to `to` and return the status code and body.
pub(crate) async fn raw(net: &Net, from: Actor, to: Actor, bytes: Vec<u8>) -> (u16, Vec<u8>) {
    let config = client_config(&net.local(from), net.row(to), net.clock.clone()).unwrap();
    let address = format!("127.0.0.1:{}", net.row(to).endpoint.port());
    let tcp = TcpStream::connect(address).await.unwrap();
    let mut tls = TlsConnector::from(config)
        .connect(ServerName::IpAddress(LOOPBACK.into()), tcp)
        .await
        .unwrap();
    tls.write_all(&bytes).await.unwrap();
    tls.flush().await.unwrap();
    let mut reply = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        tls.read_to_end(&mut reply),
    )
    .await;
    parse(&reply)
}

pub(crate) fn parse(reply: &[u8]) -> (u16, Vec<u8>) {
    let text = String::from_utf8_lossy(reply);
    let code = text
        .strip_prefix("HTTP/1.1 ")
        .and_then(|rest| rest.get(..3))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = reply
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or_else(Vec::new, |at| reply[at + 4..].to_vec());
    (code, body)
}
