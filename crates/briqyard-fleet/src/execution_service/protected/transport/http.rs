//! One request per connection over mutually pinned TLS, raw canonical bytes in and out.
//! No pooling, retry, redirect, proxy, compression, chunked request, upgrade or caller
//! chosen header ever reaches a route; every wait is bounded by the freshness deadline.

use super::{Name, PeerId, PeerRow};
use bytes::Bytes;
use futures::future::BoxFuture;
use http::{header, HeaderMap, Method, StatusCode, Version};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{body::Incoming, service::service_fn, Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::{ClientConfig, ServerConfig};
use std::{
    convert::Infallible,
    io,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::{lookup_host, TcpListener, TcpStream},
    sync::Semaphore,
    task::{JoinHandle, JoinSet},
    time::{timeout, timeout_at},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub(super) use super::super::FRESH as DEADLINE;

const MAX_CONNECTIONS: usize = 64;
const MAX_HEAD_BYTES: usize = 16 * 1024;
const JSON: &str = "application/json";
const ALPN: &[u8] = super::tls::ALPN;

/// Headers a fixed-route peer has no business sending.
const FORBIDDEN: [&str; 12] = [
    "transfer-encoding",
    "content-encoding",
    "expect",
    "upgrade",
    "te",
    "trailer",
    "via",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "proxy-authorization",
];

/// What a route answered.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Reply {
    Body(Vec<u8>),
    NoContent,
}

/// Why a client exchange gave no reply. `Status` is a definite refusal by the peer;
/// everything else is unavailable and says nothing about whether an effect happened.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Failure {
    Status(u16),
    Unavailable,
}

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A fixed origin: the pinned TLS configuration, name, address and Host value of one row.
pub(super) struct Link {
    connector: TlsConnector,
    name: rustls::pki_types::ServerName<'static>,
    host: Name,
    port: u16,
    authority: String,
}

impl Link {
    pub(super) fn new(config: Arc<ClientConfig>, target: &PeerRow) -> Self {
        Self {
            connector: TlsConnector::from(config),
            name: target.server_name.server_name(),
            host: target.endpoint.host.clone(),
            port: target.endpoint.port,
            authority: target.endpoint.authority(),
        }
    }

    /// One POST and its single response. A response larger than `limit`, a missing or
    /// wrong content type, a wrong length, a redirect or any status but 200 and 204 fails.
    pub(super) async fn post(
        &self,
        path: &'static str,
        body: Vec<u8>,
        limit: usize,
        deadline: Instant,
    ) -> Result<Reply, Failure> {
        timeout_at(deadline.into(), self.exchange(path, body, limit))
            .await
            .map_err(|_| Failure::Unavailable)?
    }

    async fn exchange(
        &self,
        path: &'static str,
        body: Vec<u8>,
        limit: usize,
    ) -> Result<Reply, Failure> {
        let io = |_: io::Error| Failure::Unavailable;
        let tcp = match &self.host {
            Name::Ip(ip) => TcpStream::connect((*ip, self.port)).await,
            Name::Dns(name) => {
                let address = lookup_host((name.as_str(), self.port))
                    .await
                    .map_err(io)?
                    .next()
                    .ok_or(Failure::Unavailable)?;
                TcpStream::connect(address).await
            }
        }
        .map_err(io)?;
        tcp.set_nodelay(true).map_err(io)?;
        let tls = self
            .connector
            .connect(self.name.clone(), tcp)
            .await
            .map_err(io)?;
        if tls.get_ref().1.alpn_protocol() != Some(ALPN) {
            return Err(Failure::Unavailable);
        }
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|_| Failure::Unavailable)?;
        let _driver = AbortOnDrop(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::HOST, &self.authority)
            .header(header::CONTENT_TYPE, JSON)
            .header(header::CONNECTION, "close")
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| Failure::Unavailable)?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| Failure::Unavailable)?;
        let (head, incoming) = response.into_parts();
        if head.version != Version::HTTP_11 {
            return Err(Failure::Unavailable);
        }
        let collected = Limited::new(incoming, limit)
            .collect()
            .await
            .map_err(|_| Failure::Unavailable)?
            .to_bytes();
        match head.status {
            StatusCode::OK => {
                let declared = length(&head.headers);
                let typed = head
                    .headers
                    .get(header::CONTENT_TYPE)
                    .is_some_and(|value| value == JSON);
                if !typed
                    || declared != Some(collected.len())
                    || head.headers.contains_key(header::CONTENT_ENCODING)
                    || collected.is_empty()
                {
                    return Err(Failure::Unavailable);
                }
                Ok(Reply::Body(collected.to_vec()))
            }
            StatusCode::NO_CONTENT => {
                if !collected.is_empty() || head.headers.contains_key(header::TRANSFER_ENCODING) {
                    return Err(Failure::Unavailable);
                }
                Ok(Reply::NoContent)
            }
            status if matches!(status.as_u16(), 400 | 401 | 403 | 409 | 507) => {
                Err(Failure::Status(status.as_u16()))
            }
            _ => Err(Failure::Unavailable),
        }
    }
}

fn length(headers: &HeaderMap) -> Option<usize> {
    let mut values = headers.get_all(header::CONTENT_LENGTH).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let text = value.to_str().ok()?;
    let parsed: usize = text.parse().ok()?;
    (parsed.to_string() == text).then_some(parsed)
}

/// An admitted request: the enrolled caller, the route path and the bounded raw body.
pub(super) struct Admitted {
    pub caller: PeerId,
    pub path: String,
    pub body: Vec<u8>,
    pub received: Instant,
}

/// The route layer behind a listener. `admit` decides from the authenticated caller and
/// path alone, before any body is read, and returns the body bound for that route.
pub(super) trait Handler: Send + Sync + 'static {
    fn admit(&self, caller: &PeerId, path: &str) -> Result<usize, u16>;
    fn handle(self: Arc<Self>, request: Admitted) -> BoxFuture<'static, Result<Reply, u16>>;
}

pub(super) struct Server {
    address: SocketAddr,
    task: JoinHandle<()>,
}

impl Server {
    pub(super) fn address(&self) -> SocketAddr {
        self.address
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Serve `listener` until dropped. The listener is already bound by the owner of its
/// descriptor; this never binds, renumbers or replaces one.
pub(super) fn serve(
    listener: std::net::TcpListener,
    tls: Arc<ServerConfig>,
    inventory: Arc<super::Inventory>,
    authority: String,
    handler: Arc<dyn Handler>,
) -> io::Result<Server> {
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let listener = TcpListener::from_std(listener)?;
    let acceptor = TlsAcceptor::from(tls);
    let gate = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            while connections.try_join_next().is_some() {}
            let Ok((tcp, _)) = listener.accept().await else {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            };
            let received = Instant::now();
            let Ok(permit) = gate.clone().try_acquire_owned() else {
                continue;
            };
            let (acceptor, inventory, authority, handler) = (
                acceptor.clone(),
                inventory.clone(),
                authority.clone(),
                handler.clone(),
            );
            connections.spawn(async move {
                let _permit = permit;
                connection(tcp, received, acceptor, inventory, authority, handler).await;
            });
        }
    });
    Ok(Server { address, task })
}

async fn connection(
    tcp: TcpStream,
    received: Instant,
    acceptor: TlsAcceptor,
    inventory: Arc<super::Inventory>,
    authority: String,
    handler: Arc<dyn Handler>,
) {
    let Ok(Ok(tls)) = timeout(DEADLINE, acceptor.accept(tcp)).await else {
        return;
    };
    let session = tls.get_ref().1;
    let caller = match session.peer_certificates() {
        Some([leaf]) => inventory
            .by_client_leaf(&briqyard_api::execution::sealed::prim::HexDigest::of(leaf))
            .map(|row| row.peer.clone()),
        _ => None,
    };
    let Some(caller) = caller else { return };
    if session.alpn_protocol() != Some(ALPN) {
        return;
    }
    let service = service_fn(move |request: Request<Incoming>| {
        let (caller, authority, handler) = (caller.clone(), authority.clone(), handler.clone());
        async move { Ok::<_, Infallible>(respond(request, received, caller, &authority, handler).await) }
    });
    let served = hyper::server::conn::http1::Builder::new()
        .keep_alive(false)
        .timer(TokioTimer::new())
        .header_read_timeout(DEADLINE)
        .max_buf_size(MAX_HEAD_BYTES)
        .serve_connection(TokioIo::new(tls), service);
    let _ = timeout(DEADLINE * 2, served).await;
}

fn status(code: u16) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = StatusCode::from_u16(code).unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    response
}

async fn respond(
    request: Request<Incoming>,
    received: Instant,
    caller: PeerId,
    authority: &str,
    handler: Arc<dyn Handler>,
) -> Response<Full<Bytes>> {
    let (head, body) = request.into_parts();
    let one = |name: header::HeaderName| head.headers.get_all(name).iter().count() == 1;
    let well_formed = head.method == Method::POST
        && head.version == Version::HTTP_11
        && head.uri.scheme().is_none()
        && head.uri.authority().is_none()
        && head.uri.query().is_none()
        && one(header::HOST)
        && head
            .headers
            .get(header::HOST)
            .is_some_and(|v| v == authority)
        && one(header::CONTENT_TYPE)
        && head
            .headers
            .get(header::CONTENT_TYPE)
            .is_some_and(|v| v == JSON)
        && head
            .headers
            .get_all(header::CONNECTION)
            .iter()
            .all(|v| v == "close")
        && !FORBIDDEN
            .iter()
            .any(|name| head.headers.contains_key(*name))
        && !head.headers.keys().any(|name| {
            name.as_str().starts_with("proxy-") || name.as_str().starts_with("x-forwarded-")
        });
    if !well_formed {
        return status(400);
    }
    let limit = match handler.admit(&caller, head.uri.path()) {
        Ok(limit) => limit,
        Err(code) => return status(code),
    };
    match length(&head.headers) {
        Some(declared) if declared <= limit => (),
        _ => return status(400),
    }
    let deadline = received + DEADLINE;
    let collected = timeout_at(deadline.into(), Limited::new(body, limit).collect()).await;
    let Ok(Ok(collected)) = collected else {
        return status(400);
    };
    let request = Admitted {
        caller,
        path: head.uri.path().to_owned(),
        body: collected.to_bytes().to_vec(),
        received,
    };
    let outcome = tokio::spawn(handler.handle(request)).await;
    match outcome {
        Ok(Ok(Reply::Body(bytes))) => {
            let mut response = Response::new(Full::new(Bytes::from(bytes)));
            response
                .headers_mut()
                .insert(header::CONTENT_TYPE, header::HeaderValue::from_static(JSON));
            response
        }
        Ok(Ok(Reply::NoContent)) => status(204),
        Ok(Err(code)) => status(code),
        Err(_) => status(503),
    }
}
