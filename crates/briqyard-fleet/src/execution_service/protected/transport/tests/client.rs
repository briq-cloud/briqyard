use super::{harness::*, pki::*};
use crate::execution_service::protected::{
    transport::{
        http::{Failure, Link, Reply, DEADLINE},
        routes::{AuthorityPeers, Route},
        tls::{client_config, server_config},
        Actor,
    },
    Error, Peers,
};
use briqyard_api::execution::sealed::{
    encode,
    objects::HostClockBody,
    prim::{Ident, Uint},
    sig::{Sig, Tag},
};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Instant,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;

/// An H-side server that reads one request and writes `response` verbatim.
struct Canned {
    count: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for Canned {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn canned(net: &Net, response: Vec<u8>, alpn: bool) -> Canned {
    let local = net.local(Actor::H);
    let mut config =
        (*server_config(&local, &net.inventory, &[Actor::A], net.clock.clone()).unwrap()).clone();
    if !alpn {
        config.alpn_protocols.clear();
    }
    let listener = net.listener(Actor::H);
    listener.set_nonblocking(true).unwrap();
    let listener = TcpListener::from_std(listener).unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    let task = tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            seen.fetch_add(1, Ordering::SeqCst);
            let Ok(mut tls) = acceptor.accept(tcp).await else {
                continue;
            };
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 4096];
            while let Ok(read) = tls.read(&mut chunk).await {
                buffer.extend_from_slice(&chunk[..read]);
                let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") else {
                    if read == 0 {
                        break;
                    }
                    continue;
                };
                let head = String::from_utf8_lossy(&buffer[..end]).to_lowercase();
                let length: usize = head
                    .split("content-length: ")
                    .nth(1)
                    .and_then(|rest| rest.split("\r\n").next())
                    .and_then(|n| n.parse().ok())
                    .unwrap_or(0);
                if buffer.len() >= end + 4 + length || read == 0 {
                    break;
                }
            }
            let _ = tls.write_all(&response).await;
            let _ = tls.shutdown().await;
        }
    });
    Canned { count, task }
}

fn response(status: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
    let mut text = format!("HTTP/1.1 {status}\r\n");
    for header in headers {
        text.push_str(header);
        text.push_str("\r\n");
    }
    text.push_str("\r\n");
    let mut bytes = text.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn ok(body: &[u8]) -> Vec<u8> {
    response(
        "200 OK",
        &[
            "Content-Type: application/json",
            &format!("Content-Length: {}", body.len()),
            "Connection: close",
        ],
        body,
    )
}

fn link(net: &Net) -> Link {
    let local = net.local(Actor::A);
    let config = client_config(&local, net.row(Actor::H), net.clock.clone()).unwrap();
    Link::new(config, net.row(Actor::H))
}

async fn post(net: &Net, bytes: Vec<u8>, limit: usize) -> (Result<Reply, Failure>, usize) {
    let server = canned(net, bytes, true).await;
    let outcome = link(net)
        .post(
            Route::HostClock.path(),
            b"{}".to_vec(),
            limit,
            Instant::now() + DEADLINE,
        )
        .await;
    (outcome, server.count.load(Ordering::SeqCst))
}

#[tokio::test]
async fn only_a_complete_typed_200_or_a_bare_204_is_a_reply() {
    let net = Net::new();
    let (reply, count) = post(&net, ok(b"{\"a\":1}"), 64).await;
    assert_eq!(reply, Ok(Reply::Body(b"{\"a\":1}".to_vec())));
    assert_eq!(count, 1);
    for bytes in [response("204 No Content", &["Connection: close"], b"")] {
        let net = Net::new();
        assert_eq!(post(&net, bytes, 64).await.0, Ok(Reply::NoContent));
    }
    for (name, bytes) in [
        (
            "no type",
            response("200 OK", &["Content-Length: 2", "Connection: close"], b"{}"),
        ),
        (
            "wrong type",
            response(
                "200 OK",
                &[
                    "Content-Type: text/plain",
                    "Content-Length: 2",
                    "Connection: close",
                ],
                b"{}",
            ),
        ),
        (
            "encoded",
            response(
                "200 OK",
                &[
                    "Content-Type: application/json",
                    "Content-Encoding: gzip",
                    "Content-Length: 2",
                    "Connection: close",
                ],
                b"{}",
            ),
        ),
        (
            "chunked",
            response(
                "200 OK",
                &[
                    "Content-Type: application/json",
                    "Transfer-Encoding: chunked",
                    "Connection: close",
                ],
                b"2\r\n{}\r\n0\r\n\r\n",
            ),
        ),
        (
            "empty",
            response(
                "200 OK",
                &[
                    "Content-Type: application/json",
                    "Content-Length: 0",
                    "Connection: close",
                ],
                b"",
            ),
        ),
        (
            "no length",
            response(
                "200 OK",
                &["Content-Type: application/json", "Connection: close"],
                b"{}",
            ),
        ),
        ("oversize", ok(&[b' '; 65])),
        (
            "http 1.0",
            b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
                .to_vec(),
        ),
        (
            "no content with a type",
            response(
                "204 No Content",
                &["Transfer-Encoding: chunked", "Connection: close"],
                b"",
            ),
        ),
        (
            "truncated",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{}"
                .to_vec(),
        ),
        ("garbage", b"\x16\x03\x01".to_vec()),
        ("silence", vec![]),
    ] {
        let net = Net::new();
        assert_eq!(
            post(&net, bytes, 64).await.0,
            Err(Failure::Unavailable),
            "{name}"
        );
    }
}

#[tokio::test]
async fn redirects_and_server_errors_are_not_followed_or_retried() {
    for code in [
        "301 Moved Permanently",
        "302 Found",
        "303 See Other",
        "307 Temporary Redirect",
        "308 Permanent Redirect",
    ] {
        let net = Net::new();
        let bytes = response(
            code,
            &[
                "Location: https://127.0.0.1:1/elsewhere",
                "Content-Length: 0",
                "Connection: close",
            ],
            b"",
        );
        let (outcome, count) = post(&net, bytes, 64).await;
        assert_eq!(outcome, Err(Failure::Unavailable), "{code}");
        assert_eq!(count, 1, "{code}");
    }
    for (status, expected) in [
        ("400 Bad Request", Failure::Status(400)),
        ("401 Unauthorized", Failure::Status(401)),
        ("403 Forbidden", Failure::Status(403)),
        ("409 Conflict", Failure::Status(409)),
        ("507 Insufficient Storage", Failure::Status(507)),
        ("404 Not Found", Failure::Unavailable),
        ("500 Internal Server Error", Failure::Unavailable),
        ("503 Service Unavailable", Failure::Unavailable),
    ] {
        let net = Net::new();
        let bytes = response(status, &["Content-Length: 0", "Connection: close"], b"");
        let (outcome, count) = post(&net, bytes, 64).await;
        assert_eq!(outcome, Err(expected), "{status}");
        assert_eq!(count, 1);
    }
}

#[tokio::test]
async fn a_server_without_the_negotiated_protocol_is_not_spoken_to() {
    let net = Net::new();
    let server = canned(&net, ok(b"{}"), false).await;
    let outcome = link(&net)
        .post(
            Route::HostClock.path(),
            b"{}".to_vec(),
            64,
            Instant::now() + DEADLINE,
        )
        .await;
    assert_eq!(outcome, Err(Failure::Unavailable));
    assert!(server.count.load(Ordering::SeqCst) <= 1);
}

#[tokio::test]
async fn a_reply_is_decoded_canonically_and_bound_to_the_query_it_answers() {
    let keys = Keys::new();
    let asked = query(Tag::QueryHost, &keys.ak, 20);
    let signed = |nonce: u8, key: &TestKey| {
        encode(
            &Sig::sign(
                Tag::HostClock,
                HostClockBody {
                    q: query(Tag::QueryHost, &keys.ak, nonce).body.q,
                    plan: asked.body.plan.clone(),
                    proc: proc(),
                    instance: Ident::new("host-instance").unwrap(),
                    now: Uint::new(1_795_000_000).unwrap(),
                    uncertainty: Uint::new(1).unwrap(),
                },
                key,
            )
            .unwrap(),
        )
        .unwrap()
    };
    let call = |net: &Net| {
        let peers =
            AuthorityPeers::new(&net.local(Actor::A), &net.inventory, net.clock.clone()).unwrap();
        let asked = asked.clone();
        async move { peers.host_clock(asked).await }
    };

    let own = Net::new();
    let server = canned(&own, ok(&signed(20, &keys.hk)), true).await;
    assert!(call(&own).await.is_ok());
    drop(server);

    let other_query = Net::new();
    let server = canned(&other_query, ok(&signed(21, &keys.hk)), true).await;
    assert!(matches!(call(&other_query).await, Err(Error::Binding)));
    drop(server);

    let mut loose = signed(20, &keys.hk);
    loose.insert(0, b' ');
    for body in [loose, b"{}".to_vec(), br#"{"tag":"host.clock"}"#.to_vec()] {
        let net = Net::new();
        let _server = canned(&net, ok(&body), true).await;
        assert!(matches!(call(&net).await, Err(Error::Binding)));
    }

    let wrong_tag = Net::new();
    let _server = canned(
        &wrong_tag,
        response("204 No Content", &["Connection: close"], b""),
        true,
    )
    .await;
    assert!(matches!(call(&wrong_tag).await, Err(Error::Unavailable)));
}

#[tokio::test]
async fn a_query_for_another_target_is_not_sent() {
    let net = Net::new();
    let keys = Keys::new();
    let server = canned(&net, ok(b"{}"), true).await;
    let peers =
        AuthorityPeers::new(&net.local(Actor::A), &net.inventory, net.clock.clone()).unwrap();
    assert!(matches!(
        peers.host_read(query(Tag::QueryApi, &keys.ak, 22)).await,
        Err(Error::Binding)
    ));
    assert!(matches!(
        peers.api_read(query(Tag::QueryHost, &keys.ak, 23)).await,
        Err(Error::Binding)
    ));
    assert_eq!(server.count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn adapters_exist_only_for_the_actor_whose_identity_they_use() {
    let net = Net::new();
    for actor in [Actor::H, Actor::B, Actor::R, Actor::Installer] {
        assert!(AuthorityPeers::new(&net.local(actor), &net.inventory, net.clock.clone()).is_err());
    }
    for actor in [Actor::A, Actor::B, Actor::R, Actor::Installer] {
        assert!(
            crate::execution_service::protected::transport::routes::HostLinks::new(
                &net.local(actor),
                &net.inventory,
                net.clock.clone()
            )
            .is_err()
        );
    }
}
