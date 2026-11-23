use super::{harness::*, pki::*};
use crate::execution_service::protected::{
    transport::{
        http::{self, Admitted, Handler, Reply},
        routes::{AuthorityPeers, Route},
        Actor, PeerId,
    },
    Error, Peers,
};
use briqyard_api::execution::sealed::{encode, sig::Tag, Limits};
use futures::future::BoxFuture;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

fn authority_peers(net: &Net) -> AuthorityPeers {
    AuthorityPeers::new(&net.local(Actor::A), &net.inventory, net.clock.clone()).unwrap()
}

#[tokio::test]
async fn a_signed_clock_query_round_trips_through_the_pinned_listener() {
    let net = Net::new();
    let keys = Keys::new();
    let service = FakeHost::new(TestKey::new());
    let _server = host_server(&net, &keys, service.clone());
    let query = query(Tag::QueryHost, &keys.ak, 1);
    let clock = authority_peers(&net)
        .host_clock(query.clone())
        .await
        .unwrap();
    assert_eq!(clock.body.q, query.body.q);
    assert_eq!(service.calls(), 1);
}

#[tokio::test]
async fn the_route_acl_is_checked_after_the_identity_and_before_any_body_is_read() {
    let net = Net::new();
    let keys = Keys::new();
    let service = FakeHost::new(TestKey::new());
    let _server = host_server(&net, &keys, service.clone());
    let read = Route::HostRead.path();
    let query = encode(&query(Tag::QueryHost, &keys.bk, 2)).unwrap();

    let ok = request(&net, Actor::H, read, &[], &query);
    assert_eq!(raw(&net, Actor::B, Actor::H, ok.clone()).await.0, 409);
    assert_eq!(service.calls(), 1);
    assert_eq!(
        raw(
            &net,
            Actor::R,
            Actor::H,
            request(
                &net,
                Actor::H,
                read,
                &[],
                &encode(&super::harness::query(Tag::QueryHost, &keys.rk, 3)).unwrap()
            )
        )
        .await
        .0,
        409
    );
    assert_eq!(service.calls(), 2);

    for path in [
        Route::HostRegister.path(),
        Route::AuthorityAdopt.path(),
        Route::AuthorityRead.path(),
        Route::ApiRead.path(),
        "/internal/execution/v1/register",
        "/internal/execution/v2/transition/seal",
        "/internal/execution/v2/transition/read/",
        "/",
    ] {
        let bytes = request(&net, Actor::H, path, &[], &query);
        let status = raw(&net, Actor::B, Actor::H, bytes).await.0;
        assert_eq!(status, 403, "{path}");
    }
    let register = request(&net, Actor::H, Route::HostRegister.path(), &[], b"{}");
    assert_eq!(raw(&net, Actor::R, Actor::H, register).await.0, 403);
    assert_eq!(service.calls(), 2);
}

#[tokio::test]
async fn a_query_must_carry_its_own_actors_signer_and_this_operations_scope() {
    let net = Net::new();
    let keys = Keys::new();
    let service = FakeHost::new(TestKey::new());
    let _server = host_server(&net, &keys, service.clone());
    let path = Route::HostClock.path();
    let send = |actor: Actor, bytes: Vec<u8>| {
        let (net, path) = (&net, path);
        async move {
            raw(
                net,
                actor,
                Actor::H,
                request(net, Actor::H, path, &[], &bytes),
            )
            .await
            .0
        }
    };

    assert_eq!(
        send(
            Actor::A,
            encode(&query(Tag::QueryHost, &keys.bk, 4)).unwrap()
        )
        .await,
        403
    );
    assert_eq!(
        send(
            Actor::B,
            encode(&query(Tag::QueryHost, &keys.ak, 5)).unwrap()
        )
        .await,
        403
    );
    assert_eq!(
        send(
            Actor::A,
            encode(&query(Tag::QueryHost, &TestKey::new(), 6)).unwrap()
        )
        .await,
        403
    );
    assert_eq!(
        send(
            Actor::A,
            encode(&query(Tag::QueryAuthority, &keys.ak, 7)).unwrap()
        )
        .await,
        400
    );
    assert_eq!(
        send(
            Actor::A,
            encode(&query(Tag::QueryApi, &keys.ak, 8)).unwrap()
        )
        .await,
        400
    );

    let mut foreign_plan = query(Tag::QueryHost, &keys.ak, 9);
    foreign_plan.body.plan = briqyard_api::execution::sealed::prim::HexDigest::of(b"other plan");
    assert_eq!(send(Actor::A, encode(&foreign_plan).unwrap()).await, 409);
    let mut foreign_x = query(Tag::QueryHost, &keys.ak, 10);
    foreign_x.body.q.x.serial = briqyard_api::execution::sealed::prim::PosInt::new(2).unwrap();
    assert_eq!(send(Actor::A, encode(&foreign_x).unwrap()).await, 409);

    let canonical = encode(&query(Tag::QueryHost, &keys.ak, 11)).unwrap();
    let mut spaced = canonical.clone();
    spaced.insert(1, b' ');
    for bad in [
        spaced,
        canonical[..canonical.len() - 1].to_vec(),
        b"{}".to_vec(),
        vec![],
    ] {
        assert_eq!(send(Actor::A, bad).await, 400);
    }
    assert_eq!(service.calls(), 0, "nothing above reached the service");
    assert_eq!(send(Actor::A, canonical).await, 200);
    assert_eq!(service.calls(), 1);
}

#[tokio::test]
async fn heads_that_a_fixed_route_has_no_use_for_are_refused_before_the_service() {
    let net = Net::new();
    let keys = Keys::new();
    let service = FakeHost::new(TestKey::new());
    let _server = host_server(&net, &keys, service.clone());
    let path = Route::HostClock.path();
    let body = encode(&query(Tag::QueryHost, &keys.ak, 12)).unwrap();
    let with = |extra: &[&str]| request(&net, Actor::H, path, extra, &body);
    for extra in [
        "Transfer-Encoding: chunked",
        "Content-Encoding: gzip",
        "Expect: 100-continue",
        "Upgrade: websocket",
        "Via: 1.1 proxy",
        "Forwarded: for=1.2.3.4",
        "X-Forwarded-For: 1.2.3.4",
        "X-Forwarded-Host: elsewhere",
        "Proxy-Authorization: Basic eA==",
        "Proxy-Connection: keep-alive",
        "Connection: keep-alive",
        "Content-Type: text/plain",
        "Content-Length: 1",
        "Host: 127.0.0.1:1",
    ] {
        let (status, _) = raw(&net, Actor::A, Actor::H, with(&[extra])).await;
        assert_eq!(status, 400, "{extra}");
    }
    let good = with(&[]);
    let text = String::from_utf8(good.clone()).unwrap();
    for (from, to) in [
        ("POST ", "GET "),
        ("POST ", "PUT "),
        ("HTTP/1.1\r\nHost", "HTTP/1.0\r\nHost"),
        (path, &format!("{path}?x=1")),
        (path, &format!("http://127.0.0.1{path}")),
    ] {
        let mutated = text.replacen(from, to, 1).into_bytes();
        let (status, _) = raw(&net, Actor::A, Actor::H, mutated).await;
        assert!(matches!(status, 400 | 0), "{from} -> {to}: {status}");
    }
    let no_host = text.replacen(
        &format!("Host: {}\r\n", net.row(Actor::H).endpoint.authority()),
        "",
        1,
    );
    assert_eq!(
        raw(&net, Actor::A, Actor::H, no_host.into_bytes()).await.0,
        400
    );
    assert_eq!(service.calls(), 0);
    assert_eq!(raw(&net, Actor::A, Actor::H, good).await.0, 200);
}

struct Echo {
    seen: AtomicUsize,
    limit: usize,
    done: AtomicUsize,
    slow: bool,
}

impl Handler for Echo {
    fn admit(&self, _: &PeerId, _: &str) -> Result<usize, u16> {
        Ok(self.limit)
    }

    fn handle(self: Arc<Self>, request: Admitted) -> BoxFuture<'static, Result<Reply, u16>> {
        Box::pin(async move {
            self.seen.store(request.body.len(), Ordering::SeqCst);
            if self.slow {
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            }
            self.done.fetch_add(1, Ordering::SeqCst);
            Ok(Reply::NoContent)
        })
    }
}

fn echo(net: &Net, limit: usize, slow: bool) -> (Arc<Echo>, http::Server) {
    let handler = Arc::new(Echo {
        seen: AtomicUsize::new(0),
        limit,
        done: AtomicUsize::new(0),
        slow,
    });
    let local = net.local(Actor::H);
    let tls = crate::execution_service::protected::transport::tls::server_config(
        &local,
        &net.inventory,
        &[Actor::A],
        net.clock.clone(),
    )
    .unwrap();
    let server = http::serve(
        net.listener(Actor::H),
        tls,
        net.inventory.clone(),
        net.row(Actor::H).endpoint.authority(),
        handler.clone(),
    )
    .unwrap();
    (handler, server)
}

#[tokio::test]
async fn the_body_bound_is_exact_at_the_message_limit_and_at_the_packet_limit() {
    for limit in [
        Limits::MESSAGE.max_bytes,
        briqyard_api::execution::sealed::transition::PACKET_LIMITS.max_bytes,
    ] {
        let net = Net::new();
        let (handler, _server) = echo(&net, limit, false);
        let path = Route::HostRead.path();
        let exact = vec![b'a'; limit];
        let (status, _) = raw(
            &net,
            Actor::A,
            Actor::H,
            request(&net, Actor::H, path, &[], &exact),
        )
        .await;
        assert_eq!(status, 204, "{limit}");
        assert_eq!(handler.seen.load(Ordering::SeqCst), limit);
        let over = vec![b'a'; limit + 1];
        let (status, _) = raw(
            &net,
            Actor::A,
            Actor::H,
            request(&net, Actor::H, path, &[], &over),
        )
        .await;
        assert_eq!(status, 400, "{limit} + 1");
        assert_eq!(handler.done.load(Ordering::SeqCst), 1);
    }
    assert_eq!(Route::HostRead.limits(), Limits::MESSAGE);
    assert_eq!(Route::HostRegister.limits().max_bytes, 1024 * 1024);
}

#[tokio::test]
async fn a_request_that_reached_a_service_completes_when_the_caller_disconnects() {
    let net = Net::new();
    let (handler, _server) = echo(&net, 1024, true);
    let bytes = request(&net, Actor::H, Route::HostRead.path(), &[], b"abc");
    let config = crate::execution_service::protected::transport::tls::client_config(
        &net.local(Actor::A),
        net.row(Actor::H),
        net.clock.clone(),
    )
    .unwrap();
    let tcp =
        tokio::net::TcpStream::connect(format!("127.0.0.1:{}", net.row(Actor::H).endpoint.port()))
            .await
            .unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(config)
        .connect(
            rustls::pki_types::ServerName::IpAddress(LOOPBACK.into()),
            tcp,
        )
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut tls, &bytes)
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::flush(&mut tls).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while handler.seen.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(handler.done.load(Ordering::SeqCst), 0);
    drop(tls);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while handler.done.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(handler.seen.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn a_failing_peer_is_asked_exactly_once() {
    let net = Net::new();
    let keys = Keys::new();
    let query = query(Tag::QueryHost, &keys.ak, 13);
    let peers = authority_peers(&net);
    let nothing_listening = peers.host_clock(query.clone()).await;
    assert!(matches!(nothing_listening, Err(Error::Unavailable)));

    let service = FakeHost::new(TestKey::new());
    let _server = host_server(&net, &keys, service.clone());
    let refused = peers.host_read(query).await;
    assert!(matches!(refused, Err(Error::Binding)));
    assert_eq!(service.calls(), 1);
}
