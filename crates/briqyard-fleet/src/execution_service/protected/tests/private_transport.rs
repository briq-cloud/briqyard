//! The real protected service behind real private listeners and pinned clients. Every
//! identity is generated in memory for the test; nothing here is production credential.
use super::*;
use crate::execution_service::protected::transport::{
    tests::{
        harness::{raw, request},
        pki::Net,
    },
    Actor, ApiService, AuthorityPeers, AuthorityService, Caller, HostLinks, HostPeers, HostService,
    Mount, PrivateServer, Route, Scope,
};
use briqyard_api::execution::sealed::{encode, transition::AReadBody};

struct Auth(Arc<Fixture>);

impl AuthorityService for Auth {
    fn read(
        &self,
        c: Caller,
        q: Sig<ProofQuery>,
        at: Instant,
    ) -> BoxFuture<'_, Result<ARead, Error>> {
        AuthorityService::read(&self.0.service, c, q, at)
    }
    fn adopt(&self, c: Caller, p: Packet, at: Instant) -> BoxFuture<'_, Result<(), Error>> {
        AuthorityService::adopt(&self.0.service, c, p, at)
    }
    fn register(&self, c: Caller, p: Packet, at: Instant) -> BoxFuture<'_, Result<(), Error>> {
        AuthorityService::register(&self.0.service, c, p, at)
    }
    fn record_ack(&self, c: Caller, p: Packet, at: Instant) -> BoxFuture<'_, Result<(), Error>> {
        AuthorityService::record_ack(&self.0.service, c, p, at)
    }
}

struct PeerHost {
    peer: Arc<Peer>,
    lose_reply: AtomicBool,
}

impl HostService for PeerHost {
    fn read(
        &self,
        _: Caller,
        q: Sig<ProofQuery>,
        _: Instant,
    ) -> BoxFuture<'_, Result<HRead, Error>> {
        self.peer.host_read(q)
    }
    fn clock(
        &self,
        _: Caller,
        q: Sig<ProofQuery>,
        _: Instant,
    ) -> BoxFuture<'_, Result<HostClock, Error>> {
        self.peer.host_clock(q)
    }
    fn register(
        &self,
        _: Caller,
        request: RegisterRequest,
        _: Instant,
    ) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            let cohort = AdoptedCohort {
                bind: request.packet.p.body.bind.clone(),
                members: members("new"),
                guard: request.witness.body.guard.clone(),
            };
            match self.peer.register_once(&cohort, request).await {
                Err(Error::Unavailable) if !self.lose_reply.load(Ordering::SeqCst) => Ok(()),
                other => other,
            }
        })
    }
}

struct PeerApi(Arc<Peer>);

impl ApiService for PeerApi {
    fn read(
        &self,
        _: Caller,
        q: Sig<ProofQuery>,
        _: Instant,
    ) -> BoxFuture<'_, Result<ApiView, Error>> {
        self.0.api_read(q)
    }
}

struct Deployment {
    net: Net,
    f: Arc<Fixture>,
    host: Arc<PeerHost>,
    _servers: Vec<PrivateServer>,
}

impl Deployment {
    fn new(lose_reply: bool) -> Self {
        let mut f = Fixture::new();
        let net = Net::for_x(f.service.plan.x.clone(), |_, _| ());
        f.service.peers = Arc::new(
            AuthorityPeers::new(&net.local(Actor::A), &net.inventory, net.clock.clone()).unwrap(),
        );
        let f = Arc::new(f);
        let scope =
            Scope::new(&f.service.plan, f.service.plan_hash.clone(), &net.inventory).unwrap();
        let host = Arc::new(PeerHost {
            peer: f.peer.clone(),
            lose_reply: AtomicBool::new(lose_reply),
        });
        let start = |actor, mount| {
            PrivateServer::start(
                &net.local(actor),
                net.inventory.clone(),
                scope.clone(),
                mount,
                net.listener(actor),
                net.clock.clone(),
            )
            .unwrap()
        };
        let servers = vec![
            start(Actor::H, Mount::Host(host.clone())),
            start(Actor::B, Mount::Api(Arc::new(PeerApi(f.peer.clone())))),
            start(Actor::A, Mount::Authority(Arc::new(Auth(f.clone())))),
        ];
        Self {
            net,
            f,
            host,
            _servers: servers,
        }
    }

    async fn send(&self, from: Actor, route: Route, body: &[u8]) -> (u16, Vec<u8>) {
        let bytes = request(&self.net, route.server(), route.path(), &[], body);
        raw(&self.net, from, route.server(), bytes).await
    }

    async fn crossing(&self, from: Actor, route: Route, action: ClaimKind) -> u16 {
        let packet = self.f.packet(action).await;
        self.send(from, route, &packet.encode().unwrap()).await.0
    }

    fn sends(&self) -> usize {
        self.f.peer.sends.load(Ordering::SeqCst)
    }
}

#[tokio::test]
async fn the_authority_answers_signed_reads_only_to_the_actors_that_may_ask() {
    let d = Deployment::new(false);
    let f = &d.f;
    let read = |signer: &Key| encode(&f.query(signer, None)).unwrap();
    for (actor, signer) in [
        (Actor::R, &f.rk),
        (Actor::B, &f.peer.bk),
        (Actor::H, &f.peer.hk),
    ] {
        let (status, body) = d.send(actor, Route::AuthorityRead, &read(signer)).await;
        assert_eq!(status, 200, "{actor:?}");
        let read = Sig::<AReadBody>::decode(&body, Tag::AuthorityRead).unwrap();
        assert_eq!(read.body.guard.phase, GuardPhase::Started);
        assert!(!read.body.ready);
    }
    assert_eq!(
        d.send(Actor::R, Route::AuthorityRead, &read(&f.peer.bk))
            .await
            .0,
        403
    );
    assert_eq!(
        d.send(Actor::B, Route::AuthorityRead, &read(&f.rk)).await.0,
        403
    );
    assert_eq!(
        d.send(Actor::Installer, Route::AuthorityRead, &read(&f.rk))
            .await
            .0,
        403
    );
    assert_eq!(
        d.send(Actor::A, Route::AuthorityRead, &read(&f.rk)).await.0,
        0,
        "the authority's own client identity is not admitted to its listener"
    );
    let ak = f.service.ak.clone();
    let own = challenge(
        ak.as_ref(),
        &f.service.plan,
        &f.service.plan_hash,
        Tag::QueryAuthority,
        None,
    )
    .unwrap();
    assert_eq!(
        d.send(Actor::H, Route::AuthorityRead, &encode(&own).unwrap())
            .await
            .0,
        403
    );
}

#[tokio::test]
async fn adoption_register_and_ack_cross_only_through_their_fixed_routes_and_actors() {
    let d = Deployment::new(false);
    let f = &d.f;

    let adopt = f.packet(ClaimKind::Adopt).await;
    let bytes = adopt.encode().unwrap();
    for actor in [Actor::Installer, Actor::R, Actor::H] {
        assert_eq!(
            d.send(actor, Route::AuthorityAdopt, &bytes).await.0,
            403,
            "{actor:?}"
        );
    }
    assert_eq!(d.send(Actor::A, Route::AuthorityAdopt, &bytes).await.0, 0);
    assert_eq!(
        d.send(Actor::B, Route::AuthorityRegister, &bytes).await.0,
        403
    );
    assert_eq!(
        d.send(Actor::Installer, Route::AuthorityRegister, &bytes)
            .await
            .0,
        400
    );
    assert_eq!(
        d.send(Actor::Installer, Route::AuthorityRecordAck, &bytes)
            .await
            .0,
        400
    );
    let mut forged = adopt.clone();
    forged.p.kid = hash("not the api signer");
    assert_eq!(
        d.send(Actor::B, Route::AuthorityAdopt, &forged.encode().unwrap())
            .await
            .0,
        403
    );
    assert!(f.service.cohort.get().is_none());

    let (status, body) = d.send(Actor::B, Route::AuthorityAdopt, &bytes).await;
    assert_eq!((status, body.len()), (204, 0));
    assert_eq!(
        f.service.snapshot().unwrap().guard().phase,
        GuardPhase::Adopted
    );
    assert!(d.send(Actor::B, Route::AuthorityAdopt, &bytes).await.0 >= 400);

    let register = f.packet(ClaimKind::Register).await.encode().unwrap();
    assert_eq!(
        d.send(Actor::B, Route::AuthorityRegister, &register)
            .await
            .0,
        403
    );
    assert_eq!(d.sends(), 0);
    let (status, body) = d
        .send(Actor::Installer, Route::AuthorityRegister, &register)
        .await;
    assert_eq!((status, body.len()), (204, 0));
    assert_eq!(d.sends(), 1);
    assert_eq!(f.peer.gate.lock().unwrap().phase, GatePhase::Registered);
    assert!(
        d.send(Actor::Installer, Route::AuthorityRegister, &register)
            .await
            .0
            >= 400
    );
    assert_eq!(d.sends(), 1);

    assert_eq!(
        d.crossing(
            Actor::Installer,
            Route::AuthorityRecordAck,
            ClaimKind::RecordAck
        )
        .await,
        204
    );
    let (_, body) = d
        .send(
            Actor::R,
            Route::AuthorityRead,
            &encode(&f.query(&f.rk, None)).unwrap(),
        )
        .await;
    let ready = Sig::<AReadBody>::decode(&body, Tag::AuthorityRead).unwrap();
    assert!(ready.body.ready && !ready.body.uncertain);
    assert_eq!(d.sends(), 1);
}

#[tokio::test]
async fn a_lost_registration_reply_is_one_send_and_the_original_survives_for_the_ack() {
    let d = Deployment::new(true);
    let f = &d.f;
    assert_eq!(
        d.crossing(Actor::B, Route::AuthorityAdopt, ClaimKind::Adopt)
            .await,
        204
    );
    let register = f.packet(ClaimKind::Register).await.encode().unwrap();
    let (status, body) = d
        .send(Actor::Installer, Route::AuthorityRegister, &register)
        .await;
    assert_eq!((status, body.len()), (503, 0));
    assert_eq!(d.sends(), 1);
    assert!(
        d.send(Actor::Installer, Route::AuthorityRegister, &register)
            .await
            .0
            >= 400
    );
    assert_eq!(d.sends(), 1);
    let pending = f.read(None).await;
    assert!(pending.body.intent.is_some() && !pending.body.ready);

    d.host.lose_reply.store(false, Ordering::SeqCst);
    assert_eq!(
        d.crossing(
            Actor::Installer,
            Route::AuthorityRecordAck,
            ClaimKind::RecordAck
        )
        .await,
        204
    );
    assert!(f.read(None).await.body.ready);
    assert_eq!(d.sends(), 1);
}

#[tokio::test]
async fn the_host_reads_the_authority_and_the_api_through_its_own_pinned_links() {
    let d = Deployment::new(false);
    let f = &d.f;
    assert_eq!(
        d.crossing(Actor::B, Route::AuthorityAdopt, ClaimKind::Adopt)
            .await,
        204
    );
    let links = HostLinks::new(
        &d.net.local(Actor::H),
        &d.net.inventory,
        d.net.clock.clone(),
    )
    .unwrap();
    let signed =
        |tag| challenge(&f.peer.hk, &f.service.plan, &f.service.plan_hash, tag, None).unwrap();
    let asked = signed(Tag::QueryAuthority);
    let read = links.authority_read(asked.clone()).await.unwrap();
    assert_eq!(read.body.q, asked.body.q);
    assert_eq!(read.body.guard.phase, GuardPhase::Adopted);
    let asked = signed(Tag::QueryApi);
    let view = links.api_read(asked.clone()).await.unwrap();
    assert_eq!(view.body.q, asked.body.q);
    assert!(links.authority_read(signed(Tag::QueryApi)).await.is_err());
    assert!(links.api_read(signed(Tag::QueryAuthority)).await.is_err());
}

#[tokio::test]
async fn the_original_registration_forwards_unchanged_and_a_second_arming_is_impossible() {
    let d = Deployment::new(false);
    let f = &d.f;
    assert_eq!(
        d.crossing(Actor::B, Route::AuthorityAdopt, ClaimKind::Adopt)
            .await,
        204
    );
    let register = f.packet(ClaimKind::Register).await;
    assert_eq!(
        d.send(
            Actor::Installer,
            Route::AuthorityRegister,
            &register.encode().unwrap()
        )
        .await
        .0,
        204
    );
    assert_eq!(d.sends(), 1);
    let gate = f.peer.gate.lock().unwrap().clone();
    let done = gate.done.expect("the host registered");
    assert_eq!(done.permit, h(&register.p).unwrap());
    let view = f.service.snapshot().unwrap();
    let origin = view.origin().unwrap();
    assert_eq!(done.witness, origin.witness);
    assert_eq!(done.permit, origin.permit);
}

#[test]
fn a_plan_of_another_operation_cannot_scope_the_inventory() {
    let f = Fixture::new();
    let net = Net::new();
    assert_ne!(f.service.plan.x, *net.inventory.x());
    assert!(Scope::new(&f.service.plan, f.service.plan_hash.clone(), &net.inventory).is_err());
    let own = Net::for_x(f.service.plan.x.clone(), |_, _| ());
    assert!(Scope::new(&f.service.plan, f.service.plan_hash.clone(), &own.inventory).is_ok());
}
