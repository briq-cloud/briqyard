//! The closed route table of the private transition surface, its ACL, the two client
//! adapters and the two server mounts. A route is one concrete operation with one typed
//! request and one typed reply; nothing here forwards bytes it did not decode.
//!
//! Server-side checks before a service sees anything: the caller is an enrolled actor the
//! route's ACL names; the signed query carries that actor's own signer key; the body is
//! canonical and (for a packet) is for exactly this action; X and the Plan digest are this
//! operation's. The service then verifies every signature and holds every state decision.

use super::{
    http::{self, Admitted, Failure, Handler, Link, Reply, DEADLINE},
    tls, Actor, ConfigError, Inventory, LocalIdentity, PeerId,
};
use crate::execution_service::protected::{AdoptedCohort, Error, Peers, Protected};
use briqyard_api::execution::{
    clock::ClockSource,
    sealed::{
        encode,
        objects::{ClaimKind, HostClockBody, Plan, ProofQuery, Q, X},
        prim::HexDigest,
        sig::{Sig, Tag},
        transition::{
            ARead, AReadBody, ApiView, ApiViewBody, HRead, HReadBody, HostClock, Packet,
            RegisterRequest,
        },
        Limits, Wire,
    },
};
use futures::future::BoxFuture;
use std::{
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Instant,
};

const PREFIX_HOST: &str = "/internal/execution/v2/transition";
const PREFIX_AUTHORITY: &str = "/internal/authority/v2/transition";

/// Every operation the private surface has. Adding one is a code change, not a config one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Route {
    HostRead,
    HostClock,
    HostRegister,
    AuthorityRead,
    AuthorityAdopt,
    AuthorityRegister,
    AuthorityRecordAck,
    ApiRead,
}

impl Route {
    pub(crate) const ALL: [Route; 8] = [
        Self::HostRead,
        Self::HostClock,
        Self::HostRegister,
        Self::AuthorityRead,
        Self::AuthorityAdopt,
        Self::AuthorityRegister,
        Self::AuthorityRecordAck,
        Self::ApiRead,
    ];

    pub(crate) const fn path(self) -> &'static str {
        match self {
            Self::HostRead => "/internal/execution/v2/transition/read",
            Self::HostClock => "/internal/execution/v2/transition/clock",
            Self::HostRegister => "/internal/execution/v2/transition/register",
            Self::AuthorityRead => "/internal/authority/v2/transition/read",
            Self::AuthorityAdopt => "/internal/authority/v2/transition/adopt",
            Self::AuthorityRegister => "/internal/authority/v2/transition/register",
            Self::AuthorityRecordAck => "/internal/authority/v2/transition/record-ack",
            Self::ApiRead => "/internal/sealed/v2/read",
        }
    }

    /// Who serves the route.
    pub(crate) const fn server(self) -> Actor {
        match self {
            Self::HostRead | Self::HostClock | Self::HostRegister => Actor::H,
            Self::AuthorityRead
            | Self::AuthorityAdopt
            | Self::AuthorityRegister
            | Self::AuthorityRecordAck => Actor::A,
            Self::ApiRead => Actor::B,
        }
    }

    /// Who may call it (v3.1: "Each target accepts only signers participating in X";
    /// registration comes from the adopted authority, never the receiver; the authority's
    /// crossings come from the API side, register and record-ack through its installer).
    pub(crate) const fn callers(self) -> &'static [Actor] {
        match self {
            Self::HostRead | Self::HostClock => &[Actor::A, Actor::R, Actor::B],
            Self::HostRegister => &[Actor::A],
            Self::AuthorityRead => &[Actor::H, Actor::R, Actor::B],
            Self::AuthorityAdopt => &[Actor::B],
            Self::AuthorityRegister | Self::AuthorityRecordAck => &[Actor::Installer],
            Self::ApiRead => &[Actor::H, Actor::A, Actor::R],
        }
    }

    /// A mutation answers 204 and nothing else; a read answers a signed proof.
    pub(crate) const fn mutation(self) -> bool {
        matches!(
            self,
            Self::HostRegister
                | Self::AuthorityAdopt
                | Self::AuthorityRegister
                | Self::AuthorityRecordAck
        )
    }

    /// Packets and the register wrapper are the only 1 MiB bodies.
    pub(crate) const fn limits(self) -> Limits {
        match self {
            Self::HostRegister
            | Self::AuthorityAdopt
            | Self::AuthorityRegister
            | Self::AuthorityRecordAck => {
                briqyard_api::execution::sealed::transition::PACKET_LIMITS
            }
            _ => Limits::MESSAGE,
        }
    }

    fn from_path(path: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|route| route.path() == path)
    }

    const fn query_tag(self) -> Tag {
        match self {
            Self::HostRead | Self::HostClock => Tag::QueryHost,
            Self::AuthorityRead => Tag::QueryAuthority,
            _ => Tag::QueryApi,
        }
    }
}

/// The caller as the transport authenticated it, after the route ACL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Caller {
    pub peer: PeerId,
}

/// What H answers on its dedicated listener. The implementation holds the host turn.
pub(crate) trait HostService: Send + Sync + 'static {
    fn read(
        &self,
        caller: Caller,
        query: Sig<ProofQuery>,
        received: Instant,
    ) -> BoxFuture<'_, Result<HRead, Error>>;
    fn clock(
        &self,
        caller: Caller,
        query: Sig<ProofQuery>,
        received: Instant,
    ) -> BoxFuture<'_, Result<HostClock, Error>>;
    fn register(
        &self,
        caller: Caller,
        request: RegisterRequest,
        received: Instant,
    ) -> BoxFuture<'_, Result<(), Error>>;
}

/// What A answers on its dedicated listener; [`Protected`] is the production implementation.
pub(crate) trait AuthorityService: Send + Sync + 'static {
    fn read(
        &self,
        caller: Caller,
        query: Sig<ProofQuery>,
        received: Instant,
    ) -> BoxFuture<'_, Result<ARead, Error>>;
    fn adopt(
        &self,
        caller: Caller,
        packet: Packet,
        received: Instant,
    ) -> BoxFuture<'_, Result<(), Error>>;
    fn register(
        &self,
        caller: Caller,
        packet: Packet,
        received: Instant,
    ) -> BoxFuture<'_, Result<(), Error>>;
    fn record_ack(
        &self,
        caller: Caller,
        packet: Packet,
        received: Instant,
    ) -> BoxFuture<'_, Result<(), Error>>;
}

impl AuthorityService for Protected {
    fn read(
        &self,
        _caller: Caller,
        query: Sig<ProofQuery>,
        received: Instant,
    ) -> BoxFuture<'_, Result<ARead, Error>> {
        Box::pin(async move { Protected::read(self, &query, received).await })
    }

    fn adopt(
        &self,
        _caller: Caller,
        packet: Packet,
        received: Instant,
    ) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move { Protected::adopt(self, &packet, received).await })
    }

    fn register(
        &self,
        _caller: Caller,
        packet: Packet,
        received: Instant,
    ) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move { Protected::register(self, packet, received).await })
    }

    fn record_ack(
        &self,
        _caller: Caller,
        packet: Packet,
        received: Instant,
    ) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            Protected::record_ack(self, &packet, received).await?;
            Ok(())
        })
    }
}

#[cfg(test)]
pub(crate) trait ApiService: Send + Sync + 'static {
    fn read(
        &self,
        caller: Caller,
        query: Sig<ProofQuery>,
        received: Instant,
    ) -> BoxFuture<'_, Result<ApiView, Error>>;
}

/// The one service a listener fronts.
#[derive(Clone)]
pub(crate) enum Mount {
    Host(Arc<dyn HostService>),
    Authority(Arc<dyn AuthorityService>),
    #[cfg(test)]
    Api(Arc<dyn ApiService>),
}

impl Mount {
    const fn actor(&self) -> Actor {
        match self {
            Self::Host(_) => Actor::H,
            Self::Authority(_) => Actor::A,
            #[cfg(test)]
            Self::Api(_) => Actor::B,
        }
    }
}

/// The operation's pins: X, the Plan digest and the four signer key IDs.
#[derive(Clone, Debug)]
pub(crate) struct Scope {
    pub x: X,
    pub plan: HexDigest,
    pub hk: HexDigest,
    pub ak: HexDigest,
    pub bk: HexDigest,
    pub rk: HexDigest,
}

impl Scope {
    /// Only for the operation the inventory was verified for: §Plan.x§ is the inputs' X.
    pub(crate) fn new(
        plan: &Plan,
        plan_hash: HexDigest,
        inventory: &Inventory,
    ) -> Result<Self, ConfigError> {
        if plan.x != *inventory.x() {
            return Err(ConfigError("plan is not the inputs' operation"));
        }
        let kid =
            |key: &briqyard_api::execution::sealed::prim::KeyBytes| HexDigest::of(key.as_array());
        Ok(Self {
            x: plan.x.clone(),
            plan: plan_hash,
            hk: kid(&plan.hk),
            ak: kid(&plan.ak),
            bk: kid(&plan.bk),
            rk: kid(&plan.rk),
        })
    }

    /// The signer key an actor's signed queries must carry.
    fn kid(&self, actor: Actor) -> Option<&HexDigest> {
        match actor {
            Actor::H => Some(&self.hk),
            Actor::A => Some(&self.ak),
            Actor::B => Some(&self.bk),
            Actor::R => Some(&self.rk),
            Actor::Installer | Actor::Gateway => None,
        }
    }

    fn check_query(&self, caller: &PeerId, query: &Sig<ProofQuery>) -> Result<(), u16> {
        if self.kid(caller.actor) != Some(&query.kid) {
            return Err(403);
        }
        if query.body.q.x != self.x || query.body.plan != self.plan {
            return Err(409);
        }
        Ok(())
    }

    fn check_packet(&self, packet: &Packet) -> Result<(), u16> {
        let ticket = &packet.p.body;
        if packet.p.kid != self.bk || packet.ok.kid != self.rk {
            return Err(403);
        }
        if ticket.x != self.x || ticket.plan != self.plan {
            return Err(409);
        }
        Ok(())
    }
}

fn refused(error: Error) -> u16 {
    match error {
        Error::Binding => 409,
        Error::Unavailable | Error::Journal(_) => 503,
    }
}

fn decode<T>(decoded: Result<T, impl Sized>) -> Result<T, u16> {
    decoded.map_err(|_| 400)
}

struct Dispatch {
    scope: Scope,
    mount: Mount,
}

impl Dispatch {
    fn route(&self, path: &str) -> Option<Route> {
        Route::from_path(path).filter(|route| route.server() == self.mount.actor())
    }

    async fn run(&self, request: Admitted) -> Result<Reply, u16> {
        let route = self.route(&request.path).ok_or(403u16)?;
        let Admitted {
            caller,
            body,
            received,
            ..
        } = request;
        let scope = &self.scope;
        let query = |tag| -> Result<Sig<ProofQuery>, u16> {
            let query = decode(ProofQuery::decode_signed(&body, tag))?;
            scope.check_query(&caller, &query)?;
            Ok(query)
        };
        let packet = |action| -> Result<Packet, u16> {
            let packet = decode(Packet::decode_for(&body, action))?;
            scope.check_packet(&packet)?;
            Ok(packet)
        };
        let who = Caller {
            peer: caller.clone(),
        };
        let signed = |reply: Result<Vec<u8>, _>| reply.map(Reply::Body).map_err(|_| 503u16);
        match (&self.mount, route) {
            (Mount::Host(service), Route::HostRead) => {
                let read = service
                    .read(who, query(route.query_tag())?, received)
                    .await
                    .map_err(refused)?;
                signed(encode(&read))
            }
            (Mount::Host(service), Route::HostClock) => {
                let clock = service
                    .clock(who, query(route.query_tag())?, received)
                    .await
                    .map_err(refused)?;
                signed(encode(&clock))
            }
            (Mount::Host(service), Route::HostRegister) => {
                let request = decode(RegisterRequest::decode(&body))?;
                scope.check_packet(&request.packet)?;
                if request.witness.kid != scope.ak {
                    return Err(403);
                }
                service
                    .register(who, request, received)
                    .await
                    .map_err(refused)?;
                Ok(Reply::NoContent)
            }
            (Mount::Authority(service), Route::AuthorityRead) => {
                let read = service
                    .read(who, query(route.query_tag())?, received)
                    .await
                    .map_err(refused)?;
                signed(encode(&read))
            }
            (Mount::Authority(service), Route::AuthorityAdopt) => {
                service
                    .adopt(who, packet(ClaimKind::Adopt)?, received)
                    .await
                    .map_err(refused)?;
                Ok(Reply::NoContent)
            }
            (Mount::Authority(service), Route::AuthorityRegister) => {
                service
                    .register(who, packet(ClaimKind::Register)?, received)
                    .await
                    .map_err(refused)?;
                Ok(Reply::NoContent)
            }
            (Mount::Authority(service), Route::AuthorityRecordAck) => {
                service
                    .record_ack(who, packet(ClaimKind::RecordAck)?, received)
                    .await
                    .map_err(refused)?;
                Ok(Reply::NoContent)
            }
            #[cfg(test)]
            (Mount::Api(service), Route::ApiRead) => {
                let view = service
                    .read(who, query(route.query_tag())?, received)
                    .await
                    .map_err(refused)?;
                signed(encode(&view))
            }
            _ => Err(403),
        }
    }
}

impl Handler for Dispatch {
    fn admit(&self, caller: &PeerId, path: &str) -> Result<usize, u16> {
        let route = self.route(path).ok_or(403u16)?;
        if !route.callers().contains(&caller.actor) {
            return Err(403);
        }
        Ok(route.limits().max_bytes)
    }

    fn handle(self: Arc<Self>, request: Admitted) -> BoxFuture<'static, Result<Reply, u16>> {
        Box::pin(async move { self.run(request).await })
    }
}

/// A running dedicated listener. Dropping it stops accepting; a request already handed to
/// a service runs to completion.
pub(crate) struct PrivateServer {
    server: http::Server,
}

impl PrivateServer {
    /// `listener` is the owner's already-bound dedicated socket; its port must be the one
    /// the local row pins. The TLS layer admits only the enrolled clients of the actors
    /// some route of this mount lists.
    pub(crate) fn start(
        local: &LocalIdentity,
        inventory: Arc<Inventory>,
        scope: Scope,
        mount: Mount,
        listener: TcpListener,
        clock: Arc<dyn ClockSource>,
    ) -> Result<Self, ConfigError> {
        let row = inventory
            .row(local.peer())
            .ok_or(ConfigError("unenrolled peer"))?;
        let port = listener
            .local_addr()
            .map_err(|_| ConfigError("listener"))?
            .port();
        if local.peer().actor != mount.actor() || row.endpoint.port() != port {
            return Err(ConfigError("mount or listener is not this peer's"));
        }
        let mut callers = Vec::new();
        for route in Route::ALL
            .into_iter()
            .filter(|r| r.server() == mount.actor())
        {
            for actor in route.callers() {
                if !callers.contains(actor) {
                    callers.push(*actor);
                }
            }
        }
        let tls = tls::server_config(local, &inventory, &callers, clock)?;
        let authority = row.endpoint.authority();
        let handler = Arc::new(Dispatch { scope, mount });
        let server = http::serve(listener, tls, inventory, authority, handler)
            .map_err(|_| ConfigError("listener"))?;
        Ok(Self { server })
    }

    pub(crate) fn address(&self) -> std::net::SocketAddr {
        self.server.address()
    }
}

/// A fixed read: one signed query out, one signed proof back, bound to that query.
async fn read<T: Wire>(
    link: &Link,
    route: Route,
    query: Sig<ProofQuery>,
    decode: fn(&[u8]) -> Option<T>,
    bound: fn(&T) -> &Q,
) -> Result<T, Error> {
    if query.tag != route.query_tag() || route.mutation() {
        return Err(Error::Binding);
    }
    let body = briqyard_api::execution::sealed::encode(&query).map_err(|_| Error::Binding)?;
    let deadline = Instant::now() + DEADLINE;
    match link
        .post(route.path(), body, route.limits().max_bytes, deadline)
        .await
    {
        Ok(Reply::Body(bytes)) => {
            let reply = decode(&bytes).ok_or(Error::Binding)?;
            if *bound(&reply) != query.body.q {
                return Err(Error::Binding);
            }
            Ok(reply)
        }
        Ok(Reply::NoContent) | Err(Failure::Unavailable) => Err(Error::Unavailable),
        Err(Failure::Status(_)) => Err(Error::Binding),
    }
}

/// One crossing: the unchanged bytes out, a bare 204 back.
async fn cross(link: &Link, route: Route, body: Vec<u8>) -> Result<(), Error> {
    if !route.mutation() {
        return Err(Error::Binding);
    }
    let deadline = Instant::now() + DEADLINE;
    match link
        .post(route.path(), body, route.limits().max_bytes, deadline)
        .await
    {
        Ok(Reply::NoContent) => Ok(()),
        _ => Err(Error::Unavailable),
    }
}

/// A's outgoing side: reads of H and B and the one original registration send to H. The
/// send is armed once for this value; the service's own durable marker is the real gate.
pub(crate) struct AuthorityPeers {
    host: Link,
    api: Link,
    sent: AtomicBool,
}

impl AuthorityPeers {
    pub(crate) fn new(
        local: &LocalIdentity,
        inventory: &Inventory,
        clock: Arc<dyn ClockSource>,
    ) -> Result<Self, ConfigError> {
        if local.peer().actor != Actor::A {
            return Err(ConfigError("not the authority"));
        }
        let link = |actor| {
            let row = inventory.only(actor)?;
            Ok(Link::new(
                tls::client_config(local, row, clock.clone())?,
                row,
            ))
        };
        Ok(Self {
            host: link(Actor::H)?,
            api: link(Actor::B)?,
            sent: AtomicBool::new(false),
        })
    }
}

fn host_read(bytes: &[u8]) -> Option<HRead> {
    Sig::<HReadBody>::decode(bytes, Tag::HostRead).ok()
}

fn host_clock(bytes: &[u8]) -> Option<HostClock> {
    Sig::<HostClockBody>::decode(bytes, Tag::HostClock).ok()
}

fn api_read(bytes: &[u8]) -> Option<ApiView> {
    Sig::<ApiViewBody>::decode(bytes, Tag::ApiRead).ok()
}

fn authority_read(bytes: &[u8]) -> Option<ARead> {
    Sig::<AReadBody>::decode(bytes, Tag::AuthorityRead).ok()
}

impl Peers for AuthorityPeers {
    fn host_read(&self, query: Sig<ProofQuery>) -> BoxFuture<'_, Result<HRead, Error>> {
        Box::pin(read(&self.host, Route::HostRead, query, host_read, |r| {
            &r.body.q
        }))
    }

    fn api_read(&self, query: Sig<ProofQuery>) -> BoxFuture<'_, Result<ApiView, Error>> {
        Box::pin(read(&self.api, Route::ApiRead, query, api_read, |r| {
            &r.body.q
        }))
    }

    fn host_clock(&self, query: Sig<ProofQuery>) -> BoxFuture<'_, Result<HostClock, Error>> {
        Box::pin(read(&self.host, Route::HostClock, query, host_clock, |r| {
            &r.body.q
        }))
    }

    fn register_once<'a>(
        &'a self,
        cohort: &'a AdoptedCohort,
        request: RegisterRequest,
    ) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            if cohort.bind != request.packet.p.body.bind
                || cohort.guard != request.witness.body.guard
            {
                return Err(Error::Binding);
            }
            let body = request.encode().map_err(|_| Error::Binding)?;
            if self.sent.swap(true, Ordering::SeqCst) {
                return Err(Error::Unavailable);
            }
            cross(&self.host, Route::HostRegister, body).await
        })
    }
}

/// H's outgoing reads, for its own verification of a registration before it commits.
pub(crate) trait HostPeers: Send + Sync {
    fn authority_read(&self, query: Sig<ProofQuery>) -> BoxFuture<'_, Result<ARead, Error>>;
    fn api_read(&self, query: Sig<ProofQuery>) -> BoxFuture<'_, Result<ApiView, Error>>;
}

pub(crate) struct HostLinks {
    authority: Link,
    api: Link,
}

impl HostLinks {
    pub(crate) fn new(
        local: &LocalIdentity,
        inventory: &Inventory,
        clock: Arc<dyn ClockSource>,
    ) -> Result<Self, ConfigError> {
        if local.peer().actor != Actor::H {
            return Err(ConfigError("not the host"));
        }
        let link = |actor| {
            let row = inventory.only(actor)?;
            Ok(Link::new(
                tls::client_config(local, row, clock.clone())?,
                row,
            ))
        };
        Ok(Self {
            authority: link(Actor::A)?,
            api: link(Actor::B)?,
        })
    }
}

impl HostPeers for HostLinks {
    fn authority_read(&self, query: Sig<ProofQuery>) -> BoxFuture<'_, Result<ARead, Error>> {
        Box::pin(read(
            &self.authority,
            Route::AuthorityRead,
            query,
            authority_read,
            |r| &r.body.q,
        ))
    }

    fn api_read(&self, query: Sig<ProofQuery>) -> BoxFuture<'_, Result<ApiView, Error>> {
        Box::pin(read(&self.api, Route::ApiRead, query, api_read, |r| {
            &r.body.q
        }))
    }
}
