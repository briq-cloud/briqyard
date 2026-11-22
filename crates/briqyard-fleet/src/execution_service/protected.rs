//! Protected service state behind the existing issuer turn. The private listener and
//! credential/FD delivery adapter own ingress authentication and byte decoding.
use super::Issuer;
use briqyard_api::execution::{
    admission::{self, AuthorityTransitionView, RegistrationState},
    clock::ClockSample,
    sealed::{
        custody::{self, Capture, CustodyWire, Exited, LoadBody, Matched, Resource},
        h,
        objects::{Bind, ClaimKind, Members, Plan, Proc, ProofQuery, Q},
        prim::{BootId, Build, HexDigest, Ident, Nonce, PosInt, Uint},
        sig::{PinnedKey, Role, Sig, Signer, Tag},
        transition::{
            self as t, ARead, AReadBody, ApiView, GatePhase, GuardPhase, HRead, HostClock, LGrant,
            LKind, Launch, LaunchStage, Packet, RegisterRequest,
        },
        Wire,
    },
    validate_authority_plan, AuthorityActionProof, AuthorityVerifier, Clock, DurableIssuer,
    GuardStart,
};
use futures::future::BoxFuture;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::{self, Read},
    path::Path,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

#[cfg(test)]
mod tests;

const FRESH: Duration = Duration::from_secs(5);
const MAX_READS: usize = 16_384;

#[derive(Debug)]
pub(crate) enum Error {
    Binding,
    Unavailable,
    Journal(admission::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Binding => f.write_str("protected authority evidence refused"),
            Self::Unavailable => f.write_str("protected authority unavailable"),
            Self::Journal(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

impl From<admission::Error> for Error {
    fn from(error: admission::Error) -> Self {
        Self::Journal(error)
    }
}

fn binding(_: impl std::fmt::Debug) -> Error {
    Error::Binding
}

/// Implementation must use the operation's isolated, pinned links and exact per-action
/// members. No legacy registry client, process-global role header, redirects, or retries.
/// Return canonical decoded envelopes; the service independently verifies every signature.
pub(crate) trait Peers: Send + Sync {
    fn host_read(&self, query: Sig<ProofQuery>) -> BoxFuture<'_, Result<HRead, Error>>;
    fn api_read(&self, query: Sig<ProofQuery>) -> BoxFuture<'_, Result<ApiView, Error>>;
    fn host_clock(&self, query: Sig<ProofQuery>) -> BoxFuture<'_, Result<HostClock, Error>>;
    fn register_once<'a>(
        &'a self,
        cohort: &'a AdoptedCohort,
        request: RegisterRequest,
    ) -> BoxFuture<'a, Result<(), Error>>;
}

/// From the trusted native custody adapter after credential, descriptor, pidfd poll and
/// final-I/O verification. These signed objects are checked again and cannot supply OS proof.
pub(crate) struct CustodyStart<'a> {
    pub plan: Plan,
    pub plan_hash: HexDigest,
    pub consumed: &'a Launch,
    pub grant: &'a LGrant,
    pub launch_claim: Nonce,
    pub capture: &'a Capture,
    pub load: &'a Sig<LoadBody>,
    pub request: &'a CustodyWire,
    pub matched: &'a Matched,
    pub exited: &'a Exited,
}

struct Pins {
    hk: PinnedKey,
    ak: PinnedKey,
    bk: PinnedKey,
    rk: PinnedKey,
}

#[derive(Clone)]
struct HostIdentity {
    proc: Proc,
    instance: Ident,
    retirement: HexDigest,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AdoptedCohort {
    pub bind: Bind,
    pub members: Members,
    pub guard: HexDigest,
}

pub(crate) struct Protected {
    issuer: Issuer,
    verifier: AuthorityVerifier,
    plan: Plan,
    plan_hash: HexDigest,
    proc: Proc,
    host: HostIdentity,
    pins: Pins,
    ak: Arc<dyn Signer + Send + Sync>,
    peers: Arc<dyn Peers>,
    cohort: OnceLock<AdoptedCohort>,
    reads: Mutex<HashMap<Nonce, Instant>>,
}

impl Protected {
    /// No listener is mounted here. Native startup must own the retained FDs and pass
    /// only independently verified custody inputs, not values parsed from an HTTP body.
    pub(crate) async fn from_custody(
        root: &Path,
        ordinary_pkcs8: &[u8],
        kid: String,
        start: CustodyStart<'_>,
        ak: Arc<dyn Signer + Send + Sync>,
        peers: Arc<dyn Peers>,
        #[cfg(test)] local: (Proc, fn() -> Option<ClockSample>),
    ) -> Result<Self, Error> {
        let deadline = Instant::now() + FRESH;
        #[cfg(not(test))]
        let (proc, clock) = (current_process()?, ClockSample::read);
        #[cfg(test)]
        let (proc, clock) = local;
        let pins = start.verify(&proc, ak.as_ref())?;
        let signed = challenge(
            ak.as_ref(),
            &start.plan,
            &start.plan_hash,
            Tag::QueryHost,
            None,
        )?;
        let host_read = within(deadline, peers.host_read(signed.clone())).await?;
        let host = verify_host(
            &host_read,
            &signed.body,
            &start.plan,
            &start.plan_hash,
            &pins.hk,
        )?;
        if host_read.body.gate.phase != GatePhase::Sealed {
            return Err(Error::Binding);
        }
        let issuer = DurableIssuer::open_guarded(
            root,
            ordinary_pkcs8,
            kid,
            GuardStart {
                plan: &start.plan,
                plan_hash: &start.plan_hash,
                launch: start.consumed,
                proc: &proc,
                receipt: host_read.body.gate.receipt.as_ref().ok_or(Error::Binding)?,
                clock,
            },
            deadline,
        )?;
        let verifier = issuer.authority_verifier()?;
        let view = verifier.snapshot()?;
        let sample = verifier.sample()?;
        if view.guard().phase != GuardPhase::Started
            || view
                .registration_state(None, sample.interval().ok_or(Error::Unavailable)?)?
                .water
                != start.plan.pre.generation.get()
        {
            return Err(Error::Binding);
        }
        Ok(Self {
            issuer: Issuer(tokio::sync::Mutex::new(issuer)),
            verifier,
            plan: start.plan,
            plan_hash: start.plan_hash,
            proc,
            host,
            pins,
            ak,
            peers,
            cohort: OnceLock::new(),
            reads: Mutex::new(HashMap::new()),
        })
    }

    /// Ingress supplies its own monotonic receive instant and authenticates the private
    /// endpoint before calling this method. An Hk caller is read-only.
    pub(crate) async fn read(
        &self,
        query: &Sig<ProofQuery>,
        received: Instant,
    ) -> Result<ARead, Error> {
        let deadline = fresh_deadline(received)?;
        let pins = [&self.pins.hk, &self.pins.rk, &self.pins.bk];
        let pin = pins
            .into_iter()
            .find(|p| HexDigest::of(p.raw()) == query.kid)
            .ok_or(Error::Binding)?;
        let query = query.verify(Tag::QueryAuthority, pin).map_err(binding)?;
        if query.q.x != self.plan.x || query.plan != self.plan_hash {
            return Err(Error::Binding);
        }
        {
            let mut reads = self.reads.lock().map_err(|_| Error::Unavailable)?;
            reads.retain(|_, until| *until > Instant::now());
            if reads.len() >= MAX_READS || reads.contains_key(&query.q.nonce) {
                return Err(Error::Unavailable);
            }
            reads.insert(query.q.nonce, deadline);
        }
        let view = self.snapshot()?;
        let preview = if view.guard().bind.is_none() {
            query.preview.as_ref()
        } else {
            None
        };
        if let Some(bind) = preview {
            self.check_bind(bind)?;
        }
        let salt = nonce()?;
        let q = Q {
            x: query.q.x.clone(),
            nonce: t::host_challenge_nonce(&query.q, &self.plan_hash, &salt).map_err(binding)?,
        };
        let request = self.sign_query(q.clone(), Tag::QueryHost, None)?;
        let began = Instant::now();
        let before = self.verifier.sample()?;
        let host_clock = within(deadline, self.peers.host_clock(request)).await?;
        let sample = self.verifier.sample()?;
        let hc = host_clock
            .verify(Tag::HostClock, &self.pins.hk)
            .map_err(binding)?;
        if hc.q != q
            || hc.plan != self.plan_hash
            || hc.proc != self.host.proc
            || hc.instance != self.host.instance
        {
            return Err(Error::Binding);
        }
        if before.monotonic < began
            || sample.monotonic >= deadline
            || sample.monotonic > Instant::now()
        {
            return Err(Error::Unavailable);
        }
        let clock = before
            .bracket_peer(
                &sample,
                Clock {
                    now: hc.now.get(),
                    uncertainty: hc.uncertainty.get(),
                },
            )
            .ok_or(Error::Unavailable)?;
        view.registration_state(preview, before.interval().ok_or(Error::Unavailable)?)?;
        let state = self.registration_state(&view, preview, clock)?;
        let cap = view.capacity(preview, &self.host.proc, clock)?;
        let guard = view.guard().clone();
        let body = AReadBody {
            q: query.q.clone(),
            plan: self.plan_hash.clone(),
            proc: self.proc.clone(),
            guard_hash: guard.hash().map_err(binding)?,
            guard,
            salt,
            host_clock,
            native_water: Uint::new(state.water).map_err(binding)?,
            intent: state.intent,
            uncertain: state.uncertain,
            ready: state.ready,
            cap,
        };
        body.check_host(&self.host.proc, &self.host.instance)
            .map_err(binding)?;
        body.check_selection(preview).map_err(binding)?;
        let read = Sig::sign(Tag::AuthorityRead, body, self.ak.as_ref()).map_err(binding)?;
        read.verify(Tag::AuthorityRead, &self.pins.ak)
            .map_err(binding)?;
        if !view.same_snapshot(&self.snapshot()?)
            || Instant::now() >= deadline.min(sample.monotonic + Duration::from_secs(1))
        {
            return Err(Error::Unavailable);
        }
        Ok(read)
    }

    /// Only the authenticated provisional API installer may reach this crossing.
    pub(crate) async fn adopt(&self, packet: &Packet, received: Instant) -> Result<(), Error> {
        let checked = self.crossing(packet, ClaimKind::Adopt, received).await?;
        let mut issuer = self.issuer.lock().await;
        if self.cohort.get().is_some() {
            return Err(Error::Binding);
        }
        issuer.adopt_guard(checked)?;
        let committed = issuer.installation_journal().authority_transition()?;
        let guard = committed.guard();
        let cohort = AdoptedCohort {
            bind: guard.bind.clone().ok_or(Error::Unavailable)?,
            members: self.plan.new.clone(),
            guard: guard.hash().map_err(binding)?,
        };
        issuer.publish();
        self.cohort.set(cohort).map_err(|_| Error::Unavailable)
    }

    /// This is the only call that can disclose a new witness and the only host send. A
    /// lost response leaves the original pending and cannot make this call forward again.
    pub(crate) async fn register(&self, packet: Packet, received: Instant) -> Result<(), Error> {
        let checked = self
            .crossing(&packet, ClaimKind::Register, received)
            .await?;
        let prepared = checked.prepare_witness(self.ak.as_ref())?;
        let (witness, deadline) = {
            let mut issuer = self.issuer.lock().await;
            issuer.begin_original_registration(checked, prepared)?
        };
        let cohort = self.cohort.get().ok_or(Error::Unavailable)?;
        if Instant::now() >= deadline {
            return Err(Error::Unavailable);
        }
        within(
            deadline,
            self.peers
                .register_once(cohort, RegisterRequest { packet, witness }),
        )
        .await
    }

    /// Records only a fresh, independently observed host ACK for the saved original.
    /// Neither this path nor a ready read calls the host registration transport.
    pub(crate) async fn record_ack(
        &self,
        packet: &Packet,
        received: Instant,
    ) -> Result<bool, Error> {
        let checked = self
            .crossing(packet, ClaimKind::RecordAck, received)
            .await?;
        let mut issuer = self.issuer.lock().await;
        Ok(issuer.record_original_ack(checked)?)
    }

    fn snapshot(&self) -> Result<AuthorityTransitionView, Error> {
        let view = self.verifier.snapshot()?;
        let guard = view.guard();
        if guard.x != self.plan.x
            || guard.plan != self.plan_hash
            || guard.proc != self.proc
            || guard.ordinary_key != self.plan.ordinary_key
            || guard.set != self.plan.new.set().map_err(binding)?
        {
            return Err(Error::Binding);
        }
        match (&guard.bind, self.cohort.get()) {
            (None, None) if guard.phase == GuardPhase::Started => (),
            (Some(bind), Some(cohort))
                if guard.phase == GuardPhase::Adopted
                    && cohort.bind == *bind
                    && cohort.members == self.plan.new
                    && cohort.guard == guard.hash().map_err(binding)? =>
            {
                self.check_bind(bind)?
            }
            _ => return Err(Error::Unavailable),
        }
        Ok(view)
    }

    fn registration_state(
        &self,
        view: &AuthorityTransitionView,
        bind: Option<&Bind>,
        clock: briqyard_api::execution::Clock,
    ) -> Result<RegistrationState, Error> {
        let state = view.registration_state(bind, clock)?;
        let water = state
            .intent
            .as_ref()
            .map_or(self.plan.pre.generation.get(), |i| {
                i.record.generation.get()
            });
        if state.water != water {
            return Err(Error::Binding);
        }
        Ok(state)
    }

    fn check_bind(&self, bind: &Bind) -> Result<(), Error> {
        t::check_bind_plan(bind, &self.plan_hash, &self.plan).map_err(binding)?;
        if bind.record.authority != self.plan.pre_record.authority
            || bind.record.epoch == self.plan.pre.epoch
            || bind.record.host_instance != self.host.instance
            || bind.intent == self.plan.pre_intent
        {
            return Err(Error::Binding);
        }
        Ok(())
    }

    fn sign_query(&self, q: Q, tag: Tag, preview: Option<Bind>) -> Result<Sig<ProofQuery>, Error> {
        Sig::sign(
            tag,
            ProofQuery {
                q,
                plan: self.plan_hash.clone(),
                preview,
            },
            self.ak.as_ref(),
        )
        .map_err(binding)
    }

    async fn crossing<'a>(
        &self,
        packet: &'a Packet,
        action: ClaimKind,
        received: Instant,
    ) -> Result<AuthorityActionProof<'a>, Error> {
        self.snapshot()?;
        let challenge = self.verifier.challenge(action, packet, received)?;
        let host_query = Sig::sign(
            Tag::QueryHost,
            challenge.host_query().clone(),
            self.ak.as_ref(),
        )
        .map_err(binding)?;
        let api_query = Sig::sign(
            Tag::QueryApi,
            challenge.api_query().clone(),
            self.ak.as_ref(),
        )
        .map_err(binding)?;
        let deadline = challenge.deadline();
        let (host, api) = tokio::try_join!(
            within(deadline, self.peers.host_read(host_query)),
            within(deadline, self.peers.api_read(api_query)),
        )?;
        Ok(challenge.finish(host, &api)?)
    }
}

impl CustodyStart<'_> {
    fn verify(&self, proc: &Proc, ak: &dyn Signer) -> Result<Pins, Error> {
        let plan = &self.plan;
        validate_authority_plan(plan)?;
        let pin = |role, key: &briqyard_api::execution::sealed::prim::KeyBytes| {
            PinnedKey::new(role, *key.as_array()).map_err(binding)
        };
        if h(plan).map_err(binding)? != self.plan_hash
            || self.consumed.plan != self.plan_hash
            || self.consumed.x != plan.x
            || self.consumed.stage != LaunchStage::Consumed
            || self.consumed.resource != Resource::Authority
            || self.consumed.old != plan.pre_a
            || proc.boot != plan.pre_a.boot
            || self.consumed.custodian.boot != proc.boot
            || proc.exe != plan.next_a
            || proc.build != plan.abuild
            || self.request.next.as_ref() != Some(proc)
            || ak.public_key() != *plan.ak.as_array()
            || ak.public_key() == *plan.ordinary_key.as_array()
            || self.launch_claim == self.consumed.nonce
        {
            return Err(Error::Binding);
        }
        self.consumed.validate().map_err(binding)?;
        let pins = Pins {
            hk: pin(Role::Hk, &plan.hk)?,
            ak: pin(Role::Ak, &plan.ak)?,
            bk: pin(Role::Bk, &plan.bk)?,
            rk: pin(Role::Rk, &plan.rk)?,
        };
        let decision = self.grant.verify(&pins.rk, &pins.bk).map_err(binding)?;
        decision.check_launch(self.consumed).map_err(binding)?;
        if decision.action != LKind::LaunchA || decision.nonce != self.launch_claim {
            return Err(Error::Binding);
        }
        self.consumed
            .check_capture(&self.capture.body.wire)
            .map_err(binding)?;
        custody::verify_exit(
            self.capture,
            self.matched,
            self.exited,
            &pins.rk,
            self.request,
        )
        .map_err(binding)?;
        let load = self
            .load
            .verify(Tag::CustodyLoad, &pins.rk)
            .map_err(binding)?;
        if load.x != plan.x
            || load.plan != self.plan_hash
            || load.resource != Resource::Authority
            || load.owner != self.consumed.owner
            || load.launch != self.consumed.hash().map_err(binding)?
            || load.capture != h(self.capture).map_err(binding)?
        {
            return Err(Error::Binding);
        }
        Ok(pins)
    }
}

fn verify_host(
    read: &HRead,
    query: &ProofQuery,
    plan: &Plan,
    plan_hash: &HexDigest,
    hk: &PinnedKey,
) -> Result<HostIdentity, Error> {
    let body = read.verify(Tag::HostRead, hk).map_err(binding)?;
    if body.q != query.q
        || body.q.x != plan.x
        || body.plan != *plan_hash
        || query.plan != *plan_hash
        || body.proc.boot != plan.pre_d.boot
        || body.proc.exe != plan.next_d
        || body.proc.build != plan.dbuild
        || body.proc == plan.pre_d
    {
        return Err(Error::Binding);
    }
    let receipt = body.gate.receipt.as_ref().ok_or(Error::Binding)?;
    t::verify_receipt(receipt, hk).map_err(binding)?;
    receipt
        .body
        .cut
        .check_plan(plan_hash, plan)
        .map_err(binding)?;
    Ok(HostIdentity {
        proc: body.proc.clone(),
        instance: body.gate.instance.clone(),
        retirement: h(receipt).map_err(binding)?,
    })
}

fn fresh_deadline(received: Instant) -> Result<Instant, Error> {
    let now = Instant::now();
    let deadline = received.checked_add(FRESH).ok_or(Error::Unavailable)?;
    if now < received || now >= deadline {
        return Err(Error::Unavailable);
    }
    Ok(deadline)
}

async fn within<T>(deadline: Instant, future: BoxFuture<'_, Result<T, Error>>) -> Result<T, Error> {
    if Instant::now() >= deadline {
        return Err(Error::Unavailable);
    }
    let result = tokio::time::timeout_at(deadline.into(), future)
        .await
        .map_err(|_| Error::Unavailable)??;
    if Instant::now() >= deadline {
        return Err(Error::Unavailable);
    }
    Ok(result)
}

fn nonce() -> Result<Nonce, Error> {
    let mut raw = [0; 32];
    OsRng
        .try_fill_bytes(&mut raw)
        .map_err(|_| Error::Unavailable)?;
    Ok(Nonce::from_array(raw))
}

fn challenge(
    signer: &dyn Signer,
    plan: &Plan,
    plan_hash: &HexDigest,
    tag: Tag,
    preview: Option<Bind>,
) -> Result<Sig<ProofQuery>, Error> {
    let q = Q {
        x: plan.x.clone(),
        nonce: nonce()?,
    };
    Sig::sign(
        tag,
        ProofQuery {
            q,
            plan: plan_hash.clone(),
            preview,
        },
        signer,
    )
    .map_err(binding)
}

#[cfg(target_os = "linux")]
fn current_process() -> Result<Proc, Error> {
    const MAX_EXECUTABLE: u64 = 256 * 1024 * 1024;
    let read_small = |path| {
        let mut bytes = String::new();
        std::fs::File::open(path)?
            .take(4097)
            .read_to_string(&mut bytes)?;
        if bytes.len() > 4096 {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        Ok::<_, io::Error>(bytes)
    };
    let boot = read_small("/proc/sys/kernel/random/boot_id").map_err(|_| Error::Unavailable)?;
    let stat = read_small("/proc/self/stat").map_err(|_| Error::Unavailable)?;
    let (leader, tail) = stat.rsplit_once(") ").ok_or(Error::Unavailable)?;
    let pid = u64::from(std::process::id());
    if leader
        .split_once(" (")
        .and_then(|(raw, _)| raw.parse().ok())
        != Some(pid)
    {
        return Err(Error::Unavailable);
    }
    let start = tail
        .split_whitespace()
        .nth(19)
        .and_then(|raw| raw.parse().ok())
        .ok_or(Error::Unavailable)?;
    let exe = std::fs::File::open("/proc/self/exe").map_err(|_| Error::Unavailable)?;
    let mut state = Sha256::new();
    let size =
        io::copy(&mut exe.take(MAX_EXECUTABLE + 1), &mut state).map_err(|_| Error::Unavailable)?;
    if size == 0 || size > MAX_EXECUTABLE {
        return Err(Error::Unavailable);
    }
    Ok(Proc {
        boot: BootId::new(boot.strip_suffix('\n').ok_or(Error::Unavailable)?).map_err(binding)?,
        pid: PosInt::new(pid).map_err(binding)?,
        start: PosInt::new(start).map_err(binding)?,
        exe: HexDigest::from_raw(state.finalize().into()),
        build: Build::new(briqyard_version::VERSION).map_err(binding)?,
    })
}

#[cfg(not(target_os = "linux"))]
fn current_process() -> Result<Proc, Error> {
    Err(Error::Unavailable)
}
