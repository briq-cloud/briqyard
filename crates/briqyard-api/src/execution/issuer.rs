//! The signing key belongs to the trusted admission service, never the public gateway.
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::signature::Ed25519KeyPair;
use sealed::{
    canonical::{h, Wire},
    custody::Resource,
    objects::{ClaimKind, Plan, Proc},
    prim::{HexDigest, Ident},
    sig::{PinnedKey, Role as SigningRole},
    transition::{
        GatePhase, Guard, GuardPhase, HRead, Launch, Permit as SealedPermit, Receipt, Witness,
    },
};
use std::{
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

mod transition;
pub use transition::{AuthorityActionProof, AuthorityChallenge, AuthorityVerifier};

/// Holds the authority key and exclusive ledger together. No public method releases a
/// newly signed permit until the complete quota vector and admission are durable.
pub struct DurableIssuer {
    journal: admission::Journal,
    key: Ed25519KeyPair,
    kid: String,
    guarded: Option<Arc<GuardedKeys>>,
}

struct GuardedKeys {
    ak: PinnedKey,
    bk: PinnedKey,
    hk: PinnedKey,
    rk: PinnedKey,
    plan: Plan,
    plan_hash: HexDigest,
    host_proc: Proc,
    host_instance: Ident,
    retirement: HexDigest,
    clock: fn() -> Option<clock::ClockSample>,
}

/// Inputs from the independently verified local custody path, never an HTTP request.
pub struct GuardStart<'a> {
    pub plan: &'a Plan,
    pub plan_hash: &'a HexDigest,
    pub launch: &'a Launch,
    pub proc: &'a Proc,
    pub receipt: &'a Receipt,
    pub clock: fn() -> Option<clock::ClockSample>,
}

/// The local Plan's exact key and cohort constraints. An absent old transition member
/// describes the legacy predecessor in the independently pinned custody inputs.
pub fn validate_authority_plan(plan: &Plan) -> Result<(), admission::Error> {
    use admission::Error::Binding;
    plan.validate().map_err(|_| Binding)?;
    if plan.pre_a.boot != plan.pre_d.boot {
        return Err(Binding);
    }
    let new_transition = plan.new.tr.as_ref().ok_or(Binding)?;
    let mut members = std::collections::BTreeSet::new();
    for member in [
        &plan.old.hi,
        &plan.old.he,
        &plan.old.ni,
        &plan.old.ng,
        &plan.new.hi,
        &plan.new.he,
        &plan.new.ni,
        &plan.new.ng,
        new_transition,
    ]
    .into_iter()
    .chain(plan.old.tr.as_ref())
    {
        if !members.insert(member) {
            return Err(Binding);
        }
    }
    Ok(())
}

/// A local bracketed clock and the monotonic request/peer-read deadline. Permit windows
/// use qualified UTC milliseconds; the native journal still orders in qualified seconds.
struct GuardedTime<'a> {
    sample: &'a clock::ClockSample,
    request_deadline: Instant,
}

impl GuardedTime<'_> {
    fn check(&self, permit: Option<&SealedPermit>) -> Result<(Clock, Instant), admission::Error> {
        use admission::Error::Binding;
        let lo = self.sample.lower_ms().ok_or(Binding)?;
        let hi = self.sample.upper_ms().ok_or(Binding)?;
        let now = Instant::now();
        let limit = if let Some(p) = permit {
            if !p.body.window_contains(lo, hi) {
                return Err(Binding);
            }
            Duration::from_millis((p.body.expires.get() - hi).min(1_000))
        } else {
            Duration::from_secs(1)
        };
        let deadline = self
            .request_deadline
            .min(self.sample.monotonic.checked_add(limit).ok_or(Binding)?);
        if now < self.sample.monotonic || now >= deadline {
            return Err(Binding);
        }
        Ok((self.sample.interval().ok_or(Binding)?, deadline))
    }
}
pub struct IssueCredentials<'a> {
    pub grant: &'a str,
    pub allocations: &'a [&'a str],
}
#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    #[error(transparent)]
    Verify(#[from] VerifyError),
    #[error(transparent)]
    Journal(#[from] admission::Error),
}
impl DurableIssuer {
    pub fn from_pkcs8(
        journal: admission::Journal,
        bytes: &[u8],
        kid: String,
    ) -> Result<Self, admission::Error> {
        let key = Ed25519KeyPair::from_pkcs8(bytes).map_err(|_| admission::Error::Binding)?;
        Self::new(journal, key, kid)
    }

    pub fn new(
        journal: admission::Journal,
        key: Ed25519KeyPair,
        kid: String,
    ) -> Result<Self, admission::Error> {
        if !matches!(journal.role(), admission::Role::Authority(_))
            || journal.is_guarded_authority()
        {
            return Err(admission::Error::Binding);
        }
        Ok(Self {
            journal,
            key,
            kid,
            guarded: None,
        })
    }

    pub fn open_guarded(
        root: &Path,
        ordinary_pkcs8: &[u8],
        kid: String,
        start: GuardStart<'_>,
        request_deadline: Instant,
    ) -> Result<Self, admission::Error> {
        use admission::Error::Binding;
        use ring::signature::KeyPair;
        let GuardStart {
            plan,
            plan_hash,
            launch,
            proc,
            receipt,
            clock: clock_source,
        } = start;
        validate_authority_plan(plan)?;
        launch.validate().map_err(|_| Binding)?;
        let key = Ed25519KeyPair::from_pkcs8(ordinary_pkcs8).map_err(|_| Binding)?;
        if h(plan).map_err(|_| Binding)? != *plan_hash
            || launch.old != plan.pre_a
            || launch.resource != Resource::Authority
            || proc.boot != plan.pre_a.boot
            || launch.custodian.boot != proc.boot
            || proc.exe != plan.next_a
            || proc.build != plan.abuild
            || *proc == plan.pre_a
            || key.public_key().as_ref() != plan.ordinary_key.as_array()
            || key.public_key().as_ref() != plan.pre_record.public_key
            || kid != plan.pre_record.key_id.as_str()
        {
            return Err(Binding);
        }
        let pin = |role, bytes: sealed::prim::KeyBytes| {
            PinnedKey::new(role, *bytes.as_array()).map_err(|_| Binding)
        };
        let hk = pin(SigningRole::Hk, plan.hk)?;
        sealed::transition::verify_receipt(receipt, &hk).map_err(|_| Binding)?;
        let cut = &receipt.body.cut;
        cut.check_plan(plan_hash, plan).map_err(|_| Binding)?;
        if cut.new_proc.boot != proc.boot
            || cut.new_proc.exe != plan.next_d
            || cut.new_proc.build != plan.dbuild
            || cut.new_proc == plan.pre_d
        {
            return Err(Binding);
        }
        let guarded = Arc::new(GuardedKeys {
            ak: pin(SigningRole::Ak, plan.ak)?,
            bk: pin(SigningRole::Bk, plan.bk)?,
            hk,
            rk: pin(SigningRole::Rk, plan.rk)?,
            plan: plan.clone(),
            plan_hash: plan_hash.clone(),
            host_proc: cut.new_proc.clone(),
            host_instance: cut.new_instance.clone(),
            retirement: h(receipt).map_err(|_| Binding)?,
            clock: clock_source,
        });
        let sample = clock_source().ok_or(admission::Error::Persistence)?;
        let (clock, deadline) = GuardedTime {
            sample: &sample,
            request_deadline,
        }
        .check(None)?;
        let journal = admission::Journal::open_guarded(
            root,
            admission::Role::Authority(plan.pre_record.authority.to_string()),
            clock,
            plan,
            &|epoch| {
                let guard = Guard {
                    x: plan.x.clone(),
                    plan: plan_hash.clone(),
                    phase: GuardPhase::Started,
                    launch: launch.hash().map_err(|_| Binding)?,
                    proc: proc.clone(),
                    epoch: Ident::new(epoch).map_err(|_| Binding)?,
                    ordinary_kid: plan.pre_record.key_id.clone(),
                    ordinary_key: plan.ordinary_key,
                    set: plan.new.set().map_err(|_| Binding)?,
                    bind: None,
                    armed_gate: None,
                    adoption: None,
                };
                guard.check_launch(launch).map_err(|_| Binding)?;
                Ok(guard)
            },
        )?;
        let view = journal.authority_transition()?;
        view.registration_state(None, clock)?;
        if Instant::now() >= deadline {
            return Err(Binding);
        }
        Ok(Self {
            journal,
            key,
            kid,
            guarded: Some(guarded),
        })
    }

    fn check_commit_deadline(&mut self, deadline: Instant) -> Result<(), admission::Error> {
        if Instant::now() >= deadline {
            self.journal.refuse_transition_readiness()?;
            return Err(admission::Error::Persistence);
        }
        Ok(())
    }
    pub fn public_key(&self) -> &[u8] {
        use ring::signature::KeyPair;
        self.key.public_key().as_ref()
    }
    pub fn instance(&self) -> &str {
        self.journal.instance()
    }
    /// Reads published state without taking whoever holds this issuer.
    pub fn reader(&self) -> admission::JournalReader {
        self.journal.reader()
    }
    /// Makes what this issuer committed visible to its readers. Call it as the action
    /// ends, before the lock around the issuer is released.
    pub fn publish(&self) {
        self.journal.publish();
    }
    /// Trusted installation uses the same exclusive authority journal and epoch.
    /// Keep the issuer alive while borrowing it; this does not expose its key.
    pub fn installation_journal(&mut self) -> &mut admission::Journal {
        &mut self.journal
    }
    pub fn status(&self, id: &str) -> Result<Option<admission::Status>, admission::Error> {
        self.journal.status(id)
    }

    /// Periodic bounded maintenance, without reopening or changing authority epoch.
    pub fn prune(&mut self, clock: Clock) -> Result<(), admission::Error> {
        self.journal.prune(clock)
    }

    /// `permit` and `context` come from the trusted admission handler's binding and
    /// request commitment. All caller-supplied credentials are verified before debit.
    /// Existing admission IDs are status-only, even when their original reply was lost.
    pub fn issue(
        &mut self,
        grant: &str,
        allocations: &[&str],
        permit: Permit,
        trust: &Trust<'_>,
        clock: Clock,
        context: &DispatchContext<'_>,
    ) -> Result<String, IssueError> {
        self.issue_with_preflight(
            IssueCredentials { grant, allocations },
            permit,
            trust,
            clock,
            context,
            |_| Ok(()),
        )
    }

    /// The trusted coordinator checks the complete serialized host envelope before
    /// either quota debit or permit release. It receives only an inert signature
    /// placeholder of the exact encoded length; no usable signature leaves here.
    pub fn issue_with_preflight(
        &mut self,
        credentials: IssueCredentials<'_>,
        permit: Permit,
        trust: &Trust<'_>,
        clock: Clock,
        context: &DispatchContext<'_>,
        preflight: impl FnOnce(&str) -> Result<(), IssueError>,
    ) -> Result<String, IssueError> {
        self.issue_mode(credentials, permit, trust, clock, context, preflight, false)
    }

    /// Only the integrated renewable coordinator uses this entry point. Callers
    /// must fence trusted policy installation and retain one-shot dispatch intent.
    pub fn issue_renewable_with_preflight(
        &mut self,
        credentials: IssueCredentials<'_>,
        permit: Permit,
        trust: &Trust<'_>,
        clock: Clock,
        context: &DispatchContext<'_>,
        preflight: impl FnOnce(&str) -> Result<(), IssueError>,
    ) -> Result<String, IssueError> {
        self.issue_mode(credentials, permit, trust, clock, context, preflight, true)
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_mode(
        &mut self,
        credentials: IssueCredentials<'_>,
        permit: Permit,
        trust: &Trust<'_>,
        clock: Clock,
        context: &DispatchContext<'_>,
        preflight: impl FnOnce(&str) -> Result<(), IssueError>,
        renewable: bool,
    ) -> Result<String, IssueError> {
        if self.guarded.is_some() {
            return Err(admission::Error::Binding.into());
        }
        if permit.limits.execution_mode.is_some() != renewable {
            return Err(VerifyError::Claims.into());
        }
        let header = Header {
            alg: "EdDSA".into(),
            typ: PERMIT_TYPE.into(),
            kid: self.kid.clone(),
            v: 1,
        };
        let head = serde_json::to_vec(&header).map_err(|_| VerifyError::Encoding)?;
        let body = serde_json::to_vec(&permit).map_err(|_| VerifyError::Encoding)?;
        let signed = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(head),
            URL_SAFE_NO_PAD.encode(body)
        );
        let placeholder = format!("{}.{}", signed, URL_SAFE_NO_PAD.encode([0_u8; 64]));
        preflight(&placeholder)?;
        let token = format!(
            "{}.{}",
            signed,
            URL_SAFE_NO_PAD.encode(self.key.sign(signed.as_bytes()).as_ref())
        );
        let bundle = verify_bundle(
            credentials.grant,
            &token,
            credentials.allocations,
            trust,
            clock,
            context,
        )?;
        let instance = self.journal.instance().to_string();
        self.journal.install(&bundle, &instance, clock)?;
        self.journal.reserve(&bundle, clock)?;
        Ok(token)
    }
}
