//! Private control envelopes: client stage/query/enable, the trial3 control messages
//! (offer, issue reply, observe, archive) around the unchanged trial ABI.

use super::common::{expect_tag, refuse};
use super::evidence::check_bind;
use crate::execution::sealed::canonical::{h, CodecError, Wire};
use crate::execution::sealed::objects::{Bind, Members, Proc, Q, X};
use crate::execution::sealed::prim::{HexDigest, Nonce};
use crate::execution::sealed::sig::{PinnedKey, Sig, SigError, Tag};
use crate::execution::sealed::trial::{ExecOk, IssuedBody, Pair, StatusBody, Trial};
use serde::{Deserialize, Serialize};

/// The client roles whose immutable client holder a replica stages: API installers and the
/// regional gateway.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClientRole {
    #[serde(rename = "ni")]
    Ni,
    #[serde(rename = "ng")]
    Ng,
}

/// `client.stage` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientStageBody {
    pub x: X,
    pub plan: HexDigest,
    pub proc: Proc,
    pub role: ClientRole,
    pub bind: Bind,
    pub member: HexDigest,
    pub nonce: Nonce,
}

impl Wire for ClientStageBody {
    fn validate(&self) -> Result<(), CodecError> {
        check_bind(&self.bind)?;
        if self.x != self.bind.x || self.plan != self.bind.plan {
            return refuse("client stage scope");
        }
        Ok(())
    }
}

impl ClientStageBody {
    /// The member digest is the role's in the new set the Bind pins.
    pub fn check_members(&self, new: &Members) -> Result<(), CodecError> {
        let expected = match self.role {
            ClientRole::Ni => &new.ni,
            ClientRole::Ng => &new.ng,
        };
        if self.bind.set != new.set()? || self.member != *expected {
            return refuse("client stage member");
        }
        Ok(())
    }
}

/// `client.query` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientQueryBody {
    pub q: Q,
    pub plan: HexDigest,
    pub role: ClientRole,
    pub proc: Proc,
}

impl Wire for ClientQueryBody {}

/// The replica's reported mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClientMode {
    #[serde(rename = "verification")]
    Verification,
    #[serde(rename = "normal")]
    Normal,
}

/// The canonical (unsigned) response of a replica, authenticated by its pinned mTLS peer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientState {
    pub q: Q,
    pub plan: HexDigest,
    pub role: ClientRole,
    pub proc: Proc,
    pub bind: Bind,
    pub member: HexDigest,
    pub mode: ClientMode,
}

impl Wire for ClientState {
    /// The response is for the Bind's operation and plan.
    fn validate(&self) -> Result<(), CodecError> {
        check_bind(&self.bind)?;
        if self.q.x != self.bind.x || self.bind.plan != self.plan {
            return refuse("client state scope");
        }
        Ok(())
    }
}

impl ClientState {
    /// It answers exactly this query, from the staged slot of this stage request, and the query
    /// is for the staged operation and plan.
    pub fn check(
        &self,
        query: &ClientQueryBody,
        stage: &ClientStageBody,
    ) -> Result<(), CodecError> {
        if query.q.x != stage.x
            || query.plan != stage.plan
            || self.q != query.q
            || self.plan != query.plan
            || self.role != query.role
            || self.proc != query.proc
            || self.role != stage.role
            || self.proc != stage.proc
            || self.bind != stage.bind
            || self.member != stage.member
        {
            return refuse("client state");
        }
        Ok(())
    }
}

/// `client.enable` body; `trial` is `H(Trial)`, never the status hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientEnableBody {
    pub x: X,
    pub plan: HexDigest,
    pub role: ClientRole,
    pub proc: Proc,
    pub bind: Bind,
    pub trial: HexDigest,
    pub nonce: Nonce,
}

impl Wire for ClientEnableBody {
    fn validate(&self) -> Result<(), CodecError> {
        check_bind(&self.bind)?;
        if self.x != self.bind.x || self.plan != self.bind.plan {
            return refuse("client enable scope");
        }
        Ok(())
    }
}

impl ClientEnableBody {
    /// The trial is the one enabled, and it pins this exact Bind: `trial.bind_hash = H(bind)`.
    pub fn check_trial(&self, trial: &Trial) -> Result<(), CodecError> {
        if self.trial != trial.hash()?
            || self.bind.x != trial.x
            || self.plan != trial.plan
            || trial.bind_hash != h(&self.bind)?
        {
            return refuse("client enable trial");
        }
        Ok(())
    }
}

/// `trial3.offer.query` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferQueryBody {
    pub q: Q,
    pub plan: HexDigest,
    pub bind_hash: HexDigest,
}

impl Wire for OfferQueryBody {}

/// `trial3.offer` body: B's single immutable prospective trial. It grants nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferBody {
    pub q: Q,
    pub trial: Trial,
}

impl Wire for OfferBody {
    fn validate(&self) -> Result<(), CodecError> {
        self.trial.validate()?;
        if self.trial.x != self.q.x {
            return refuse("offer scope");
        }
        Ok(())
    }
}

impl OfferBody {
    /// It answers this query and offers a trial for the plan and Bind it named.
    pub fn check_query(&self, query: &OfferQueryBody) -> Result<(), CodecError> {
        if self.q != query.q
            || self.trial.plan != query.plan
            || self.trial.bind_hash != query.bind_hash
        {
            return refuse("offer query");
        }
        Ok(())
    }
}

/// `trial3.observe` and `trial3.archive` bodies share one shape: a fresh query and
/// `trial = H(Trial)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialQueryBody {
    pub q: Q,
    pub plan: HexDigest,
    pub trial: HexDigest,
}

impl Wire for TrialQueryBody {}

/// `trial3.archive.reply` body: R's read nonce outside, B's historical Ak-signed status
/// nested unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveReplyBody {
    pub q: Q,
    pub plan: HexDigest,
    pub trial: HexDigest,
    pub status: Sig<StatusBody>,
}

impl Wire for ArchiveReplyBody {
    /// The nested status is for this trial, operation and plan. Its nonce is B's, never R's.
    fn validate(&self) -> Result<(), CodecError> {
        expect_tag(&self.status, Tag::Trial3Status)?;
        self.status.validate()?;
        let inner = &self.status.body;
        if inner.trial != self.trial || inner.q.x != self.q.x || inner.plan != self.plan {
            return refuse("archive status");
        }
        Ok(())
    }
}

impl ArchiveReplyBody {
    /// It answers exactly this archive query.
    pub fn check_query(&self, query: &TrialQueryBody) -> Result<(), CodecError> {
        if self.q != query.q || self.plan != query.plan || self.trial != query.trial {
            return refuse("archive query");
        }
        Ok(())
    }

    /// The archived status commitment: `H` of the complete nested B-challenged envelope.
    pub fn archived_status_hash(&self) -> Result<HexDigest, CodecError> {
        h(&self.status)
    }

    /// Verify the nested status under Ak (not the outer envelope; the caller checks that
    /// under Bk).
    pub fn verify_status(&self, ak: &PinnedKey) -> Result<(), SigError> {
        self.status.verify(Tag::Trial3Status, ak).map(|_| ())
    }
}

/// The 200 body B returns to R for `P3/issue`: both approvals, the issuance and the one
/// verified execution. Never the raw grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialReply {
    pub approvals: Pair,
    pub issued: Sig<IssuedBody>,
    pub execution: ExecOk,
}

impl Wire for TrialReply {
    fn validate(&self) -> Result<(), CodecError> {
        expect_tag(&self.approvals.receiver, Tag::Trial3Receiver)?;
        expect_tag(&self.approvals.api, Tag::Trial3Api)?;
        expect_tag(&self.issued, Tag::Trial3Issued)?;
        self.approvals.validate()?;
        let trial = &self.approvals.receiver.body;
        if self.issued.body.trial != trial.hash()? {
            return refuse("trial reply issued");
        }
        self.execution.check(trial)
    }
}
