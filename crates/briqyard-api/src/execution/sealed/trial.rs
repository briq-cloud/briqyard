//! The single sealed-trial ABI (ABI 3): the one canary command, its native commitments,
//! the approvals that bind it and the status that proves it ran.
//!
//! The canary is exactly one native `ExecRequest`:
//! `cmd=["/bin/busybox","printf","%s",nonce]`, empty env, cwd and stdin, `timeout_ms=1000`,
//! `wake=false`. Nothing else is expressible: the request type has no free field.

use super::canonical::{h, wire, CodecError, Wire};
use super::objects::{Proc, Q, X};
use super::prim::{EmptyMap, EmptyStr, HexDigest, Ident, LitBool, LitU, Nonce, V4};
use super::sig::{PinnedKey, Sig, SigError, Tag};
use crate::{ExecRequest, ExecResult};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;

/// The fixed request timeout; also the only timeout a trial may be sent with.
pub const TRIAL_TIMEOUT_MS: u64 = 1000;
/// The native commitment's domain, followed by one NUL byte.
const COMMAND_DOMAIN: &[u8] = b"briqyard-exec-request-v1";
/// The origin commitment's domain, followed by one NUL byte.
const ORIGIN_DOMAIN: &[u8] = b"briqyard/trial-origin/v3";

/// `Trial`: the single immutable prospective canary of an operation. Its three UUIDs are
/// distinct one-use identities sampled by B and frozen with R before either approves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trial {
    pub x: X,
    pub plan: HexDigest,
    pub bind_hash: HexDigest,
    pub team: Ident,
    pub key_id: Ident,
    pub stack: Ident,
    pub briq: Ident,
    pub namespace: Ident,
    pub machine: Ident,
    pub grant_id: V4,
    pub delegation_intent: V4,
    pub run: V4,
    pub nonce: Nonce,
    pub command_hash: HexDigest,
    pub gateway_origin_hash: HexDigest,
}

impl Wire for Trial {
    /// Checked on every decode and every signature: the identities are three different
    /// UUIDs (a grant ID is never a delegation intent) and `command_hash` is the native
    /// commitment of exactly this nonce's canary command.
    fn validate(&self) -> Result<(), CodecError> {
        if self.grant_id == self.delegation_intent
            || self.grant_id == self.run
            || self.delegation_intent == self.run
        {
            return Err(CodecError::Value("trial identities"));
        }
        if self.command_hash != command_hash(&self.nonce) {
            return Err(CodecError::Value("trial command hash"));
        }
        Ok(())
    }
}

impl Trial {
    /// `H(Trial)`: the value of every `trial:D` reference except the archived status one.
    pub fn hash(&self) -> Result<HexDigest, CodecError> {
        h(self)
    }

    /// The origin this trial is pinned to, compared byte for byte.
    pub fn check_origin(&self, origin: &Origin) -> Result<(), CodecError> {
        if self.gateway_origin_hash != origin.hash() {
            return Err(CodecError::Value("trial origin"));
        }
        Ok(())
    }
}

/// The ordinary regional gateway origin: `https://` + a lowercase ASCII DNS name. No port,
/// path, trailing dot or slash, userinfo, IP literal or query; never normalized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin(String);

fn valid_origin(text: &str) -> bool {
    let Some(host) = text.strip_prefix("https://") else {
        return false;
    };
    let label = |label: &str| {
        let bytes = label.as_bytes();
        (1..=63).contains(&bytes.len())
            && bytes
                .iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
            && bytes[0] != b'-'
            && bytes[bytes.len() - 1] != b'-'
    };
    let labels: Vec<&str> = host.split('.').collect();
    let numeric_tld = labels[labels.len() - 1].bytes().all(|c| c.is_ascii_digit());
    (1..=253).contains(&host.len()) && labels.iter().all(|l| label(l)) && !numeric_tld
}

impl Origin {
    pub fn new(text: &str) -> Result<Self, CodecError> {
        if !valid_origin(text) {
            return Err(CodecError::Value("gateway origin"));
        }
        Ok(Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `gateway_origin_hash`: hex SHA-256 of the domain, one NUL and the ASCII origin.
    pub fn hash(&self) -> HexDigest {
        let mut bytes = ORIGIN_DOMAIN.to_vec();
        bytes.push(0);
        bytes.extend_from_slice(self.0.as_bytes());
        HexDigest::of(&bytes)
    }
}

fn u(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn s(out: &mut Vec<u8>, value: &str) {
    u(out, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

/// The raw binary preimage of the native request commitment for the canary command:
/// domain, NUL, `u(4) s("/bin/busybox") s("printf") s("%s") s(nonce) u(0) s("") s("") u(1000)`
/// with `u` an 8-byte big-endian integer and `s` a length-prefixed string.
pub fn command_preimage(nonce: &Nonce) -> Vec<u8> {
    let mut bytes = COMMAND_DOMAIN.to_vec();
    bytes.push(0);
    u(&mut bytes, 4);
    for part in CANARY_PREFIX {
        s(&mut bytes, part);
    }
    s(&mut bytes, &nonce.to_text());
    u(&mut bytes, 0);
    s(&mut bytes, "");
    s(&mut bytes, "");
    u(&mut bytes, TRIAL_TIMEOUT_MS);
    bytes
}

/// `Trial.command_hash`: hex SHA-256 of [`command_preimage`]. Never a hash of JSON or argv.
pub fn command_hash(nonce: &Nonce) -> HexDigest {
    HexDigest::of(&command_preimage(nonce))
}

/// The canary `cmd`: three literals and the nonce text. Anything else does not decode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrialCmd(pub Nonce);

const CANARY_PREFIX: [&str; 3] = ["/bin/busybox", "printf", "%s"];

impl Serialize for TrialCmd {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut cmd: Vec<String> = CANARY_PREFIX
            .iter()
            .map(|part| (*part).to_owned())
            .collect();
        cmd.push(self.0.to_text());
        cmd.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TrialCmd {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let cmd = Vec::<String>::deserialize(d)?;
        let [a, b, c, nonce] =
            <[String; 4]>::try_from(cmd).map_err(|_| de::Error::custom("canary argv"))?;
        if [a.as_str(), b.as_str(), c.as_str()] != CANARY_PREFIX {
            return Err(de::Error::custom("canary argv"));
        }
        Nonce::parse(&nonce).map(Self).map_err(de::Error::custom)
    }
}

/// The native `ExecRequest` the canary sends, as a closed type: `timeout_ms` is 1000 and
/// `wake` is false by construction, `env`, `cwd` and `stdin` are present and empty.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialRequest {
    pub cmd: TrialCmd,
    pub cwd: EmptyStr,
    pub env: EmptyMap,
    pub stdin: EmptyStr,
    pub timeout_ms: LitU<1000>,
    pub wake: LitBool<false>,
}

impl TrialRequest {
    pub fn for_nonce(nonce: Nonce) -> Self {
        Self {
            cmd: TrialCmd(nonce),
            cwd: EmptyStr,
            env: EmptyMap,
            stdin: EmptyStr,
            timeout_ms: LitU,
            wake: LitBool,
        }
    }

    /// The actual native request, for the native digest and the native coordinator.
    pub fn to_native(&self) -> ExecRequest {
        ExecRequest {
            cmd: CANARY_PREFIX
                .iter()
                .map(|part| (*part).to_owned())
                .chain([self.cmd.0.to_text()])
                .collect(),
            env: BTreeMap::new(),
            cwd: String::new(),
            stdin: String::new(),
            timeout_ms: TRIAL_TIMEOUT_MS,
            wake: false,
        }
    }

    /// The native `request_digest` (unpadded base64url) of the actual request.
    pub fn native_request_digest(&self) -> Result<String, CodecError> {
        let limits = crate::execution::Limits {
            execution_mode: None,
            max_duration_seconds: 60,
            max_input_bytes: 0,
            max_output_bytes: 0,
            output_mode: None,
        };
        crate::execution::exec_request_digest(&self.to_native(), &limits)
            .map_err(|_| CodecError::Value("canary request"))
    }
}

/// `Pair`: both approvals over the identical Trial.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pair {
    pub receiver: Sig<Trial>,
    pub api: Sig<Trial>,
}

impl Wire for Pair {
    fn validate(&self) -> Result<(), CodecError> {
        if self.receiver.body != self.api.body {
            return Err(CodecError::Value("approvals differ"));
        }
        self.receiver.validate()?;
        self.api.validate()
    }
}

impl Pair {
    /// Verify RA under the pinned Rk and BA under the pinned Bk over the same Trial.
    pub fn verify(&self, rk: &PinnedKey, bk: &PinnedKey) -> Result<&Trial, SigError> {
        let trial = self.receiver.verify(Tag::Trial3Receiver, rk)?;
        let api = self.api.verify(Tag::Trial3Api, bk)?;
        if trial != api {
            return Err(CodecError::Value("approvals differ").into());
        }
        Ok(trial)
    }
}

/// `Issued` body: commitments to the one grant and its projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedBody {
    pub trial: HexDigest,
    pub grant_hash: HexDigest,
    pub projection_hash: HexDigest,
}

/// `Job`: the only fields of B's private request to G.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub approvals: Pair,
    pub issued: Sig<IssuedBody>,
}

impl Wire for Job {
    fn validate(&self) -> Result<(), CodecError> {
        self.approvals.validate()?;
        if self.issued.body.trial != self.approvals.receiver.body.hash()? {
            return Err(CodecError::Value("issued trial"));
        }
        Ok(())
    }
}

impl Job {
    /// Verify both approvals and the issuance under the pinned Rk and Bk. Returns the Trial.
    pub fn verify(&self, rk: &PinnedKey, bk: &PinnedKey) -> Result<&Trial, SigError> {
        let trial = self.approvals.verify(rk, bk)?;
        let issued = self.issued.verify(Tag::Trial3Issued, bk)?;
        if issued.trial != trial.hash()? {
            return Err(CodecError::Value("issued trial").into());
        }
        Ok(trial)
    }
}

/// `C({job, request})`: G→A's body. The request nonce must be the approved Trial's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecBody {
    pub job: Job,
    pub request: TrialRequest,
}

impl Wire for ExecBody {
    fn validate(&self) -> Result<(), CodecError> {
        self.job.validate()?;
        if self.request.cmd.0 != self.job.approvals.receiver.body.nonce {
            return Err(CodecError::Value("request nonce"));
        }
        Ok(())
    }
}

/// `Result`: the only permitted success. `stdout` is the nonce, never a field rebuilt from
/// an expectation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialResult {
    pub stdout: Nonce,
    pub stderr: EmptyStr,
    pub exit_code: LitU<0>,
    pub timed_out: LitBool<false>,
}

impl TrialResult {
    pub fn success(nonce: Nonce) -> Self {
        Self {
            stdout: nonce,
            stderr: EmptyStr,
            exit_code: LitU,
            timed_out: LitBool,
        }
    }

    /// The native result: field order `stdout, stderr, exit_code, timed_out`.
    pub fn to_native(&self) -> ExecResult {
        ExecResult {
            stdout: self.stdout.to_text(),
            stderr: String::new(),
            exit_code: 0,
            timed_out: false,
        }
    }

    /// `outcome`: hex SHA-256 of the native compact `serde_json::to_vec(ExecResult)`, which
    /// is the decoded form of the stored unpadded-base64url result hash.
    pub fn outcome(&self) -> HexDigest {
        let bytes = serde_json::to_vec(&self.to_native()).expect("native result serializes");
        HexDigest::of(&bytes)
    }
}

/// `ExecOK`: A→G and G→B's HTTP 200 body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecOk {
    pub trial: HexDigest,
    pub run: V4,
    pub grant_id: V4,
    pub delegation_intent: V4,
    pub request_hash: HexDigest,
    pub result: TrialResult,
}

impl ExecOk {
    /// Every binding equals the approved Trial and the result is the canary's own success.
    pub fn check(&self, trial: &Trial) -> Result<(), CodecError> {
        if self.trial != trial.hash()?
            || self.run != trial.run
            || self.grant_id != trial.grant_id
            || self.delegation_intent != trial.delegation_intent
            || self.request_hash != trial.command_hash
            || self.result.stdout != trial.nonce
        {
            return Err(CodecError::Value("exec result bindings"));
        }
        Ok(())
    }
}

/// The only phase a trial status admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Finished {
    #[serde(rename = "finished")]
    Finished,
}

/// `Status` body, Ak-signed over a fresh query challenge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusBody {
    pub q: Q,
    pub plan: HexDigest,
    pub trial: HexDigest,
    pub proc: Proc,
    pub bind_hash: HexDigest,
    pub run: V4,
    pub grant_id: V4,
    pub delegation_intent: V4,
    pub request_hash: HexDigest,
    pub grant_hash: HexDigest,
    pub projection_hash: HexDigest,
    pub phase: Finished,
    pub outcome: HexDigest,
}

impl StatusBody {
    /// Compare each separately bound fact with the approved Trial, its issuance and the
    /// actual result, never with another verifier's status.
    pub fn check(
        &self,
        trial: &Trial,
        issued: &IssuedBody,
        result: &TrialResult,
    ) -> Result<(), CodecError> {
        if self.q.x != trial.x
            || self.plan != trial.plan
            || self.trial != trial.hash()?
            || self.bind_hash != trial.bind_hash
            || self.run != trial.run
            || self.grant_id != trial.grant_id
            || self.delegation_intent != trial.delegation_intent
            || self.request_hash != trial.command_hash
            || self.grant_hash != issued.grant_hash
            || self.projection_hash != issued.projection_hash
            || self.outcome != result.outcome()
        {
            return Err(CodecError::Value("status bindings"));
        }
        Ok(())
    }
}

wire!(IssuedBody, StatusBody, TrialResult, ExecOk, TrialRequest);

/// `grant_hash`: hex SHA-256 of the exact ASCII compact grant JWS.
pub fn grant_hash(compact_jws: &str) -> HexDigest {
    HexDigest::of(compact_jws.as_bytes())
}

/// `projection_hash`: hex SHA-256 of the raw opaque projection bytes.
pub fn projection_hash(projection: &[u8]) -> HexDigest {
    HexDigest::of(projection)
}

/// The trial timeout rule, applied after the grant, metadata and projection checks:
/// `room = 1000*exp - nowMs - 1000`, `allowed = min(1000, 60000, 1000*max_duration, room)`
/// in checked signed arithmetic. Only an `allowed` of exactly 1000 may be sent.
pub fn trial_timeout_ms(
    grant_exp: u64,
    max_duration_seconds: u64,
    now_ms: u64,
) -> Result<u64, TimeoutRefused> {
    let room = 1000 * i128::from(grant_exp) - i128::from(now_ms) - 1000;
    let allowed = room
        .min(i128::from(TRIAL_TIMEOUT_MS))
        .min(60_000)
        .min(1000 * i128::from(max_duration_seconds));
    if allowed != i128::from(TRIAL_TIMEOUT_MS) {
        return Err(TimeoutRefused);
    }
    Ok(TRIAL_TIMEOUT_MS)
}

/// The trial is not sent: a shorter timeout is never substituted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("trial timeout would be shorter than 1000 ms")]
pub struct TimeoutRefused;
