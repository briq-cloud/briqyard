//! The signing key belongs to the trusted admission service, never the public gateway.
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::signature::Ed25519KeyPair;

/// Holds the authority key and exclusive ledger together. No public method releases a
/// newly signed permit until the complete quota vector and admission are durable.
pub struct DurableIssuer {
    journal: admission::Journal,
    key: Ed25519KeyPair,
    kid: String,
}
#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    #[error(transparent)]
    Verify(#[from] VerifyError),
    #[error(transparent)]
    Journal(#[from] admission::Error),
}
impl DurableIssuer {
    pub fn new(
        journal: admission::Journal,
        key: Ed25519KeyPair,
        kid: String,
    ) -> Result<Self, admission::Error> {
        if !matches!(journal.role(), admission::Role::Authority(_)) {
            return Err(admission::Error::Binding);
        }
        Ok(Self { journal, key, kid })
    }
    pub fn instance(&self) -> &str {
        self.journal.instance()
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
        let token = format!(
            "{}.{}",
            signed,
            URL_SAFE_NO_PAD.encode(self.key.sign(signed.as_bytes()).as_ref())
        );
        let bundle = verify_bundle(grant, &token, allocations, trust, clock, context)?;
        let instance = self.journal.instance().to_string();
        self.journal.install(&bundle, &instance, clock)?;
        self.journal.reserve(&bundle, clock)?;
        Ok(token)
    }
}
