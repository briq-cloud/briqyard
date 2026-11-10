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
        if !matches!(journal.role(), admission::Role::Authority(_)) {
            return Err(admission::Error::Binding);
        }
        Ok(Self { journal, key, kid })
    }
    pub fn public_key(&self) -> &[u8] {
        use ring::signature::KeyPair;
        self.key.public_key().as_ref()
    }
    pub fn instance(&self) -> &str {
        self.journal.instance()
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
        // The continuation primitives do not activate the dispatch path.
        if permit.limits.execution_mode.is_some() {
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
