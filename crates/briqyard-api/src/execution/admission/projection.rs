//! Immutable application bytes installed with a delegation. The runtime never
//! interprets their contents; the authenticated caller owns their schema.
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};

pub const MAX_PROJECTION_BYTES: usize = 4096;

#[derive(Clone, Serialize, PartialEq, Eq, Deserialize)]
#[serde(try_from = "ProjectionWire")]
pub struct Projection {
    version: u8,
    bytes: Vec<u8>,
    digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectionWire {
    version: u8,
    bytes: Vec<u8>,
    digest: String,
}

impl std::fmt::Debug for Projection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Projection")
            .field("version", &self.version)
            .field("length", &self.bytes.len())
            .field("digest", &self.digest)
            .finish()
    }
}

impl Projection {
    pub fn new(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > MAX_PROJECTION_BYTES {
            return Err(Error::Binding);
        }
        Ok(Self {
            version: 1,
            digest: URL_SAFE_NO_PAD.encode(Sha256::digest(&bytes)),
            bytes,
        })
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

impl TryFrom<ProjectionWire> for Projection {
    type Error = Error;
    fn try_from(wire: ProjectionWire) -> Result<Self, Error> {
        let projection = Self::new(wire.bytes)?;
        if wire.version != 1 || wire.digest != projection.digest {
            return Err(Error::Binding);
        }
        Ok(projection)
    }
}

/// Scoped read evidence. It contains neither signed credentials nor allocations.
#[derive(Clone, Debug, Serialize)]
pub struct ProjectionEvidence {
    pub intent: String,
    pub authority_epoch: String,
    pub delegation: String,
    pub version: u64,
    pub grant_digest: String,
    pub ownership_generation: u64,
    pub projection: Projection,
}

impl Journal {
    /// Possession is rechecked for each read and dispatch. A prior projection read
    /// is never authorization for a later operation.
    pub fn presented_projection(
        &self,
        id: &str,
        grant: &str,
        clock: Clock,
    ) -> Result<ProjectionEvidence, Error> {
        self.check(clock)?;
        let installed = self.delegation_intent(id)?.ok_or(Error::Binding)?;
        let end = clock.now.saturating_add(clock.uncertainty);
        if !self.delegation_intent_ready(id)?
            || installed.expected.grant_digest != token_digest(grant)
            || installed.expected.expires_at <= end
            || !installed
                .trusted_source
                .as_ref()
                .is_some_and(|s| s.expires_at > end)
            || installed.request.protection_expires_at_ms / 1000 <= end
        {
            return Err(Error::Binding);
        }
        Ok(ProjectionEvidence {
            intent: id.into(),
            authority_epoch: self.instance().into(),
            delegation: installed.request.id.clone(),
            version: installed.request.version,
            grant_digest: installed.expected.grant_digest.clone(),
            ownership_generation: installed.request.generation,
            projection: installed.projection.clone().ok_or(Error::Binding)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_is_bounded_and_recovery_verifies_its_digest() {
        assert!(Projection::new(vec![]).is_err());
        assert!(Projection::new(vec![0; MAX_PROJECTION_BYTES + 1]).is_err());
        let projection = Projection::new(vec![42; MAX_PROJECTION_BYTES]).unwrap();
        let mut wire = serde_json::to_value(&projection).unwrap();
        assert_eq!(
            serde_json::from_value::<Projection>(wire.clone()).unwrap(),
            projection
        );
        wire["bytes"][0] = 41.into();
        assert!(serde_json::from_value::<Projection>(wire).is_err());
        let mut wire = serde_json::to_value(&projection).unwrap();
        wire["version"] = 2.into();
        assert!(serde_json::from_value::<Projection>(wire).is_err());
        assert!(!format!("{projection:?}").contains("42, 42"));
    }
}
