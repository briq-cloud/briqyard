//! Independently authenticated installer policy identity for a renewable grant.
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostOperationPolicy {
    pub host_instance: String,
    pub ownership: String,
    pub ownership_generation: u64,
    pub delegation: String,
    pub delegation_version: u64,
    pub grant_digest: String,
    pub policy_revision: String,
}
impl Journal {
    pub fn install_operation_policy(
        &mut self,
        record: HostOperationPolicy,
        clock: Clock,
    ) -> Result<(), Error> {
        self.check(clock)?;
        let delegation = self
            .state
            .delegations
            .get(&record.delegation)
            .ok_or(Error::Binding)?;
        let owner = self
            .state
            .ownership
            .get(&record.ownership)
            .ok_or(Error::Binding)?;
        if !matches!(self.role(), Role::Host(_))
            || record.host_instance != self.instance()
            || !valid_id(&record.policy_revision)
            || record.ownership_generation != owner.generation
            || delegation.ownership != record.ownership
            || delegation.ownership_generation != record.ownership_generation
            || delegation.version != record.delegation_version
            || delegation.grant_digest != record.grant_digest
            || delegation.expires_at <= clock.now.saturating_add(clock.uncertainty)
            || self
                .state
                .delegation_tombstones
                .contains_key(&record.delegation)
        {
            return Err(Error::Binding);
        }
        if let Some(saved) = self.state.operation_policies.get(&record.grant_digest) {
            return if saved == &record {
                Ok(())
            } else {
                Err(Error::Binding)
            };
        }
        let mut next = self.state.clone();
        next.operation_policies
            .insert(record.grant_digest.clone(), record);
        next.clock_floor = clock.now;
        self.commit(next)
    }
    pub fn operation_policy(
        &self,
        grant_digest: &str,
    ) -> Result<Option<&HostOperationPolicy>, Error> {
        self.ownership()?;
        Ok(self.state.operation_policies.get(grant_digest))
    }
}
