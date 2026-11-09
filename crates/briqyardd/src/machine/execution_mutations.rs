//! Short durable fences around publication. No fence mutex survives an await;
//! failed effects retain their ticket until explicit reconciliation can prove them.
use super::*;
use execution_fence::{GenerationSnapshot, MutationMode};
use sha2::{Digest, Sha256};

impl Manager {
    pub(super) fn begin_execution_mutation(
        &self,
        namespaces: &[String],
        mode: MutationMode,
    ) -> Result<execution_fence::MutationTicket> {
        let mut fence = self.inner.execution_fence.lock().unwrap();
        let now = if mode == MutationMode::Invalidate {
            fence.last_observed_ms()
        } else if fence.has_protection() {
            execution_now_ms()?
        } else {
            fence.last_observed_ms()
        };
        fence.begin_mutation(&self.inner.store, namespaces, mode, now)
    }

    pub(super) fn finish_execution_mutation(
        &self,
        ticket: &execution_fence::MutationTicket,
    ) -> Result<()> {
        self.inner
            .execution_fence
            .lock()
            .unwrap()
            .finish_mutation(&self.inner.store, ticket)
    }

    pub(super) async fn execution_mutation<T>(
        &self,
        namespace: &str,
        mode: MutationMode,
        effect: impl std::future::Future<Output = Result<T>>,
    ) -> Result<T> {
        let ticket = self.begin_execution_mutation(&[namespace.to_owned()], mode)?;
        let result = effect.await?;
        self.finish_execution_mutation(&ticket)?;
        Ok(result)
    }

    /// Revocation must remain possible when scoped admission cannot persist its
    /// fence. Poison admission before polling the pure detachment operation.
    pub(super) async fn execution_revocation<T>(
        &self,
        namespace: &str,
        effect: impl std::future::Future<Output = Result<T>>,
    ) -> Result<T> {
        let ticket = match self
            .begin_execution_mutation(&[namespace.to_owned()], MutationMode::Invalidate)
        {
            Ok(ticket) => Some(ticket),
            Err(_) => {
                self.inner.execution_fence.lock().unwrap().poison();
                tracing::warn!("execution revocation fence unavailable; scoped admission disabled");
                None
            }
        };
        let result = effect.await;
        if result.is_ok()
            && ticket
                .as_ref()
                .is_some_and(|ticket| self.finish_execution_mutation(ticket).is_err())
        {
            self.inner.execution_fence.lock().unwrap().poison();
            tracing::warn!("execution revocation fence unresolved; scoped admission disabled");
        }
        result
    }

    /// A host-owned revision for the exact runs and their namespace generations.
    /// Discovery alone establishes no protection and is never dispatch authority.
    pub fn execution_resource_revision(
        &self,
        targets: &[api::execution::Target],
    ) -> Result<String, MError> {
        let snapshot = self.execution_namespace_snapshot(targets)?;
        execution_resource_revision(targets, &snapshot).map_err(MError::from)
    }

    pub(super) fn execution_namespace_snapshot(
        &self,
        targets: &[api::execution::Target],
    ) -> Result<GenerationSnapshot, MError> {
        if targets.is_empty()
            || targets.len() > api::execution::MAX_RESOURCES
            || targets
                .iter()
                .any(|target| target.host != self.inner.host_id)
        {
            return Err(invalid("execution resources require a bounded local set"));
        }
        let mut namespaces = targets
            .iter()
            .map(|target| target.namespace.clone())
            .collect::<Vec<_>>();
        namespaces.sort();
        namespaces.dedup();
        self.inner
            .execution_fence
            .lock()
            .unwrap()
            .snapshot(&self.inner.store, &namespaces, execution_now_ms()?)
            .map_err(|_| MError::Conflict("execution namespace mutation unresolved".into()))
    }
}

pub(super) fn execution_resource_revision(
    targets: &[api::execution::Target],
    snapshot: &GenerationSnapshot,
) -> Result<String> {
    let mut targets = targets.iter().collect::<Vec<_>>();
    targets.sort_by(|a, b| (&a.host, &a.machine).cmp(&(&b.host, &b.machine)));
    anyhow::ensure!(
        targets
            .windows(2)
            .all(|pair| (&pair[0].host, &pair[0].machine) != (&pair[1].host, &pair[1].machine)),
        "duplicate execution resource"
    );
    // The domain and tuple order are versioned. Both structures serialize without
    // unordered maps; supplied resource order cannot change the revision.
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&(
        "briqyard-execution-resource-set-v1",
        snapshot,
        targets,
    ))?)))
}

pub(super) fn execution_now_ms() -> Result<u64> {
    api::execution::clock::ClockSample::read()
        .and_then(|sample| sample.lower_ms())
        .context("qualified execution clock unavailable")
}
