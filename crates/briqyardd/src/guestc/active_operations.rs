//! Exact effect ownership starts before the first guest write. A lease becomes
//! observable only after guest acceptance and the durable active ACK.
use super::{active_lease::ActiveLease, Conn};
use crate::api::execution::context::{AdmissionTurns, RequestIdentity};
use briqyard_api::execution::{
    admission::{ActiveOperation, Journal, PreparedAdmission, Status},
    clock::ClockSample,
    Permit,
};
use std::{
    collections::BTreeMap,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, ReadBuf};

#[derive(Default)]
pub struct ActiveOperations(Mutex<BTreeMap<String, Arc<EffectOwner>>>);

pub(crate) struct OriginalIntent {
    pub request: RequestIdentity,
    pub dispatched: PreparedAdmission,
    pub permit: Permit,
}

pub(crate) struct EffectOwner {
    intent: Option<OriginalIntent>,
    lease: Mutex<Option<ActiveLease>>,
}

impl EffectOwner {
    pub(crate) fn lease(&self) -> Option<ActiveLease> {
        self.lease.lock().unwrap().clone()
    }
}

pub(crate) struct ActiveOperationGuard {
    registry: Arc<ActiveOperations>,
    admission: String,
    owner: Arc<EffectOwner>,
}
impl ActiveOperations {
    pub(crate) fn reserve(
        self: &Arc<Self>,
        admission: &str,
        intent: Option<OriginalIntent>,
    ) -> anyhow::Result<ActiveOperationGuard> {
        anyhow::ensure!(
            intent.as_ref().is_none_or(|i| {
                i.request.execution()
                    && i.dispatched.dispatched
                    && i.dispatched.admission == admission
                    && i.permit.admission == admission
            }),
            "execution intent does not own admission"
        );
        let mut entries = self.0.lock().unwrap();
        anyhow::ensure!(
            entries.len() < 16_384 && !entries.contains_key(admission),
            "active operation already registered or full"
        );
        let owner = Arc::new(EffectOwner {
            intent,
            lease: Mutex::new(None),
        });
        entries.insert(admission.into(), owner.clone());
        Ok(ActiveOperationGuard {
            registry: self.clone(),
            admission: admission.into(),
            owner,
        })
    }

    #[cfg(test)]
    pub(crate) fn register(
        self: &Arc<Self>,
        admission: &str,
        lease: ActiveLease,
    ) -> anyhow::Result<ActiveOperationGuard> {
        let guard = self.reserve(admission, None)?;
        guard.activate(lease)?;
        Ok(guard)
    }

    #[cfg(test)]
    pub(crate) fn get(&self, admission: &str) -> Option<ActiveLease> {
        self.0.lock().unwrap().get(admission)?.lease()
    }

    pub(crate) fn in_context(
        &self,
        admission: &str,
        request: &RequestIdentity,
    ) -> anyhow::Result<Option<Arc<EffectOwner>>> {
        let entries = self.0.lock().unwrap();
        let Some(owner) = entries.get(admission) else {
            return Ok(None);
        };
        anyhow::ensure!(
            owner
                .intent
                .as_ref()
                .is_some_and(|i| i.request.same_context(request)),
            "execution owner context changed"
        );
        Ok(Some(owner.clone()))
    }

    pub(crate) fn revoke_where(
        &self,
        request: Option<&RequestIdentity>,
        mut evidence: impl FnMut(&str) -> Option<ActiveOperation>,
    ) {
        for (admission, owner) in self.0.lock().unwrap().iter() {
            if request.is_some_and(|r| {
                !owner
                    .intent
                    .as_ref()
                    .is_some_and(|i| i.request.same_context(r))
            }) {
                continue;
            }
            if let (Some(lease), Some(record)) = (owner.lease(), evidence(admission)) {
                let _ = lease.revoke_committed(&record);
            }
        }
    }
    pub fn end_all(&self) {
        for owner in self.0.lock().unwrap().values() {
            if let Some(lease) = owner.lease() {
                lease.end();
            }
        }
    }
}

impl ActiveOperationGuard {
    pub(crate) fn activate(&self, lease: ActiveLease) -> anyhow::Result<()> {
        let mut live = self.owner.lease.lock().unwrap();
        anyhow::ensure!(live.is_none(), "execution owner already activated");
        *live = Some(lease);
        Ok(())
    }

    pub(crate) fn finish(
        &self,
        admission: &AdmissionTurns,
        journal: &mut Journal,
        sample: &ClockSample,
    ) -> anyhow::Result<()> {
        let intent = self
            .owner
            .intent
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("original execution intent missing"))?;
        admission
            .terminal(&intent.request, journal)
            .map_err(|_| anyhow::anyhow!("original execution context changed"))?;
        anyhow::ensure!(
            journal.prepared(&self.admission)? == Some(&intent.dispatched)
                && journal.status(&self.admission)? == Some(Status::Consumed),
            "execution journal no longer matches original dispatch"
        );
        if intent.permit.limits.execution_mode.is_some() {
            let evidence = journal
                .active_operation(&self.admission)?
                .ok_or_else(|| anyhow::anyhow!("original lease evidence missing"))?;
            self.owner
                .lease()
                .ok_or_else(|| anyhow::anyhow!("original lease owner missing"))?
                .check_terminal(evidence, sample)?;
        }
        journal.finish(
            &intent.permit,
            sample
                .interval()
                .ok_or_else(|| anyhow::anyhow!("execution clock range"))?,
        )?;
        Ok(())
    }
}

impl Drop for ActiveOperationGuard {
    fn drop(&mut self) {
        let mut entries = self.registry.0.lock().unwrap();
        if let Some(lease) = self.owner.lease() {
            lease.end();
        }
        entries.remove(&self.admission);
    }
}

/// Every renewable output read samples qualified time. The outer live guard also
/// owns an independent timer so a quiet socket cannot conceal expiry or revocation.
pub(crate) struct ActiveConnection {
    pub(crate) conn: Box<dyn Conn>,
    pub(crate) lease: Option<ActiveLease>,
}
impl AsyncRead for ActiveConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(lease) = &self.lease {
            lease.check_io()?;
        }
        Pin::new(&mut self.conn).poll_read(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use briqyard_api::execution::{admission::ActiveOperation, clock::ClockSample};
    use std::time::Duration;
    fn evidence() -> ActiveOperation {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../briqyard-api/tests/fixtures/execution-continuation-v1.json"
        ))
        .unwrap();
        serde_json::from_value(fixture["active"].clone()).unwrap()
    }
    #[tokio::test]
    async fn exact_registry_evidence_is_live_until_owner_exits_and_cannot_reappear_from_status() {
        let evidence = evidence();
        let sample = ClockSample {
            wall: Duration::from_secs(1035),
            monotonic: std::time::Instant::now(),
            uncertainty: Duration::from_secs(1),
        };
        let registry = Arc::new(ActiveOperations::default());
        assert!(registry.get(&evidence.binding.admission).is_none());
        let lease = ActiveLease::from_committed(evidence.clone(), &sample).unwrap();
        let owner = registry
            .register(&evidence.binding.admission, lease.clone())
            .unwrap();
        registry
            .get(&evidence.binding.admission)
            .unwrap()
            .observe(&evidence, &sample)
            .unwrap();
        assert!(registry
            .register(&evidence.binding.admission, lease.clone())
            .is_err());
        let mut crossed = evidence.clone();
        crossed.binding.request_digest.push('x');
        assert!(lease.observe(&crossed, &sample).is_err());
        drop(owner);
        assert!(registry.get(&evidence.binding.admission).is_none());
        assert!(lease.observe(&evidence, &sample).is_err());
    }
    #[tokio::test]
    async fn terminal_owner_remains_distinct_from_abandoned_until_finish_fsync() {
        let evidence = evidence();
        let sample = ClockSample {
            wall: Duration::from_secs(1035),
            monotonic: std::time::Instant::now(),
            uncertainty: Duration::from_secs(1),
        };
        let registry = Arc::new(ActiveOperations::default());
        let lease = ActiveLease::from_committed(evidence.clone(), &sample).unwrap();
        let owner = registry
            .register(&evidence.binding.admission, lease.clone())
            .unwrap();
        lease.end(); // Terminal output observed; manager has not obtained journal yet.
        assert!(registry.get(&evidence.binding.admission).is_some());
        assert!(lease.observe(&evidence, &sample).is_err());
        drop(owner); // Completion persistence or manager cancellation releases ownership.
        assert!(registry.get(&evidence.binding.admission).is_none());
    }

    #[tokio::test]
    async fn retained_revocation_ends_the_exact_live_connection_before_ack() {
        let mut evidence = evidence();
        let sample = ClockSample {
            wall: Duration::from_secs(1035),
            monotonic: std::time::Instant::now(),
            uncertainty: Duration::from_secs(1),
        };
        let registry = Arc::new(ActiveOperations::default());
        let lease = ActiveLease::from_committed(evidence.clone(), &sample).unwrap();
        let _owner = registry
            .register(&evidence.binding.admission, lease.clone())
            .unwrap();
        evidence.phase = briqyard_api::execution::admission::ActivePhase::Revoked;
        registry.revoke_where(None, |id| {
            (id == evidence.binding.admission).then(|| evidence.clone())
        });
        assert!(lease.observe(&evidence, &sample).is_err());
    }
}
