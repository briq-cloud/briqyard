//! Exact live operation ownership. Entries exist only after guest acceptance and
//! durable active ACK, and disappear on every manager-future exit, including cancel.
use super::{active_lease::ActiveLease, Conn};
use std::{
    collections::BTreeMap,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
pub struct ActiveOperations(Mutex<BTreeMap<String, ActiveLease>>);
pub struct ActiveOperationGuard {
    registry: Arc<ActiveOperations>,
    admission: String,
    lease: ActiveLease,
}
impl ActiveOperations {
    pub fn register(
        self: &Arc<Self>,
        admission: &str,
        lease: ActiveLease,
    ) -> anyhow::Result<ActiveOperationGuard> {
        let mut entries = self.0.lock().unwrap();
        anyhow::ensure!(
            entries.len() < 16_384 && !entries.contains_key(admission),
            "active operation already registered or full"
        );
        entries.insert(admission.into(), lease.clone());
        Ok(ActiveOperationGuard {
            registry: self.clone(),
            admission: admission.into(),
            lease,
        })
    }
    pub fn get(&self, admission: &str) -> Option<ActiveLease> {
        self.0.lock().unwrap().get(admission).cloned()
    }
    pub fn revoke_where(
        &self,
        mut evidence: impl FnMut(&str) -> Option<briqyard_api::execution::admission::ActiveOperation>,
    ) {
        for (admission, lease) in self.0.lock().unwrap().iter() {
            if let Some(record) = evidence(admission) {
                if record.phase == briqyard_api::execution::admission::ActivePhase::Revoked {
                    lease.end();
                }
            }
        }
    }
    pub fn end_all(&self) {
        for lease in self.0.lock().unwrap().values() {
            lease.end();
        }
    }
}
impl Drop for ActiveOperationGuard {
    fn drop(&mut self) {
        self.lease.end();
        self.registry.0.lock().unwrap().remove(&self.admission);
    }
}

/// Every actual read/write poll samples qualified time. The outer live guard also
/// owns an independent timer so a quiet socket cannot conceal expiry or revocation.
pub struct ActiveConnection {
    pub conn: Box<dyn Conn>,
    pub lease: ActiveLease,
}
impl AsyncRead for ActiveConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.lease.check_io()?;
        Pin::new(&mut self.conn).poll_read(cx, buf)
    }
}
impl AsyncWrite for ActiveConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.lease.check_io()?;
        Pin::new(&mut self.conn).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.lease.check_io()?;
        Pin::new(&mut self.conn).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.lease.check_io()?;
        Pin::new(&mut self.conn).poll_shutdown(cx)
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
        registry.revoke_where(|id| (id == evidence.binding.admission).then(|| evidence.clone()));
        assert!(lease.observe(&evidence, &sample).is_err());
    }
}
