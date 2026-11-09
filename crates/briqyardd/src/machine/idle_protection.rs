//! Durable idle protection for accepted execution admissions. The receipt is the
//! authority; the per-machine maximum is rebuilt before startup can run a tick.
use super::*;
use crate::store::InspectionBudget;
use briqyard_api::execution::{self, Target};

const KIND: &str = "execution-idle-protection";
// Store::inspect admits at most 4096 directory entries, including stray files.
const MAX_RECEIPTS: usize = 4_096;
const MAX_TOTAL_BYTES: usize = 32 * 1024 * 1024;
const CLOCK_SKEW_MS: u64 = 5_000;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Receipt {
    admission: String,
    targets: Vec<Target>,
    expires_at_ms: u64,
}

#[derive(Default)]
pub(super) struct Protection {
    receipts: BTreeMap<String, Receipt>,
    ends: HashMap<String, u64>,
    bytes: usize,
    poisoned: bool,
}

impl Protection {
    pub(super) fn load(store: &Store) -> Result<Self> {
        let mut budget =
            InspectionBudget::new(tokio::time::Instant::now() + Duration::from_secs(10));
        let receipts = store.inspect::<Receipt>(KIND, &mut budget)?;
        anyhow::ensure!(
            receipts.len() <= MAX_RECEIPTS,
            "execution idle protection capacity"
        );
        let mut result = Self {
            receipts,
            ends: HashMap::new(),
            bytes: 0,
            poisoned: false,
        };
        for (key, receipt) in &result.receipts {
            result.bytes = result
                .bytes
                .checked_add(serde_json::to_vec_pretty(receipt)?.len())
                .context("execution idle protection byte capacity")?;
            anyhow::ensure!(
                key == &receipt.admission
                    && safe_id(key)
                    && !receipt.targets.is_empty()
                    && receipt.targets.len() <= execution::MAX_RESOURCES
                    && receipt.expires_at_ms > 0
                    && i64::try_from(receipt.expires_at_ms)
                        .ok()
                        .and_then(DateTime::from_timestamp_millis)
                        .is_some(),
                "invalid execution idle protection receipt"
            );
            let mut names = std::collections::HashSet::new();
            for target in &receipt.targets {
                anyhow::ensure!(
                    safe_id(&target.machine) && names.insert(&target.machine),
                    "invalid execution idle protection target"
                );
                result
                    .ends
                    .entry(target.machine.clone())
                    .and_modify(|end| *end = (*end).max(receipt.expires_at_ms))
                    .or_insert(receipt.expires_at_ms);
            }
        }
        anyhow::ensure!(
            result.bytes <= MAX_TOTAL_BYTES,
            "execution idle protection byte capacity"
        );
        Ok(result)
    }

    pub(super) fn accept(
        &mut self,
        store: &Store,
        admission: &str,
        targets: &[Target],
        expires_at_ms: u64,
    ) -> Result<()> {
        anyhow::ensure!(
            !self.poisoned,
            "execution idle protection persistence unresolved"
        );
        anyhow::ensure!(
            safe_id(admission) && !targets.is_empty() && targets.len() <= execution::MAX_RESOURCES,
            "invalid execution idle protection request"
        );
        anyhow::ensure!(
            i64::try_from(expires_at_ms)
                .ok()
                .and_then(DateTime::from_timestamp_millis)
                .is_some(),
            "invalid execution idle protection deadline"
        );
        let receipt = Receipt {
            admission: admission.into(),
            targets: targets.to_vec(),
            expires_at_ms,
        };
        if let Some(old) = self.receipts.get(admission) {
            anyhow::ensure!(
                old == &receipt,
                "execution idle protection receipt collision"
            );
            return Ok(());
        }
        anyhow::ensure!(
            self.receipts.len() < MAX_RECEIPTS,
            "execution idle protection capacity"
        );
        let bytes = serde_json::to_vec_pretty(&receipt)?;
        anyhow::ensure!(
            bytes.len() <= 64 * 1024,
            "execution idle protection receipt size"
        );
        anyhow::ensure!(
            self.bytes
                .checked_add(bytes.len())
                .is_some_and(|total| total <= MAX_TOTAL_BYTES),
            "execution idle protection byte capacity"
        );
        // One atomic durable record covers every target. An uncertain write never
        // acknowledges admission; reopening reconstructs any completed rename.
        if let Err(err) = store.put_durable(KIND, admission, &receipt) {
            self.poisoned = true;
            return Err(err);
        }
        for target in targets {
            self.ends
                .entry(target.machine.clone())
                .and_modify(|end| *end = (*end).max(expires_at_ms))
                .or_insert(expires_at_ms);
        }
        self.receipts.insert(admission.into(), receipt);
        self.bytes += bytes.len();
        Ok(())
    }

    fn end(&self, machine: &str) -> Option<DateTime<Utc>> {
        self.ends
            .get(machine)
            .and_then(|ms| DateTime::from_timestamp_millis((*ms).try_into().ok()?))
    }
}

fn safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

impl Manager {
    pub(super) fn protected_sleeps_at(&self, r: &Record) -> Option<DateTime<Utc>> {
        let protection = self.inner.idle_protection.lock().unwrap();
        if protection.poisoned {
            return None;
        }
        let end = protection.end(&r.id);
        let at = sleeps_at(bounded_last_use(r.last_used_at, end), r.sleep_window())?;
        if end.is_some() {
            at.checked_add_signed(chrono::TimeDelta::milliseconds(CLOCK_SKEW_MS as i64))
        } else {
            Some(at)
        }
    }

    /// Idle use is a bound, not a new observation. Keep Record.last_used_at and
    /// its version untouched by protection installation.
    pub(super) fn idle_due(&self, r: &Record, now: DateTime<Utc>) -> bool {
        let protection = self.inner.idle_protection.lock().unwrap();
        if protection.poisoned {
            return false;
        }
        let end = protection.end(&r.id);
        let last = bounded_last_use(r.last_used_at, end);
        // The lower bound on wall time must have passed the protected deadline.
        let lower = if end.is_some() {
            now - chrono::TimeDelta::milliseconds(CLOCK_SKEW_MS as i64)
        } else {
            now
        };
        idle_past(last, r.sleep_window(), lower)
    }

    pub(super) fn idle_stop_allowed(&self, r: &Record, now: DateTime<Utc>) -> bool {
        if !r.is_gateway() {
            return self.idle_due(r, now);
        }
        let protection = self.inner.idle_protection.lock().unwrap();
        if protection.poisoned {
            return false;
        }
        protection.end(&r.id).is_none_or(|deadline| {
            now - chrono::TimeDelta::milliseconds(CLOCK_SKEW_MS as i64) > deadline
        })
    }
}

fn bounded_last_use(
    actual: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
) -> Option<DateTime<Utc>> {
    match (actual, end) {
        (Some(actual), Some(bound)) => Some(actual.max(bound)),
        (actual, bound) => actual.or(bound),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target {
            host: "h_test".into(),
            machine: "m_test".into(),
            namespace: "n_test".into(),
            run: "r_test".into(),
            placement: "p_test".into(),
        }
    }

    #[test]
    fn exact_receipt_is_idempotent_and_rebuilds_the_maximum() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let mut protection = Protection::load(&store).unwrap();
        let end = (Utc::now().timestamp() as u64 + 30) * 1000;
        protection
            .accept(&store, "a_one", &[target()], end)
            .unwrap();
        protection
            .accept(&store, "a_one", &[target()], end)
            .unwrap();
        assert!(protection
            .accept(&store, "a_one", &[target()], end + 1000)
            .is_err());
        let mut changed = target();
        changed.run = "other_run".into();
        assert!(protection.accept(&store, "a_one", &[changed], end).is_err());
        protection
            .accept(&store, "a_two", &[target()], end + 1000)
            .unwrap();
        let restored = Protection::load(&store).unwrap();
        assert_eq!(restored.receipts.len(), 2);
        assert_eq!(restored.ends["m_test"], end + 1000);
    }

    #[test]
    fn uncertain_write_poison_blocks_new_receipts() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let mut protection = Protection::load(&store).unwrap();
        std::fs::remove_dir(store.dir(KIND)).unwrap();
        std::fs::write(store.dir(KIND), b"unavailable").unwrap();
        let end = (Utc::now().timestamp() as u64 + 30) * 1000;
        assert!(protection
            .accept(&store, "a_one", &[target()], end)
            .is_err());
        assert!(protection.poisoned);
        assert!(protection
            .accept(&store, "a_two", &[target()], end)
            .is_err());
        assert!(protection.receipts.is_empty());
    }

    #[test]
    fn aggregate_startup_budget_refuses_before_ack() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let mut protection = Protection::load(&store).unwrap();
        let end = (Utc::now().timestamp() as u64 + 30) * 1000;
        let receipt = Receipt {
            admission: "a_one".into(),
            targets: vec![target()],
            expires_at_ms: end,
        };
        let size = serde_json::to_vec_pretty(&receipt).unwrap().len();
        protection.bytes = MAX_TOTAL_BYTES - size + 1;
        assert!(protection
            .accept(&store, "a_one", &[target()], end)
            .is_err());
        assert!(!store.dir(KIND).join("a_one.json").exists());
    }
}
