//! Durable namespace generations and command-deadline mutation exclusion.
//!
//! This state is host owned, independent of namespace and machine records. A pending
//! mutation is evidence of an uncertain effect after a crash, never work to replay.
use super::*;
use crate::store::InspectionBudget;

const KIND: &str = "execution-namespace-fence";
const KEY: &str = "state";
const MAX_NAMESPACES: usize = 16_384;
const MAX_PENDING: usize = 4_096;
const MAX_BYTES: usize = 4 * 1024 * 1024;
const CLOCK_UNCERTAINTY_MS: u64 = 5_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GenerationSnapshot(pub Vec<(String, u64)>);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum MutationMode {
    /// Changes membership, policy, routing or other reachable resources.
    Broaden,
    /// Explicit stop/removal may end a command, but cannot widen its resources.
    Invalidate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MutationTicket {
    pub id: String,
    pub generations: GenerationSnapshot,
    pub mode: MutationMode,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    generations: BTreeMap<String, u64>,
    protected_until_ms: BTreeMap<String, u64>,
    pending: BTreeMap<String, MutationTicket>,
    max_observed_ms: u64,
}

pub(super) struct ExecutionFence {
    record: Record,
    poisoned: bool,
}

impl ExecutionFence {
    /// Reconstruction has no witness that its rules equal the protected topology.
    /// Preserve the existing kernel state until every retained deadline has drained.
    pub(super) fn has_protection(&self) -> bool {
        !self.record.protected_until_ms.is_empty()
    }
    pub(super) fn last_observed_ms(&self) -> u64 {
        self.record.max_observed_ms.max(1)
    }
    pub(super) async fn drain_at_start(&self, runtime_millis: u64) -> Result<()> {
        if !self.has_protection() && runtime_millis == 0 {
            return Ok(());
        }
        // Retained receipts distinguish the 60s legacy bound from the 80s
        // renewable envelope. Never trust a wall step to shorten either drain.
        // A wall forward step cannot shorten this retained command lifetime.
        tokio::time::sleep(Duration::from_millis(
            runtime_millis.max(api::execution::MAX_COMMAND_SECONDS * 1000),
        ))
        .await;
        let delay = self.startup_delay(execution_mutations::execution_now_ms()?)?;
        if !delay.is_zero() {
            tracing::info!(
                delay_ms = delay.as_millis() as u64,
                "waiting for execution protection before recovery"
            );
            tokio::time::sleep(delay).await;
        }
        anyhow::ensure!(
            self.startup_delay(execution_mutations::execution_now_ms()?)?
                .is_zero(),
            "execution protection deadline has not drained"
        );
        Ok(())
    }

    fn startup_delay(&self, now_ms: u64) -> Result<Duration> {
        self.check_clock(now_ms)?;
        let Some(deadline) = self.record.protected_until_ms.values().max() else {
            return Ok(Duration::ZERO);
        };
        let released_at = deadline
            .checked_add(CLOCK_UNCERTAINTY_MS)
            .and_then(|end| end.checked_add(1))
            .context("execution protection deadline exceeds clock range")?;
        Ok(Duration::from_millis(released_at.saturating_sub(now_ms)))
    }

    pub(super) fn load(store: &Store) -> Result<Self> {
        let dir = store.dir(KIND);
        let mut removed = false;
        for entry in
            std::fs::read_dir(&dir).with_context(|| format!("inspect {}", dir.display()))?
        {
            let entry = entry?;
            let regular = entry.file_type()?.is_file();
            if entry.file_name() == "state.json.tmp" && regular {
                // `write_private` renames the temp file over `state.json`: the rename
                // is the commit, so a leftover temp file is a write that never
                // committed. Drop it; it is never read as the record.
                std::fs::remove_file(entry.path())
                    .with_context(|| format!("remove {}", entry.path().display()))?;
                removed = true;
                continue;
            }
            anyhow::ensure!(
                entry.file_name() == "state.json" && regular,
                "unexpected execution namespace fence file"
            );
        }
        if removed {
            store.sync_dir(KIND)?;
        }
        let records = store.inspect::<Record>(
            KIND,
            &mut InspectionBudget::new(tokio::time::Instant::now() + Duration::from_secs(10)),
        )?;
        anyhow::ensure!(records.len() <= 1, "execution namespace fence record count");
        let record = records.into_values().next().unwrap_or_default();
        validate(&record)?;
        Ok(Self {
            record,
            poisoned: false,
        })
    }

    /// Seed never-before-seen names durably. A later deletion cannot reset a name's generation.
    pub(super) fn snapshot(
        &mut self,
        store: &Store,
        namespaces: &[String],
        now_ms: u64,
    ) -> Result<GenerationSnapshot> {
        self.check_clock(now_ms)?;
        check_names(namespaces)?;
        self.ensure_clear(namespaces)?;
        let mut next = self.record.clone();
        let mut changed = false;
        for name in namespaces {
            if !next.generations.contains_key(name) {
                next.generations.insert(name.clone(), 0);
                changed = true;
            }
        }
        if changed {
            next.max_observed_ms = next.max_observed_ms.max(now_ms);
            self.commit(store, next)?;
        }
        Ok(self.current(namespaces))
    }

    /// Persist protection of the exact previously observed generations in one write.
    pub(super) fn protect(
        &mut self,
        store: &Store,
        expected: &GenerationSnapshot,
        deadline_ms: u64,
        now_ms: u64,
    ) -> Result<()> {
        self.check_clock(now_ms)?;
        let names = names_of(expected)?;
        self.ensure_clear(&names)?;
        anyhow::ensure!(
            names
                .iter()
                .all(|name| self.record.generations.contains_key(name)),
            "unknown namespace generation"
        );
        anyhow::ensure!(
            self.current(&names) == *expected,
            "namespace generation changed"
        );
        anyhow::ensure!(
            deadline_ms > now_ms
                && deadline_ms - now_ms <= api::execution::MAX_COMMAND_SECONDS * 1000,
            "invalid namespace protection deadline"
        );
        let mut next = self.record.clone();
        for name in names {
            next.protected_until_ms
                .entry(name)
                .and_modify(|end| *end = (*end).max(deadline_ms))
                .or_insert(deadline_ms);
        }
        next.max_observed_ms = next.max_observed_ms.max(now_ms);
        self.commit(store, next)
    }

    /// Reserve named mutations before any lifecycle effect begins. Names first seen by
    /// an ordinary mutation stay untracked until an explicit snapshot discovers them.
    pub(super) fn begin_mutation(
        &mut self,
        store: &Store,
        namespaces: &[String],
        mode: MutationMode,
        now_ms: u64,
    ) -> Result<MutationTicket> {
        self.check_clock(now_ms)?;
        check_names(namespaces)?;
        anyhow::ensure!(
            self.record.pending.len() < MAX_PENDING,
            "namespace mutation capacity"
        );
        if mode == MutationMode::Broaden {
            for name in namespaces {
                anyhow::ensure!(
                    self.record
                        .protected_until_ms
                        .get(name)
                        .is_none_or(|end| now_ms.saturating_sub(CLOCK_UNCERTAINTY_MS) > *end),
                    "namespace protected through command deadline"
                );
            }
        }
        let mut next = self.record.clone();
        let mut generations = Vec::with_capacity(namespaces.len());
        for name in namespaces {
            let generation = if let Some(current) = next.generations.get_mut(name) {
                *current = current
                    .checked_add(1)
                    .context("namespace generation exhausted")?;
                *current
            } else {
                // Pending tickets still fence discovery, including after restart.
                0
            };
            generations.push((name.clone(), generation));
        }
        let ticket = MutationTicket {
            id: hex::encode(rand::random::<[u8; 16]>()),
            generations: GenerationSnapshot(generations),
            mode,
        };
        anyhow::ensure!(
            !next.pending.contains_key(&ticket.id),
            "namespace mutation ticket collision"
        );
        next.pending.insert(ticket.id.clone(), ticket.clone());
        next.max_observed_ms = next.max_observed_ms.max(now_ms);
        self.commit(store, next)?;
        Ok(ticket)
    }

    /// Only the holder of the exact ticket may retire the pending evidence.
    pub(super) fn finish_mutation(&mut self, store: &Store, ticket: &MutationTicket) -> Result<()> {
        anyhow::ensure!(!self.poisoned, "namespace fence persistence unresolved");
        anyhow::ensure!(
            self.record.pending.get(&ticket.id) == Some(ticket),
            "namespace mutation ticket changed"
        );
        let mut next = self.record.clone();
        next.pending.remove(&ticket.id);
        self.commit(store, next)
    }

    /// Retain a fail-closed in-memory state after another uncertain boundary.
    pub(super) fn poison(&mut self) {
        self.poisoned = true;
    }

    pub(super) fn matches_snapshot(
        &self,
        expected: &GenerationSnapshot,
        now_ms: u64,
    ) -> Result<bool> {
        self.check_clock(now_ms)?;
        let names = names_of(expected)?;
        Ok(self.ensure_clear(&names).is_ok()
            && names
                .iter()
                .all(|name| self.record.generations.contains_key(name))
            && self.current(&names) == *expected)
    }

    pub(super) fn check_protected(
        &self,
        expected: &GenerationSnapshot,
        deadline_ms: u64,
        now_ms: u64,
    ) -> Result<bool> {
        let names = names_of(expected)?;
        Ok(self.matches_snapshot(expected, now_ms)?
            && names.iter().all(|name| {
                self.record.generations.contains_key(name)
                    && self
                        .record
                        .protected_until_ms
                        .get(name)
                        .is_some_and(|end| *end >= deadline_ms)
            }))
    }

    fn current(&self, names: &[String]) -> GenerationSnapshot {
        GenerationSnapshot(
            names
                .iter()
                .map(|name| (name.clone(), self.record.generations[name]))
                .collect(),
        )
    }

    fn ensure_clear(&self, names: &[String]) -> Result<()> {
        anyhow::ensure!(
            self.record.pending.values().all(|ticket| ticket
                .generations
                .0
                .iter()
                .all(|(name, _)| !names.contains(name))),
            "namespace mutation pending"
        );
        Ok(())
    }

    fn check_clock(&self, now_ms: u64) -> Result<()> {
        anyhow::ensure!(!self.poisoned, "namespace fence persistence unresolved");
        anyhow::ensure!(
            now_ms > 0
                && now_ms.saturating_add(CLOCK_UNCERTAINTY_MS) >= self.record.max_observed_ms,
            "namespace fence clock rollback"
        );
        Ok(())
    }

    fn commit(&mut self, store: &Store, next: Record) -> Result<()> {
        validate(&next)?;
        if let Err(err) = store.put_durable(KIND, KEY, &next) {
            self.poisoned = true;
            return Err(err).context("persist namespace fence");
        }
        self.record = next;
        Ok(())
    }
}

fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
}

fn check_names(names: &[String]) -> Result<()> {
    anyhow::ensure!(
        !names.is_empty() && names.len() <= briqyard_api::execution::MAX_RESOURCES,
        "invalid namespace mutation size"
    );
    anyhow::ensure!(
        names.iter().all(|name| safe_name(name)),
        "invalid namespace name"
    );
    anyhow::ensure!(
        names.windows(2).all(|pair| pair[0] < pair[1]),
        "namespace names must be sorted and unique"
    );
    Ok(())
}

fn names_of(snapshot: &GenerationSnapshot) -> Result<Vec<String>> {
    let names: Vec<_> = snapshot.0.iter().map(|(name, _)| name.clone()).collect();
    check_names(&names)?;
    Ok(names)
}

fn validate(record: &Record) -> Result<()> {
    anyhow::ensure!(
        record.generations.len() <= MAX_NAMESPACES
            && record.protected_until_ms.len() <= MAX_NAMESPACES
            && record.pending.len() <= MAX_PENDING,
        "namespace fence capacity"
    );
    anyhow::ensure!(
        serde_json::to_vec_pretty(record)?.len() <= MAX_BYTES,
        "namespace fence byte capacity"
    );
    anyhow::ensure!(
        record.generations.keys().all(|name| safe_name(name)),
        "invalid namespace fence name"
    );
    for (name, deadline) in &record.protected_until_ms {
        anyhow::ensure!(
            record.generations.contains_key(name) && *deadline > 0,
            "invalid namespace protection"
        );
    }
    for (id, ticket) in &record.pending {
        anyhow::ensure!(
            id == &ticket.id && id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid namespace ticket ID"
        );
        names_of(&ticket.generations)?;
        for (name, generation) in &ticket.generations.0 {
            match record.generations.get(name) {
                Some(current) => anyhow::ensure!(
                    *generation > 0 && generation <= current,
                    "invalid pending namespace generation"
                ),
                None => anyhow::ensure!(
                    *generation == 0,
                    "invalid pending untracked namespace generation"
                ),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("state")).unwrap();
        (dir, store)
    }

    fn names(values: &[&str]) -> Vec<String> {
        values.iter().map(|name| (*name).into()).collect()
    }

    #[test]
    fn leftover_uncommitted_write_is_removed_on_load() {
        let (_dir, store) = open();
        let mut fence = ExecutionFence::load(&store).unwrap();
        fence.snapshot(&store, &names(&["a"]), 10_000).unwrap();
        let dir = store.dir(KIND);
        std::fs::write(dir.join("state.json.tmp"), b"{ torn").unwrap();
        let reopened = ExecutionFence::load(&store).unwrap();
        assert!(reopened.record.generations.contains_key("a"));
        assert!(!dir.join("state.json.tmp").exists());
        assert!(dir.join("state.json").exists());
    }

    #[test]
    fn leftover_uncommitted_write_alone_loads_the_empty_record() {
        let (_dir, store) = open();
        let dir = store.dir(KIND);
        // A well-formed temp file must not be taken as the record either.
        let record = serde_json::to_vec(&Record::default()).unwrap();
        std::fs::write(dir.join("state.json.tmp"), record).unwrap();
        let fence = ExecutionFence::load(&store).unwrap();
        assert!(fence.record.generations.is_empty());
        assert!(!dir.join("state.json.tmp").exists());
        assert!(!dir.join("state.json").exists());
    }

    #[test]
    fn other_stray_files_are_still_refused() {
        let (_dir, store) = open();
        let dir = store.dir(KIND);
        for name in ["state.json.bak", "other.tmp", "state.json.tmp.tmp"] {
            std::fs::write(dir.join(name), b"x").unwrap();
            assert!(ExecutionFence::load(&store).is_err(), "{name}");
            std::fs::remove_file(dir.join(name)).unwrap();
        }
        // A directory named like the temp file is not an uncommitted write.
        std::fs::create_dir(dir.join("state.json.tmp")).unwrap();
        assert!(ExecutionFence::load(&store).is_err());
    }

    #[test]
    fn startup_drain_retains_all_deadlines_and_pending_evidence() {
        let (_dir, store) = open();
        let mut fence = ExecutionFence::load(&store).unwrap();
        for (name, deadline) in [("old", 30_000), ("current", 40_000)] {
            let snapshot = fence.snapshot(&store, &names(&[name]), 10_000).unwrap();
            fence.protect(&store, &snapshot, deadline, 10_000).unwrap();
        }
        fence
            .begin_mutation(&store, &names(&["old"]), MutationMode::Invalidate, 10_000)
            .unwrap();
        let mut reopened = ExecutionFence::load(&store).unwrap();
        assert_eq!(
            reopened.startup_delay(10_000).unwrap(),
            Duration::from_millis(35_001)
        );
        assert_eq!(
            reopened.startup_delay(45_000).unwrap(),
            Duration::from_millis(1)
        );
        assert_eq!(reopened.startup_delay(45_001).unwrap(), Duration::ZERO);
        assert!(reopened.snapshot(&store, &names(&["old"]), 45_001).is_err());
        assert!(reopened.startup_delay(4_999).is_err());
        reopened.poison();
        assert!(reopened.startup_delay(45_001).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn startup_monotonic_wait_does_not_replace_wall_clock_proof() {
        let (_dir, store) = open();
        let mut fence = ExecutionFence::load(&store).unwrap();
        let now = execution_mutations::execution_now_ms().unwrap_or(10_000);
        let snapshot = fence.snapshot(&store, &names(&["a"]), now).unwrap();
        fence.protect(&store, &snapshot, now + 30_000, now).unwrap();
        // Tokio advances the monotonic timer; the wall clock remains before expiry.
        let start = tokio::time::Instant::now();
        let error = fence.drain_at_start(80_000).await.unwrap_err();
        assert!(tokio::time::Instant::now() - start >= Duration::from_millis(80_000));
        assert!(
            error.to_string().contains("has not drained")
                || error
                    .to_string()
                    .contains("qualified execution clock unavailable")
        );
        assert!(fence.startup_delay(now).unwrap() > Duration::ZERO);
    }

    #[test]
    fn restart_keeps_generations_pending_and_protection() {
        let (_dir, store) = open();
        let mut fence = ExecutionFence::load(&store).unwrap();
        let a = names(&["a"]);
        let first = fence.snapshot(&store, &a, 10_000).unwrap();
        fence.protect(&store, &first, 30_000, 10_000).unwrap();
        let ticket = fence
            .begin_mutation(&store, &a, MutationMode::Invalidate, 11_000)
            .unwrap();
        let mut reopened = ExecutionFence::load(&store).unwrap();
        assert!(!reopened.matches_snapshot(&first, 11_000).unwrap());
        assert!(reopened.snapshot(&store, &a, 11_000).is_err());
        assert!(reopened
            .begin_mutation(&store, &a, MutationMode::Broaden, 11_000)
            .is_err());
        reopened.finish_mutation(&store, &ticket).unwrap();
        let second = reopened.snapshot(&store, &a, 11_000).unwrap();
        assert_ne!(first, second);
        assert!(reopened.check_protected(&second, 30_000, 11_000).unwrap());
        assert!(reopened
            .begin_mutation(&store, &a, MutationMode::Broaden, 35_000)
            .is_err());
        reopened
            .begin_mutation(&store, &a, MutationMode::Broaden, 35_001)
            .unwrap();
    }

    #[test]
    fn multi_namespace_reservation_is_atomic_and_late_finish_is_exact() {
        let (_dir, store) = open();
        let mut fence = ExecutionFence::load(&store).unwrap();
        let both = names(&["a", "b"]);
        let before = fence.snapshot(&store, &both, 10_000).unwrap();
        let first = fence
            .begin_mutation(&store, &both, MutationMode::Invalidate, 10_001)
            .unwrap();
        let second = fence
            .begin_mutation(&store, &names(&["a"]), MutationMode::Invalidate, 10_002)
            .unwrap();
        assert!(fence.finish_mutation(&store, &first).is_ok());
        assert!(fence.finish_mutation(&store, &first).is_err());
        assert!(fence.snapshot(&store, &both, 10_002).is_err());
        fence.finish_mutation(&store, &second).unwrap();
        let after = fence.snapshot(&store, &both, 10_002).unwrap();
        assert_eq!(before.0[0].1 + 2, after.0[0].1);
        assert_eq!(before.0[1].1 + 1, after.0[1].1);
        assert!(fence
            .begin_mutation(
                &store,
                &names(&["b", "a"]),
                MutationMode::Invalidate,
                10_002
            )
            .is_err());
    }

    #[test]
    fn untracked_mutations_fence_discovery_until_every_ticket_finishes() {
        let (_dir, store) = open();
        let mut fence = ExecutionFence::load(&store).unwrap();
        let a = names(&["a"]);
        let first = fence
            .begin_mutation(&store, &a, MutationMode::Invalidate, 10_000)
            .unwrap();
        let second = fence
            .begin_mutation(&store, &a, MutationMode::Invalidate, 10_001)
            .unwrap();
        assert_eq!(first.generations.0, vec![("a".into(), 0)]);
        assert_eq!(second.generations.0, first.generations.0);
        assert!(!fence.record.generations.contains_key("a"));

        let mut reopened = ExecutionFence::load(&store).unwrap();
        assert!(reopened.snapshot(&store, &a, 10_001).is_err());
        reopened.finish_mutation(&store, &first).unwrap();
        assert!(reopened.snapshot(&store, &a, 10_001).is_err());
        reopened.finish_mutation(&store, &second).unwrap();
        assert!(!reopened.record.generations.contains_key("a"));

        let discovered = reopened.snapshot(&store, &a, 10_001).unwrap();
        assert_eq!(discovered.0, vec![("a".into(), 0)]);
        assert_eq!(
            ExecutionFence::load(&store).unwrap().record.generations["a"],
            0
        );
        let later = reopened
            .begin_mutation(&store, &a, MutationMode::Invalidate, 10_002)
            .unwrap();
        assert_eq!(later.generations.0, vec![("a".into(), 1)]);
        assert!(!reopened.matches_snapshot(&discovered, 10_002).unwrap());
    }

    #[test]
    fn successful_never_discovered_mutation_leaves_no_generation_entry() {
        let (_dir, store) = open();
        let mut fence = ExecutionFence::load(&store).unwrap();
        let ticket = fence
            .begin_mutation(
                &store,
                &names(&["transient"]),
                MutationMode::Broaden,
                10_000,
            )
            .unwrap();
        fence.finish_mutation(&store, &ticket).unwrap();
        let reopened = ExecutionFence::load(&store).unwrap();
        assert!(!reopened.record.generations.contains_key("transient"));
        assert!(reopened.record.pending.is_empty());
    }

    #[test]
    fn protection_requires_exact_snapshot_and_survives_clock_rollback() {
        let (_dir, store) = open();
        let mut fence = ExecutionFence::load(&store).unwrap();
        let a = names(&["a"]);
        let first = fence.snapshot(&store, &a, 10_000).unwrap();
        assert!(fence
            .protect(
                &store,
                &GenerationSnapshot(vec![("unknown".into(), 0)]),
                20_000,
                10_000
            )
            .is_err());
        let ticket = fence
            .begin_mutation(&store, &a, MutationMode::Invalidate, 10_001)
            .unwrap();
        assert!(fence.protect(&store, &first, 20_000, 10_001).is_err());
        fence.finish_mutation(&store, &ticket).unwrap();
        assert!(fence.protect(&store, &first, 20_000, 10_001).is_err());
        let second = fence.snapshot(&store, &a, 10_001).unwrap();
        fence.protect(&store, &second, 20_000, 10_001).unwrap();
        assert!(fence
            .begin_mutation(&store, &a, MutationMode::Broaden, 25_000)
            .is_err());
        assert!(fence
            .begin_mutation(&store, &a, MutationMode::Broaden, 24_000)
            .is_err());
        assert!(fence
            .begin_mutation(&store, &a, MutationMode::Broaden, 18_999)
            .is_err());
        assert!(fence.snapshot(&store, &a, 4_999).is_err());
    }

    #[test]
    fn corrupt_state_and_uncertain_write_refuse_admission() {
        let (dir, store) = open();
        let mut fence = ExecutionFence::load(&store).unwrap();
        let a = names(&["a"]);
        fence.snapshot(&store, &a, 10_000).unwrap();
        let state = dir.path().join("state").join(KIND).join("state.json");
        std::fs::write(&state, b"{").unwrap();
        assert!(ExecutionFence::load(&store).is_err());
        std::fs::remove_file(&state).unwrap();
        let stray = dir.path().join("state").join(KIND).join("stray");
        std::fs::write(&stray, b"{}").unwrap();
        assert!(ExecutionFence::load(&store).is_err());
        std::fs::remove_file(&stray).unwrap();
        std::fs::create_dir(&state).unwrap();
        assert!(fence
            .begin_mutation(&store, &a, MutationMode::Invalidate, 10_001)
            .is_err());
        assert!(fence.snapshot(&store, &a, 10_001).is_err());
    }
}
