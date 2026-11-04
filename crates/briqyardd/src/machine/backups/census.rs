//! Bounded observations of backup objects. No deletion or all-host ownership authority.
use super::*;
use crate::metrics::backup_census::Snapshot;
use briqyard_objstore::{BoundedList, ListedObject};
use std::collections::BTreeMap;
use std::time::Instant;

const PERIOD: Duration = Duration::from_secs(24 * 60 * 60);
const RUNTIME: Duration = Duration::from_secs(30);
const OBJECTS: usize = 4096;
const RECORD_BYTES: usize = 64 << 10;
const TOTAL_BYTES: usize = 8 << 20;

#[derive(Default)]
pub(super) struct Census {
    state: Mutex<Cache>,
    turn: Turn,
}
struct Cache {
    next: Option<Instant>,
    observation: Snapshot,
}
impl Default for Cache {
    fn default() -> Self {
        Self {
            next: Some(Instant::now() + PERIOD),
            observation: Snapshot::default(),
        }
    }
}
impl Cache {
    fn reserve(&mut self, now: Instant) -> bool {
        if self.next.is_some_and(|next| now < next) {
            return false;
        }
        self.next = Some(now + PERIOD);
        // Never retain a previous successful observation while a new attempt is unsettled.
        self.observation = Snapshot::default();
        true
    }
}

impl Manager {
    pub(super) fn backup_census_step(&self, tasks: &mut Vec<tokio::task::JoinHandle<()>>) {
        let backups = &self.inner.backups;
        let Ok(turn) = backups.census.turn.clone().try_lock_owned() else {
            return;
        };
        let Some(admission) = backups.jobs.try_reserve() else {
            return;
        };
        let Ok(mut cache) = backups.census.state.try_lock() else {
            return;
        };
        if !cache.reserve(Instant::now()) {
            return;
        }
        drop(cache);
        if let Ok(ticket) = backups
            .jobs
            .start(self.clone(), jobs::Work::Census, turn, admission)
        {
            tasks.push(tokio::spawn(ticket.finished()));
        }
    }

    pub(in super::super) fn backup_census_observation(&self) -> Snapshot {
        // A scrape never waits on a census or performs store I/O. Busy/poisoned is unknown.
        self.inner
            .backups
            .census
            .state
            .try_lock()
            .map(|s| fresh(s.observation, Utc::now().timestamp()))
            .unwrap_or_default()
    }

    pub(super) async fn run_backup_census(&self) {
        let jobs = &self.inner.backups.jobs;
        let epoch = jobs.epoch();
        let active = jobs.pending() > 1;
        let result = tokio::time::timeout(RUNTIME, self.observe_backup_objects()).await;
        let mut observation = match result {
            Ok(Ok(s)) => s,
            // No paths, metadata, provider messages or identifiers enter logs or the cache.
            _ => Snapshot {
                failed: true,
                enumeration_complete: false,
                metadata_complete: false,
                ..self.backup_census_observation()
            },
        };
        observation.local_activity = active || jobs.pending() > 1 || jobs.epoch() != epoch;
        if observation.local_activity {
            observation.enumeration_complete = false;
            observation.metadata_complete = false;
        }
        observation.finished_at = Utc::now().timestamp();
        self.inner.backups.census.state.lock().unwrap().observation = observation;
    }

    async fn observe_backup_objects(&self) -> Result<Snapshot> {
        let store = self.backup_store()?;
        let _read = self.inner.backups.reads.acquire().await?;
        let listed = store.list_bounded("backups/", OBJECTS).await?;
        let mut scan = Scan::new(listed);
        self.inner.backups.census.state.lock().unwrap().observation = scan.snapshot;
        let mut budget = MetadataBudget(TOTAL_BYTES);
        // One metadata request at a time. Never call the legacy unbounded list/read path.
        let records: Vec<ListedObject> = scan
            .objects
            .values()
            .filter(|o| matches!(path(&o.key), Some(Path::Record(..))))
            .cloned()
            .collect();
        for object in records {
            let Some(limit) = budget.reserve(object.bytes) else {
                scan.snapshot.read_failures += 1;
                continue;
            };
            match store.get_bytes_bounded(&object, limit).await {
                Ok(bytes) => scan.record(&object.key, &bytes, |machine, namespace| {
                    self.observed_backup_owner(machine, namespace)
                }),
                Err(_) => scan.snapshot.read_failures += 1,
            }
            self.inner.backups.census.state.lock().unwrap().observation = scan.snapshot;
            tokio::task::yield_now().await;
        }
        Ok(scan.finish())
    }

    fn observed_backup_owner(&self, machine: &str, namespace: &str) -> bool {
        if self.inner.backups.jobs.has_owner(machine, namespace) {
            return true;
        }
        // Observe one owner at a time, without allocating an all-machine inventory. Missing
        // or busy local registries prove nothing about retained, foreign or future owners.
        if let Ok(machines) = self.inner.machines.try_lock() {
            if let Some(entry) = machines.get(machine) {
                if let Ok(rec) = entry.rec.try_lock() {
                    if rec.namespace == namespace {
                        return true;
                    }
                }
            }
        }
        if let Ok(holders) = self.inner.backups.holders.try_lock() {
            if let Some(holder) = holders.get(machine) {
                if let Ok(rec) = holder.rec.try_lock() {
                    if rec.namespace == namespace {
                        return true;
                    }
                }
            }
        }
        false
    }
}

struct MetadataBudget(usize);
impl MetadataBudget {
    fn reserve(&mut self, bytes: u64) -> Option<usize> {
        if bytes > RECORD_BYTES as u64 {
            return None;
        }
        let limit = (bytes as usize).max(1);
        // The bounded reader probes one extra byte to reject an oversized body.
        let reserved = limit + 1;
        if reserved > self.0 {
            return None;
        }
        self.0 -= reserved;
        Some(limit)
    }
}

fn fresh(mut observation: Snapshot, now: i64) -> Snapshot {
    if observation.finished_at == 0
        || now < observation.finished_at
        || now.saturating_sub(observation.finished_at) > (2 * PERIOD.as_secs()) as i64
    {
        observation.enumeration_complete = false;
        observation.metadata_complete = false;
    }
    observation
}

enum Path<'a> {
    Record(&'a str, &'a str),
    Stream,
}
fn backup_id(id: &str) -> bool {
    id.len() == 20
        && chrono::NaiveDateTime::parse_from_str(id, "%Y%m%dT%H%M%S%.3fZ")
            .is_ok_and(|t| t.format("%Y%m%dT%H%M%S%.3fZ").to_string() == id)
}
fn path(key: &str) -> Option<Path<'_>> {
    let parts: Vec<_> = key.split('/').collect();
    match parts.as_slice() {
        ["backups", machine, record] if api::valid_id(machine) => {
            let id = record.strip_suffix(".json")?;
            backup_id(id).then_some(Path::Record(machine, id))
        }
        ["backups", machine, "root" | "data", stream] if api::valid_id(machine) => {
            backup_id(stream.strip_suffix(".zfs")?).then_some(Path::Stream)
        }
        _ => None,
    }
}

fn parse(key: &str, bytes: &[u8]) -> Option<api::Backup> {
    let Path::Record(machine, id) = path(key)? else {
        return None;
    };
    // Reject unknown record/disk schemas instead of silently blessing fields we do not
    // understand. Opaque legacy machine contents are never interpreted, opened or exported.
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let allowed = [
        "consistency",
        "consistency_reason",
        "size",
        "id",
        "machine_id",
        "namespace",
        "tenant",
        "name",
        "created_at",
        "bytes",
        "incremental",
        "disks",
        "key_id",
        "machine",
        "sealed",
        "deletes_at",
    ];
    if !value
        .as_object()?
        .keys()
        .all(|k| allowed.contains(&k.as_str()))
    {
        return None;
    }
    for disk in value.get("disks")?.as_array()? {
        if !disk
            .as_object()?
            .keys()
            .all(|k| ["disk", "key", "bytes", "from"].contains(&k.as_str()))
        {
            return None;
        }
    }
    drop(value);
    // Deserialize the actual API types: duplicate recognized fields and incorrect types fail.
    let mut b: api::Backup = serde_json::from_slice(bytes).ok()?;
    if !matches!(
        b.copy_consistency.consistency.as_str(),
        "filesystem" | "synced" | "unsynced"
    ) || b.machine_id != machine
        || b.id != id
        || !api::valid_id(&b.namespace)
        || b.disks.is_empty()
        || b.disks.len() > 2
        || b.deletes_at.is_some()
        || b.key_id.as_ref().is_some_and(|k| {
            k.len() != 32
                || !k
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        })
    {
        return None;
    }
    if let Some(sealed) = &b.sealed {
        use base64::Engine;
        if b.key_id.is_none()
            || b.machine.is_some()
            || base64::engine::general_purpose::STANDARD
                .decode(sealed)
                .ok()?
                .len()
                < 28
        {
            return None;
        }
    } else if b.key_id.is_some() || !b.machine.as_ref().is_some_and(|m| m.is_object()) {
        return None;
    }
    let mut disks = HashSet::new();
    let mut total = 0u64;
    for d in &b.disks {
        if !matches!(d.disk.as_str(), "root" | "data")
            || !disks.insert(&d.disk)
            || d.key != format!("backups/{machine}/{}/{id}.zfs", d.disk)
            || d.from
                .as_ref()
                .is_some_and(|f| !backup_id(f) || f.as_str() >= id)
        {
            return None;
        }
        total = total.checked_add(d.bytes)?;
    }
    if total != b.bytes || b.incremental != b.disks.iter().any(|d| d.from.is_some()) {
        return None;
    }
    b.name = String::new();
    b.machine = None;
    b.sealed = None;
    Some(b)
}

struct Scan {
    snapshot: Snapshot,
    objects: BTreeMap<String, ListedObject>,
    records: BTreeMap<(String, String), api::Backup>,
}
impl Scan {
    fn new(list: BoundedList) -> Self {
        let mut snapshot = Snapshot {
            enumeration_complete: list.complete,
            objects: list.objects.len() as u64,
            ..Snapshot::default()
        };
        let mut objects = BTreeMap::new();
        for object in list.objects {
            if path(&object.key).is_none() {
                snapshot.malformed += 1;
            }
            if objects.insert(object.key.clone(), object).is_some() {
                // Duplicate keys can be a changed-page race, never evidence of exhaustion.
                snapshot.enumeration_complete = false;
                snapshot.malformed += 1;
            }
        }
        Self {
            snapshot,
            objects,
            records: BTreeMap::new(),
        }
    }
    fn record(&mut self, key: &str, bytes: &[u8], owner: impl FnOnce(&str, &str) -> bool) {
        let Some(b) = parse(key, bytes) else {
            self.snapshot.malformed += 1;
            return;
        };
        self.snapshot.records += 1;
        if owner(&b.machine_id, &b.namespace) {
            self.snapshot.local_owners += 1;
        } else {
            self.snapshot.unresolved_owners += 1;
        }
        self.records.insert((b.machine_id.clone(), b.id.clone()), b);
    }
    fn finish(mut self) -> Snapshot {
        let mut referenced = HashSet::new();
        let mut chains = BTreeMap::new();
        // Strictly older bases make this a bounded forward pass, including transitive gaps.
        for ((machine, id), b) in &self.records {
            for d in &b.disks {
                referenced.insert(d.key.as_str());
                let present = match self.objects.get(&d.key) {
                    None => {
                        self.snapshot.missing_streams += 1;
                        false
                    }
                    Some(o) if o.bytes != d.bytes => {
                        self.snapshot.size_mismatches += 1;
                        false
                    }
                    Some(_) => true,
                };
                let base = d.from.as_ref().is_none_or(|from| {
                    let key = (machine.clone(), from.clone());
                    self.records.get(&key).is_some_and(|base| {
                        base.namespace == b.namespace
                            && base.key_id == b.key_id
                            && chains.get(&(machine.clone(), from.clone(), d.disk.clone()))
                                == Some(&true)
                    })
                });
                if !base {
                    self.snapshot.unresolved_chains += 1;
                }
                chains.insert(
                    (machine.clone(), id.clone(), d.disk.clone()),
                    present && base,
                );
            }
        }
        self.snapshot.unreferenced_streams = self
            .objects
            .values()
            .filter(|o| {
                matches!(path(&o.key), Some(Path::Stream)) && !referenced.contains(o.key.as_str())
            })
            .count() as u64;
        self.snapshot.metadata_complete = self.snapshot.enumeration_complete
            && self.snapshot.malformed == 0
            && self.snapshot.read_failures == 0
            && self.snapshot.missing_streams == 0
            && self.snapshot.size_mismatches == 0
            && self.snapshot.unresolved_chains == 0
            && self.snapshot.unreferenced_streams == 0;
        self.snapshot
    }
}

#[cfg(test)]
mod tests;
