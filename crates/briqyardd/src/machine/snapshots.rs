//! Snapshots (ADR 0031): both disks at one instant, the memory with them when asked, named,
//! listed from the record, and restored in place. A restore swaps each disk for a clone of its
//! snapshot and keeps the disk it replaces, retired, for as long as something still needs it
//! (a newer snapshot, a fork), so restoring never breaks another snapshot, a fork or the
//! backup chain.

use super::*;
use std::collections::HashSet;

/// The disks a machine can have, by the name their datasets end with.
pub(super) const DISKS: [&str; 2] = ["root", "data"];

/// A snapshot as the machine's record keeps it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SnapshotRec {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    /// The disks it holds; a new image drops `root` (ADR 0024).
    pub disks: Vec<String>,
    /// Taken with the memory: the digest of what its processes ran (`memory_spec`), so a
    /// restore resumes them only into the same spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
    /// With the memory: what ran the machine when it was taken (`Record::vmm_version`). A
    /// restore puts it on the record with the memory, so the start loads the memory only under
    /// the same Firecracker and host kernel (ADR 0027).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vmm_version: String,
}

impl SnapshotRec {
    fn view(&self, machine_id: &str) -> api::Snapshot {
        api::Snapshot {
            id: self.id.clone(),
            machine_id: machine_id.to_string(),
            name: self.name.clone(),
            created_at: self.created_at,
            disks: self.disks.clone(),
            memory: self.memory.is_some(),
        }
    }

    fn is(&self, id_or_name: &str) -> bool {
        self.id == id_or_name || self.name.as_deref() == Some(id_or_name)
    }
}

/// What a memory snapshot holds of the machine's spec, as a digest: its image, command, env,
/// files and size (what makes a resume cold under ADR 0024), and its volume's size as the
/// guest booted with it: the record's, unless a growth waits for the next boot (ADR 0040).
fn memory_spec(r: &Record) -> String {
    use sha2::{Digest, Sha256};
    let volume = r.volume.as_ref().map(|v| v.size_gb);
    let growing = r.pending.as_ref().is_some_and(|p| p.volume.is_some());
    let held = json!([
        r.image_key,
        r.entrypoint,
        r.cmd,
        r.env,
        r.files,
        r.size,
        volume,
        growing
    ]);
    hex::encode(Sha256::digest(held.to_string()))
}

/// Which disk a dataset of the machine is, and whether it is the one in use: `root` and
/// `data` are; `root.<n>` and `data.<n>` were retired by a swap.
fn lineage(r: &Record, ds: &str) -> Option<(&'static str, bool)> {
    let last = ds.strip_prefix(&r.dataset())?.strip_prefix('/')?;
    DISKS.into_iter().find_map(|d| match last.strip_prefix(d) {
        Some("") => Some((d, true)),
        Some(rest) if rest.starts_with('.') => Some((d, false)),
        _ => None,
    })
}

/// The snapshots the record names, per disk.
fn named(r: &Record) -> HashSet<(&str, &str)> {
    r.snapshots
        .iter()
        .flat_map(|s| s.disks.iter().map(|d| (d.as_str(), s.id.as_str())))
        .collect()
}

/// Whether `tidy` removes a snapshot of the machine: nothing clones it, and it is an `s_` the
/// record does not name for that disk, a fork's, or anything on a retired disk but a named one.
fn unwanted(r: &Record, named: &HashSet<(&str, &str)>, s: &crate::zfs::SnapshotOf) -> bool {
    let Some((disk, live)) = lineage(r, &s.dataset) else {
        return false;
    };
    if !s.clones.is_empty() {
        return false;
    }
    match s.snap.starts_with("s_") {
        true => !named.contains(&(disk, s.snap.as_str())),
        false => s.snap.starts_with("fork-") || !live,
    }
}

/// The machine a dataset belongs to (`m/<id>/…`).
pub(super) fn machine_of(ds: &str) -> Option<&str> {
    ds.strip_prefix("m/")?.split('/').next()
}

/// The refusal while a restore is unfinished (its intent in the record).
pub(super) fn unfinished(snap: &str) -> MError {
    MError::BadState(format!(
        "a restore to {snap} is unfinished: restore again, or start the machine"
    ))
}

impl Manager {
    /// Where a machine's memory snapshots are kept: beside its jail's root, on the pool (ADR
    /// 0014), or in its run directory without the jailer.
    fn memory_dir(&self, r: &Record) -> PathBuf {
        let jail = self.jail_for(r).map(|j| j.base);
        fc::memory_dir(
            &self.inner.cfg.run_dir().join(&r.id),
            jail.as_deref(),
            &r.id,
        )
    }

    /// A snapshot's memory files: its state and its memory.
    fn memory_files(&self, r: &Record, snap: &str) -> [PathBuf; 2] {
        let dir = self.memory_dir(r);
        ["state", "mem"].map(|ext| dir.join(format!("{snap}.{ext}")))
    }

    /// Every memory snapshot file of a machine, for its usage.
    pub(super) fn memory_snapshot_files(&self, r: &Record) -> Vec<PathBuf> {
        r.snapshots
            .iter()
            .filter(|s| s.memory.is_some())
            .flat_map(|s| self.memory_files(r, &s.id))
            .collect()
    }

    /// Removes the memory files of snapshots the record does not name: what a crash between
    /// their move into the memory directory and the record's save leaves.
    fn remove_stray_memory(&self, r: &Record) {
        let ids: HashSet<&str> = r.snapshots.iter().map(|s| s.id.as_str()).collect();
        let Ok(dir) = std::fs::read_dir(self.memory_dir(r)) else {
            return;
        };
        for f in dir.flatten() {
            let name = f.file_name();
            let Some((id, ext)) = name.to_str().and_then(|n| n.rsplit_once('.')) else {
                continue;
            };
            if !id.starts_with("s_") || !matches!(ext, "state" | "mem") || ids.contains(id) {
                continue;
            }
            match std::fs::remove_file(f.path()) {
                Ok(()) => tracing::info!(
                    machine = r.id,
                    file = %f.path().display(),
                    why = "named by no snapshot",
                    "memory file removed"
                ),
                Err(err) => {
                    tracing::warn!(machine = r.id, file = %f.path().display(), err = %err, "memory file not removed")
                }
            }
        }
    }

    pub(super) fn remove_memory(&self, r: &Record, snap: &str) {
        for f in self.memory_files(r, snap) {
            let _ = std::fs::remove_file(f);
        }
    }

    pub async fn snapshots(&self, id: &str) -> Result<Vec<api::Snapshot>, MError> {
        let e = self.own_entry(id)?;
        let r = e.snapshot();
        Ok(r.snapshots.iter().map(|s| s.view(&r.id)).collect())
    }

    /// Snapshots both disks at one instant; with `memory`, a running machine is paused for
    /// it, its memory written beside its jail and its disks flushed, then it runs on.
    pub async fn snapshot(
        &self,
        id: &str,
        req: api::SnapshotRequest,
    ) -> Result<api::Snapshot, MError> {
        let e = self.own_entry(id)?;
        if let Some(n) = &req.name {
            api::check_snapshot_name(n).map_err(invalid)?;
        }
        let _lock = e.lock.lock().await;
        let r = e.snapshot();
        if r.state == state::DESTROYING {
            return Err(MError::BadState(r.state));
        }
        if let Some(s) = &r.restoring {
            return Err(unfinished(s));
        }
        if let Some(n) = &req.name {
            if r.snapshots.iter().any(|s| s.is(n)) {
                return Err(MError::Conflict(format!(
                    "a snapshot named {n} exists on the machine"
                )));
            }
        }
        let disks: Vec<&str> = match r.volume {
            Some(_) => DISKS.to_vec(),
            None => vec!["root"],
        };
        let datasets: Vec<String> = disks.iter().map(|d| r.disk_dataset(d)).collect();
        let snap = new_id("s");
        let (memory, vmm_version) = match req.memory {
            true => {
                self.snapshot_with_memory(&e, &r, &datasets, &snap).await?;
                (Some(memory_spec(&r)), r.vmm_version.clone())
            }
            false => {
                self.inner.zfs.snapshot_all(&datasets, &snap).await?;
                (None, String::new())
            }
        };
        let s = SnapshotRec {
            id: snap,
            name: req.name,
            created_at: Utc::now(),
            disks: disks.iter().map(|d| d.to_string()).collect(),
            memory,
            vmm_version,
        };
        {
            let mut rec = e.rec.lock().unwrap();
            rec.snapshots.push(s.clone());
            let named = s
                .name
                .as_deref()
                .map(|n| format!(" ({n})"))
                .unwrap_or_default();
            let with = if s.memory.is_some() {
                " and memory"
            } else {
                ""
            };
            let ev = Ev::normal(
                reason::SNAPSHOT_TAKEN,
                format!("snapshot {}{named} of {}{with}", s.id, s.disks.join(" and ")),
            )
            .data(json!({ "snapshot": s.id, "name": s.name, "disks": s.disks, "memory": s.memory.is_some() }));
            e.note_locked(&mut rec, ev);
        }
        self.save(&e)?;
        Ok(s.view(id))
    }

    /// The memory part of a snapshot, its lock held: paused, the memory and state written by
    /// Firecracker, the disks flushed so the snapshot holds every write the guest made, the
    /// disks snapshotted, resumed; the files then moved to the memory directory. A failure
    /// leaves no snapshot, and the machine running.
    async fn snapshot_with_memory(
        &self,
        e: &Arc<Entry>,
        r: &Record,
        datasets: &[String],
        snap: &str,
    ) -> Result<(), MError> {
        let live = e.live.lock().unwrap().clone();
        let (Some(live), state::RUNNING) = (live, r.state.as_str()) else {
            return Err(MError::NotRunning(
                "a snapshot with memory needs the machine running".into(),
            ));
        };
        let z = &self.inner.zfs;
        let jail = self.jail_for(r).map(|j| j.base);
        let written = fc::snapshot_files(&live.dir, jail.as_deref(), &r.id);
        // A link a memory restore left there names a kept snapshot's files: Firecracker would
        // write through it.
        for f in &written {
            let _ = std::fs::remove_file(f);
        }
        // Unsynced: the machine is paused while Firecracker writes, and the sync is the
        // longest part (ADR 0037). The files are synced below, after the resume and before the
        // record names the snapshot: a crash before that leaves files nothing names.
        self.inner
            .vmm
            .snapshot(&live, false)
            .await
            .context("memory snapshot")?;
        let disks = async {
            for ds in datasets {
                let dev = z.device(ds).await?;
                std::fs::File::open(&dev)
                    .and_then(|f| f.sync_all())
                    .with_context(|| format!("flush {}", dev.display()))?;
            }
            z.snapshot_all(datasets, snap).await
        }
        .await;
        let resumed = self.inner.vmm.resume(&live).await;
        let kept = async {
            disks?;
            let dir = self.memory_dir(r);
            std::fs::create_dir_all(&dir).context("memory snapshot directory")?;
            for (from, to) in written.iter().zip(self.memory_files(r, snap)) {
                if from.exists() {
                    std::fs::rename(from, &to).context("keep the memory snapshot")?;
                    std::fs::File::open(&to)
                        .and_then(|f| f.sync_all())
                        .context("sync the memory snapshot")?;
                }
            }
            std::fs::File::open(&dir)
                .and_then(|d| d.sync_all())
                .context("sync the memory snapshot directory")?;
            anyhow::Ok(())
        }
        .await;
        if let Err(err) = resumed {
            // Paused for good: ended, as a process that died; the watcher settles it.
            tracing::warn!(machine = r.id, err = %err, "resume after a memory snapshot failed");
            self.inner.vmm.kill(live.pid);
        }
        if let Err(err) = kept {
            for f in written.iter().chain(self.memory_files(r, snap).iter()) {
                let _ = std::fs::remove_file(f);
            }
            for ds in datasets {
                let _ = z.destroy_snapshot(ds, snap).await;
            }
            return Err(err.into());
        }
        Ok(())
    }

    /// Deletes a snapshot, by id or name; missing is success. What it alone held goes now;
    /// what something still clones (a retired disk) goes with the last of those.
    pub async fn delete_snapshot(&self, id: &str, snap: &str) -> Result<(), MError> {
        let e = self.own_entry(id)?;
        let parents = {
            // The turn too, as a restore takes it: no backup sends while a retired disk goes.
            let _turns = e.lock_with_turn().await;
            let r = e.snapshot();
            if let Some(s) = &r.restoring {
                return Err(unfinished(s));
            }
            let Some(s) = r.snapshots.iter().find(|s| s.is(snap)).cloned() else {
                return Ok(());
            };
            {
                let mut rec = e.rec.lock().unwrap();
                rec.snapshots.retain(|x| x.id != s.id);
                let ev = Ev::normal(
                    reason::SNAPSHOT_DELETED,
                    format!("snapshot {} deleted", s.id),
                )
                .data(json!({ "snapshot": s.id, "name": s.name }));
                e.note_locked(&mut rec, ev);
            }
            self.save(&e)?;
            self.remove_memory(&r, &s.id);
            self.tidy(&e).await?
        };
        // Other machines after this one's lock is released, as everywhere.
        self.tidy_machines(parents).await;
        Ok(())
    }

    /// Takes the machine's disks back to a snapshot (by id or name), and its memory too when
    /// the snapshot holds it and the machine still runs the same spec. A running machine is
    /// stopped first and booted (or resumed) after; any other stays as it is. Its backup turn
    /// is taken before its lock, as a start that remakes a disk takes it: no backup sends a
    /// disk while it is swapped.
    pub async fn restore_snapshot(
        &self,
        id: &str,
        snap: &str,
        at: Option<u64>,
    ) -> Result<api::Machine, MError> {
        let e = self.own_entry(id)?;
        let turns = e.lock_once_stopped(true).await;
        self.check_version(&e, at)?;
        let r = e.snapshot();
        let s = r
            .snapshots
            .iter()
            .find(|s| s.is(snap))
            .cloned()
            .ok_or_else(|| MError::NoSnapshot(format!("{id}/{snap}")))?;
        let was_running = match r.state.as_str() {
            state::RUNNING => true,
            state::STOPPED | state::CREATED | state::ERROR => false,
            other => return Err(MError::BadState(other.into())),
        };
        if was_running {
            self.stop_locked(&e, format!("to restore {}", s.id)).await;
        }
        {
            // The intent first: a restore cut short is finished by the next one, the next
            // start or the daemon's. The memory snapshot of a suspend held the old disks.
            let mut rec = e.rec.lock().unwrap();
            rec.restoring = Some(s.id.clone());
            rec.suspended = false;
        }
        self.save(&e)?;
        let parents = self.finish_restore(&e).await?;
        let started = match was_running {
            true => self.start_entry(&e, true).await,
            false => Ok(()),
        };
        drop(turns);
        self.tidy_machines(parents).await;
        started?;
        Ok(self.view(&e))
    }

    /// Ends a running machine's process under its lock: `stopping`, then `stopped` on
    /// request once Firecracker is gone. The watcher finds nothing left to settle.
    async fn stop_locked(&self, e: &Arc<Entry>, why: String) {
        e.set_state(state::STOPPING, |_| {
            Some(
                Ev::normal(reason::STOPPING, format!("stopping ({why})"))
                    .data(json!({ "reason": stop::USER, "suspend": false })),
            )
        });
        let _ = self.save(e);
        let live = e.live.lock().unwrap().clone();
        if let Some(live) = live {
            self.end_process(e, &live, Duration::from_secs(10)).await;
        }
        self.settle_stopped(e, stop::USER);
    }

    /// The restore the record's intent names, its lock (and turn) held: each disk swapped for
    /// a clone of the snapshot, then what no longer serves tidied away, the memory put where
    /// a resume reads it, the intent cleared and `restored` logged. Run again from the top
    /// when cut short. Returns the machines `tidy` found to tidy next.
    pub(super) async fn finish_restore(&self, e: &Arc<Entry>) -> Result<Vec<String>, MError> {
        let r = e.snapshot();
        let Some(id) = r.restoring.clone() else {
            return Ok(Vec::new());
        };
        let s = r.snapshots.iter().find(|s| s.id == id).cloned();
        let Some(s) = s else {
            // Not ours to restore any more: nothing a later call could finish.
            e.rec.lock().unwrap().restoring = None;
            self.save(e)?;
            return Ok(Vec::new());
        };
        for disk in &s.disks {
            self.finish_swap(&r, disk).await?;
            let from = self
                .holder_of(&r, disk, &s.id)
                .await?
                .ok_or_else(|| anyhow!("snapshot {} of the {disk} disk is gone", s.id))?;
            self.swap(&r, disk, &from, &s.id).await?;
        }
        // A volume grown since the snapshot keeps its size, and its filesystem, the
        // snapshot's, is smaller until the next boot (ADR 0040). Read from the snapshot, not
        // from the disk, so a restore run again from the top says the same.
        let grew = match s.disks.iter().any(|d| d == "data") {
            true => self.smaller_than_its_volume(&r, &s.id).await?,
            false => false,
        };
        self.fit_volume(&r).await?;
        let kept = self.memory_files(&r, &s.id);
        let resume = s.memory.as_deref() == Some(memory_spec(&r).as_str())
            && kept.iter().all(|f| f.exists());
        if resume {
            let jail = self.jail_for(&r).map(|j| j.base);
            let dir = self.inner.cfg.run_dir().join(&r.id);
            for (from, to) in kept
                .iter()
                .zip(fc::snapshot_files(&dir, jail.as_deref(), &r.id))
            {
                let _ = std::fs::remove_file(&to);
                std::fs::hard_link(from, &to).context("the memory snapshot")?;
            }
        }
        {
            let mut rec = e.rec.lock().unwrap();
            rec.restoring = None;
            rec.suspended = resume;
            // Its filesystem is the snapshot's: it grows at the next boot, cold since the
            // memory of a smaller disk is not resumed. A start under way is that boot.
            if grew && rec.state != state::STARTING {
                let mut p = rec.pending.take().unwrap_or_default();
                p.volume = rec
                    .volume
                    .as_ref()
                    .map(|v| api::VolumeSize { size_gb: v.size_gb });
                rec.pending = Some(p);
                rec.pending_since.get_or_insert(Utc::now());
            }
            if resume {
                // What took the memory: the start resumes it only under the same (ADR 0027).
                rec.vmm_version = s.vmm_version.clone();
            }
            let named = s
                .name
                .as_deref()
                .map(|n| format!(" ({n})"))
                .unwrap_or_default();
            let with = if resume { ", its memory to resume" } else { "" };
            let ev = Ev::normal(
                reason::RESTORED,
                format!(
                    "{} restored to snapshot {}{named}{with}",
                    s.disks.join(" and "),
                    s.id
                ),
            )
            .data(json!({ "snapshot": s.id, "name": s.name, "disks": s.disks, "memory": resume }));
            e.note_locked(&mut rec, ev);
        }
        self.save(e)?;
        tracing::info!(
            machine = r.id,
            snapshot = s.id,
            memory = resume,
            "restored to a snapshot"
        );
        Ok(self.tidy_or_warn(e).await)
    }

    /// Whether the data disk's snapshot `snap` is smaller than the record's volume: taken
    /// before a growth (ADR 0040).
    async fn smaller_than_its_volume(&self, r: &Record, snap: &str) -> Result<bool> {
        let (Some(v), Some(ds)) = (&r.volume, self.holder_of(r, "data", snap).await?) else {
            return Ok(false);
        };
        let size = self.inner.zfs.volsize(&format!("{ds}@{snap}")).await?;
        Ok(size < (v.size_gb as u64) << 30)
    }

    /// The dataset of a disk's lineage (the disk, or one it retired) holding `snap`.
    async fn holder_of(&self, r: &Record, disk: &str, snap: &str) -> Result<Option<String>> {
        Ok(self
            .inner
            .zfs
            .snapshot_tree(&r.dataset())
            .await?
            .into_iter()
            .find(|s| s.snap == snap && lineage(r, &s.dataset).is_some_and(|(d, _)| d == disk))
            .map(|s| s.dataset))
    }

    /// Makes a disk of the machine a clone of `from@snap`: the clone is made beside it
    /// (`<disk>.next`), the disk renamed aside (`<disk>.<n>`, retired: it keeps its snapshots
    /// newer than `snap`, and whatever clones them), the clone renamed into its place, then
    /// promoted until it owns its history. Used by a restore and by a new image's root disk.
    pub(super) async fn swap(&self, r: &Record, disk: &str, from: &str, snap: &str) -> Result<()> {
        let z = &self.inner.zfs;
        let live = r.disk_dataset(disk);
        let next = format!("{live}.next");
        z.clone_snapshot(from, snap, &next).await?;
        if z.exists(&live).await? {
            let retired = format!("{live}.{}", new_id("r"));
            z.rename(&live, &retired).await?;
        }
        z.rename(&next, &live).await?;
        self.own_history(r, disk).await
    }

    /// What a swap cut short left: a clone made beside the disk goes; one the disk was
    /// renamed away from goes into its place; then the disk owns its history.
    pub(super) async fn finish_swap(&self, r: &Record, disk: &str) -> Result<()> {
        let z = &self.inner.zfs;
        let live = r.disk_dataset(disk);
        let next = format!("{live}.next");
        if z.exists(&next).await? {
            match z.exists(&live).await? {
                true => z.destroy(&next).await?,
                false => z.rename(&next, &live).await?,
            }
        }
        if z.exists(&live).await? {
            self.own_history(r, disk).await?;
        }
        Ok(())
    }

    /// Promotes the disk until its origin is outside the machine: it then holds every snapshot
    /// of its history, and a retired disk is a clone of one of them, never the other way. Each
    /// promotion moves the origin one dataset up the chain, so the rounds are bounded by the
    /// machine's datasets.
    async fn own_history(&self, r: &Record, disk: &str) -> Result<()> {
        let z = &self.inner.zfs;
        let (live, inside) = (r.disk_dataset(disk), format!("{}/", r.dataset()));
        let rounds = z.volumes_under(&r.dataset()).await?.len();
        for _ in 0..=rounds {
            match z.origin(&live).await? {
                Some((ds, _)) if ds.starts_with(&inside) => z.promote(&live).await?,
                _ => return Ok(()),
            }
        }
        Err(anyhow!(
            "{live} still a clone of its own machine after {rounds} promotions"
        ))
    }

    /// Removes what no longer serves, its lock held: memory files no snapshot names, then,
    /// until nothing more goes, a snapshot nothing clones that is an `s_` the record does not
    /// name for that disk, a fork's, or, on a retired disk, anything but a named one; then a
    /// retired disk that holds neither a named snapshot nor one something clones. A retired
    /// disk that stays is rolled back to its newest snapshot, freeing the state it was retired
    /// with. Returns the machines a destroyed retired disk was cloned from: their snapshot may
    /// be free now. A crash that leaves memory files also leaves their unnamed `s_` snapshot
    /// (the disks are snapshotted first), so the daemon's start tidies that machine.
    pub(super) async fn tidy(&self, e: &Entry) -> Result<Vec<String>> {
        let r = e.snapshot();
        if r.restoring.is_some() {
            return Ok(Vec::new());
        }
        self.remove_stray_memory(&r);
        let z = &self.inner.zfs;
        let named = named(&r);
        let mut parents = Vec::new();
        loop {
            if !z.exists(&r.dataset()).await? {
                return Ok(parents);
            }
            let tree = z.snapshot_tree(&r.dataset()).await?;
            let mut gone = 0;
            for s in tree.iter().filter(|s| unwanted(&r, &named, s)) {
                z.destroy_snapshot(&s.dataset, &s.snap).await?;
                tracing::info!(
                    machine = r.id,
                    dataset = s.dataset,
                    snapshot = s.snap,
                    why = "named by nothing, cloned by nothing",
                    "snapshot destroyed"
                );
                gone += 1;
            }
            if gone > 0 {
                continue;
            }
            for ds in z.volumes_under(&r.dataset()).await? {
                let Some((disk, false)) = lineage(&r, &ds) else {
                    continue;
                };
                let mut mine = tree.iter().filter(|s| s.dataset == ds);
                let held = mine
                    .clone()
                    .any(|s| !s.clones.is_empty() || named.contains(&(disk, s.snap.as_str())));
                if held {
                    // Back to its newest snapshot: what it held past that served nothing.
                    if let Some(newest) = mine.next_back() {
                        z.rollback(&ds, &newest.snap).await?;
                    }
                    continue;
                }
                if let Some((origin, _)) = z.origin(&ds).await? {
                    if let Some(m) = machine_of(&origin).filter(|m| *m != r.id) {
                        parents.push(m.to_string());
                    }
                }
                z.destroy(&ds).await?;
                tracing::info!(
                    machine = r.id,
                    dataset = ds,
                    why = "no named snapshot, nothing cloned",
                    "retired disk destroyed"
                );
                gone += 1;
            }
            if gone == 0 {
                return Ok(parents);
            }
        }
    }

    /// At the daemon's start: each restore cut short is finished, and each machine with
    /// something to tidy is tidied, found in one listing of the pool. How many machines it
    /// changed.
    pub(super) async fn tidy_at_start(&self) -> usize {
        let z = &self.inner.zfs;
        let (tree, volumes) = match (z.snapshot_tree("m").await, z.volumes_under("m").await) {
            (Ok(t), Ok(v)) => (t, v),
            (Err(err), _) | (_, Err(err)) => {
                tracing::warn!(err = %err, "snapshots not tidied at start");
                return 0;
            }
        };
        let entries: Vec<Arc<Entry>> = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        let (mut parents, mut changed) = (Vec::new(), 0);
        for e in entries {
            let r = e.snapshot();
            let named = named(&r);
            let untidy = r.restoring.is_some()
                || tree.iter().any(|s| unwanted(&r, &named, s))
                || volumes
                    .iter()
                    .any(|v| matches!(lineage(&r, v), Some((_, false))));
            if !untidy {
                continue;
            }
            // Uncontended before the API serves, taken all the same: what these assume.
            let done = {
                let _turns = e.lock_with_turn().await;
                match r.restoring.is_some() {
                    true => self.finish_restore(&e).await,
                    false => self.tidy(&e).await.map_err(MError::from),
                }
            };
            match done {
                Ok(more) => {
                    parents.extend(more);
                    changed += 1;
                }
                Err(err) => {
                    tracing::warn!(machine = r.id, err = %err, "snapshots not tidied at start")
                }
            }
        }
        self.tidy_machines(parents).await;
        changed
    }

    /// `tidy` where its work is done already (a disk swapped): a failure is a warning, and
    /// the next tidy or the daemon's start does it.
    pub(super) async fn tidy_or_warn(&self, e: &Entry) -> Vec<String> {
        self.tidy(e).await.unwrap_or_else(|err| {
            tracing::warn!(machine = e.snapshot().id, err = %err, "snapshots not tidied");
            Vec::new()
        })
    }

    /// `tidy_machines` from under a machine's lock: in a task of its own, which takes each
    /// lock once the caller has released its own.
    pub(super) fn tidy_later(&self, ids: Vec<String>) {
        if ids.is_empty() {
            return;
        }
        let m = self.clone();
        tokio::spawn(async move { m.tidy_machines(ids).await });
    }

    /// Tidies each machine named, under its lock, and those their tidying names in turn. A
    /// failure is a warning: the next tidy or the daemon's start does it.
    pub(super) async fn tidy_machines(&self, mut ids: Vec<String>) {
        while let Some(id) = ids.pop() {
            let Ok(e) = self.entry(&id) else {
                continue;
            };
            let _lock = e.lock.lock().await;
            if !self.holds(&e) {
                continue;
            }
            match self.tidy(&e).await {
                Ok(more) => ids.extend(more),
                Err(err) => tracing::warn!(machine = id, err = %err, "snapshots not tidied"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{grow_to, harness_config, with_volume, Harness};
    use super::*;

    const IMAGE3: &str =
        "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000003";

    async fn harness() -> Harness {
        let h = harness_config(|cfg| {
            cfg.network.range = "10.64.0.0/22".into();
            cfg.capacity = crate::config::Capacity {
                memory_mb: 4096,
                vcpus: 1000,
                ..Default::default()
            };
            cfg.egress_limits = crate::config::EgressLimits {
                blocked_ports: vec![],
                new_connections_per_minute: 0,
                bandwidth_mbit: 0,
            };
            cfg.backup.store = format!("file://{}", cfg.data_dir.join("store").display());
        })
        .await;
        h.ready().await;
        h
    }

    fn named(name: &str) -> api::SnapshotRequest {
        api::SnapshotRequest {
            name: Some(name.into()),
            memory: false,
        }
    }

    fn with_memory() -> api::SnapshotRequest {
        api::SnapshotRequest {
            name: None,
            memory: true,
        }
    }

    impl Harness {
        /// The machine's datasets, sorted: its disks and the ones they retired.
        async fn datasets(&self, id: &str) -> Vec<String> {
            let mut v = self
                .pool
                .zfs
                .volumes_under(&format!("m/{id}"))
                .await
                .unwrap();
            v.sort();
            v
        }

        /// Its retired root disks.
        async fn retired(&self, id: &str) -> Vec<String> {
            let root = format!("m/{id}/root.");
            let all = self.datasets(id).await;
            all.into_iter().filter(|d| d.starts_with(&root)).collect()
        }

        async fn origin(&self, ds: &str) -> Option<(String, String)> {
            self.pool.zfs.origin(ds).await.unwrap()
        }

        fn snapshot_ids(&self, id: &str) -> Vec<String> {
            self.stored(id)
                .unwrap()
                .snapshots
                .iter()
                .map(|s| s.id.clone())
                .collect()
        }

        fn restored_data(&self, id: &str) -> serde_json::Value {
            self.events_of(id)
                .into_iter()
                .rev()
                .find(|e| e.reason == reason::RESTORED)
                .and_then(|e| e.data)
                .unwrap()
        }
    }

    #[tokio::test]
    async fn a_snapshot_is_taken_named_listed_and_deleted() {
        let h = harness().await;
        let e = h.add("m_s", state::STOPPED, 256);
        h.disks(&e).await;
        let v0 = e.snapshot().version;
        let a = h.m.snapshot("m_s", named("before")).await.unwrap();
        // Both disks at one instant, one `zfs snapshot`.
        assert!(h.snapshot_exists("m/m_s/root", &a.id));
        assert!(h.snapshot_exists("m/m_s/data", &a.id));
        assert!(h.pool.calls().contains(&format!(
            "snapshot byard/m/m_s/root@{0} byard/m/m_s/data@{0}",
            a.id
        )));
        assert_eq!(
            (a.name.as_deref(), a.disks.clone(), a.memory),
            (
                Some("before"),
                vec!["root".to_string(), "data".to_string()],
                false
            )
        );
        assert!(e.snapshot().version > v0);
        let b =
            h.m.snapshot("m_s", api::SnapshotRequest::default())
                .await
                .unwrap();
        let listed = h.m.snapshots("m_s").await.unwrap();
        assert_eq!(
            listed.iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
            [a.id.clone(), b.id.clone()]
        );
        assert_eq!(listed[0].created_at, a.created_at);
        assert_eq!(h.reasons("m_s"), ["snapshot_taken", "snapshot_taken"]);
        // A name is the machine's once; it is not an id's shape; memory needs a process.
        assert!(matches!(
            h.m.snapshot("m_s", named("before")).await,
            Err(MError::Conflict(_))
        ));
        assert!(matches!(
            h.m.snapshot("m_s", named("s_1")).await,
            Err(MError::Invalid(_))
        ));
        assert!(matches!(
            h.m.snapshot("m_s", with_memory()).await,
            Err(MError::NotRunning(_))
        ));
        // Deleted by name: both disks' snapshots go; missing again is success.
        h.m.delete_snapshot("m_s", "before").await.unwrap();
        assert!(!h.snapshot_exists("m/m_s/root", &a.id));
        assert!(!h.snapshot_exists("m/m_s/data", &a.id));
        assert_eq!(h.snapshot_ids("m_s"), std::slice::from_ref(&b.id));
        h.m.delete_snapshot("m_s", "before").await.unwrap();
        h.m.delete_snapshot("m_s", "fork-x").await.unwrap();
        assert_eq!(h.reasons("m_s").last().unwrap(), "snapshot_deleted");
        assert!(matches!(
            h.m.snapshots("m_none").await,
            Err(MError::NotFound)
        ));
        assert!(matches!(
            h.m.restore_snapshot("m_s", "before", None).await,
            Err(MError::NoSnapshot(_))
        ));
    }

    #[tokio::test]
    async fn a_restore_swaps_the_disk_and_keeps_newer_snapshots_and_forks() {
        let h = harness().await;
        let src = h.m.create(h.request("src")).await.unwrap();
        let s1 = h.m.snapshot(&src.id, named("one")).await.unwrap();
        let fork = h.fork(&src.id, "fork").await;
        let fork_snap = format!("fork-{}", fork.id);
        let s2 =
            h.m.snapshot(&src.id, api::SnapshotRequest::default())
                .await
                .unwrap();
        h.host_calls();
        let m = h.m.restore_snapshot(&src.id, "one", None).await.unwrap();
        // Running before, so stopped, swapped and booted again.
        assert_eq!(m.state, state::RUNNING);
        let calls = h.host_calls();
        assert!(calls.iter().any(|c| c.starts_with(&format!("boot {} ", src.id)) && c.ends_with("resume=false")), "{calls:?}");
        let tail: Vec<String> = h.reasons(&src.id).into_iter().rev().take(5).rev().collect();
        assert_eq!(
            tail,
            ["stopping", "stopped", "restored", "starting", "started"]
        );
        assert_eq!(h.restored_data(&src.id)["snapshot"], s1.id.as_str());
        // The disk in use is a clone of the snapshot, promoted: it holds the snapshot, and its
        // origin is the image's, as before.
        let root = format!("m/{}/root", src.id);
        assert!(h.snapshot_exists(&root, &s1.id));
        assert!(!h.snapshot_exists(&root, &s2.id));
        assert!(h.origin(&root).await.unwrap().0.starts_with("images/"));
        // The disk it replaced is retired, holding the newer snapshot and the fork's.
        let retired = h.retired(&src.id).await;
        assert_eq!(retired.len(), 1, "{retired:?}");
        assert!(h.snapshot_exists(&retired[0], &s2.id));
        assert!(h.snapshot_exists(&retired[0], &fork_snap));
        let fork_root = format!("m/{}/root", fork.id);
        assert_eq!(
            h.origin(&fork_root).await,
            Some((retired[0].clone(), fork_snap.clone()))
        );
        assert_eq!(h.snapshot_ids(&src.id), [s1.id.clone(), s2.id.clone()]);
        // Forward again, to the newer one: every snapshot back on the disk in use, the fork's
        // with it, nothing retired left.
        h.m.restore_snapshot(&src.id, &s2.id, None).await.unwrap();
        for s in [&s1.id, &s2.id, &fork_snap] {
            assert!(h.snapshot_exists(&root, s), "{s}");
        }
        assert_eq!(h.datasets(&src.id).await, std::slice::from_ref(&root));
        assert_eq!(h.origin(&fork_root).await, Some((root.clone(), fork_snap)));
        assert_eq!(h.m.get(&fork.id).unwrap().state, state::RUNNING);
    }

    /// The restore of RISE-M (ADR 0046): udev drops every event from the snapshot on, so the
    /// link at the root disk's name still names the disk the restore retired, then destroyed.
    /// The machine boots on the clone's device all the same, never on the retired disk's.
    #[tokio::test(start_paused = true)]
    async fn a_restore_boots_the_new_disk_whatever_udev_missed() {
        use std::os::unix::fs::MetadataExt;
        let h = harness().await;
        let m = h.m.create(h.request("m")).await.unwrap();
        let root = h.pool.dev().join(format!("byard/m/{}/root", m.id));
        let before = std::fs::metadata(&root).unwrap().ino();
        let s = h.m.snapshot(&m.id, named("one")).await.unwrap();
        std::fs::write(h.pool.dev().join("udev.drop"), "").unwrap();
        h.m.restore_snapshot(&m.id, &s.id, None).await.unwrap();
        assert!(h.retired(&m.id).await.is_empty(), "the retired disk went");
        let booted = h.booted_root(&m.id);
        let ino = std::fs::metadata(&booted).unwrap().ino();
        assert_ne!(ino, before, "booted on the retired disk");
        assert_eq!(ino, std::fs::metadata(&root).unwrap().ino());
    }

    #[tokio::test]
    async fn deleted_snapshots_a_retired_disk_hangs_from_go_with_it() {
        let h = harness().await;
        let src = h.m.create(h.request("src")).await.unwrap();
        let root = format!("m/{}/root", src.id);
        let s1 =
            h.m.snapshot(&src.id, api::SnapshotRequest::default())
                .await
                .unwrap();
        let s2 =
            h.m.snapshot(&src.id, api::SnapshotRequest::default())
                .await
                .unwrap();
        h.m.restore_snapshot(&src.id, &s1.id, None).await.unwrap();
        // The retired disk holding s2 is a clone of s1: s1 leaves the list, its blocks stay.
        h.m.delete_snapshot(&src.id, &s1.id).await.unwrap();
        assert_eq!(h.snapshot_ids(&src.id), std::slice::from_ref(&s2.id));
        assert!(h.snapshot_exists(&root, &s1.id));
        // With s2 gone, nothing needs the retired disk, then nothing clones s1.
        h.m.delete_snapshot(&src.id, &s2.id).await.unwrap();
        assert_eq!(h.datasets(&src.id).await, std::slice::from_ref(&root));
        assert!(!h.snapshot_exists(&root, &s1.id));
    }

    #[tokio::test]
    async fn a_fork_that_goes_frees_the_retired_disk_it_held() {
        let h = harness().await;
        let src = h.m.create(h.request("src")).await.unwrap();
        let s1 =
            h.m.snapshot(&src.id, api::SnapshotRequest::default())
                .await
                .unwrap();
        let fork = h.fork(&src.id, "fork").await;
        h.m.restore_snapshot(&src.id, &s1.id, None).await.unwrap();
        assert_eq!(h.retired(&src.id).await.len(), 1);
        h.m.destroy(&fork.id, None).await.unwrap();
        assert!(h.retired(&src.id).await.is_empty());
        // And the source, destroyed, leaves nothing.
        h.m.destroy(&src.id, None).await.unwrap();
        assert!(!h.pool.dev().join(format!("byard/m/{}", src.id)).exists());
    }

    #[tokio::test]
    async fn a_destroyed_source_promotes_a_fork_of_its_retired_disk() {
        let h = harness().await;
        let src = h.m.create(h.request("src")).await.unwrap();
        let s1 =
            h.m.snapshot(&src.id, api::SnapshotRequest::default())
                .await
                .unwrap();
        let fork = h.fork(&src.id, "fork").await;
        h.m.restore_snapshot(&src.id, &s1.id, None).await.unwrap();
        // The fork clones the retired disk, which clones the source's: promoted twice, it
        // owns its history, and keeps none of the source's snapshots.
        h.m.destroy(&src.id, None).await.unwrap();
        let fork_root = format!("m/{}/root", fork.id);
        assert!(h.origin(&fork_root).await.unwrap().0.starts_with("images/"));
        let left = h.pool.zfs.snapshots(&fork_root).await.unwrap();
        assert!(left.is_empty(), "{left:?}");
        assert_eq!(h.m.get(&fork.id).unwrap().state, state::RUNNING);
    }

    #[tokio::test]
    async fn a_backup_after_a_restore_continues_from_an_ancestor_or_is_whole() {
        let h = harness().await;
        let m = h.m.create(h.request("db")).await.unwrap();
        let b1 = h.m.backup(&m.id).await.unwrap();
        let s =
            h.m.snapshot(&m.id, api::SnapshotRequest::default())
                .await
                .unwrap();
        h.m.restore_snapshot(&m.id, &s.id, None).await.unwrap();
        // b1 was made before the snapshot: still in the disk's history, a base.
        let b2 = h.m.backup(&m.id).await.unwrap();
        assert_eq!(b2.disks[0].from.as_deref(), Some(b1.id.as_str()));
        // b2 was made after it: retired and freed by the restore, so the next is whole.
        h.m.restore_snapshot(&m.id, &s.id, None).await.unwrap();
        assert!(!h.snapshot_exists(&format!("m/{}/root", m.id), &format!("bk-{}", b2.id)));
        assert!(h.retired(&m.id).await.is_empty());
        let b3 = h.m.backup(&m.id).await.unwrap();
        assert!(!b3.incremental, "{b3:?}");
        // Both chains restore.
        for (name, b) in [("r2", &b2), ("r3", &b3)] {
            let r =
                h.m.create(api::CreateMachineRequest {
                    tenant: "t1".into(),
                    name: name.into(),
                    restore: Some(api::RestoreSpec {
                        machine_id: m.id.clone(),
                        backup: b.id.clone(),
                    }),
                    start: Some(false),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert_eq!(r.state, state::CREATED);
        }
    }

    #[tokio::test]
    async fn a_restore_keeps_a_grown_volume_and_never_resumes_the_smaller_disks_memory() {
        let h = harness().await;
        with_volume(&h, "m_v", state::STOPPED, 2).await;
        h.m.start("m_v", None).await.unwrap();
        h.m.snapshot("m_v", named("small")).await.unwrap();
        h.m.snapshot("m_v", with_memory()).await.unwrap();
        let warm = h.snapshot_ids("m_v")[1].clone();
        h.m.update("m_v", grow_to(5), None).await.unwrap();
        // Taken while the growth waits for a boot: its memory is the smaller disk's too.
        h.m.snapshot("m_v", with_memory()).await.unwrap();
        let waiting = h.snapshot_ids("m_v")[2].clone();
        h.m.restart("m_v", None).await.unwrap();
        h.m.stop("m_v", Duration::ZERO, false, None).await.unwrap();
        assert!(h.m.get("m_v").unwrap().pending.is_none());
        // Back to a snapshot of the smaller disk: the volume keeps its size, its filesystem
        // is the snapshot's until the next boot.
        let m = h.m.restore_snapshot("m_v", "small", None).await.unwrap();
        assert_eq!(h.pool.zfs.volsize("m/m_v/data").await.unwrap(), 5 << 30);
        assert_eq!(m.volume.map(|v| v.size_gb), Some(5));
        assert_eq!(
            m.pending.and_then(|p| p.volume),
            Some(api::VolumeSize { size_gb: 5 })
        );
        h.m.start("m_v", None).await.unwrap();
        // A running machine's restore boots it, cold: that boot grows the filesystem.
        for snap in [&warm, &waiting] {
            h.host_calls();
            let m = h.m.restore_snapshot("m_v", snap, None).await.unwrap();
            assert!(m.pending.is_none(), "{snap}");
            let calls = h.host_calls();
            assert!(
                calls.iter().any(|c| c.ends_with(" resume=false")),
                "{snap}: {calls:?}"
            );
            assert_eq!(h.restored_data("m_v")["memory"], false, "{snap}");
        }
    }

    #[tokio::test]
    async fn a_restore_cut_short_after_the_growth_still_leaves_the_filesystem_pending() {
        let h = harness().await;
        let e = with_volume(&h, "m_v", state::STOPPED, 2).await;
        let s = h.m.snapshot("m_v", named("small")).await.unwrap();
        h.m.update("m_v", grow_to(5), None).await.unwrap();
        h.m.restart("m_v", None).await.unwrap();
        h.m.stop("m_v", Duration::ZERO, false, None).await.unwrap();
        // The disks swapped and the volume grown back, then the daemon stopped before the
        // record said so: the record still has the intent, nothing pending.
        h.m.restore_snapshot("m_v", "small", None).await.unwrap();
        {
            let mut r = e.rec.lock().unwrap();
            r.pending = None;
            r.restoring = Some(s.id.clone());
        }
        h.m.finish_restore(&e).await.unwrap();
        assert_eq!(h.pool.zfs.volsize("m/m_v/data").await.unwrap(), 5 << 30);
        assert_eq!(
            h.m.get("m_v").unwrap().pending.and_then(|p| p.volume),
            Some(api::VolumeSize { size_gb: 5 })
        );
    }

    #[tokio::test]
    async fn a_restore_checks_the_version_and_keeps_a_stopped_machine_stopped() {
        let h = harness().await;
        let m = h.m.create(h.request("m")).await.unwrap();
        let s =
            h.m.snapshot(&m.id, api::SnapshotRequest::default())
                .await
                .unwrap();
        let v = h.m.get(&m.id).unwrap().version;
        assert!(matches!(
            h.m.restore_snapshot(&m.id, &s.id, Some(v - 1)).await,
            Err(MError::Moved(_))
        ));
        // Suspended: the memory of the old disks is dropped, the machine stays stopped.
        h.m.stop(&m.id, Duration::ZERO, true, None).await.unwrap();
        assert!(h.stored(&m.id).unwrap().suspended);
        h.host_calls();
        let v = h.m.get(&m.id).unwrap().version;
        let r = h.m.restore_snapshot(&m.id, &s.id, Some(v)).await.unwrap();
        assert_eq!(r.state, state::STOPPED);
        assert!(!h.stored(&m.id).unwrap().suspended);
        assert!(!h.host_calls().iter().any(|c| c.starts_with("boot ")));
        assert!(r.version > v);
    }

    #[tokio::test]
    async fn a_restore_cut_short_is_finished_by_the_daemon_or_a_start() {
        let h = harness().await;
        let m = h.m.create(h.request("m")).await.unwrap();
        let s =
            h.m.snapshot(&m.id, api::SnapshotRequest::default())
                .await
                .unwrap();
        h.m.stop(&m.id, Duration::ZERO, false, None).await.unwrap();
        let e = h.m.entry(&m.id).unwrap();
        let root = format!("m/{}/root", m.id);
        // Cut between the renames: the disk renamed aside, its clone beside it.
        e.rec.lock().unwrap().restoring = Some(s.id.clone());
        let z = &h.pool.zfs;
        z.rename(&root, &format!("{root}.r_cut")).await.unwrap();
        z.clone_snapshot(&format!("{root}.r_cut"), &s.id, &format!("{root}.next"))
            .await
            .unwrap();
        // Half swapped: no backup sends it, no fork copies it, no snapshot is taken of it.
        assert!(matches!(h.m.backup(&m.id).await, Err(MError::BadState(_))));
        assert!(matches!(
            h.m.snapshot(&m.id, api::SnapshotRequest::default()).await,
            Err(MError::BadState(_))
        ));
        h.m.sweep_orphans().await;
        assert_eq!(h.datasets(&m.id).await, std::slice::from_ref(&root));
        assert!(h.snapshot_exists(&root, &s.id));
        assert!(h.stored(&m.id).unwrap().restoring.is_none());
        assert_eq!(h.reasons(&m.id).last().unwrap(), "restored");
        // Cut right after its intent: the next start finishes it before it boots.
        e.rec.lock().unwrap().restoring = Some(s.id.clone());
        h.m.start(&m.id, None).await.unwrap();
        let tail: Vec<String> = h.reasons(&m.id).into_iter().rev().take(3).rev().collect();
        assert_eq!(tail, ["starting", "restored", "started"]);
        assert_eq!(h.datasets(&m.id).await, [root]);
    }

    #[tokio::test]
    async fn a_tidy_that_fails_after_the_swap_does_not_fail_the_restore() {
        let h = harness().await;
        let m = h.m.create(h.request("m")).await.unwrap();
        let s =
            h.m.snapshot(&m.id, api::SnapshotRequest::default())
                .await
                .unwrap();
        // Newer than the one restored and named by nothing: the tidy tries to destroy it,
        // and this `zfs` refuses.
        let root = format!("m/{}/root", m.id);
        h.pool.zfs.snapshot(&root, "s_boom").await.unwrap();
        let r = h.m.restore_snapshot(&m.id, &s.id, None).await.unwrap();
        assert_eq!(r.state, state::RUNNING);
        assert_eq!(h.restored_data(&m.id)["snapshot"], s.id.as_str());
        assert!(h.snapshot_exists(&root, &s.id));
    }

    #[tokio::test]
    async fn a_restore_during_a_stop_waits_for_it() {
        let h = harness().await;
        let m = h.m.create(h.request("m")).await.unwrap();
        let s =
            h.m.snapshot(&m.id, api::SnapshotRequest::default())
                .await
                .unwrap();
        let e = h.m.entry(&m.id).unwrap();
        h.stops_take(Duration::from_millis(300));
        let (m2, e2) = (h.m.clone(), e.clone());
        let sleep = tokio::spawn(async move {
            m2.stop_entry(&e2, stop::IDLE, Duration::from_secs(1), false, None)
                .await
                .unwrap()
        });
        while e.snapshot().state != state::STOPPING {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // Stopped by then: restored, and left stopped.
        let r = h.m.restore_snapshot(&m.id, &s.id, None).await.unwrap();
        assert_eq!(
            (r.state.as_str(), r.stopped_reason.as_str()),
            (state::STOPPED, stop::IDLE)
        );
        sleep.await.unwrap();
        assert_eq!(h.reasons(&m.id).last().unwrap(), "restored");
    }

    #[tokio::test]
    async fn a_memory_snapshot_never_writes_through_a_link_left_in_the_jail() {
        let h = harness().await;
        let m = h.m.create(h.request("m")).await.unwrap();
        let s1 = h.m.snapshot(&m.id, with_memory()).await.unwrap();
        let rec = h.stored(&m.id).unwrap();
        let kept = h.m.memory_files(&rec, &s1.id)[1].clone();
        std::fs::write(&kept, b"the first one").unwrap();
        // A restore's link, where Firecracker writes the next memory snapshot.
        let dir = h.m.inner.cfg.run_dir().join(&m.id);
        std::fs::hard_link(&kept, dir.join("snap.mem")).unwrap();
        h.m.snapshot(&m.id, with_memory()).await.unwrap();
        assert_eq!(std::fs::read(&kept).unwrap(), b"the first one");
    }

    #[tokio::test]
    async fn tidy_removes_memory_files_no_snapshot_names() {
        let h = harness().await;
        let m = h.m.create(h.request("m")).await.unwrap();
        let s1 = h.m.snapshot(&m.id, with_memory()).await.unwrap();
        let rec = h.stored(&m.id).unwrap();
        let kept = h.m.memory_files(&rec, &s1.id);
        // What a crash between the move of a memory snapshot's files and the record's save
        // leaves: files of a snapshot the record does not name.
        let stray = h.m.memory_files(&rec, "s_crashed");
        for f in &stray {
            std::fs::write(f, b"x").unwrap();
        }
        let other = h.m.memory_dir(&rec).join("notes");
        std::fs::write(&other, b"not ours").unwrap();
        let e = h.m.entry(&m.id).unwrap();
        h.m.tidy(&e).await.unwrap();
        assert!(stray.iter().all(|f| !f.exists()), "{stray:?}");
        assert!(kept.iter().all(|f| f.exists()), "{kept:?}");
        assert!(other.exists());
    }

    #[tokio::test]
    async fn a_snapshots_memory_resumes_only_under_the_vmm_that_took_it() {
        let h = harness().await;
        let m = h.m.create(h.request("m")).await.unwrap();
        let s = h.m.snapshot(&m.id, with_memory()).await.unwrap();
        let taken = h.stored(&m.id).unwrap();
        assert_eq!(taken.snapshots[0].vmm_version, "v1.17.0/test");
        // The same Firecracker and kernel: resumed.
        h.m.restore_snapshot(&m.id, &s.id, None).await.unwrap();
        assert_eq!(h.reasons(&m.id).last().unwrap(), "resumed");
        // Another (an upgrade since): the memory is put back, then not loaded; the boot is cold
        // and says why.
        h.set_vmm_version("v1.18.0/test");
        h.m.restore_snapshot(&m.id, &s.id, None).await.unwrap();
        assert_eq!(h.reasons(&m.id).last().unwrap(), "started");
        let starting = h
            .events_of(&m.id)
            .into_iter()
            .rev()
            .find(|e| e.reason == "starting")
            .unwrap();
        assert_eq!(
            starting.data,
            Some(json!({"resume": false, "snapshot_vmm": "v1.17.0/test"}))
        );
        assert_eq!(h.m.get(&m.id).unwrap().vmm_version, "v1.18.0/test");
    }

    #[tokio::test]
    async fn a_snapshot_with_memory_resumes_where_it_was_while_the_spec_is_the_same() {
        let h = harness().await;
        let m = h.m.create(h.request("m")).await.unwrap();
        let pid = h.stored(&m.id).unwrap().pid;
        h.host_calls();
        let s = h.m.snapshot(&m.id, with_memory()).await.unwrap();
        assert!(s.memory);
        // Paused for the snapshot, then running on: the same process.
        let calls = h.host_calls();
        // Unsynced while paused; the files synced by the daemon after the resume.
        assert_eq!(
            calls,
            [format!("snapshot {pid} unsynced"), format!("resume {pid}")]
        );
        assert_eq!(h.m.get(&m.id).unwrap().state, state::RUNNING);
        let rec = h.stored(&m.id).unwrap();
        let mem = h.m.memory_files(&rec, &s.id)[1].clone();
        assert!(mem.exists(), "{}", mem.display());
        // Restored: resumed from it, and the snapshot keeps it for the next restore.
        for _ in 0..2 {
            h.m.restore_snapshot(&m.id, &s.id, None).await.unwrap();
            assert_eq!(h.restored_data(&m.id)["memory"], true);
            assert_eq!(h.reasons(&m.id).last().unwrap(), "resumed");
            assert!(mem.exists());
        }
        // Another spec since: the processes it holds are not this machine's any more.
        let mut env = BTreeMap::new();
        env.insert("V".to_string(), "2".to_string());
        let patch = api::UpdateMachineRequest {
            spec: api::SpecChange {
                env: Some(env),
                ..Default::default()
            },
            ..Default::default()
        };
        h.m.update(&m.id, patch, None).await.unwrap();
        h.m.restart(&m.id, None).await.unwrap();
        h.m.restore_snapshot(&m.id, &s.id, None).await.unwrap();
        assert_eq!(h.restored_data(&m.id)["memory"], false);
        assert_eq!(h.reasons(&m.id).last().unwrap(), "started");
        h.m.delete_snapshot(&m.id, &s.id).await.unwrap();
        assert!(!mem.exists());
    }

    #[tokio::test]
    async fn a_new_image_drops_the_root_halves_and_keeps_the_old_root_for_its_forks() {
        let h = harness().await;
        h.m.inner
            .images
            .seed(IMAGE3, ImageConfig::default())
            .await
            .unwrap();
        let m = h.m.create(h.request("m")).await.unwrap();
        let root = format!("m/{}/root", m.id);
        let first = h.origin(&root).await;
        let s =
            h.m.snapshot(&m.id, api::SnapshotRequest::default())
                .await
                .unwrap();
        let fork = h.fork(&m.id, "fork").await;
        let patch = api::UpdateMachineRequest {
            spec: api::SpecChange {
                image: Some(IMAGE3.into()),
                ..Default::default()
            },
            ..Default::default()
        };
        h.m.update(&m.id, patch, None).await.unwrap();
        h.m.restart(&m.id, None).await.unwrap();
        // The snapshot held the root disk only: it goes with it.
        assert!(
            h.snapshot_ids(&m.id).is_empty(),
            "{:?}",
            h.snapshot_ids(&m.id)
        );
        let now = h.origin(&root).await.unwrap();
        assert!(
            now.0.starts_with("images/") && Some(&now) != first.as_ref(),
            "{now:?}"
        );
        // The old root disk, retired, stays while the fork clones it; its other snapshots go.
        let retired = h.retired(&m.id).await;
        assert_eq!(retired.len(), 1);
        assert!(!h.snapshot_exists(&retired[0], &s.id));
        h.m.destroy(&fork.id, None).await.unwrap();
        assert!(h.retired(&m.id).await.is_empty());
    }
}
