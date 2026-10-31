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
        if !r.has_disks() {
            return Err(super::made_never(&r));
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
            self.stop_locked(&e, format!("to restore {}", s.id)).await?;
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
    async fn stop_locked(&self, e: &Arc<Entry>, why: String) -> Result<()> {
        e.set_state(state::STOPPING, |_| {
            Some(
                Ev::normal(reason::STOPPING, format!("stopping ({why})"))
                    .data(json!({ "reason": stop::USER, "suspend": false })),
            )
        });
        let _ = self.save(e);
        let live = e.live.lock().unwrap().clone();
        if let Some(live) = live {
            self.end_process(e, &live, Duration::from_secs(10)).await?;
        }
        self.settle_stopped(e, stop::USER);
        Ok(())
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
mod tests;
