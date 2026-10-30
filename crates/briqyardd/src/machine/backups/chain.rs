//! Backups as chains: whole and incremental, what to prune and what depends on what.

use super::*;

/// `backup_deleted` for these ids, when there are any.
pub(super) fn deleted_event(ids: &[String], why: &str) -> Option<Ev> {
    (!ids.is_empty()).then(|| {
        Ev::normal(
            reason::BACKUP_DELETED,
            format!("backups deleted ({why}): {}", ids.join(", ")),
        )
        .data(json!({ "backups": ids, "reason": why }))
    })
}

/// The newest backup snapshot (`bk-<id>`) among a dataset's snapshots: the base of the next
/// incremental send.
pub(super) fn newest_backup_snapshot(snaps: &[String]) -> Option<String> {
    snaps.iter().filter(|s| s.starts_with("bk-")).max().cloned()
}

/// Whether a snapshot `bk-<id>` is the snapshot of a backup in `all` holding that disk, sent
/// raw under the key `key_id`.
pub(super) fn in_store(all: &[api::Backup], snap: &str, disk: &str, key_id: &str) -> bool {
    let id = snap.trim_start_matches("bk-");
    all.iter().any(|b| {
        b.id == id && b.key_id.as_deref() == Some(key_id) && b.disks.iter().any(|d| d.disk == disk)
    })
}

pub(super) fn is_whole(b: &api::Backup) -> bool {
    b.disks.iter().all(|d| d.from.is_none())
}

/// How many backups the newest chain holds: from the newest back to the whole one it starts
/// from (all of them when none is whole).
pub(super) fn chain_length(all: &[api::Backup]) -> usize {
    match all.iter().rposition(is_whole) {
        Some(i) => all.len() - i,
        None => all.len(),
    }
}

/// What retention deletes from `all` (oldest first): every backup that is neither among the
/// newest `keep` nor a base of one of them. Bases are older, so one pass from the newest
/// finds them all.
pub(super) fn prune(all: &[api::Backup], keep: usize) -> Vec<&api::Backup> {
    let mut kept: HashSet<&str> = all.iter().rev().take(keep).map(|b| b.id.as_str()).collect();
    for b in all.iter().rev() {
        if kept.contains(b.id.as_str()) {
            kept.extend(b.disks.iter().filter_map(|d| d.from.as_deref()));
        }
    }
    all.iter()
        .filter(|b| !kept.contains(b.id.as_str()))
        .collect()
}

/// The backups (their places in `all`, oldest first) that continue from `all[target]`, at
/// any distance. Each continues from an older one, so one pass in order finds them.
pub(super) fn dependents(all: &[api::Backup], target: usize) -> Vec<usize> {
    let mut gone: HashSet<&str> = HashSet::from([all[target].id.as_str()]);
    let mut out = Vec::new();
    for (i, b) in all.iter().enumerate().skip(target + 1) {
        if b.disks
            .iter()
            .any(|d| d.from.as_deref().is_some_and(|f| gone.contains(f)))
        {
            gone.insert(&b.id);
            out.push(i);
        }
    }
    out
}

/// The streams to receive, oldest first, to get one disk of a backup: the backup's own stream
/// preceded by the ones it continues from, back to a whole one.
pub(super) fn backup_chain<'a>(
    all: &'a [api::Backup],
    target: &'a api::Backup,
    disk: &str,
) -> Vec<&'a api::BackupDisk> {
    let mut chain = Vec::new();
    let mut cur = target.disks.iter().find(|d| d.disk == disk);
    let mut guard = 0;
    while let Some(d) = cur {
        chain.push(d);
        guard += 1;
        cur = match &d.from {
            Some(from) if guard < 10_000 => all
                .iter()
                .find(|b| &b.id == from)
                .and_then(|b| b.disks.iter().find(|x| x.disk == disk)),
            _ => None,
        };
    }
    chain.reverse();
    chain
}
