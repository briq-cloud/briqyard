//! A backup in flight, written down before its first byte, so that a kill does not leave its
//! stream in the store with nothing to own it (ADR 0100).

use super::*;

/// The local store's kind for backups in flight.
pub(super) const ATTEMPTS: &str = "backup-attempts";

/// The disks a backup sends, which name its streams.
const DISKS: [&str; 2] = ["root", "data"];

/// One backup under way: the machine, the backup's id (a millisecond timestamp, unique to
/// this attempt), and the disks whose streams it will send.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(in super::super) struct Attempt {
    pub machine_id: String,
    pub id: String,
    pub disks: Vec<String>,
}

/// The backup id's shape: `%Y%m%dT%H%M%S%.3fZ`, as `send_backup` makes it.
fn is_backup_id(id: &str) -> bool {
    id.len() == 20
        && id.bytes().enumerate().all(|(i, b)| match i {
            8 => b == b'T',
            15 => b == b'.',
            19 => b == b'Z',
            _ => b.is_ascii_digit(),
        })
}

impl Attempt {
    pub fn new(machine_id: &str, id: &str, disks: &[&str]) -> Self {
        Self {
            machine_id: machine_id.into(),
            id: id.into(),
            disks: disks.iter().map(|d| d.to_string()).collect(),
        }
    }

    /// The marker's file name in the local store.
    pub fn key(&self) -> String {
        format!("{}.{}", self.machine_id, self.id)
    }

    /// Whether every field is what `send_backup` writes. A marker that is not is never acted
    /// on: its names would reach the store.
    fn valid(&self) -> bool {
        api::valid_id(&self.machine_id)
            && is_backup_id(&self.id)
            && !self.disks.is_empty()
            && self.disks.iter().all(|d| DISKS.contains(&d.as_str()))
    }

    /// The record that makes the backup exist.
    fn record(&self) -> String {
        format!("backups/{}/{}.json", self.machine_id, self.id)
    }

    /// The streams it sends, as `send_backup` names them.
    fn streams(&self) -> Vec<String> {
        self.disks
            .iter()
            .map(|d| format!("backups/{}/{d}/{}.zfs", self.machine_id, self.id))
            .collect()
    }
}

/// What a listing of the machine's prefix says about an attempt.
#[derive(Debug, PartialEq)]
pub(super) enum Verdict {
    /// The record is listed: the backup exists, whatever else.
    Finished,
    /// No record: these of its streams are listed, and only these may go (none: nothing to do).
    Streams(Vec<String>),
}

impl Attempt {
    pub(super) fn verdict(&self, listed: &[String]) -> Verdict {
        if listed.contains(&self.record()) {
            return Verdict::Finished;
        }
        Verdict::Streams(
            self.streams()
                .into_iter()
                .filter(|s| listed.contains(s))
                .collect(),
        )
    }
}

impl Manager {
    /// Written durably before the first stream: from here a kill leaves a marker to find.
    pub(super) fn begin_attempt(&self, attempt: &Attempt) -> Result<()> {
        self.inner
            .store
            .put_durable(ATTEMPTS, &attempt.key(), attempt)
            .context("backup marker")
    }

    /// The backup is a record in the store, or its streams are gone: the marker has no more
    /// to say. A failure leaves it, which is safe: the next start reads it again.
    pub(super) fn end_attempt(&self, attempt: &Attempt) {
        if let Err(err) = self.inner.store.delete_durable(ATTEMPTS, &attempt.key()) {
            tracing::warn!(machine = attempt.machine_id, backup = attempt.id, err = %err, "backup marker kept");
        }
    }

    /// The markers a previous process left: backups under way when it ended. Read at start,
    /// before any backup of this process can write one.
    pub(in super::super) fn attempts_left(&self) -> Vec<Attempt> {
        let keys = match self.inner.store.keys(ATTEMPTS) {
            Ok(keys) => keys,
            Err(err) => {
                tracing::warn!(err = %err, "backup markers not read");
                return Vec::new();
            }
        };
        keys.into_iter()
            .filter_map(|key| match self.inner.store.get::<Attempt>(ATTEMPTS, &key) {
                Ok(attempt) => attempt,
                Err(err) => {
                    tracing::warn!(marker = key, err = %format!("{err:#}"), "backup marker unreadable, kept");
                    None
                }
            })
            .collect()
    }

    /// Removes the streams of backups that never finished. Only a marker of this host's own,
    /// with no record in the store, gives a stream away; a record keeps everything (a kill
    /// between the record and the end of the marker), and so does any doubt: a marker whose
    /// names are not ours, a store that does not answer, a delete that fails. Those stay for
    /// the next start. Objects with no marker are not touched.
    pub(in super::super) async fn settle_attempts(&self, left: Vec<Attempt>) {
        let Ok(store) = self.backup_store() else {
            return;
        };
        for attempt in left {
            if !attempt.valid() {
                tracing::warn!(
                    machine = attempt.machine_id,
                    "backup marker with names that are not ours, kept"
                );
                continue;
            }
            // A listing, not a GET: the object store reports "not found" for an object that is
            // absent and also for a 404 from a missing bucket or a degraded node, and a false
            // "no record" would delete a whole backup. Only a listing that answers, shows the
            // streams and shows no record gives them away.
            let listed = match store
                .list(&format!("backups/{}/", attempt.machine_id))
                .await
            {
                Ok(listed) => listed,
                Err(err) => {
                    tracing::warn!(machine = attempt.machine_id, backup = attempt.id, err = %format!("{err:#}"), "backup marker kept: the store could not be listed");
                    continue;
                }
            };
            let streams = match attempt.verdict(&listed) {
                Verdict::Finished => {
                    tracing::debug!(
                        machine = attempt.machine_id,
                        backup = attempt.id,
                        "backup finished before the daemon ended"
                    );
                    self.end_attempt(&attempt);
                    continue;
                }
                Verdict::Streams(streams) => streams,
            };
            let mut left_over = 0;
            for key in &streams {
                if let Err(err) = store.delete(key).await {
                    left_over += 1;
                    tracing::warn!(key, err = %format!("{err:#}"), "stream of a backup that never finished kept");
                }
            }
            if left_over == 0 {
                tracing::info!(
                    machine = attempt.machine_id,
                    backup = attempt.id,
                    streams = streams.len(),
                    "streams of a backup that never finished removed"
                );
                self.end_attempt(&attempt);
            }
        }
    }
}
