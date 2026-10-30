//! Events and their reasons (ADR 0019).

use super::*;

/// Event types, as Kubernetes's.
pub mod event {
    pub const NORMAL: &str = "normal";
    pub const WARNING: &str = "warning";
}

/// Why an event happened: a closed list (ADR 0019).
pub mod reason {
    pub const CREATED: &str = "created";
    pub const FORKED: &str = "forked";
    /// Its create waits for its image to be pulled (ADR 0048).
    pub const PULLING: &str = "pulling";
    /// Its create could not pull its image: the machine is in `error` (ADR 0048).
    pub const PULL_FAILED: &str = "pull_failed";
    /// Its create could not make its disks or start it: the machine is in `error` (ADR 0048).
    pub const CREATE_FAILED: &str = "create_failed";
    pub const RESTORED: &str = "restored";
    /// It joined another namespace (ADR 0056), in the one it left and in the one it joined.
    pub const MOVED: &str = "moved";
    pub const STARTING: &str = "starting";
    pub const STARTED: &str = "started";
    pub const RESUMED: &str = "resumed";
    pub const READY: &str = "ready";
    pub const NOT_READY: &str = "not_ready";
    pub const STOPPING: &str = "stopping";
    pub const STOPPED: &str = "stopped";
    pub const SUSPENDED: &str = "suspended";
    pub const EXITED: &str = "exited";
    pub const RESTARTING: &str = "restarting";
    pub const CRASH_LOOP: &str = "crash_loop";
    pub const LIVENESS_FAILED: &str = "liveness_failed";
    pub const STARTUP_FAILED: &str = "startup_failed";
    pub const BOOT_FAILED: &str = "boot_failed";
    pub const START_FAILED: &str = "start_failed";
    pub const UPDATED: &str = "updated";
    /// A PATCH's pending change went onto the machine at its start (ADR 0024).
    pub const APPLIED: &str = "applied";
    pub const EGRESS_CHANGED: &str = "egress_changed";
    pub const BACKED_UP: &str = "backed_up";
    pub const BACKUP_FAILED: &str = "backup_failed";
    pub const BACKUP_DELETED: &str = "backup_deleted";
    /// A snapshot of its disks taken, or deleted (ADR 0031).
    pub const SNAPSHOT_TAKEN: &str = "snapshot_taken";
    pub const SNAPSHOT_DELETED: &str = "snapshot_deleted";
    pub const DESTROYED: &str = "destroyed";
    pub const GATEWAY_STARTED: &str = "gateway_started";
    pub const GATEWAY_STOPPED: &str = "gateway_stopped";
    pub const IMAGE_PULLED: &str = "image_pulled";
    pub const HOST_STARTED: &str = "host_started";
    pub const ADOPTED: &str = "adopted";
    /// A host condition changed (ADR 0021).
    pub const HOST_CONDITION: &str = "host_condition";
    pub const IMAGE_REMOVED: &str = "image_removed";
    /// A create or a start refused by the namespace's quota (ADR 0025).
    pub const QUOTA_EXCEEDED: &str = "quota_exceeded";
    /// An exec session began (ADR 0029): someone is in the machine. A use: no new version.
    pub const SESSION_OPENED: &str = "session_opened";
    pub const ALL: &[&str] = &[
        CREATED,
        FORKED,
        PULLING,
        PULL_FAILED,
        CREATE_FAILED,
        RESTORED,
        MOVED,
        STARTING,
        STARTED,
        RESUMED,
        READY,
        NOT_READY,
        STOPPING,
        STOPPED,
        SUSPENDED,
        EXITED,
        RESTARTING,
        CRASH_LOOP,
        LIVENESS_FAILED,
        STARTUP_FAILED,
        BOOT_FAILED,
        START_FAILED,
        UPDATED,
        APPLIED,
        EGRESS_CHANGED,
        BACKED_UP,
        BACKUP_FAILED,
        BACKUP_DELETED,
        SNAPSHOT_TAKEN,
        SNAPSHOT_DELETED,
        DESTROYED,
        GATEWAY_STARTED,
        GATEWAY_STOPPED,
        IMAGE_PULLED,
        HOST_STARTED,
        ADOPTED,
        HOST_CONDITION,
        IMAGE_REMOVED,
        QUOTA_EXCEEDED,
        SESSION_OPENED,
    ];
}

/// Something that happened on a host (ADR 0019). `GET /v1/events`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// One more per event on its host, never reused.
    pub seq: u64,
    pub at: DateTime<Utc>,
    /// `normal` or `warning`.
    #[serde(rename = "type")]
    pub kind: String,
    /// One of `reason::ALL`.
    pub reason: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub machine_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[serde(alias = "tenant")]
    pub namespace: String,
    /// The host it happened on (set by the fleet on a fleet-wide read).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// How many times it happened: more than 1 on a line that folds repeats (ADR 0019), whose
    /// `at` is the last time and `first_at` the first; `message` and `data` are the last's.
    #[serde(default = "one", skip_serializing_if = "at_most_one")]
    pub count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_at: Option<DateTime<Utc>>,
}

fn one() -> u64 {
    1
}

fn at_most_one(n: &u64) -> bool {
    *n <= 1
}

/// A page of events, oldest first, and the cursor to read on from.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EventsPage {
    pub events: Vec<Event>,
    /// What to send as `since` next: a host's seq, or the fleet's `<host>:<seq>,…`.
    pub next: String,
}

/// Events a page holds: 500 unless asked, 5000 at most.
pub fn events_limit(asked: Option<usize>) -> usize {
    match asked {
        None | Some(0) => 500,
        Some(n) => n.min(5000),
    }
}
