//! Events (ADR 0019): what happened on this host, in one append-only log. An event is a line
//! of `state/events/<hour>.ndjson`, appended and synced under the log's lock, then sent to the
//! watchers; `seq` is one more per event and never reused. Repeats of a use, a refusal or a
//! readiness flip within `FOLD_MINUTES` of its line are folded into one later line.

use anyhow::{Context, Result};
use briqyard_api::{self as api, event, reason};
use chrono::{DateTime, Duration, Utc};
use std::collections::BTreeMap;
use std::io::{BufRead, Seek, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, mpsc, watch};

mod fold;
mod handle;
mod log;
#[cfg(test)]
mod testutil;

use fold::*;
use log::*;

/// The most events a host keeps, whatever their age: whole hours go, oldest first.
pub const MAX_EVENTS: u64 = 100_000;
/// The longest message: a console tail is cut here.
const MAX_MESSAGE: usize = 1024;
/// How far a watcher may fall behind the log before it is closed.
const WATCH_BUFFER: usize = 1024;
/// A quiet watch sends a bookmark this often, so a proxy does not cut it.
pub const HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(30);

/// An event about to be logged: what it says, and whom it is about.
#[derive(Clone, Debug)]
pub struct Ev {
    kind: &'static str,
    reason: &'static str,
    message: String,
    machine_id: String,
    namespace: String,
    data: Option<serde_json::Value>,
}

impl Ev {
    pub fn normal(reason: &'static str, message: impl Into<String>) -> Self {
        Self::new(event::NORMAL, reason, message.into())
    }

    pub fn warning(reason: &'static str, message: impl Into<String>) -> Self {
        Self::new(event::WARNING, reason, message.into())
    }

    fn new(kind: &'static str, reason: &'static str, message: String) -> Self {
        Self {
            kind,
            reason,
            message,
            machine_id: String::new(),
            namespace: String::new(),
            data: None,
        }
    }

    pub fn data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }

    /// About a namespace, no machine of it: a create refused before it made one.
    pub fn namespace(mut self, namespace: &str) -> Self {
        namespace.clone_into(&mut self.namespace);
        self
    }

    /// About a machine of a namespace.
    pub fn of(mut self, machine_id: &str, namespace: &str) -> Self {
        machine_id.clone_into(&mut self.machine_id);
        namespace.clone_into(&mut self.namespace);
        self
    }
}

/// What a read keeps: every field given must match.
#[derive(Clone, Debug, Default)]
pub struct Filter {
    pub namespace: Option<String>,
    pub machine: Option<String>,
    pub kind: Option<String>,
}

impl Filter {
    fn matches(&self, e: &api::Event) -> bool {
        let is = |want: &Option<String>, got: &str| want.as_deref().is_none_or(|w| w == got);
        is(&self.namespace, &e.namespace)
            && is(&self.machine, &e.machine_id)
            && is(&self.kind, &e.kind)
    }
}

/// Events after a cursor, oldest first, and the cursor to read on from: the last one returned
/// when the page is full, else the log's last seq.
#[derive(Debug, Default, PartialEq)]
pub struct Page {
    pub events: Vec<api::Event>,
    pub next: u64,
}

/// A cursor the log cannot answer from: the events after it are gone, or it is past the
/// log's last seq (the log began again). A read from `oldest - 1` is whole.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct Gone {
    pub oldest: u64,
    pub message: String,
}

#[derive(Clone)]
pub struct Events {
    inner: Arc<Shared>,
}

struct Shared {
    log: Mutex<Log>,
    tx: broadcast::Sender<api::Event>,
    /// Set when the daemon goes down: every watch ends.
    closing: watch::Sender<bool>,
}

/// Sends a line, unless the watcher went away or the daemon is going down.
pub async fn send(
    tx: &mpsc::Sender<String>,
    closing: &mut watch::Receiver<bool>,
    line: String,
) -> bool {
    tokio::select! {
        r = tx.send(line) => r.is_ok(),
        _ = closing.wait_for(|c| *c) => false,
    }
}

/// A watch's quiet line: the seq up to which it looked at every event, as a bookmark (no
/// `seq`: it is not an event).
pub fn bookmark(cursor: u64) -> String {
    format!("{{\"bookmark\":{cursor}}}\n")
}

/// The line a watch ends with: an error body, as the API's.
pub fn last_line(code: &str, why: &str) -> String {
    let e = api::ApiError {
        error: why.into(),
        code: code.into(),
        request_id: String::new(),
        machine: None,
        oldest: None,
    };
    serde_json::to_string(&e).unwrap_or_default() + "\n"
}
