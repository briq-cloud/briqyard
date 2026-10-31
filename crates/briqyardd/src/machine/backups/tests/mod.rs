//! Tests of backups.

use super::super::tests::{at, grow_to, harness_config, with_volume, Harness};
use super::*;
use tokio::task::JoinHandle;

/// A harness whose host backs up to a directory, after `f`; namespace `t1` and the image in
/// place.
async fn harness(f: impl FnOnce(&mut config::Backup)) -> Harness {
    let h = harness_config(|cfg| {
        cfg.network.range = "10.64.0.0/22".into();
        cfg.capacity = config::Capacity {
            memory_mb: 4096,
            vcpus: 1000,

            ..Default::default()
        };
        cfg.egress_limits = config::EgressLimits {
            blocked_ports: vec![],
            new_connections_per_minute: 0,
            bandwidth_mbit: 0,
        };
        cfg.backup.store = format!("file://{}", cfg.data_dir.join("store").display());
        f(&mut cfg.backup);
    })
    .await;
    h.ready().await;
    h
}

fn every(e: &str, keep: u32) -> Option<Option<api::BackupPolicy>> {
    Some(Some(api::BackupPolicy {
        every: e.into(),
        keep,
    }))
}

impl Harness {
    /// A machine of `t1` with this schedule, running or only created.
    async fn machine(
        &self,
        name: &str,
        backup: Option<Option<api::BackupPolicy>>,
        start: bool,
    ) -> api::Machine {
        let mut req = self.request(name);
        req.backup = backup;
        req.start = Some(start);
        self.m.create_made(req).await.unwrap()
    }

    async fn volsize_gb(&self, id: &str) -> u64 {
        let ds = format!("m/{id}/data");
        self.pool.zfs.volsize(&ds).await.unwrap() >> 30
    }

    fn ids(&self, bs: &[api::Backup]) -> Vec<String> {
        bs.iter().map(|b| b.id.clone()).collect()
    }

    async fn listed(&self, id: &str) -> Vec<api::Backup> {
        self.m.backups(id).await.unwrap()
    }

    /// The store's objects of a machine.
    async fn objects(&self, id: &str) -> Vec<String> {
        let store = self.m.backup_store().unwrap();
        store.list(&format!("backups/{id}/")).await.unwrap()
    }

    fn last_of(&self, id: &str, reason: &str) -> api::Event {
        self.events_of(id)
            .into_iter()
            .rev()
            .find(|e| e.reason == reason)
            .unwrap_or_else(|| panic!("{id}: no {reason} in {:?}", self.reasons(id)))
    }

    /// The sends the fake `zfs` started, read without taking the calls, which other
    /// processes are still appending to.
    fn sends(&self) -> usize {
        let calls = self.pool.dev().parent().unwrap().join("calls");
        std::fs::read_to_string(calls)
            .unwrap_or_default()
            .lines()
            .filter(|c| c.starts_with("send "))
            .count()
    }
}

/// Waits for the tasks a step started; how many there were.
async fn run(tasks: Vec<JoinHandle<()>>) -> usize {
    let n = tasks.len();
    for t in tasks {
        t.await.unwrap();
    }
    n
}

mod chain;
mod holders;
mod restore;
mod schedule;

mod ownership;
