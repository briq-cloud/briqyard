//! Guest quiescence for disk copies (ADR 0092). Callers hold only the source entry lock.
use super::*;
use crate::profile::stage;
use std::time::Instant;

const HOLD: Duration = Duration::from_secs(30);

pub(super) fn achieved(level: &str, reason: Option<&str>) -> api::CopyConsistency {
    api::CopyConsistency {
        consistency: level.into(),
        consistency_reason: reason.map(str::to_owned),
    }
}
fn fallback(error: &anyhow::Error) -> api::CopyConsistency {
    let reason = if error.is::<guestc::UnknownOp>() {
        "init_too_old"
    } else if error.is::<guestc::FreezeExpired>() {
        "freeze_expired"
    } else if error.is::<tokio::time::error::Elapsed>() {
        "freeze_timeout"
    } else {
        "freeze_refused"
    };
    tracing::warn!(reason, error = %error, "guest copy consistency fallback");
    achieved("crash", Some(reason))
}
impl Manager {
    pub(super) async fn bounded_sync(&self, vsock: &Path) -> Result<()> {
        tokio::time::timeout(guestc::CONTROL_TIMEOUT, self.inner.guest.fs_sync(vsock))
            .await
            .context("copy fs_sync timeout")?
    }
    pub(super) async fn sync_copy(
        &self,
        e: &Entry,
        opt: Option<api::CopyConsistencyRequest>,
    ) -> api::CopyConsistency {
        if opt.is_some() {
            return achieved("crash", Some("requested"));
        }
        let live = e.live.lock().unwrap().clone();
        let Some(live) = live else {
            return achieved("crash", Some("not_running"));
        };
        let started = Instant::now();
        let result = self.bounded_sync(&live.vsock).await;
        stage(
            "copy",
            "fs_sync",
            &e.snapshot().id,
            live.pid,
            started,
            result.is_ok(),
        );
        match result {
            Ok(()) => achieved("synced", None),
            Err(err) => fallback(&err),
        }
    }
    pub(super) async fn frozen_copy(
        &self,
        e: &Entry,
        datasets: &[String],
        snap: &str,
        operation: &'static str,
        opt: Option<api::CopyConsistencyRequest>,
    ) -> Result<api::CopyConsistency> {
        let r = e.snapshot();
        let live = e.live.lock().unwrap().clone();
        let mut frozen = None;
        let mut held_since = None;
        let mut consistency = if opt.is_some() {
            achieved("crash", Some("requested"))
        } else if r.suspended {
            if r.suspend_synced {
                achieved("synced", None)
            } else {
                achieved("crash", Some("unsynced_suspend"))
            }
        } else if matches!(
            r.state.as_str(),
            state::RUNNING | state::STARTING | state::STOPPING
        ) {
            let synced = self.sync_copy(e, None).await;
            if synced.consistency == "synced" {
                if let Some(live) = live {
                    let started = Instant::now();
                    let result = tokio::time::timeout(
                        guestc::CONTROL_TIMEOUT,
                        self.inner.guest.fs_freeze(&live.vsock, HOLD),
                    )
                    .await
                    .context("copy fs_freeze timeout")
                    .and_then(|r| r);
                    stage(
                        "copy",
                        "fs_freeze",
                        &r.id,
                        live.pid,
                        started,
                        result.is_ok(),
                    );
                    match result {
                        Ok(f) => {
                            frozen = Some(f);
                            held_since = Some(Instant::now());
                            achieved("filesystem", None)
                        }
                        Err(err) => fallback(&err),
                    }
                } else {
                    achieved("crash", Some("not_running"))
                }
            } else {
                synced
            }
        } else {
            achieved("filesystem", None)
        };
        let started = Instant::now();
        let result = self.inner.zfs.snapshot_all(datasets, snap).await;
        stage(
            "copy",
            "zfs_snapshot",
            &r.id,
            r.pid,
            started,
            result.is_ok(),
        );
        // Always thaw before propagating a storage error. Dropping this future closes the
        // held stream too. A storage command retains its existing ADR 0046 ownership.
        if let Some(frozen) = frozen {
            let started = Instant::now();
            let thaw = tokio::time::timeout(guestc::CONTROL_TIMEOUT, frozen.thaw())
                .await
                .context("copy fs_thaw timeout")
                .and_then(|r| r);
            stage("copy", "fs_thaw", &r.id, r.pid, started, thaw.is_ok());
            if let Err(err) = thaw {
                consistency = fallback(&err);
            }
            if held_since.is_some_and(|t| t.elapsed() >= HOLD) {
                consistency = achieved("crash", Some("freeze_expired"));
            }
        }
        self.inner
            .stats
            .copies
            .lock()
            .unwrap()
            .hold(held_since.map(|t| t.elapsed().as_secs_f64()));
        result?;
        self.inner
            .stats
            .copies
            .lock()
            .unwrap()
            .record(operation, &consistency.consistency, None);
        Ok(consistency)
    }
}
