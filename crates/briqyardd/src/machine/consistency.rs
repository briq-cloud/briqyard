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
fn fallback(error: &anyhow::Error, phase: &str) -> api::CopyConsistency {
    let reason = if error.is::<guestc::UnknownOp>() {
        "init_too_old"
    } else if error.is::<guestc::FreezeExpired>() {
        "freeze_expired"
    } else if error.is::<tokio::time::error::Elapsed>() {
        if phase == "sync" {
            "sync_timeout"
        } else {
            "freeze_timeout"
        }
    } else {
        if phase == "sync" {
            "sync_refused"
        } else {
            "freeze_refused"
        }
    };
    tracing::warn!(reason, error = %error, "guest copy consistency fallback");
    achieved("unsynced", Some(reason))
}
/// A stopped state alone does not prove the init completed its halt path.
fn stopped_consistency(r: &Record) -> api::CopyConsistency {
    if r.state == state::CREATED && r.started_at.is_none() {
        return if !r.from_source {
            achieved("filesystem", None)
        } else {
            r.fork
                .as_ref()
                .map(|origin| origin.copy_consistency.clone())
                .unwrap_or_else(|| achieved("unsynced", Some("unverified_source")))
        };
    }
    if r.state != state::STOPPED {
        return achieved("unsynced", Some("unverified_stop"));
    }
    let Some(exit) = r
        .exit
        .as_ref()
        .filter(|exit| r.started_at.is_none_or(|started| exit.at >= started))
    else {
        return achieved("unsynced", Some("unverified_stop"));
    };
    if exit.oom_killed {
        return achieved("unsynced", Some("oom_killed"));
    }
    if exit.vmm_oom_killed {
        return achieved("unsynced", Some("vmm_oom_killed"));
    }
    if exit.code == 255 {
        return achieved(
            "unsynced",
            Some(if r.stopped_reason == stop::EXIT {
                "unclean_exit"
            } else {
                "forced_stop"
            }),
        );
    }
    achieved("filesystem", None)
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
            return achieved("unsynced", Some("requested"));
        }
        let live = e.live.lock().unwrap().clone();
        let Some(live) = live else {
            return achieved("unsynced", Some("not_running"));
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
            Err(err) => fallback(&err, "sync"),
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
            achieved("unsynced", Some("requested"))
        } else if r.suspended {
            if r.suspend_synced {
                achieved("synced", None)
            } else {
                achieved("unsynced", Some("unsynced_suspend"))
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
                        Err(err) => fallback(&err, "freeze"),
                    }
                } else {
                    achieved("unsynced", Some("not_running"))
                }
            } else {
                synced
            }
        } else {
            stopped_consistency(&r)
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
                consistency = fallback(&err, "freeze");
            }
            if held_since.is_some_and(|t| t.elapsed() >= HOLD) {
                consistency = achieved("unsynced", Some("freeze_expired"));
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stopped_copy_reports_each_exit_kind_conservatively() {
        for (kind, reason, code, oom, expected) in [
            ("graceful stop", stop::USER, Some(143), false, None),
            ("normal exit", stop::EXIT, Some(0), false, None),
            (
                "guest kills workload then halts",
                stop::USER,
                Some(137),
                false,
                None,
            ),
            (
                "application error through init",
                stop::EXIT,
                Some(1),
                false,
                None,
            ),
            ("OOM", stop::EXIT, Some(137), true, Some("oom_killed")),
            (
                "VMM crash",
                stop::EXIT,
                Some(255),
                false,
                Some("unclean_exit"),
            ),
            (
                "VMM over its memory ceiling",
                stop::EXIT,
                Some(255),
                false,
                Some("vmm_oom_killed"),
            ),
            (
                "kill after grace",
                stop::USER,
                Some(255),
                false,
                Some("forced_stop"),
            ),
            (
                "unconfirmed old stop",
                stop::USER,
                None,
                false,
                Some("unverified_stop"),
            ),
        ] {
            let mut r = crate::machine::tests::record();
            r.state = state::STOPPED.into();
            r.stopped_reason = reason.into();
            r.exit = code.map(|code| api::Exit {
                code,
                oom_killed: oom,
                vmm_oom_killed: kind == "VMM over its memory ceiling",
                at: Utc::now(),
                restarting: false,
            });
            let got = stopped_consistency(&r);
            assert_eq!(got.consistency_reason.as_deref(), expected, "{kind}");
            assert_eq!(
                got.consistency,
                if expected.is_some() {
                    "unsynced"
                } else {
                    "filesystem"
                },
                "{kind}"
            );
        }
    }
}

#[cfg(test)]
mod lineage_tests {
    use super::*;
    #[test]
    fn prior_exit_cannot_bless_an_error_or_an_unbooted_restored_copy() {
        let mut r = crate::machine::tests::record();
        r.state = state::ERROR.into();
        r.exit = Some(api::Exit {
            code: 0,
            oom_killed: false,
            vmm_oom_killed: false,
            at: Utc::now(),
            restarting: false,
        });
        assert_eq!(stopped_consistency(&r).consistency, "unsynced");
        r.state = state::CREATED.into();
        r.started_at = None;
        r.from_source = true;
        assert_eq!(stopped_consistency(&r).consistency, "unsynced");
        r.fork = Some(api::ForkOrigin {
            machine_id: "m_parent".into(),
            copy_consistency: achieved("unsynced", Some("requested")),
        });
        assert_eq!(stopped_consistency(&r).consistency, "unsynced");
        r.fork = None;
        r.from_source = false;
        assert_eq!(stopped_consistency(&r).consistency, "filesystem");
    }
}
