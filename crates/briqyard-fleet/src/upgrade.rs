//! `POST /v1/hosts/{id}/upgrade` (ADR 0027): a host's daemon moved to another release with its
//! machines running. Artifacts are prepared while admission is unchanged, then the host is
//! `upgrading` (placement stops). The bootstrap activates the prepared release (the one install path: the binaries, then the daemon hands its
//! machines over to the new one), and the upgrade waits for a heartbeat from a new start of
//! the installed version that adopted every machine left running. Then the host is back in the
//! state it had, or stays `draining` when requested for external verification (ADR 0136).
//! A failure after withdrawal leaves it `draining`, the reason in its note. One upgrade at a time.
//!
//! The upgrade runs in a task of its own that the request waits on: a caller that hangs up
//! leaves it to finish, never a host half-moved.

use crate::{bootstrap, err, AppState, Refusal};
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use briqyard_api as api;
use chrono::Utc;
use std::sync::Arc;
use std::time::Duration;

/// How long a host is given to heartbeat from its new start once the script is done.
const COME_BACK: Duration = Duration::from_secs(300);

pub async fn upgrade_host(
    st: Arc<AppState>,
    Path(id): Path<String>,
    Json(req): Json<api::UpgradeHostRequest>,
) -> Result<Response, Refusal> {
    if (req.stay_draining || req.require_ready) && !st.cfg.bootstrap.script.as_os_str().is_empty() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid",
            "stay_draining and require_ready need the embedded prepared upgrade contract",
        ));
    }
    let release = bootstrap::release_url(&req.release).ok_or_else(|| {
        err(
            StatusCode::BAD_REQUEST,
            "invalid",
            format!(
                "release {:?}: a URL, or a version such as 0.2.0",
                req.release
            ),
        )
    })?;
    if let Some(bad) = req
        .runtime_classes
        .iter()
        .find(|c| !api::valid_class_name(c))
    {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid",
            format!("runtime class {bad:?}: a class name such as nested"),
        ));
    }
    let key = &st.cfg.bootstrap.ssh_key;
    if !key.exists() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid",
            format!(
                "no SSH key at {} (bootstrap.ssh_key): the fleet installs over SSH",
                key.display()
            ),
        ));
    }
    let turn = st.upgrade.clone().try_lock_owned().map_err(|_| {
        err(
            StatusCode::CONFLICT,
            "conflict",
            "another host is upgrading: one at a time",
        )
    })?;
    let was = {
        let reg = st.reg.lock().unwrap();
        let h = reg
            .hosts
            .get(&id)
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "not_found", "host not found"))?;
        if req.require_ready && h.state != "ready" {
            return Err(err(
                StatusCode::CONFLICT,
                "conflict",
                "require_ready: host is not ready; nothing prepared or activated",
            ));
        }
        if !matches!(h.state.as_str(), "ready" | "draining") {
            return Err(err(
                StatusCode::CONFLICT,
                "conflict",
                format!(
                    "host {id} is {}: only a ready or draining host upgrades",
                    h.state
                ),
            ));
        }
        h.clone()
    };
    let mut timing =
        crate::upgrade_timing::Timing::new(&st.cfg.state_dir, &was.id, &was.version, &req.release)
            .map_err(|_| {
                err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "cannot initialize upgrade timing journal; nothing dispatched",
                )
            })?;
    let classes = req.runtime_classes;
    let task = tokio::spawn(async move {
        let _turn = turn;
        let env = bootstrap::upgrade_env(
            &release,
            &st.cfg.bootstrap.release_token,
            &was.runtime_classes,
            &classes,
        );
        // Custom bootstrap scripts retain their single invocation and drain-first contract.
        let phases = bootstrap::upgrade_phases(&st.cfg.bootstrap, &env);
        if phases.is_some() {
            timing.start("prepare");
        }
        let preparation = async {
            if let Some((prepare, _)) = &phases {
                bootstrap::install(&st, &was.id, bootstrap::ssh_address(&was), prepare)
                    .await
                    .map_err(|e| format!("prepare: {e:#}"))?;
            }
            Ok(())
        };
        let prepared: Result<(), String> = preparation.await;
        if phases.is_some() {
            timing.end(prepared.is_ok());
        }
        prepared?;
        timing.start("withdrawal");
        let withdrawn = prepare_before_withdraw(&st, &was, &release, async { Ok(()) }).await;
        timing.end(withdrawn.is_ok());
        let current = withdrawn?;
        let activation = phases
            .as_ref()
            .map(|(_, activate)| activate.as_str())
            .unwrap_or(&env);
        let outcome = run(&st, &current, &release, activation, &mut timing).await;
        timing.start("completion");
        let result = finish(&st, &was, &release, req.stay_draining, outcome).await;
        timing.end(result.is_ok());
        result
    });
    match task.await {
        Ok(Ok(host)) => Ok(Json(host).into_response()),
        Ok(Err(why)) => Err(err(StatusCode::BAD_GATEWAY, "upgrade_failed", why)),
        Err(e) => Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            format!("upgrade task: {e}"),
        )),
    }
}

/// Preparation leaves admission unchanged. Recheck ownership before withdrawing it:
/// an operator may have drained or retired the host while downloads ran.
pub(crate) async fn prepare_before_withdraw(
    st: &AppState,
    was: &crate::registry::HostRec,
    release: &str,
    preparation: impl std::future::Future<Output = Result<(), String>>,
) -> Result<crate::registry::HostRec, String> {
    preparation.await?;
    let current = {
        let mut reg = st.reg.lock().unwrap();
        let h = reg
            .hosts
            .get_mut(&was.id)
            .ok_or("host forgotten during preparation")?;
        if h.state != was.state || h.url != was.url || h.ssh != was.ssh || h.token != was.token {
            return Err(
                "host state or identity changed during preparation; nothing activated".into(),
            );
        }
        let current = h.clone();
        h.state = "upgrading".into();
        h.note = format!("upgrading to {release}");
        current
    };
    if let Err(e) = st.save().await {
        if let Some(h) = st.reg.lock().unwrap().hosts.get_mut(&was.id) {
            (h.state, h.note) = (was.state.clone(), was.note.clone());
        }
        return Err(format!("record upgrade: {e:#}"));
    }
    Ok(current)
}

/// The steps; the version and start the host came back with, or why it did not.
async fn run(
    st: &AppState,
    was: &crate::registry::HostRec,
    release: &str,
    env: &str,
    timing: &mut crate::upgrade_timing::Timing,
) -> Result<(String, api::DaemonStart), String> {
    // Over SSH where the bootstrap reached it: a host added by hand has an SSH address of its
    // own, the API on the private network.
    let ip = bootstrap::ssh_address(was).to_string();
    tracing::info!(host = was.id, release, "host upgrade");
    timing.start("activation");
    let installed = bootstrap::install(st, &was.id, &ip, env).await;
    timing.end(installed.is_ok());
    let installed = installed.map_err(|e| format!("install: {e:#}"))?;
    // What the install says of the SSH host key: pinned now (a static host's first upgrade),
    // or already.
    tracing::info!(host = was.id, note = installed, "host upgrade installed");
    timing.start("installed_version");
    let version = bootstrap::installed_version(st, &ip).await;
    timing.end(version.is_ok());
    let version = version.map_err(|e| format!("{e:#}"))?;
    if api::version::newer(&version, briqyard_version::VERSION) {
        return Err(format!(
            "the host now runs {version}, newer than this fleet ({}): upgrade the fleet first",
            briqyard_version::VERSION
        ));
    }
    let before = was.started.map(|s| s.at);
    timing.start("adoption_readiness");
    let started = come_back(st, &was.id, before, &version, COME_BACK).await;
    timing.end(started.is_ok());
    let started = started?;
    Ok((version, started))
}

/// Waits for the host's record to show a start of `version` other than `before`, and answers
/// it; an error when that start stopped machines it could not take over (one whose process
/// had exited meanwhile is `gone`, not a failure), or when none came `within`. A daemon that
/// reports no start is older than ADR 0027: not the one installed.
pub async fn come_back(
    st: &AppState,
    id: &str,
    before: Option<chrono::DateTime<Utc>>,
    version: &str,
    within: Duration,
) -> Result<api::DaemonStart, String> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let seen = st
            .reg
            .lock()
            .unwrap()
            .hosts
            .get(id)
            .map(|h| (h.version.clone(), h.started));
        match seen {
            Some((v, Some(started))) if v == version && Some(started.at) != before => {
                return match started.stopped {
                    0 => Ok(started),
                    n => Err(format!(
                        "{version} started and stopped {n} machines it could not take over ({} adopted)",
                        started.adopted
                    )),
                }
            }
            None => return Err("the host was forgotten".into()),
            Some(_) => {}
        }
        if tokio::time::Instant::now() > deadline {
            return Err(format!(
                "no heartbeat from a new start of {version} within {} s",
                within.as_secs()
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Restore the original state unless external verification was requested; failures drain.
pub async fn finish(
    st: &AppState,
    was: &crate::registry::HostRec,
    release: &str,
    stay_draining: bool,
    outcome: Result<(String, api::DaemonStart), String>,
) -> Result<api::Host, String> {
    let when = Utc::now().to_rfc3339();
    let host = {
        let mut reg = st.reg.lock().unwrap();
        let Some(h) = reg.hosts.get_mut(&was.id) else {
            return Err("the host was forgotten during its upgrade".into());
        };
        match &outcome {
            Ok((version, started)) => {
                h.state = if stay_draining {
                    "draining".into()
                } else {
                    was.state.clone()
                };
                h.note = format!(
                    "upgraded to {version} at {when}; machines handed over: {}",
                    started.adopted
                );
                tracing::warn!(
                    host = h.id,
                    version,
                    adopted = started.adopted,
                    "host upgraded"
                );
            }
            Err(why) => {
                h.state = "draining".into();
                h.note = format!(
                    "upgrade to {release} failed at {when}: {why}; undrain once it is fixed"
                );
                tracing::error!(host = h.id, release, err = why, "host upgrade failed");
            }
        }
        h.to_api()
    };
    st.save().await.map_err(|e| format!("{e:#}"))?;
    outcome.map(|_| host)
}

/// A host left `upgrading` by a fleet that stopped during the upgrade: `draining`, for the
/// operator to look at. At the fleet's start.
pub fn interrupted(reg: &mut crate::registry::Registry) {
    for h in reg.hosts.values_mut().filter(|h| h.state == "upgrading") {
        h.state = "draining".into();
        h.note = format!(
            "{}: interrupted by a fleet restart; undrain once checked",
            h.note
        );
    }
}

/// Safe structured observations, including an unmatched start after interruption.
pub async fn timings(st: Arc<AppState>, Path(id): Path<String>) -> Result<Response, Refusal> {
    if !st.reg.lock().unwrap().hosts.contains_key(&id) {
        return Err(err(StatusCode::NOT_FOUND, "not_found", "host not found"));
    }
    let record = crate::upgrade_timing::latest(&st.cfg.state_dir, &id).map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "upgrade timing unavailable",
        )
    })?;
    Ok(Json(record).into_response())
}
