//! `POST /v1/hosts/{id}/upgrade` (ADR 0027): a host's daemon moved to another release with its
//! machines running. The host is `upgrading` (placement stops), the bootstrap script runs on
//! it again with the release (the one install path: the binaries, then the daemon hands its
//! machines over to the new one), and the upgrade waits for a heartbeat from a new start of
//! the installed version that adopted every machine left running. Then the host is back in the
//! state it had; a failure leaves it `draining`, the reason in its note. One upgrade at a time.
//!
//! The upgrade runs in a task of its own that the request waits on: a caller that hangs up
//! leaves it to finish, never a host half-moved.

use crate::registry::url_host;
use crate::{bootstrap, err, registry_error, AppState, Refusal};
use axum::extract::{Path, State};
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
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<api::UpgradeHostRequest>,
) -> Result<Response, Refusal> {
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
    let key = &st.cfg.provisioner.bootstrap.ssh_key;
    if !key.exists() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "invalid",
            format!(
                "no SSH key at {} (provisioner.bootstrap.ssh_key): the fleet installs over SSH",
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
        let mut reg = st.reg.lock().unwrap();
        let h = reg
            .hosts
            .get_mut(&id)
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "not_found", "host not found"))?;
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
        let was = h.clone();
        h.state = "upgrading".into();
        h.note = format!("upgrading to {release}");
        was
    };
    if let Err(e) = st.save() {
        // Not recorded: nothing starts, and the host is as it was.
        if let Some(h) = st.reg.lock().unwrap().hosts.get_mut(&id) {
            (h.state, h.note) = (was.state.clone(), was.note.clone());
        }
        return Err(registry_error(e));
    }
    let task = tokio::spawn(async move {
        let _turn = turn;
        let outcome = run(&st, &was, &release).await;
        finish(&st, &was, &release, outcome)
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

/// The steps; the version and start the host came back with, or why it did not.
async fn run(
    st: &AppState,
    was: &crate::registry::HostRec,
    release: &str,
) -> Result<(String, api::DaemonStart), String> {
    let ip = url_host(&was.url).to_string();
    tracing::warn!(host = was.id, release, "host upgrade");
    let installed = bootstrap::install(st, &was.id, &ip, &was.url, &was.token, release)
        .await
        .map_err(|e| format!("install: {e:#}"))?;
    // What the install says of the SSH host key: pinned now (a static host's first upgrade),
    // or already.
    tracing::warn!(host = was.id, note = installed, "host upgrade installed");
    let version = bootstrap::installed_version(st, &ip)
        .await
        .map_err(|e| format!("{e:#}"))?;
    if api::version::newer(&version, api::VERSION) {
        return Err(format!(
            "the host now runs {version}, newer than this fleet ({}): upgrade the fleet first",
            api::VERSION
        ));
    }
    let started = come_back(st, &was.id, was.started.at, &version, COME_BACK).await?;
    Ok((version, started))
}

/// Waits for the host's record to show a start other than `before` of `version`, and answers
/// it; an error when that start stopped machines it could not take over, or when none came
/// `within`.
pub async fn come_back(
    st: &AppState,
    id: &str,
    before: chrono::DateTime<Utc>,
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
            Some((v, started)) if v == version && started.at != before => {
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

/// The host back in the state it had, or `draining` with why.
pub fn finish(
    st: &AppState,
    was: &crate::registry::HostRec,
    release: &str,
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
                h.state = was.state.clone();
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
    st.save().map_err(|e| format!("{e:#}"))?;
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
