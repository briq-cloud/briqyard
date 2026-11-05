//! Durable namespace evacuation, with one authoritative host for every copied id.
use super::*;
use serde::{Deserialize, Serialize};
pub(crate) mod driver;
mod host;
mod io;
pub(crate) use host::*;
mod routes;
pub(crate) use routes::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct MachineCopy {
    pub id: String,
    pub name: String,
    pub manifest: serde_json::Value,
    pub backup: Option<String>,
    pub restored: bool,
    pub verified: bool,
    pub ip: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Evacuation {
    pub job: String,
    pub namespace: String,
    pub from: String,
    pub to: String,
    pub step: String,
    pub machines: Vec<MachineCopy>,
    pub endpoints: Vec<api::Endpoint>,
    pub quota: api::Quota,
    pub started: chrono::DateTime<Utc>,
    pub error: Option<String>,
    pub cancel_requested: bool,
    pub drop_snapshots: bool,
    #[serde(skip)]
    pub reservation: u64,
}

impl Evacuation {
    pub fn switched(&self) -> bool {
        matches!(self.step.as_str(), "switched" | "finishing" | "done")
    }
    pub fn active(&self) -> bool {
        !matches!(self.step.as_str(), "done" | "cancelled")
    }
    pub fn authority(&self) -> &str {
        if self.switched() {
            &self.to
        } else {
            &self.from
        }
    }
}

pub(crate) fn authoritative<'a>(reg: &'a Registry, what: Indexed, id: &str) -> Option<&'a str> {
    reg.evacuations
        .values()
        .find(|job| match what {
            Indexed::Machine => job.machines.iter().any(|m| m.id == id),
            Indexed::Endpoint => job.endpoints.iter().any(|e| e.id == id),
        })
        .map(Evacuation::authority)
}

pub(crate) fn namespace_available(reg: &Registry, namespace: &str) -> Result<(), Refusal> {
    if let Some(job) = reg.evacuations.get(namespace).filter(|j| j.active()) {
        return Err(err(
            StatusCode::CONFLICT,
            "evacuating",
            format!(
                "namespace {namespace} is evacuating in job {} ({})",
                job.job, job.step
            ),
        ));
    }
    Ok(())
}

pub(crate) fn host_busy(reg: &Registry, id: &str) -> bool {
    reg.evacuations
        .values()
        .any(|j| j.active() && (j.from == id || j.to == id))
}
