//! Probes (ADR 0022).

use super::*;

/// A check the daemon runs on a running machine (ADR 0022): exactly one of `exec`, `tcp` and
/// `http`, every `period_sec`, from `initial_delay_sec` after it may start.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Probe {
    /// A command run in the machine through its init: exit 0 passes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<Vec<String>>,
    /// A TCP connect from the host to this port of the machine's address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp: Option<u16>,
    /// A GET from the host: 200 to 399 passes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpProbe>,
    #[serde(default = "default_period")]
    pub period_sec: u32,
    /// For one execution, counted once it holds its turn.
    #[serde(default = "default_probe_timeout")]
    pub timeout_sec: u32,
    /// Failures in a row that fail it.
    #[serde(default = "default_failures")]
    pub failure_threshold: u32,
    /// Passes in a row that pass it; 1 for startup and liveness.
    #[serde(default = "default_successes")]
    pub success_threshold: u32,
    #[serde(default)]
    pub initial_delay_sec: u32,
}

/// An HTTP probe's target on the machine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpProbe {
    pub port: u16,
    #[serde(default = "default_probe_path")]
    pub path: String,
}

fn default_period() -> u32 {
    10
}
fn default_probe_timeout() -> u32 {
    5
}
fn default_failures() -> u32 {
    3
}
fn default_successes() -> u32 {
    1
}
fn default_probe_path() -> String {
    "/".into()
}

impl Default for Probe {
    /// No action yet, Kubernetes's timings.
    fn default() -> Self {
        Self {
            exec: None,
            tcp: None,
            http: None,
            period_sec: default_period(),
            timeout_sec: default_probe_timeout(),
            failure_threshold: default_failures(),
            success_threshold: default_successes(),
            initial_delay_sec: 0,
        }
    }
}

impl Probe {
    /// One action, well formed, and timings the daemon can run; the message names the field
    /// under `name` (`probes.readiness`).
    pub fn check(&self, name: &str, one_success: bool) -> Result<(), String> {
        let actions = [self.exec.is_some(), self.tcp.is_some(), self.http.is_some()];
        if actions.iter().filter(|a| **a).count() != 1 {
            return Err(format!("{name}: exactly one of exec, tcp and http"));
        }
        if self.exec.as_ref().is_some_and(|c| c.is_empty()) {
            return Err(format!("{name}.exec: an empty command"));
        }
        if self.tcp == Some(0) {
            return Err(format!("{name}.tcp: 0 is not a port"));
        }
        if let Some(h) = &self.http {
            if h.port == 0 {
                return Err(format!("{name}.http.port: 0 is not a port"));
            }
            if !h.path.starts_with('/') || !h.path.bytes().all(|c| c.is_ascii_graphic()) {
                return Err(format!(
                    "{name}.http.path: a path, \"/\" then printable ASCII without spaces"
                ));
            }
        }
        for (field, v) in [
            ("period_sec", self.period_sec),
            ("timeout_sec", self.timeout_sec),
            ("failure_threshold", self.failure_threshold),
            ("success_threshold", self.success_threshold),
        ] {
            if v == 0 {
                return Err(format!("{name}.{field}: at least 1"));
            }
        }
        if one_success && self.success_threshold != 1 {
            return Err(format!("{name}.success_threshold: must be 1"));
        }
        Ok(())
    }

    /// What it checks, for a person: `exec test -f /tmp/alive`, `tcp :5432`, `http :8080/`.
    pub fn target(&self) -> String {
        match (&self.exec, self.tcp, &self.http) {
            (Some(cmd), _, _) => format!("exec {}", cmd.join(" ")),
            (_, Some(port), _) => format!("tcp :{port}"),
            (_, _, Some(h)) => format!("http :{}{}", h.port, h.path),
            _ => "nothing".into(),
        }
    }
}

/// A machine's probes (ADR 0022): startup gates the other two, readiness sets `ready`, liveness
/// restarts the machine under its restart policy.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Probes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup: Option<Probe>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness: Option<Probe>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness: Option<Probe>,
}

impl Probes {
    pub fn is_empty(&self) -> bool {
        self.startup.is_none() && self.readiness.is_none() && self.liveness.is_none()
    }

    /// Each probe checked, its field named under `probes`.
    pub fn check(&self) -> Result<(), String> {
        for (name, p, one_success) in [
            ("startup", &self.startup, true),
            ("readiness", &self.readiness, false),
            ("liveness", &self.liveness, true),
        ] {
            if let Some(p) = p {
                p.check(&format!("probes.{name}"), one_success)?;
            }
        }
        Ok(())
    }
}

/// The last execution of a probe in the current run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeStatus {
    pub passed: bool,
    /// What it answered: `exit 1: …`, `HTTP 503`, `connection refused`.
    pub message: String,
    /// Failures in a row; 0 after a pass.
    pub failures: u32,
    pub at: DateTime<Utc>,
}

/// Each probe's last result in the current run; absent before its first execution.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbesStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup: Option<ProbeStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness: Option<ProbeStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness: Option<ProbeStatus>,
}

impl ProbesStatus {
    pub fn is_empty(&self) -> bool {
        self.startup.is_none() && self.readiness.is_none() && self.liveness.is_none()
    }
}
