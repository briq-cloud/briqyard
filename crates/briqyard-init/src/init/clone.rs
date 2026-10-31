//! A guest born at a barrier never accepts ordinary work until identity and activation.
use super::*;
use guest::{CloneConfigure, CloneIdentity, CloneStatus, INIT_READY_V1};

pub(super) enum Gate {
    Ordinary,
    Builder,
    Configured {
        request: CloneConfigure,
        identity: CloneIdentity,
        active: bool,
        activating: bool,
    },
    Failed,
}
impl Gate {
    pub(super) fn from_config(cfg: &Config) -> Result<Self> {
        match cfg.template_profile.as_deref() {
            None => Ok(Self::Ordinary),
            Some(INIT_READY_V1)
                if cfg.files.is_empty()
                    && cfg.mounts.is_empty()
                    && cfg.ip.is_empty()
                    && cfg.gateway.is_empty()
                    && cfg.dns.is_empty()
                    && cfg.hosts.is_empty()
                    && cfg.hostname.is_empty() =>
            {
                Ok(Self::Builder)
            }
            Some(_) => Err(anyhow!("unsupported or non-quarantined template config")),
        }
    }
    pub(super) fn allows(&self, op: &str) -> bool {
        match self {
            Self::Ordinary => !op.starts_with("clone_"),
            Self::Configured { active: true, .. } => true,
            _ => matches!(op, "ping" | "clone_configure_v1" | "clone_activate_v1"),
        }
    }
    pub(super) fn activation_requested(&self) -> bool {
        matches!(
            self,
            Self::Configured {
                activating: true,
                ..
            }
        )
    }
    pub(super) fn mark_active(&mut self) {
        if let Self::Configured { active, .. } = self {
            *active = true;
        }
    }
    pub(super) fn status(&self) -> Option<CloneStatus> {
        let (stage, identity) = match self {
            Self::Ordinary => return None,
            Self::Builder => ("builder", None),
            Self::Failed => ("failed", None),
            Self::Configured {
                identity,
                active,
                activating,
                ..
            } => (
                if *active {
                    "active"
                } else if *activating {
                    "activating"
                } else {
                    "identity_done"
                },
                Some(identity.clone()),
            ),
        };
        Some(CloneStatus {
            protocol: 1,
            profile: INIT_READY_V1.into(),
            stage: stage.into(),
            identity,
        })
    }
}
fn response(gate: &Gate) -> Response {
    Response {
        clone_status: gate.status(),
        ..Response::new("ok")
    }
}

pub(super) async fn configure(st: &State, request: Option<CloneConfigure>) -> Response {
    let Some(request) = request else {
        return Response::error("missing clone configuration");
    };
    if let Err(e) = request.validate() {
        return Response::error(e);
    }
    // Serialize side effects and the ACK: replay cannot regenerate identity after a lost ACK.
    let mut gate = st.clone_gate.lock().await;
    match &*gate {
        Gate::Configured {
            request: previous, ..
        } if previous == &request => return response(&gate),
        Gate::Builder => {}
        _ => return Response::error("clone generation conflict or unavailable barrier"),
    }
    // Partial configuration is terminal; never rerun RNG/key reset on an uncertain guest.
    *gate = Gate::Failed;
    match clone_identity::configure(&request).await {
        Ok(identity) => {
            *gate = Gate::Configured {
                request,
                identity,
                active: false,
                activating: false,
            };
            response(&gate)
        }
        Err(e) => Response::error(format!("clone identity failed: {e:#}")),
    }
}

pub(super) async fn activate(st: &State, generation: &str) -> Response {
    let mut gate = st.clone_gate.lock().await;
    match &mut *gate {
        Gate::Configured {
            identity,
            activating,
            ..
        } if identity.generation == generation => {
            *activating = true;
            st.activate.notify_one();
            response(&gate)
        }
        _ => Response::error("clone activation requires acknowledged identity generation"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn builder_refuses_all_work_and_unknown_profiles() {
        let cfg = Config {
            template_profile: Some(INIT_READY_V1.into()),
            ..Default::default()
        };
        let gate = Gate::from_config(&cfg).unwrap();
        for op in ["exec", "put", "get", "put_stream", "get_stream", "shutdown"] {
            assert!(!gate.allows(op));
        }
        assert!(gate.allows("ping"));
        assert!(gate.allows("clone_configure_v1"));
        let cfg = Config {
            ip: "10.64.1.2/24".into(),
            ..cfg
        };
        assert!(Gate::from_config(&cfg).is_err());
        let cfg = Config {
            template_profile: Some("service-ready-v1".into()),
            ..Default::default()
        };
        assert!(Gate::from_config(&cfg).is_err());
    }
    fn configured(st: &State) -> CloneConfigure {
        let request = CloneConfigure {
            generation: "clone-1".into(),
            hostname: "clone-1".into(),
            ip: "10.64.1.2/24".into(),
            gateway: "10.64.1.1".into(),
            dns: vec!["10.64.1.1".into()],
            mac: [2, 1, 2, 3, 4, 5],
            entropy: [42; 32],
            realtime_sec: 1_793_404_800,
        };
        let identity = CloneIdentity {
            generation: request.generation.clone(),
            hostname: request.hostname.clone(),
            ip: request.ip.clone(),
            mac: request.mac,
            machine_id: "0123456789abcdef0123456789abcdef".into(),
        };
        *st.clone_gate.try_lock().unwrap() = Gate::Configured {
            request: request.clone(),
            identity,
            active: false,
            activating: false,
        };
        request
    }

    #[tokio::test]
    async fn lost_ack_replay_never_reconfigures_and_conflicting_generation_refused() {
        let st = testutil::state();
        let request = configured(&st);
        let response = configure(&st, Some(request.clone())).await;
        assert_eq!(response.kind, "ok");
        assert_eq!(response.clone_status.unwrap().stage, "identity_done");
        let mut conflicting = request.clone();
        conflicting.generation = "clone-2".into();
        assert_eq!(configure(&st, Some(conflicting)).await.kind, "error");
        assert_eq!(activate(&st, "clone-2").await.kind, "error");
        assert_eq!(activate(&st, "clone-1").await.kind, "ok");
        assert!(!st.clone_gate.lock().await.allows("exec"));
        assert_eq!(activate(&st, "clone-1").await.kind, "ok");
        st.clone_gate.lock().await.mark_active();
        assert!(st.clone_gate.lock().await.allows("exec"));
        // Retried configure after activation must return the original identity unchanged.
        assert_eq!(
            configure(&st, Some(request))
                .await
                .clone_status
                .unwrap()
                .stage,
            "active"
        );
    }

    #[tokio::test]
    async fn activation_before_identity_and_retry_of_partial_failure_refused() {
        let st = testutil::state();
        let request = configured(&st);
        *st.clone_gate.lock().await = Gate::Builder;
        assert_eq!(activate(&st, "clone-1").await.kind, "error");
        *st.clone_gate.lock().await = Gate::Failed;
        assert_eq!(configure(&st, Some(request)).await.kind, "error");
    }
}
