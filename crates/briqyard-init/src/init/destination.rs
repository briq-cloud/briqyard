//! One-way installation of a complete sandbox destination before main exists.
use super::*;
use guest::{CloneIdentity, CloneStatus, DestinationBind, SANDBOX_READY_V1};
use sha2::{Digest, Sha256};

pub(super) const RECEIPT: &str = "/.briqyard-destination-binding-v1.json";

pub(super) enum Barrier {
    Builder,
    Bound {
        fingerprint: String,
        identity: CloneIdentity,
        activating: bool,
        active: bool,
    },
    Failed,
}
impl Barrier {
    pub(super) fn allows(&self, op: &str) -> bool {
        matches!(self, Self::Bound { active: true, .. })
            || matches!(op, "ping" | "destination_bind_v1" | "clone_activate_v1")
    }
    pub(super) fn activating(&self) -> bool {
        matches!(
            self,
            Self::Bound {
                activating: true,
                ..
            }
        )
    }
    pub(super) fn mark_active(&mut self) {
        if let Self::Bound { active, .. } = self {
            *active = true;
        }
    }
    pub(super) fn status(&self) -> CloneStatus {
        let (stage, identity) = match self {
            Self::Builder => ("builder", None),
            Self::Failed => ("failed", None),
            Self::Bound {
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
                    "destination_done"
                },
                Some(identity.clone()),
            ),
        };
        CloneStatus {
            protocol: 1,
            profile: SANDBOX_READY_V1.into(),
            ram_marker: clone_identity::ram_marker(),
            stage: stage.into(),
            identity,
        }
    }
    fn response(&self) -> Response {
        Response {
            clone_status: Some(self.status()),
            sha256: match self {
                Self::Bound { fingerprint, .. } => fingerprint.clone(),
                _ => String::new(),
            },
            ..Response::new("ok")
        }
    }
    pub(super) fn activate(
        &mut self,
        st: &State,
        generation: &str,
        realtime: Option<u64>,
    ) -> Response {
        match self {
            Self::Bound {
                identity,
                activating,
                active,
                ..
            } if identity.generation == generation => {
                if !*active && !*activating {
                    let Some(seconds) = realtime else {
                        return Response::error("sandbox activation requires fresh wall time");
                    };
                    if !(1_735_689_600..=4_102_444_800).contains(&seconds) {
                        return Response::error(
                            "sandbox activation clock outside supported interval",
                        );
                    }
                    if let Err(e) = clone_identity::set_clock(seconds) {
                        return Response::error(format!("sandbox activation clock: {e:#}"));
                    }
                }
                *activating = true;
                st.activate.notify_one();
                self.response()
            }
            _ => Response::error("sandbox activation requires acknowledged destination generation"),
        }
    }
}

pub(super) fn pristine(c: &Config) -> bool {
    c.hostname.is_empty()
        && c.ip.is_empty()
        && c.gateway.is_empty()
        && c.dns.is_empty()
        && c.hosts.is_empty()
        && c.entrypoint.is_empty()
        && c.cmd.is_empty()
        && c.env.is_empty()
        && c.workdir.is_empty()
        && c.user.is_empty()
        && c.mounts.is_empty()
        && c.files.is_empty()
}

fn fingerprint(request: &DestinationBind) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(request.fingerprint_bytes()?);
    Ok(hex::encode(hash.finalize()))
}

/// A durable consumed marker precedes all identity, disk and file side effects. A crash
/// leaves the disk consumed; only the live gate can replay a completed acknowledgment.
fn reserve(path: &Path, fingerprint: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let parent = path.parent().context("destination receipt parent")?;
    fs::create_dir_all(parent)?;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(
        serde_json::to_string(&serde_json::json!({
            "protocol": 1, "stage": "consumed", "sha256": fingerprint
        }))?
        .as_bytes(),
    )?;
    f.sync_all()?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub(super) async fn bind(st: &State, request: Option<DestinationBind>) -> Response {
    bind_with(st, request, Path::new(RECEIPT), |request| {
        install(st, request)
    })
    .await
}

async fn bind_with<F, Fut>(
    st: &State,
    request: Option<DestinationBind>,
    receipt: &Path,
    install: F,
) -> Response
where
    F: FnOnce(DestinationBind) -> Fut,
    Fut: std::future::Future<Output = Result<CloneIdentity>>,
{
    let Some(request) = request else {
        return Response::error("missing sandbox destination");
    };
    if let Err(e) = request.validate() {
        return Response::error(e);
    }
    let fingerprint = match fingerprint(&request) {
        Ok(v) => v,
        Err(_) => return Response::error("destination fingerprint failed"),
    };
    let mut gate = st.clone_gate.lock().await;
    match &*gate {
        clone::Gate::Sandbox(Barrier::Bound {
            fingerprint: previous,
            ..
        }) if previous == &fingerprint => {
            if let clone::Gate::Sandbox(b) = &*gate {
                return b.response();
            }
        }
        clone::Gate::Sandbox(Barrier::Builder) => {}
        _ => return Response::error("destination conflict or unavailable barrier"),
    }
    *gate = clone::Gate::Sandbox(Barrier::Failed);
    let result = async {
        reserve(receipt, &fingerprint)?;
        install(request).await
    }
    .await;
    match result {
        Ok(identity) => {
            let bound = Barrier::Bound {
                fingerprint,
                identity,
                activating: false,
                active: false,
            };
            let response = bound.response();
            *gate = clone::Gate::Sandbox(bound);
            response
        }
        Err(_) => {
            Response::error("sandbox destination installation failed; guest remains quarantined")
        }
    }
}

async fn install(st: &State, request: DestinationBind) -> Result<CloneIdentity> {
    let identity = clone_identity::configure(&request.identity).await?;
    destination_mounts::setup(&request.config)?;
    for file in &request.files {
        files::install(Path::new("/"), &file.path, file.mode, &file.data).await?;
    }
    fs::write("/etc/hosts", hosts_text(&request.config))?;
    let env = build_env(&request.config.env);
    st.destination
        .set((request.config, env))
        .map_err(|_| anyhow!("destination already installed"))?;
    // Flush destination files and mounted volume before acknowledging the bind.
    if unsafe { libc::syncfs(fs::File::open("/")?.as_raw_fd()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("sync destination root");
    }
    if unsafe { libc::syncfs(fs::File::open("/work")?.as_raw_fd()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("sync destination volume");
    }
    Ok::<_, anyhow::Error>(identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn receipt_is_durable_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipt");
        reserve(&path, "first").unwrap();
        assert!(reserve(&path, "second").is_err());
        assert!(fs::read_to_string(path).unwrap().contains("first"));
    }
    #[tokio::test]
    async fn sandbox_cannot_activate_or_execute_before_binding() {
        let st = testutil::state_with(Config {
            template_profile: Some(SANDBOX_READY_V1.into()),
            ..Default::default()
        });
        assert_eq!(clone::activate(&st, "unbound", None).await.kind, "error");
        let gate = st.clone_gate.lock().await;
        for op in ["exec", "put", "get", "shutdown", "clone_configure_v1"] {
            assert!(!gate.allows(op));
        }
        assert!(gate.allows("destination_bind_v1"));
    }
}

#[cfg(test)]
mod replay_tests {
    use super::*;
    pub(super) fn request() -> DestinationBind {
        let identity = guest::CloneConfigure {
            generation: "sandbox-1".into(),
            hostname: "sandbox-1".into(),
            ip: "10.64.1.2/24".into(),
            gateway: "10.64.1.1".into(),
            dns: vec!["10.64.1.1".into()],
            mac: [2, 1, 2, 3, 4, 5],
            entropy: [42; 32],
            realtime_sec: 1_793_404_800,
        };
        DestinationBind {
            config: Config {
                hostname: identity.hostname.clone(),
                ip: identity.ip.clone(),
                gateway: identity.gateway.clone(),
                dns: identity.dns.clone(),
                cmd: vec!["sleep".into(), "infinity".into()],
                mounts: vec![guest::Mount {
                    device: "/dev/vdc".into(),
                    path: "/work".into(),
                    fstype: "ext4".into(),
                }],
                sandbox_device: Some(guest::SandboxDevice {
                    bytes: 2 << 30,
                    logical_sector_bytes: 512,
                    drive_id: "data".into(),
                }),
                ..Default::default()
            },
            identity,
            files: vec![],
            receipt: "a".repeat(64),
        }
    }
    #[tokio::test]
    async fn replay_returns_original_ack_and_changed_application_config_conflicts() {
        let st = testutil::state();
        let r = request();
        let digest = fingerprint(&r).unwrap();
        *st.clone_gate.lock().await = clone::Gate::Sandbox(Barrier::Bound {
            fingerprint: digest.clone(),
            identity: CloneIdentity {
                generation: r.identity.generation.clone(),
                hostname: r.identity.hostname.clone(),
                ip: r.identity.ip.clone(),
                mac: r.identity.mac,
                machine_id: "fresh".into(),
            },
            activating: false,
            active: false,
        });
        let ack = bind(&st, Some(r.clone())).await;
        assert_eq!(ack.kind, "ok");
        assert_eq!(ack.sha256, digest);
        assert_eq!(
            ack.clone_status.unwrap().identity.unwrap().machine_id,
            "fresh"
        );
        let mut changed = r.clone();
        changed
            .config
            .env
            .insert("SECRET".into(), "different".into());
        assert_eq!(bind(&st, Some(changed)).await.kind, "error");
        let mut changed = r.clone();
        changed.config.cmd.push("different".into());
        assert_eq!(bind(&st, Some(changed)).await.kind, "error");
        let mut changed = r.clone();
        changed.receipt = "b".repeat(64);
        assert_eq!(bind(&st, Some(changed)).await.kind, "error");
        assert!(!st.clone_gate.lock().await.allows("exec"));
        assert_eq!(clone::activate(&st, "wrong", None).await.kind, "error");
        assert_eq!(clone::activate(&st, "sandbox-1", None).await.kind, "error");
        assert_eq!(bind(&st, Some(r)).await.kind, "ok");
    }
    #[tokio::test]
    async fn seed_failure_consumes_destination_without_ack_or_activation() {
        let root = tempfile::tempdir().unwrap();
        let receipt = root.path().join("receipt");
        let source = root.path().join("work");
        let destination = root.path().join("disk");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(source.join("original"), b"retained source").unwrap();
        let st = testutil::state_with(Config {
            template_profile: Some(SANDBOX_READY_V1.into()),
            ..Default::default()
        });
        let r = request();
        let digest = fingerprint(&r).unwrap();
        let response = bind_with(&st, Some(r.clone()), &receipt, |_| async {
            destination_mounts::injected_seed_failure(&source, &destination)?;
            panic!("seed failure must abort installation")
        })
        .await;
        assert_eq!(response.kind, "error");
        assert!(response.sha256.is_empty());
        assert!(response.clone_status.is_none());
        assert!(fs::read_to_string(&receipt).unwrap().contains(&digest));
        assert_eq!(
            fs::read(root.path().join("work.briqyard-seed/content/original")).unwrap(),
            b"retained source"
        );
        assert_eq!(
            fs::read(destination.join("partial")).unwrap(),
            b"partial copy"
        );
        assert!(st.destination.get().is_none());
        assert!(!st.clone_gate.lock().await.allows("exec"));
        assert!(!st.clone_gate.lock().await.activation_requested());
        assert_eq!(
            clone::activate(&st, "sandbox-1", Some(1_793_404_800))
                .await
                .kind,
            "error"
        );
        assert_eq!(
            bind_with(&st, Some(r), &receipt, |_| async {
                panic!("failed bind must not retry")
            })
            .await
            .kind,
            "error"
        );
        assert!(reserve(&receipt, "another").is_err());
    }

    #[test]
    fn installed_config_replaces_seed_environment_for_main_and_exec() {
        let st = testutil::state();
        let mut cfg = request().config;
        cfg.env.insert("DESTINATION".into(), "new".into());
        cfg.workdir = "/work".into();
        let env = build_env(&cfg.env);
        st.destination.set((cfg, env)).unwrap();
        assert_eq!(st.config().workdir, "/work");
        assert!(st
            .environment()
            .contains(&("DESTINATION".into(), "new".into())));
        assert_eq!(st.config().cmd, ["sleep", "infinity"]);
    }
    #[tokio::test]
    async fn boot_file_install_never_follows_image_symlinks() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("receipt"), b"retained").unwrap();
        std::os::unix::fs::symlink("receipt", root.path().join("alias")).unwrap();
        files::install(root.path(), "/alias", 0o600, b"destination")
            .await
            .unwrap();
        assert_eq!(fs::read(root.path().join("receipt")).unwrap(), b"retained");
        std::os::unix::fs::symlink(root.path(), root.path().join("dir")).unwrap();
        assert!(files::install(root.path(), "/dir/receipt", 0o600, b"bad")
            .await
            .is_err());
    }
}

#[cfg(test)]
mod device_failure_tests {
    use super::*;
    #[tokio::test]
    async fn block_cache_invalidation_failure_cannot_ack_or_activate() {
        // Use the same valid payload fixture as replay coverage.
        let request = super::replay_tests::request();
        let st = testutil::state_with(Config {
            template_profile: Some(SANDBOX_READY_V1.into()),
            ..Default::default()
        });
        let directory = tempfile::tempdir().unwrap();
        let receipt = directory.path().join("receipt");
        let file = tempfile::tempfile().unwrap();
        let response = bind_with(&st, Some(request), &receipt, |_| async {
            sandbox_device::reset_cache(&file, || Ok("0 0".into()))?;
            panic!("regular file cannot pass block invalidation")
        })
        .await;
        assert_eq!(response.kind, "error");
        assert!(response.sha256.is_empty());
        assert!(receipt.exists());
        assert!(!st.clone_gate.lock().await.allows("exec"));
        assert_eq!(
            clone::activate(&st, "sandbox-1", Some(1_793_404_800))
                .await
                .kind,
            "error"
        );
    }
}
