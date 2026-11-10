//! Disposable native fixture using the configured production Service constructor.
use super::*;
use crate::{config::Execution, execution_host::TrustedHost};
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use briqyard_api::execution::{
    admission::InstalledProtection, channel::ActiveStatus, CONTINUATION_TYPE,
};
use ring::signature::Ed25519KeyPair;
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex as StdMutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;

fn renewal_protection_deadline_from_qualified_check(qualified_checked_at: u64) -> u64 {
    (qualified_checked_at + 60) * 1000
}

#[test]
fn continuation_protection_covers_the_lease_within_the_qualified_lower_budget() {
    use briqyard_api::execution::clock::ClockSample;
    for fraction_ms in [100, 900] {
        for uncertainty_ms in [2_000, 4_000] {
            let sample = ClockSample {
                wall: Duration::from_millis(1_000_000 + fraction_ms),
                monotonic: std::time::Instant::now(),
                uncertainty: Duration::from_millis(uncertainty_ms),
            };
            let clock = sample.interval().unwrap();
            let checked = (clock.now - 5).min(clock.now - clock.uncertainty);
            let deadline = renewal_protection_deadline_from_qualified_check(checked);
            let lease_expiry = checked + 60;
            assert_eq!(deadline, lease_expiry * 1000);
            assert!(deadline > sample.upper_ms().unwrap());
            assert!(deadline <= (clock.now + 60) * 1000);
            assert!(deadline <= sample.lower_ms().unwrap() + 60_000);
            assert!((clock.now + 60) * 1000 > sample.lower_ms().unwrap() + 60_000);
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    execution: Execution,
    host_tls_fingerprint: String,
    host_administrator_file: PathBuf,
    fleet_administrator_file: PathBuf,
}
#[derive(Clone)]
struct Central {
    app: Arc<StdMutex<Option<Router>>>,
    credential: String,
    key: Arc<Ed25519KeyPair>,
    callbacks: Arc<AtomicUsize>,
    initial_expiry: Arc<StdMutex<Option<u64>>>,
    revoke_ack: Arc<StdMutex<Option<std::time::Instant>>>,
    tasks: Arc<StdMutex<Vec<tokio::task::JoinHandle<()>>>>,
    scenario: String,
    directory: PathBuf,
}
impl Central {
    async fn call(&self, action: &str, body: Value) -> Result<Value> {
        let app = self
            .app
            .lock()
            .unwrap()
            .clone()
            .context("fixture unavailable")?;
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/internal/authority/v1/{action}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", self.credential))
                    .body(Body::from(serde_json::to_vec(&body)?))?,
            )
            .await?;
        ensure!(
            response.status().is_success(),
            "native central {action} refused: {}",
            response.status()
        );
        Ok(serde_json::from_slice(
            &to_bytes(response.into_body(), MAX_BODY_BYTES).await?,
        )?)
    }
    async fn extend(&self, id: &str, previous: u64) -> Result<()> {
        self.callbacks.fetch_add(1, Ordering::SeqCst);
        // This callback re-enters the actual service while its original dispatch
        // RPC remains open. No issuer mutex may span this call.
        let status: ActiveStatus =
            serde_json::from_value(self.call("operation_active", json!({"id":id})).await?)?;
        ensure!(
            status.state == briqyard_api::execution::channel::ActiveState::Active,
            "not active"
        );
        let active = status.evidence.context("missing active evidence")?;
        ensure!(active.sequence == previous, "sequence changed");
        *self.initial_expiry.lock().unwrap() = Some(active.lease_expires_at);
        if self.scenario == "renewable-refused" {
            anyhow::bail!("fixture source reauthorization refused");
        }

        if self.scenario == "renewable-revoked" {
            let reply = self.call("revoke", json!({"id":"native-revoke","host_instance":active.binding.host_instance,
                "request":{"id":active.binding.delegation,"version":active.binding.delegation_version}})).await?;
            ensure!(reply["state"] == "ready", "revocation not committed");
            *self.revoke_ack.lock().unwrap() = Some(std::time::Instant::now());
            return Ok(());
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let clocks: briqyard_api::execution::channel::AuthorizationClock =
            serde_json::from_value(self.call("authorization_clock", json!({})).await?)?;
        let checked = now
            .saturating_sub(5)
            .min(
                clocks
                    .authority
                    .now
                    .saturating_sub(clocks.authority.uncertainty),
            )
            .min(clocks.host.now.saturating_sub(clocks.host.uncertainty));
        let expiry = (checked + 60)
            .min(active.binding.operation_deadline_ms / 1000)
            .min(active.binding.source.expires_at);
        ensure!(expiry > active.lease_expires_at, "no extension");
        let attempt = format!("native-{id}-{previous}");
        let deadline = renewal_protection_deadline_from_qualified_check(checked);
        std::fs::write(
            self.directory.join("protection-deadline"),
            deadline.to_string(),
        )?;
        let receipt: briqyard_api::execution::channel::ProtectionAck = serde_json::from_value(
            self.call(
                "operation_protect",
                json!({
                    "id":attempt,"operation_id":id,"previous_sequence":previous,
                    "committed":{"admission":attempt,"expires_at_ms":deadline}
                }),
            )
            .await?,
        )?;
        let protection = InstalledProtection {
            admission: receipt.admission,
            installation: active.binding.ownership.clone(),
            generation: active.binding.ownership_generation,
            expires_at_ms: receipt.expires_at_ms,
            resources: receipt.resources,
            resource_revision: receipt.revision,
        };
        let claims = briqyard_api::execution::OperationContinuation {
            v: 1,
            iss: "central".into(),
            aud: "runtime".into(),
            iat: checked,
            nbf: checked,
            checked_at: checked,
            exp: expiry,
            previous_sequence: previous,
            sequence: previous + 1,
            binding: active.binding,
            protection,
        };
        let header = json!({"alg":"EdDSA","typ":CONTINUATION_TYPE,"kid":"native-central","v":1});
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?)
        );
        let token = format!(
            "{}.{}",
            input,
            URL_SAFE_NO_PAD.encode(self.key.sign(input.as_bytes()).as_ref())
        );
        let body = json!({"id":attempt,"operation_id":id,"previous_sequence":previous,"continuation":token});
        let ack: ActiveStatus =
            serde_json::from_value(self.call("operation_continue", body.clone()).await?)?;
        ensure!(
            ack.evidence
                .as_ref()
                .is_some_and(|e| e.sequence == previous + 1 && e.lease_expires_at == expiry),
            "timer ACK differs"
        );
        // Duplicate delivery is observation only, even with exhausted quota.
        let duplicate: ActiveStatus =
            serde_json::from_value(self.call("operation_continue", body).await?)?;
        ensure!(
            duplicate
                .evidence
                .as_ref()
                .is_some_and(|e| e.sequence == previous + 1),
            "duplicate continuation differs"
        );
        Ok(())
    }
}
impl renewal::ContinuationProvider for Central {
    fn request<'a>(
        &'a self,
        id: &'a str,
        previous: u64,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), renewal::ContinuationError>> + Send + 'a>,
    > {
        if self.scenario == "renewable-revoked" {
            // The independent central attempt may finish after the dispatch
            // response cancels its callback waiter. Retain and join that exact
            // task; cancellation never creates another revocation request.
            let central = self.clone();
            let id = id.to_owned();
            let (send, receive) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(async move {
                let result = central
                    .extend(&id, previous)
                    .await
                    .map_err(|_| renewal::ContinuationError::Unconfirmed);
                let _ = send.send(result);
            });
            self.tasks.lock().unwrap().push(task);
            return Box::pin(async {
                receive
                    .await
                    .unwrap_or(Err(renewal::ContinuationError::Unconfirmed))
            });
        }
        Box::pin(async move {
            self.extend(id, previous)
                .await
                .map_err(|_| renewal::ContinuationError::Unconfirmed)
        })
    }
}

#[tokio::test]
#[ignore = "requires the disposable scoped-execution-native.sh fixture, real Linux KVM guests"]
async fn renewable_service_callback_host_guest() -> Result<()> {
    ensure!(
        cfg!(target_os = "linux")
            && std::env::var("RUNNER_ENVIRONMENT").as_deref() == Ok("github-hosted"),
        "disposable Linux fixture required"
    );
    let dir = PathBuf::from(std::env::var("BRIQYARD_NATIVE_DIRECTORY")?);
    let driver = PathBuf::from(std::env::var("BRIQYARD_NATIVE_DRIVER")?);
    let namespace = std::env::var("BRIQYARD_NATIVE_NAMESPACE")?;
    let machine = std::env::var("BRIQYARD_NATIVE_MACHINE")?;
    let sibling = std::env::var("BRIQYARD_NATIVE_SIBLING")?;
    let configuration: Configuration =
        serde_yaml::from_slice(&std::fs::read(dir.join("authority.yaml"))?)?;
    for (index, scenario) in ["renewable", "renewable-refused", "renewable-revoked"]
        .into_iter()
        .enumerate()
    {
        let cfg = &configuration.execution;
        let (credentials, keys, tls) = cfg.channel.load().map_err(anyhow::Error::msg)?;
        let central = Arc::new(Central {
            app: Arc::new(StdMutex::new(None)),
            credential: credentials.central_installer.clone(),
            key: Arc::new(
                Ed25519KeyPair::from_pkcs8(&std::fs::read(dir.join("central.pk8"))?)
                    .map_err(|_| anyhow::anyhow!("fixture key"))?,
            ),
            callbacks: Arc::new(AtomicUsize::new(0)),
            initial_expiry: Arc::new(StdMutex::new(None)),
            revoke_ack: Arc::new(StdMutex::new(None)),
            tasks: Arc::new(StdMutex::new(Vec::new())),
            scenario: scenario.into(),
            directory: dir.clone(),
        });
        let journal = briqyard_api::execution::admission::Journal::open(
            &dir.join(format!("native-authority-{index}")),
            briqyard_api::execution::admission::Role::Authority(cfg.authority.clone()),
        )?;
        let issuer = briqyard_api::execution::DurableIssuer::from_pkcs8(
            journal,
            &std::fs::read(&cfg.signing_key)?,
            cfg.key_id.clone(),
        )?;
        let host_admin = std::fs::read_to_string(&configuration.host_administrator_file)?;
        let fleet_admin = std::fs::read_to_string(&configuration.fleet_administrator_file)?;
        let transport = HostTransport::from_trusted(
            TrustedHost {
                id: &cfg.host_id,
                tls_fingerprint: &configuration.host_tls_fingerprint,
                administrator: &host_admin,
            },
            &cfg.host_url,
            &credentials.host_installer,
            &credentials.host_execution,
            Duration::from_secs(85),
        )
        .map_err(|_| anyhow::anyhow!("host transport"))?;
        let app = router_with_continuation(
            issuer,
            transport,
            cfg.host_id.clone(),
            Credentials {
                installer: credentials.central_installer,
                gateway: credentials.gateway,
                administrator: fleet_admin.clone(),
                host_administrator: host_admin,
            },
            &fleet_admin,
            TrustConfig {
                keys,
                central_issuer: cfg.channel.central_issuer.clone(),
                authority_issuer: cfg.channel.authority_issuer.clone(),
                audience: cfg.channel.audience.clone(),
            },
            Arc::new(briqyard_api::execution::clock::KernelClock),
            Some(central.clone()),
        )
        .map_err(anyhow::Error::msg)?;
        *central.app.lock().unwrap() = Some(app.clone());
        let listener = std::net::TcpListener::bind(cfg.channel.listen)?;
        let handle = axum_server::Handle::new();
        let running = handle.clone();
        let server = tokio::spawn(async move {
            axum_server::from_tcp_rustls(
                listener,
                axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls)),
            )
            .handle(running)
            .serve(app.into_make_service())
            .await
        });
        let mut command = tokio::process::Command::new(&driver);
        command
            .args([
                scenario,
                dir.to_str().context("fixture path")?,
                &namespace,
                &machine,
                &sibling,
            ])
            .kill_on_drop(true);
        let outcome = tokio::time::timeout(Duration::from_secs(100), command.status()).await;
        let completed = std::time::Instant::now();
        let tasks = std::mem::take(&mut *central.tasks.lock().unwrap());
        for mut task in tasks {
            if tokio::time::timeout(Duration::from_secs(10), &mut task)
                .await
                .is_err()
            {
                task.abort();
                let _ = task.await;
            }
        }
        handle.shutdown();
        server.abort();
        let _ = server.await;
        *central.app.lock().unwrap() = None;
        ensure!(
            outcome
                .context("native driver deadline; do not replay")??
                .success(),
            "native driver failed"
        );
        if index > 0 {
            let expiry = central
                .initial_expiry
                .lock()
                .unwrap()
                .context("no live initial lease observed")?;
            let observed: briqyard_api::execution::channel::ClockObservation =
                serde_json::from_slice(&std::fs::read(
                    dir.join(format!("response-observation-{scenario}")),
                )?)?;
            let upper = observed.now.saturating_add(observed.uncertainty);
            if scenario == "renewable-refused" {
                ensure!(
                    upper >= expiry,
                    "source refusal returned before earliest qualified lease expiry"
                );
            } else {
                let ack = central
                    .revoke_ack
                    .lock()
                    .unwrap()
                    .context("no successful durable revoke ACK")?;
                ensure!(
                    completed.saturating_duration_since(ack) < Duration::from_secs(5),
                    "quiet command did not terminate promptly after revoke ACK"
                );
                ensure!(
                    upper.saturating_add(8) < expiry,
                    "revocation termination was not distinct from initial lease expiry"
                );
            }
        }
        let callbacks = central.callbacks.load(Ordering::SeqCst);
        ensure!(
            callbacks >= if index == 0 { 2 } else { 1 },
            "continuation callback was not exercised"
        );
    }
    println!("renewable native: Service callback reentry, full guest timeout, quota-window crossing, quiet I/O, duplicate continuation, source refusal and revoke passed");
    Ok(())
}
