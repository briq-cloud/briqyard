//! Scoped authority process. Never opens a fleet registry or starts fleet management.
use crate::{
    api,
    config::Execution,
    execution_host::{HostTransport, TrustedHost},
    execution_service,
};
use anyhow::{anyhow, Context, Result};
use axum::Router;
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityConfig {
    execution: Execution,
    host_tls_fingerprint: String,
    host_administrator_file: PathBuf,
    fleet_administrator_file: PathBuf,
}
impl AuthorityConfig {
    fn load(path: &Path) -> Result<Self> {
        // No defaults, environment overlays or alternate fleet configuration path.
        let bytes =
            api::execution::provision::read(path, false, 256 * 1024).map_err(anyhow::Error::msg)?;
        let config: Self = serde_yaml::from_slice(&bytes)
            .map_err(|_| anyhow!("invalid authority configuration"))?;
        config
            .execution
            .channel
            .validate("")
            .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(
            config.host_administrator_file.is_absolute()
                && config.host_administrator_file != config.fleet_administrator_file
                && config.fleet_administrator_file.is_absolute()
                && config.execution.signing_key.is_absolute(),
            "invalid authority file path"
        );
        Ok(config)
    }
}
fn administrator(path: &Path) -> Result<String> {
    let bytes = api::execution::provision::read(path, true, 4096).map_err(anyhow::Error::msg)?;
    let token = String::from_utf8(bytes).map_err(|_| anyhow!("invalid administrator reference"))?;
    anyhow::ensure!(
        !token.is_empty() && token.bytes().all(|b| b.is_ascii_graphic()),
        "invalid administrator reference"
    );
    Ok(token)
}

pub(super) fn provision(
    execution: &Execution,
    host: TrustedHost<'_>,
    administrator: &str,
) -> Result<(axum_server::tls_rustls::RustlsConfig, Router)> {
    let channel = &execution.channel;
    let (credentials, keys, tls) = channel.load().map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        execution.host_id == host.id
            && credentials.host_administrator == host.administrator
            && credentials.fleet_administrator == administrator,
        "execution administrator identity mismatch"
    );
    let transport = HostTransport::from_trusted(
        host,
        &execution.host_url,
        &credentials.host_installer,
        &credentials.host_execution,
        std::time::Duration::from_secs(75),
    )
    .map_err(|_| anyhow!("invalid execution host transport"))?;
    let journal = api::execution::admission::Journal::open(
        &channel.journal,
        api::execution::admission::Role::Authority(execution.authority.clone()),
    )?;
    let key = api::execution::provision::read(&execution.signing_key, true, 16 * 1024)
        .map_err(anyhow::Error::msg)?;
    let issuer =
        api::execution::DurableIssuer::from_pkcs8(journal, &key, execution.key_id.clone())?;
    anyhow::ensure!(
        keys.iter()
            .any(|key| key.role == api::execution::KeyRole::Authority
                && key.kid == execution.key_id
                && key.issuer == channel.authority_issuer
                && key.authority.as_deref() == Some(&execution.authority)
                && key.public_key.as_slice() == issuer.public_key()),
        "execution signing identity mismatch"
    );
    let router = execution_service::router(
        issuer,
        transport,
        execution.host_id.clone(),
        execution_service::Credentials {
            installer: credentials.central_installer,
            gateway: credentials.gateway,
            administrator: credentials.fleet_administrator,
            host_administrator: credentials.host_administrator,
        },
        administrator,
        execution_service::TrustConfig {
            keys,
            central_issuer: channel.central_issuer.clone(),
            authority_issuer: channel.authority_issuer.clone(),
            audience: channel.audience.clone(),
        },
        Arc::new(api::execution::clock::KernelClock),
    )
    .map_err(anyhow::Error::msg)?;
    Ok((
        axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls)),
        router,
    ))
}

pub(super) async fn run(path: &Path) -> Result<()> {
    let config = AuthorityConfig::load(path)?;
    let host_admin = administrator(&config.host_administrator_file)?;
    let fleet_admin = administrator(&config.fleet_administrator_file)?;
    let (tls, router) = provision(
        &config.execution,
        TrustedHost {
            id: &config.execution.host_id,
            tls_fingerprint: &config.host_tls_fingerprint,
            administrator: &host_admin,
        },
        &fleet_admin,
    )?;
    let listeners = api::listeners::Listeners::from_env();
    let listener = listeners
        .tcp("execution", config.execution.channel.listen)
        .context("listen for scoped authority")?;
    listener.set_nonblocking(true)?;
    listeners
        .release_unused()
        .context("release unused authority listeners")?;
    let handle = axum_server::Handle::new();
    let server = axum_server::from_tcp_rustls(listener, tls)
        .handle(handle.clone())
        .serve(router.into_make_service());
    tokio::pin!(server);
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = &mut server => result?,
        _ = async { tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} } } => {
            handle.graceful_shutdown(Some(crate::DRAIN));
            server.await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn configuration() -> serde_json::Value {
        serde_json::json!({"execution":{"channel":{"listen":"127.0.0.1:7442",
            "cert":"/cert","key":"/key","journal":"/journal","credentials":"/credentials",
            "verification_keys":"/keys","central_issuer":"central","authority_issuer":"authority","audience":"runtime"},
            "host_id":"host","host_url":"https://127.0.0.1:7441","authority":"region",
            "key_id":"key","signing_key":"/signing"},"host_tls_fingerprint":"ab".repeat(32),
            "host_administrator_file":"/host-admin","fleet_administrator_file":"/fleet-admin"})
    }
    #[test]
    fn authority_configuration_rejects_normal_fleet_fields_and_missing_inputs() {
        let value = configuration();
        assert!(serde_json::from_value::<AuthorityConfig>(value.clone()).is_ok());
        for field in [
            "hosts",
            "placement",
            "bootstrap",
            "registry",
            "backup",
            "listen",
            "metrics_token",
            "state_dir",
            "token",
            "tls",
        ] {
            let mut changed = value.clone();
            changed[field] = serde_json::json!({});
            assert!(
                serde_json::from_value::<AuthorityConfig>(changed).is_err(),
                "{field}"
            );
        }
        for field in [
            "execution",
            "host_tls_fingerprint",
            "host_administrator_file",
            "fleet_administrator_file",
        ] {
            let mut changed = value.clone();
            changed.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<AuthorityConfig>(changed).is_err(),
                "{field}"
            );
        }
    }
    #[tokio::test]
    async fn authority_dispatch_never_uses_missing_fleet_defaults_or_creates_state() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("missing.yaml");
        assert!(crate::run(crate::Args {
            config: path,
            cmd: Some(crate::Cmd::Authority)
        })
        .await
        .is_err());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
        let path = root.path().join("invalid.yaml");
        let mut value = configuration();
        value["state_dir"] = serde_json::json!(root.path().join("registry"));
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(crate::run(crate::Args {
            config: path,
            cmd: Some(crate::Cmd::Authority)
        })
        .await
        .is_err());
        assert!(!root.path().join("registry").exists());
    }
    fn private_file(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[test]
    fn administrator_references_require_exact_bounded_private_regular_files() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("admin");
        private_file(&file, b"administrator-reference");
        assert_eq!(administrator(&file).unwrap(), "administrator-reference");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(administrator(&file).is_err());
        for bytes in [
            b"".as_slice(),
            b"administrator-reference\n",
            &[255],
            &vec![b'x'; 4097],
        ] {
            private_file(&file, bytes);
            assert!(administrator(&file).is_err());
        }
        let link = dir.path().join("link");
        symlink(&file, &link).unwrap();
        assert!(administrator(&link).is_err());
    }
    #[tokio::test]
    async fn authority_provision_checks_independent_admin_references_and_mounts_no_admin_routes() {
        use ring::signature::{Ed25519KeyPair, KeyPair};
        use tower::ServiceExt;
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_file = dir.path().join("cert");
        let tls_key = dir.path().join("tls-key");
        private_file(&cert_file, cert.cert.pem().as_bytes());
        private_file(&tls_key, cert.key_pair.serialize_pem().as_bytes());
        let signing_file = dir.path().join("signing");
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        private_file(&signing_file, pkcs8.as_ref());
        let public = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .unwrap()
            .public_key()
            .as_ref()
            .to_vec();
        let keys = dir.path().join("keys");
        private_file(&keys,&serde_json::to_vec(&serde_json::json!([{"kid":"authority-key","role":"authority","issuer":"authority","authority":"region","public_key":public}])).unwrap());
        let credentials = dir.path().join("credentials");
        private_file(&credentials,&serde_json::to_vec(&serde_json::json!({"host_installer":"host-installer","host_execution":"host-execution","central_installer":"central-installer","gateway":"gateway","host_administrator":"host-admin","fleet_administrator":"fleet-admin"})).unwrap());
        let execution = Execution {
            channel: api::execution::provision::Config {
                listen: "127.0.0.1:7442".parse().unwrap(),
                cert: cert_file,
                key: tls_key,
                journal: dir.path().join("journal"),
                credentials,
                verification_keys: keys,
                central_issuer: "central".into(),
                authority_issuer: "authority".into(),
                audience: "runtime".into(),
            },
            host_id: "host".into(),
            host_url: "https://localhost:7441".into(),
            authority: "region".into(),
            key_id: "authority-key".into(),
            signing_key: signing_file,
        };
        let pin = api::tls::fingerprint(cert.cert.der());
        let host = |admin| TrustedHost {
            id: "host",
            tls_fingerprint: &pin,
            administrator: admin,
        };
        assert!(provision(&execution, host("wrong-admin"), "fleet-admin").is_err());
        assert!(provision(&execution, host("host-admin"), "wrong-admin").is_err());
        assert!(
            !execution.channel.journal.exists(),
            "independent comparisons precede opening/rotating a journal"
        );
        let (_, app) = provision(&execution, host("host-admin"), "fleet-admin").unwrap();
        for route in ["/v1/machines", "/v1/hosts", "/metrics", "/healthz"] {
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri(route)
                        .header("authorization", "Bearer fleet-admin")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                axum::http::StatusCode::NOT_FOUND,
                "{route}"
            );
        }
    }
}
