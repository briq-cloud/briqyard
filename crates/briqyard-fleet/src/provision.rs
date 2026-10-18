//! Provisioners add and release hosts through a cloud API. Adding a host costs money: every
//! provisioner runs in dry-run mode unless the configuration says otherwise, and the fleet
//! never orders more than `max_hosts`.
//!
//! A new server needs briqyardd installed before it can take machines; `hack/bootstrap-host.sh`
//! does that over SSH. The fleet records the server as `provisioning` and the host turns
//! `ready` on its first heartbeat.

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use serde::Deserialize;

/// A server a provisioner made.
#[derive(Clone, Debug)]
pub struct Server {
    pub provider_id: String,
    pub ip: Option<String>,
    pub note: String,
}

#[async_trait]
pub trait Provisioner: Send + Sync {
    fn name(&self) -> &str;
    /// Orders a server. In dry-run mode, says what it would order and makes nothing.
    async fn create(&self, hint: &str) -> Result<Server>;
    /// Releases a server (cancels or deletes it). In dry-run mode, says so and does nothing.
    async fn release(&self, provider_id: &str) -> Result<()>;
    /// The server's address once the provider has delivered it; `None` while it is being set up.
    async fn lookup(&self, _provider_id: &str) -> Result<Option<String>> {
        Ok(None)
    }
}

/// The provisioner the configuration names.
pub fn build(p: &crate::config::Provisioner) -> Box<dyn Provisioner> {
    match p.kind.as_str() {
        "hetzner-robot" => Box::new(HetznerRobot::new(
            p.hetzner.user.clone(),
            p.hetzner.password.clone(),
            p.hetzner.product.clone(),
            p.hetzner.location.clone(),
            p.hetzner.ssh_key_fingerprint.clone(),
            p.dry_run,
        )),
        "scaleway" => Box::new(Scaleway::new(
            p.scaleway.secret_key.clone(),
            p.scaleway.project_id.clone(),
            p.scaleway.zone.clone(),
            p.scaleway.offer_id.clone(),
            p.scaleway.os_id.clone(),
            p.dry_run,
        )),
        _ => Box::new(Static),
    }
}

/// Servers you manage yourself: the fleet adds and releases nothing.
pub struct Static;

#[async_trait]
impl Provisioner for Static {
    fn name(&self) -> &str {
        "static"
    }
    async fn create(&self, _hint: &str) -> Result<Server> {
        Err(anyhow!("the static provisioner cannot add hosts: add one to the configuration and run hack/bootstrap-host.sh"))
    }
    async fn release(&self, _provider_id: &str) -> Result<()> {
        Err(anyhow!("the static provisioner releases nothing"))
    }
}

/// Hetzner dedicated servers through the Robot API. Orders a product from the standard line
/// (`AX102-1` for example) in a data center. Servers are billed monthly; cancellation takes
/// effect at the end of the period.
pub struct HetznerRobot {
    pub user: String,
    pub password: String,
    pub product: String,
    pub location: String,
    pub ssh_key_fingerprint: String,
    pub dry_run: bool,
    http: reqwest::Client,
}

impl HetznerRobot {
    pub fn new(
        user: String,
        password: String,
        product: String,
        location: String,
        ssh_key_fingerprint: String,
        dry_run: bool,
    ) -> Self {
        Self {
            user,
            password,
            product,
            location,
            ssh_key_fingerprint,
            dry_run,
            http: reqwest::Client::new(),
        }
    }
}

#[derive(Deserialize)]
struct RobotTransaction {
    transaction: RobotTransactionBody,
}

#[derive(Deserialize)]
struct RobotTransactionBody {
    id: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    server_ip: Option<String>,
}

#[async_trait]
impl Provisioner for HetznerRobot {
    fn name(&self) -> &str {
        "hetzner-robot"
    }

    async fn create(&self, hint: &str) -> Result<Server> {
        let note = format!("order {} in {} ({hint})", self.product, self.location);
        if self.dry_run {
            return Ok(Server {
                provider_id: format!("dry-run-{}", chrono::Utc::now().timestamp()),
                ip: None,
                note: format!("DRY RUN: would {note}"),
            });
        }
        let form = [
            ("product_id", self.product.as_str()),
            ("location", self.location.as_str()),
            ("authorized_key[]", self.ssh_key_fingerprint.as_str()),
            ("dist", "Ubuntu 24.04 LTS base"),
            ("lang", "en"),
        ];
        let resp = self
            .http
            .post("https://robot-ws.your-server.de/order/server/transaction")
            .basic_auth(&self.user, Some(&self.password))
            .form(&form)
            .send()
            .await
            .context("hetzner robot order")?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(anyhow!("hetzner robot answered {status}: {text}"));
        }
        let t: RobotTransaction =
            serde_json::from_str(&text).context("hetzner robot order response")?;
        Ok(Server {
            provider_id: t.transaction.id,
            ip: t.transaction.server_ip,
            note: format!("ordered, status {}", t.transaction.status),
        })
    }

    async fn release(&self, provider_id: &str) -> Result<()> {
        if self.dry_run || provider_id.starts_with("dry-run-") {
            tracing::info!(provider_id, "DRY RUN: would cancel the Hetzner server");
            return Ok(());
        }
        let resp = self
            .http
            .post(format!(
                "https://robot-ws.your-server.de/server/{provider_id}/cancellation"
            ))
            .basic_auth(&self.user, Some(&self.password))
            .form(&[("cancellation_date", "now")])
            .send()
            .await
            .context("hetzner robot cancellation")?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "hetzner robot answered {}: {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            ));
        }
        Ok(())
    }

    async fn lookup(&self, provider_id: &str) -> Result<Option<String>> {
        if provider_id.starts_with("dry-run-") {
            return Ok(None);
        }
        let resp = self
            .http
            .get(format!(
                "https://robot-ws.your-server.de/order/server/transaction/{provider_id}"
            ))
            .basic_auth(&self.user, Some(&self.password))
            .send()
            .await
            .context("hetzner robot transaction")?;
        if !resp.status().is_success() {
            return Err(anyhow!("hetzner robot answered {}", resp.status()));
        }
        let t: RobotTransaction = resp.json().await.context("hetzner robot transaction")?;
        Ok(t.transaction.server_ip.filter(|ip| !ip.is_empty()))
    }
}

/// Scaleway Elastic Metal. Servers are billed by the hour or the month; a delete stops the
/// billing at once.
pub struct Scaleway {
    pub secret_key: String,
    pub project_id: String,
    pub zone: String,
    pub offer_id: String,
    pub os_id: String,
    pub dry_run: bool,
    http: reqwest::Client,
}

impl Scaleway {
    pub fn new(
        secret_key: String,
        project_id: String,
        zone: String,
        offer_id: String,
        os_id: String,
        dry_run: bool,
    ) -> Self {
        Self {
            secret_key,
            project_id,
            zone,
            offer_id,
            os_id,
            dry_run,
            http: reqwest::Client::new(),
        }
    }
}

#[derive(Deserialize)]
struct ScalewayServer {
    id: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    ips: Vec<ScalewayIp>,
}

#[derive(Deserialize)]
struct ScalewayIp {
    address: String,
}

#[async_trait]
impl Provisioner for Scaleway {
    fn name(&self) -> &str {
        "scaleway"
    }

    async fn create(&self, hint: &str) -> Result<Server> {
        let name = format!("byard-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
        if self.dry_run {
            return Ok(Server {
                provider_id: format!("dry-run-{name}"),
                ip: None,
                note: format!(
                    "DRY RUN: would create Elastic Metal offer {} in {} as {name} ({hint})",
                    self.offer_id, self.zone
                ),
            });
        }
        let body = serde_json::json!({
            "name": name,
            "offer_id": self.offer_id,
            "project_id": self.project_id,
            "install": {"os_id": self.os_id, "hostname": name},
            "tags": ["briqyard"],
        });
        let resp = self
            .http
            .post(format!(
                "https://api.scaleway.com/baremetal/v1/zones/{}/servers",
                self.zone
            ))
            .header("X-Auth-Token", &self.secret_key)
            .json(&body)
            .send()
            .await
            .context("scaleway create server")?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(anyhow!("scaleway answered {status}: {text}"));
        }
        let s: ScalewayServer = serde_json::from_str(&text).context("scaleway server response")?;
        Ok(Server {
            provider_id: s.id,
            ip: s.ips.first().map(|i| i.address.clone()),
            note: format!("created, status {}", s.status),
        })
    }

    async fn release(&self, provider_id: &str) -> Result<()> {
        if self.dry_run || provider_id.starts_with("dry-run-") {
            tracing::info!(provider_id, "DRY RUN: would delete the Scaleway server");
            return Ok(());
        }
        let resp = self
            .http
            .delete(format!(
                "https://api.scaleway.com/baremetal/v1/zones/{}/servers/{provider_id}",
                self.zone
            ))
            .header("X-Auth-Token", &self.secret_key)
            .send()
            .await
            .context("scaleway delete server")?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "scaleway answered {}: {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            ));
        }
        Ok(())
    }

    async fn lookup(&self, provider_id: &str) -> Result<Option<String>> {
        if provider_id.starts_with("dry-run-") {
            return Ok(None);
        }
        let resp = self
            .http
            .get(format!(
                "https://api.scaleway.com/baremetal/v1/zones/{}/servers/{provider_id}",
                self.zone
            ))
            .header("X-Auth-Token", &self.secret_key)
            .send()
            .await
            .context("scaleway get server")?;
        if !resp.status().is_success() {
            return Err(anyhow!("scaleway answered {}", resp.status()));
        }
        let srv: ScalewayServer = resp.json().await.context("scaleway server")?;
        if srv.status != "ready" {
            return Ok(None);
        }
        Ok(srv.ips.first().map(|i| i.address.clone()))
    }
}
