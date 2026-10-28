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
use std::sync::Mutex;

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
        "ovh" => Box::new(Ovh::new(&p.ovh, p.dry_run)),
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
    /// The Robot API; tests point it at a stub.
    pub base_url: String,
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
            base_url: "https://robot-ws.your-server.de".into(),
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
            .post(format!("{}/order/server/transaction", self.base_url))
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
                "{}/server/{provider_id}/cancellation",
                self.base_url
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
                "{}/order/server/transaction/{provider_id}",
                self.base_url
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
    /// The Scaleway API; tests point it at a stub.
    pub base_url: String,
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
            base_url: "https://api.scaleway.com".into(),
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
                "{}/baremetal/v1/zones/{}/servers",
                self.base_url, self.zone
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
                "{}/baremetal/v1/zones/{}/servers/{provider_id}",
                self.base_url, self.zone
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
                "{}/baremetal/v1/zones/{}/servers/{provider_id}",
                self.base_url, self.zone
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

/// OVHcloud dedicated servers: the Eco range (Kimsufi, So you Start, Rise) and the Bare Metal
/// range (Advance, Scale), ordered through the API's cart with the plan's cheapest option of
/// each mandatory family (memory, disks, bandwidth: the plan's base configuration).
/// A server is billed monthly; a termination takes effect at the end of the period, once the
/// operator confirms it from the email OVH sends.
///
/// The provider id is `order:<orderId>`: the server has no name until OVH delivers it.
/// `lookup` turns the order into the server (`server_of_order`), starts the Ubuntu install
/// (`/reinstall`, the OS on a small RAID 1, the rest of the disks left for the pool) with the
/// fleet's key and answers the address; `release` terminates the server.
///
/// Not run against the real API yet: the paths and bodies follow OVH's published API schemas
/// (`/1.0/order.json`, `/1.0/dedicated/server.json`, `/1.0/me.json`, read 2026-10-21).
pub struct Ovh {
    pub application_key: String,
    pub application_secret: String,
    pub consumer_key: String,
    pub plan_code: String,
    pub range: String,
    pub datacenter: String,
    pub ssh_key_name: String,
    pub subsidiary: String,
    pub dry_run: bool,
    /// The OVH API (the European endpoint); tests point it at a stub.
    pub base_url: String,
    http: reqwest::Client,
    /// OVH's clock minus ours, in seconds, from `/auth/time`: a signature whose timestamp is
    /// more than a few seconds off is refused. Fetched once.
    time_offset: Mutex<Option<i64>>,
}

/// The OS installed on a delivered server.
const OVH_TEMPLATE: &str = "ubuntu2604-server_64";

#[derive(Deserialize)]
struct OvhCart {
    #[serde(rename = "cartId")]
    cart_id: String,
}

/// OVH sends its ids as numbers; a string is kept as it is, without its quotes.
#[derive(Deserialize)]
#[serde(untagged)]
enum OvhId {
    Number(u64),
    Text(String),
}

impl OvhId {
    /// As OVH sent it, for a body that names it back (`itemId` is a long).
    fn json(&self) -> serde_json::Value {
        match self {
            OvhId::Number(n) => (*n).into(),
            OvhId::Text(s) => s.as_str().into(),
        }
    }
}

impl std::fmt::Display for OvhId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OvhId::Number(n) => write!(f, "{n}"),
            OvhId::Text(s) => f.write_str(s),
        }
    }
}

#[derive(Deserialize)]
struct OvhItem {
    #[serde(rename = "itemId")]
    item_id: OvhId,
}

#[derive(Deserialize)]
struct OvhOrder {
    #[serde(rename = "orderId")]
    order_id: OvhId,
}

#[derive(Deserialize)]
struct OvhOrderDetail {
    #[serde(default)]
    domain: String,
}

/// An option of a plan in the cart (`order.cart.GenericOptionDefinition`).
#[derive(Deserialize)]
struct OvhOption {
    family: String,
    mandatory: bool,
    #[serde(rename = "planCode")]
    plan_code: String,
    #[serde(default)]
    prices: Vec<OvhPrice>,
}

#[derive(Deserialize)]
struct OvhPrice {
    #[serde(default)]
    duration: String,
    #[serde(default, rename = "pricingMode")]
    pricing_mode: String,
    #[serde(default, rename = "priceInUcents")]
    price_in_ucents: u64,
}

#[derive(Deserialize)]
struct OvhSshKey {
    key: String,
}

/// The disks of a server the fleet installs (`dedicated.server.reinstall.Storage`): the OS on
/// a software RAID 1 of every disk, `/boot` 1 GiB and `/` 100 GiB, no swap (memory is never
/// overcommitted, ADR 0007); no partition fills the disks, so the rest of each one is left
/// for the bootstrap's pool, a mirror of the two (ADR 0028). Sizes in MiB.
fn ovh_storage() -> serde_json::Value {
    serde_json::json!([{
        "partitioning": {
            "layout": [
                {"mountPoint": "/boot", "fileSystem": "ext4", "raidLevel": 1, "size": 1024},
                {"mountPoint": "/", "fileSystem": "ext4", "raidLevel": 1, "size": 102400},
            ]
        }
    }])
}

/// The cheapest option of each mandatory family for a month, in the default pricing mode:
/// the plan's base configuration. Ordered by family, so the cart is filled the same way
/// every time.
fn mandatory_options(options: &[OvhOption]) -> Vec<&str> {
    let mut best: std::collections::BTreeMap<&str, (u64, &str)> = Default::default();
    for o in options.iter().filter(|o| o.mandatory) {
        let price = o
            .prices
            .iter()
            .filter(|p| p.duration == "P1M" && p.pricing_mode == "default")
            .map(|p| p.price_in_ucents)
            .min();
        if let Some(price) = price {
            let e = best.entry(&o.family).or_insert((price, &o.plan_code));
            if price < e.0 {
                *e = (price, &o.plan_code);
            }
        }
    }
    best.into_values().map(|(_, code)| code).collect()
}

#[derive(Deserialize)]
struct OvhServer {
    #[serde(default)]
    ip: String,
    #[serde(default)]
    datacenter: String,
    #[serde(default)]
    state: String,
}

#[derive(Deserialize)]
struct OvhError {
    message: String,
}

impl Ovh {
    pub fn new(cfg: &crate::config::Ovh, dry_run: bool) -> Self {
        Self {
            application_key: cfg.application_key.clone(),
            application_secret: cfg.application_secret.clone(),
            consumer_key: cfg.consumer_key.clone(),
            plan_code: cfg.plan_code.clone(),
            range: cfg.range.clone(),
            datacenter: cfg.datacenter.clone(),
            ssh_key_name: cfg.ssh_key_name.clone(),
            subsidiary: cfg.subsidiary.clone(),
            dry_run,
            base_url: "https://eu.api.ovh.com/1.0".into(),
            http: reqwest::Client::new(),
            time_offset: Mutex::new(None),
        }
    }

    /// The cart endpoint that takes the configured range's plan codes.
    fn cart_product(&self) -> Result<&'static str> {
        match self.range.as_str() {
            "eco" => Ok("eco"),
            "baremetal" => Ok("baremetalServers"),
            other => Err(anyhow!(
                "ovh.range is {other:?}: it is \"eco\" (Kimsufi, So you Start, Rise) or \"baremetal\" (Advance, Scale)"
            )),
        }
    }

    /// `$1$` + SHA-1 of the secret, the consumer key, the method, the full URL, the body and
    /// the timestamp, joined with `+`.
    fn sign(&self, method: &str, url: &str, body: &str, timestamp: i64) -> String {
        use sha1::{Digest, Sha1};
        let material = format!(
            "{}+{}+{method}+{url}+{body}+{timestamp}",
            self.application_secret, self.consumer_key
        );
        format!("$1${:x}", Sha1::digest(material.as_bytes()))
    }

    /// OVH's time, read once, kept as an offset from ours.
    async fn timestamp(&self) -> Result<i64> {
        let now = chrono::Utc::now().timestamp();
        if let Some(off) = *self.time_offset.lock().unwrap() {
            return Ok(now + off);
        }
        let text = self
            .http
            .get(format!("{}/auth/time", self.base_url))
            .send()
            .await
            .context("ovh auth time")?
            .error_for_status()
            .context("ovh auth time")?
            .text()
            .await?;
        let theirs: i64 = text
            .trim()
            .parse()
            .with_context(|| format!("ovh auth time answered {text:?}"))?;
        *self.time_offset.lock().unwrap() = Some(theirs - now);
        Ok(theirs)
    }

    /// One signed call. The body is sent exactly as signed. Answers the status and the text.
    async fn call_raw(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<(reqwest::StatusCode, String)> {
        let url = format!("{}{path}", self.base_url);
        let body = match body {
            Some(b) => serde_json::to_string(b)?,
            None => String::new(),
        };
        let ts = self.timestamp().await?;
        let signature = self.sign(method.as_str(), &url, &body, ts);
        let mut req = self
            .http
            .request(method, &url)
            .header("X-Ovh-Application", &self.application_key)
            .header("X-Ovh-Consumer", &self.consumer_key)
            .header("X-Ovh-Timestamp", ts.to_string())
            .header("X-Ovh-Signature", signature);
        if !body.is_empty() {
            req = req.header("Content-Type", "application/json").body(body);
        }
        let resp = req.send().await.with_context(|| format!("ovh {path}"))?;
        let status = resp.status();
        let text = resp.text().await?;
        Ok((status, text))
    }

    /// A signed call that must succeed: a refusal becomes an error with OVH's message.
    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<String> {
        let (status, text) = self.call_raw(method, path, body).await?;
        if !status.is_success() {
            let message = serde_json::from_str::<OvhError>(&text)
                .map(|e| e.message)
                .unwrap_or_else(|_| text.clone());
            return Err(anyhow!("ovh answered {status} on {path}: {message}"));
        }
        Ok(text)
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let text = self.call(reqwest::Method::GET, path, None).await?;
        serde_json::from_str(&text).with_context(|| format!("ovh {path} response"))
    }

    async fn post(&self, path: &str, body: &serde_json::Value) -> Result<String> {
        self.call(reqwest::Method::POST, path, Some(body)).await
    }

    /// The server an order delivered. Assumes that, once the order is `delivered`, one of its
    /// details carries the server's service name as `domain` (a placeholder like `*001`
    /// before), and checks that name against the account's server list before answering it:
    /// `lookup` reinstalls the server it answers, so a name it is not sure of is an error, never
    /// a guess. `None` while the order is not delivered; an error for an order that will not be.
    async fn server_of_order(&self, order_id: &str) -> Result<Option<String>> {
        let status: String = self.get(&format!("/me/order/{order_id}/status")).await?;
        match status.as_str() {
            "delivered" => {}
            "cancelled" | "cancelling" | "notPaid" | "documentsRequested" => {
                return Err(anyhow!(
                    "ovh order {order_id} is {status}: see it in the OVH manager"
                ))
            }
            _ => return Ok(None),
        }
        let ids: Vec<u64> = self.get(&format!("/me/order/{order_id}/details")).await?;
        let mut details: Vec<OvhOrderDetail> = Vec::with_capacity(ids.len());
        for id in ids {
            details.push(
                self.get(&format!("/me/order/{order_id}/details/{id}"))
                    .await?,
            );
        }
        let servers: Vec<String> = self.get("/dedicated/server").await?;
        let name = details
            .iter()
            .map(|d| d.domain.as_str())
            .find(|d| !d.is_empty() && servers.iter().any(|s| s == d));
        match name {
            Some(n) => Ok(Some(n.to_string())),
            None => Err(anyhow!(
                "ovh order {order_id} is delivered but none of its details names a server of the account ({}): add the host by hand",
                details
                    .iter()
                    .map(|d| d.domain.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
    }

    /// `order:<id>` resolves through the order; anything else is a server name already.
    async fn server_name(&self, provider_id: &str) -> Result<Option<String>> {
        match provider_id.strip_prefix("order:") {
            Some(id) => self.server_of_order(id).await,
            None => Ok(Some(provider_id.to_string())),
        }
    }

    /// Starts the Ubuntu install with the fleet's key unless one is running already (an
    /// install in progress answers `/install/status`; none answers 404), so a lookup tried
    /// again after a lost answer does not start a second one. `/reinstall` takes the key
    /// itself, read from the account's key of that name.
    async fn ensure_installing(&self, name: &str) -> Result<()> {
        let (status, text) = self
            .call_raw(
                reqwest::Method::GET,
                &format!("/dedicated/server/{name}/install/status"),
                None,
            )
            .await?;
        if status.is_success() {
            tracing::info!(server = name, "ovh install in progress");
            return Ok(());
        }
        if status != reqwest::StatusCode::NOT_FOUND {
            return Err(anyhow!(
                "ovh answered {status} on /dedicated/server/{name}/install/status: {text}"
            ));
        }
        let key: OvhSshKey = self
            .get(&format!("/me/sshKey/{}", self.ssh_key_name))
            .await?;
        let body = serde_json::json!({
            "operatingSystem": OVH_TEMPLATE,
            "customizations": {"sshKey": key.key},
            "storage": ovh_storage(),
        });
        self.post(&format!("/dedicated/server/{name}/reinstall"), &body)
            .await?;
        tracing::info!(
            server = name,
            template = OVH_TEMPLATE,
            key = self.ssh_key_name,
            "ovh install started"
        );
        Ok(())
    }
}

#[async_trait]
impl Provisioner for Ovh {
    fn name(&self) -> &str {
        "ovh"
    }

    async fn create(&self, hint: &str) -> Result<Server> {
        let product = self.cart_product()?;
        let note = format!(
            "order {} ({} range) in {} with the plan's default options, {OVH_TEMPLATE} with key {} ({hint})",
            self.plan_code, self.range, self.datacenter, self.ssh_key_name
        );
        if self.dry_run {
            return Ok(Server {
                provider_id: format!("dry-run-{}", chrono::Utc::now().timestamp()),
                ip: None,
                note: format!("DRY RUN: would {note}"),
            });
        }
        let cart: OvhCart = serde_json::from_str(
            &self
                .post(
                    "/order/cart",
                    &serde_json::json!({"ovhSubsidiary": self.subsidiary}),
                )
                .await?,
        )
        .context("ovh cart response")?;
        let cart_id = cart.cart_id;
        self.call(
            reqwest::Method::POST,
            &format!("/order/cart/{cart_id}/assign"),
            None,
        )
        .await?;
        let item: OvhItem = serde_json::from_str(
            &self
                .post(
                    &format!("/order/cart/{cart_id}/{product}"),
                    &serde_json::json!({
                        "planCode": self.plan_code,
                        "duration": "P1M",
                        "pricingMode": "default",
                        "quantity": 1,
                    }),
                )
                .await?,
        )
        .context("ovh cart item response")?;
        let item_id = item.item_id;
        let options: Vec<OvhOption> = self
            .get(&format!(
                "/order/cart/{cart_id}/{product}/options?planCode={}",
                self.plan_code
            ))
            .await?;
        for code in mandatory_options(&options) {
            self.post(
                &format!("/order/cart/{cart_id}/{product}/options"),
                &serde_json::json!({
                    "itemId": item_id.json(),
                    "planCode": code,
                    "duration": "P1M",
                    "pricingMode": "default",
                    "quantity": 1,
                }),
            )
            .await?;
        }
        let mut configs = vec![
            ("dedicated_datacenter", self.datacenter.as_str()),
            ("dedicated_os", "none_64.en"),
        ];
        if product == "eco" {
            configs.push(("region", "europe"));
        }
        for (label, value) in configs {
            self.post(
                &format!("/order/cart/{cart_id}/item/{item_id}/configuration"),
                &serde_json::json!({"label": label, "value": value}),
            )
            .await?;
        }
        let order: OvhOrder = serde_json::from_str(
            &self
                .post(
                    &format!("/order/cart/{cart_id}/checkout"),
                    &serde_json::json!({
                        "autoPayWithPreferredPaymentMethod": true,
                        "waiveRetractationPeriod": true,
                    }),
                )
                .await?,
        )
        .context("ovh checkout response")?;
        let order_id = order.order_id;
        Ok(Server {
            provider_id: format!("order:{order_id}"),
            ip: None,
            note: format!(
                "ordered {} in {}, order {order_id}",
                self.plan_code, self.datacenter
            ),
        })
    }

    async fn release(&self, provider_id: &str) -> Result<()> {
        if self.dry_run || provider_id.starts_with("dry-run-") {
            tracing::info!(provider_id, "DRY RUN: would terminate the OVH server");
            return Ok(());
        }
        let name = match self.server_name(provider_id).await? {
            Some(n) => n,
            None => {
                return Err(anyhow!(
                    "ovh {provider_id} is not delivered yet: retire it again once it is, or cancel the order in the OVH manager"
                ))
            }
        };
        self.call(
            reqwest::Method::POST,
            &format!("/dedicated/server/{name}/terminate"),
            None,
        )
        .await?;
        tracing::warn!(
            server = name,
            "ovh termination requested: confirm it from the email OVH sends; the server is billed to the end of its period"
        );
        Ok(())
    }

    async fn lookup(&self, provider_id: &str) -> Result<Option<String>> {
        if provider_id.starts_with("dry-run-") {
            return Ok(None);
        }
        let name = match self.server_name(provider_id).await? {
            Some(n) => n,
            None => return Ok(None),
        };
        let srv: OvhServer = self.get(&format!("/dedicated/server/{name}")).await?;
        if srv.ip.is_empty() {
            return Ok(None);
        }
        tracing::info!(
            server = name,
            ip = srv.ip,
            datacenter = srv.datacenter,
            state = srv.state,
            "ovh server delivered"
        );
        self.ensure_installing(&name).await?;
        Ok(Some(srv.ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Bytes;
    use axum::extract::{Request, State};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// One request as the stub saw it.
    #[derive(Clone, Debug)]
    struct Seen {
        method: String,
        path: String,
        query: String,
        authorization: String,
        auth_token: String,
        content_type: String,
        body: String,
        /// OVH's four headers: application, consumer, timestamp, signature.
        ovh: [String; 4],
    }

    /// A provider API on loopback: records every request and answers the next canned reply;
    /// an unexpected request answers 500 so the test fails on it.
    struct Canned {
        seen: Mutex<Vec<Seen>>,
        replies: Mutex<VecDeque<(StatusCode, String)>>,
    }

    impl Canned {
        async fn start(replies: Vec<(StatusCode, &str)>) -> (String, Arc<Canned>) {
            let stub = Arc::new(Canned {
                seen: Mutex::new(vec![]),
                replies: Mutex::new(
                    replies
                        .into_iter()
                        .map(|(s, b)| (s, b.to_string()))
                        .collect(),
                ),
            });
            let app = axum::Router::new()
                .fallback(answer)
                .with_state(stub.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            (url, stub)
        }

        fn seen(&self) -> Vec<Seen> {
            self.seen.lock().unwrap().clone()
        }
    }

    fn header(req: &Request, name: &str) -> String {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }

    async fn answer(State(stub): State<Arc<Canned>>, req: Request) -> axum::response::Response {
        let mut seen = Seen {
            method: req.method().to_string(),
            path: req.uri().path().to_string(),
            query: req.uri().query().unwrap_or("").to_string(),
            authorization: header(&req, "authorization"),
            auth_token: header(&req, "x-auth-token"),
            content_type: header(&req, "content-type"),
            body: String::new(),
            ovh: [
                header(&req, "x-ovh-application"),
                header(&req, "x-ovh-consumer"),
                header(&req, "x-ovh-timestamp"),
                header(&req, "x-ovh-signature"),
            ],
        };
        let body: Bytes = axum::body::to_bytes(req.into_body(), 1 << 20)
            .await
            .unwrap();
        seen.body = String::from_utf8_lossy(&body).into_owned();
        stub.seen.lock().unwrap().push(seen);
        // Popped into a local: a lock guard in the tail expression would make the future !Send.
        let next = stub.replies.lock().unwrap().pop_front();
        match next {
            Some((status, body)) => (status, body).into_response(),
            None => (StatusCode::INTERNAL_SERVER_ERROR, "no canned reply").into_response(),
        }
    }

    fn hetzner(dry_run: bool, base_url: &str) -> HetznerRobot {
        let mut h = HetznerRobot::new(
            "#ws+user".into(),
            "pa55".into(),
            "AX102".into(),
            "FSN1".into(),
            "ab:cd".into(),
            dry_run,
        );
        if !base_url.is_empty() {
            h.base_url = base_url.into();
        }
        h
    }

    fn scaleway(dry_run: bool, base_url: &str) -> Scaleway {
        let mut s = Scaleway::new(
            "scw-secret".into(),
            "proj-1".into(),
            "fr-par-2".into(),
            "offer-9".into(),
            "os-ubuntu".into(),
            dry_run,
        );
        if !base_url.is_empty() {
            s.base_url = base_url.into();
        }
        s
    }

    fn ovh(dry_run: bool, base_url: &str) -> Ovh {
        let cfg = crate::config::Ovh {
            application_key: "app-key".into(),
            application_secret: "app-secret".into(),
            consumer_key: "consumer-key".into(),
            plan_code: "25risem01-v2".into(),
            range: "eco".into(),
            datacenter: "gra".into(),
            ssh_key_name: "fleet".into(),
            subsidiary: "FR".into(),
        };
        let mut o = Ovh::new(&cfg, dry_run);
        if !base_url.is_empty() {
            o.base_url = base_url.into();
        }
        o
    }

    /// A Rise plan's options as the cart lists them: memory, disks and bandwidth mandatory (two
    /// of them priced), a vRack bandwidth optional, one mandatory option priced for a year only.
    const OVH_OPTIONS: &str = r#"[
        {"family":"memory","mandatory":true,"planCode":"ram-128g-ecc-4800-25rise","exclusive":true,
         "prices":[{"duration":"P1M","pricingMode":"default","priceInUcents":4000000000}]},
        {"family":"memory","mandatory":true,"planCode":"ram-64g-ecc-4800-25rise","exclusive":true,
         "prices":[{"duration":"P1M","pricingMode":"default","priceInUcents":0},
                   {"duration":"P12M","pricingMode":"upfront12","priceInUcents":0}]},
        {"family":"storage","mandatory":true,"planCode":"softraid-2x960nvme-25rise","exclusive":true,
         "prices":[{"duration":"P1M","pricingMode":"default","priceInUcents":0}]},
        {"family":"storage","mandatory":true,"planCode":"softraid-2x1920nvme-yearly","exclusive":true,
         "prices":[{"duration":"P12M","pricingMode":"upfront12","priceInUcents":0}]},
        {"family":"bandwidth","mandatory":true,"planCode":"bandwidth-2000-unguaranteed-25rise","exclusive":true,
         "prices":[{"duration":"P1M","pricingMode":"default","priceInUcents":900000000}]},
        {"family":"bandwidth","mandatory":true,"planCode":"bandwidth-1000-unguaranteed-25rise","exclusive":true,
         "prices":[{"duration":"P1M","pricingMode":"default","priceInUcents":0}]},
        {"family":"vrack","mandatory":false,"planCode":"vrack-bandwidth-1000-25rise","exclusive":true,
         "prices":[{"duration":"P1M","pricingMode":"default","priceInUcents":0}]}
    ]"#;

    /// The signature OVH expects, computed here from the recipe, not through the code under test.
    fn ovh_signature(method: &str, url: &str, body: &str, timestamp: &str) -> String {
        use sha1::{Digest, Sha1};
        let mut h = Sha1::new();
        h.update(format!(
            "app-secret+consumer-key+{method}+{url}+{body}+{timestamp}"
        ));
        let digest = h.finalize();
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        format!("$1${hex}")
    }

    /// Checks every OVH request the stub saw after `/auth/time`: the headers and the signature
    /// recomputed from what was sent.
    fn assert_signed(seen: &[Seen], base_url: &str) {
        for s in seen {
            if s.path == "/auth/time" {
                assert_eq!(s.ovh, ["", "", "", ""], "the time call is not signed");
                continue;
            }
            assert_eq!(s.ovh[0], "app-key", "{}", s.path);
            assert_eq!(s.ovh[1], "consumer-key", "{}", s.path);
            let url = match s.query.as_str() {
                "" => format!("{base_url}{}", s.path),
                q => format!("{base_url}{}?{q}", s.path),
            };
            assert_eq!(
                s.ovh[3],
                ovh_signature(&s.method, &url, &s.body, &s.ovh[2]),
                "signature of {} {}",
                s.method,
                s.path
            );
            if s.body.is_empty() {
                assert_eq!(s.content_type, "", "no body, no content type: {}", s.path);
            } else {
                assert_eq!(s.content_type, "application/json", "{}", s.path);
            }
        }
    }

    #[test]
    fn the_configuration_names_the_provisioner() {
        let mut p = crate::config::Provisioner::default();
        assert_eq!(build(&p).name(), "static");
        p.kind = "hetzner-robot".into();
        assert_eq!(build(&p).name(), "hetzner-robot");
        p.kind = "scaleway".into();
        assert_eq!(build(&p).name(), "scaleway");
        p.kind = "ovh".into();
        assert_eq!(build(&p).name(), "ovh");
        p.kind = "anything else".into();
        assert_eq!(build(&p).name(), "static", "an unknown kind adds nothing");
        // Nothing points at a stub by default.
        assert_eq!(
            hetzner(true, "").base_url,
            "https://robot-ws.your-server.de"
        );
        assert_eq!(scaleway(true, "").base_url, "https://api.scaleway.com");
        assert_eq!(ovh(true, "").base_url, "https://eu.api.ovh.com/1.0");
    }

    #[tokio::test]
    async fn the_static_provisioner_adds_and_releases_nothing() {
        let err = Static.create("x").await.unwrap_err().to_string();
        assert!(err.contains("cannot add hosts"), "{err}");
        assert!(Static.release("srv").await.is_err());
        assert_eq!(Static.lookup("srv").await.unwrap(), None);
    }

    #[tokio::test]
    async fn dry_runs_order_nothing() {
        // No stub behind the URL: a call that reaches the network fails to connect.
        let h = hetzner(true, "http://127.0.0.1:1");
        let s = h.create("more capacity").await.unwrap();
        assert!(s.provider_id.starts_with("dry-run-"), "{}", s.provider_id);
        assert_eq!(s.ip, None);
        assert_eq!(s.note, "DRY RUN: would order AX102 in FSN1 (more capacity)");
        h.release(&s.provider_id).await.unwrap();
        h.release("1234").await.unwrap();
        assert_eq!(h.lookup(&s.provider_id).await.unwrap(), None);

        let sc = scaleway(true, "http://127.0.0.1:1");
        let s = sc.create("no slot").await.unwrap();
        assert!(
            s.provider_id.starts_with("dry-run-byard-"),
            "{}",
            s.provider_id
        );
        assert_eq!(s.ip, None);
        assert!(
            s.note.starts_with(
                "DRY RUN: would create Elastic Metal offer offer-9 in fr-par-2 as byard-"
            ),
            "{}",
            s.note
        );
        assert!(s.note.ends_with("(no slot)"), "{}", s.note);
        sc.release(&s.provider_id).await.unwrap();
        sc.release("srv-1").await.unwrap();
        assert_eq!(sc.lookup(&s.provider_id).await.unwrap(), None);

        let o = ovh(true, "http://127.0.0.1:1");
        let s = o.create("more capacity").await.unwrap();
        assert!(s.provider_id.starts_with("dry-run-"), "{}", s.provider_id);
        assert_eq!(s.ip, None);
        assert_eq!(
            s.note,
            "DRY RUN: would order 25risem01-v2 (eco range) in gra with the plan's default options, ubuntu2604-server_64 with key fleet (more capacity)"
        );
        o.release(&s.provider_id).await.unwrap();
        o.release("order:123").await.unwrap();
        assert_eq!(o.lookup(&s.provider_id).await.unwrap(), None);
        // A range that is neither is refused before anything is ordered, dry run or not.
        let mut o = ovh(true, "http://127.0.0.1:1");
        o.range = "cloud".into();
        let err = o.create("x").await.unwrap_err().to_string();
        assert!(err.contains("ovh.range is \"cloud\""), "{err}");
    }

    #[tokio::test]
    async fn a_live_provisioner_never_touches_a_dry_run_id() {
        let (url, stub) = Canned::start(vec![]).await;
        let h = hetzner(false, &url);
        h.release("dry-run-1").await.unwrap();
        assert_eq!(h.lookup("dry-run-1").await.unwrap(), None);
        let s = scaleway(false, &url);
        s.release("dry-run-byard-1").await.unwrap();
        assert_eq!(s.lookup("dry-run-byard-1").await.unwrap(), None);
        let o = ovh(false, &url);
        o.release("dry-run-1").await.unwrap();
        assert_eq!(o.lookup("dry-run-1").await.unwrap(), None);
        assert!(stub.seen().is_empty(), "no request for a dry-run id");
    }

    #[tokio::test]
    async fn hetzner_orders_a_server() {
        let (url, stub) = Canned::start(vec![(
            StatusCode::CREATED,
            r#"{"transaction":{"id":"B20261019-1","status":"in process","server_ip":null}}"#,
        )])
        .await;
        let s = hetzner(false, &url).create("more capacity").await.unwrap();
        assert_eq!(s.provider_id, "B20261019-1");
        assert_eq!(s.ip, None);
        assert_eq!(s.note, "ordered, status in process");
        let seen = stub.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].method, "POST");
        assert_eq!(seen[0].path, "/order/server/transaction");
        assert!(
            seen[0].authorization.starts_with("Basic "),
            "{}",
            seen[0].authorization
        );
        assert_eq!(seen[0].content_type, "application/x-www-form-urlencoded");
        for part in [
            "product_id=AX102",
            "location=FSN1",
            "authorized_key%5B%5D=ab%3Acd",
            "dist=Ubuntu+24.04+LTS+base",
        ] {
            assert!(seen[0].body.contains(part), "{part} in {}", seen[0].body);
        }
    }

    #[tokio::test]
    async fn hetzner_refusals_carry_the_body() {
        let (url, _stub) = Canned::start(vec![
            (
                StatusCode::BAD_REQUEST,
                r#"{"error":{"status":400,"code":"INVALID_INPUT","message":"product not available"}}"#,
            ),
            (StatusCode::OK, "<html>not json</html>"),
            (StatusCode::CONFLICT, "already cancelled"),
            (StatusCode::NOT_FOUND, "{}"),
        ])
        .await;
        let h = hetzner(false, &url);
        let err = h.create("x").await.unwrap_err().to_string();
        assert!(err.starts_with("hetzner robot answered 400"), "{err}");
        assert!(err.contains("product not available"), "{err}");
        let err = format!("{:#}", h.create("x").await.unwrap_err());
        assert!(err.contains("hetzner robot order response"), "{err}");
        let err = h.release("1234").await.unwrap_err().to_string();
        assert!(
            err.contains("409") && err.contains("already cancelled"),
            "{err}"
        );
        let err = h.lookup("1234").await.unwrap_err().to_string();
        assert!(err.contains("404"), "{err}");
    }

    #[tokio::test]
    async fn hetzner_cancels_and_looks_up() {
        let (url, stub) = Canned::start(vec![
            (StatusCode::OK, "{}"),
            (
                StatusCode::OK,
                r#"{"transaction":{"id":"B1","status":"in process"}}"#,
            ),
            (
                StatusCode::OK,
                r#"{"transaction":{"id":"B1","status":"ready","server_ip":""}}"#,
            ),
            (
                StatusCode::OK,
                r#"{"transaction":{"id":"B1","status":"ready","server_ip":"1.2.3.4"}}"#,
            ),
        ])
        .await;
        let h = hetzner(false, &url);
        h.release("1234").await.unwrap();
        assert_eq!(h.lookup("B1").await.unwrap(), None, "no address yet");
        assert_eq!(
            h.lookup("B1").await.unwrap(),
            None,
            "an empty address is none"
        );
        assert_eq!(h.lookup("B1").await.unwrap().as_deref(), Some("1.2.3.4"));
        let seen = stub.seen();
        assert_eq!(seen[0].method, "POST");
        assert_eq!(seen[0].path, "/server/1234/cancellation");
        assert_eq!(seen[0].body, "cancellation_date=now");
        assert_eq!(seen[1].method, "GET");
        assert_eq!(seen[1].path, "/order/server/transaction/B1");
        assert!(seen.iter().all(|s| s.authorization.starts_with("Basic ")));
    }

    #[tokio::test]
    async fn scaleway_creates_a_server() {
        let (url, stub) = Canned::start(vec![(
            StatusCode::OK,
            r#"{"id":"srv-1","status":"delivering","ips":[]}"#,
        )])
        .await;
        let s = scaleway(false, &url).create("no slot").await.unwrap();
        assert_eq!(s.provider_id, "srv-1");
        assert_eq!(s.ip, None);
        assert_eq!(s.note, "created, status delivering");
        let seen = stub.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].method, "POST");
        assert_eq!(seen[0].path, "/baremetal/v1/zones/fr-par-2/servers");
        assert_eq!(seen[0].auth_token, "scw-secret");
        assert_eq!(seen[0].content_type, "application/json");
        let body: serde_json::Value = serde_json::from_str(&seen[0].body).unwrap();
        assert_eq!(body["offer_id"], "offer-9");
        assert_eq!(body["project_id"], "proj-1");
        assert_eq!(body["install"]["os_id"], "os-ubuntu");
        assert_eq!(body["install"]["hostname"], body["name"]);
        assert!(body["name"].as_str().unwrap().starts_with("byard-"));
        assert_eq!(body["tags"], serde_json::json!(["briqyard"]));
    }

    #[tokio::test]
    async fn scaleway_refusals_carry_the_body() {
        let (url, _stub) = Canned::start(vec![
            (
                StatusCode::FORBIDDEN,
                r#"{"message":"insufficient permissions","type":"permissions_denied"}"#,
            ),
            (StatusCode::NOT_FOUND, r#"{"message":"resource not found"}"#),
            (StatusCode::INTERNAL_SERVER_ERROR, "oops"),
        ])
        .await;
        let s = scaleway(false, &url);
        let err = s.create("x").await.unwrap_err().to_string();
        assert!(err.starts_with("scaleway answered 403"), "{err}");
        assert!(err.contains("insufficient permissions"), "{err}");
        let err = s.release("srv-1").await.unwrap_err().to_string();
        assert!(
            err.contains("404") && err.contains("resource not found"),
            "{err}"
        );
        let err = s.lookup("srv-1").await.unwrap_err().to_string();
        assert!(err.contains("500"), "{err}");
    }

    #[tokio::test]
    async fn scaleway_deletes_and_looks_up() {
        let (url, stub) = Canned::start(vec![
            (StatusCode::NO_CONTENT, ""),
            (
                StatusCode::OK,
                r#"{"id":"srv-1","status":"delivering","ips":[{"address":"5.6.7.8"}]}"#,
            ),
            (StatusCode::OK, r#"{"id":"srv-1","status":"ready","ips":[]}"#),
            (
                StatusCode::OK,
                r#"{"id":"srv-1","status":"ready","ips":[{"address":"5.6.7.8"},{"address":"5.6.7.9"}]}"#,
            ),
        ])
        .await;
        let s = scaleway(false, &url);
        s.release("srv-1").await.unwrap();
        assert_eq!(
            s.lookup("srv-1").await.unwrap(),
            None,
            "an address before the server is ready is not one to bootstrap"
        );
        assert_eq!(
            s.lookup("srv-1").await.unwrap(),
            None,
            "ready without an address"
        );
        assert_eq!(s.lookup("srv-1").await.unwrap().as_deref(), Some("5.6.7.8"));
        let seen = stub.seen();
        assert_eq!(seen[0].method, "DELETE");
        assert_eq!(seen[0].path, "/baremetal/v1/zones/fr-par-2/servers/srv-1");
        assert_eq!(seen[1].method, "GET");
        assert_eq!(seen[1].path, "/baremetal/v1/zones/fr-par-2/servers/srv-1");
        assert!(seen.iter().all(|s| s.auth_token == "scw-secret"));
    }

    #[test]
    fn ovh_signature_follows_the_recipe() {
        // A vector computed outside Rust (python's hashlib): sha1 of
        // "app-secret+consumer-key+GET+https://eu.api.ovh.com/1.0/me++1700000000".
        let o = ovh(false, "");
        let sig = o.sign("GET", "https://eu.api.ovh.com/1.0/me", "", 1700000000);
        assert_eq!(
            sig,
            ovh_signature("GET", "https://eu.api.ovh.com/1.0/me", "", "1700000000")
        );
        assert!(sig.starts_with("$1$") && sig.len() == 3 + 40, "{sig}");
        assert_eq!(sig, "$1$7ff65a14b20844556b102f5f06c9d6e206702042");
        // The body and the method are part of it.
        assert_ne!(
            sig,
            o.sign("POST", "https://eu.api.ovh.com/1.0/me", "", 1700000000)
        );
        assert_ne!(
            sig,
            o.sign("GET", "https://eu.api.ovh.com/1.0/me", "{}", 1700000000)
        );
    }

    #[tokio::test]
    async fn ovh_signs_every_request_with_the_servers_time() {
        // OVH's clock is an hour ahead of ours: the timestamp follows theirs.
        let theirs = chrono::Utc::now().timestamp() + 3600;
        let (url, stub) = Canned::start(vec![
            (StatusCode::OK, &theirs.to_string()),
            (StatusCode::OK, r#"{"nichandle":"xx-ovh"}"#),
            (StatusCode::OK, r#"{"nichandle":"xx-ovh"}"#),
        ])
        .await;
        let o = ovh(false, &url);
        o.call(reqwest::Method::GET, "/me", None).await.unwrap();
        o.call(
            reqwest::Method::POST,
            "/me",
            Some(&serde_json::json!({"a": 1})),
        )
        .await
        .unwrap();
        let seen = stub.seen();
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[0].path, "/auth/time", "the time is read first");
        assert_eq!(seen[1].path, "/me");
        assert_eq!(seen[2].path, "/me");
        assert_eq!(seen[2].body, r#"{"a":1}"#);
        for s in &seen[1..] {
            let ts: i64 = s.ovh[2].parse().unwrap();
            assert!((ts - theirs).abs() <= 2, "their time {theirs}, sent {ts}");
        }
        assert_signed(&seen, &url);
        // The time is read once.
        assert_eq!(seen.iter().filter(|s| s.path == "/auth/time").count(), 1);
        // A clock that does not answer is an error, not a request with our time.
        let o = ovh(false, "http://127.0.0.1:1");
        let err = format!(
            "{:#}",
            o.call(reqwest::Method::GET, "/me", None).await.unwrap_err()
        );
        assert!(err.contains("ovh auth time"), "{err}");
    }

    #[tokio::test]
    async fn ovh_orders_a_server_through_the_cart() {
        let (url, stub) = Canned::start(vec![
            (StatusCode::OK, "1700000000"),
            (
                StatusCode::OK,
                r#"{"cartId":"cart-1","expire":"2026-10-20T00:00:00+00:00"}"#,
            ),
            (StatusCode::OK, "null"),
            (
                StatusCode::OK,
                r#"{"itemId":456,"cartId":"cart-1","settings":{"planCode":"25risem01-v2"}}"#,
            ),
            (StatusCode::OK, OVH_OPTIONS),
            (StatusCode::OK, r#"{"itemId":457}"#),
            (StatusCode::OK, r#"{"itemId":458}"#),
            (StatusCode::OK, r#"{"itemId":459}"#),
            (StatusCode::OK, r#"{"label":"dedicated_datacenter","value":"gra"}"#),
            (StatusCode::OK, r#"{"label":"dedicated_os","value":"none_64.en"}"#),
            (StatusCode::OK, r#"{"label":"region","value":"europe"}"#),
            (
                StatusCode::OK,
                r#"{"orderId":123,"url":"https://www.ovh.com/cgi-bin/order/display-order.cgi?orderId=123","prices":{}}"#,
            ),
        ])
        .await;
        let s = ovh(false, &url).create("more capacity").await.unwrap();
        assert_eq!(s.provider_id, "order:123");
        assert_eq!(s.ip, None);
        assert_eq!(s.note, "ordered 25risem01-v2 in gra, order 123");
        let seen = stub.seen();
        let calls: Vec<(&str, &str)> = seen
            .iter()
            .map(|s| (s.method.as_str(), s.path.as_str()))
            .collect();
        assert_eq!(
            calls,
            [
                ("GET", "/auth/time"),
                ("POST", "/order/cart"),
                ("POST", "/order/cart/cart-1/assign"),
                ("POST", "/order/cart/cart-1/eco"),
                ("GET", "/order/cart/cart-1/eco/options"),
                ("POST", "/order/cart/cart-1/eco/options"),
                ("POST", "/order/cart/cart-1/eco/options"),
                ("POST", "/order/cart/cart-1/eco/options"),
                ("POST", "/order/cart/cart-1/item/456/configuration"),
                ("POST", "/order/cart/cart-1/item/456/configuration"),
                ("POST", "/order/cart/cart-1/item/456/configuration"),
                ("POST", "/order/cart/cart-1/checkout"),
            ]
        );
        let body = |i: usize| serde_json::from_str::<serde_json::Value>(&seen[i].body).unwrap();
        assert_eq!(body(1), serde_json::json!({"ovhSubsidiary": "FR"}));
        assert_eq!(seen[2].body, "", "assign has no body");
        assert_eq!(
            body(3),
            serde_json::json!({"planCode": "25risem01-v2", "duration": "P1M", "pricingMode": "default", "quantity": 1})
        );
        assert_eq!(seen[4].query, "planCode=25risem01-v2", "the plan's options");
        // The cheapest of each mandatory family for a month, by family: no option chosen for
        // the optional vRack, none priced only for a year.
        let option = |code: &str| serde_json::json!({"itemId": 456, "planCode": code, "duration": "P1M", "pricingMode": "default", "quantity": 1});
        assert_eq!(body(5), option("bandwidth-1000-unguaranteed-25rise"));
        assert_eq!(body(6), option("ram-64g-ecc-4800-25rise"));
        assert_eq!(body(7), option("softraid-2x960nvme-25rise"));
        assert_eq!(
            body(8),
            serde_json::json!({"label": "dedicated_datacenter", "value": "gra"})
        );
        assert_eq!(
            body(9),
            serde_json::json!({"label": "dedicated_os", "value": "none_64.en"})
        );
        assert_eq!(
            body(10),
            serde_json::json!({"label": "region", "value": "europe"})
        );
        assert_eq!(
            body(11),
            serde_json::json!({"autoPayWithPreferredPaymentMethod": true, "waiveRetractationPeriod": true})
        );
        assert_signed(&seen, &url);

        // The Bare Metal range goes through its own cart endpoint, without the region.
        let (url, stub) = Canned::start(vec![
            (StatusCode::OK, "1700000000"),
            (StatusCode::OK, r#"{"cartId":"cart-2"}"#),
            (StatusCode::OK, "null"),
            (StatusCode::OK, r#"{"itemId":"789"}"#),
            (StatusCode::OK, "[]"),
            (StatusCode::OK, "{}"),
            (StatusCode::OK, "{}"),
            (StatusCode::OK, r#"{"orderId":"124"}"#),
        ])
        .await;
        let mut o = ovh(false, &url);
        o.range = "baremetal".into();
        o.plan_code = "24ska01".into();
        o.subsidiary = "IE".into();
        let s = o.create("x").await.unwrap();
        assert_eq!(s.provider_id, "order:124", "an id sent as a string is kept");
        let seen = stub.seen();
        let paths: Vec<&str> = seen.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "/auth/time",
                "/order/cart",
                "/order/cart/cart-2/assign",
                "/order/cart/cart-2/baremetalServers",
                "/order/cart/cart-2/baremetalServers/options",
                "/order/cart/cart-2/item/789/configuration",
                "/order/cart/cart-2/item/789/configuration",
                "/order/cart/cart-2/checkout",
            ]
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&seen[1].body).unwrap(),
            serde_json::json!({"ovhSubsidiary": "IE"})
        );
        assert!(seen[3].body.contains("24ska01"), "{}", seen[3].body);
        assert!(
            seen.iter().all(|s| !s.body.contains("europe")),
            "no region for the Bare Metal range"
        );
        assert_signed(&seen, &url);
    }

    #[tokio::test]
    async fn ovh_refusals_carry_the_message() {
        let (url, stub) = Canned::start(vec![
            (StatusCode::OK, "1700000000"),
            (
                StatusCode::BAD_REQUEST,
                r#"{"class":"Client::BadRequest","message":"Invalid plan code: 25risem01-v2","errorCode":"INVALID_ARGUMENT"}"#,
            ),
            (StatusCode::OK, r#"{"cartId":"cart-1"}"#),
            (StatusCode::FORBIDDEN, "<html>forbidden</html>"),
            (StatusCode::OK, r#"{"cartId":"cart-1"}"#),
            (StatusCode::OK, "null"),
            (StatusCode::OK, "not an item"),
            (StatusCode::NOT_FOUND, r#"{"message":"This service does not exist"}"#),
            (StatusCode::INTERNAL_SERVER_ERROR, "oops"),
        ])
        .await;
        let o = ovh(false, &url);
        let err = o.create("x").await.unwrap_err().to_string();
        assert_eq!(
            err,
            "ovh answered 400 Bad Request on /order/cart: Invalid plan code: 25risem01-v2"
        );
        // A refusal that is not OVH's JSON keeps the text; the step that failed is named.
        let err = o.create("x").await.unwrap_err().to_string();
        assert!(
            err.contains("403")
                && err.contains("/order/cart/cart-1/assign")
                && err.contains("<html>forbidden</html>"),
            "{err}"
        );
        let err = format!("{:#}", o.create("x").await.unwrap_err());
        assert!(err.contains("ovh cart item response"), "{err}");
        let err = o
            .release("ns1.ip-1-2-3-4.eu")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("404") && err.contains("This service does not exist"),
            "{err}"
        );
        let err = o.lookup("order:123").await.unwrap_err().to_string();
        assert!(err.contains("500") && err.contains("oops"), "{err}");
        assert_eq!(stub.seen().len(), 9, "every refusal ends the flow there");
    }

    #[tokio::test]
    async fn ovh_looks_up_an_order() {
        let delivered = r#""delivered""#;
        let ids = "[1]";
        let detail = r#"{"orderDetailId":1,"description":"Rise-1","domain":"ns1.ip-1-2-3-4.eu","detailType":"DURATION","quantity":"1"}"#;
        let list = r#"["ns0.ip-9-9-9-9.eu","ns1.ip-1-2-3-4.eu"]"#;
        let server = r#"{"name":"ns1.ip-1-2-3-4.eu","ip":"1.2.3.4","datacenter":"gra2","state":"ok","os":"none_64"}"#;
        let (url, stub) = Canned::start(vec![
            (StatusCode::OK, "1700000000"),
            // Not delivered: nothing more is asked.
            (StatusCode::OK, r#""delivering""#),
            (StatusCode::OK, r#""checking""#),
            // Delivered, first look: the install starts, with the key of that name.
            (StatusCode::OK, delivered),
            (StatusCode::OK, ids),
            (StatusCode::OK, detail),
            (StatusCode::OK, list),
            (StatusCode::OK, server),
            (
                StatusCode::NOT_FOUND,
                r#"{"message":"No installation in progress"}"#,
            ),
            (
                StatusCode::OK,
                r#"{"keyName":"fleet","key":"ssh-ed25519 AAAAC3Nz fleet"}"#,
            ),
            (
                StatusCode::OK,
                r#"{"taskId":1,"status":"todo","function":"reinstallServer"}"#,
            ),
            // Delivered, looked up again (the first answer was lost): the install is running.
            (StatusCode::OK, delivered),
            (StatusCode::OK, ids),
            (StatusCode::OK, detail),
            (StatusCode::OK, list),
            (StatusCode::OK, server),
            (StatusCode::OK, r#"{"progress":[]}"#),
            // Delivered, no address yet.
            (StatusCode::OK, delivered),
            (StatusCode::OK, ids),
            (StatusCode::OK, detail),
            (StatusCode::OK, list),
            (StatusCode::OK, r#"{"name":"ns1.ip-1-2-3-4.eu","ip":""}"#),
            // Delivered, but no detail names a server of the account.
            (StatusCode::OK, delivered),
            (StatusCode::OK, "[1,2]"),
            (StatusCode::OK, r#"{"domain":"*001"}"#),
            (StatusCode::OK, r#"{"domain":"ns2.ip-5-5-5-5.eu"}"#),
            (StatusCode::OK, list),
            // An order that will not be delivered.
            (StatusCode::OK, r#""cancelled""#),
        ])
        .await;
        let o = ovh(false, &url);
        assert_eq!(o.lookup("order:123").await.unwrap(), None);
        assert_eq!(o.lookup("order:123").await.unwrap(), None);
        assert_eq!(
            o.lookup("order:123").await.unwrap().as_deref(),
            Some("1.2.3.4")
        );
        assert_eq!(
            o.lookup("order:123").await.unwrap().as_deref(),
            Some("1.2.3.4")
        );
        assert_eq!(o.lookup("order:123").await.unwrap(), None);
        let err = o.lookup("order:123").await.unwrap_err().to_string();
        assert!(
            err.contains("order 123 is delivered but none of its details names a server")
                && err.contains("*001, ns2.ip-5-5-5-5.eu"),
            "{err}"
        );
        let err = o.lookup("order:123").await.unwrap_err().to_string();
        assert!(err.contains("order 123 is cancelled"), "{err}");

        let seen = stub.seen();
        let calls: Vec<(&str, &str)> = seen
            .iter()
            .map(|s| (s.method.as_str(), s.path.as_str()))
            .collect();
        let status = ("GET", "/me/order/123/status");
        let details = ("GET", "/me/order/123/details");
        let detail = |id: &'static str| ("GET", id);
        let list = ("GET", "/dedicated/server");
        let server = ("GET", "/dedicated/server/ns1.ip-1-2-3-4.eu");
        let install_status = ("GET", "/dedicated/server/ns1.ip-1-2-3-4.eu/install/status");
        let key = ("GET", "/me/sshKey/fleet");
        let reinstall = ("POST", "/dedicated/server/ns1.ip-1-2-3-4.eu/reinstall");
        let one = detail("/me/order/123/details/1");
        assert_eq!(
            calls,
            [
                ("GET", "/auth/time"),
                status,
                status,
                status,
                details,
                one,
                list,
                server,
                install_status,
                key,
                reinstall,
                status,
                details,
                one,
                list,
                server,
                install_status,
                status,
                details,
                one,
                list,
                server,
                status,
                details,
                one,
                detail("/me/order/123/details/2"),
                list,
                status,
            ]
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&seen[10].body).unwrap(),
            serde_json::json!({
                "operatingSystem": "ubuntu2604-server_64",
                "customizations": {"sshKey": "ssh-ed25519 AAAAC3Nz fleet"},
                "storage": [{"partitioning": {"layout": [
                    {"mountPoint": "/boot", "fileSystem": "ext4", "raidLevel": 1, "size": 1024},
                    {"mountPoint": "/", "fileSystem": "ext4", "raidLevel": 1, "size": 102400},
                ]}}],
            }),
            "the OS on a RAID 1 of every disk, no partition filling them: the rest is the pool's"
        );
        assert_signed(&seen, &url);
    }

    #[tokio::test]
    async fn ovh_terminates() {
        let (url, stub) = Canned::start(vec![
            (StatusCode::OK, "1700000000"),
            // Not delivered: nothing to terminate yet.
            (StatusCode::OK, r#""delivering""#),
            // Delivered: the order's server.
            (StatusCode::OK, r#""delivered""#),
            (StatusCode::OK, "[7]"),
            (StatusCode::OK, r#"{"domain":"ns1.ip-1-2-3-4.eu"}"#),
            (StatusCode::OK, r#"["ns1.ip-1-2-3-4.eu"]"#),
            (StatusCode::OK, r#""ns1.ip-1-2-3-4.eu""#),
            // A server name as the id.
            (StatusCode::OK, r#""ns2.ip-5-5-5-5.eu""#),
        ])
        .await;
        let o = ovh(false, &url);
        let err = o.release("order:123").await.unwrap_err().to_string();
        assert!(err.contains("order:123 is not delivered yet"), "{err}");
        o.release("order:123").await.unwrap();
        o.release("ns2.ip-5-5-5-5.eu").await.unwrap();
        let seen = stub.seen();
        let calls: Vec<(&str, &str)> = seen
            .iter()
            .map(|s| (s.method.as_str(), s.path.as_str()))
            .collect();
        assert_eq!(
            calls,
            [
                ("GET", "/auth/time"),
                ("GET", "/me/order/123/status"),
                ("GET", "/me/order/123/status"),
                ("GET", "/me/order/123/details"),
                ("GET", "/me/order/123/details/7"),
                ("GET", "/dedicated/server"),
                ("POST", "/dedicated/server/ns1.ip-1-2-3-4.eu/terminate"),
                ("POST", "/dedicated/server/ns2.ip-5-5-5-5.eu/terminate"),
            ]
        );
        assert_eq!(seen[6].body, "", "terminate takes no body");
        assert_signed(&seen, &url);
    }
}
