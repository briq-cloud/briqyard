//! Finite native guest proof through the dedicated authenticated execution channels.
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use briqyard_api::execution::{admission::Projection, ALLOCATION_TYPE, GRANT_TYPE};
use reqwest::{Client, StatusCode};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use serde_json::{json, Value};
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn key(path: &Path) -> Result<Ed25519KeyPair> {
    Ed25519KeyPair::from_pkcs8(&std::fs::read(path)?)
        .map_err(|_| anyhow::anyhow!("invalid fixture key"))
}
fn sign(key: &Ed25519KeyPair, kind: &str, body: Value) -> String {
    let header = json!({"alg":"EdDSA","typ":kind,"kid":"native-central","v":1});
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(body.to_string())
    );
    format!(
        "{}.{}",
        input,
        URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).as_ref())
    )
}
fn initial_idle_admission(generation: u64) -> String {
    format!("idle-{generation}")
}

#[test]
fn native_scenarios_have_distinct_initial_protection_admissions() {
    // Manager idle-protection receipts survive authority registration replacement.
    let admissions: std::collections::HashSet<_> = (1..=4).map(initial_idle_admission).collect();
    assert_eq!(admissions.len(), 4);
}

fn provision(dir: &Path) -> Result<()> {
    let mut keys = vec![];
    for (name, role, issuer, authority) in [
        ("central", "central", "central", None),
        ("authority", "authority", "authority", Some("native")),
    ] {
        let bytes = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| anyhow::anyhow!("fixture key generation failed"))?;
        std::fs::write(dir.join(format!("{name}.pk8")), bytes.as_ref())?;
        let pair = key(&dir.join(format!("{name}.pk8")))?;
        keys.push(json!({"kid":format!("native-{name}"),"role":role,"issuer":issuer,"authority":authority,"public_key":pair.public_key().as_ref()}));
    }
    std::fs::write(dir.join("verification.json"), serde_json::to_vec(&keys)?)?;
    Ok(())
}
// Namespace teardown broadens membership and cannot bypass retained execution
// protection. Observe its qualified lower clock bound before the one-shot cleanup.
async fn drain_protection(dir: &Path) -> Result<()> {
    let path = dir.join("protection-deadline");
    let deadline: u64 = match std::fs::read_to_string(path) {
        Ok(value) => value.parse()?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    tokio::time::timeout(Duration::from_secs(140), async {
        loop {
            let lower = briqyard_api::execution::clock::ClockSample::read()
                .and_then(|sample| sample.lower_ms());
            // The mutation fence subtracts a further five-second uncertainty bound.
            if lower.is_some_and(|now| now.saturating_sub(5000) > deadline) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .context("native protection did not drain")?;
    Ok(())
}
struct Channel {
    client: Client,
    installer: String,
    gateway: String,
    host_installer: String,
    host_execution: String,
}
impl Channel {
    async fn request(&self, role: &str, action: &str, body: &Value) -> Result<reqwest::Response> {
        let token = match role {
            "installer" => &self.installer,
            "gateway" => &self.gateway,
            _ => &self.host_installer,
        };
        self.client
            .post(format!(
                "https://127.0.0.1:7442/internal/authority/v1/{action}"
            ))
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("authority transport failed for {action}; do not replay"))
    }
    async fn call(&self, role: &str, action: &str, body: Value) -> Result<Value> {
        let mut response = self.request(role, action, &body).await?;
        ensure!(
            response.status().is_success(),
            "authority {action} returned {}",
            response.status()
        );
        let limit = if action == "exec" {
            briqyard_api::execution::MAX_EXEC_RESPONSE_BYTES
        } else {
            briqyard_api::execution::MAX_BODY_BYTES
        };
        ensure!(
            response.content_length().is_none_or(|n| n <= limit as u64),
            "oversized authority reply"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .context("authority reply unavailable; do not replay")?
        {
            ensure!(
                chunk.len() <= limit - bytes.len(),
                "oversized authority reply"
            );
            bytes.extend_from_slice(&chunk);
        }
        Ok(serde_json::from_slice(&bytes)?)
    }
    async fn wait_ready(&self) -> Result<()> {
        // Read-only discovery may wait for the independently started listeners and clock.
        // Installation and execution below are still sent exactly once.
        tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                match self.request("installer", "identity", &json!({})).await {
                    Ok(response) if response.status().is_success() => return Ok(()),
                    Ok(response)
                        if !matches!(
                            response.status(),
                            StatusCode::SERVICE_UNAVAILABLE | StatusCode::BAD_GATEWAY
                        ) =>
                    {
                        anyhow::bail!("authority readiness refused")
                    }
                    _ => tokio::time::sleep(Duration::from_millis(250)).await,
                }
            }
        })
        .await
        .context("authority readiness deadline exceeded")?
    }

    async fn install(&self, action: &str, body: Value) -> Result<Value> {
        let value = self.call("installer", action, body).await?;
        ensure!(
            value["state"] == "ready",
            "{action} did not acknowledge readiness"
        );
        Ok(value["evidence"].clone())
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    briqyard_testing::exit_with_parent();
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() >= 3,
        "usage: scoped-execution-native provision DIR | run DIR NAMESPACE MACHINE SIBLING"
    );
    let dir = Path::new(&args[2]);
    if args[1] == "drain" {
        return drain_protection(dir).await;
    }
    if args[1] == "provision" {
        return provision(dir);
    }
    ensure!(
        args.len() == 6
            && matches!(
                args[1].as_str(),
                "run" | "renewable" | "renewable-refused" | "renewable-revoked"
            ),
        "invalid harness arguments"
    );
    let renewable = args[1] != "run";
    let generation = match args[1].as_str() {
        "renewable" => 2,
        "renewable-refused" => 3,
        "renewable-revoked" => 4,
        _ => 1,
    };
    let credentials: Value = serde_json::from_slice(&std::fs::read(dir.join("credentials.json"))?)?;
    let pin = briqyard_api::tls::pem_fingerprint(&std::fs::read(dir.join("cert.pem"))?)?;
    let client = Client::builder()
        .use_preconfigured_tls(briqyard_api::tls::pinned_client(&pin))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(Duration::from_secs(85))
        .build()?;
    let channel = Channel {
        client,
        installer: credentials["central_installer"]
            .as_str()
            .context("installer credential")?
            .into(),
        gateway: credentials["gateway"]
            .as_str()
            .context("gateway credential")?
            .into(),
        host_installer: credentials["host_installer"]
            .as_str()
            .context("host credential")?
            .into(),
        host_execution: credentials["host_execution"]
            .as_str()
            .context("host execution credential")?
            .into(),
    };
    channel.wait_ready().await?;
    // Both TLS and role negatives are read-only and precede installation.
    let wrong_pin = Client::builder()
        .use_preconfigured_tls(briqyard_api::tls::pinned_client(&"00".repeat(32)))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(Duration::from_secs(5))
        .build()?;
    ensure!(
        wrong_pin
            .post("https://127.0.0.1:7442/internal/authority/v1/identity")
            .json(&json!({}))
            .send()
            .await
            .is_err(),
        "wrong TLS pin accepted"
    );
    for role in ["gateway", "host"] {
        ensure!(
            channel
                .request(role, "identity", &json!({}))
                .await?
                .status()
                == StatusCode::UNAUTHORIZED,
            "wrong authority role accepted"
        );
    }
    let host_wrong_role = channel
        .client
        .get("https://127.0.0.1:7441/internal/execution/v1/instance")
        .bearer_auth(&channel.gateway)
        .send()
        .await?;
    ensure!(
        host_wrong_role.status() == StatusCode::UNAUTHORIZED,
        "gateway credential accepted by host"
    );
    let identity = channel.call("installer", "identity", json!({})).await?;
    let authority = key(&dir.join("authority.pk8"))?;
    channel.install("register", json!({"id":"registration","record":{
        "authority":"native","epoch":identity["authority_epoch"],"key_id":"native-authority",
        "public_key":authority.public_key().as_ref(),"host_instance":identity["host_instance"],"generation":generation
    }})).await?;
    let namespace = &args[3];
    let discovery = channel.install("discover", json!({"id":"discovery","registration":"registration","control":{
        "host_instance":identity["host_instance"],"installation":"ownership-installation","generation":generation,
        "team":namespace,"primary_id":"native-primary","metadata_revision":"native-metadata",
        "seeds":[{"id":"native-primary","machine":args[4],"namespace":namespace,"team":namespace,"expected_version":null},
                 {"id":"native-sibling","machine":args[5],"namespace":namespace,"team":namespace,"expected_version":null}]
    }})).await?;
    ensure!(
        discovery["resource_set"]["resources"]
            .as_array()
            .context("discovery resources")?
            .len()
            == 3,
        "discovery did not include both public guests and native gateway"
    );
    channel
        .install(
            "ownership",
            json!({"id":"ownership","discovery":"discovery"}),
        )
        .await?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let clocks: briqyard_api::execution::channel::AuthorizationClock = serde_json::from_value(
        channel
            .call("installer", "authorization_clock", json!({}))
            .await?,
    )?;
    let issued = now
        .saturating_sub(5)
        .min(
            clocks
                .authority
                .now
                .saturating_sub(clocks.authority.uncertainty),
        )
        .min(clocks.host.now.saturating_sub(clocks.host.uncertainty));
    let expiry = if renewable { issued + 60 } else { now + 40 };
    let allocation_expiry = if renewable { now + 18 } else { expiry };
    let idle_expiry = if renewable { now + 120 } else { expiry + 15 };
    let idle_admission = initial_idle_admission(generation);
    std::fs::write(
        dir.join("protection-deadline"),
        (idle_expiry * 1000).to_string(),
    )?;
    channel.install("protect", json!({"id":"protection","ownership":"ownership","committed":{"admission":idle_admission,"expires_at_ms":idle_expiry*1000}})).await?;
    let central = key(&dir.join("central.pk8"))?;
    let mut grant_body = json!({"v":1,"iss":"central","aud":"runtime","iat":issued,"nbf":issued,"exp":expiry,
        "id":"delegation","principal":"key:native","source":{"kind":"api_key","id":"native","expires_at":expiry+60},
        "team":namespace,"subject":"native-primary","target":discovery["primary"],"resource_set":discovery["resource_set"],
        "idle":{"admission":idle_admission,"expires_at":idle_expiry},"metadata_revision":"native-metadata",
        "operations":["exec"],"limits":{"max_duration_seconds":20,"max_input_bytes":1024,"max_output_bytes":briqyard_api::execution::MAX_CAPTURE_BYTES,"output_mode":"capture_per_stream_v1"}});
    if renewable {
        grant_body["limits"]["max_duration_seconds"] = json!(60);
        grant_body["limits"]["execution_mode"] = json!("renewable_exec_v1");
    }
    let allocations: Vec<_> = ["requests", "exec_calls"].into_iter().map(|bucket| sign(&central, ALLOCATION_TYPE,
        json!({"v":1,"iss":"central","aud":"runtime","iat":issued,"nbf":issued,"exp":allocation_expiry,
            "id":bucket,"epoch":"native-allocation","authority":"native","authority_epoch":identity["authority_epoch"],
            "principal":"key:native","bucket":bucket,"window_start":now-20,"window_end":if renewable {now+20} else {expiry+30},"units":if renewable {1} else {10}}))).collect();
    let projection = Projection::new(b"native guest proof".to_vec())?;
    let grant = sign(&central, GRANT_TYPE, grant_body.clone());
    let delegation = |id: &str, signed: &str| {
        json!({"id":id,"registration":"registration","control":{
        "id":"delegation","version":generation,"principal":"key:native","ownership":"ownership","protection":"protection",
        "source":{"kind":"api_key","id":"native","expires_at":expiry+60},"policy_revision":"native-policy","projection":projection},
        "signed":{"grant":signed,"allocations":allocations}})
    };
    let native_gateway = discovery["resource_set"]["resources"]
        .as_array()
        .context("closure resources")?
        .iter()
        .find(|target| target["machine"] != args[4] && target["machine"] != args[5])
        .context("native gateway missing from closure")?["machine"]
        .clone();
    let mut omitted = grant_body;
    omitted["resource_set"]["resources"]
        .as_array_mut()
        .context("grant resources")?
        .retain(|target| target["machine"] != native_gateway);
    let refused = channel
        .request(
            "installer",
            "delegation",
            &delegation("omitted-closure", &sign(&central, GRANT_TYPE, omitted)),
        )
        .await?;
    ensure!(
        refused.status() == StatusCode::CONFLICT,
        "omitted native closure accepted"
    );
    channel
        .install("delegation", delegation("signed", &grant))
        .await?;
    let presented = channel
        .call(
            "gateway",
            "projection",
            json!({"delegation_intent":"signed","grant":grant}),
        )
        .await?;
    ensure!(
        presented["projection"] == serde_json::to_value(&projection)?,
        "projection binding differs"
    );
    let operation = |id: &str, command: &str| {
        json!({"id":id,"delegation_intent":"signed","grant":grant,"projection_digest":projection.digest(),
        "request":{"cmd":["sh","-c",command],"timeout_ms":10000,"wake":false}})
    };
    if renewable {
        let request = json!({"id":args[1],"delegation_intent":"signed","grant":grant,"projection_digest":projection.digest(),
            "request":{"cmd":["sh","-c","echo once >> /tmp/scoped-renewable-counter; sleep 90"],"timeout_ms":60000,"wake":false}});
        let began = std::time::Instant::now();
        if args[1] != "renewable" {
            let response = channel.request("gateway", "exec", &request).await?;
            let observed = briqyard_api::execution::clock::ClockSample::read()
                .and_then(|sample| sample.interval())
                .context("response clock unqualified")?;
            std::fs::write(
                dir.join(format!("response-observation-{}", args[1])),
                serde_json::to_vec(&briqyard_api::execution::channel::ClockObservation {
                    now: observed.now,
                    uncertainty: observed.uncertainty,
                })?,
            )?;
            ensure!(
                !response.status().is_success(),
                "source refusal completed a quiet command"
            );
            ensure!(
                began.elapsed() < Duration::from_secs(25),
                "quiet I/O did not wake at initial lease expiry"
            );
        } else {
            let result = channel.call("gateway", "exec", request.clone()).await?;
            ensure!(
                result["state"] == "completed" && result["result"]["timed_out"] == true,
                "renewable full guest timeout did not complete"
            );
            ensure!(
                began.elapsed() >= Duration::from_secs(59)
                    && began.elapsed() < Duration::from_secs(80),
                "guest/envelope time bounds differ"
            );
            ensure!(
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() > now + 20,
                "execution did not cross original quota window"
            );
        }
        let duplicate = channel.call("gateway", "exec", request).await?;
        ensure!(
            duplicate["state"] == "existing",
            "duplicate command was dispatched again"
        );
        let status = channel
            .call("gateway", "observe", json!({"id":args[1]}))
            .await?;
        ensure!(
            status["state"] == "known",
            "operation evidence lost beyond permit expiry"
        );
        println!("scoped renewable native: {} quiet guest, bounded runtime and status-only duplicate passed", args[1]);
        return Ok(());
    }
    let first = operation(
        "counter",
        "echo executed >> /tmp/scoped-native-counter; wc -l < /tmp/scoped-native-counter",
    );
    let result = channel.call("gateway", "exec", first.clone()).await?;
    ensure!(
        result["state"] == "completed"
            && result["result"]["exit_code"] == 0
            && result["result"]["stdout"]
                .as_str()
                .is_some_and(|s| s.trim() == "1"),
        "real guest counter did not complete once"
    );
    let duplicate = channel.call("gateway", "exec", first).await?;
    ensure!(
        duplicate["state"] == "existing" && duplicate["status"]["phase"] == "finished",
        "duplicate was dispatched or lost"
    );
    let status = channel
        .call("gateway", "observe", json!({"id":"counter"}))
        .await?;
    ensure!(
        status["state"] == "known" && status["evidence"]["phase"] == "finished",
        "finished authority admission not observed"
    );
    let host_status = channel
        .client
        .post("https://127.0.0.1:7441/internal/execution/v1/status")
        .bearer_auth(&channel.host_execution)
        .json(&json!({"admission":"counter"}))
        .send()
        .await?;
    ensure!(host_status.status().is_success(), "host status refused");
    let host_status: briqyard_api::execution::channel::AdmissionStatus = host_status.json().await?;
    ensure!(
        host_status.prepared
            && host_status.dispatched
            && host_status.journal == Some(briqyard_api::execution::admission::Status::Finished),
        "host journal did not confirm finished admission"
    );
    let read = channel
        .call(
            "gateway",
            "exec",
            operation("read-counter", "wc -l < /tmp/scoped-native-counter"),
        )
        .await?;
    ensure!(
        read["state"] == "completed"
            && read["result"]["exit_code"] == 0
            && read["result"]["stdout"]
                .as_str()
                .is_some_and(|s| s.trim() == "1"),
        "duplicate replayed guest side effect"
    );
    let capture = channel
        .call(
            "gateway",
            "exec",
            operation(
                "capture-output",
                "head -c 4194432 /dev/zero; head -c 4194432 /dev/zero >&2; exit 7",
            ),
        )
        .await?;
    ensure!(
        capture["state"] == "completed" && capture["result"]["exit_code"] == 7,
        "capture saturation lost terminal completion"
    );
    for stream in ["stdout", "stderr"] {
        let text = capture["result"][stream]
            .as_str()
            .context("captured stream missing")?;
        ensure!(
            text.len() == briqyard_api::execution::MAX_CAPTURE_BYTES as usize
                && text.bytes().all(|b| b == 0),
            "captured raw stream prefix differs"
        );
    }
    println!("scoped native: TLS pin, role separation, full closure, omitted closure refusal, projection, guest exec, duplicate, host status and saturated capture passed");
    Ok(())
}
