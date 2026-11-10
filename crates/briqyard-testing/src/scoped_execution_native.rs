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
fn initial_delegation_id(generation: u64) -> String {
    format!("delegation-{generation}")
}

#[test]
fn native_scenario_delegations_survive_retained_registration_history() {
    use briqyard_api::execution::{
        admission::{Error, HostDelegation, HostOwnership, HostRegistration, Journal, Role},
        Clock, Grant, PublicResource,
    };
    let fixture: Value = serde_json::from_str(include_str!(
        "../../briqyard-api/tests/fixtures/execution-v1.json"
    ))
    .unwrap();
    let grant: Grant = serde_json::from_value(fixture["grant"].clone()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut journal = Journal::open(
        &dir.path().join("host"),
        Role::Host(grant.target.host.clone()),
    )
    .unwrap();
    let clock = Clock {
        now: 1010,
        uncertainty: 1,
    };
    let mut previous: Option<HostDelegation> = None;
    for generation in 1..=4 {
        journal
            .register_host(
                HostRegistration {
                    authority: "native".into(),
                    epoch: format!("native-epoch-{generation}"),
                    key_id: "native-authority".into(),
                    public_key: [7; 32],
                    host_instance: journal.instance().into(),
                    generation,
                },
                clock,
            )
            .unwrap();
        let owner = HostOwnership {
            installation: "ownership-installation".into(),
            generation,
            team: grant.team.clone(),
            subject: grant.subject.clone(),
            metadata_revision: grant.metadata_revision.clone(),
            primary: grant.target.clone(),
            public_seeds: vec![grant.target.clone()],
            public_resources: vec![PublicResource {
                id: grant.subject.clone(),
                target: grant.target.clone(),
            }],
            resource_set: grant.resource_set.clone(),
            host_instance: journal.instance().into(),
        };
        journal.install_ownership(owner.clone(), clock).unwrap();
        let record = HostDelegation {
            id: initial_delegation_id(generation),
            version: generation,
            ownership: owner.installation,
            ownership_generation: generation,
            grant_digest: format!("grant-{generation}"),
            allocation_digests: vec![],
            principal: "key:native".into(),
            expires_at: 1050,
        };
        if let Some(prior) = &previous {
            // Registration replaces current ownership, not retained delegation identity.
            assert!(matches!(
                journal.install_delegation(
                    HostDelegation {
                        id: prior.id.clone(),
                        ..record.clone()
                    },
                    clock
                ),
                Err(Error::Binding)
            ));
        }
        journal.install_delegation(record.clone(), clock).unwrap();
        previous = Some(record);
    }
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

fn initial_idle_expiry_from_qualified_issue(
    qualified_issued_at: u64,
    grant_expiry: u64,
    renewable: bool,
) -> u64 {
    let protection_limit = qualified_issued_at + 60;
    if renewable {
        protection_limit
    } else {
        (grant_expiry + 15).min(protection_limit)
    }
}

#[test]
fn initial_protection_covers_grants_within_the_qualified_lower_budget() {
    use briqyard_api::execution::clock::ClockSample;
    for fraction_ms in [100, 900] {
        for uncertainty_ms in [2_000, 4_000] {
            let sample = ClockSample {
                wall: Duration::from_millis(1_000_000 + fraction_ms),
                monotonic: std::time::Instant::now(),
                uncertainty: Duration::from_millis(uncertainty_ms),
            };
            let clock = sample.interval().unwrap();
            let issued = (clock.now - 5).min(clock.now - clock.uncertainty);
            for (grant_expiry, renewable) in [(issued + 60, true), (issued + 50, false)] {
                let expiry =
                    initial_idle_expiry_from_qualified_issue(issued, grant_expiry, renewable);
                assert!(expiry >= grant_expiry);
                assert!(expiry * 1000 > sample.upper_ms().unwrap());
                assert!(expiry <= clock.now + 60);
                assert!(expiry * 1000 <= sample.lower_ms().unwrap() + 60_000);
            }
            // Wall time plus sixty seconds exceeds the fence's lower-clock budget.
            assert!((clock.now + 60) * 1000 > sample.lower_ms().unwrap() + 60_000);
            assert_eq!(
                initial_idle_expiry_from_qualified_issue(issued, issued + 30, false),
                issued + 45
            );
        }
    }
}

fn native_grant_body(
    issued: u64,
    expiry: u64,
    idle_expiry: u64,
    identities: (&str, &str),
    namespace: &str,
    discovery: &Value,
    renewable: bool,
) -> Value {
    let (delegation_id, idle_admission) = identities;
    let mut body = json!({"v":1,"iss":"central","aud":"runtime","iat":issued,"nbf":issued,"exp":expiry,
        "id":delegation_id,"principal":"key:native","source":{"kind":"api_key","id":"native","expires_at":expiry+60},
        "team":namespace,"subject":"native-primary","target":discovery["primary"],"resource_set":discovery["resource_set"],
        "idle":{"admission":idle_admission,"expires_at":idle_expiry},"metadata_revision":"native-metadata",
        "operations":["exec"],"limits":{"max_duration_seconds":20,"max_input_bytes":1024,"max_output_bytes":briqyard_api::execution::MAX_CAPTURE_BYTES,"output_mode":"capture_per_stream_v1"}});
    if renewable {
        body["limits"]["max_duration_seconds"] = json!(60);
        body["limits"]["execution_mode"] = json!("renewable_exec_v1");
    }
    body
}

fn native_allocations(
    central: &Ed25519KeyPair,
    issued: u64,
    allocation_expiry: u64,
    now: u64,
    expiry: u64,
    identity: &Value,
    renewable: bool,
) -> Vec<String> {
    ["requests", "exec_calls"].into_iter().map(|bucket| sign(central, ALLOCATION_TYPE,
        json!({"v":1,"iss":"central","aud":"runtime","iat":issued,"nbf":issued,"exp":allocation_expiry,
            "id":bucket,"epoch":"native-allocation","authority":"native","authority_epoch":identity["authority_epoch"],
            "principal":"key:native","bucket":bucket,"window_start":now-20,"window_end":if renewable {now+20} else {expiry+30},"units":if renewable {1} else {10}}))).collect()
}

#[test]
fn native_signed_credentials_match_the_complete_discovered_closure() {
    use briqyard_api::execution::{
        verify_delegation, Clock, DelegationContext, DiscoveryReceipt, KeyRole, Trust,
        VerificationKey, VerifyError,
    };
    let central = Ed25519KeyPair::from_seed_unchecked(&[1; 32]).unwrap();
    let keys = [VerificationKey {
        kid: "native-central".into(),
        role: KeyRole::Central,
        issuer: "central".into(),
        authority: None,
        public_key: central.public_key().as_ref().try_into().unwrap(),
    }];
    let trust = Trust {
        keys: &keys,
        central_issuer: "central",
        authority_issuer: "authority",
        audience: "runtime",
    };
    let target = |machine: &str| {
        json!({
            "host":"host-native", "machine":machine, "namespace":"scoped-native-1000",
            "run":briqyard_api::execution::process_run_id("boot-native", 123, 456, "host-instance"),
            "placement":"version-1"
        })
    };
    let discovery = json!({
        "host_instance":"host-instance", "primary":target("primary"),
        "public_seeds":[target("primary"), target("sibling")],
        "public_resources":[{"id":"native-primary","target":target("primary")},
                            {"id":"native-sibling","target":target("sibling")}],
        "resource_set":{"revision":"a".repeat(64),
                        "resources":[target("gateway"), target("primary"), target("sibling")]}
    });
    let receipt: DiscoveryReceipt = serde_json::from_value(discovery.clone()).unwrap();
    let identity = json!({"authority_epoch":"authority-instance"});
    let context = DelegationContext {
        principal: "key:native",
        team: "scoped-native-1000",
        subject: "native-primary",
        target: &receipt.primary,
        resource_set: &receipt.resource_set,
        metadata_revision: "native-metadata",
        authority: "native",
        authority_epoch: "authority-instance",
    };
    for renewable in [false, true] {
        let now = 1000;
        let issued = 995;
        let expiry = if renewable { issued + 60 } else { now + 40 };
        let allocation_expiry = if renewable { now + 18 } else { expiry };
        let idle_expiry = initial_idle_expiry_from_qualified_issue(issued, expiry, renewable);
        let body = native_grant_body(
            issued,
            expiry,
            idle_expiry,
            (&initial_delegation_id(1), "idle-1"),
            context.team,
            &discovery,
            renewable,
        );
        let allocations = native_allocations(
            &central,
            issued,
            allocation_expiry,
            now,
            expiry,
            &identity,
            renewable,
        );
        let tokens: Vec<_> = allocations.iter().map(String::as_str).collect();
        let grant = sign(&central, GRANT_TYPE, body.clone());
        for uncertainty in [0, 2, 5] {
            let clock = Clock { now, uncertainty };
            let checked = verify_delegation(&grant, &tokens, &trust, clock, &context).unwrap();
            assert_eq!(checked.grant().resource_set, receipt.resource_set);
            assert_eq!(checked.grant().idle.expires_at, idle_expiry);
            assert_eq!(checked.allocations().len(), 2);
            assert!(checked
                .allocations()
                .iter()
                .all(|a| a.exp == allocation_expiry));
            // This is the harness's intentional negative, before the real install.
            let mut omitted = body.clone();
            omitted["resource_set"]["resources"]
                .as_array_mut()
                .unwrap()
                .retain(|t| t["machine"] != "gateway");
            assert!(matches!(
                verify_delegation(
                    &sign(&central, GRANT_TYPE, omitted),
                    &tokens,
                    &trust,
                    clock,
                    &context
                ),
                Err(VerifyError::Binding)
            ));
        }
    }
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
        "team":namespace,"primary_id":"native-primary","require_renewable":renewable,"metadata_revision":"native-metadata",
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
    let idle_expiry = initial_idle_expiry_from_qualified_issue(issued, expiry, renewable);
    let idle_admission = initial_idle_admission(generation);
    let delegation_id = initial_delegation_id(generation);
    std::fs::write(
        dir.join("protection-deadline"),
        (idle_expiry * 1000).to_string(),
    )?;
    channel.install("protect", json!({"id":"protection","ownership":"ownership","committed":{"admission":idle_admission,"expires_at_ms":idle_expiry*1000}})).await?;
    let central = key(&dir.join("central.pk8"))?;
    let grant_body = native_grant_body(
        issued,
        expiry,
        idle_expiry,
        (&delegation_id, &idle_admission),
        namespace,
        &discovery,
        renewable,
    );
    let allocations = native_allocations(
        &central,
        issued,
        allocation_expiry,
        now,
        expiry,
        &identity,
        renewable,
    );
    let projection = Projection::new(b"native guest proof".to_vec())?;
    let grant = sign(&central, GRANT_TYPE, grant_body.clone());
    let delegation = |id: &str, signed: &str| {
        json!({"id":id,"registration":"registration","control":{
        "id":delegation_id,"version":generation,"principal":"key:native","ownership":"ownership","protection":"protection",
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
