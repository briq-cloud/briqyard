use super::*;

#[tokio::test]
async fn fleet_observation_binds_loaded_input_and_process_lifetime() {
    use sha2::{Digest, Sha256};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fleet.yaml");
    let input = "token: observation-test-secret\n";
    std::fs::write(&path, input).unwrap();
    let f = fleet(config::Config::load(Some(&path)).unwrap());
    let (_, _, first) = call(&f.st, "GET", "/v1/status", "observation-test-secret", None).await;
    let first: serde_json::Value = serde_json::from_str(&first).unwrap();
    let observation: api::RuntimeObservation =
        serde_json::from_value(first["observation"].clone()).unwrap();
    assert_eq!(observation.host_id, "fleet");
    assert_eq!(observation.version, briqyard_version::VERSION);
    assert_eq!(observation.incarnation.len(), 32);
    assert_eq!(
        observation.config,
        api::LoadedConfigIdentity::File {
            sha256: format!("{:x}", Sha256::digest(input.as_bytes())),
        }
    );
    assert!(!first["observation"]
        .to_string()
        .contains("observation-test-secret"));
    std::fs::write(&path, "token: replacement-secret\n").unwrap();
    let (_, _, second) = call(&f.st, "GET", "/v1/status", "observation-test-secret", None).await;
    let second: serde_json::Value = serde_json::from_str(&second).unwrap();
    assert_eq!(first["observation"], second["observation"]);
    let next = fleet(config::Config::load(Some(&path)).unwrap());
    let (_, _, body) = call(&next.st, "GET", "/v1/status", "replacement-secret", None).await;
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_ne!(
        first["observation"]["config"],
        body["observation"]["config"]
    );
    assert_ne!(
        first["observation"]["incarnation"],
        body["observation"]["incarnation"]
    );
}

#[tokio::test]
async fn fleet_observation_distinguishes_defaults_and_unobserved_configuration() {
    for (cfg, source) in [
        (config::Config::default(), "unobserved"),
        (config::Config::load(None).unwrap(), "defaults"),
    ] {
        let f = fleet(cfg);
        let (_, _, body) = call(&f.st, "GET", "/v1/status", "", None).await;
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["observation"]["config"]["source"], source);
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fleet.yaml");
    std::fs::write(&path, "loaded_identity: {source: defaults}\n").unwrap();
    assert!(config::Config::load(Some(&path)).is_err());
}
