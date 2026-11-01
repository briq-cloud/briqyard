use super::*;

#[test]
fn pool_keys_bind_owner_and_name_without_delimiter_aliases() {
    assert_ne!(key("a_b", "c").unwrap(), key("a", "b-c").unwrap());
    assert!(key("../other", "pool").is_err());
    assert!(key("owner", "bad/name").is_err());
}

#[test]
fn claims_cannot_inject_a_recipe_or_private_workload_inputs() {
    for field in ["env", "files", "image", "cmd", "size", "warm_slot"] {
        let mut request = json!({"name":"worker", "request_id":"stable"});
        request[field] = json!({"injected":true});
        assert!(serde_json::from_value::<api::ClaimWarmPoolRequest>(request).is_err());
    }
}
