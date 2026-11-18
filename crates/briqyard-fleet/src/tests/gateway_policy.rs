//! The selected host's own word gates every request that carries a gateway policy (ADR 0143).
use super::*;

fn bound(namespace: &str) -> serde_json::Value {
    let mut body = create_body(namespace, "consumer", 128);
    body["egress"] = serde_json::json!({
        "mode": "via", "via": "gateway",
        "gateway_policy": {
            "policy_format": 1,
            "policy_digest": format!("sha256:{}", "ab".repeat(32)),
            "enforcement_version": 1
        }
    });
    body
}

#[tokio::test]
async fn a_host_without_the_capability_never_receives_a_bound_create() {
    let (f, ds) = fleet_with_daemons(1).await;
    ds[0].stub.gateway_policy.store(false, Ordering::SeqCst);
    ds[0].stub.calls.lock().unwrap().clear();
    let (status, _, body) = call(&f.st, "POST", "/v1/machines", "api", Some(bound("new"))).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(json(&body)["code"], "capability_unsupported");
    assert!(ds[0].stub.creates.lock().unwrap().is_empty());
    // A restore that leaves egress to its backup may inherit a binding: also refused.
    let mut restore = create_body("new", "restored", 128);
    restore["restore"] = serde_json::json!({"machine_id": "m_0123456789ab", "backup": "latest"});
    let (status, _, body) = call(&f.st, "POST", "/v1/machines", "api", Some(restore)).await;
    assert_ne!(status, StatusCode::CREATED, "{body}");
    assert!(ds[0].stub.creates.lock().unwrap().is_empty());
    // A gateway put with a policy, and the readback, are refused the same way.
    let put = serde_json::json!({"image": "i", "port": 1, "policy": bound("x")["egress"]["gateway_policy"]});
    let (status, _, body) =
        call(&f.st, "PUT", "/v1/namespaces/new/gateway", "api", Some(put)).await;
    assert_eq!(
        json(&body)["code"],
        "capability_unsupported",
        "{status} {body}"
    );
    // The same host, now saying yes, receives the field untouched.
    ds[0].stub.gateway_policy.store(true, Ordering::SeqCst);
    let (status, _, body) = call(&f.st, "POST", "/v1/machines", "api", Some(bound("new"))).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(ds[0].stub.creates.lock().unwrap()[0]
        .egress
        .as_ref()
        .unwrap()
        .gateway_policy
        .is_some());
}

#[test]
fn only_requests_that_carry_a_policy_need_the_capability() {
    use axum::http::Method;
    let json = |v: serde_json::Value| serde_json::to_vec(&v).unwrap();
    let plain = json(serde_json::json!({"egress": {"mode": "via", "via": "gateway"}}));
    assert!(!crate::forward::needs_gateway_policy(
        &Method::POST,
        "/v1/machines",
        &plain
    ));
    assert!(!crate::forward::needs_gateway_policy(
        &Method::PUT,
        "/v1/namespaces/t/gateway",
        &json(serde_json::json!({"image": "i", "port": 1}))
    ));
    assert!(crate::forward::needs_gateway_policy(
        &Method::PATCH,
        "/v1/machines/m_1",
        &bound_egress()
    ));
    assert!(crate::forward::needs_gateway_policy(
        &Method::POST,
        "/v1/namespaces/t/gateway/policy-status",
        b"{}"
    ));
    assert!(crate::forward::needs_gateway_policy(
        &Method::PUT,
        "/v1/namespaces/t/gateway",
        &json(serde_json::json!({"policy": {}}))
    ));
    assert!(!crate::forward::needs_gateway_policy(
        &Method::GET,
        "/v1/machines",
        b""
    ));
}

fn bound_egress() -> Vec<u8> {
    serde_json::to_vec(&bound("t")).unwrap()
}
