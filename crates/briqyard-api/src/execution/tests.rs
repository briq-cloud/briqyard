use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};

// Public deterministic test seeds only. Never use these for real credentials.
const CENTRAL_SEED: [u8; 32] = [1; 32];
const AUTHORITY_SEED: [u8; 32] = [2; 32];
fn sign_value(header: &Value, body: &Value, seed: &[u8; 32]) -> String {
    sign_raw(&header.to_string(), &body.to_string(), seed)
}
fn sign_raw(header: &str, body: &str, seed: &[u8; 32]) -> String {
    let pair = Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(body)
    );
    format!(
        "{}.{}",
        input,
        URL_SAFE_NO_PAD.encode(pair.sign(input.as_bytes()).as_ref())
    )
}
fn header(typ: &str, kid: &str) -> Value {
    json!({"alg":"EdDSA","typ":typ,"kid":kid,"v":1})
}
fn fixture() -> Value {
    let target = json!({"host":"host-1","machine":"machine-1","namespace":"team-1","run":"run-1","placement":"placement-1"});
    let limits = json!({"max_duration_seconds":20,"max_input_bytes":1024,"max_output_bytes":4096});
    let grant = json!({"v":1,"iss":"central","aud":"runtime","iat":1000,"nbf":1000,"exp":1050,
        "id":"grant-1","principal":"key:credential-1","source":{"kind":"api_key","id":"credential-1","expires_at":1100},
        "team":"team-1","subject":"subject-1","target":target,"resource_set":{"revision":"resources-1","resources":[target]},
        "idle":{"admission":"idle-1","expires_at":1060},"metadata_revision":"metadata-1",
        "operations":["exec","exec_stream","shell","files_read","files_write"],"limits":limits});
    let allocation = json!({"v":1,"iss":"central","aud":"runtime","iat":990,"nbf":990,"exp":1060,
        "id":"allocation-1","epoch":"allocation-epoch-1","authority":"authority-1","authority_epoch":"authority-epoch-1",
        "principal":"key:credential-1","bucket":"exec","window_start":960,"window_end":1080,"units":10});
    let grant_token = sign_value(&header(GRANT_TYPE, "central-test"), &grant, &CENTRAL_SEED);
    let allocation_token = sign_value(
        &header(ALLOCATION_TYPE, "central-test"),
        &allocation,
        &CENTRAL_SEED,
    );
    let permit = json!({"v":1,"iss":"authority","aud":"runtime","iat":1001,"nbf":1001,"exp":1040,
        "admission":"admission-1","authority":"authority-1","authority_epoch":"authority-epoch-1",
        "grant_digest":token_digest(&grant_token),"allocations":[{"id":"allocation-1","epoch":"allocation-epoch-1",
        "digest":token_digest(&allocation_token),"units":1}],"target":target,"operation":"exec",
        "request_digest":token_digest("test-only-request-encoding"),"metadata_revision":"metadata-1","limits":limits});
    let permit_token = sign_value(
        &header(PERMIT_TYPE, "authority-test"),
        &permit,
        &AUTHORITY_SEED,
    );
    let public = |seed: &[u8; 32]| {
        URL_SAFE_NO_PAD.encode(
            Ed25519KeyPair::from_seed_unchecked(seed)
                .unwrap()
                .public_key()
                .as_ref(),
        )
    };
    json!({"description":"TEST ONLY: deterministic Ed25519 seeds are 32 bytes of 0x01 (central) and 0x02 (authority). JSON claims below are informational; signatures bind the compact bytes.",
        "now":1010,"uncertainty":1,"keys":[{"kid":"central-test","role":"central","issuer":"central","authority":null,"public_key":public(&CENTRAL_SEED)},
        {"kid":"authority-test","role":"authority","issuer":"authority","authority":"authority-1","public_key":public(&AUTHORITY_SEED)}],
        "grant":grant,"allocation":allocation,"permit":permit,"grant_token":grant_token,"allocation_token":allocation_token,"permit_token":permit_token})
}
fn keys(f: &Value) -> Vec<VerificationKey> {
    f["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| VerificationKey {
            kid: k["kid"].as_str().unwrap().into(),
            issuer: k["issuer"].as_str().unwrap().into(),
            authority: k["authority"].as_str().map(str::to_owned),
            role: if k["role"] == "central" {
                KeyRole::Central
            } else {
                KeyRole::Authority
            },
            public_key: URL_SAFE_NO_PAD
                .decode(k["public_key"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        })
        .collect()
}
fn check(f: &Value, now: u64, uncertainty: u64) -> Result<VerifiedBundle, VerifyError> {
    let keys = keys(f);
    let original = fixture();
    let g: Grant = serde_json::from_value(original["grant"].clone()).unwrap();
    let p: Permit = serde_json::from_value(original["permit"].clone()).unwrap();
    verify_bundle(
        f["grant_token"].as_str().unwrap(),
        f["permit_token"].as_str().unwrap(),
        &[f["allocation_token"].as_str().unwrap()],
        &Trust {
            keys: &keys,
            central_issuer: "central",
            authority_issuer: "authority",
            audience: "runtime",
        },
        Clock { now, uncertainty },
        &DispatchContext {
            principal: "key:credential-1",
            team: "team-1",
            subject: "subject-1",
            target: &g.target,
            resource_set: &g.resource_set,
            metadata_revision: "metadata-1",
            authority: "authority-1",
            authority_epoch: "authority-epoch-1",
            installed_allocations: &p.allocations,
            operation: Operation::Exec,
            request_digest: &p.request_digest,
        },
    )
}
fn resign(f: &mut Value, which: &str) {
    let (typ, kid, seed) = match which {
        "grant" => (GRANT_TYPE, "central-test", &CENTRAL_SEED),
        "allocation" => (ALLOCATION_TYPE, "central-test", &CENTRAL_SEED),
        _ => (PERMIT_TYPE, "authority-test", &AUTHORITY_SEED),
    };
    f[format!("{which}_token")] = sign_value(&header(typ, kid), &f[which], seed).into();
    if which != "permit" {
        let digest = token_digest(f[format!("{which}_token")].as_str().unwrap());
        if which == "grant" {
            f["permit"]["grant_digest"] = digest.into();
        } else {
            f["permit"]["allocations"][0]["digest"] = digest.into();
        }
        resign(f, "permit");
    }
}
#[test]
fn signing_keys_cannot_impersonate_other_authorities_or_issuers() {
    let mut f = fixture();
    let other_seed = [3; 32];
    let other_key = Ed25519KeyPair::from_seed_unchecked(&other_seed).unwrap();
    let public_key = URL_SAFE_NO_PAD.encode(other_key.public_key().as_ref());
    // Both keys are valid, trusted authority keys. The signed permit names authority-1,
    // but authority-2's key cannot claim that identity even with an exact allocation.
    f["keys"].as_array_mut().unwrap().push(json!({
        "kid":"other-authority", "role":"authority", "issuer":"authority",
        "authority":"authority-2", "public_key":public_key
    }));
    f["permit_token"] = sign_value(
        &header(PERMIT_TYPE, "other-authority"),
        &f["permit"],
        &other_seed,
    )
    .into();
    assert!(matches!(check(&f, 1010, 1), Err(VerifyError::Signature)));
    let mut f = fixture();
    f["keys"][0]["issuer"] = "other-central".into();
    assert!(matches!(check(&f, 1010, 1), Err(VerifyError::Signature)));
    let mut f = fixture();
    f["keys"][1]["issuer"] = "other-issuer".into();
    assert!(matches!(check(&f, 1010, 1), Err(VerifyError::Signature)));
}
#[test]
fn interoperable_fixture() {
    let generated = fixture();
    if std::env::var_os("BRIQYARD_UPDATE_EXECUTION_FIXTURE").is_some() {
        std::fs::write(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/execution-v1.json"
            ),
            serde_json::to_string_pretty(&generated).unwrap() + "\n",
        )
        .unwrap();
    }
    let disk: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/execution-v1.json"
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(disk, generated);
    let verified = check(&disk, 1010, 1).unwrap();
    assert_eq!(verified.grant().subject, "subject-1");
    assert_eq!(verified.permit().admission, "admission-1");
    assert_eq!(verified.allocations().len(), 1);
}
#[test]
fn validity_is_conservative() {
    let f = fixture();
    for (now, error) in [
        (1000, 0),
        (1001, 1),
        (1039, 1),
        (1040, 0),
        (0, 1),
        (MAX_SAFE_INTEGER, 1),
    ] {
        assert!(check(&f, now, error).is_err(), "{now}/{error}");
    }
    assert!(check(&f, 1001, 0).is_ok());
    assert!(check(&f, 1039, 0).is_ok());
}
#[test]
fn rejects_nested_ceilings_and_binding_changes() {
    for (which, path, value) in [
        ("grant", "/source/expires_at", json!(1049)),
        ("grant", "/idle/expires_at", json!(1049)),
        ("grant", "/subject", json!("other")),
        ("grant", "/team", json!("other")),
        ("grant", "/principal", json!("other")),
        ("grant", "/resource_set/revision", json!("other")),
        ("grant", "/operations", json!(["shell"])),
        ("grant", "/exp", json!(MAX_SAFE_INTEGER + 1)),
        ("grant", "/source/id", json!("")),
        ("grant", "/operations", json!(["exec", "exec"])),
        ("grant", "/v", json!(2)),
        ("permit", "/target/run", json!("stale")),
        ("permit", "/target/placement", json!("stale")),
        ("permit", "/metadata_revision", json!("stale")),
        ("permit", "/authority_epoch", json!("stale")),
        ("permit", "/exp", json!(1051)),
        ("permit", "/limits/max_input_bytes", json!(1025)),
        ("permit", "/grant_digest", json!(token_digest("wrong"))),
        ("allocation", "/exp", json!(1030)),
        ("allocation", "/window_end", json!(1059)),
        ("allocation", "/units", json!(0)),
        ("allocation", "/authority_epoch", json!("stale")),
        ("allocation", "/principal", json!("other")),
        ("allocation", "/epoch", json!("stale")),
        ("grant", "/iss", json!("other")),
        ("grant", "/aud", json!("other")),
        ("permit", "/iss", json!("other")),
        ("allocation", "/aud", json!("other")),
    ] {
        let mut f = fixture();
        *f[which].pointer_mut(path).unwrap() = value;
        resign(&mut f, which);
        assert!(check(&f, 1010, 1).is_err(), "{which}{path}");
    }
}
#[test]
fn rejects_malformed_tokens_headers_and_json() {
    for which in ["grant", "allocation", "permit"] {
        let base = fixture();
        let (typ, kid, seed) = if which == "permit" {
            (PERMIT_TYPE, "authority-test", &AUTHORITY_SEED)
        } else if which == "grant" {
            (GRANT_TYPE, "central-test", &CENTRAL_SEED)
        } else {
            (ALLOCATION_TYPE, "central-test", &CENTRAL_SEED)
        };
        for (field, value) in [
            ("alg", json!("HS256")),
            ("typ", json!(GRANT_TYPE)),
            ("kid", json!("missing")),
            ("v", json!(2)),
            ("jku", json!("https://example.invalid/key")),
        ] {
            if field == "typ" && which == "grant" {
                continue;
            }
            let mut f = base.clone();
            let mut h = header(typ, kid);
            h[field] = value;
            f[format!("{which}_token")] = sign_value(&h, &f[which], seed).into();
            assert!(check(&f, 1010, 1).is_err(), "{which}/{field}");
        }
        for raw in [
            format!("{{\"v\":1,{}", &base[which].to_string()[1..]),
            format!("{{\"unknown\":true,{}", &base[which].to_string()[1..]),
        ] {
            let mut f = base.clone();
            f[format!("{which}_token")] =
                sign_raw(&header(typ, kid).to_string(), &raw, seed).into();
            assert!(check(&f, 1010, 1).is_err());
        }
        for token in [
            "x".repeat(MAX_TOKEN_BYTES + 1),
            "a.b.c.d".into(),
            format!("{}x", base[format!("{which}_token")].as_str().unwrap()),
        ] {
            let mut f = base.clone();
            f[format!("{which}_token")] = token.into();
            assert!(check(&f, 1010, 1).is_err());
        }
    }
}
#[test]
fn rejects_wrong_key_role_and_signature() {
    let mut f = fixture();
    f["keys"][0]["role"] = "authority".into();
    assert!(check(&f, 1010, 1).is_err());
    let mut f = fixture();
    f["keys"][0]["public_key"] = f["keys"][1]["public_key"].clone();
    assert!(check(&f, 1010, 1).is_err());
    let mut f = fixture();
    f["keys"]
        .as_array_mut()
        .unwrap()
        .push(fixture()["keys"][0].clone());
    assert!(check(&f, 1010, 1).is_err());
    let mut f = fixture();
    f["permit_token"] = sign_value(
        &header(PERMIT_TYPE, "central-test"),
        &f["permit"],
        &CENTRAL_SEED,
    )
    .into();
    assert!(check(&f, 1010, 1).is_err());
}

#[test]
fn rejects_collection_bounds_and_nested_unknown_or_duplicate_fields() {
    for resources in [
        json!([]),
        json!(vec![
            fixture()["grant"]["target"].clone();
            MAX_RESOURCES + 1
        ]),
        json!([fixture()["grant"]["target"], fixture()["grant"]["target"]]),
    ] {
        let mut f = fixture();
        f["grant"]["resource_set"]["resources"] = resources;
        resign(&mut f, "grant");
        assert!(check(&f, 1010, 1).is_err());
    }
    for path in ["/source", "/target", "/resource_set", "/idle", "/limits"] {
        let mut f = fixture();
        f["grant"].pointer_mut(path).unwrap()["unknown"] = json!(true);
        resign(&mut f, "grant");
        assert!(check(&f, 1010, 1).is_err());
    }
    let f = fixture();
    let duplicate = f["grant"].to_string().replace(
        "\"kind\":\"api_key\"",
        "\"kind\":\"api_key\",\"kind\":\"api_key\"",
    );
    let mut nested = f.clone();
    nested["grant_token"] = sign_raw(
        &header(GRANT_TYPE, "central-test").to_string(),
        &duplicate,
        &CENTRAL_SEED,
    )
    .into();
    assert!(check(&nested, 1010, 1).is_err());
    let mut duplicate_header = f.clone();
    duplicate_header["grant_token"]=sign_raw(
        "{\"alg\":\"EdDSA\",\"alg\":\"EdDSA\",\"typ\":\"briqyard-execution-grant+jwt\",\"kid\":\"central-test\",\"v\":1}",
        &f["grant"].to_string(),&CENTRAL_SEED).into();
    assert!(check(&duplicate_header, 1010, 1).is_err());
}

#[test]
fn rejects_tampering_and_non_integer_times() {
    let mut f = fixture();
    let token = f["grant_token"].as_str().unwrap();
    let parts: Vec<_> = token.split('.').collect();
    let body = f["grant"].to_string().replace("subject-1", "subject-2");
    f["grant_token"] = format!("{}.{}.{}", parts[0], URL_SAFE_NO_PAD.encode(body), parts[2]).into();
    assert_eq!(check(&f, 1010, 1).err(), Some(VerifyError::Signature));
    for value in [json!(1000.5), json!(-1), json!("1000"), Value::Null] {
        let mut f = fixture();
        f["grant"]["iat"] = value;
        resign(&mut f, "grant");
        assert!(check(&f, 1010, 1).is_err());
    }
}

fn check_delegation(
    f: &Value,
    tokens: &[&str],
    now: u64,
) -> Result<VerifiedDelegation, VerifyError> {
    // Installation needs no authority signing key or fabricated permit.
    let keys: Vec<_> = keys(f)
        .into_iter()
        .filter(|k| k.role == KeyRole::Central)
        .collect();
    let original = fixture();
    let g: Grant = serde_json::from_value(original["grant"].clone()).unwrap();
    verify_delegation(
        f["grant_token"].as_str().unwrap(),
        tokens,
        &Trust {
            keys: &keys,
            central_issuer: "central",
            authority_issuer: "authority",
            audience: "runtime",
        },
        Clock {
            now,
            uncertainty: 1,
        },
        &DelegationContext {
            principal: "key:credential-1",
            team: "team-1",
            subject: "subject-1",
            target: &g.target,
            resource_set: &g.resource_set,
            metadata_revision: "metadata-1",
            authority: "authority-1",
            authority_epoch: "authority-epoch-1",
        },
    )
}

#[test]
fn delegation_installation_is_independent_of_operation_permits() {
    let mut f = fixture();
    // A grant can outlive its allocation, but allocation expiry still prevents use.
    f["allocation"]["exp"] = json!(1020);
    resign(&mut f, "allocation");
    let token = f["allocation_token"].as_str().unwrap();
    let verified = check_delegation(&f, &[token], 1010).unwrap();
    assert_eq!(verified.grant().id, "grant-1");
    assert_eq!(verified.allocations()[0].exp, 1020);
    assert!(matches!(
        check_delegation(&f, &[token], 1019),
        Err(VerifyError::Time)
    ));
    assert!(check_delegation(&f, &[], 1010).is_err());
    assert!(check_delegation(&f, &[token; MAX_ALLOCATIONS + 1], 1010).is_err());
    assert!(check_delegation(&f, &[token, token], 1010).is_err());
}

#[test]
fn delegation_installation_requires_exact_trusted_binding_and_valid_capacity() {
    for (which, path, value) in [
        ("grant", "/target/run", json!("stale")),
        ("grant", "/resource_set/revision", json!("stale")),
        ("grant", "/metadata_revision", json!("stale")),
        ("grant", "/subject", json!("other")),
        ("grant", "/team", json!("other")),
        ("grant", "/principal", json!("other")),
        ("grant", "/idle/expires_at", json!(1040)),
        ("grant", "/source/expires_at", json!(1040)),
        ("allocation", "/authority", json!("other")),
        ("allocation", "/authority_epoch", json!("stale")),
        ("allocation", "/principal", json!("other")),
        ("allocation", "/units", json!(0)),
        ("allocation", "/window_end", json!(1050)),
        ("allocation", "/nbf", json!(1011)),
    ] {
        let mut f = fixture();
        *f[which].pointer_mut(path).unwrap() = value;
        resign(&mut f, which);
        assert!(
            check_delegation(&f, &[f["allocation_token"].as_str().unwrap()], 1010).is_err(),
            "{which}{path}"
        );
    }
    let f = fixture();
    let mut second = f["allocation"].clone();
    second["id"] = json!("second");
    let token = sign_value(
        &header(ALLOCATION_TYPE, "central-test"),
        &second,
        &CENTRAL_SEED,
    );
    assert!(matches!(
        check_delegation(&f, &[f["allocation_token"].as_str().unwrap(), &token], 1010),
        Err(VerifyError::Binding)
    ));
    second["bucket"] = json!("other");
    second["id"] = f["allocation"]["id"].clone();
    let token = sign_value(
        &header(ALLOCATION_TYPE, "central-test"),
        &second,
        &CENTRAL_SEED,
    );
    assert!(matches!(
        check_delegation(&f, &[f["allocation_token"].as_str().unwrap(), &token], 1010),
        Err(VerifyError::Binding)
    ));
    let wrong_role = sign_value(
        &header(ALLOCATION_TYPE, "authority-test"),
        &f["allocation"],
        &AUTHORITY_SEED,
    );
    assert!(check_delegation(&f, &[&wrong_role], 1010).is_err());
}
