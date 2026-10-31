//! The API's bounds and routing, tested without a network.

use super::*;

#[test]
fn request_bounds_hold_at_the_extremes() {
    // The margins the manager adds (10 s to an exec, 5 s to a stop) fit after the cap.
    assert_eq!(stop_timeout(u64::MAX), Duration::from_secs(MAX_STOP_SEC));
    assert_eq!(stop_timeout(0), Duration::ZERO);
    assert_eq!(stop_timeout(30), Duration::from_secs(30));
    assert_eq!(exec_timeout_ms(u64::MAX), MAX_EXEC_MS);
    assert_eq!(exec_timeout_ms(0), 0);
    assert_eq!(exec_timeout_ms(5000), 5000);
    assert!(Duration::from_millis(exec_timeout_ms(u64::MAX) + 10_000) > Duration::ZERO);
    assert_eq!(
        wait_timeout(Some(u64::MAX)),
        Duration::from_secs(MAX_WAIT_SEC)
    );
    assert_eq!(wait_timeout(Some(0)), Duration::from_secs(1));
    assert_eq!(wait_timeout(None), Duration::from_secs(60));
    assert_eq!(log_limit(Some(usize::MAX)), MAX_LOG_LINES);
    assert_eq!(log_limit(None), 0);
    assert_eq!(log_limit(Some(10)), 10);
}

#[test]
fn tenant_is_read_as_namespace_in_a_query() {
    // ADR 0055: the former name of the parameter.
    for q in ["namespace=t1&label=a", "tenant=t1&label=a"] {
        let (namespace, labels) = list_query(Some(q)).unwrap();
        assert_eq!(namespace.as_deref(), Some("t1"), "{q}");
        assert_eq!(labels.len(), 1, "{q}");
    }
    let uri: axum::http::Uri = "/v1/usage?tenant=t1".parse().unwrap();
    let Query(q) = Query::<UsageQuery>::try_from_uri(&uri).unwrap();
    assert_eq!(q.namespace.as_deref(), Some("t1"));
}

#[test]
fn the_description_lists_the_reasons_the_daemon_has() {
    let doc: serde_yaml::Value = serde_yaml::from_str(api::OPENAPI).unwrap();
    let listed: Vec<&str> = doc["components"]["schemas"]["Event"]["properties"]["reason"]["enum"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(listed, api::reason::ALL);
    let conditions: Vec<&str> = doc["components"]["schemas"]["Condition"]["properties"]["type"]
        ["enum"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(conditions, api::condition::ALL);
    for schema in ["Status", "Host", "RegisterHostRequest"] {
        assert_eq!(
            doc["components"]["schemas"][schema]["properties"]["memory_policy"]["$ref"].as_str(),
            Some("#/components/schemas/MemoryPolicy")
        );
    }
}

#[test]
fn a_listing_reads_its_namespace_and_every_label() {
    assert_eq!(list_query(None).unwrap(), (None, vec![]));
    let (namespace, labels) =
        list_query(Some("namespace=t1&label=app%3Dweb&label=tier&other=x")).unwrap();
    assert_eq!(namespace.as_deref(), Some("t1"));
    assert_eq!(
        labels,
        [
            api::Label::parse("app=web").unwrap(),
            api::Label::parse("tier").unwrap()
        ]
    );
    // Unencoded, as a person types it.
    assert_eq!(list_query(Some("label=app=web")).unwrap().1.len(), 1);
    let e = AppError::from(list_query(Some("label=app!%3Dweb")).unwrap_err());
    assert_eq!((e.status, e.code), (StatusCode::BAD_REQUEST, "invalid"));
    assert!(e.error.contains("no !="), "{}", e.error);
}

#[test]
fn wait_is_for_ready_unless_asked() {
    assert_eq!(wait_until(None).ok(), Some(Until::Ready));
    assert_eq!(wait_until(Some("ready")).ok(), Some(Until::Ready));
    assert_eq!(wait_until(Some("running")).ok(), Some(Until::Running));
    let e = AppError::from(wait_until(Some("up")).unwrap_err());
    assert_eq!((e.status, e.code), (StatusCode::BAD_REQUEST, "invalid"));
    assert_eq!(
        e.error,
        "invalid request: for \"up\": want \"ready\" or \"running\""
    );
}

#[test]
fn if_match_is_a_version() {
    let h = |v: &str| {
        let mut m = HeaderMap::new();
        m.insert(header::IF_MATCH, HeaderValue::from_str(v).unwrap());
        m
    };
    assert_eq!(if_match(&HeaderMap::new()).ok(), Some(None));
    assert_eq!(if_match(&h("12")).ok(), Some(Some(12)));
    // An entity tag's quotes are taken off.
    assert_eq!(if_match(&h("\"12\"")).ok(), Some(Some(12)));
    let e = if_match(&h("*")).err().unwrap();
    assert_eq!((e.status, e.code), (StatusCode::BAD_REQUEST, "invalid"));
}

#[test]
fn which_bearer_a_path_needs() {
    assert_eq!(bearer_for("/healthz", false), Bearer::None);
    assert_eq!(bearer_for("/v1/machines", true), Bearer::Api);
    // On loopback, a scrape and a browser need no secret.
    assert_eq!(bearer_for("/metrics", true), Bearer::None);
    assert_eq!(bearer_for("/v1/openapi.yaml", true), Bearer::None);
    // Elsewhere, the metrics token or the API's (the fleet relays with the API's).
    assert_eq!(bearer_for("/metrics", false), Bearer::MetricsOrApi);
    assert_eq!(bearer_for("/v1/openapi.yaml", false), Bearer::Api);
}

#[test]
fn error_codes() {
    let m = api::Machine {
        id: "m_1".into(),
        state: api::state::ERROR.into(),
        error: "the guest did not come up: tail".into(),
        ..Default::default()
    };
    let e = AppError::from(MError::BootFailed(Box::new(m)));
    assert_eq!((e.status, e.code), (StatusCode::CONFLICT, "boot_failed"));
    assert_eq!(e.error, "boot failed: the guest did not come up: tail");
    assert_eq!(e.machine.as_ref().map(|m| m.id.as_str()), Some("m_1"));
    // A stale If-Match: 409 `conflict`, with the machine as it is now.
    let now = api::Machine {
        id: "m_1".into(),
        version: 12,
        ..Default::default()
    };
    let e = AppError::from(MError::Moved(Box::new(now)));
    assert_eq!((e.status, e.code), (StatusCode::CONFLICT, "conflict"));
    assert_eq!(e.error, "machine m_1 is at version 12: read it again");
    assert_eq!(e.machine.map(|m| m.version), Some(12));
    let e = AppError::from(MError::Gone {
        oldest: 40,
        message: "since 3: the events after it are gone; the oldest kept is 40".into(),
    });
    assert_eq!(
        (e.status, e.code, e.oldest),
        (StatusCode::GONE, "gone", Some(40))
    );
    let e = AppError::from(MError::NoBackup("m_1/20261021T101500.123Z".into()));
    assert_eq!((e.status, e.code), (StatusCode::NOT_FOUND, "not_found"));
    assert_eq!(e.error, "backup m_1/20261021T101500.123Z not found");
    // A `/wait` that ran out on a running machine its probes do not pass: the machine.
    let running = api::Machine {
        id: "m_1".into(),
        state: api::state::RUNNING.into(),
        probes_status: api::ProbesStatus {
            readiness: Some(api::ProbeStatus {
                passed: false,
                message: "HTTP 503".into(),
                failures: 4,
                at: chrono::Utc::now(),
            }),
            ..Default::default()
        },
        ..Default::default()
    };
    let e = AppError::from(MError::NotReady(Box::new(running)));
    assert_eq!((e.status, e.code), (StatusCode::CONFLICT, "not_ready"));
    assert_eq!(
        e.error,
        "machine m_1 is running, not ready: readiness: HTTP 503"
    );
    assert_eq!(e.machine.map(|m| m.state), Some("running".to_string()));
    // ADR 0048: on its way at the timeout, a create that failed, a name taken: the machine.
    let on_its_way = api::Machine {
        id: "m_1".into(),
        state: api::state::CREATING.into(),
        ..Default::default()
    };
    let e = AppError::from(MError::NotReady(Box::new(on_its_way.clone())));
    assert_eq!(
        (e.code, e.error.as_str()),
        ("not_ready", "machine m_1 is still creating")
    );
    let failed = api::Machine {
        state: api::state::ERROR.into(),
        error: "pull x: manifest unknown".into(),
        ..on_its_way.clone()
    };
    let e = AppError::from(MError::PullFailed(Box::new(failed.clone())));
    assert_eq!((e.status, e.code), (StatusCode::CONFLICT, "pull_failed"));
    assert_eq!(e.error, "pull failed: pull x: manifest unknown");
    let e = AppError::from(MError::CreateFailed(Box::new(failed)));
    assert_eq!((e.status, e.code), (StatusCode::CONFLICT, "create_failed"));
    assert!(e.machine.is_some());
    let e = AppError::from(MError::NameTaken(Box::new(on_its_way)));
    assert_eq!((e.status, e.code), (StatusCode::CONFLICT, "conflict"));
    assert_eq!(e.machine.map(|m| m.id), Some("m_1".to_string()));
    let e = AppError::from(MError::Quota(
        "namespace t1's quota: machines 1 of 1 used, 1 more asked".into(),
    ));
    assert_eq!((e.status, e.code), (StatusCode::FORBIDDEN, "quota"));
    assert_eq!(
        e.error,
        "namespace t1's quota: machines 1 of 1 used, 1 more asked"
    );
    let e = AppError::from(MError::GatewayInUse);
    assert_eq!((e.status, e.code), (StatusCode::CONFLICT, "gateway_in_use"));
    let e = AppError::from(MError::Gateway("t1".into()));
    assert_eq!((e.status, e.code), (StatusCode::CONFLICT, "gateway"));
    assert_eq!(
        e.error,
        "the namespace's gateway: use /v1/namespaces/t1/gateway"
    );
    let e = AppError::from(MError::Capacity("1 MB used of 1".into()));
    assert_eq!(
        (e.status, e.code),
        (StatusCode::SERVICE_UNAVAILABLE, "capacity")
    );
    assert!(e.machine.is_none());
    let e = AppError::from(MError::Other(anyhow::anyhow!("boom")));
    assert_eq!(
        (e.status, e.code),
        (StatusCode::INTERNAL_SERVER_ERROR, "internal")
    );
}
