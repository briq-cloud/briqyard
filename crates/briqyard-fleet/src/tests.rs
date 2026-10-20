//! The HTTP handlers, driven in process through the router. Hosts are stub daemons on
//! loopback: they answer the few routes the fleet asks and record what was asked.

use super::*;
use axum::body::Body;
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

// --- a stub daemon ---

struct Daemon {
    id: String,
    token: String,
    calls: Mutex<Vec<String>>,
    machines: Mutex<Vec<api::Machine>>,
    next: AtomicUsize,
    /// A tenant the daemon refuses to delete (answers 409), to test a failed forward.
    keep_tenant: String,
}

impl Daemon {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn machine(&self, tenant: &str, name: &str, memory_mb: u32) -> api::Machine {
        let n = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        let now = Utc::now();
        api::Machine {
            id: format!("m_{}_{n}", self.id),
            tenant: tenant.into(),
            name: name.into(),
            image: "nginx".into(),
            state: api::state::RUNNING.into(),
            ip: format!("10.1.0.{n}"),
            hostname: format!("{name}.internal"),
            size: api::Size {
                vcpus: 1,
                memory_mb,
            },
            sleep: "30m".into(),
            created_at: now,
            updated_at: now,
            ..Default::default()
        }
    }

    /// Adds a machine as if it had been created on this daemon.
    fn add(&self, tenant: &str, name: &str, memory_mb: u32) -> api::Machine {
        let m = self.machine(tenant, name, memory_mb);
        self.machines.lock().unwrap().push(m.clone());
        m
    }
}

/// A daemon on loopback: its URL and the stub behind it.
struct Running {
    url: String,
    stub: Arc<Daemon>,
}

async fn start_daemon(id: &str, token: &str) -> Running {
    let stub = Arc::new(Daemon {
        id: id.into(),
        token: token.into(),
        calls: Mutex::new(vec![]),
        machines: Mutex::new(vec![]),
        next: AtomicUsize::new(0),
        keep_tenant: "kept".into(),
    });
    type D = State<Arc<Daemon>>;
    async fn status(State(d): D) -> Json<api::Status> {
        let ms = d.machines.lock().unwrap();
        Json(api::Status {
            version: "0.1-stub".into(),
            host_id: d.id.clone(),
            capacity: api::Capacity {
                memory_mb: 64_000,
                vcpus: 32,
            },
            used: api::Capacity {
                memory_mb: ms.iter().map(|m| m.size.memory_mb).sum(),
                vcpus: ms.len() as u32,
            },
            machines: ms.len(),
            running: ms.len(),
            disk_free_mb: 100_000,
        })
    }
    async fn tenants(State(d): D) -> Json<Vec<api::Tenant>> {
        let ms = d.machines.lock().unwrap();
        let mut ids: Vec<String> = ms.iter().map(|m| m.tenant.clone()).collect();
        ids.sort();
        ids.dedup();
        Json(
            ids.into_iter()
                .map(|id| api::Tenant {
                    id,
                    subnet: "10.1.0.0/24".into(),
                    gateway: "10.1.0.1".into(),
                    machines: 1,
                    created_at: Utc::now(),
                    host: String::new(),
                })
                .collect(),
        )
    }
    async fn delete_tenant(State(d): D, Path(id): Path<String>) -> Response {
        if id == d.keep_tenant {
            return err(StatusCode::CONFLICT, "busy", "tenant has machines");
        }
        d.machines.lock().unwrap().retain(|m| m.tenant != id);
        StatusCode::NO_CONTENT.into_response()
    }
    async fn list(State(d): D, uri: Uri) -> Json<Vec<api::Machine>> {
        let tenant = uri
            .query()
            .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("tenant=")))
            .map(|t| t.to_string());
        let ms = d.machines.lock().unwrap();
        Json(
            ms.iter()
                .filter(|m| tenant.as_deref().map(|t| t == m.tenant).unwrap_or(true))
                .cloned()
                .collect(),
        )
    }
    async fn create(State(d): D, Json(req): Json<api::CreateMachineRequest>) -> Response {
        let m = d.add(&req.tenant, &req.name, req.size.memory_mb);
        (StatusCode::CREATED, Json(m)).into_response()
    }
    async fn get_machine(State(d): D, Path(id): Path<String>) -> Response {
        let ms = d.machines.lock().unwrap();
        match ms.iter().find(|m| m.id == id) {
            Some(m) => Json(m.clone()).into_response(),
            None => (
                StatusCode::NOT_FOUND,
                Json(api::ApiError {
                    error: "machine not found".into(),
                    code: "not_found".into(),
                    request_id: "d-req-1".into(),
                    machine: None,
                }),
            )
                .into_response(),
        }
    }
    async fn delete_machine(State(d): D, Path(id): Path<String>) -> StatusCode {
        let mut ms = d.machines.lock().unwrap();
        let before = ms.len();
        ms.retain(|m| m.id != id);
        if ms.len() == before {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::NO_CONTENT
        }
    }
    async fn start_machine(State(d): D, Path(id): Path<String>) -> Response {
        let ms = d.machines.lock().unwrap();
        match ms.iter().find(|m| m.id == id) {
            Some(m) => {
                let mut out = Json(m.clone()).into_response();
                out.headers_mut()
                    .insert("x-request-id", HeaderValue::from_static("d-req-2"));
                out
            }
            None => StatusCode::NOT_FOUND.into_response(),
        }
    }
    /// The store is shared: every host answers for every machine id, with nothing here.
    async fn backups(State(_d): D) -> Json<Vec<serde_json::Value>> {
        Json(vec![])
    }

    async fn endpoints(State(d): D) -> Json<Vec<api::Endpoint>> {
        Json(vec![api::Endpoint {
            id: format!("ep_{}", d.id),
            machine_id: format!("m_{}_1", d.id),
            port: 80,
            protocol: "tcp".into(),
            host_port: Some(30080),
            host: String::new(),
            address: "127.0.0.1:30080".into(),
            created_at: Utc::now(),
        }])
    }
    async fn delete_endpoint(State(d): D, Path(id): Path<String>) -> StatusCode {
        if id == format!("ep_{}", d.id) {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::NOT_FOUND
        }
    }
    // Every request is recorded, with its query, and checked for the daemon's token.
    async fn record(State(d): D, req: Request, next: axum::middleware::Next) -> Response {
        let line = format!(
            "{} {}",
            req.method(),
            req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("")
        );
        d.calls.lock().unwrap().push(line);
        let bearer = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        if !d.token.is_empty() && bearer != d.token {
            return err(StatusCode::UNAUTHORIZED, "unauthorized", "bad token");
        }
        next.run(req).await
    }
    let app = Router::new()
        .route("/v1/status", get(status))
        .route("/v1/tenants", get(tenants))
        .route("/v1/tenants/:id", axum::routing::delete(delete_tenant))
        .route("/v1/machines", get(list).post(create))
        .route("/v1/machines/:id", get(get_machine).delete(delete_machine))
        .route("/v1/machines/:id/start", post(start_machine))
        .route("/v1/machines/:id/backups", get(backups))
        .route("/v1/endpoints", get(endpoints))
        .route("/v1/endpoints/:id", axum::routing::delete(delete_endpoint))
        .layer(axum::middleware::from_fn_with_state(stub.clone(), record))
        .with_state(stub.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Running { url, stub }
}

// --- the fleet under test ---

struct Fleet {
    st: Arc<AppState>,
    _dir: tempfile::TempDir,
}

/// A fleet on a fresh state directory, with the hosts of the configuration seeded as `run` does.
fn fleet(mut cfg: config::Config, prov: Box<dyn provision::Provisioner>) -> Fleet {
    let dir = tempfile::tempdir().unwrap();
    cfg.state_dir = dir.path().to_path_buf();
    let mut reg = Registry::default();
    let now = Utc::now();
    for h in &cfg.hosts {
        reg.heartbeat(static_host(h, now), now);
    }
    let st = Arc::new(AppState {
        state_path: cfg.state_dir.join("registry.json"),
        policy: Policy {
            fill_ceiling: cfg.placement.fill_ceiling,
            down_after: Duration::seconds(cfg.placement.down_after_sec as i64),
        },
        cfg,
        reg: Mutex::new(reg),
        http: reqwest::Client::new(),
        prov,
    });
    Fleet { st, _dir: dir }
}

fn dry_scaleway() -> Box<dyn provision::Provisioner> {
    provision::build(&config::Provisioner {
        kind: "scaleway".into(),
        ..Default::default()
    })
}

/// A ready host in the registry, with no daemon behind it.
fn seed(st: &AppState, id: &str, cap: u32, used: u32, machines: usize, tenants: &[&str]) {
    let now = Utc::now();
    let mut h = static_host(
        &config::StaticHost {
            id: id.into(),
            url: format!("http://10.0.0.{}:7420", id.len()),
            ..Default::default()
        },
        now,
    );
    h.capacity = api::Capacity {
        memory_mb: cap,
        vcpus: 32,
    };
    h.used = api::Capacity {
        memory_mb: used,
        vcpus: 0,
    };
    h.machines = machines;
    h.tenants = tenants.iter().map(|t| t.to_string()).collect();
    let mut reg = st.reg.lock().unwrap();
    reg.heartbeat(h, now);
}

fn set_state(st: &AppState, id: &str, state: &str) {
    st.reg.lock().unwrap().hosts.get_mut(id).unwrap().state = state.into();
}

/// A fleet in front of `n` stub daemons, polled once so their capacity is known.
async fn fleet_with_daemons(n: usize) -> (Fleet, Vec<Running>) {
    let mut daemons = Vec::new();
    let mut cfg = config::Config {
        token: "api".into(),
        host_token: "hosty".into(),
        ..Default::default()
    };
    for i in 1..=n {
        let d = start_daemon(&format!("d{i}"), &format!("tok-{i}")).await;
        cfg.hosts.push(config::StaticHost {
            id: format!("d{i}"),
            url: d.url.clone(),
            token: format!("tok-{i}"),
            region: "fsn".into(),
        });
        daemons.push(d);
    }
    let f = fleet(cfg, Box::new(provision::Static));
    poll_static_hosts_once(&f.st).await;
    (f, daemons)
}

/// One request through the router. The body comes back as text.
async fn call(
    st: &Arc<AppState>,
    method: &str,
    path: &str,
    token: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, HeaderMap, String) {
    let mut req = axum::http::Request::builder().method(method).uri(path);
    if !token.is_empty() {
        req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let req = match body {
        Some(v) => req
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&v).unwrap())),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let resp = app(st.clone()).oneshot(req).await.unwrap();
    let (parts, body) = resp.into_parts();
    let data = axum::body::to_bytes(body, 64 << 20).await.unwrap();
    (
        parts.status,
        parts.headers,
        String::from_utf8(data.to_vec()).unwrap(),
    )
}

fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("{e}: {text:?}"))
}

fn hosts(st: &Arc<AppState>) -> Vec<api::Host> {
    let reg = st.reg.lock().unwrap();
    let mut v: Vec<api::Host> = reg.hosts.values().map(|h| h.to_api()).collect();
    v.sort_by(|a, b| a.id.cmp(&b.id));
    v
}

fn create_body(tenant: &str, name: &str, memory_mb: u32) -> serde_json::Value {
    serde_json::to_value(api::CreateMachineRequest {
        tenant: tenant.into(),
        name: name.into(),
        image: "nginx".into(),
        size: api::Size {
            vcpus: 1,
            memory_mb,
        },
        ..Default::default()
    })
    .unwrap()
}

// --- pure helpers ---

#[test]
fn a_static_host_without_an_id_is_named_by_its_url() {
    let now = Utc::now();
    let h = static_host(
        &config::StaticHost {
            url: "http://10.0.0.5:7420".into(),
            token: "t".into(),
            ..Default::default()
        },
        now,
    );
    assert_eq!(h.id, "http://10.0.0.5:7420");
    assert_eq!(h.state, "ready");
    assert_eq!(h.provider, "static");
    assert_eq!(h.token, "t");
    let named = static_host(
        &config::StaticHost {
            id: "h1".into(),
            url: "http://10.0.0.5:7420".into(),
            ..Default::default()
        },
        now,
    );
    assert_eq!(named.id, "h1");
}

#[test]
fn with_host_marks_a_machine_body_and_leaves_the_rest() {
    let out = with_host(Bytes::from(r#"{"id":"m1","host":""}"#), "d1");
    assert_eq!(json(std::str::from_utf8(&out).unwrap())["host"], "d1");
    let list = Bytes::from(r#"[{"id":"m1"}]"#);
    assert_eq!(
        with_host(list.clone(), "d1"),
        list,
        "not an object: untouched"
    );
    let text = Bytes::from("not json");
    assert_eq!(with_host(text.clone(), "d1"), text);
}

// --- auth, status, hosts ---

#[tokio::test]
async fn a_bearer_token_guards_every_route_but_healthz() {
    let f = fleet(
        config::Config {
            token: "api".into(),
            host_token: "hosty".into(),
            ..Default::default()
        },
        Box::new(provision::Static),
    );
    let (s, _, body) = call(&f.st, "GET", "/healthz", "", None).await;
    assert_eq!((s, body.as_str()), (StatusCode::OK, "ok\n"));
    let (s, _, body) = call(&f.st, "GET", "/v1/status", "", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(json(&body)["code"], "unauthorized");
    let (s, _, _) = call(&f.st, "GET", "/v1/status", "wrong", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _, _) = call(&f.st, "GET", "/v1/status", "api", None).await;
    assert_eq!(s, StatusCode::OK);
    // The host token opens the register route alone.
    let hb = serde_json::json!({
        "id": "h1", "url": "http://10.0.0.1:7420",
        "capacity": {"memory_mb": 1000, "vcpus": 4}, "used": {"memory_mb": 0, "vcpus": 0},
        "machines": 0
    });
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/register", "api", Some(hb.clone())).await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "the API token is not a host token"
    );
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/register", "hosty", Some(hb)).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _, _) = call(&f.st, "GET", "/v1/hosts", "hosty", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "a host token reads nothing");

    // No token configured: nothing is asked.
    let open = fleet(config::Config::default(), Box::new(provision::Static));
    let (s, _, _) = call(&open.st, "GET", "/v1/hosts", "", None).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn status_sums_the_ready_hosts_and_hosts_are_sorted() {
    let f = fleet(config::Config::default(), Box::new(provision::Static));
    seed(&f.st, "b", 64_000, 8_000, 3, &["t1", "t2"]);
    seed(&f.st, "a", 32_000, 1_000, 1, &["t3"]);
    seed(&f.st, "c", 16_000, 0, 0, &[]);
    set_state(&f.st, "a", "down");
    set_state(&f.st, "c", "draining");
    let (s, _, body) = call(&f.st, "GET", "/v1/status", "", None).await;
    assert_eq!(s, StatusCode::OK);
    let v = json(&body);
    assert_eq!(v["host_id"], "fleet");
    assert_eq!(v["hosts"], 3);
    assert_eq!(v["ready"], 1, "only b is ready");
    assert_eq!(v["capacity"]["memory_mb"], 64_000);
    assert_eq!(v["used"]["memory_mb"], 8_000);
    assert_eq!(v["machines"], 3);
    assert_eq!(
        v["tenants"], 3,
        "pins are counted whatever the host's state"
    );
    assert_eq!(v["provisioner"], "static");
    assert_eq!(v["dry_run"], true);
    let (s, _, body) = call(&f.st, "GET", "/v1/hosts", "", None).await;
    assert_eq!(s, StatusCode::OK);
    let hs: Vec<api::Host> = serde_json::from_str(&body).unwrap();
    let ids: Vec<&str> = hs.iter().map(|h| h.id.as_str()).collect();
    assert_eq!(ids, ["a", "b", "c"]);
    let states: Vec<&str> = hs.iter().map(|h| h.state.as_str()).collect();
    assert_eq!(states, ["down", "ready", "draining"]);
    assert_eq!(hs[1].tenants, ["t1", "t2"]);
}

#[tokio::test]
async fn a_heartbeat_takes_over_the_record_ordered_for_its_address() {
    let f = fleet(
        config::Config {
            host_token: "hosty".into(),
            ..Default::default()
        },
        dry_scaleway(),
    );
    {
        let mut reg = f.st.reg.lock().unwrap();
        let mut ordered = static_host(&config::StaticHost::default(), Utc::now());
        ordered.id = "h_srv-9".into();
        ordered.url = "http://10.0.0.9:7420".into();
        ordered.state = "provisioning".into();
        ordered.provider = "scaleway".into();
        ordered.provider_id = "srv-9".into();
        ordered.token = "t0k".into();
        ordered.note = "delivered at 10.0.0.9".into();
        reg.hosts.insert(ordered.id.clone(), ordered);
    }
    let hb = serde_json::json!({
        "id": "h_byard-1", "url": "http://10.0.0.9:7420", "region": "par",
        "capacity": {"memory_mb": 64000, "vcpus": 32}, "used": {"memory_mb": 512, "vcpus": 1},
        "machines": 1, "tenants": ["t1"], "version": "0.1", "disk_free_mb": 5000
    });
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/register", "hosty", Some(hb)).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let hs = hosts(&f.st);
    assert_eq!(
        hs.len(),
        1,
        "the ordered record is replaced, not kept beside"
    );
    let h = &hs[0];
    assert_eq!(h.id, "h_byard-1");
    assert_eq!(h.state, "ready");
    assert_eq!(h.provider, "scaleway");
    assert_eq!(h.region, "par");
    assert_eq!(h.capacity.memory_mb, 64_000);
    assert_eq!(h.machines, 1);
    assert_eq!(h.note, "delivered at 10.0.0.9");
    {
        let reg = f.st.reg.lock().unwrap();
        let rec = &reg.hosts["h_byard-1"];
        assert_eq!(rec.provider_id, "srv-9");
        assert_eq!(
            rec.token, "t0k",
            "the token the bootstrap gave it carries over"
        );
        assert_eq!(reg.tenants.get("t1").map(String::as_str), Some("h_byard-1"));
    }
    // The registry is written after each register.
    let saved: Registry =
        serde_json::from_slice(&std::fs::read(&f.st.state_path).unwrap()).unwrap();
    assert!(saved.hosts.contains_key("h_byard-1"));
    let (s, _, body) = call(&f.st, "GET", "/v1/tenants", "", None).await;
    assert_eq!(s, StatusCode::OK);
    let ts: Vec<api::Tenant> = serde_json::from_str(&body).unwrap();
    assert_eq!(ts.len(), 1);
    assert_eq!(
        (ts[0].id.as_str(), ts[0].host.as_str()),
        ("t1", "h_byard-1")
    );
}

// --- ordering, retiring, draining, forgetting ---

#[tokio::test]
async fn the_static_provisioner_cannot_order() {
    let f = fleet(config::Config::default(), Box::new(provision::Static));
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/hosts/order",
        "",
        Some(serde_json::json!({"reason": "x"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_GATEWAY);
    let v = json(&body);
    assert_eq!(v["code"], "provisioner");
    assert!(
        v["error"].as_str().unwrap().contains("cannot add hosts"),
        "{v}"
    );
    assert!(hosts(&f.st).is_empty(), "nothing recorded");
}

#[tokio::test]
async fn an_order_in_dry_run_records_a_dry_run_host() {
    let f = fleet(config::Config::default(), dry_scaleway());
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/hosts/order",
        "",
        Some(serde_json::json!({"reason": "launch week"})),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{body}");
    let h: api::Host = serde_json::from_str(&body).unwrap();
    assert!(h.id.starts_with("h_dry-run-byard-"), "{}", h.id);
    assert_eq!(h.state, "dry-run");
    assert_eq!(h.provider, "scaleway");
    assert_eq!(h.url, "", "no address yet");
    assert!(h.note.starts_with("DRY RUN: would create"), "{}", h.note);
    assert!(h.note.ends_with("(launch week)"), "{}", h.note);
    let listed = hosts(&f.st);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, h.id);
    {
        let reg = f.st.reg.lock().unwrap();
        let rec = &reg.hosts[&h.id];
        assert!(rec.provider_id.starts_with("dry-run-"));
        assert_eq!(rec.token.len(), 32, "a token of its own for its API");
        assert!(rec.empty_since.is_some());
    }
    // No reason: a default one in the note.
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/hosts/order",
        "",
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{body}");
    let h: api::Host = serde_json::from_str(&body).unwrap();
    assert!(h.note.ends_with("(ordered through the API)"), "{}", h.note);
}

#[tokio::test]
async fn an_order_past_max_hosts_is_refused() {
    let f = fleet(
        config::Config {
            provisioner: config::Provisioner {
                kind: "scaleway".into(),
                max_hosts: 2,
                ..Default::default()
            },
            ..Default::default()
        },
        dry_scaleway(),
    );
    seed(&f.st, "a", 1000, 0, 0, &[]);
    seed(&f.st, "b", 1000, 0, 0, &[]);
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/hosts/order",
        "",
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");
    let v = json(&body);
    assert_eq!(v["code"], "max_hosts");
    assert_eq!(v["error"], "the fleet has 2 hosts, its maximum");
    assert_eq!(hosts(&f.st).len(), 2);
    // A host that is down does not hold a place.
    set_state(&f.st, "b", "down");
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/hosts/order",
        "",
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{body}");
    assert_eq!(hosts(&f.st).len(), 3);
    // Now 2 are counted again (a and the dry-run one): the next order is refused.
    let (s, _, _) = call(
        &f.st,
        "POST",
        "/v1/hosts/order",
        "",
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
}

#[tokio::test]
async fn retire_releases_an_empty_host_at_once() {
    let f = fleet(config::Config::default(), dry_scaleway());
    seed(&f.st, "h_a", 1000, 0, 0, &[]);
    {
        let mut reg = f.st.reg.lock().unwrap();
        let h = reg.hosts.get_mut("h_a").unwrap();
        h.provider = "scaleway".into();
        h.provider_id = "dry-run-x".into();
        // Stale index entries from a machine long gone and a tenant never confirmed.
        reg.machines.insert("m9".into(), "h_a".into());
        reg.tenants.insert("t9".into(), "h_a".into());
    }
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/h_a/retire", "", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let h: api::Host = serde_json::from_str(&body).unwrap();
    assert_eq!(h.id, "h_a");
    assert_eq!(h.state, "released");
    assert!(hosts(&f.st).is_empty(), "released and forgotten");
    {
        let reg = f.st.reg.lock().unwrap();
        assert!(reg.machines.is_empty(), "its machine index goes with it");
        assert!(reg.tenants.is_empty());
    }
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/h_a/retire", "", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // A static host (no provider id) is forgotten without a provider call: with the static
    // provisioner, a release call would fail the request.
    let g = fleet(config::Config::default(), Box::new(provision::Static));
    seed(&g.st, "h_s", 1000, 0, 0, &[]);
    let (s, _, body) = call(&g.st, "POST", "/v1/hosts/h_s/retire", "", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert!(hosts(&g.st).is_empty());
}

#[tokio::test]
async fn retire_drains_a_busy_host_until_it_empties() {
    let f = fleet(config::Config::default(), dry_scaleway());
    seed(&f.st, "h_b", 64_000, 4_000, 2, &["t1"]);
    {
        let mut reg = f.st.reg.lock().unwrap();
        reg.hosts.get_mut("h_b").unwrap().provider_id = "dry-run-b".into();
    }
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/h_b/retire", "", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let h: api::Host = serde_json::from_str(&body).unwrap();
    assert_eq!(h.state, "draining");
    assert_eq!(h.machines, 2);
    let listed = hosts(&f.st);
    assert_eq!(listed.len(), 1, "still here");
    assert_eq!(listed[0].state, "draining");
    assert!(f.st.reg.lock().unwrap().retirable().is_empty());
    // Asked again while busy: still draining, not released.
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/h_b/retire", "", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(json(&body)["state"], "draining");
    // Its last machine goes (a heartbeat says so): the scaler's pass would release it.
    {
        let mut reg = f.st.reg.lock().unwrap();
        let mut empty = reg.hosts["h_b"].clone();
        empty.machines = 0;
        empty.tenants.clear();
        reg.heartbeat(empty, Utc::now());
        reg.tenants.clear();
        assert_eq!(reg.retirable().len(), 1);
    }
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/h_b/retire", "", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(json(&body)["state"], "released");
    assert!(hosts(&f.st).is_empty());
}

#[tokio::test]
async fn drain_and_forget() {
    let f = fleet(config::Config::default(), Box::new(provision::Static));
    seed(&f.st, "h_a", 64_000, 0, 1, &["t1"]);
    seed(&f.st, "h_b", 64_000, 0, 1, &["t2"]);
    f.st.reg
        .lock()
        .unwrap()
        .machines
        .insert("m1".into(), "h_a".into());
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/h_a/drain", "", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(hosts(&f.st)[0].state, "draining");
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/h_x/drain", "", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(json(&body)["code"], "not_found");
    // Placement goes elsewhere now, and the pins on h_a stay.
    assert_eq!(
        f.st.reg
            .lock()
            .unwrap()
            .place("t3", 512, 0, &f.st.policy)
            .as_deref(),
        Some("h_b")
    );

    let (s, _, _) = call(&f.st, "DELETE", "/v1/hosts/h_a", "", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let ids: Vec<String> = hosts(&f.st).into_iter().map(|h| h.id).collect();
    assert_eq!(ids, ["h_b"]);
    {
        let reg = f.st.reg.lock().unwrap();
        assert_eq!(reg.tenants.get("t1"), None, "its tenants are unpinned");
        assert_eq!(reg.tenants.get("t2").map(String::as_str), Some("h_b"));
        assert_eq!(reg.machines.get("m1"), None);
    }
    let (s, _, _) = call(&f.st, "DELETE", "/v1/hosts/h_a", "", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "forgetting twice is fine");
    let saved: Registry =
        serde_json::from_slice(&std::fs::read(&f.st.state_path).unwrap()).unwrap();
    assert!(!saved.hosts.contains_key("h_a"));
}

// --- the poll of static hosts ---

#[tokio::test]
async fn the_poll_fills_a_static_host_in_and_marks_a_silent_one_down() {
    let d = start_daemon("d1", "tok-1").await;
    d.stub.add("t1", "web", 512);
    let cfg = config::Config {
        hosts: vec![
            config::StaticHost {
                id: "d1".into(),
                url: d.url.clone(),
                token: "tok-1".into(),
                region: "fsn".into(),
            },
            config::StaticHost {
                id: "gone".into(),
                // Nothing listens there.
                url: "http://127.0.0.1:1".into(),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let f = fleet(cfg, Box::new(provision::Static));
    assert_eq!(
        hosts(&f.st)[0].capacity.memory_mb,
        0,
        "nothing known before the first poll"
    );
    let unseen = poll_static_hosts_once(&f.st).await;
    assert!(unseen, "a host that never answered is asked again soon");
    let hs = hosts(&f.st);
    assert_eq!(hs[0].id, "d1");
    assert_eq!(hs[0].state, "ready");
    assert_eq!(hs[0].capacity.memory_mb, 64_000);
    assert_eq!(hs[0].used.memory_mb, 512);
    assert_eq!(hs[0].machines, 1);
    assert_eq!(hs[0].tenants, ["t1"]);
    assert_eq!(hs[0].version, "0.1-stub");
    assert_eq!(hs[1].id, "gone");
    assert_eq!(hs[1].state, "ready", "silent but not yet past the grace");
    assert_eq!(
        d.stub.calls(),
        ["GET /v1/status", "GET /v1/tenants"],
        "the poll asks for status and tenants, with the host's token"
    );
    // Past the grace, a silent host is down; the next answer brings it back.
    {
        let mut reg = f.st.reg.lock().unwrap();
        for h in reg.hosts.values_mut() {
            h.last_seen = Utc::now() - Duration::minutes(2);
        }
    }
    poll_static_hosts_once(&f.st).await;
    let hs = hosts(&f.st);
    assert_eq!((hs[0].id.as_str(), hs[0].state.as_str()), ("d1", "ready"));
    assert_eq!((hs[1].id.as_str(), hs[1].state.as_str()), ("gone", "down"));
    // A forgotten static host is back on the next poll: it leaves by leaving the configuration.
    let (s, _, _) = call(&f.st, "DELETE", "/v1/hosts/d1", "", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    poll_static_hosts_once(&f.st).await;
    assert_eq!(hosts(&f.st)[0].id, "d1");
}

// --- the machine API, forwarded ---

#[tokio::test]
async fn a_create_is_placed_and_forwarded_with_its_host() {
    let (f, ds) = fleet_with_daemons(2).await;
    let (s, headers, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t1", "web", 512)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    let m: api::Machine = serde_json::from_str(&body).unwrap();
    let host = headers["x-briqyard-host"].to_str().unwrap().to_string();
    assert!(host == "d1" || host == "d2", "{host}");
    assert_eq!(m.host, host, "the host is added to the body");
    assert_eq!(m.name, "web");
    let on = ds.iter().find(|d| d.stub.id == host).unwrap();
    assert_eq!(on.stub.calls().last().unwrap(), "POST /v1/machines");
    assert_eq!(on.stub.machines.lock().unwrap().len(), 1);
    {
        let reg = f.st.reg.lock().unwrap();
        assert_eq!(
            reg.machines.get(&m.id).map(String::as_str),
            Some(host.as_str())
        );
        assert_eq!(
            reg.tenants.get("t1").map(String::as_str),
            Some(host.as_str())
        );
    }
    // The tenant's next machine lands on the same host, whatever the other has free.
    let other = if host == "d1" { "d2" } else { "d1" };
    f.st.reg
        .lock()
        .unwrap()
        .hosts
        .get_mut(&host)
        .unwrap()
        .used
        .memory_mb = 60_000;
    let (s, headers, _) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t1", "db", 512)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(headers["x-briqyard-host"], host.as_str());
    // A new tenant goes to the emptiest host.
    let (s, headers, _) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t2", "web", 512)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(headers["x-briqyard-host"], other);
    // The registry was written.
    let saved: Registry =
        serde_json::from_slice(&std::fs::read(&f.st.state_path).unwrap()).unwrap();
    assert_eq!(saved.machines.len(), 3);
}

#[tokio::test]
async fn a_create_without_room_or_sense_is_refused_before_any_host() {
    let (f, ds) = fleet_with_daemons(1).await;
    let before = ds[0].stub.calls().len();
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t1", "big", 100_000)),
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(json(&body)["code"], "capacity");
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(serde_json::json!({"tenant": "t1"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["code"], "invalid");
    assert_eq!(ds[0].stub.calls().len(), before, "no host was asked");
    assert!(f.st.reg.lock().unwrap().tenants.is_empty());
}

#[tokio::test]
async fn a_fork_lands_where_its_source_is() {
    let (f, ds) = fleet_with_daemons(2).await;
    let src = ds[1].stub.add("t1", "web", 512);
    f.st.reg
        .lock()
        .unwrap()
        .machines
        .insert(src.id.clone(), "d2".into());
    // d1 is emptier (d2 has a machine after a poll), and d1 would be the pick for a new tenant.
    poll_static_hosts_once(&f.st).await;
    let mut body = create_body("t9", "web-fork", 512);
    body["fork"] = serde_json::json!({"machine_id": src.id});
    let (s, headers, _) = call(&f.st, "POST", "/v1/machines", "api", Some(body)).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(headers["x-briqyard-host"], "d2");
    assert!(
        !ds[0].stub.calls().iter().any(|c| c.starts_with("POST")),
        "d1 was not asked"
    );
}

#[tokio::test]
async fn a_machine_is_found_through_the_index_then_by_searching() {
    let (f, ds) = fleet_with_daemons(2).await;
    let m = ds[1].stub.add("t1", "web", 512);
    let path = format!("/v1/machines/{}", m.id);
    // Not in the index: every ready host is asked, in order, until one has it.
    let (s, headers, body) = call(&f.st, "GET", &path, "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d2");
    assert_eq!(json(&body)["host"], "d2", "a plain get carries the host");
    assert_eq!(ds[0].stub.calls().last().unwrap(), &format!("GET {path}"));
    assert_eq!(
        ds[1]
            .stub
            .calls()
            .iter()
            .filter(|c| *c == &format!("GET {path}"))
            .count(),
        2,
        "the search, then the forward"
    );
    assert_eq!(
        f.st.reg
            .lock()
            .unwrap()
            .machines
            .get(&m.id)
            .map(String::as_str),
        Some("d2"),
        "learned"
    );
    // In the index: straight to its host, d1 is not asked.
    let d1_before = ds[0].stub.calls().len();
    let (s, headers, body) = call(&f.st, "POST", &format!("{path}/start"), "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d2");
    assert_eq!(
        headers["x-request-id"], "d-req-2",
        "the daemon's request id passes through"
    );
    assert_eq!(ds[0].stub.calls().len(), d1_before);
    assert_eq!(
        ds[1].stub.calls().last().unwrap(),
        &format!("POST {path}/start")
    );
    // A sub-path answer that is not a plain get is passed as is: no host added.
    assert!(json(&body).get("host").is_none(), "{body}");
    // Unknown anywhere: 404 from the fleet, after asking every host.
    let (s, _, body) = call(&f.st, "GET", "/v1/machines/m_nope", "api", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(json(&body)["code"], "not_found");
    assert!(ds.iter().all(|d| d
        .stub
        .calls()
        .contains(&"GET /v1/machines/m_nope".to_string())));
    // A delete drops the index entry.
    let (s, _, _) = call(&f.st, "DELETE", &path, "api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(f.st.reg.lock().unwrap().machines.get(&m.id), None);
}

#[tokio::test]
async fn a_listing_adds_the_host_and_is_never_partial() {
    let (f, ds) = fleet_with_daemons(2).await;
    let a = ds[0].stub.add("t1", "web", 512);
    let b = ds[1].stub.add("t2", "db", 1024);
    let (s, _, body) = call(&f.st, "GET", "/v1/machines", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let ms: Vec<api::Machine> = serde_json::from_str(&body).unwrap();
    let got: Vec<(String, String)> = ms.iter().map(|m| (m.id.clone(), m.host.clone())).collect();
    assert_eq!(
        got,
        [(a.id.clone(), "d1".into()), (b.id.clone(), "d2".into())]
    );
    {
        let reg = f.st.reg.lock().unwrap();
        assert_eq!(reg.machines.get(&a.id).map(String::as_str), Some("d1"));
        assert_eq!(reg.machines.get(&b.id).map(String::as_str), Some("d2"));
    }
    // A host down fails the whole listing: a reader takes a missing machine for gone.
    set_state(&f.st, "d2", "down");
    let d2_before = ds[1].stub.calls().len();
    let (s, _, body) = call(&f.st, "GET", "/v1/machines", "api", None).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    let v = json(&body);
    assert_eq!(v["code"], "host_down");
    assert!(
        v["error"].as_str().unwrap().contains("host d2 is down"),
        "{v}"
    );
    assert_eq!(
        ds[1].stub.calls().len(),
        d2_before,
        "a down host is not asked"
    );
    // A host that does not answer (nothing listens where its record points) fails it too.
    set_state(&f.st, "d2", "ready");
    f.st.reg.lock().unwrap().hosts.get_mut("d2").unwrap().url = "http://127.0.0.1:1".into();
    let (s, _, body) = call(&f.st, "GET", "/v1/machines", "api", None).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(json(&body)["code"], "host_unreachable");
}

#[tokio::test]
async fn a_tenant_listing_asks_its_host_alone() {
    let (f, ds) = fleet_with_daemons(2).await;
    ds[0].stub.add("t1", "web", 512);
    ds[1].stub.add("t2", "db", 512);
    poll_static_hosts_once(&f.st).await;
    assert_eq!(
        f.st.reg
            .lock()
            .unwrap()
            .tenants
            .get("t1")
            .map(String::as_str),
        Some("d1"),
        "the poll pins the tenants the hosts list"
    );
    set_state(&f.st, "d2", "down");
    let d2_before = ds[1].stub.calls().len();
    let (s, _, body) = call(&f.st, "GET", "/v1/machines?tenant=t1", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let ms: Vec<api::Machine> = serde_json::from_str(&body).unwrap();
    assert_eq!(ms.len(), 1);
    assert_eq!(ms[0].tenant, "t1");
    assert_eq!(ms[0].host, "d1");
    assert_eq!(
        ds[0].stub.calls().last().unwrap(),
        "GET /v1/machines?tenant=t1",
        "the query is passed on"
    );
    assert_eq!(ds[1].stub.calls().len(), d2_before, "d2 was not asked");
    // Its own host down: the tenant's listing fails, nothing else is asked.
    let (s, _, body) = call(&f.st, "GET", "/v1/machines?tenant=t2", "api", None).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    // A tenant the fleet has not pinned: every host, so the answer is still whole.
    set_state(&f.st, "d2", "ready");
    let (s, _, body) = call(&f.st, "GET", "/v1/machines?tenant=t3", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(json(&body).as_array().unwrap().len(), 0);
    assert_eq!(
        ds[1].stub.calls().last().unwrap(),
        "GET /v1/machines?tenant=t3"
    );
}

#[tokio::test]
async fn a_machine_on_a_down_host_answers_503() {
    let (f, ds) = fleet_with_daemons(1).await;
    let m = ds[0].stub.add("t1", "web", 512);
    f.st.reg
        .lock()
        .unwrap()
        .machines
        .insert(m.id.clone(), "d1".into());
    set_state(&f.st, "d1", "down");
    let before = ds[0].stub.calls().len();
    for (method, path) in [
        ("GET", format!("/v1/machines/{}", m.id)),
        ("POST", format!("/v1/machines/{}/stop", m.id)),
        ("DELETE", format!("/v1/machines/{}", m.id)),
    ] {
        let (s, _, body) = call(&f.st, method, &path, "api", None).await;
        assert_eq!(
            s,
            StatusCode::SERVICE_UNAVAILABLE,
            "{method} {path}: {body}"
        );
        let v = json(&body);
        assert_eq!(v["code"], "host_down");
        assert!(
            v["error"].as_str().unwrap().contains("host d1 is down"),
            "{v}"
        );
    }
    assert_eq!(ds[0].stub.calls().len(), before, "the host was not asked");
    assert_eq!(
        f.st.reg
            .lock()
            .unwrap()
            .machines
            .get(&m.id)
            .map(String::as_str),
        Some("d1"),
        "a failed delete keeps the index entry"
    );
}

#[tokio::test]
async fn backups_are_listed_from_any_host_that_is_up() {
    let (f, ds) = fleet_with_daemons(2).await;
    // A machine nobody has: the store is shared, so any ready host answers.
    let (s, _, body) = call(&f.st, "GET", "/v1/machines/m_gone/backups", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(json(&body), serde_json::json!([]));
    let asked: usize = ds
        .iter()
        .map(|d| {
            d.stub
                .calls()
                .iter()
                .filter(|c| c.contains("backups"))
                .count()
        })
        .sum();
    assert_eq!(asked, 1, "one host asked, the first that answered");
    // The host that holds the machine is the one asked; down, nothing else is tried.
    let m = ds[0].stub.add("t1", "web", 512);
    f.st.reg
        .lock()
        .unwrap()
        .machines
        .insert(m.id.clone(), "d1".into());
    set_state(&f.st, "d1", "down");
    let before = ds[0].stub.calls().len();
    let (s, _, body) = call(
        &f.st,
        "GET",
        &format!("/v1/machines/{}/backups", m.id),
        "api",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(ds[0].stub.calls().len(), before, "a down host is not asked");
}

#[tokio::test]
async fn deleting_a_tenant_unpins_it() {
    let (f, ds) = fleet_with_daemons(2).await;
    ds[0].stub.add("t1", "web", 512);
    ds[0].stub.add("kept", "db", 512);
    poll_static_hosts_once(&f.st).await;
    let (s, _, body) = call(&f.st, "DELETE", "/v1/tenants/t1", "api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(ds[0].stub.calls().last().unwrap(), "DELETE /v1/tenants/t1");
    assert_eq!(f.st.reg.lock().unwrap().tenants.get("t1"), None);
    // The host refused: the pin stays.
    let (s, _, body) = call(&f.st, "DELETE", "/v1/tenants/kept", "api", None).await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        json(&body)["code"],
        "busy",
        "the host's answer passes through"
    );
    assert_eq!(
        f.st.reg
            .lock()
            .unwrap()
            .tenants
            .get("kept")
            .map(String::as_str),
        Some("d1")
    );
    // A tenant the fleet never placed: nothing to do, no host asked.
    let before: Vec<usize> = ds.iter().map(|d| d.stub.calls().len()).collect();
    let (s, _, _) = call(&f.st, "DELETE", "/v1/tenants/nobody", "api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let after: Vec<usize> = ds.iter().map(|d| d.stub.calls().len()).collect();
    assert_eq!(before, after);
}

#[tokio::test]
async fn endpoints_are_gathered_and_found_across_hosts() {
    let (f, ds) = fleet_with_daemons(2).await;
    let (s, _, body) = call(&f.st, "GET", "/v1/endpoints", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let eps: Vec<api::Endpoint> = serde_json::from_str(&body).unwrap();
    let ids: Vec<&str> = eps.iter().map(|e| e.id.as_str()).collect();
    assert_eq!(ids, ["ep_d1", "ep_d2"]);
    // An endpoint call goes to the first host that does not answer 404.
    let (s, headers, _) = call(&f.st, "DELETE", "/v1/endpoints/ep_d2", "api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(headers["x-briqyard-host"], "d2");
    assert_eq!(
        ds[0].stub.calls().last().unwrap(),
        "DELETE /v1/endpoints/ep_d2"
    );
    let (s, _, body) = call(&f.st, "DELETE", "/v1/endpoints/ep_x", "api", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(json(&body)["error"], "endpoint ep_x not found");
}
