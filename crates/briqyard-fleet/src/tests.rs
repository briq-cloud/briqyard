//! The HTTP handlers, driven in process through the router. Hosts are stub daemons on
//! loopback: they answer the few routes the fleet asks and record what was asked.

use super::*;
use axum::body::Body;
use chrono::TimeZone;
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

// --- a stub daemon ---

/// What a stub daemon hands out, like the fleet's capacity figure for it.
const DAEMON_MEMORY_MB: u32 = 64_000;

struct Daemon {
    id: String,
    token: String,
    calls: Mutex<Vec<String>>,
    machines: Mutex<Vec<api::Machine>>,
    endpoints: Mutex<Vec<api::Endpoint>>,
    /// Tenants' gateways: the tenant and the memory it takes.
    gateways: Mutex<Vec<(String, u32)>>,
    next: AtomicUsize,
    /// A tenant the daemon refuses to delete (answers 409), to test a failed forward.
    keep_tenant: String,
    /// Its event log, and the `If-Match` of each request that had one.
    events: Mutex<Vec<api::Event>>,
    if_match: Mutex<Vec<String>>,
    /// The open watch's sender: a test sends its live lines.
    watcher: Mutex<Option<tokio::sync::mpsc::Sender<String>>>,
    /// Its certificate's, when it serves TLS.
    tls_fingerprint: String,
    /// What its status reports (ADR 0021).
    conditions: Mutex<Vec<api::Condition>>,
    /// Tenants' quotas (ADR 0025).
    quotas: Mutex<Vec<(String, api::Quota)>>,
    /// Run by a create before it answers: a test's look at the fleet mid-forward.
    on_create: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
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

    /// Adds an endpoint as if it had been opened on this daemon.
    fn add_endpoint(&self, machine_id: &str) -> api::Endpoint {
        let n = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        let e = api::Endpoint {
            id: format!("ep_{}_{n}", self.id),
            machine_id: machine_id.into(),
            port: 80,
            protocol: "tcp".into(),
            host_port: Some(30000 + n as u16),
            host: String::new(),
            address: format!("127.0.0.1:{}", 30000 + n),
            created_at: Utc::now(),
        };
        self.endpoints.lock().unwrap().push(e.clone());
        e
    }

    /// Logs an event at `at` (seconds past 14:00), about a machine of a tenant.
    fn log(&self, at: u32, tenant: &str, reason: &str) -> api::Event {
        let mut evs = self.events.lock().unwrap();
        let e = api::Event {
            seq: evs.len() as u64 + 1,
            at: Utc.with_ymd_and_hms(2026, 10, 20, 14, 0, 0).unwrap()
                + Duration::seconds(at as i64),
            kind: api::event::NORMAL.into(),
            reason: reason.into(),
            message: String::new(),
            machine_id: format!("m_{}_{}", self.id, evs.len() + 1),
            tenant: tenant.into(),
            host: String::new(),
            data: None,
            count: 1,
            first_at: None,
        };
        evs.push(e.clone());
        e
    }

    fn used_mb(&self) -> u32 {
        self.machines
            .lock()
            .unwrap()
            .iter()
            .map(|m| m.size.memory_mb)
            .sum()
    }
}

/// A daemon on loopback: its URL and the stub behind it.
struct Running {
    url: String,
    stub: Arc<Daemon>,
}

async fn start_daemon(id: &str, token: &str) -> Running {
    start_daemon_on(id, token, None).await
}

/// A stub daemon serving TLS with `cert` when given, as a daemon off loopback does.
async fn start_daemon_on(id: &str, token: &str, cert: Option<&rcgen::CertifiedKey>) -> Running {
    let stub = Arc::new(Daemon {
        id: id.into(),
        token: token.into(),
        calls: Mutex::new(vec![]),
        machines: Mutex::new(vec![]),
        endpoints: Mutex::new(vec![]),
        gateways: Mutex::new(vec![]),
        next: AtomicUsize::new(0),
        keep_tenant: "kept".into(),
        events: Mutex::new(vec![]),
        if_match: Mutex::new(vec![]),
        watcher: Mutex::new(None),
        tls_fingerprint: cert
            .map(|c| api::tls::fingerprint(c.cert.der()))
            .unwrap_or_default(),
        conditions: Mutex::new(vec![]),
        quotas: Mutex::new(vec![]),
        on_create: Mutex::new(None),
    });
    type D = State<Arc<Daemon>>;
    async fn status(State(d): D) -> Json<api::Status> {
        let ms = d.machines.lock().unwrap();
        Json(api::Status {
            version: "0.1-stub".into(),
            host_id: d.id.clone(),
            capacity: api::Capacity {
                memory_mb: DAEMON_MEMORY_MB,
                vcpus: 32,
            },
            used: api::Capacity {
                memory_mb: ms.iter().map(|m| m.size.memory_mb).sum(),
                vcpus: ms.len() as u32,
            },
            machines: ms.len(),
            running: ms.len(),
            disk_free_mb: 100_000,
            tls_fingerprint: d.tls_fingerprint.clone(),
            conditions: d.conditions.lock().unwrap().clone(),
            started: Default::default(),
            vmm_version: String::new(),
            regions: Vec::new(),
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
                    router: "10.1.0.1".into(),
                    machines: 1,
                    created_at: Utc::now(),
                    host: String::new(),
                    region: String::new(),
                    gateway: None,
                })
                .collect(),
        )
    }
    fn tenant_of(d: &Daemon, id: &str) -> Option<api::Tenant> {
        let machines = d.machines.lock().unwrap();
        let gateway = d.gateways.lock().unwrap().iter().any(|(t, _)| t == id);
        let n = machines.iter().filter(|m| m.tenant == id).count();
        (gateway || n > 0).then(|| api::Tenant {
            id: id.into(),
            subnet: "10.1.0.0/24".into(),
            router: "10.1.0.1".into(),
            machines: n,
            created_at: Utc::now(),
            host: String::new(),
            region: String::new(),
            gateway: gateway.then(|| api::GatewayView {
                state: api::state::CREATED.into(),
                ip: "10.1.0.2".into(),
                port: 3128,
                machine_id: format!("m_{}_gw", d.id),
                error: String::new(),
            }),
        })
    }
    async fn get_tenant(State(d): D, Path(id): Path<String>) -> Response {
        match tenant_of(&d, &id) {
            Some(t) => Json(t).into_response(),
            None => err(StatusCode::NOT_FOUND, "not_found", "tenant not found").into_response(),
        }
    }
    /// Like the daemon: a gateway that does not fit in what the host has left is refused.
    async fn set_gateway(
        State(d): D,
        Path(id): Path<String>,
        Json(spec): Json<api::GatewaySpec>,
    ) -> Response {
        let need = spec.size().memory_mb;
        if d.used_mb() + need > DAEMON_MEMORY_MB {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "capacity",
                "the host has no room",
            )
            .into_response();
        }
        d.gateways.lock().unwrap().push((id.clone(), need));
        Json(tenant_of(&d, &id).unwrap()).into_response()
    }
    async fn delete_gateway(State(d): D, Path(id): Path<String>) -> Response {
        if id == d.keep_tenant {
            return err(StatusCode::CONFLICT, "gateway_in_use", "in use").into_response();
        }
        d.gateways.lock().unwrap().retain(|(t, _)| *t != id);
        StatusCode::NO_CONTENT.into_response()
    }
    async fn delete_tenant(State(d): D, Path(id): Path<String>) -> Response {
        if id == d.keep_tenant {
            return err(StatusCode::CONFLICT, "busy", "tenant has machines").into_response();
        }
        d.machines.lock().unwrap().retain(|m| m.tenant != id);
        StatusCode::NO_CONTENT.into_response()
    }
    /// Like the daemon: a tenant's or every machine, those every `label` selects.
    async fn list(State(d): D, uri: Uri) -> Json<Vec<api::Machine>> {
        let url = reqwest::Url::parse(&format!("http://stub{uri}")).unwrap();
        let mut tenant = None;
        let mut labels = vec![];
        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                "tenant" => tenant = Some(v.into_owned()),
                "label" => labels.push(api::Label::parse(&v).unwrap()),
                _ => {}
            }
        }
        let ms = d.machines.lock().unwrap();
        Json(
            ms.iter()
                .filter(|m| tenant.as_deref().map(|t| t == m.tenant).unwrap_or(true))
                .filter(|m| labels.iter().all(|l| l.matches(&m.metadata)))
                .cloned()
                .collect(),
        )
    }
    async fn put_quota(
        State(d): D,
        Path(id): Path<String>,
        Json(q): Json<api::Quota>,
    ) -> Json<api::TenantQuota> {
        d.quotas.lock().unwrap().push((id.clone(), q));
        Json(api::TenantQuota {
            tenant: id,
            quota: q,
            used: Default::default(),
        })
    }
    async fn get_quota(State(d): D, Path(id): Path<String>) -> Response {
        let qs = d.quotas.lock().unwrap();
        match qs.iter().rev().find(|(t, _)| *t == id) {
            Some((t, q)) => Json(api::TenantQuota {
                tenant: t.clone(),
                quota: *q,
                used: Default::default(),
            })
            .into_response(),
            None => err(StatusCode::NOT_FOUND, "not_found", "tenant not found").into_response(),
        }
    }
    /// A follow (ADR 0025): NDJSON kept open, what the test sends through `watcher`.
    async fn logs(State(d): D) -> Response {
        let (tx, rx) = tokio::sync::mpsc::channel::<String>(16);
        *d.watcher.lock().unwrap() = Some(tx);
        let lines = futures::stream::unfold(rx, |mut rx| async move {
            rx.recv()
                .await
                .map(|l| (Ok::<_, std::convert::Infallible>(l), rx))
        });
        (
            [(header::CONTENT_TYPE, "application/x-ndjson")],
            Body::from_stream(lines),
        )
            .into_response()
    }
    /// A session (ADR 0029) as the daemon serves one, reduced: its stdin back on stdout until
    /// stdin closes, then an exit of 7. A machine not running is refused before the upgrade.
    async fn exec_session(
        State(d): D,
        Path(id): Path<String>,
        ws: axum::extract::ws::WebSocketUpgrade,
    ) -> Response {
        use api::session::{channel, message, parse};
        use axum::extract::ws::Message;
        let running = d
            .machines
            .lock()
            .unwrap()
            .iter()
            .any(|m| m.id == id && m.state == api::state::RUNNING);
        if !running {
            return err(
                StatusCode::CONFLICT,
                "not_running",
                "machine is not running: stopped",
            )
            .into_response();
        }
        ws.on_upgrade(|mut socket| async move {
            while let Some(Ok(Message::Binary(b))) = socket.recv().await {
                let reply = match parse(&b) {
                    Some((channel::STDIN, p)) => message(channel::STDOUT, p),
                    Some((channel::CLOSE, _)) => message(channel::EXIT, br#"{"exit_code":7}"#),
                    _ => continue,
                };
                let last = reply[0] == channel::EXIT;
                if socket.send(Message::Binary(reply)).await.is_err() || last {
                    break;
                }
            }
        })
    }
    /// Like the daemon: a bad name is refused, and a machine that does not fit in what the
    /// host has left.
    async fn create(State(d): D, Json(req): Json<api::CreateMachineRequest>) -> Response {
        if !api::valid_name(&req.name) {
            return err(StatusCode::BAD_REQUEST, "invalid", "name").into_response();
        }
        if d.used_mb() + req.size.memory_mb > DAEMON_MEMORY_MB {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "capacity",
                "the host has no room",
            )
            .into_response();
        }
        if let Some(f) = d.on_create.lock().unwrap().as_ref() {
            f();
        }
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
                    oldest: None,
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
    /// The backups of the daemon's machines, destroyed ones' included: one of a machine named
    /// after the daemon.
    async fn all_backups(State(d): D) -> Json<Vec<serde_json::Value>> {
        Json(vec![serde_json::json!({
            "id": "20261021T101500.123Z", "machine_id": format!("m_{}", d.id), "tenant": "t1",
            "name": "db", "created_at": "2026-10-21T10:15:00Z", "bytes": 1,
            "incremental": false, "disks": []
        })])
    }
    async fn delete_backup() -> StatusCode {
        StatusCode::NO_CONTENT
    }
    async fn add_endpoint(State(d): D, Path(id): Path<String>) -> Response {
        if !d.machines.lock().unwrap().iter().any(|m| m.id == id) {
            return StatusCode::NOT_FOUND.into_response();
        }
        (StatusCode::CREATED, Json(d.add_endpoint(&id))).into_response()
    }
    async fn endpoints(State(d): D) -> Json<Vec<api::Endpoint>> {
        Json(d.endpoints.lock().unwrap().clone())
    }
    async fn get_endpoint(State(d): D, Path(id): Path<String>) -> Response {
        let eps = d.endpoints.lock().unwrap();
        match eps.iter().find(|e| e.id == id) {
            Some(e) => Json(e.clone()).into_response(),
            None => err(StatusCode::NOT_FOUND, "not_found", "endpoint not found").into_response(),
        }
    }
    async fn delete_endpoint(State(d): D, Path(id): Path<String>) -> StatusCode {
        let mut eps = d.endpoints.lock().unwrap();
        let before = eps.len();
        eps.retain(|e| e.id != id);
        if eps.len() == before {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::NO_CONTENT
        }
    }
    /// A line per machine, the tenant's when asked, as the daemon's top.
    async fn top(
        State(d): D,
        Query(q): Query<HashMap<String, String>>,
    ) -> Json<Vec<api::TopMachine>> {
        let ms = d.machines.lock().unwrap();
        Json(
            ms.iter()
                .filter(|m| q.get("tenant").is_none_or(|t| *t == m.tenant))
                .map(|m| api::TopMachine {
                    machine_id: m.id.clone(),
                    tenant: m.tenant.clone(),
                    name: m.name.clone(),
                    cpu_percent: 1.5,
                    window_sec: 15.0,
                    ..Default::default()
                })
                .collect(),
        )
    }
    /// One closed bucket of a machine named after the daemon; a range the daemon would refuse
    /// (no `from`) is refused here too.
    async fn usage(State(d): D, uri: Uri) -> Response {
        if !uri.query().unwrap_or("").contains("from=") {
            return err(StatusCode::BAD_REQUEST, "invalid", "from is required").into_response();
        }
        Json(vec![api::UsageBucket {
            hour: "2026-10-20T14:00:00Z".parse().unwrap(),
            machine_id: format!("m_{}", d.id),
            tenant: "t1".into(),
            closed: true,
            ..Default::default()
        }])
        .into_response()
    }
    /// The daemon's read, with its cursor rules: the events after `since` that match, up to
    /// `limit`; `next` the last returned when the page is full, else the last seq. With
    /// `watch`, NDJSON kept open: the backlog, then what the test sends.
    async fn events(State(d): D, Query(q): Query<EventsQuery>) -> Response {
        let since: u64 = q.since.as_deref().unwrap_or("0").parse().unwrap_or(0);
        let limit = api::events_limit(q.limit);
        let evs = d.events.lock().unwrap().clone();
        let last = evs.last().map_or(0, |e| e.seq);
        if since > last {
            return err(StatusCode::GONE, "gone", "past the last event").into_response();
        }
        let mut page: Vec<api::Event> = evs
            .into_iter()
            .filter(|e| e.seq > since)
            .filter(|e| q.tenant.as_deref().is_none_or(|t| t == e.tenant))
            .filter(|e| q.machine.as_deref().is_none_or(|m| m == e.machine_id))
            .collect();
        page.truncate(limit);
        if q.watch {
            let (tx, rx) = tokio::sync::mpsc::channel::<String>(16);
            for e in &page {
                tx.try_send(serde_json::to_string(e).unwrap() + "\n")
                    .unwrap();
            }
            *d.watcher.lock().unwrap() = Some(tx);
            let lines = futures::stream::unfold(rx, |mut rx| async move {
                rx.recv()
                    .await
                    .map(|l| (Ok::<_, std::convert::Infallible>(l), rx))
            });
            return (
                [(header::CONTENT_TYPE, "application/x-ndjson")],
                Body::from_stream(lines),
            )
                .into_response();
        }
        let next = match page.len() == limit {
            true => page.last().map_or(last, |e| e.seq),
            false => last,
        };
        Json(api::EventsPage {
            events: page,
            next: next.to_string(),
        })
        .into_response()
    }
    // Every request is recorded, with its query, and checked for the daemon's token.
    async fn record(State(d): D, req: Request, next: axum::middleware::Next) -> Response {
        let line = format!(
            "{} {}",
            req.method(),
            req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("")
        );
        d.calls.lock().unwrap().push(line);
        if let Some(v) = req.headers().get(header::IF_MATCH) {
            d.if_match
                .lock()
                .unwrap()
                .push(v.to_str().unwrap().to_string());
        }
        if !d.token.is_empty() && bearer(req.headers()) != d.token {
            return err(StatusCode::UNAUTHORIZED, "unauthorized", "bad token").into_response();
        }
        next.run(req).await
    }
    let app = Router::new()
        .route("/v1/status", get(status))
        .route("/v1/tenants", get(tenants))
        .route("/v1/tenants/:id", get(get_tenant).delete(delete_tenant))
        .route(
            "/v1/tenants/:id/gateway",
            axum::routing::put(set_gateway).delete(delete_gateway),
        )
        .route("/v1/machines", get(list).post(create))
        .route("/v1/machines/:id", get(get_machine).delete(delete_machine))
        .route("/v1/machines/:id/start", post(start_machine))
        .route("/v1/machines/:id/logs", get(logs))
        .route("/v1/machines/:id/exec", get(exec_session))
        .route("/v1/tenants/:id/quota", get(get_quota).put(put_quota))
        .route("/v1/machines/:id/backups", get(backups))
        .route(
            "/v1/machines/:id/backups/:backup",
            axum::routing::delete(delete_backup),
        )
        .route("/v1/backups", get(all_backups))
        .route("/v1/machines/:id/endpoints", post(add_endpoint))
        .route("/v1/endpoints", get(endpoints))
        .route("/v1/usage", get(usage))
        .route("/v1/top", get(top))
        .route("/v1/events", get(events))
        .route(
            "/v1/endpoints/:id",
            get(get_endpoint).delete(delete_endpoint),
        )
        .layer(axum::middleware::from_fn_with_state(stub.clone(), record))
        .with_state(stub.clone());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let app = app.into_make_service();
    let url = match cert {
        None => {
            tokio::spawn(axum_server::from_tcp(listener).serve(app));
            format!("http://{addr}")
        }
        Some(c) => {
            let cfg = api::tls::server_config(
                c.cert.pem().as_bytes(),
                c.key_pair.serialize_pem().as_bytes(),
            )
            .unwrap();
            let cfg = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(cfg));
            tokio::spawn(axum_server::from_tcp_rustls(listener, cfg).serve(app));
            format!("https://{addr}")
        }
    };
    Running { url, stub }
}

// --- the fleet under test ---

struct Fleet {
    st: Arc<AppState>,
    _dir: tempfile::TempDir,
}

/// A fleet on a fresh state directory, with the hosts of the configuration seeded as `run` does.
fn fleet(cfg: config::Config) -> Fleet {
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("registry.json");
    fleet_at(cfg, dir, state_path)
}

fn fleet_at(mut cfg: config::Config, dir: tempfile::TempDir, state_path: PathBuf) -> Fleet {
    cfg.state_dir = dir.path().to_path_buf();
    let backup = backup::Backup::open(&cfg.backup).unwrap();
    let mut reg = Registry::default();
    let now = Utc::now();
    for h in &cfg.hosts {
        reg.heartbeat(static_host(h, now), now);
    }
    let st = Arc::new(AppState {
        state_path,
        policy: Policy {
            fill_ceiling: cfg.placement.fill_ceiling,
            down_after: Duration::seconds(cfg.placement.down_after_sec as i64),
        },
        cfg,
        reg: Mutex::new(reg),
        // A stub daemon that never answers fails its test rather than holding it forever.
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap(),
        pinned: Mutex::new(HashMap::new()),
        upgrade: Default::default(),
        backup,
        key_turn: Default::default(),
        restores: Default::default(),
        refusals: Default::default(),
        written: Default::default(),
    });
    Fleet { st, _dir: dir }
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
    fleet_in_regions(&vec!["fsn"; n]).await
}

/// A fleet in front of a stub daemon in each region given, `d1` in the first.
async fn fleet_in_regions(regions: &[&str]) -> (Fleet, Vec<Running>) {
    let mut daemons = Vec::new();
    let mut cfg = config::Config {
        token: "api".into(),
        ..Default::default()
    };
    for (i, region) in (1..).zip(regions) {
        let d = start_daemon(&format!("d{i}"), &format!("tok-{i}")).await;
        cfg.hosts.push(config::StaticHost {
            id: format!("d{i}"),
            url: d.url.clone(),
            token: format!("tok-{i}"),
            region: region.to_string(),
            ..Default::default()
        });
        daemons.push(d);
    }
    let f = fleet(cfg);
    poll_static_hosts_once(&f.st).await;
    (f, daemons)
}

/// One request through the router. The body comes back as text.
/// A call as a client makes it. A host's own call (a body with a `url`) comes from that url's
/// address, as it does through a fleet that terminates its connections; anything else from
/// loopback.
async fn call(
    st: &Arc<AppState>,
    method: &str,
    path: &str,
    token: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, HeaderMap, String) {
    let peer = body
        .as_ref()
        .and_then(|b| b["url"].as_str())
        .and_then(|u| url_host(u).parse().ok())
        .unwrap_or(std::net::IpAddr::from([127, 0, 0, 1]));
    call_from(st, peer, method, path, token, body).await
}

/// `call` from the peer address given.
async fn call_from(
    st: &Arc<AppState>,
    peer: std::net::IpAddr,
    method: &str,
    path: &str,
    token: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, HeaderMap, String) {
    call_with(st, peer, &[], method, path, token, body).await
}

/// `call_from` with request headers of its own (a proxy's `X-Forwarded-For`).
async fn call_with(
    st: &Arc<AppState>,
    peer: std::net::IpAddr,
    extra: &[(&str, &str)],
    method: &str,
    path: &str,
    token: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, HeaderMap, String) {
    let mut req = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::new(
            peer, 40000,
        )));
    for (k, v) in extra {
        req = req.header(*k, *v);
    }
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

fn saved(st: &AppState) -> Registry {
    serde_json::from_slice(&std::fs::read(&st.state_path).unwrap()).unwrap()
}

fn pinned(st: &AppState, tenant: &str) -> Option<String> {
    st.reg.lock().unwrap().tenants.get(tenant).cloned()
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

/// A daemon's heartbeat body for `url`.
fn heartbeat(url: &str, memory_mb: u32, tenants: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "id": "h_daemon", "url": url, "region": "par",
        "capacity": {"memory_mb": memory_mb, "vcpus": 32}, "used": {"memory_mb": 512, "vcpus": 1},
        "machines": tenants.len(), "tenants": tenants, "version": "0.1", "disk_free_mb": 5000
    })
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
    assert_eq!(
        error_code(br#"{"error":"full","code":"capacity"}"#),
        "capacity"
    );
    assert_eq!(error_code(b"[]"), "");
}

// --- auth, status, hosts ---

#[tokio::test]
async fn a_bearer_token_guards_every_route_but_healthz_and_register() {
    let f = fleet(config::Config {
        token: "api".into(),
        ..Default::default()
    });
    let (s, _, body) = call(&f.st, "GET", "/healthz", "", None).await;
    assert_eq!((s, body.as_str()), (StatusCode::OK, "ok\n"));
    let (s, _, body) = call(&f.st, "GET", "/v1/status", "", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(json(&body)["code"], "unauthorized");
    let (s, _, _) = call(&f.st, "GET", "/v1/status", "wrong", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _, _) = call(&f.st, "GET", "/v1/status", "api", None).await;
    assert_eq!(s, StatusCode::OK);
    // The register route is checked against the host's own token, not the API's: with the
    // API token it gets as far as the handler, which knows no host at that address.
    let hb = heartbeat("http://10.0.0.1:7420", 1000, &[]);
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/register", "api", Some(hb)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(json(&body)["code"], "unknown_host");

    // No token configured: nothing is asked of API clients.
    let open = fleet(config::Config::default());
    let (s, _, _) = call(&open.st, "GET", "/v1/hosts", "", None).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn a_registration_is_taken_only_for_the_host_that_expects_it() {
    let f = fleet(config::Config {
        token: "api".into(),
        hosts: vec![
            config::StaticHost {
                id: "s1".into(),
                url: "http://10.0.0.1:7420".into(),
                token: "s1-token".into(),
                region: "fsn".into(),
                ..Default::default()
            },
            config::StaticHost {
                id: "open".into(),
                url: "http://10.0.0.2:7420".into(),
                ..Default::default()
            },
        ],
        ..Default::default()
    });
    // An address no record expects: refused whatever it presents.
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/hosts/register",
        "s1-token",
        Some(heartbeat("http://10.0.0.9:7420", 1000, &[])),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
    let v = json(&body);
    assert_eq!(v["code"], "unknown_host");
    assert!(v["error"].as_str().unwrap().contains("10.0.0.9"), "{v}");
    assert_eq!(hosts(&f.st).len(), 2, "nothing was added");
    // The expected address with another host's token, the API token, or none: refused.
    for token in ["", "api", "wrong", "s1-toke"] {
        let (s, _, body) = call(
            &f.st,
            "POST",
            "/v1/hosts/register",
            token,
            Some(heartbeat("http://10.0.0.1:7420", 1000, &[])),
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "token {token:?}: {body}");
        assert_eq!(json(&body)["code"], "unauthorized");
    }
    assert_eq!(hosts(&f.st)[1].capacity.memory_mb, 0, "nothing was taken");
    // A host listed without a token is polled only: no token opens its registration.
    let (s, _, _) = call(
        &f.st,
        "POST",
        "/v1/hosts/register",
        "",
        Some(heartbeat("http://10.0.0.2:7420", 1000, &[])),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // Its own token: taken, under the id the fleet knows it by, whatever the daemon calls itself.
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/hosts/register",
        "s1-token",
        Some(heartbeat("http://10.0.0.1:7420", 64_000, &["t1"])),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    let hs = hosts(&f.st);
    assert_eq!(hs.len(), 2);
    assert_eq!(hs[1].id, "s1");
    assert_eq!(hs[1].capacity.memory_mb, 64_000);
    assert_eq!(hs[1].region, "par");
    assert_eq!(hs[1].tenants, ["t1"]);
    assert_eq!(pinned(&f.st, "t1").as_deref(), Some("s1"));
    assert_eq!(
        f.st.reg.lock().unwrap().hosts["s1"].token,
        "s1-token",
        "a heartbeat never changes a token"
    );
    assert!(
        saved(&f.st).hosts["s1"].capacity.memory_mb == 64_000,
        "written"
    );
}

/// A host's pool key (ADR 0026): made at its first ask and the same after, served to the host
/// at its address with its own token and to nobody else, written (`0600`) before it is
/// answered, in no listing, and no longer the host's once its record is forgotten.
#[tokio::test]
async fn a_host_gets_its_own_pool_key_and_no_other() {
    let host = |id: &str, n: u8| config::StaticHost {
        id: id.into(),
        url: format!("http://10.0.0.{n}:7420"),
        token: format!("{id}-token"),
        ..Default::default()
    };
    let f = fleet(config::Config {
        token: "api".into(),
        hosts: vec![host("s1", 1), host("s2", 2)],
        ..Default::default()
    });
    let ask = |n: u8| Some(serde_json::json!({ "url": format!("http://10.0.0.{n}:7420") }));
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s1-token", ask(9)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(json(&body)["code"], "unknown_host");
    for token in ["", "api", "s2-token"] {
        let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", token, ask(1)).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "token {token:?}: {body}");
    }
    assert!(
        f.st.reg.lock().unwrap().hosts["s1"].pool_key.is_empty(),
        "nothing made for a refused ask"
    );

    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s1-token", ask(1)).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let key = json(&body)["key"].as_str().unwrap().to_string();
    assert!(
        key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()),
        "ZFS's hex format: {key}"
    );
    assert_eq!(saved(&f.st).hosts["s1"].pool_key.expose(), key, "written");
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&f.st.state_path)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "the registry is the fleet's alone");
    let (_, _, again) = call(&f.st, "POST", "/v1/hosts/key", "s1-token", ask(1)).await;
    assert_eq!(json(&again)["key"], key.as_str(), "the same key every time");
    let (_, _, other) = call(&f.st, "POST", "/v1/hosts/key", "s2-token", ask(2)).await;
    assert_ne!(json(&other)["key"], key.as_str(), "one key per host");

    let (_, _, listed) = call(&f.st, "GET", "/v1/hosts", "api", None).await;
    assert!(!listed.contains(&key), "never listed: {listed}");
    let (s, _, _) = call(&f.st, "DELETE", "/v1/hosts/s1?force=true", "api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s1-token", ask(1)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
    assert!(!body.contains(&key));
}

/// A backup's key (ADR 0035): the key of a backup's `key_id`, a live host's or a forgotten
/// one's (kept as a retired key), served to the host the fleet forwarded a restore to, for
/// that restore, once; refused with no restore open, and never made for the ask.
#[tokio::test]
async fn a_host_gets_the_key_of_a_backup_for_a_restore_it_was_given() {
    let host = |id: &str, n: u8| config::StaticHost {
        id: id.into(),
        url: format!("http://10.0.0.{n}:7420"),
        token: format!("{id}-token"),
        ..Default::default()
    };
    let f = fleet(config::Config {
        token: "api".into(),
        hosts: vec![host("s1", 1), host("s2", 2)],
        ..Default::default()
    });
    let rs = api::RestoreSpec {
        machine_id: "m_src".into(),
        backup: "b1".into(),
    };
    let ask = |n: u8, id: &str| {
        Some(serde_json::json!({
            "url": format!("http://10.0.0.{n}:7420"),
            "key_id": id,
            "restore": { "machine_id": "m_src", "backup": "b1" },
        }))
    };
    let opened = |host: &str| {
        f.st.restores.open(host, &rs, std::time::Instant::now());
    };
    let own = Some(serde_json::json!({ "url": "http://10.0.0.1:7420" }));
    let (_, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s1-token", own).await;
    let k1 = json(&body)["key"].as_str().unwrap().to_string();
    let id1 = briqyard_api::poolkey::id(&k1).unwrap();

    // Its own, by id: served without a restore, as without the id (ADR 0045).
    let mine = Some(serde_json::json!({ "url": "http://10.0.0.1:7420", "key_id": id1 }));
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s1-token", mine).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(json(&body)["key"], k1.as_str());
    // No restore forwarded to s2: refused, with or without one named.
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s2-token", ask(2, &id1)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(json(&body)["code"], "no_restore");
    let bare = Some(serde_json::json!({ "url": "http://10.0.0.2:7420", "key_id": id1 }));
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/key", "s2-token", bare).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // One forwarded to s2: served to s2 once. s1's ask for its own key leaves it open.
    opened("s2");
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s1-token", ask(1, &id1)).await;
    assert_eq!(s, StatusCode::OK, "its own: {body}");
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s2-token", ask(2, &id1)).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(
        json(&body)["key"],
        k1.as_str(),
        "s1's key, for s2's restore"
    );
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/key", "s2-token", ask(2, &id1)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "served once");
    assert!(
        f.st.reg.lock().unwrap().hosts["s2"].pool_key.is_empty(),
        "no key made for s2 by an ask for another's"
    );
    opened("s2");
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/hosts/key",
        "s2-token",
        ask(2, &"0".repeat(32)),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(json(&body)["code"], "no_key");
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/key", "api", ask(2, &id1)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "a host's token only");
    // Neither refusal took the restore: it is the last check.

    // s1 forgotten: its key stays, for its backups, and for nothing else.
    let (s, _, _) = call(&f.st, "DELETE", "/v1/hosts/s1?force=true", "api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s2-token", ask(2, &id1)).await;
    assert_eq!(
        s,
        StatusCode::OK,
        "the restore opened before the 404, still open: {body}"
    );
    assert_eq!(json(&body)["key"], k1.as_str());
    let retired = &saved(&f.st).retired_keys;
    assert_eq!(retired.len(), 1);
    assert_eq!(
        (retired[0].host.as_str(), retired[0].key.expose()),
        ("s1", k1.as_str())
    );
}

/// A restore says what the fleet will trust once started on it, never a token or a key.
#[test]
fn a_restore_says_what_the_fleet_will_trust() {
    let mut reg = Registry::default();
    let mut h = static_host(
        &config::StaticHost {
            id: "h1".into(),
            url: "https://10.0.0.1:7420".into(),
            token: "h1-token".into(),
            ..Default::default()
        },
        Utc.with_ymd_and_hms(2026, 10, 21, 12, 0, 0).unwrap(),
    );
    h.tls_fingerprint = "ab".repeat(32);
    reg.hosts.insert("h1".into(), h);
    let (key, _) = reg.pool_key("h1").unwrap();
    let out = restored(
        &reg,
        "file:///b fleet/registry.json.age",
        std::path::Path::new("/s/registry.json"),
    );
    assert!(out.starts_with("restored 1 hosts (1 pool keys, 0 retired) and 0 tenants from file:///b fleet/registry.json.age into /s/registry.json\n"), "{out}");
    assert!(
        out.contains("newest heartbeat in it: 2026-10-21T12:00:00+00:00"),
        "{out}"
    );
    assert!(
        out.contains("  h1  https://10.0.0.1:7420  pin abababababababab…  token  pool key\n"),
        "{out}"
    );
    assert!(
        !out.contains("h1-token") && !out.contains(key.expose()),
        "{out}"
    );
}

/// With a backup, a pool key is handed out only once the store holds it (ADR 0032): a store
/// that refuses the write refuses the key, and the backup read back holds the key served.
#[tokio::test]
async fn a_pool_key_is_in_the_backup_before_it_is_served() {
    let dir = tempfile::tempdir().unwrap();
    let identity = dir.path().join("backup.key");
    let recipient = backup::keygen(&identity).unwrap();
    let store = dir.path().join("store");
    let f = fleet(config::Config {
        hosts: vec![config::StaticHost {
            id: "s1".into(),
            url: "http://10.0.0.1:7420".into(),
            token: "s1-token".into(),
            ..Default::default()
        }],
        backup: config::Backup {
            store: format!("file://{}", store.display()),
            recipient,
            ..Default::default()
        },
        ..Default::default()
    });
    let ask = Some(serde_json::json!({ "url": "http://10.0.0.1:7420" }));
    // The store's directory turned into a file: no write can make its `fleet/`, whoever runs.
    let aside = dir.path().join("store.aside");
    std::fs::rename(&store, &aside).unwrap();
    std::fs::write(&store, b"").unwrap();
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s1-token", ask.clone()).await;
    std::fs::remove_file(&store).unwrap();
    std::fs::rename(&aside, &store).unwrap();
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(json(&body)["code"], "backup");
    assert!(
        !body.contains("\"key\"") && !body.contains("store"),
        "no key, no details: {body}"
    );
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s1-token", ask).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let key = json(&body)["key"].as_str().unwrap().to_string();
    let b = f.st.backup.as_ref().unwrap();
    let back = b
        .fetch(backup::LATEST, &backup::identity(&identity).unwrap())
        .await
        .unwrap();
    assert_eq!(back.hosts["s1"].pool_key.expose(), key);
}

/// Where the fleet terminates the connection (its TLS, or plain on loopback), a host's call
/// must come from the host's address: its token alone, read off a disk that left our hands, is
/// not enough (ADR 0026). Behind `tls: off` the peer is the proxy in front: not checked.
#[tokio::test]
async fn a_host_call_must_come_from_the_host() {
    let hosts = vec![
        config::StaticHost {
            id: "s1".into(),
            url: "http://10.0.0.1:7420".into(),
            token: "s1-token".into(),
            ..Default::default()
        },
        config::StaticHost {
            id: "named".into(),
            url: "http://host.example:7420".into(),
            token: "named-token".into(),
            ..Default::default()
        },
    ];
    let f = fleet(config::Config {
        hosts: hosts.clone(),
        ..Default::default()
    });
    let ask = |u: &str| Some(serde_json::json!({ "url": u }));
    let elsewhere = std::net::IpAddr::from([203, 0, 113, 7]);
    for path in ["/v1/hosts/key", "/v1/hosts/register"] {
        let body = if path.ends_with("key") {
            ask("http://10.0.0.1:7420")
        } else {
            Some(heartbeat("http://10.0.0.1:7420", 1000, &[]))
        };
        let (s, _, text) = call_from(&f.st, elsewhere, "POST", path, "s1-token", body).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{path}: {text}");
        assert!(
            text.contains("come from 10.0.0.1, not 203.0.113.7"),
            "{text}"
        );
    }
    assert!(f.st.reg.lock().unwrap().hosts["s1"].pool_key.is_empty());
    // A host known by a name cannot be checked by address: refused, saying so.
    let (s, _, text) = call_from(
        &f.st,
        elsewhere,
        "POST",
        "/v1/hosts/key",
        "named-token",
        ask("http://host.example:7420"),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{text}");
    assert!(text.contains("its url must be one"), "{text}");
    // An IPv4 peer seen as IPv6-mapped is the same address.
    let mapped: std::net::IpAddr = "::ffff:10.0.0.1".parse().unwrap();
    let (s, _, text) = call_from(
        &f.st,
        mapped,
        "POST",
        "/v1/hosts/key",
        "s1-token",
        ask("http://10.0.0.1:7420"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{text}");

    // tls: off on a public address: whatever is in front is unknown, the token alone.
    let behind = fleet(config::Config {
        hosts: hosts.clone(),
        listen: "0.0.0.0:7430".into(),
        tls: config::Tls::Off,
        ..Default::default()
    });
    let (s, _, text) = call_from(
        &behind.st,
        elsewhere,
        "POST",
        "/v1/hosts/key",
        "s1-token",
        ask("http://10.0.0.1:7420"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "tls: off checks the token alone: {text}");

    // tls: off on loopback: a proxy of ours in front; its last X-Forwarded-For is the caller.
    let local = fleet(config::Config {
        hosts,
        listen: "127.0.0.1:7430".into(),
        tls: config::Tls::Off,
        ..Default::default()
    });
    let proxy = std::net::IpAddr::from([127, 0, 0, 1]);
    let key = |xff: &'static [(&'static str, &'static str)]| {
        let st = local.st.clone();
        async move {
            call_with(
                &st,
                proxy,
                xff,
                "POST",
                "/v1/hosts/key",
                "s1-token",
                ask("http://10.0.0.1:7420"),
            )
            .await
        }
    };
    let (s, _, text) = key(&[("x-forwarded-for", "203.0.113.7, 10.0.0.1")]).await;
    assert_eq!(s, StatusCode::OK, "the proxy's own value, the last: {text}");
    let (s, _, text) = key(&[("x-forwarded-for", "10.0.0.1, 203.0.113.7")]).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "a forged first value counts for nothing: {text}"
    );
    assert!(text.contains("not 203.0.113.7"), "{text}");
    let (s, _, text) = key(&[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "no header, no address: {text}");
    assert!(text.contains("not an unknown address"), "{text}");
}

#[tokio::test]
async fn a_heartbeat_lands_on_the_record_added_for_its_address() {
    let f = fleet(config::Config::default());
    {
        let mut reg = f.st.reg.lock().unwrap();
        let mut added = static_host(&config::StaticHost::default(), Utc::now());
        added.id = "h_srv-9".into();
        added.url = "http://10.0.0.9:7420".into();
        added.state = "provisioning".into();
        added.provider = "manual".into();
        added.token = "t0k".into();
        added.note = "bootstrapped at 2026-10-20".into();
        reg.hosts.insert(added.id.clone(), added);
    }
    // The token the bootstrap gave it is its credential; the fleet's API needs none here.
    let mut hb = heartbeat("http://10.0.0.9:7420", 64_000, &["t1"]);
    hb["conditions"] = serde_json::json!([{"type": "memory_pressure", "status": true,
        "since": "2026-10-21T10:00:00Z", "message": "63000 MB of 64000 committed (98%), over 95%"}]);
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/hosts/register",
        "other",
        Some(hb.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{body}");
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/register", "t0k", Some(hb)).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    let hs = hosts(&f.st);
    assert_eq!(hs.len(), 1);
    let h = &hs[0];
    assert_eq!(h.id, "h_srv-9", "the fleet's id for it, not the daemon's");
    assert_eq!(h.state, "ready");
    assert_eq!(h.provider, "manual");
    assert_eq!(h.region, "par");
    assert_eq!(h.capacity.memory_mb, 64_000);
    assert_eq!(h.machines, 1);
    assert_eq!(h.note, "bootstrapped at 2026-10-20");
    assert_eq!(
        (h.conditions[0].kind.as_str(), h.conditions[0].status),
        ("memory_pressure", true),
        "the heartbeat's conditions are the host's"
    );
    {
        let reg = f.st.reg.lock().unwrap();
        let rec = &reg.hosts["h_srv-9"];
        assert_eq!(rec.token, "t0k");
        assert_eq!(reg.tenants.get("t1").map(String::as_str), Some("h_srv-9"));
    }
    assert!(saved(&f.st).hosts.contains_key("h_srv-9"));
    let (s, _, body) = call(&f.st, "GET", "/v1/tenants", "", None).await;
    assert_eq!(s, StatusCode::OK);
    let ts: Vec<api::Tenant> = serde_json::from_str(&body).unwrap();
    assert_eq!(ts.len(), 1);
    assert_eq!((ts[0].id.as_str(), ts[0].host.as_str()), ("t1", "h_srv-9"));
}

#[tokio::test]
async fn status_sums_the_ready_hosts_and_hosts_are_sorted() {
    let f = fleet(config::Config::default());
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
    assert!(
        v.get("provisioner").is_none(),
        "no provisioner (ADR 0042): {v}"
    );
    let (s, _, body) = call(&f.st, "GET", "/v1/hosts", "", None).await;
    assert_eq!(s, StatusCode::OK);
    let hs: Vec<api::Host> = serde_json::from_str(&body).unwrap();
    let ids: Vec<&str> = hs.iter().map(|h| h.id.as_str()).collect();
    assert_eq!(ids, ["a", "b", "c"]);
    let states: Vec<&str> = hs.iter().map(|h| h.state.as_str()).collect();
    assert_eq!(states, ["down", "ready", "draining"]);
    assert_eq!(hs[1].tenants, ["t1", "t2"]);
}

/// Forgetting a host that holds a pool key is refused unless forced: the key goes with the
/// record, and a static host polled back would get a key its pool does not open.
/// A create in `region`, of `memory_mb`, with a volume of `volume_gb` when not 0.
fn ask(tenant: &str, region: &str, memory_mb: u32, volume_gb: u32) -> serde_json::Value {
    let mut b = create_body(tenant, "web", memory_mb);
    b["region"] = region.into();
    if volume_gb > 0 {
        b["volume"] = serde_json::json!({"size_gb": volume_gb, "mount": "/data"});
    }
    b
}

/// The fleet's `/metrics`, checked against the format, as lines.
async fn scrape(st: &Arc<AppState>, token: &str) -> Vec<String> {
    let (s, headers, text) = call(st, "GET", "/metrics", token, None).await;
    assert_eq!(s, StatusCode::OK, "{text}");
    assert_eq!(
        headers[header::CONTENT_TYPE],
        "text/plain; version=0.0.4; charset=utf-8"
    );
    api::metrics::check_exposition(&text);
    text.lines().map(String::from).collect()
}

#[tokio::test]
async fn each_refusal_is_counted_by_what_ran_out_and_the_room_is_shown() {
    let f = fleet(config::Config::default());
    seed(&f.st, "a", 64_000, 4_000, 1, &["t0"]);
    seed(&f.st, "b", 64_000, 0, 0, &[]);
    seed(&f.st, "c", 64_000, 0, 0, &[]);
    {
        let mut reg = f.st.reg.lock().unwrap();
        for (id, disk) in [("a", 10_000), ("b", 900_000), ("c", 900_000)] {
            let h = reg.hosts.get_mut(id).unwrap();
            h.region = "gra".into();
            h.disk_free_mb = disk;
        }
    }
    set_state(&f.st, "b", "draining");
    let refused = |tenant: &'static str, region: &'static str, mb: u32, gb: u32| {
        let st = f.st.clone();
        async move {
            let body = ask(tenant, region, mb, gb);
            let (s, _, body) = call(&st, "POST", "/v1/machines", "", Some(body)).await;
            assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{tenant}: {body}");
            assert_eq!(json(&body)["code"], "capacity", "{tenant}");
        }
    };
    // No host of gra has 100 GB of memory; a and c have 512 MB, neither 1000 GB of disk.
    refused("t1", "gra", 100_000, 0).await;
    refused("t2", "gra", 512, 1000).await;
    let lines = scrape(&f.st, "").await;
    for want in [
        r#"briqyard_fleet_hosts{state="ready"} 2"#,
        r#"briqyard_fleet_hosts{state="draining"} 1"#,
        r#"briqyard_fleet_host_state{host="b",region="gra",state="draining"} 1"#,
        r#"briqyard_fleet_host_state{host="c",region="gra",state="ready"} 1"#,
        // a and c: b is drained.
        r#"briqyard_fleet_free_mb{resource="memory",region="gra"} 124000"#,
        r#"briqyard_fleet_free_mb{resource="disk",region="gra"} 910000"#,
        r#"briqyard_fleet_largest_slot_mb{resource="memory",region="gra"} 64000"#,
        r#"briqyard_fleet_largest_slot_mb{resource="disk",region="gra"} 900000"#,
        r#"briqyard_fleet_unschedulable_total{resource="memory",region="gra"} 1"#,
        r#"briqyard_fleet_unschedulable_total{resource="disk",region="gra"} 1"#,
        r#"briqyard_fleet_unschedulable_total{resource="pressure",region="gra"} 0"#,
    ] {
        assert!(lines.iter().any(|l| l == want), "{want}\n{lines:#?}");
    }
    // c has the room and memory pressure: memory, a new host fixes it. t0's host a gets a
    // condition: its own create is refused before a is asked, as pressure, which a new host
    // does not fix.
    f.st.reg
        .lock()
        .unwrap()
        .hosts
        .get_mut("c")
        .unwrap()
        .conditions = vec![pressure(api::condition::MEMORY_PRESSURE, true)];
    refused("t3", "gra", 512, 20).await;
    f.st.reg
        .lock()
        .unwrap()
        .hosts
        .get_mut("a")
        .unwrap()
        .conditions = vec![pressure(api::condition::DISK_PRESSURE, true)];
    refused("t0", "", 512, 0).await;
    // A region no host is in counts as `other`; no region asked, as none.
    refused("t5", "nowhere", 512, 0).await;
    refused("t6", "", 100_000, 0).await;
    let lines = scrape(&f.st, "").await;
    for want in [
        r#"briqyard_fleet_free_mb{resource="memory",region="gra"} 0"#,
        r#"briqyard_fleet_largest_slot_mb{resource="disk",region="gra"} 0"#,
        r#"briqyard_fleet_unschedulable_total{resource="memory",region="gra"} 2"#,
        r#"briqyard_fleet_unschedulable_total{resource="pressure",region="gra"} 1"#,
        r#"briqyard_fleet_unschedulable_total{resource="memory",region="other"} 1"#,
        r#"briqyard_fleet_unschedulable_total{resource="disk",region="other"} 0"#,
        r#"briqyard_fleet_unschedulable_total{resource="memory",region=""} 1"#,
    ] {
        assert!(lines.iter().any(|l| l == want), "{want}\n{lines:#?}");
    }
    assert!(!lines.iter().any(|l| l.contains("nowhere")), "{lines:#?}");
    // `other` and `""` have no host: their counters only, never a room of 0 that reads as a
    // full region.
    for region in ["other", ""] {
        let room = format!("region=\"{region}\"}}");
        let gauges: Vec<&String> = lines
            .iter()
            .filter(|l| l.starts_with("briqyard_fleet_") && !l.contains("unschedulable"))
            .filter(|l| l.split(' ').next().unwrap().ends_with(&room))
            .collect();
        assert!(gauges.is_empty(), "{region:?}: {gauges:#?}");
    }
    // The same in /v1/status.
    let (s, _, body) = call(&f.st, "GET", "/v1/status", "", None).await;
    assert_eq!(s, StatusCode::OK);
    let regions: Vec<api::RegionRoom> =
        serde_json::from_value(json(&body)["regions"].clone()).unwrap();
    let names: Vec<&str> = regions.iter().map(|r| r.region.as_str()).collect();
    assert_eq!(names, ["", "gra", "other"]);
    assert_eq!(
        regions[1].unschedulable,
        api::Unschedulable {
            memory: 2,
            disk: 1,
            pressure: 1
        }
    );
    assert_eq!(regions[1].free, Some(api::Room::default()), "gra: full");
    assert_eq!(regions[2].unschedulable.memory, 1);
    for r in [&regions[0], &regions[2]] {
        assert_eq!(
            (r.free, r.largest_slot),
            (None, None),
            "{:?}: no host",
            r.region
        );
    }
    let v = json(&body);
    assert!(v["regions"][0].get("free").is_none(), "absent, not 0: {v}");
}

#[tokio::test]
async fn metrics_take_the_metrics_token_or_the_apis() {
    let mut cfg = config::Config {
        token: "api".into(),
        tls: config::Tls::Off,
        ..Default::default()
    };
    let f = fleet(cfg.clone());
    let (s, _, _) = call(&f.st, "GET", "/metrics", "", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    scrape(&f.st, "api").await;
    // A metrics token of its own: the scraper's; the API's still opens what it reads anyway
    // (ADR 0054). The same on every path a scraper reads.
    cfg.metrics_token = "scrape".into();
    let f = fleet(cfg.clone());
    scrape(&f.st, "scrape").await;
    scrape(&f.st, "api").await;
    for path in ["/metrics", "/v1/metrics/targets", "/v1/hosts/h1/metrics"] {
        let (s, _, _) = call(&f.st, "GET", path, "", None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{path}");
        let (s, _, _) = call(&f.st, "GET", path, "other", None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{path}");
    }
    let (s, _, _) = call(&f.st, "GET", "/v1/status", "scrape", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "it opens nothing else");
    let (s, _, _) = call(&f.st, "GET", "/v1/hosts/h1/drain", "scrape", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "nor a host's other routes");
    // On loopback with nothing in front (`tls` unset), none, as the daemon's.
    cfg.tls = config::Tls::Unset;
    let f = fleet(cfg);
    let lines = scrape(&f.st, "").await;
    assert!(lines.contains(&r#"briqyard_fleet_hosts{state="ready"} 0"#.to_string()));
    let (s, _, _) = call(&f.st, "GET", "/v1/status", "", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

// --- what Prometheus scrapes (ADR 0054) ---

#[tokio::test]
async fn the_targets_are_every_host_through_the_relay_at_the_address_asked() {
    let f = fleet(config::Config {
        token: "api".into(),
        ..Default::default()
    });
    seed(&f.st, "a", 64_000, 0, 0, &[]);
    seed(&f.st, "b", 64_000, 0, 0, &[]);
    seed(&f.st, "c", 64_000, 0, 0, &[]);
    seed(&f.st, "new", 64_000, 0, 0, &[]);
    f.st.reg.lock().unwrap().hosts.get_mut("a").unwrap().region = "gra".into();
    set_state(&f.st, "b", "down");
    set_state(&f.st, "c", "draining");
    set_state(&f.st, "new", "provisioning");
    let host = [("host", "fleet.example.com")];
    let peer = std::net::IpAddr::from([127, 0, 0, 1]);
    let (s, _, body) = call_with(
        &f.st,
        peer,
        &host,
        "GET",
        "/v1/metrics/targets",
        "api",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let want = serde_json::json!([
        { "targets": ["fleet.example.com"], "labels": { "instance": "fleet" } },
        { "targets": ["fleet.example.com"], "labels": {
            "__metrics_path__": "/v1/hosts/a/metrics", "instance": "a", "host": "a", "region": "gra" } },
        // A down host is still a target: scraped, it is `up == 0`.
        { "targets": ["fleet.example.com"], "labels": {
            "__metrics_path__": "/v1/hosts/b/metrics", "instance": "b", "host": "b", "region": "" } },
        { "targets": ["fleet.example.com"], "labels": {
            "__metrics_path__": "/v1/hosts/c/metrics", "instance": "c", "host": "c", "region": "" } },
        // A host still being bootstrapped has no daemon to scrape yet.
    ]);
    assert_eq!(json(&body), want);
    // Retired and forgotten: gone from the next answer.
    f.st.reg.lock().unwrap().hosts.remove("c");
    let (_, _, body) = call_with(
        &f.st,
        peer,
        &host,
        "GET",
        "/v1/metrics/targets",
        "api",
        None,
    )
    .await;
    assert_eq!(json(&body).as_array().unwrap().len(), 3);
    // No Host header: no address to give.
    let (s, _, body) = call(&f.st, "GET", "/v1/metrics/targets", "api", None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
}

/// A host whose `/metrics` answers its text, over TLS when `cert` is given.
async fn metrics_host(cert: Option<&rcgen::CertifiedKey>) -> String {
    async fn text(headers: HeaderMap) -> Response {
        if headers.get(header::AUTHORIZATION).map(|v| v.as_bytes()) != Some(b"Bearer h-tok") {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        (
            [(
                header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            "briqyard_machines_total 3\n",
        )
            .into_response()
    }
    let app = Router::new()
        .route("/metrics", get(text))
        .into_make_service();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    match cert {
        None => {
            tokio::spawn(axum_server::from_tcp(listener).serve(app));
            format!("http://{addr}")
        }
        Some(c) => {
            let cfg = api::tls::server_config(
                c.cert.pem().as_bytes(),
                c.key_pair.serialize_pem().as_bytes(),
            )
            .unwrap();
            let cfg = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(cfg));
            tokio::spawn(axum_server::from_tcp_rustls(listener, cfg).serve(app));
            format!("https://{addr}")
        }
    }
}

fn metrics_fleet(url: &str, fingerprint: &str) -> Fleet {
    fleet(config::Config {
        token: "api".into(),
        hosts: vec![config::StaticHost {
            id: "h1".into(),
            url: url.into(),
            token: "h-tok".into(),
            tls_fingerprint: fingerprint.into(),
            ..Default::default()
        }],
        ..Default::default()
    })
}

#[tokio::test]
async fn a_hosts_metrics_are_relayed_over_its_pinned_certificate_with_its_token() {
    let (cert, fp) = certificate();
    let url = metrics_host(Some(&cert)).await;
    let f = metrics_fleet(&url, &fp);
    let (s, headers, body) = call(&f.st, "GET", "/v1/hosts/h1/metrics", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(
        body, "briqyard_machines_total 3\n",
        "the host's text as it is"
    );
    assert_eq!(
        headers[header::CONTENT_TYPE],
        "text/plain; version=0.0.4; charset=utf-8"
    );
    assert_eq!(headers["x-briqyard-host"], "h1");
    // Another certificate at that address: not the host, nothing sent to it.
    let (_, other) = certificate();
    let f = metrics_fleet(&url, &other);
    let (s, _, body) = call(&f.st, "GET", "/v1/hosts/h1/metrics", "api", None).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY, "{body}");
    assert!(
        body.contains(&format!("is not the pinned {other}")),
        "{body}"
    );
    // A host's own refusal is relayed as it is: a token the host does not take.
    let url = metrics_host(None).await;
    let f = metrics_fleet(&url, "");
    f.st.reg.lock().unwrap().hosts.get_mut("h1").unwrap().token = "stale".into();
    let (s, _, _) = call(&f.st, "GET", "/v1/hosts/h1/metrics", "api", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_host_down_or_silent_is_not_scraped_as_up() {
    let url = metrics_host(None).await;
    let f = metrics_fleet(&url, "");
    set_state(&f.st, "h1", "down");
    let (s, _, body) = call(&f.st, "GET", "/v1/hosts/h1/metrics", "api", None).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(json(&body)["code"], "host_down");
    // Ready in the registry, nothing listening: it does not answer.
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let f = metrics_fleet(&format!("http://{closed}"), "");
    let (s, _, body) = call(&f.st, "GET", "/v1/hosts/h1/metrics", "api", None).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(json(&body)["code"], "host_unreachable");
    assert!(
        json(&body)["error"]
            .as_str()
            .unwrap()
            .starts_with("host h1: "),
        "{body}"
    );
    let (s, _, body) = call(&f.st, "GET", "/v1/hosts/nope/metrics", "api", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn a_body_cut_short_is_a_host_that_did_not_answer() {
    async fn cut() -> Response {
        let chunks: Vec<std::io::Result<Bytes>> = vec![
            Ok(Bytes::from_static(b"briqyard_machines_total 3\n")),
            Err(std::io::Error::other("gone")),
        ];
        Body::from_stream(futures::stream::iter(chunks)).into_response()
    }
    let app = Router::new()
        .route("/metrics", get(cut))
        .into_make_service();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum_server::from_tcp(listener).serve(app));
    let f = metrics_fleet(&format!("http://{addr}"), "");
    let (s, _, body) = call(&f.st, "GET", "/v1/hosts/h1/metrics", "api", None).await;
    assert_eq!(
        s,
        StatusCode::BAD_GATEWAY,
        "a 200 with half a body would read as up: {body}"
    );
    assert_eq!(json(&body)["code"], "host_unreachable");
}

#[tokio::test]
async fn a_keyed_host_is_forgotten_only_by_force() {
    let f = fleet(config::Config {
        hosts: vec![config::StaticHost {
            id: "s1".into(),
            url: "http://10.0.0.1:7420".into(),
            token: "s1-token".into(),
            ..Default::default()
        }],
        ..Default::default()
    });
    seed(&f.st, "plain", 64_000, 0, 0, &[]);
    let (s, _, _) = call(&f.st, "DELETE", "/v1/hosts/plain", "", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "no key: forgotten as before");
    let ask = Some(serde_json::json!({ "url": "http://10.0.0.1:7420" }));
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/key", "s1-token", ask).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, body) = call(&f.st, "DELETE", "/v1/hosts/s1", "", None).await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");
    assert_eq!(json(&body)["code"], "pool_key");
    assert!(
        body.contains("the pool is unreadable at the host's next restart; retire it, or --force"),
        "{body}"
    );
    assert!(f.st.reg.lock().unwrap().hosts.contains_key("s1"), "kept");
    let (s, _, body) = call(&f.st, "DELETE", "/v1/hosts/s1?force=true", "", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    assert!(
        !saved(&f.st).hosts.contains_key("s1"),
        "forgotten, its key with it"
    );
}

/// A key the registry could not be written with is not kept: the next ask is refused the same
/// way rather than served a key only memory holds (ADR 0026).
#[tokio::test]
async fn a_key_that_could_not_be_written_is_not_served() {
    let dir = tempfile::tempdir().unwrap();
    let nowhere = dir.path().join("missing").join("registry.json");
    let f = fleet_at(
        config::Config {
            hosts: vec![config::StaticHost {
                id: "s1".into(),
                url: "http://10.0.0.1:7420".into(),
                token: "s1-token".into(),
                ..Default::default()
            }],
            ..Default::default()
        },
        dir,
        nowhere.clone(),
    );
    let ask = Some(serde_json::json!({ "url": "http://10.0.0.1:7420" }));
    for attempt in 1..=2 {
        let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s1-token", ask.clone()).await;
        assert_eq!(
            s,
            StatusCode::INTERNAL_SERVER_ERROR,
            "attempt {attempt}: {body}"
        );
        assert_eq!(json(&body)["code"], "registry");
        assert!(
            f.st.reg.lock().unwrap().hosts["s1"].pool_key.is_empty(),
            "attempt {attempt}"
        );
    }
    std::fs::create_dir_all(nowhere.parent().unwrap()).unwrap();
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/key", "s1-token", ask).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(
        saved(&f.st).hosts["s1"].pool_key.expose(),
        json(&body)["key"].as_str().unwrap()
    );
}

#[tokio::test]
async fn a_registry_that_cannot_be_written_fails_the_request() {
    let dir = tempfile::tempdir().unwrap();
    let nowhere = dir.path().join("missing").join("registry.json");
    let f = fleet_at(config::Config::default(), dir, nowhere.clone());
    seed(&f.st, "h_a", 64_000, 0, 0, &[]);
    for (method, path) in [
        ("POST", "/v1/hosts/h_a/drain"),
        ("POST", "/v1/tenants/t1/unpin"),
        ("DELETE", "/v1/hosts/h_a"),
    ] {
        let (s, _, text) = call(&f.st, method, path, "", None).await;
        assert_eq!(
            s,
            StatusCode::INTERNAL_SERVER_ERROR,
            "{method} {path}: {text}"
        );
        let v = json(&text);
        assert_eq!(v["code"], "registry", "{method} {path}");
        assert!(
            v["error"]
                .as_str()
                .unwrap()
                .contains(&format!("write registry {}", nowhere.display())),
            "{v}"
        );
    }
    assert!(!nowhere.exists());
    // A create is refused before any host is asked: a pin the fleet would forget on restart
    // could put the tenant's next machine on another host.
    let d = start_daemon("d1", "tok").await;
    let dir = tempfile::tempdir().unwrap();
    let nowhere = dir.path().join("missing").join("registry.json");
    let g = fleet_at(
        config::Config {
            hosts: vec![config::StaticHost {
                id: "d1".into(),
                url: d.url.clone(),
                token: "tok".into(),
                ..Default::default()
            }],
            ..Default::default()
        },
        dir,
        nowhere,
    );
    poll_static_hosts_once(&g.st).await;
    let before = d.stub.calls().len();
    let (s, _, body) = call(
        &g.st,
        "POST",
        "/v1/machines",
        "",
        Some(create_body("t1", "web", 512)),
    )
    .await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(json(&body)["code"], "registry");
    assert_eq!(d.stub.calls().len(), before, "the host was not asked");
}

/// ADR 0043: writes take turns, each writing the registry as it is when its turn comes.
/// Hundreds at once all succeed, every read of the file in between parses, and the file
/// ends with every change.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn writes_at_once_all_land_and_the_file_ends_with_every_change() {
    use std::sync::atomic::AtomicBool;
    let f = fleet(config::Config::default());
    let stop = Arc::new(AtomicBool::new(false));
    let reader = {
        let (path, stop) = (f.st.state_path.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut reads = 0;
            while !stop.load(Ordering::SeqCst) {
                if let Ok(data) = std::fs::read(&path) {
                    serde_json::from_slice::<Registry>(&data).expect("a read parses");
                    reads += 1;
                }
            }
            reads
        })
    };
    let writes: Vec<_> = (0..300)
        .map(|i| {
            let st = f.st.clone();
            tokio::spawn(async move {
                st.reg
                    .lock()
                    .unwrap()
                    .tenants
                    .insert(format!("t{i}"), "h_a".into());
                st.save().await
            })
        })
        .collect();
    for w in writes {
        w.await.unwrap().expect("a write");
    }
    stop.store(true, Ordering::SeqCst);
    assert!(reader.join().unwrap() > 0);
    assert_eq!(
        saved(&f.st).tenants.len(),
        300,
        "the last write holds them all"
    );
    assert!(!f.st.state_path.with_extension("json.tmp").exists());
}

/// Creates at once never fail on the registry's write, and each machine is in the file.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn creates_at_once_all_land_in_the_registry() {
    let (f, _ds) = fleet_with_daemons(2).await;
    let creates: Vec<_> = (0..64)
        .map(|i| {
            let st = f.st.clone();
            tokio::spawn(async move {
                let body = create_body(&format!("t{i}"), "web", 256);
                call(&st, "POST", "/v1/machines", "api", Some(body)).await
            })
        })
        .collect();
    for c in creates {
        let (s, _, body) = c.await.unwrap();
        assert_eq!(s, StatusCode::CREATED, "{body}");
    }
    let reg = saved(&f.st);
    assert_eq!((reg.machines.len(), reg.tenants.len()), (64, 64));
}

/// A machine the host made is the caller's answer even when the write after it fails: a 500
/// there would leave a machine nobody knows the id of. The next write records it.
#[tokio::test]
async fn a_machine_made_is_answered_when_the_write_after_it_fails() {
    let d = start_daemon("d1", "tok").await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    std::fs::create_dir(&state).unwrap();
    let g = fleet_at(
        config::Config {
            hosts: vec![config::StaticHost {
                id: "d1".into(),
                url: d.url.clone(),
                token: "tok".into(),
                ..Default::default()
            }],
            ..Default::default()
        },
        dir,
        state.join("registry.json"),
    );
    poll_static_hosts_once(&g.st).await;
    // The host makes it; meanwhile the fleet's state directory goes.
    let gone = state.with_extension("gone");
    {
        let (state, gone) = (state.clone(), gone.clone());
        *d.stub.on_create.lock().unwrap() =
            Some(Box::new(move || std::fs::rename(&state, &gone).unwrap()));
    }
    let (s, _, body) = call(
        &g.st,
        "POST",
        "/v1/machines",
        "",
        Some(create_body("t1", "web", 512)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    let id = json(&body)["id"].as_str().unwrap().to_string();
    assert_eq!(g.st.reg.lock().unwrap().machines[&id], "d1");
    std::fs::rename(&gone, &state).unwrap();
    assert!(!saved(&g.st).machines.contains_key(&id));
    poll_static_hosts_once(&g.st).await;
    assert_eq!(saved(&g.st).machines[&id], "d1", "the next write has it");
}

// --- adding, retiring, draining, forgetting ---

/// The fleet buys no server (ADR 0042): the order route is gone, and nothing is recorded.
#[tokio::test]
async fn there_is_no_order() {
    let f = fleet(config::Config::default());
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/hosts/order",
        "",
        Some(serde_json::json!({"reason": "x"})),
    )
    .await;
    assert!(
        matches!(s, StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED),
        "{s}: {body}"
    );
    assert!(hosts(&f.st).is_empty(), "nothing recorded");
}

/// A fleet that bootstraps the hosts added to it, its APIs on the 10.42.0.0/16 vRack.
fn bootstrapping_fleet() -> Fleet {
    let mut cfg = config::Config::default();
    cfg.bootstrap.enabled = true;
    cfg.bootstrap.private_network = "10.42.0.0/16".into();
    cfg.bootstrap.public_tcp_ports = vec![80, 443];
    fleet(cfg)
}

#[tokio::test]
async fn a_server_bought_by_hand_is_added_for_the_bootstrap() {
    let f = bootstrapping_fleet();
    let add = |body: serde_json::Value| {
        let st = f.st.clone();
        async move { call(&st, "POST", "/v1/hosts", "", Some(body)).await }
    };
    let (s, _, body) =
        add(serde_json::json!({"ssh": "51.68.1.2", "address": "10.42.0.11", "region": "gra"}))
            .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{body}");
    let h: api::Host = serde_json::from_str(&body).unwrap();
    assert_eq!(h.id, "h_10-42-0-11");
    assert_eq!(
        h.url, "https://10.42.0.11:7420",
        "its API on the vRack, over TLS"
    );
    assert_eq!(h.ssh, "51.68.1.2");
    assert_eq!(
        (h.state.as_str(), h.provider.as_str(), h.region.as_str()),
        ("provisioning", "manual", "gra")
    );
    assert_eq!(h.tls_fingerprint, "", "pinned by the bootstrap");
    {
        let reg = f.st.reg.lock().unwrap();
        let rec = &reg.hosts["h_10-42-0-11"];
        assert_eq!(rec.token.len(), 32, "a token of its own for its API");
        let picked: Vec<String> = bootstrap::to_install(&reg)
            .into_iter()
            .map(|h| h.id)
            .collect();
        assert_eq!(picked, ["h_10-42-0-11"], "the bootstrap takes it");
    }
    assert!(saved(&f.st).hosts.contains_key("h_10-42-0-11"), "written");
    assert_eq!(
        h.public_tcp_ports,
        [80, 443],
        "the fleet's, kept on the host"
    );
    // One address only: the API there too, its id named; no public ports of its own (a host
    // without an edge), whatever the fleet's are.
    let (s, _, body) = add(serde_json::json!({
        "ssh": "51.68.1.3", "id": "gra-2", "public_tcp_ports": []
    }))
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{body}");
    let h: api::Host = serde_json::from_str(&body).unwrap();
    assert_eq!(
        (h.id.as_str(), h.url.as_str(), h.ssh.as_str()),
        ("gra-2", "https://51.68.1.3:7420", "")
    );
    assert_eq!(
        f.st.reg.lock().unwrap().hosts["gra-2"].public_tcp_ports,
        Some(vec![]),
        "its own, empty: never the fleet's"
    );
    // The same server again, by its address, its id or its SSH address.
    for body in [
        serde_json::json!({"ssh": "51.68.1.9", "address": "10.42.0.11"}),
        serde_json::json!({"ssh": "51.68.1.9", "address": "10.42.0.12", "id": "gra-2"}),
        serde_json::json!({"ssh": "51.68.1.2", "address": "10.42.0.13"}),
    ] {
        let (s, _, text) = add(body).await;
        assert_eq!(s, StatusCode::CONFLICT, "{text}");
        assert_eq!(json(&text)["code"], "conflict", "{text}");
    }
    // What makes no host.
    for (body, msg) in [
        (
            serde_json::json!({"ssh": ""}),
            "ssh \"\": want the server's address or name",
        ),
        (
            serde_json::json!({"ssh": "-oProxyCommand=x"}),
            "want the server's address or name",
        ),
        (
            serde_json::json!({"ssh": "root@1.2.3.4"}),
            "want the server's address or name",
        ),
        (
            serde_json::json!({"ssh": "1.2.3.4:2222"}),
            "want the server's address or name",
        ),
        (
            serde_json::json!({"ssh": "server.example"}),
            "address \"server.example\": want the API's IPv4 address",
        ),
        (
            serde_json::json!({"ssh": "51.68.1.2", "address": "192.168.1.5"}),
            "is not in bootstrap.private_network",
        ),
        (
            serde_json::json!({"ssh": "51.68.1.4", "id": "Gra 1"}),
            "id \"Gra 1\": a-z, 0-9, _ and -",
        ),
        (
            serde_json::json!({"ssh": "51.68.1.4", "public_tcp_ports": [443, 0]}),
            "public_tcp_ports: 0 is not a port",
        ),
    ] {
        let (s, _, text) = add(body.clone()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}: {text}");
        let m = json(&text)["error"].as_str().unwrap().to_string();
        assert!(m.contains(msg), "{body}: {m}");
    }
    assert_eq!(hosts(&f.st).len(), 2, "nothing recorded for a refusal");
    // A fleet that bootstraps nothing adds nothing.
    let off = fleet(config::Config::default());
    let (s, _, text) = call(
        &off.st,
        "POST",
        "/v1/hosts",
        "",
        Some(serde_json::json!({"ssh": "51.68.1.2"})),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{text}");
    assert_eq!(json(&text)["code"], "bootstrap_off");
}

#[tokio::test]
async fn an_added_host_turns_ready_at_its_first_heartbeat_on_its_private_address() {
    let f = bootstrapping_fleet();
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/hosts",
        "",
        Some(serde_json::json!({"ssh": "51.68.1.2", "address": "10.42.0.11"})),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{body}");
    let token = f.st.reg.lock().unwrap().hosts["h_10-42-0-11"].token.clone();
    let fp = "ab".repeat(32);
    bootstrap::bootstrapped(
        f.st.reg
            .lock()
            .unwrap()
            .hosts
            .get_mut("h_10-42-0-11")
            .unwrap(),
        "bootstrapped".into(),
        fp.clone(),
    );
    let mut hb = heartbeat("https://10.42.0.11:7420", 64_000, &[]);
    hb["tls_fingerprint"] = fp.clone().into();
    // From its public address, it is no host the fleet expects.
    let mut public = hb.clone();
    public["url"] = "https://51.68.1.2:7420".into();
    let (s, _, text) = call(&f.st, "POST", "/v1/hosts/register", &token, Some(public)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{text}");
    let (s, _, text) = call(&f.st, "POST", "/v1/hosts/register", &token, Some(hb)).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{text}");
    let h = &hosts(&f.st)[0];
    assert_eq!((h.state.as_str(), h.provider.as_str()), ("ready", "manual"));
    assert_eq!(h.ssh, "51.68.1.2", "kept for the next bootstrap");
    assert_eq!(h.tls_fingerprint, fp);
}

#[tokio::test]
async fn retire_forgets_an_empty_host_at_once() {
    let f = fleet(config::Config::default());
    seed(&f.st, "h_a", 1000, 0, 0, &[]);
    {
        let mut reg = f.st.reg.lock().unwrap();
        // Stale index entries from a machine long gone and a tenant never confirmed.
        reg.machines.insert("m9".into(), "h_a".into());
        reg.endpoints.insert("e9".into(), "h_a".into());
        reg.tenants.insert("t9".into(), "h_a".into());
    }
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/h_a/retire", "", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let h: api::Host = serde_json::from_str(&body).unwrap();
    assert_eq!(h.id, "h_a");
    assert_eq!(h.state, "retired");
    assert!(hosts(&f.st).is_empty(), "forgotten");
    assert!(!saved(&f.st).hosts.contains_key("h_a"), "and written");
    {
        let reg = f.st.reg.lock().unwrap();
        assert!(reg.machines.is_empty(), "its index goes with it");
        assert!(reg.endpoints.is_empty());
        assert!(reg.tenants.is_empty());
    }
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/h_a/retire", "", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn retire_keeps_a_busy_host_until_it_empties() {
    let f = fleet(config::Config::default());
    seed(&f.st, "h_b", 64_000, 4_000, 2, &["t1"]);
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/h_b/retire", "", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let h: api::Host = serde_json::from_str(&body).unwrap();
    assert_eq!(h.state, "retiring");
    assert_eq!(h.machines, 2);
    let listed = hosts(&f.st);
    assert_eq!(listed.len(), 1, "still here");
    assert_eq!(listed[0].state, "retiring");
    assert!(f.st.reg.lock().unwrap().retirable().is_empty());
    // Asked again while busy: still retiring, not forgotten.
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/h_b/retire", "", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(json(&body)["state"], "retiring");
    // Its last machine goes (a heartbeat says so): `forget_retired`'s pass would forget it.
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
    assert_eq!(json(&body)["state"], "retired");
    assert!(hosts(&f.st).is_empty());
}

#[tokio::test]
async fn drain_and_forget() {
    let f = fleet(config::Config::default());
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
            .place("t3", "", 512, 0, &f.st.policy)
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
    assert!(!saved(&f.st).hosts.contains_key("h_a"));
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
                ..Default::default()
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
    let f = fleet(cfg);
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
        assert_eq!(
            reg.hosts[&host].used.memory_mb, 512,
            "reserved until the host reports"
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
    assert_eq!(saved(&f.st).machines.len(), 3, "the registry was written");
}

#[tokio::test]
async fn a_burst_of_creates_is_spread_by_what_each_one_reserved() {
    let (f, _ds) = fleet_with_daemons(2).await;
    // Three tenants, created before any poll could show the first's memory as used: each
    // sees what the ones before it reserved, so the two larger ones land apart.
    let mut on = Vec::new();
    for (t, mb) in [("t1", 30_000), ("t2", 20_000), ("t3", 20_000)] {
        let (s, headers, body) = call(
            &f.st,
            "POST",
            "/v1/machines",
            "api",
            Some(create_body(t, "web", mb)),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{body}");
        on.push(headers["x-briqyard-host"].to_str().unwrap().to_string());
    }
    assert_ne!(on[0], on[1], "t2 saw t1's 30 GB taken: {on:?}");
    assert_eq!(
        on[1], on[2],
        "t3 saw 30 GB on one host and 20 GB on the other: {on:?}"
    );
    let used: Vec<u32> = {
        let reg = f.st.reg.lock().unwrap();
        on.iter().map(|h| reg.hosts[h].used.memory_mb).collect()
    };
    assert_eq!(used, [30_000, 40_000, 40_000]);
    // The hosts report: what they run is what is used, no more.
    poll_static_hosts_once(&f.st).await;
    let used: Vec<u32> = {
        let reg = f.st.reg.lock().unwrap();
        on.iter().map(|h| reg.hosts[h].used.memory_mb).collect()
    };
    assert_eq!(used, [30_000, 40_000, 40_000]);
}

/// ADR 0044: what a create held is given back when the host does not make it, and what a
/// destroy freed is room at once, not at the host's next heartbeat.
#[tokio::test]
async fn room_comes_back_at_a_failed_create_and_at_a_destroy() {
    let (f, ds) = fleet_with_daemons(1).await;
    let used = |f: &Fleet| f.st.reg.lock().unwrap().hosts["d1"].used.memory_mb;
    // The host refuses (a bad name): nothing stays held.
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t0", "Bad Name", 30_000)),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(used(&f), 0);
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t1", "big", 50_000)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    let big = json(&body)["id"].as_str().unwrap().to_string();
    assert_eq!(used(&f), 50_000, "held until a report counts it");
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t2", "web", 20_000)),
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "no room: {body}");
    // The destroy answers once the host has freed it: the next create fits, no poll between.
    let path = format!("/v1/machines/{big}");
    let (s, _, body) = call(&f.st, "DELETE", &path, "api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(used(&f), 0, "the host's figure, asked after the destroy");
    let (free, _) = f.st.reg.lock().unwrap().room(&f.st.policy)["fsn"];
    assert_eq!(free.memory_mb, DAEMON_MEMORY_MB as u64, "the signals' too");
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t2", "web", 20_000)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert_eq!(used(&f), 20_000);
    assert_eq!(ds[0].stub.used_mb(), 20_000);
}

/// A caller that hangs up mid-create drops its handler, and the hold with it (ADR 0044). The
/// host takes the connection and never answers.
#[tokio::test]
async fn a_create_whose_caller_hangs_up_gives_its_hold_back() {
    let f = fleet(config::Config::default());
    seed(&f.st, "h_a", 64_000, 0, 0, &[]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    f.st.reg.lock().unwrap().hosts.get_mut("h_a").unwrap().url =
        format!("http://{}", listener.local_addr().unwrap());
    let (asked, mut forwarded) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        let mut open = Vec::new();
        while let Ok((conn, _)) = listener.accept().await {
            open.push(conn);
            let _ = asked.try_send(());
        }
    });
    let used = |f: &Fleet| f.st.reg.lock().unwrap().hosts["h_a"].used.memory_mb;
    let st = f.st.clone();
    let create = tokio::spawn(async move {
        let body = create_body("t1", "web", 20_000);
        call(&st, "POST", "/v1/machines", "", Some(body)).await
    });
    forwarded.recv().await.unwrap();
    assert_eq!(used(&f), 20_000, "held while the host makes it");
    create.abort();
    assert!(create.await.unwrap_err().is_cancelled());
    assert_eq!(used(&f), 0, "given back");
}

#[tokio::test]
async fn a_capacity_answer_unpins_a_tenants_first_machine_only() {
    let (f, ds) = fleet_with_daemons(1).await;
    // The host filled up since the fleet last looked: the fleet pins t1 to it and asks; the
    // host refuses; the pin goes, so a retry can be placed where there is room.
    ds[0].stub.add("t0", "big", 50_000);
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t1", "web", 20_000)),
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(
        json(&body)["code"],
        "capacity",
        "the host's answer passes through"
    );
    assert_eq!(ds[0].stub.calls().last().unwrap(), "POST /v1/machines");
    assert_eq!(pinned(&f.st, "t1"), None, "unpinned");
    assert_eq!(saved(&f.st).tenants.get("t1"), None, "written");
    // A tenant already on the host keeps its pin through a refusal: its network is there.
    poll_static_hosts_once(&f.st).await;
    assert_eq!(pinned(&f.st, "t0").as_deref(), Some("d1"));
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t0", "more", 20_000)),
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(pinned(&f.st, "t0").as_deref(), Some("d1"), "still pinned");
    // A refusal that is not `capacity` leaves a first machine's pin: the host had room, the
    // request was wrong.
    let (s, _, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t2", "Bad Name", 10)),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["code"], "invalid");
    assert_eq!(pinned(&f.st, "t2").as_deref(), Some("d1"));
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
    assert_eq!(
        f.st.reg.lock().unwrap().hosts["d2"].used.memory_mb,
        1024,
        "the fork is reserved on the source's host"
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
    // A query changes nothing of what the call is: a get carries the host, a delete drops
    // the index entry.
    let with_tenant = format!("{path}?tenant=t1");
    let (s, _, body) = call(&f.st, "GET", &with_tenant, "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(json(&body)["host"], "d2");
    let (s, _, _) = call(&f.st, "DELETE", &with_tenant, "api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(f.st.reg.lock().unwrap().machines.get(&m.id), None);
    assert!(!saved(&f.st).machines.contains_key(&m.id), "written");
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

/// A condition a daemon reports, true or not.
fn pressure(kind: &str, status: bool) -> api::Condition {
    api::Condition {
        kind: kind.into(),
        status,
        since: Utc::now(),
        message: "pool 4.0 GB free of 100.0 (4%), under 10%".into(),
    }
}

#[tokio::test]
async fn a_host_under_pressure_takes_no_new_tenant_and_refuses_its_own() {
    let (f, ds) = fleet_with_daemons(2).await;
    let src = ds[0].stub.add("t1", "web", 512);
    ds[1].stub.add("t0", "big", 30_000);
    *ds[0].stub.conditions.lock().unwrap() = vec![
        pressure(api::condition::MEMORY_PRESSURE, false),
        pressure(api::condition::DISK_PRESSURE, true),
    ];
    poll_static_hosts_once(&f.st).await;
    assert_eq!(pinned(&f.st, "t1").as_deref(), Some("d1"));
    assert_eq!(
        hosts(&f.st)[0].conditions[1],
        ds[0].stub.conditions.lock().unwrap()[1],
        "the poll keeps what the host said"
    );
    // A new tenant goes to d2, though d1 is emptier.
    let (s, headers, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t2", "web", 512)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d2");
    // The tenant on d1: refused before d1 is asked, with the condition, as `capacity`; so is
    // a fork of its machine and its gateway.
    f.st.reg
        .lock()
        .unwrap()
        .machines
        .insert(src.id.clone(), "d1".into());
    let mut fork = create_body("t9", "fork", 512);
    fork["fork"] = serde_json::json!({"machine_id": src.id});
    for (method, path, body) in [
        ("POST", "/v1/machines", create_body("t1", "db", 512)),
        ("POST", "/v1/machines", fork),
        ("PUT", "/v1/tenants/t1/gateway", gateway_body()),
    ] {
        let (s, _, body) = call(&f.st, method, path, "api", Some(body)).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{path}: {body}");
        assert_eq!(json(&body)["code"], "capacity");
        assert_eq!(
            json(&body)["error"],
            "host d1 is under disk_pressure: pool 4.0 GB free of 100.0 (4%), under 10%"
        );
    }
    assert!(
        !ds[0]
            .stub
            .calls()
            .iter()
            .any(|c| c.starts_with("POST") || c.starts_with("PUT")),
        "d1 was not asked"
    );
    assert_eq!(pinned(&f.st, "t1").as_deref(), Some("d1"), "still pinned");
    // Cleared at the next report: the tenant's create goes through.
    ds[0].stub.conditions.lock().unwrap()[1].status = false;
    poll_static_hosts_once(&f.st).await;
    let (s, headers, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t1", "db", 512)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d1");
}

#[tokio::test]
async fn top_asks_the_tenants_host_or_every_host_never_partially() {
    let (f, ds) = fleet_with_daemons(2).await;
    ds[0].stub.add("t1", "web", 512);
    ds[1].stub.add("t2", "db", 512);
    poll_static_hosts_once(&f.st).await;
    let d2_before = ds[1].stub.calls().len();
    let (s, _, body) = call(&f.st, "GET", "/v1/top?tenant=t1", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let ms: Vec<api::TopMachine> = serde_json::from_str(&body).unwrap();
    let got: Vec<(&str, &str)> = ms
        .iter()
        .map(|m| (m.name.as_str(), m.host.as_str()))
        .collect();
    assert_eq!(got, [("web", "d1")]);
    assert_eq!(ds[0].stub.calls().last().unwrap(), "GET /v1/top?tenant=t1");
    assert_eq!(ds[1].stub.calls().len(), d2_before, "d2 was not asked");
    let (s, _, body) = call(&f.st, "GET", "/v1/top", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let ms: Vec<api::TopMachine> = serde_json::from_str(&body).unwrap();
    let got: Vec<(&str, &str)> = ms
        .iter()
        .map(|m| (m.name.as_str(), m.host.as_str()))
        .collect();
    assert_eq!(got, [("web", "d1"), ("db", "d2")]);
    // A host down fails the whole answer.
    set_state(&f.st, "d2", "down");
    let (s, _, body) = call(&f.st, "GET", "/v1/top", "api", None).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(json(&body)["code"], "host_down");
}

#[tokio::test]
async fn usage_asks_every_host_and_is_never_partial() {
    let (f, ds) = fleet_with_daemons(2).await;
    let q = "/v1/usage?from=2026-10-20T14:00:00Z&to=2026-10-20T15:00:00Z&tenant=t1";
    let (s, _, body) = call(&f.st, "GET", q, "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let bs: Vec<api::UsageBucket> = serde_json::from_str(&body).unwrap();
    let got: Vec<(&str, &str)> = bs
        .iter()
        .map(|b| (b.machine_id.as_str(), b.host.as_str()))
        .collect();
    assert_eq!(got, [("m_d1", "d1"), ("m_d2", "d2")]);
    for d in &ds {
        assert_eq!(
            d.stub.calls().last().unwrap(),
            &format!("GET {q}"),
            "every host, the query as it came"
        );
    }
    // The hosts check the range: their refusal is the answer.
    let (s, _, body) = call(&f.st, "GET", "/v1/usage?to=x", "api", None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["code"], "invalid");
    // A host down fails the whole report, without asking it: a report missing a host
    // undercounts.
    set_state(&f.st, "d2", "down");
    let d2_before = ds[1].stub.calls().len();
    let (s, _, body) = call(&f.st, "GET", q, "api", None).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(json(&body)["code"], "host_down");
    assert_eq!(ds[1].stub.calls().len(), d2_before);
    // A host that does not answer fails it too.
    set_state(&f.st, "d2", "ready");
    f.st.reg.lock().unwrap().hosts.get_mut("d2").unwrap().url = "http://127.0.0.1:1".into();
    let (s, _, body) = call(&f.st, "GET", q, "api", None).await;
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
        pinned(&f.st, "t1").as_deref(),
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
async fn every_backup_is_listed_from_every_host() {
    let (f, ds) = fleet_with_daemons(2).await;
    let (s, _, body) = call(&f.st, "GET", "/v1/backups", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let ids: Vec<String> = serde_json::from_str::<Vec<api::Backup>>(&body)
        .unwrap()
        .into_iter()
        .map(|b| b.machine_id)
        .collect();
    assert_eq!(ids, ["m_d1", "m_d2"]);
    // A tenant's: every host too, the query as it came. Its host is d2, and the host it moved
    // from still holds the backups of what was destroyed there (ADR 0045).
    f.st.reg
        .lock()
        .unwrap()
        .tenants
        .insert("t1".into(), "d2".into());
    let (s, _, body) = call(&f.st, "GET", "/v1/backups?tenant=t1", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(json(&body).as_array().unwrap().len(), 2);
    for d in &ds {
        assert_eq!(d.stub.calls().last().unwrap(), "GET /v1/backups?tenant=t1");
    }
    // Every host or nothing: one down fails the listing.
    set_state(&f.st, "d1", "down");
    let (s, _, body) = call(&f.st, "GET", "/v1/backups?tenant=t1", "api", None).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
}

#[tokio::test]
async fn a_destroyed_machine_s_backup_is_deleted_on_the_host_that_holds_it() {
    let (f, ds) = fleet_with_daemons(2).await;
    // Its tenant moved to d2 (ADR 0045): the backups of m_d1 stay held on d1.
    f.st.reg
        .lock()
        .unwrap()
        .tenants
        .insert("t1".into(), "d2".into());
    for (query, search) in [
        (
            "chain=true&tenant=t1",
            "GET /v1/backups?machine=m_d1&tenant=t1",
        ),
        ("chain=true", "GET /v1/backups?machine=m_d1"),
    ] {
        let path = format!("/v1/machines/m_d1/backups/b1?{query}");
        let (s, _, body) = call(&f.st, "DELETE", &path, "api", None).await;
        assert_eq!(s, StatusCode::NO_CONTENT, "{query}: {body}");
        let calls = ds[0].stub.calls();
        assert_eq!(calls.last().unwrap(), &format!("DELETE {path}"), "{query}");
        // The search asks for that machine's alone; every host at once.
        assert_eq!(calls[calls.len() - 2], search);
        assert_eq!(ds[1].stub.calls().last().unwrap(), search);
        assert!(!ds[1].stub.calls().iter().any(|c| c.starts_with("DELETE")));
    }
    // Held nowhere: not found, and no host is asked to delete.
    let (s, _, _) = call(
        &f.st,
        "DELETE",
        "/v1/machines/m_gone/backups/b1",
        "api",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // A host that cannot say what it holds fails a search no other host answers with its
    // answer: it may be the one. The host that lists the machine's backups is the one,
    // whatever another could not say. The stubs list all they hold whatever the filter, as a
    // host older than it does: the fleet reads the machine's alone.
    set_state(&f.st, "d1", "down");
    let (s, _, body) = call(
        &f.st,
        "DELETE",
        "/v1/machines/m_gone/backups/b1",
        "api",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(json(&body)["code"], "host_down");
    let (s, _, body) = call(&f.st, "DELETE", "/v1/machines/m_d2/backups/b1", "api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(
        ds[1].stub.calls().last().unwrap(),
        "DELETE /v1/machines/m_d2/backups/b1"
    );
    // Only a backup's path searches: anything else about a machine no host has is a 404.
    set_state(&f.st, "d1", "ready");
    let before = ds[0].stub.calls().len();
    let (s, _, _) = call(&f.st, "POST", "/v1/machines/m_d1/start", "api", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(!ds[0].stub.calls()[before..]
        .iter()
        .any(|c| c.starts_with("GET /v1/backups")));
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
    assert_eq!(pinned(&f.st, "t1"), None);
    // The host refused: the pin stays.
    let (s, _, body) = call(&f.st, "DELETE", "/v1/tenants/kept", "api", None).await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        json(&body)["code"],
        "busy",
        "the host's answer passes through"
    );
    assert_eq!(pinned(&f.st, "kept").as_deref(), Some("d1"));
    // A tenant the fleet never placed: nothing to do, no host asked.
    let before: Vec<usize> = ds.iter().map(|d| d.stub.calls().len()).collect();
    let (s, _, _) = call(&f.st, "DELETE", "/v1/tenants/nobody", "api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let after: Vec<usize> = ds.iter().map(|d| d.stub.calls().len()).collect();
    assert_eq!(before, after);
}

#[tokio::test]
async fn unpin_releases_a_tenant_without_asking_its_host() {
    let (f, ds) = fleet_with_daemons(2).await;
    ds[0].stub.add("kept", "db", 512);
    poll_static_hosts_once(&f.st).await;
    assert_eq!(pinned(&f.st, "kept").as_deref(), Some("d1"));
    set_state(&f.st, "d1", "down");
    let before: Vec<usize> = ds.iter().map(|d| d.stub.calls().len()).collect();
    let (s, _, body) = call(&f.st, "POST", "/v1/tenants/kept/unpin", "api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    let after: Vec<usize> = ds.iter().map(|d| d.stub.calls().len()).collect();
    assert_eq!(before, after, "no host asked, down or not");
    assert_eq!(pinned(&f.st, "kept"), None);
    assert_eq!(saved(&f.st).tenants.get("kept"), None, "written");
    // Its next machine is placed afresh: d1 is down, so on d2.
    let (s, headers, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("kept", "db-restored", 512)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d2");
    let (s, _, _) = call(&f.st, "POST", "/v1/tenants/nobody/unpin", "api", None).await;
    assert_eq!(
        s,
        StatusCode::NO_CONTENT,
        "unpinning what is not pinned is fine"
    );
}

#[tokio::test]
async fn endpoints_are_indexed_to_their_host_and_listed_whole() {
    let (f, ds) = fleet_with_daemons(2).await;
    let m1 = ds[0].stub.add("t1", "web", 512);
    let m2 = ds[1].stub.add("t2", "db", 512);
    // Opened through the fleet: indexed at once.
    let (s, headers, body) = call(
        &f.st,
        "POST",
        &format!("/v1/machines/{}/endpoints", m1.id),
        "api",
        Some(serde_json::json!({"port": 80})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d1");
    let e1: api::Endpoint = serde_json::from_str(&body).unwrap();
    assert_eq!(
        f.st.reg
            .lock()
            .unwrap()
            .endpoints
            .get(&e1.id)
            .map(String::as_str),
        Some("d1")
    );
    assert_eq!(
        saved(&f.st).endpoints.get(&e1.id).map(String::as_str),
        Some("d1")
    );
    // Opened elsewhere: the listing asks every host and learns.
    let e2 = ds[1].stub.add_endpoint(&m2.id);
    let (s, _, body) = call(&f.st, "GET", "/v1/endpoints", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let eps: Vec<api::Endpoint> = serde_json::from_str(&body).unwrap();
    let ids: Vec<&str> = eps.iter().map(|e| e.id.as_str()).collect();
    assert_eq!(ids, [e1.id.as_str(), e2.id.as_str()]);
    assert_eq!(
        f.st.reg
            .lock()
            .unwrap()
            .endpoints
            .get(&e2.id)
            .map(String::as_str),
        Some("d2")
    );
    // Indexed: a call goes to its host alone.
    let d1_before = ds[0].stub.calls().len();
    let (s, headers, body) = call(
        &f.st,
        "GET",
        &format!("/v1/endpoints/{}", e2.id),
        "api",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d2");
    assert_eq!(ds[0].stub.calls().len(), d1_before, "d1 was not asked");
    // Not indexed (a fleet restarted with an empty registry): found by asking each host.
    f.st.reg.lock().unwrap().endpoints.clear();
    let (s, headers, _) = call(
        &f.st,
        "DELETE",
        &format!("/v1/endpoints/{}", e2.id),
        "api",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(headers["x-briqyard-host"], "d2");
    assert_eq!(
        ds[0].stub.calls().last().unwrap(),
        &format!("GET /v1/endpoints/{}", e2.id),
        "the search asked d1 first"
    );
    assert_eq!(
        f.st.reg.lock().unwrap().endpoints.get(&e2.id),
        None,
        "a delete drops the entry"
    );
    let (s, _, body) = call(&f.st, "DELETE", "/v1/endpoints/ep_x", "api", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(json(&body)["error"], "endpoint ep_x not found");
    // The listing is never partial: a host down fails it, like machines.
    set_state(&f.st, "d2", "down");
    let (s, _, body) = call(&f.st, "GET", "/v1/endpoints", "api", None).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(json(&body)["code"], "host_down");
    set_state(&f.st, "d2", "ready");
    f.st.reg.lock().unwrap().hosts.get_mut("d2").unwrap().url = "http://127.0.0.1:1".into();
    let (s, _, body) = call(&f.st, "GET", "/v1/endpoints", "api", None).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(json(&body)["code"], "host_unreachable");
}

fn gateway_body() -> serde_json::Value {
    serde_json::json!({"image": "proxy:1", "port": 3128})
}

#[tokio::test]
async fn a_gateway_places_a_new_tenant_and_is_forwarded_to_its_host() {
    let (f, ds) = fleet_with_daemons(2).await;
    // d1 is the fuller: a new tenant's gateway goes to d2, as its first machine would.
    ds[0].stub.add("t0", "big", 50_000);
    poll_static_hosts_once(&f.st).await;
    let (s, headers, body) = call(
        &f.st,
        "PUT",
        "/v1/tenants/t1/gateway",
        "api",
        Some(gateway_body()),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d2");
    let t: api::Tenant = serde_json::from_str(&body).unwrap();
    assert_eq!(t.host, "d2", "the host is added to the body");
    assert_eq!(t.gateway.map(|g| g.port), Some(3128));
    assert_eq!(
        ds[1].stub.calls().last().unwrap(),
        "PUT /v1/tenants/t1/gateway"
    );
    assert_eq!(pinned(&f.st, "t1").as_deref(), Some("d2"));
    assert_eq!(
        saved(&f.st).tenants.get("t1").map(String::as_str),
        Some("d2")
    );
    assert_eq!(
        f.st.reg.lock().unwrap().hosts["d2"].used.memory_mb,
        256,
        "the gateway's size, reserved until the host reports"
    );
    // The tenant lives there now: its machines follow, its reads and removal go there.
    let (s, headers, _) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some(create_body("t1", "sbx", 512)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(headers["x-briqyard-host"], "d2");
    let (s, _, body) = call(&f.st, "GET", "/v1/tenants/t1", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let t: api::Tenant = serde_json::from_str(&body).unwrap();
    assert_eq!((t.host.as_str(), t.machines), ("d2", 1));
    assert!(t.gateway.is_some());
    assert_eq!(ds[1].stub.calls().last().unwrap(), "GET /v1/tenants/t1");
    let (s, _, body) = call(&f.st, "DELETE", "/v1/tenants/t1/gateway", "api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(
        ds[1].stub.calls().last().unwrap(),
        "DELETE /v1/tenants/t1/gateway"
    );
    // A tenant the fleet never placed: no host is asked.
    let before: Vec<usize> = ds.iter().map(|d| d.stub.calls().len()).collect();
    let (s, _, body) = call(&f.st, "GET", "/v1/tenants/nobody", "api", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(json(&body)["code"], "not_found");
    let (s, _, _) = call(&f.st, "DELETE", "/v1/tenants/nobody/gateway", "api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let after: Vec<usize> = ds.iter().map(|d| d.stub.calls().len()).collect();
    assert_eq!(before, after);
}

#[tokio::test]
async fn a_gateway_refused_is_answered_as_the_host_said() {
    let (f, ds) = fleet_with_daemons(1).await;
    // The host filled up since the fleet looked: the first gateway's pin goes with the refusal.
    ds[0].stub.add("t0", "big", 63_900);
    let (s, _, body) = call(
        &f.st,
        "PUT",
        "/v1/tenants/t1/gateway",
        "api",
        Some(gateway_body()),
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(json(&body)["code"], "capacity");
    assert_eq!(pinned(&f.st, "t1"), None);
    assert_eq!(saved(&f.st).tenants.get("t1"), None, "written");
    // A removal the host refuses passes through.
    ds[0].stub.add("kept", "sbx", 10);
    poll_static_hosts_once(&f.st).await;
    let (s, _, body) = call(&f.st, "DELETE", "/v1/tenants/kept/gateway", "api", None).await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");
    assert_eq!(json(&body)["code"], "gateway_in_use");
    // A bad tenant id or body is refused before any host.
    let before = ds[0].stub.calls().len();
    for (path, body) in [
        ("/v1/tenants/Bad/gateway", gateway_body()),
        (
            "/v1/tenants/t2/gateway",
            serde_json::json!({"image": "proxy:1"}),
        ),
    ] {
        let (s, _, text) = call(&f.st, "PUT", path, "api", Some(body)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{path}: {text}");
        assert_eq!(json(&text)["code"], "invalid");
    }
    assert_eq!(ds[0].stub.calls().len(), before);
    assert_eq!(pinned(&f.st, "t2"), None);
}

// --- events (ADR 0019) ---

#[tokio::test]
async fn a_scoped_read_goes_to_one_host_with_its_own_cursor() {
    let (f, ds) = fleet_with_daemons(2).await;
    ds[0].stub.add("t1", "web", 512);
    let m = ds[1].stub.add("t2", "db", 512);
    poll_static_hosts_once(&f.st).await;
    ds[0].stub.log(1, "t1", "created");
    ds[1].stub.log(2, "t2", "created");
    // A tenant's: its host alone, the query as it came, the host named.
    let (s, headers, body) = call(&f.st, "GET", "/v1/events?tenant=t1&since=0", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d1");
    let page: api::EventsPage = serde_json::from_str(&body).unwrap();
    assert_eq!((page.events.len(), page.next.as_str()), (1, "1"));
    assert_eq!(
        page.events[0].host, "",
        "one host's log: no host on each event"
    );
    assert_eq!(
        ds[0].stub.calls().last().unwrap(),
        "GET /v1/events?tenant=t1&since=0"
    );
    assert!(!ds[1]
        .stub
        .calls()
        .iter()
        .any(|c| c.starts_with("GET /v1/events")));
    // A machine's: found where it runs.
    let q = format!("/v1/events?machine={}", m.id);
    let (s, headers, _) = call(&f.st, "GET", &q, "api", None).await;
    assert_eq!(
        (s, &headers["x-briqyard-host"]),
        (StatusCode::OK, &HeaderValue::from_static("d2"))
    );
    // Neither known: 404, the way to a destroyed machine's events in the message.
    let (s, _, body) = call(&f.st, "GET", "/v1/events?tenant=nobody", "api", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{body}");
    let (s, _, body) = call(&f.st, "GET", "/v1/events?machine=m_gone", "api", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(
        json(&body)["error"]
            .as_str()
            .unwrap()
            .contains("?tenant=…&machine=m_gone"),
        "{body}"
    );
    // The host's refusal passes through: a cursor past its log.
    let (s, _, body) = call(&f.st, "GET", "/v1/events?tenant=t1&since=9", "api", None).await;
    assert_eq!(
        (s, json(&body)["code"].as_str()),
        (StatusCode::GONE, Some("gone"))
    );
}

#[tokio::test]
async fn a_fleet_wide_read_merges_every_host_by_time_and_is_never_partial() {
    let (f, ds) = fleet_with_daemons(2).await;
    ds[0].stub.log(1, "t1", "created");
    ds[1].stub.log(2, "t2", "created");
    ds[0].stub.log(3, "t1", "started");
    ds[1].stub.log(4, "t2", "started");
    ds[0].stub.log(5, "t1", "stopped");
    let (s, _, body) = call(&f.st, "GET", "/v1/events", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let page: api::EventsPage = serde_json::from_str(&body).unwrap();
    let got: Vec<(&str, u64)> = page
        .events
        .iter()
        .map(|e| (e.host.as_str(), e.seq))
        .collect();
    assert_eq!(got, [("d1", 1), ("d2", 1), ("d1", 2), ("d2", 2), ("d1", 3)]);
    assert_eq!(page.next, "d1:3,d2:2");
    // From that cursor: each host from its own seq; nothing new, the cursor stays.
    ds[1].stub.log(6, "t2", "stopped");
    let (s, _, body) = call(&f.st, "GET", "/v1/events?since=d1:3,d2:2", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let page: api::EventsPage = serde_json::from_str(&body).unwrap();
    assert_eq!(page.events.len(), 1);
    assert_eq!(
        (page.events[0].host.as_str(), page.next.as_str()),
        ("d2", "d1:3,d2:3")
    );
    assert_eq!(ds[0].stub.calls().last().unwrap(), "GET /v1/events?since=3");
    // A page past its limit: each host's cursor is its last event kept, nothing is skipped.
    let (_, _, body) = call(&f.st, "GET", "/v1/events?limit=3", "api", None).await;
    let page: api::EventsPage = serde_json::from_str(&body).unwrap();
    let got: Vec<(&str, u64)> = page
        .events
        .iter()
        .map(|e| (e.host.as_str(), e.seq))
        .collect();
    assert_eq!(got, [("d1", 1), ("d2", 1), ("d1", 2)]);
    assert_eq!(page.next, "d1:2,d2:1");
    assert_eq!(
        ds[1].stub.calls().last().unwrap(),
        "GET /v1/events?since=0&limit=3",
        "the rest of the query as it came"
    );
    let (_, _, body) = call(
        &f.st,
        "GET",
        &format!("/v1/events?since={}", page.next),
        "api",
        None,
    )
    .await;
    let page: api::EventsPage = serde_json::from_str(&body).unwrap();
    let got: Vec<(&str, u64)> = page
        .events
        .iter()
        .map(|e| (e.host.as_str(), e.seq))
        .collect();
    assert_eq!(got, [("d2", 2), ("d1", 3), ("d2", 3)]);
    // A cursor that is not the fleet's, and a watch of every host, are refused.
    for q in [
        "/v1/events?since=12",
        "/v1/events?since=d1:x",
        "/v1/events?watch=true",
    ] {
        let (s, _, body) = call(&f.st, "GET", q, "api", None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{q}: {body}");
        assert_eq!(json(&body)["code"], "invalid");
    }
    // A host down fails the whole read: events missing a host are a partial story.
    set_state(&f.st, "d2", "down");
    let (s, _, body) = call(&f.st, "GET", "/v1/events", "api", None).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(json(&body)["code"], "host_down");
}

/// The next chunk of a stream, one line here, as JSON.
async fn chunk(w: &mut reqwest::Response) -> serde_json::Value {
    let c = tokio::time::timeout(std::time::Duration::from_secs(5), w.chunk())
        .await
        .expect("a line in time")
        .unwrap()
        .expect("open");
    json(std::str::from_utf8(&c).unwrap().trim())
}

#[tokio::test]
async fn a_scoped_watch_is_streamed_through_as_it_comes() {
    let (f, ds) = fleet_with_daemons(1).await;
    ds[0].stub.add("t1", "web", 512);
    poll_static_hosts_once(&f.st).await;
    ds[0].stub.log(1, "t1", "created");
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", ln.local_addr().unwrap());
    let app = app(f.st.clone());
    tokio::spawn(async move { axum::serve(ln, app).await.unwrap() });
    let mut w = reqwest::Client::new()
        .get(format!("{url}/v1/events?tenant=t1&watch=true"))
        .bearer_auth("api")
        .send()
        .await
        .unwrap();
    assert_eq!(w.status(), StatusCode::OK);
    assert_eq!(w.headers()["content-type"], "application/x-ndjson");
    assert_eq!(w.headers()["x-briqyard-host"], "d1");
    assert_eq!(chunk(&mut w).await["reason"], "created");
    // The host's next line reaches the client while the stream stays open.
    let live = serde_json::to_string(&ds[0].stub.log(2, "t1", "started")).unwrap() + "\n";
    let tx = ds[0].stub.watcher.lock().unwrap().clone().unwrap();
    tx.send(live).await.unwrap();
    assert_eq!(chunk(&mut w).await["reason"], "started");
}

#[tokio::test]
async fn if_match_is_passed_to_the_host() {
    let (f, ds) = fleet_with_daemons(1).await;
    let m = ds[0].stub.add("t1", "web", 512);
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/v1/machines/{}/start", m.id))
        .header(header::AUTHORIZATION, "Bearer api")
        .header(header::IF_MATCH, "7")
        .body(Body::empty())
        .unwrap();
    let resp = app(f.st.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // To the call it was sent with, not to the search for the machine's host before it.
    assert_eq!(*ds[0].stub.if_match.lock().unwrap(), ["7"]);
}

// --- TLS to the hosts (ADR 0020) ---

fn certificate() -> (rcgen::CertifiedKey, String) {
    let c = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let fp = api::tls::fingerprint(c.cert.der());
    (c, fp)
}

#[tokio::test]
async fn an_added_host_is_pinned_at_bootstrap_then_forwarded_to_over_tls() {
    let (cert, fp) = certificate();
    let d = start_daemon_on("d1", "tok", Some(&cert)).await;
    assert!(d.url.starts_with("https://127.0.0.1:"));
    let f = fleet(config::Config::default());
    {
        let mut added = static_host(&config::StaticHost::default(), Utc::now());
        added.id = "h_srv-9".into();
        added.url = d.url.clone();
        added.state = "provisioning".into();
        added.provider = "manual".into();
        added.token = "tok".into();
        f.st.reg
            .lock()
            .unwrap()
            .hosts
            .insert(added.id.clone(), added);
    }
    let mut hb = heartbeat(&d.url, 64_000, &[]);
    hb["tls_fingerprint"] = fp.clone().into();
    // The daemon is up before the bootstrap has read its certificate: not taken on its word.
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/register", "tok", Some(hb.clone())).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(json(&body)["code"], "tls_mismatch");
    assert!(json(&body)["error"]
        .as_str()
        .unwrap()
        .contains("no fingerprint is pinned"));
    assert_eq!(hosts(&f.st)[0].state, "provisioning");
    // The bootstrap pins it; the next heartbeat makes the host ready.
    {
        let mut reg = f.st.reg.lock().unwrap();
        let r = reg.hosts.get_mut("h_srv-9").unwrap();
        bootstrap::bootstrapped(r, "bootstrapped".into(), fp.clone());
    }
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/register", "tok", Some(hb.clone())).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
    let h = &hosts(&f.st)[0];
    assert_eq!(
        (h.state.as_str(), h.tls_fingerprint.as_str()),
        ("ready", fp.as_str())
    );
    assert_eq!(saved(&f.st).hosts["h_srv-9"].tls_fingerprint, fp, "written");
    // A create is forwarded over TLS, to the pinned certificate.
    let (s, headers, body) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "",
        Some(create_body("t1", "web", 512)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert_eq!(headers["x-briqyard-host"], "h_srv-9");
    assert_eq!(d.stub.calls(), ["POST /v1/machines"]);
    // Another machine at that address: refused, the pin kept.
    let (_, other) = certificate();
    hb["tls_fingerprint"] = other.clone().into();
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/register", "tok", Some(hb)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
    let why = json(&body)["error"].as_str().unwrap().to_string();
    assert!(
        why.starts_with(&format!("certificate {other} is not the one pinned ({fp})")),
        "{why}"
    );
    assert_eq!(hosts(&f.st)[0].tls_fingerprint, fp);
}

#[tokio::test]
async fn a_host_presenting_another_certificate_is_not_forwarded_to() {
    let (served, _) = certificate();
    let (_, pinned) = certificate();
    let d = start_daemon_on("d1", "tok", Some(&served)).await;
    d.stub.add("t1", "web", 512);
    let f = fleet(config::Config {
        hosts: vec![config::StaticHost {
            id: "d1".into(),
            url: d.url.clone(),
            token: "tok".into(),
            tls_fingerprint: pinned.clone(),
            ..Default::default()
        }],
        ..Default::default()
    });
    let (s, _, body) = call(&f.st, "GET", "/v1/machines", "", None).await;
    assert_eq!(s, StatusCode::BAD_GATEWAY, "{body}");
    let v = json(&body);
    assert_eq!(v["code"], "host_unreachable");
    let why = v["error"].as_str().unwrap();
    assert!(
        why.contains(&format!("is not the pinned {pinned}")),
        "{why}"
    );
    assert!(
        d.stub.calls().is_empty(),
        "no request reached it, token included"
    );
    // The poll asks it nothing either: its capacity stays unknown.
    poll_static_hosts_once(&f.st).await;
    assert_eq!(hosts(&f.st)[0].capacity.memory_mb, 0);
    assert!(d.stub.calls().is_empty());
}

// --- placement by region, labels, quotas, logs follow (ADR 0025) ---

fn in_region(tenant: &str, name: &str, region: &str) -> serde_json::Value {
    let mut b = create_body(tenant, name, 512);
    b["region"] = region.into();
    b
}

#[tokio::test]
async fn a_tenant_is_placed_in_its_region_and_never_leaves_it() {
    let (f, ds) = fleet_in_regions(&["gra", "vin"]).await;
    // d1 is fuller: by memory alone, t1 would go to d2.
    ds[0].stub.add("t0", "big", 10_000);
    poll_static_hosts_once(&f.st).await;
    let create = |body| call(&f.st, "POST", "/v1/machines", "api", Some(body));
    let (s, headers, body) = create(in_region("t1", "a", "gra")).await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d1");
    assert_eq!(f.st.reg.lock().unwrap().region_of("t1"), Some("gra"));
    // Its next machine in another region: refused before any host is asked.
    let before: Vec<usize> = ds.iter().map(|d| d.stub.calls().len()).collect();
    let (s, _, body) = create(in_region("t1", "b", "vin")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["code"], "invalid");
    assert_eq!(
        json(&body)["error"],
        "tenant t1 is in region \"gra\" (host d1), not \"vin\": a tenant never spans regions"
    );
    // A fork is bound to its source's host, so to its region.
    let src = json(&create(in_region("t1", "c", "")).await.2)["id"]
        .as_str()
        .unwrap()
        .to_string();
    let mut fork = in_region("t1", "f", "vin");
    fork["fork"] = serde_json::json!({ "machine_id": src });
    let (s, _, body) = create(fork).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    let after: Vec<usize> = ds.iter().map(|d| d.stub.calls().len()).collect();
    assert_eq!(after[1], before[1], "d2 was never asked");
    // No region: any, and a pinned tenant stays.
    let (s, headers, _) = create(in_region("t2", "a", "")).await;
    assert_eq!(
        (s, &headers["x-briqyard-host"]),
        (StatusCode::CREATED, &HeaderValue::from_static("d2"))
    );
    // A region with no host: 503, naming it.
    let (s, _, body) = create(in_region("t3", "a", "sgp")).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(json(&body)["code"], "capacity");
    assert_eq!(
        json(&body)["error"],
        "no host in region sgp has room for this machine"
    );
    assert_eq!(pinned(&f.st, "t3"), None);
    // The tenants say where they are.
    let (_, _, body) = call(&f.st, "GET", "/v1/tenants", "api", None).await;
    let ts: Vec<api::Tenant> = serde_json::from_str(&body).unwrap();
    let t1 = ts.iter().find(|t| t.id == "t1").unwrap();
    assert_eq!((t1.host.as_str(), t1.region.as_str()), ("d1", "gra"));
    let (_, _, body) = call(&f.st, "GET", "/v1/tenants/t1", "api", None).await;
    assert_eq!(json(&body)["region"], "gra");
    // A gateway places a new tenant in the region its query names.
    let (s, headers, body) = call(
        &f.st,
        "PUT",
        "/v1/tenants/t4/gateway?region=vin",
        "api",
        Some(gateway_body()),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d2");
    assert_eq!(
        ds[1].stub.calls().last().unwrap(),
        "PUT /v1/tenants/t4/gateway",
        "where to place is the fleet's: the host gets the spec"
    );
}

#[tokio::test]
async fn a_quota_goes_to_the_tenants_host_and_places_a_new_one() {
    let (f, ds) = fleet_in_regions(&["gra", "vin"]).await;
    let quota = serde_json::json!({"machines": 3, "memory_mb": 2048});
    // No host yet: placed in the region asked, with no need, and forwarded there.
    let (s, headers, body) = call(
        &f.st,
        "PUT",
        "/v1/tenants/t1/quota?region=vin",
        "api",
        Some(quota.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(headers["x-briqyard-host"], "d2");
    assert_eq!(pinned(&f.st, "t1").as_deref(), Some("d2"));
    assert_eq!(
        saved(&f.st).tenants.get("t1").map(String::as_str),
        Some("d2")
    );
    assert_eq!(f.st.reg.lock().unwrap().hosts["d2"].used.memory_mb, 0);
    let (s, _, body) = call(&f.st, "GET", "/v1/tenants/t1/quota", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let q: api::TenantQuota = serde_json::from_str(&body).unwrap();
    assert_eq!((q.quota.machines, q.quota.memory_mb), (Some(3), Some(2048)));
    assert_eq!(
        ds[1].stub.calls().last().unwrap(),
        "GET /v1/tenants/t1/quota"
    );
    // Pinned: the next put goes to its host, and another region is refused.
    let (s, _, _) = call(
        &f.st,
        "PUT",
        "/v1/tenants/t1/quota",
        "api",
        Some(quota.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(ds[1].stub.quotas.lock().unwrap().len(), 2);
    let (s, _, body) = call(
        &f.st,
        "PUT",
        "/v1/tenants/t1/quota?region=gra",
        "api",
        Some(quota),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    // A body that is not a quota is refused before anything is placed; a tenant with no host
    // has no quota to read.
    let (s, _, _) = call(
        &f.st,
        "PUT",
        "/v1/tenants/t2/quota",
        "api",
        Some(serde_json::json!({"machines": -1})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(pinned(&f.st, "t2"), None);
    let (s, _, _) = call(&f.st, "GET", "/v1/tenants/t2/quota", "api", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(ds[0].stub.quotas.lock().unwrap().is_empty());
}

#[tokio::test]
async fn labels_are_passed_to_the_hosts_and_a_listing_stays_whole() {
    let (f, ds) = fleet_with_daemons(2).await;
    let label = |d: &Running, tenant: &str, name: &str, app: &str| {
        let mut m = d.stub.add(tenant, name, 256);
        m.metadata.insert("app".into(), app.into());
        let mut ms = d.stub.machines.lock().unwrap();
        *ms.iter_mut().find(|x| x.id == m.id).unwrap() = m.clone();
        m
    };
    let web1 = label(&ds[0], "t1", "web", "web");
    label(&ds[0], "t1", "db", "db");
    let web2 = label(&ds[1], "t2", "web", "web");
    poll_static_hosts_once(&f.st).await;
    let ids = |body: &str| -> Vec<String> {
        let ms: Vec<api::Machine> = serde_json::from_str(body).unwrap();
        ms.into_iter().map(|m| m.id).collect()
    };
    // Every host, the query as it came.
    let (s, _, body) = call(&f.st, "GET", "/v1/machines?label=app%3Dweb", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(ids(&body), [web1.id.as_str(), web2.id.as_str()]);
    for d in &ds {
        assert_eq!(
            d.stub.calls().last().unwrap(),
            "GET /v1/machines?label=app%3Dweb"
        );
    }
    // A tenant's: its host alone.
    let before = ds[1].stub.calls().len();
    let (_, _, body) = call(
        &f.st,
        "GET",
        "/v1/machines?tenant=t1&label=app=web&label=app",
        "api",
        None,
    )
    .await;
    assert_eq!(ids(&body), [web1.id.as_str()]);
    assert_eq!(ds[1].stub.calls().len(), before);
    // One host down: the selection fails whole, as any listing.
    set_state(&f.st, "d2", "down");
    let (s, _, body) = call(&f.st, "GET", "/v1/machines?label=app", "api", None).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(json(&body)["code"], "host_down");
}

#[tokio::test]
async fn a_logs_follow_is_streamed_through_as_it_comes() {
    let (f, ds) = fleet_with_daemons(1).await;
    let m = ds[0].stub.add("t1", "web", 512);
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", ln.local_addr().unwrap());
    let app = app(f.st.clone());
    tokio::spawn(async move { axum::serve(ln, app).await.unwrap() });
    let mut w = reqwest::Client::new()
        .get(format!(
            "{url}/v1/machines/{}/logs?since=12&follow=true",
            m.id
        ))
        .bearer_auth("api")
        .send()
        .await
        .unwrap();
    assert_eq!(w.status(), StatusCode::OK);
    assert_eq!(w.headers()["content-type"], "application/x-ndjson");
    assert_eq!(w.headers()["x-briqyard-host"], "d1");
    assert_eq!(
        ds[0].stub.calls().last().unwrap(),
        &format!("GET /v1/machines/{}/logs?since=12&follow=true", m.id)
    );
    // Each line the host sends reaches the client while the stream stays open.
    let tx = ds[0].stub.watcher.lock().unwrap().clone().unwrap();
    for line in ["one", "two"] {
        let l = serde_json::json!({"ts": "2026-10-21T10:00:00Z", "line": line});
        tx.send(l.to_string() + "\n").await.unwrap();
        assert_eq!(chunk(&mut w).await["line"], line);
    }
}

// --- drain, undrain, upgrade (ADR 0027) ---

#[tokio::test]
async fn a_drained_host_is_never_forgotten_and_undrains() {
    let f = fleet(config::Config::default());
    seed(&f.st, "h_a", 64_000, 0, 0, &[]);
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/h_a/drain", "", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(
        f.st.reg.lock().unwrap().retirable().is_empty(),
        "an empty drained host is kept: only a retire forgets"
    );
    // A heartbeat keeps the drain.
    let h = f.st.reg.lock().unwrap().hosts["h_a"].clone();
    f.st.reg.lock().unwrap().heartbeat(h, Utc::now());
    assert_eq!(hosts(&f.st)[0].state, "draining");
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/h_a/undrain", "", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(hosts(&f.st)[0].state, "ready");
    // Undrain of a ready host, or of one that is not there.
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/h_a/undrain", "", None).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(json(&body)["error"], "host h_a is ready");
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/h_x/undrain", "", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // A retire is undone the same way, before the host empties.
    seed(&f.st, "h_b", 64_000, 0, 1, &["t1"]);
    call(&f.st, "POST", "/v1/hosts/h_b/retire", "", None).await;
    assert_eq!(f.st.reg.lock().unwrap().hosts["h_b"].state, "retiring");
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/h_b/undrain", "", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(f.st.reg.lock().unwrap().hosts["h_b"].state, "ready");
}

/// A fleet whose SSH key is a file that exists, so an upgrade gets past its own checks (the
/// key is only read by `ssh`).
fn fleet_with_key() -> Fleet {
    let mut cfg = config::Config::default();
    cfg.bootstrap.ssh_key = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml").into();
    fleet(cfg)
}

#[tokio::test]
async fn an_upgrade_refuses_what_it_cannot_do() {
    let up = |r: &str| Some(serde_json::json!({ "release": r }));
    // No SSH key: nothing can be installed. Named, not the default: a dev VM has that one.
    let mut cfg = config::Config::default();
    cfg.bootstrap.ssh_key = "/nonexistent/briqyard-fleet-key".into();
    let f = fleet(cfg);
    seed(&f.st, "h_a", 64_000, 0, 0, &[]);
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/h_a/upgrade", "", up("0.2.0")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(
        json(&body)["error"]
            .as_str()
            .unwrap()
            .contains("(bootstrap.ssh_key)"),
        "{body}"
    );
    let f = fleet_with_key();
    seed(&f.st, "h_a", 64_000, 0, 0, &[]);
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/h_a/upgrade", "", up("latest")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(
        json(&body)["error"],
        "release \"latest\": a URL, or a version such as 0.2.0"
    );
    let (s, _, _) = call(&f.st, "POST", "/v1/hosts/h_x/upgrade", "", up("0.2.0")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    for state in ["down", "retiring", "provisioning", "upgrading"] {
        set_state(&f.st, "h_a", state);
        let (s, _, body) = call(&f.st, "POST", "/v1/hosts/h_a/upgrade", "", up("0.2.0")).await;
        assert_eq!(s, StatusCode::CONFLICT, "{state}");
        assert!(
            json(&body)["error"].as_str().unwrap().contains(state),
            "{body}"
        );
    }
    // One at a time: while another upgrade holds the turn, nothing moves.
    set_state(&f.st, "h_a", "ready");
    let _turn = f.st.upgrade.clone().try_lock_owned().unwrap();
    let (s, _, body) = call(&f.st, "POST", "/v1/hosts/h_a/upgrade", "", up("0.2.0")).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(
        json(&body)["error"],
        "another host is upgrading: one at a time"
    );
    assert_eq!(hosts(&f.st)[0].state, "ready");
    // An upgrading host's state is the upgrade's: no drain, undrain or retire meanwhile.
    set_state(&f.st, "h_a", "upgrading");
    for op in ["drain", "undrain", "retire"] {
        let (s, _, _) = call(&f.st, "POST", &format!("/v1/hosts/h_a/{op}"), "", None).await;
        assert_eq!(s, StatusCode::CONFLICT, "{op}");
    }
    // And a heartbeat keeps it.
    let h = f.st.reg.lock().unwrap().hosts["h_a"].clone();
    f.st.reg.lock().unwrap().heartbeat(h, Utc::now());
    assert_eq!(hosts(&f.st)[0].state, "upgrading");
}

#[tokio::test]
async fn an_upgrade_waits_for_a_new_start_of_the_version_installed() {
    let f = fleet_with_key();
    seed(&f.st, "h_a", 64_000, 0, 1, &["t1"]);
    let before = Utc::now() - Duration::minutes(5);
    let beat = |version: &str, started: Option<api::DaemonStart>| {
        let mut h = f.st.reg.lock().unwrap().hosts["h_a"].clone();
        h.version = version.into();
        h.started = started;
        f.st.reg.lock().unwrap().heartbeat(h, Utc::now());
    };
    let start = |at, adopted, stopped, gone| {
        Some(api::DaemonStart {
            at,
            adopted,
            stopped,
            gone,
        })
    };
    let wait = |ms| {
        upgrade::come_back(
            &f.st,
            "h_a",
            Some(before),
            "0.2.0+b",
            std::time::Duration::from_millis(ms),
        )
    };
    // The old daemon still answering, or a new one of another build: not yet.
    beat("0.1.0+a", start(before, 0, 0, 0));
    let err = wait(600).await.unwrap_err();
    assert_eq!(err, "no heartbeat from a new start of 0.2.0+b within 0 s");
    beat("0.2.0+b", start(before, 0, 0, 0));
    assert!(wait(600).await.is_err(), "the same start is not a new one");
    // A daemon older than ADR 0027 reports no start: never the one installed.
    beat("0.2.0+b", None);
    assert!(wait(600).await.is_err(), "no start is not a new one");
    // The new start, which adopted the machine; one whose process had exited meanwhile is gone,
    // not a failure.
    let now = Utc::now();
    beat("0.2.0+b", start(now, 1, 0, 1));
    let started = wait(600).await.unwrap();
    assert_eq!((started.at, started.adopted, started.gone), (now, 1, 1));
    // One that stopped a machine it could not take over fails the upgrade.
    beat("0.2.0+b", start(now, 1, 2, 0));
    let err = wait(600).await.unwrap_err();
    assert_eq!(
        err,
        "0.2.0+b started and stopped 2 machines it could not take over (1 adopted)"
    );
}

#[tokio::test]
async fn an_upgrade_ends_in_the_hosts_state_or_drained() {
    let f = fleet_with_key();
    seed(&f.st, "h_a", 64_000, 0, 0, &[]);
    let was = f.st.reg.lock().unwrap().hosts["h_a"].clone();
    set_state(&f.st, "h_a", "upgrading");
    let started = api::DaemonStart {
        at: Utc::now(),
        adopted: 3,
        stopped: 0,
        gone: 0,
    };
    let h = upgrade::finish(&f.st, &was, "file:///r", Ok(("0.2.0+b".into(), started)))
        .await
        .unwrap();
    assert_eq!(h.state, "ready");
    assert!(h.note.starts_with("upgraded to 0.2.0+b at "), "{}", h.note);
    assert!(h.note.ends_with("; machines handed over: 3"), "{}", h.note);
    // A failure leaves it drained, the reason in its note, whatever it was before.
    set_state(&f.st, "h_a", "upgrading");
    let err = upgrade::finish(
        &f.st,
        &was,
        "file:///r",
        Err("install: ssh exited 255".into()),
    )
    .await
    .unwrap_err();
    assert_eq!(err, "install: ssh exited 255");
    let h = &hosts(&f.st)[0];
    assert_eq!(h.state, "draining");
    assert!(
        h.note.starts_with("upgrade to file:///r failed at "),
        "{}",
        h.note
    );
    assert!(
        h.note
            .ends_with(": install: ssh exited 255; undrain once it is fixed"),
        "{}",
        h.note
    );
    // A fleet that stopped during an upgrade finds the host drained at its start.
    set_state(&f.st, "h_a", "upgrading");
    upgrade::interrupted(&mut f.st.reg.lock().unwrap());
    let h = &hosts(&f.st)[0];
    assert_eq!(h.state, "draining");
    assert!(
        h.note
            .ends_with("interrupted by a fleet restart; undrain once checked"),
        "{}",
        h.note
    );
}

#[tokio::test]
async fn a_heartbeat_carries_the_daemons_start() {
    let f = fleet(config::Config::default());
    let mut h = static_host(
        &config::StaticHost {
            id: "h_a".into(),
            url: "http://10.0.0.1:7420".into(),
            ..Default::default()
        },
        Utc::now(),
    );
    h.started = Some(api::DaemonStart {
        at: Utc::now(),
        adopted: 4,
        stopped: 1,
        gone: 2,
    });
    f.st.reg.lock().unwrap().heartbeat(h.clone(), Utc::now());
    assert_eq!(hosts(&f.st)[0].started, h.started);
}

// --- exec sessions (ADR 0029) ---

/// The fleet on a port of its own: an upgrade needs a real connection.
async fn serve_fleet(f: &Fleet) -> String {
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    let app = app(f.st.clone());
    tokio::spawn(async move { axum::serve(ln, app).await.unwrap() });
    addr.to_string()
}

#[tokio::test]
async fn a_session_is_relayed_unchanged_to_the_machines_host() {
    use api::session::{channel, message, parse};
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};
    let (f, ds) = fleet_with_daemons(2).await;
    let m = ds[1].stub.add("t1", "sbx", 512);
    let addr = serve_fleet(&f).await;
    let mut req = format!("ws://{addr}/v1/machines/{}/exec?cmd=sh&tty=true", m.id)
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("authorization", "Bearer api".parse().unwrap());
    let tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let (mut ws, resp) = tokio_tungstenite::client_async(req, tcp).await.unwrap();
    assert_eq!(resp.headers()["x-briqyard-host"], "d2");
    // The handshake reached the machine's host, with its query and the host's token.
    assert_eq!(
        ds[1].stub.calls().last().unwrap(),
        &format!("GET /v1/machines/{}/exec?cmd=sh&tty=true", m.id)
    );
    ws.send(Message::Binary(message(channel::STDIN, b"hi\n")))
        .await
        .unwrap();
    let Some(Ok(Message::Binary(b))) = ws.next().await else {
        panic!("no echo")
    };
    assert_eq!(parse(&b), Some((channel::STDOUT, &b"hi\n"[..])));
    ws.send(Message::Binary(message(channel::CLOSE, &[channel::STDIN])))
        .await
        .unwrap();
    let Some(Ok(Message::Binary(b))) = ws.next().await else {
        panic!("no exit")
    };
    assert_eq!(parse(&b), Some((channel::EXIT, &br#"{"exit_code":7}"#[..])));
}

#[tokio::test]
async fn a_session_refused_by_the_host_or_not_a_websocket_is_an_answer() {
    let (f, ds) = fleet_with_daemons(1).await;
    let m = ds[0].stub.add("t1", "sbx", 512);
    let addr = serve_fleet(&f).await;
    let http = reqwest::Client::new();
    // Not an upgrade: refused by the fleet, before any host is asked.
    let r = http
        .get(format!("http://{addr}/v1/machines/{}/exec?cmd=sh", m.id))
        .bearer_auth("api")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(&r.text().await.unwrap())["code"], "invalid");
    // A machine no host has: 404, as for every machine route.
    let upgrade = |url: String| {
        http.get(url)
            .bearer_auth("api")
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .send()
    };
    let r = upgrade(format!("http://{addr}/v1/machines/m_none/exec?cmd=sh"))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    // The host's refusal comes back as it said it.
    ds[0].stub.machines.lock().unwrap()[0].state = api::state::STOPPED.into();
    let r = upgrade(format!("http://{addr}/v1/machines/{}/exec?cmd=sh", m.id))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(r.headers()["x-briqyard-host"], "d1");
    assert_eq!(json(&r.text().await.unwrap())["code"], "not_running");
}

#[tokio::test]
async fn a_host_unreachable_never_shows_the_sessions_query() {
    // The query holds the session's env: an error names the host, never the URL.
    let (f, ds) = fleet_with_daemons(1).await;
    let m = ds[0].stub.add("t1", "sbx", 512);
    f.st.reg
        .lock()
        .unwrap()
        .machines
        .insert(m.id.clone(), "d1".into());
    f.st.reg.lock().unwrap().hosts.get_mut("d1").unwrap().url = "http://127.0.0.1:1".into();
    let addr = serve_fleet(&f).await;
    let r = reqwest::Client::new()
        .get(format!(
            "http://{addr}/v1/machines/{}/exec?cmd=sh&env=TOKEN=hunter2",
            m.id
        ))
        .bearer_auth("api")
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_GATEWAY);
    let body = r.text().await.unwrap();
    assert_eq!(json(&body)["code"], "host_unreachable");
    assert!(
        !body.contains("hunter2") && !body.contains("exec?"),
        "{body}"
    );
}

/// A create with `restore` opens that restore for its host while the forward lasts, and closes
/// it after: a backup's key is asked for during the create, never after it (ADR 0035).
#[tokio::test]
async fn a_forwarded_restore_is_open_during_its_create_alone() {
    let (f, ds) = fleet_with_daemons(1).await;
    let rs = api::RestoreSpec {
        machine_id: "m_src".into(),
        backup: "b1".into(),
    };
    let restore = |name: &str| {
        let mut body = create_body("t1", name, 256);
        body["restore"] = serde_json::to_value(&rs).unwrap();
        Some(body)
    };
    let seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let (st, seen, rs) = (f.st.clone(), seen.clone(), rs.clone());
        *ds[0].stub.on_create.lock().unwrap() = Some(Box::new(move || {
            let open = st.restores.take("d1", &rs, std::time::Instant::now());
            seen.store(open, Ordering::SeqCst);
        }));
    }
    let (s, _, body) = call(&f.st, "POST", "/v1/machines", "api", restore("r1")).await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert!(seen.load(Ordering::SeqCst), "open while the host made it");
    // A forward that never asked: closed once it is over.
    *ds[0].stub.on_create.lock().unwrap() = None;
    let (s, _, body) = call(&f.st, "POST", "/v1/machines", "api", restore("r2")).await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert!(
        !f.st.restores.take("d1", &rs, std::time::Instant::now()),
        "closed after"
    );
}
