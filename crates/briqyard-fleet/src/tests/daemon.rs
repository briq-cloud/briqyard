//! A stub daemon: answers the few routes the fleet asks and records what was asked.

use super::*;

/// What a stub daemon hands out, like the fleet's capacity figure for it.
pub(super) const DAEMON_MEMORY_MB: u32 = 64_000;

pub(super) struct Daemon {
    pub(super) id: String,
    pub(super) token: String,
    pub(super) calls: Mutex<Vec<String>>,
    pub(super) machines: Mutex<Vec<api::Machine>>,
    pub(super) endpoints: Mutex<Vec<api::Endpoint>>,
    /// Namespaces' gateways: the namespace and the memory it takes.
    pub(super) gateways: Mutex<Vec<(String, u32)>>,
    pub(super) next: AtomicUsize,
    /// A namespace the daemon refuses to delete (answers 409), to test a failed forward.
    pub(super) keep_namespace: String,
    /// Its event log, and the `If-Match` of each request that had one.
    pub(super) events: Mutex<Vec<api::Event>>,
    pub(super) if_match: Mutex<Vec<String>>,
    /// The open watch's sender: a test sends its live lines.
    pub(super) watcher: Mutex<Option<tokio::sync::mpsc::Sender<String>>>,
    /// Its certificate's, when it serves TLS.
    pub(super) tls_fingerprint: String,
    /// What its status reports (ADR 0021).
    pub(super) conditions: Mutex<Vec<api::Condition>>,
    /// Namespaces' quotas (ADR 0025).
    pub(super) quotas: Mutex<Vec<(String, api::Quota)>>,
    /// Run by a create before it answers: a test's look at the fleet mid-forward.
    pub(super) on_delete_namespace: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    pub(super) create_finished: Mutex<Option<Arc<tokio::sync::Notify>>>,
    pub(super) move_gate: Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
    pub(super) move_finished: Mutex<Option<Arc<tokio::sync::Notify>>>,
    pub(super) create_gate: Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
    pub(super) on_create: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    pub(super) creates: Mutex<Vec<api::CreateMachineRequest>>,
    pub(super) egress_siblings: std::sync::atomic::AtomicBool,
    pub(super) sandbox_lookup: Mutex<Option<(StatusCode, serde_json::Value)>>,
    pub(super) sandbox_lookups: Mutex<Vec<api::SandboxRequestLookup>>,
    pub(super) snapshots: Mutex<Vec<api::Snapshot>>,
    pub(super) backup_records: Mutex<Vec<serde_json::Value>>,
}

impl Daemon {
    pub(super) fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    pub(super) fn machine(&self, namespace: &str, name: &str, memory_mb: u32) -> api::Machine {
        let n = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        let now = Utc::now();
        api::Machine {
            id: format!("m_{}_{n}", self.id),
            namespace: namespace.into(),
            name: name.into(),
            image: "nginx".into(),
            state: api::state::RUNNING.into(),
            ip: format!("10.1.0.{n}"),
            hostname: format!("{name}.internal"),
            size: api::Size {
                vcpus: 1,
                memory_mb,
                cpu_millis: None,
            },
            sleep: "30m".into(),
            created_at: now,
            updated_at: now,
            ..Default::default()
        }
    }

    /// Adds a machine as if it had been created on this daemon.
    pub(super) fn add(&self, namespace: &str, name: &str, memory_mb: u32) -> api::Machine {
        let m = self.machine(namespace, name, memory_mb);
        self.machines.lock().unwrap().push(m.clone());
        m
    }

    /// Adds an endpoint as if it had been opened on this daemon.
    pub(super) fn add_endpoint(&self, machine_id: &str) -> api::Endpoint {
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

    /// Logs an event at `at` (seconds past 14:00), about a machine of a namespace.
    pub(super) fn log(&self, at: u32, namespace: &str, reason: &str) -> api::Event {
        let mut evs = self.events.lock().unwrap();
        let e = api::Event {
            seq: evs.len() as u64 + 1,
            at: Utc.with_ymd_and_hms(2026, 10, 20, 14, 0, 0).unwrap()
                + Duration::seconds(at as i64),
            kind: api::event::NORMAL.into(),
            reason: reason.into(),
            message: String::new(),
            machine_id: format!("m_{}_{}", self.id, evs.len() + 1),
            namespace: namespace.into(),
            host: String::new(),
            data: None,
            count: 1,
            first_at: None,
        };
        evs.push(e.clone());
        e
    }

    pub(super) fn used_mb(&self) -> u32 {
        self.machines
            .lock()
            .unwrap()
            .iter()
            .map(|m| m.size.memory_mb)
            .sum()
    }
}

/// A daemon on loopback: its URL and the stub behind it.
pub(super) struct Running {
    pub(super) url: String,
    pub(super) stub: Arc<Daemon>,
}

pub(super) async fn start_daemon(id: &str, token: &str) -> Running {
    start_daemon_on(id, token, None).await
}

/// A stub daemon serving TLS with `cert` when given, as a daemon off loopback does.
pub(super) async fn start_daemon_on(
    id: &str,
    token: &str,
    cert: Option<&rcgen::CertifiedKey>,
) -> Running {
    let stub = Arc::new(Daemon {
        id: id.into(),
        token: token.into(),
        calls: Mutex::new(vec![]),
        machines: Mutex::new(vec![]),
        endpoints: Mutex::new(vec![]),
        gateways: Mutex::new(vec![]),
        next: AtomicUsize::new(0),
        keep_namespace: "kept".into(),
        events: Mutex::new(vec![]),
        if_match: Mutex::new(vec![]),
        watcher: Mutex::new(None),
        tls_fingerprint: cert
            .map(|c| api::tls::fingerprint(c.cert.der()))
            .unwrap_or_default(),
        conditions: Mutex::new(vec![]),
        quotas: Mutex::new(vec![]),
        on_delete_namespace: Mutex::new(None),
        create_finished: Mutex::new(None),
        move_gate: Mutex::new(None),
        move_finished: Mutex::new(None),
        create_gate: Mutex::new(None),
        on_create: Mutex::new(None),
        creates: Mutex::new(vec![]),
        egress_siblings: std::sync::atomic::AtomicBool::new(true),
        sandbox_lookup: Mutex::new(None),
        sandbox_lookups: Mutex::new(vec![]),
        snapshots: Mutex::new(vec![]),
        backup_records: Mutex::new(vec![]),
    });
    type D = State<Arc<Daemon>>;
    async fn status(State(d): D) -> Json<api::Status> {
        let ms = d.machines.lock().unwrap();
        Json(api::Status {
            egress_siblings_v1: d.egress_siblings.load(Ordering::SeqCst),
            named_memory_fork_v1: false,
            named_memory_profiles: Vec::new(),
            warm_pool_profiles: Vec::new(),
            version: "0.1-stub".into(),
            host_id: d.id.clone(),
            capacity: api::Capacity {
                memory_mb: DAEMON_MEMORY_MB,
                vcpus: 32,
                cpu_millis: Some(32_000),
            },
            used: api::Capacity {
                memory_mb: ms.iter().map(|m| m.size.memory_mb).sum(),
                vcpus: ms.len() as u32,
                cpu_millis: Some(ms.iter().map(|m| m.size.cpu_millis()).sum()),
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
    async fn namespaces(State(d): D) -> Json<Vec<api::Namespace>> {
        let mut ids: Vec<String> = {
            let ms = d.machines.lock().unwrap();
            ms.iter().map(|m| m.namespace.clone()).collect()
        };
        ids.sort();
        ids.dedup();
        Json(ids.iter().filter_map(|id| namespace_of(&d, id)).collect())
    }
    fn namespace_of(d: &Daemon, id: &str) -> Option<api::Namespace> {
        let machines = d.machines.lock().unwrap();
        let gateway = d.gateways.lock().unwrap().iter().any(|(t, _)| t == id);
        let n = machines.iter().filter(|m| m.namespace == id).count();
        // A subnet of the daemon's own, so a listing says which host answered.
        let net = d.id.trim_start_matches('d');
        (gateway || n > 0).then(|| api::Namespace {
            id: id.into(),
            subnet: format!("10.{net}.0.0/24"),
            router: format!("10.{net}.0.1"),
            machines: n,
            created_at: Utc::now(),
            host: String::new(),
            region: String::new(),
            host_state: String::new(),
            gateway: gateway.then(|| api::GatewayView {
                state: api::state::CREATED.into(),
                ip: "10.1.0.2".into(),
                port: 3128,
                machine_id: format!("m_{}_gw", d.id),
                error: String::new(),
            }),
        })
    }
    async fn get_namespace(State(d): D, Path(id): Path<String>) -> Response {
        match namespace_of(&d, &id) {
            Some(t) => Json(t).into_response(),
            None => err(StatusCode::NOT_FOUND, "not_found", "namespace not found").into_response(),
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
        Json(namespace_of(&d, &id).unwrap()).into_response()
    }
    async fn delete_gateway(State(d): D, Path(id): Path<String>) -> Response {
        if id == d.keep_namespace {
            return err(StatusCode::CONFLICT, "gateway_in_use", "in use").into_response();
        }
        d.gateways.lock().unwrap().retain(|(t, _)| *t != id);
        StatusCode::NO_CONTENT.into_response()
    }
    async fn delete_namespace(State(d): D, Path(id): Path<String>) -> Response {
        if let Some(callback) = d.on_delete_namespace.lock().unwrap().as_ref() {
            callback();
        }
        if id == d.keep_namespace {
            return err(StatusCode::CONFLICT, "busy", "namespace has machines").into_response();
        }
        d.machines.lock().unwrap().retain(|m| m.namespace != id);
        StatusCode::NO_CONTENT.into_response()
    }
    /// Like the daemon: a namespace's or every machine, those every `label` selects.
    async fn list(State(d): D, uri: Uri) -> Json<Vec<api::Machine>> {
        let url = reqwest::Url::parse(&format!("http://stub{uri}")).unwrap();
        let mut namespace = None;
        let mut labels = vec![];
        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                "namespace" => namespace = Some(v.into_owned()),
                "label" => labels.push(api::Label::parse(&v).unwrap()),
                _ => {}
            }
        }
        let ms = d.machines.lock().unwrap();
        Json(
            ms.iter()
                .filter(|m| {
                    namespace
                        .as_deref()
                        .map(|t| t == m.namespace)
                        .unwrap_or(true)
                })
                .filter(|m| labels.iter().all(|l| l.matches(&m.metadata)))
                .cloned()
                .collect(),
        )
    }
    async fn put_quota(
        State(d): D,
        Path(id): Path<String>,
        Json(q): Json<api::Quota>,
    ) -> Json<api::NamespaceQuota> {
        d.quotas.lock().unwrap().push((id.clone(), q));
        Json(api::NamespaceQuota {
            namespace: id,
            quota: q,
            used: Default::default(),
        })
    }
    async fn get_quota(State(d): D, Path(id): Path<String>) -> Response {
        let qs = d.quotas.lock().unwrap();
        match qs.iter().rev().find(|(t, _)| *t == id) {
            Some((t, q)) => Json(api::NamespaceQuota {
                namespace: t.clone(),
                quota: *q,
                used: Default::default(),
            })
            .into_response(),
            None => err(StatusCode::NOT_FOUND, "not_found", "namespace not found").into_response(),
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
        // Model a dispatched daemon operation that can outlive the fleet HTTP handler.
        tokio::spawn(perform_create(d, req)).await.unwrap()
    }
    async fn perform_create(d: Arc<Daemon>, req: api::CreateMachineRequest) -> Response {
        let gate = d.create_gate.lock().unwrap().clone();
        if let Some((entered, release)) = gate {
            entered.notify_one();
            release.notified().await;
        }
        d.creates.lock().unwrap().push(req.clone());
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
        let m = d.add(&req.namespace, &req.name, req.size.memory_mb);
        if let Some(done) = d.create_finished.lock().unwrap().as_ref() {
            done.notify_one();
        }
        (StatusCode::CREATED, Json(m)).into_response()
    }
    async fn get_machine(State(d): D, Path(id): Path<String>) -> Response {
        let ms = d.machines.lock().unwrap();
        match ms.iter().find(|m| m.id == id) {
            Some(m) => {
                let mut m = m.clone();
                m.endpoints = d
                    .endpoints
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|e| e.machine_id == id)
                    .cloned()
                    .collect();
                Json(m).into_response()
            }
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
    async fn stop_machine(State(d): D, Path(id): Path<String>) -> Response {
        let mut ms = d.machines.lock().unwrap();
        match ms.iter_mut().find(|m| m.id == id) {
            Some(m) => {
                m.state = api::state::STOPPED.into();
                Json(m.clone()).into_response()
            }
            None => StatusCode::NOT_FOUND.into_response(),
        }
    }
    /// A move on the host: the machine joins the namespace; a namespace the daemon already
    /// has is a restart on a new address, else a rename.
    async fn move_machine(
        State(d): D,
        Path(id): Path<String>,
        Json(req): Json<api::MoveRequest>,
    ) -> Response {
        // Production moves are detached: losing the client cannot cancel host-side work.
        tokio::spawn(move_inner(d, id, req)).await.unwrap()
    }
    async fn move_inner(d: Arc<Daemon>, id: String, req: api::MoveRequest) -> Response {
        let gate = d.move_gate.lock().unwrap().clone();
        if let Some((entered, release)) = gate {
            entered.notify_one();
            release.notified().await;
        }
        let mut ms = d.machines.lock().unwrap();
        let joins = ms.iter().any(|m| m.namespace == req.namespace);
        let Some(m) = ms.iter_mut().find(|m| m.id == id) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let (from, previous_ip) = (m.namespace.clone(), m.ip.clone());
        m.namespace = req.namespace;
        if joins {
            m.ip = "10.9.0.7".into();
        }
        if let Some(done) = d.move_finished.lock().unwrap().as_ref() {
            done.notify_one();
        }
        Json(api::MoveResult {
            machine: m.clone(),
            from,
            previous_ip,
            restarted: joins,
        })
        .into_response()
    }
    async fn make_backup(State(d): D, Path(id): Path<String>) -> Response {
        let b = serde_json::json!({
            "id": "20261029T100000.000Z", "machine_id": id, "namespace": "t1", "name": "web",
            "created_at": "2026-10-29T10:00:00Z", "bytes": 1, "incremental": false, "disks": [],
            "host": d.id,
        });
        (StatusCode::CREATED, Json(b)).into_response()
    }
    /// The store is shared: every host answers for every machine id, with nothing here.
    async fn sandbox_lookup(State(d): D, Json(query): Json<api::SandboxRequestLookup>) -> Response {
        d.sandbox_lookups.lock().unwrap().push(query);
        let (status, body) = d.sandbox_lookup.lock().unwrap().clone().unwrap_or((
            StatusCode::NOT_FOUND,
            serde_json::json!({"code":"sandbox_request_unknown","error":"not accepted"}),
        ));
        (status, Json(body)).into_response()
    }
    async fn snapshots(State(d): D) -> Json<Vec<api::Snapshot>> {
        Json(d.snapshots.lock().unwrap().clone())
    }
    async fn backups(State(d): D) -> Json<Vec<serde_json::Value>> {
        Json(d.backup_records.lock().unwrap().clone())
    }
    /// The backups of the daemon's machines, destroyed ones' included: one of a machine named
    /// after the daemon.
    async fn all_backups(State(d): D) -> Json<Vec<serde_json::Value>> {
        Json(vec![serde_json::json!({
            "id": "20261021T101500.123Z", "machine_id": format!("m_{}", d.id), "namespace": "t1",
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
    /// A line per machine, the namespace's when asked, as the daemon's top.
    async fn top(
        State(d): D,
        Query(q): Query<HashMap<String, String>>,
    ) -> Json<Vec<api::TopMachine>> {
        let ms = d.machines.lock().unwrap();
        Json(
            ms.iter()
                .filter(|m| q.get("namespace").is_none_or(|t| *t == m.namespace))
                .map(|m| api::TopMachine {
                    machine_id: m.id.clone(),
                    namespace: m.namespace.clone(),
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
            namespace: "t1".into(),
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
            .filter(|e| q.namespace.as_deref().is_none_or(|t| t == e.namespace))
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
    async fn warm_claim(
        State(d): D,
        Path((namespace, pool)): Path<(String, String)>,
        Json(request): Json<api::ClaimWarmPoolRequest>,
    ) -> Response {
        d.calls.lock().unwrap().push(format!(
            "POST /v1/namespaces/{namespace}/warm-pools/{pool}/claims"
        ));
        if let Some(hook) = d.on_create.lock().unwrap().as_ref() {
            hook();
        }
        let mut machines = d.machines.lock().unwrap();
        let Some(machine) = machines.iter_mut().find(|m| m.namespace == namespace) else {
            return err(StatusCode::CONFLICT, "pool_empty", "pool empty").into_response();
        };
        machine.name = request.name;
        Json(machine.clone()).into_response()
    }
    let app = Router::new()
        .route(
            "/v1/namespaces/:id/warm-pools/:pool/claims",
            post(warm_claim),
        )
        .route("/v1/status", get(status))
        .route("/v1/sandbox-requests/lookup", post(sandbox_lookup))
        .route("/v1/namespaces", get(namespaces))
        // What the fleet polls, as every daemon serves it (ADR 0055).
        .route("/v1/tenants", get(namespaces))
        .route(
            "/v1/namespaces/:id",
            get(get_namespace).delete(delete_namespace),
        )
        .route(
            "/v1/namespaces/:id/gateway",
            axum::routing::put(set_gateway).delete(delete_gateway),
        )
        .route("/v1/machines", get(list).post(create))
        .route("/v1/machines/:id", get(get_machine).delete(delete_machine))
        .route("/v1/machines/:id/start", post(start_machine))
        .route("/v1/machines/:id/stop", post(stop_machine))
        .route("/v1/machines/:id/move", post(move_machine))
        .route("/v1/machines/:id/logs", get(logs))
        .route("/v1/machines/:id/exec", get(exec_session))
        .route("/v1/namespaces/:id/quota", get(get_quota).put(put_quota))
        .route("/v1/machines/:id/snapshots", get(snapshots))
        .route("/v1/machines/:id/backups", get(backups).post(make_backup))
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
