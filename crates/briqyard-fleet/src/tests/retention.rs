//! What the registry forgets and when (ADR 0119), and the writes that follow a change.

use super::templates::sandbox_body;
use super::*;
use crate::create_replay::key;
use crate::registry::REPLAY_WINDOW;
use chrono::DateTime;
use serde_json::json;

fn route(
    namespace: &str,
    id: &str,
    accepted: bool,
    settled_at: Option<DateTime<Utc>>,
) -> serde_json::Value {
    let mut r = json!({
        "namespace": namespace, "request_id": id, "host": "h1",
        "create_sha256": "00", "accepted": accepted,
    });
    if let Some(at) = settled_at {
        r["settled_at"] = json!(at);
    }
    r
}

fn admission(
    namespace: &str,
    id: &str,
    phase: &str,
    mode: &str,
    at: Option<DateTime<Utc>>,
) -> serde_json::Value {
    let request = json!({
        "region": "fsn", "size": {"vcpus": 1, "memory_mb": 256},
        "sandbox_seed": {"machine_id": "m_a", "snapshot": "s_a", "generation": "g_a"},
    });
    let mut a = json!({
        "namespace": namespace, "request_id": id, "fingerprint": "f",
        "request": if mode == "sandbox-seed" { request } else { json!(null) },
        "mode": mode, "host": "h1", "phase": phase,
    });
    if let Some(at) = at {
        a["at"] = json!(at);
    }
    a
}

/// A registry file as an earlier fleet wrote it: no times on its requests and admissions.
fn old_registry() -> Registry {
    let routes = [
        route("gone", "a", true, None),
        route("kept", "b", true, None),
        route("stuck", "c", false, None),
    ];
    let admissions = [
        admission("gone", "a", "dispatched", "cold", None),
        admission("kept", "b", "cancelled", "cold", None),
        admission("fenced", "d", "pending", "sandbox-seed", None),
    ];
    let file = json!({
        "hosts": {},
        "namespaces": {"kept": "h1", "fenced": "h1"},
        "machines": {},
        "sandbox_requests": routes.iter().map(|r| (
            key(r["namespace"].as_str().unwrap(), r["request_id"].as_str().unwrap()), r.clone()
        )).collect::<serde_json::Map<_, _>>(),
        "sandbox_admissions": admissions.iter().map(|a| (
            key(a["namespace"].as_str().unwrap(), a["request_id"].as_str().unwrap()), a.clone()
        )).collect::<serde_json::Map<_, _>>(),
        "namespace_versions": {"gone": 4, "kept": 3, "stuck": 9, "fenced": 2, "old": 7},
        "pinned_at": {"kept": Utc::now(), "old": Utc::now()},
    });
    serde_json::from_value(file).unwrap()
}

fn has_route(reg: &Registry, ns: &str, id: &str) -> bool {
    reg.sandbox_requests.contains_key(&key(ns, id))
}
fn has_admission(reg: &Registry, ns: &str, id: &str) -> bool {
    reg.sandbox_admissions.contains_key(&key(ns, id))
}

#[test]
fn a_registry_from_before_the_times_is_pruned_at_the_start_and_keeps_what_fences() {
    let mut reg = old_registry();
    let now = Utc::now();
    reg.prune(now);
    // Accepted, and its namespace is pinned nowhere: nothing can replay it to a machine.
    assert!(!has_route(&reg, "gone", "a"));
    assert!(!has_admission(&reg, "gone", "a"));
    // Its namespace is pinned: the window starts now.
    assert!(has_admission(&reg, "kept", "b"));
    // Not accepted: fences until an operator reconciles it (ADR 0076), whatever its age.
    assert!(has_route(&reg, "stuck", "c"));
    assert!(has_admission(&reg, "fenced", "d"));
    // A version stays with a pin or an unsettled request, and goes with nothing.
    let versions: std::collections::BTreeSet<_> =
        reg.namespace_versions.keys().map(String::as_str).collect();
    assert_eq!(versions, ["fenced", "kept", "stuck"].into());
    assert!(!reg.pinned_at.contains_key("old"));
    assert!(reg.pinned_at.contains_key("kept"));
    // Idempotent.
    let before = serde_json::to_string(&reg).unwrap();
    reg.prune(now);
    assert_eq!(serde_json::to_string(&reg).unwrap(), before);
    // The legacy entry of a pinned namespace leaves a window after the start.
    reg.prune(now + Duration::hours(23));
    assert!(has_admission(&reg, "kept", "b"));
    reg.prune(now + Duration::hours(25));
    assert!(!has_admission(&reg, "kept", "b"));
    assert!(has_route(&reg, "stuck", "c"), "unaccepted, never forgotten");
    assert!(has_admission(&reg, "fenced", "d"));
}

#[test]
fn settled_entries_leave_after_the_window_and_not_before() {
    let now = Utc::now();
    let mut reg = Registry::default();
    for (ns, age) in [("young", 23), ("old", 25)] {
        let at = now - Duration::hours(age);
        reg.namespaces.insert(ns.into(), "h1".into());
        reg.sandbox_requests.insert(
            key(ns, "r"),
            serde_json::from_value(route(ns, "r", true, Some(at))).unwrap(),
        );
        reg.sandbox_admissions.insert(
            key(ns, "r"),
            serde_json::from_value(admission(ns, "r", "dispatched", "cold", Some(at))).unwrap(),
        );
    }
    reg.prune(now);
    assert!(has_route(&reg, "young", "r") && has_admission(&reg, "young", "r"));
    assert!(!has_route(&reg, "old", "r") && !has_admission(&reg, "old", "r"));
}

#[test]
fn an_admission_waiting_on_an_unaccepted_dispatch_is_kept() {
    let now = Utc::now();
    let long_ago = now - Duration::days(30);
    let mut reg = Registry::default();
    reg.sandbox_requests.insert(
        key("n", "r"),
        serde_json::from_value(route("n", "r", false, None)).unwrap(),
    );
    reg.sandbox_admissions.insert(
        key("n", "r"),
        serde_json::from_value(admission("n", "r", "dispatched", "cold", Some(long_ago))).unwrap(),
    );
    reg.prune(now);
    assert!(has_route(&reg, "n", "r") && has_admission(&reg, "n", "r"));
}

#[test]
fn a_version_pruned_is_never_given_again() {
    let mut reg = Registry::default();
    reg.namespace_versions.insert("n".into(), 7);
    reg.prune(Utc::now());
    assert!(reg.namespace_versions.is_empty());
    // A holder of version 7 from before is stale against anything made now.
    assert!(reg.namespace_version("n") >= 7);
    reg.note_namespace_create("n");
    assert_eq!(reg.namespace_version("n"), 8);
}

#[test]
fn a_heartbeat_prunes() {
    let mut reg = old_registry();
    let now = Utc::now();
    reg.heartbeat(crate::static_host(&Default::default(), now), now);
    assert!(!has_route(&reg, "gone", "a"));
}

#[test]
fn the_registry_on_disk_is_pruned_when_the_file_loads_at_the_start() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.json");
    std::fs::write(&path, crate::backup::encode(&old_registry())).unwrap();
    let mut loaded = Registry::load(&path).unwrap();
    assert!(has_route(&loaded, "gone", "a"));
    loaded.prune(Utc::now());
    assert!(!has_route(&loaded, "gone", "a"));
    assert!(
        crate::backup::encode(&loaded).len() < std::fs::metadata(&path).unwrap().len() as usize
    );
}

#[tokio::test]
async fn a_create_replayed_inside_the_window_returns_the_same_machine() {
    let (f, ds) = fleet_with_daemons(1).await;
    let id = ds[0].stub.id.clone();
    let existing = ds[0].stub.machine("destination", "sandbox", 256);
    *ds[0].stub.sandbox_lookup.lock().unwrap() =
        Some((StatusCode::OK, serde_json::to_value(&existing).unwrap()));
    f.st.reg
        .lock()
        .unwrap()
        .namespaces
        .insert("destination".into(), id.clone());
    let parsed: api::CreateMachineRequest = serde_json::from_value(sandbox_body()).unwrap();
    crate::create_replay::insert_route(
        &mut f.st.reg.lock().unwrap(),
        crate::create_replay::request_route(&parsed, id.clone())
            .unwrap_or_else(|_| panic!("route")),
    );
    let (status, _, body) = call(&f.st, "POST", "/v1/machines", "api", Some(sandbox_body())).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let now = Utc::now();
    f.st.reg.lock().unwrap().prune(now + Duration::hours(1));
    let (status, _, again) = call(&f.st, "POST", "/v1/machines", "api", Some(sandbox_body())).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(json(&again)["id"], existing.id);
    assert!(
        ds[0].stub.creates.lock().unwrap().is_empty(),
        "no second machine"
    );
    // The namespace and its machine are pinned, the pin stays through the prune.
    assert!(f
        .st
        .reg
        .lock()
        .unwrap()
        .namespaces
        .contains_key("destination"));
    // Past the window the record is gone.
    f.st.reg
        .lock()
        .unwrap()
        .prune(now + REPLAY_WINDOW + Duration::hours(1));
    assert!(
        crate::create_replay::existing_route(&f.st.reg.lock().unwrap(), &parsed)
            .unwrap_or_else(|_| panic!("route"))
            .is_none()
    );
}

fn counting(
    writes: &Arc<AtomicUsize>,
) -> impl FnOnce(&std::path::Path, &[u8]) -> std::io::Result<()> + Send + 'static {
    let writes = writes.clone();
    move |path, data| {
        writes.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_millis(30));
        write_registry(path, data)
    }
}

#[tokio::test]
async fn a_save_with_no_change_does_not_encode() {
    let f = fleet(config::Config::default());
    let encodes = || f.st.encodes.load(Ordering::SeqCst);
    f.st.save().await.unwrap();
    let first = encodes();
    for _ in 0..5 {
        f.st.save_with(|_, _| panic!("unchanged save wrote"))
            .await
            .unwrap();
    }
    assert_eq!(encodes(), first, "nothing changed: nothing encoded");
    f.st.reg
        .lock()
        .unwrap()
        .namespaces
        .insert("n".into(), "h1".into());
    f.st.save().await.unwrap();
    assert_eq!(encodes(), first + 1);
    // Borrowed for a change that changed nothing: encoded once, found equal, not written.
    let _ = f.st.reg.lock().unwrap().namespaces.get_mut("n");
    f.st.save_with(|_, _| panic!("equal bytes were written"))
        .await
        .unwrap();
    assert_eq!(encodes(), first + 2);
    f.st.save_with(|_, _| panic!("unchanged save wrote"))
        .await
        .unwrap();
    assert_eq!(encodes(), first + 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn saves_made_together_share_writes_and_each_caller_finds_its_change_on_disk() {
    let f = fleet(config::Config::default());
    f.st.save().await.unwrap();
    let writes = Arc::new(AtomicUsize::new(0));
    let callers = 24;
    let mut tasks = Vec::new();
    for i in 0..callers {
        let st = f.st.clone();
        let writes = writes.clone();
        tasks.push(tokio::spawn(async move {
            let name = format!("ns{i}");
            st.reg
                .lock()
                .unwrap()
                .namespaces
                .insert(name.clone(), "h1".into());
            st.save_with(counting(&writes)).await.unwrap();
            let on_disk = Registry::load(&st.state_path).unwrap();
            assert!(on_disk.namespaces.contains_key(&name), "{name} not on disk");
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let writes = writes.load(Ordering::SeqCst);
    assert!(
        writes >= 1 && writes < callers,
        "{writes} writes for {callers} callers"
    );
}

#[tokio::test]
async fn a_caller_whose_write_failed_is_not_served_by_it() {
    let f = fleet(config::Config::default());
    f.st.save().await.unwrap();
    f.st.reg
        .lock()
        .unwrap()
        .namespaces
        .insert("n".into(), "h1".into());
    let failed =
        f.st.save_with(|_, _| Err(std::io::Error::other("disk")))
            .await;
    assert!(failed.is_err());
    // The next caller finds the change not on disk and writes it, though nothing changed since.
    f.st.save().await.unwrap();
    assert!(Registry::load(&f.st.state_path)
        .unwrap()
        .namespaces
        .contains_key("n"));
}
