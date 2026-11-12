//! Placement admission across an ordered list of regions (ADR 0128): a test for each row of the
//! ADR's failure matrix, for each host state, and for the fences.

use super::*;
use serde_json::{json, Value};

pub(super) fn path(namespace: &str, id: &str) -> String {
    format!("/v1/namespaces/{namespace}/admissions/{id}")
}
pub(super) fn gateway() -> Value {
    json!({"role": "gateway", "size": {"vcpus": 1, "memory_mb": 256}})
}
pub(super) fn consumer(memory_mb: u32) -> Value {
    json!({"role": "consumer", "size": {"vcpus": 1, "memory_mb": memory_mb}, "volume_gb": 2})
}
pub(super) fn body(regions: &[&str], requirements: Vec<Value>) -> Value {
    json!({"regions": regions, "requirements": requirements})
}
pub(super) fn both(regions: &[&str]) -> Value {
    body(regions, vec![gateway(), consumer(256)])
}

/// A ready host with `used` of `cap` MB taken, in `region`, with no daemon behind it.
pub(super) fn put_host(f: &Fleet, id: &str, region: &str, cap: u32, used: u32) {
    let now = Utc::now();
    let mut h = static_host(
        &config::StaticHost {
            id: id.into(),
            url: format!(
                "http://10.0.1.{}:7420",
                id.bytes().map(usize::from).sum::<usize>() % 250
            ),
            region: region.into(),
            ..Default::default()
        },
        now,
    );
    h.capacity = api::Capacity {
        memory_mb: cap,
        vcpus: 32,
        cpu_millis: Some(32_000),
    };
    h.used = api::Capacity {
        memory_mb: used,
        vcpus: 0,
        cpu_millis: Some(0),
    };
    f.st.reg.lock().unwrap().heartbeat(h, now);
}
pub(super) fn fill(f: &Fleet, id: &str) {
    let mut reg = f.st.reg.lock().unwrap();
    let h = reg.hosts.get_mut(id).unwrap();
    h.used.memory_mb = h.capacity.memory_mb;
}
pub(super) fn cfg() -> config::Config {
    config::Config {
        token: "api".into(),
        ..Default::default()
    }
}

/// Two regions of two hosts each, all with room: `bhs` has h1 and h2, `gra` h3 and h4.
fn world() -> Fleet {
    let f = fleet(cfg());
    for (id, region) in [("h1", "bhs"), ("h2", "bhs"), ("h3", "gra"), ("h4", "gra")] {
        put_host(&f, id, region, 10_000, 1_000);
    }
    f
}
fn fill_region(f: &Fleet, region: &str) {
    let ids: Vec<String> =
        f.st.reg
            .lock()
            .unwrap()
            .hosts
            .values()
            .filter(|h| h.region == region)
            .map(|h| h.id.clone())
            .collect();
    for id in ids {
        fill(f, &id);
    }
}

pub(super) async fn admit(f: &Fleet, namespace: &str, id: &str, b: Value) -> (StatusCode, Value) {
    let (s, _, text) = call(&f.st, "PUT", &path(namespace, id), "api", Some(b)).await;
    (s, json(&text))
}
async fn cancel(f: &Fleet, namespace: &str, id: &str) -> StatusCode {
    call(&f.st, "DELETE", &path(namespace, id), "api", None)
        .await
        .0
}
async fn put_gateway(f: &Fleet, namespace: &str, region: &str, id: &str) -> (StatusCode, String) {
    let (s, _, b) = call(
        &f.st,
        "PUT",
        &format!("/v1/namespaces/{namespace}/gateway?region={region}&placement_request_id={id}"),
        "api",
        Some(gateway_body()),
    )
    .await;
    (s, b)
}
async fn create_under(
    f: &Fleet,
    namespace: &str,
    region: &str,
    id: &str,
    memory_mb: u32,
) -> (StatusCode, HeaderMap, String) {
    let mut b = create_body(namespace, "sandbox", memory_mb);
    b["region"] = region.into();
    b["volume"] = json!({"size_gb": 2, "mount": "/work"});
    call_with(
        &f.st,
        "127.0.0.1".parse().unwrap(),
        &[(crate::sandbox_admissions::HEADER, id)],
        "POST",
        "/v1/machines",
        "api",
        Some(b),
    )
    .await
}
/// The registry as it would be saved, with the holds it does not save (the count on each host),
/// to compare before and after.
fn snapshot(f: &Fleet) -> String {
    let reg = f.st.reg.lock().unwrap();
    let mut held: Vec<(&String, usize)> = reg
        .hosts
        .iter()
        .map(|(id, h)| (id, h.holds.len()))
        .collect();
    held.sort();
    format!("{}{held:?}", serde_json::to_string(&*reg).unwrap())
}
fn host_used(f: &Fleet, id: &str) -> u32 {
    f.st.reg.lock().unwrap().hosts[id].used.memory_mb
}
/// The holds an admission made and no dispatch has taken over.
pub(super) fn holds(f: &Fleet, id: &str) -> usize {
    let reg = f.st.reg.lock().unwrap();
    reg.hosts[id]
        .holds
        .iter()
        .filter(|h| h.is_admission())
        .count()
}
fn refused_in(f: &Fleet, region: &str) -> u64 {
    let reg = f.st.reg.lock().unwrap();
    signals::regions(&reg, &f.st.policy, &f.st.refusals)
        .iter()
        .find(|r| r.region == region)
        .map_or(0, |r| r.unschedulable.memory)
}
pub(super) fn outcomes(b: &Value) -> Vec<(String, String)> {
    b["regions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| {
            (
                o["region"].as_str().unwrap().into(),
                o["outcome"].as_str().unwrap().into(),
            )
        })
        .collect()
}
pub(super) fn pair(region: &str, outcome: &str) -> (String, String) {
    (region.into(), outcome.into())
}

// Matrix rows.

#[tokio::test]
async fn preferred_region_has_room() {
    let f = world();
    let (s, b) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(
        (b["region"].as_str(), b["binding"].as_str()),
        (Some("bhs"), Some("new"))
    );
    assert_eq!(b["mode"], "cold");
    assert_eq!(outcomes(&b), vec![pair("bhs", "placed")]);
    let host = b["host"].as_str().unwrap();
    assert_eq!(pinned(&f.st, "ns").as_deref(), Some(host));
    // A hold for each requirement, and the decision saved before it was answered.
    assert_eq!(holds(&f, host), 2);
    assert_eq!(host_used(&f, host), 1_000 + 256 + 256);
    assert_eq!(saved(&f.st).sandbox_admissions.len(), 1);
    assert_eq!(
        saved(&f.st).namespaces.get("ns").map(String::as_str),
        Some(host)
    );
}

#[tokio::test]
async fn preferred_full_next_has_room() {
    let f = world();
    fill_region(&f, "bhs");
    let (s, b) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["region"], "gra");
    assert_eq!(
        outcomes(&b),
        vec![pair("bhs", "full"), pair("gra", "placed")]
    );
    assert_eq!(f.st.reg.lock().unwrap().region_of("ns"), Some("gra"));
}

#[tokio::test]
async fn all_regions_full() {
    let f = world();
    fill_region(&f, "bhs");
    fill_region(&f, "gra");
    let before = snapshot(&f);
    let (s, b) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{b}");
    assert_eq!(b["code"], "capacity");
    assert_eq!(b["reason"], "regions_full");
    assert_eq!(outcomes(&b), vec![pair("bhs", "full"), pair("gra", "full")]);
    // Nothing stored, and the refusal counted once in each region found full.
    assert_eq!(snapshot(&f), before);
    assert_eq!((refused_in(&f, "bhs"), refused_in(&f, "gra")), (1, 1));
}

#[tokio::test]
async fn a_host_that_served_the_requirements_is_down_and_none_has_room() {
    let f = world();
    fill(&f, "h1");
    set_state(&f.st, "h2", "down");
    let before = snapshot(&f);
    let (s, b) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{b}");
    assert_eq!(b["reason"], "region_unconfirmed");
    // gra has room, and is not tried.
    assert_eq!(outcomes(&b), vec![pair("bhs", "unconfirmed")]);
    assert_eq!(snapshot(&f), before);
    assert_eq!(pinned(&f.st, "ns"), None);
}

#[tokio::test]
async fn first_region_ineligible_refuses_as_a_single_region_create() {
    let f = world();
    let (s, b) = admit(&f, "ns", "req_one", both(&["sgp", "gra"])).await;
    let (cs, _, cb) = call(
        &f.st,
        "POST",
        "/v1/machines",
        "api",
        Some({
            let mut b = create_body("other", "a", 256);
            b["region"] = "sgp".into();
            b
        }),
    )
    .await;
    assert_eq!(
        (s, b["code"].clone()),
        (cs, json(&cb)["code"].clone()),
        "{b} / {cb}"
    );
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(pinned(&f.st, "ns"), None);
    assert!(f.st.reg.lock().unwrap().sandbox_admissions.is_empty());
}

#[tokio::test]
async fn first_region_ineligible_for_a_class_no_host_serves() {
    let f = world();
    let mut c = consumer(256);
    c["runtime_class"] = "nested".into();
    let (s, b) = admit(&f, "ns", "req_one", body(&["bhs", "gra"], vec![c])).await;
    let mut single = create_body("other", "a", 256);
    single["region"] = "bhs".into();
    single["runtime_class"] = "nested".into();
    let (cs, _, cb) = call(&f.st, "POST", "/v1/machines", "api", Some(single)).await;
    assert_eq!(
        (s, b["code"].clone()),
        (cs, json(&cb)["code"].clone()),
        "{b} / {cb}"
    );
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(f.st.reg.lock().unwrap().sandbox_admissions.is_empty());
}

#[tokio::test]
async fn namespace_pinned_and_it_fits() {
    let f = world();
    f.st.reg.lock().unwrap().pin("ns", "h3");
    let (s, b) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    // Its own host, whatever the preference says.
    assert_eq!(
        (b["host"].as_str(), b["region"].as_str()),
        (Some("h3"), Some("gra"))
    );
    assert_eq!(b["binding"], "existing");
    assert_eq!(holds(&f, "h3"), 2);
}

#[tokio::test]
async fn namespace_pinned_and_it_does_not_fit() {
    let f = world();
    f.st.reg.lock().unwrap().pin("ns", "h3");
    fill(&f, "h3");
    let before = snapshot(&f);
    let (s, b) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{b}");
    assert_eq!(b["code"], "capacity");
    // A stack is never split: bhs is not tried.
    assert_eq!(snapshot(&f), before);
    assert_eq!(f.st.reg.lock().unwrap().region_of("ns"), Some("gra"));
}

#[tokio::test]
async fn same_id_same_body_replays_the_original() {
    let f = world();
    let (_, first) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    let held = host_used(&f, first["host"].as_str().unwrap());
    // The key order of the caller's JSON does not matter.
    let reordered = json!({"requirements": [gateway(), consumer(256)], "regions": ["bhs", "gra"]});
    let (s, again) = admit(&f, "ns", "req_one", reordered).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(again, first);
    assert_eq!(host_used(&f, first["host"].as_str().unwrap()), held);
}

#[tokio::test]
async fn same_id_other_body_or_other_kind_is_409() {
    let (f, ds) = fleet_in_regions(&["bhs", "gra"]).await;
    seed_on(&f, &ds[0], "m_seed");
    let (s, _) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    assert_eq!(s, StatusCode::OK);
    let before = snapshot(&f);
    let (s, b) = admit(&f, "ns", "req_one", both(&["gra", "bhs"])).await;
    assert_eq!(s, StatusCode::CONFLICT, "{b}");
    assert_eq!(snapshot(&f), before);
    // A seed admission of the same id.
    let seed = json!({"region": "bhs", "size": {"vcpus": 1, "memory_mb": 256},
        "sandbox_seed": {"machine_id": "m_seed", "snapshot": "s_one", "generation": "g_one"}});
    let seed_path = |ns: &str, id: &str| format!("/v1/namespaces/{ns}/sandbox-admissions/{id}");
    let (s, _, text) = call(
        &f.st,
        "PUT",
        &seed_path("ns", "req_one"),
        "api",
        Some(seed.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{text}");
    // And a placement admission to an id the seed route holds.
    let (s, _, text) = call(
        &f.st,
        "PUT",
        &seed_path("other", "req_two"),
        "api",
        Some(seed),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{text}");
    let (s, b) = admit(&f, "other", "req_two", both(&["bhs"])).await;
    assert_eq!(s, StatusCode::CONFLICT, "{b}");
    // Cancel is one route for both kinds.
    assert_eq!(cancel(&f, "ns", "req_one").await, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn the_sum_of_the_requirements_decides_the_region() {
    let f = world();
    // 700 MB free on each bhs host, under the fill ceiling: the consumer (600) fits, the gateway and
    // the consumer (856) do not.
    for id in ["h1", "h2"] {
        let mut reg = f.st.reg.lock().unwrap();
        let h = reg.hosts.get_mut(id).unwrap();
        h.capacity.memory_mb = 2_000;
        h.used.memory_mb = 1_300;
    }
    let (s, alone) = admit(
        &f,
        "solo",
        "req_solo",
        body(&["bhs", "gra"], vec![consumer(600)]),
    )
    .await;
    assert_eq!(
        (s, alone["region"].as_str()),
        (StatusCode::OK, Some("bhs")),
        "{alone}"
    );
    let (s, both_) = admit(
        &f,
        "duo",
        "req_duo",
        body(&["bhs", "gra"], vec![gateway(), consumer(600)]),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{both_}");
    assert_eq!(both_["region"], "gra", "{both_}");
    assert_eq!(
        outcomes(&both_),
        vec![pair("bhs", "full"), pair("gra", "placed")]
    );
}

#[tokio::test]
async fn dispatch_after_the_hold_expired_and_the_host_filled() {
    let (f, ds) = fleet_in_regions(&["bhs", "bhs", "gra", "gra"]).await;
    let (s, b) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let host = b["host"].as_str().unwrap().to_string();
    // The hold lapses (the heartbeat prunes it) and another tenant fills the host.
    {
        let mut reg = f.st.reg.lock().unwrap();
        reg.expire_holds(Utc::now() + chrono::Duration::minutes(5));
        reg.hosts.get_mut(&host).unwrap().used.memory_mb = 64_000;
    }
    let (s, text) = put_gateway(&f, "ns", "bhs", "req_one").await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{text}");
    assert_eq!(json(&text)["code"], "capacity");
    // Role not marked, decision and pin kept, nothing sent to the host. The lapsed hold is not
    // brought back, and the requirement's other hold is as it was.
    assert_eq!(holds(&f, &host), 0);
    assert_eq!(pinned(&f.st, "ns").as_deref(), Some(host.as_str()));
    assert!(f
        .st
        .reg
        .lock()
        .unwrap()
        .sandbox_admissions
        .values()
        .next()
        .unwrap()
        .pending());
    assert!(ds.iter().all(|d| d.stub.creates.lock().unwrap().is_empty()));
    // Cancelling is still possible, nothing was dispatched.
    assert_eq!(cancel(&f, "ns", "req_one").await, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn a_dispatch_without_room_puts_the_hold_it_took_back_and_marks_no_role() {
    let (f, ds) = fleet_in_regions(&["bhs", "gra"]).await;
    let (_, b) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    let host = b["host"].as_str().unwrap().to_string();
    let used = host_used(&f, &host);
    assert_eq!(holds(&f, &host), 2);
    // Another tenant fills the host while both holds are still there.
    let full = {
        let mut reg = f.st.reg.lock().unwrap();
        let h = reg.hosts.get_mut(&host).unwrap();
        h.used.memory_mb = h.capacity.memory_mb + 1_000;
        h.used.memory_mb
    };
    let (s, text) = put_gateway(&f, "ns", "bhs", "req_one").await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{text}");
    assert_eq!(json(&text)["code"], "capacity");
    // The gateway's hold was taken off for the check and is back, as it was: both holds,
    // the same figure, no role marked, nothing sent.
    assert_eq!(holds(&f, &host), 2);
    assert_eq!(host_used(&f, &host), full);
    assert!(ds.iter().all(|d| d.stub.creates.lock().unwrap().is_empty()));
    // The host frees up: the same dispatch now takes over the hold it kept.
    f.st.reg
        .lock()
        .unwrap()
        .hosts
        .get_mut(&host)
        .unwrap()
        .used
        .memory_mb = used;
    let (s, text) = put_gateway(&f, "ns", "bhs", "req_one").await;
    assert_eq!(s, StatusCode::OK, "{text}");
    assert_eq!(holds(&f, &host), 1);
}

#[tokio::test]
async fn a_repeated_dispatch_does_not_extend_the_window() {
    let (f, _ds) = fleet_in_regions(&["bhs", "gra"]).await;
    let at = |f: &Fleet, ns: &str| {
        let reg = f.st.reg.lock().unwrap();
        reg.sandbox_admissions
            .values()
            .find(|a| a.namespace == ns)
            .unwrap()
            .at()
            .unwrap()
    };
    let backdate = |f: &Fleet, ns: &str| {
        let mut reg = f.st.reg.lock().unwrap();
        reg.sandbox_admissions
            .values_mut()
            .find(|a| a.namespace == ns)
            .unwrap()
            .backdate(chrono::Duration::hours(20));
    };
    let quota = |ns: &'static str| {
        let f = &f;
        async move {
            let (s, _, text) = call(
                &f.st,
                "PUT",
                &format!("/v1/namespaces/{ns}/quota?region=bhs&placement_request_id=req_one"),
                "api",
                Some(json!({})),
            )
            .await;
            assert_eq!(s, StatusCode::OK, "{text}");
        }
    };
    let old = Utc::now() - chrono::Duration::hours(19);
    // A quota carrying the id: the first one changes the phase, the next ones change nothing.
    assert_eq!(
        admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await.0,
        StatusCode::OK
    );
    backdate(&f, "ns");
    quota("ns").await;
    assert!(at(&f, "ns") > old, "the first dispatch starts the window");
    backdate(&f, "ns");
    quota("ns").await;
    assert!(at(&f, "ns") < old, "a repeated quota extended the window");
    // So a periodic quota cannot keep a partly dispatched admission from expiring.
    f.st.reg
        .lock()
        .unwrap()
        .prune(Utc::now() + chrono::Duration::hours(5));
    assert!(!crate::sandbox_admissions::namespace_pending(
        &f.st.reg.lock().unwrap(),
        "ns"
    ));
    // A role newly marked starts it again; its retry does not.
    assert_eq!(
        admit(&f, "ns2", "req_one", both(&["bhs", "gra"])).await.0,
        StatusCode::OK
    );
    backdate(&f, "ns2");
    let (s, text) = put_gateway(&f, "ns2", "bhs", "req_one").await;
    assert_eq!(s, StatusCode::OK, "{text}");
    assert!(at(&f, "ns2") > old, "a new role starts the window");
    backdate(&f, "ns2");
    let (s, text) = put_gateway(&f, "ns2", "bhs", "req_one").await;
    assert_eq!(s, StatusCode::OK, "{text}");
    assert!(at(&f, "ns2") < old, "a retried role extended the window");
}

#[tokio::test]
async fn a_create_under_an_expired_admission_is_409_and_forwards_nothing() {
    let (f, ds) = fleet_in_regions(&["bhs", "gra"]).await;
    let (_, b) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    let host = b["host"].as_str().unwrap().to_string();
    f.st.reg
        .lock()
        .unwrap()
        .prune(Utc::now() + chrono::Duration::hours(25));
    let (s, _, text) = create_under(&f, "ns", "bhs", "req_one", 256).await;
    assert_eq!(s, StatusCode::CONFLICT, "{text}");
    assert!(text.contains("admission expired"), "{text}");
    assert_eq!(holds(&f, &host), 0);
    assert!(ds.iter().all(|d| d.stub.creates.lock().unwrap().is_empty()));
}

#[tokio::test]
async fn cancel_before_dispatch_keeps_the_pin_and_releases_the_holds() {
    let f = world();
    let (_, b) = admit(&f, "ns", "req_one", both(&["bhs"])).await;
    let host = b["host"].as_str().unwrap();
    assert_eq!(holds(&f, host), 2);
    assert_eq!(cancel(&f, "ns", "req_one").await, StatusCode::NO_CONTENT);
    assert_eq!((holds(&f, host), host_used(&f, host)), (0, 1_000));
    assert_eq!(pinned(&f.st, "ns").as_deref(), Some(host));
    // The id is a tombstone now: the same id is refused, another walks afresh.
    let (s, _) = admit(&f, "ns", "req_one", both(&["bhs"])).await;
    assert_eq!(s, StatusCode::CONFLICT);
    // A cancel of an unknown id writes a tombstone both kinds find.
    assert_eq!(cancel(&f, "ns", "req_never").await, StatusCode::NO_CONTENT);
    let (s, _) = admit(&f, "ns", "req_never", both(&["bhs"])).await;
    assert_eq!(s, StatusCode::CONFLICT);
}

#[tokio::test]
async fn cancel_after_any_dispatch_is_409_gateway_included() {
    let (f, _ds) = fleet_in_regions(&["bhs", "gra"]).await;
    let (_, b) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    assert_eq!(b["region"], "bhs");
    let (s, text) = put_gateway(&f, "ns", "bhs", "req_one").await;
    assert_eq!(s, StatusCode::OK, "{text}");
    assert_eq!(cancel(&f, "ns", "req_one").await, StatusCode::CONFLICT);
}

#[tokio::test]
async fn dispatch_after_expiry_is_409_then_missing_then_a_new_walk() {
    let (f, _ds) = fleet_in_regions(&["bhs", "gra"]).await;
    let (_, b) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    let host = b["host"].as_str().unwrap().to_string();
    let day = chrono::Duration::hours(25);
    f.st.reg.lock().unwrap().prune(Utc::now() + day);
    // The fence and the holds are gone, the id is a tombstone.
    assert_eq!(holds(&f, &host), 0);
    {
        let reg = f.st.reg.lock().unwrap();
        assert!(!crate::sandbox_admissions::namespace_pending(&reg, "ns"));
    }
    let (s, text) = put_gateway(&f, "ns", "bhs", "req_one").await;
    assert_eq!(s, StatusCode::CONFLICT, "{text}");
    assert!(text.contains("admission expired"), "{text}");
    let (s, _) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    assert_eq!(s, StatusCode::CONFLICT);
    // Another window, and the tombstone goes.
    f.st.reg
        .lock()
        .unwrap()
        .prune(Utc::now() + day * 2 + chrono::Duration::hours(2));
    let (s, text) = put_gateway(&f, "ns", "bhs", "req_one").await;
    assert_eq!(s, StatusCode::CONFLICT, "{text}");
    assert!(text.contains("placement admission missing"), "{text}");
    let (s, again) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    assert_eq!(s, StatusCode::OK, "{again}");
}

#[tokio::test]
async fn gateway_dispatched_consumer_never_holds_the_fence_until_expiry() {
    let (f, _ds) = fleet_in_regions(&["bhs", "gra"]).await;
    let (_, b) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    let host = b["host"].as_str().unwrap().to_string();
    let (s, text) = put_gateway(&f, "ns", "bhs", "req_one").await;
    assert_eq!(s, StatusCode::OK, "{text}");
    {
        let reg = f.st.reg.lock().unwrap();
        assert!(crate::sandbox_admissions::namespace_pending(&reg, "ns"));
    }
    // Still held a day less a minute after the gateway, released a day after.
    let at = Utc::now();
    f.st.reg
        .lock()
        .unwrap()
        .prune(at + chrono::Duration::hours(23));
    assert!(crate::sandbox_admissions::namespace_pending(
        &f.st.reg.lock().unwrap(),
        "ns"
    ));
    f.st.reg
        .lock()
        .unwrap()
        .prune(at + chrono::Duration::hours(25));
    assert!(!crate::sandbox_admissions::namespace_pending(
        &f.st.reg.lock().unwrap(),
        "ns"
    ));
    assert_eq!(holds(&f, &host), 0);
    // The gateway was dispatched: its machine is the caller's, the pin follows the heartbeat.
    assert_eq!(pinned(&f.st, "ns").as_deref(), Some(host.as_str()));
}

#[tokio::test]
async fn first_region_full_later_regions_ineligible() {
    let f = world();
    fill_region(&f, "bhs");
    let before = snapshot(&f);
    let (s, b) = admit(&f, "ns", "req_one", both(&["bhs", "sgp"])).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{b}");
    assert_eq!(b["reason"], "regions_full");
    assert_eq!(
        outcomes(&b),
        vec![pair("bhs", "full"), pair("sgp", "ineligible")]
    );
    assert_eq!(snapshot(&f), before);
}

#[tokio::test]
async fn restart_after_the_saved_answer_replays_the_same_decision() {
    let f = world();
    let (_, first) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    // The registry as a restore or a restart loads it, with the preferred region full since.
    let loaded = Registry::load(&f.st.state_path).unwrap();
    *f.st.reg.lock().unwrap() = loaded;
    fill_region(&f, "bhs");
    let (s, again) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    assert_eq!(s, StatusCode::OK, "{again}");
    assert_eq!(again, first);
}

#[tokio::test]
async fn a_registry_restored_from_backup_returns_the_same_decision() {
    let f = world();
    let (_, first) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    // What `restore` writes: the backup's bytes, parsed as the registry.
    let bytes = crate::backup::encode(&f.st.reg.lock().unwrap());
    *f.st.reg.lock().unwrap() = serde_json::from_slice(&bytes).unwrap();
    fill_region(&f, "bhs");
    let (s, again) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    assert_eq!((s, again), (StatusCode::OK, first));
}

#[tokio::test]
async fn no_token_configured_is_409_capability_unsupported() {
    let f = fleet(config::Config::default());
    put_host(&f, "h1", "bhs", 10_000, 0);
    let (s, _, b) = call(
        &f.st,
        "PUT",
        &path("ns", "req_one"),
        "",
        Some(both(&["bhs"])),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{b}");
    assert_eq!(json(&b)["code"], "capability_unsupported");
}

// Gating tests.

#[tokio::test]
async fn a_replay_after_the_preferred_region_filled_returns_the_original_region() {
    let f = world();
    let (_, first) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    assert_eq!(first["region"], "bhs");
    fill_region(&f, "bhs");
    let (s, again) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    assert_eq!((s, again), (StatusCode::OK, first));
}

#[tokio::test]
async fn two_concurrent_admissions_for_one_new_namespace_end_on_one_host() {
    let f = world();
    let (a, b) = tokio::join!(
        admit(&f, "ns", "req_a", both(&["bhs", "gra"])),
        admit(&f, "ns", "req_b", both(&["bhs", "gra"])),
    );
    assert_eq!((a.0, b.0), (StatusCode::OK, StatusCode::OK));
    assert_eq!(a.1["host"], b.1["host"]);
    let bindings = [
        a.1["binding"].as_str().unwrap(),
        b.1["binding"].as_str().unwrap(),
    ];
    assert!(
        bindings.contains(&"new") && bindings.contains(&"existing"),
        "{bindings:?}"
    );
}

/// One host in `state` in region `rx`, next to a full `rf` and a `ry` with room: how `rx` counts.
async fn classified(
    mutate: impl FnOnce(&mut HostRec),
    consumer: Value,
    first: &[&str],
) -> (StatusCode, Value) {
    let f = fleet(cfg());
    put_host(&f, "hf", "rf", 10_000, 9_900);
    put_host(&f, "hx", "rx", 10_000, 1_000);
    put_host(&f, "hy", "ry", 10_000, 1_000);
    mutate(f.st.reg.lock().unwrap().hosts.get_mut("hx").unwrap());
    f.st.reg
        .lock()
        .unwrap()
        .hosts
        .get_mut("hy")
        .unwrap()
        .runtime_classes = vec![api::RuntimeClassInfo {
        name: "nested".into(),
        nested: true,
        kernel_release: String::new(),
        openzfs: String::new(),
    }];
    let mut regions = first.to_vec();
    regions.push("ry");
    admit(&f, "ns", "req_one", body(&regions, vec![consumer])).await
}

#[tokio::test]
async fn every_host_state_classifies_as_written() {
    let candidate = |_: &mut HostRec| {};
    let (s, b) = classified(candidate, consumer(256), &["rx"]).await;
    assert_eq!(
        (s, b["region"].as_str()),
        (StatusCode::OK, Some("rx")),
        "{b}"
    );
    // Ready, no room: full, the next region is tried.
    let (s, b) = classified(|h| h.used.memory_mb = 9_900, consumer(256), &["rx"]).await;
    assert_eq!(
        (s, outcomes(&b)),
        (
            StatusCode::OK,
            vec![pair("rx", "full"), pair("ry", "placed")]
        )
    );
    // Ready under a pressure condition: also full.
    let (s, b) = classified(
        |h| h.conditions = vec![pressure("memory_pressure", true)],
        consumer(256),
        &["rx"],
    )
    .await;
    assert_eq!(
        (s, outcomes(&b)),
        (
            StatusCode::OK,
            vec![pair("rx", "full"), pair("ry", "placed")]
        )
    );
    // Down, stale, upgrading, or with its memory policy unresolved: unconfirmed, the walk stops.
    type Mutation = Box<dyn FnOnce(&mut HostRec)>;
    let unknown: Vec<(&str, Mutation)> = vec![
        ("down", Box::new(|h| h.state = "down".into())),
        ("upgrading", Box::new(|h| h.state = "upgrading".into())),
        (
            "stale",
            Box::new(|h| h.last_seen = Utc::now() - chrono::Duration::hours(1)),
        ),
        (
            "unresolved",
            Box::new(|h| {
                h.memory_policy = Some(api::MemoryPolicy {
                    version: 99,
                    vmm_overhead_mb: 1,
                })
            }),
        ),
    ];
    for (what, mutate) in unknown {
        let (s, b) = classified(mutate, consumer(256), &["rx"]).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{what}: {b}");
        assert_eq!(b["reason"], "region_unconfirmed", "{what}");
        assert_eq!(outcomes(&b), vec![pair("rx", "unconfirmed")], "{what}");
    }
    // An operator decision, or not capacity yet: ignored, so a later region is next after a
    // full one. Behind a full first region the ignored one is skipped.
    for state in [
        "draining",
        "retiring",
        "failed",
        "joining",
        "provisioning",
        "bootstrapped",
    ] {
        let s = state.to_string();
        let (code, b) = classified(move |h| h.state = s, consumer(256), &["rf", "rx"]).await;
        assert_eq!(code, StatusCode::OK, "{state}: {b}");
        assert_eq!(
            outcomes(&b),
            vec![
                pair("rf", "full"),
                pair("rx", "ineligible"),
                pair("ry", "placed")
            ],
            "{state}"
        );
    }
    // Ready and serving nothing the requirements need, in the first region: its own refusal.
    let mut nested = consumer(256);
    nested["runtime_class"] = "nested".into();
    let (s, b) = classified(candidate, nested, &["rx"]).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
}

#[tokio::test]
async fn a_mixed_region_places_on_its_candidate() {
    let f = world();
    set_state(&f.st, "h1", "down");
    let (s, b) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(
        (b["region"].as_str(), b["host"].as_str()),
        (Some("bhs"), Some("h2"))
    );
    // And a down host beside a full one, no candidate: unconfirmed, as the table says.
    let f = world();
    set_state(&f.st, "h1", "down");
    fill(&f, "h2");
    let (s, b) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    assert_eq!(
        (s, b["reason"].as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, Some("region_unconfirmed"))
    );
}

#[tokio::test]
async fn within_a_region_the_host_with_the_most_free_memory_is_picked() {
    let f = world();
    f.st.reg
        .lock()
        .unwrap()
        .hosts
        .get_mut("h1")
        .unwrap()
        .used
        .memory_mb = 3_000;
    let (_, b) = admit(&f, "ns", "req_one", both(&["bhs"])).await;
    assert_eq!(b["host"], "h2");
}

/// A seed on `host` of the daemon `d`, as a seed admission's test makes one.
pub(super) fn seed_on(f: &Fleet, d: &Running, machine: &str) {
    let host = d.stub.id.clone();
    {
        let mut reg = f.st.reg.lock().unwrap();
        reg.machines.insert(machine.into(), host.clone());
        let h = reg.hosts.get_mut(&host).unwrap();
        h.named_memory_fork_v1 = true;
        h.named_memory_profiles = vec!["sandbox-ready-v1".into()];
    }
    d.stub.snapshots.lock().unwrap().push(api::Snapshot {
        copy_consistency: Default::default(),
        id: "s_one".into(),
        machine_id: machine.into(),
        name: None,
        created_at: Utc::now(),
        disks: vec!["root".into(), "data".into()],
        memory: true,
        clone_profile: Some("sandbox-ready-v1".into()),
        source_host: Some(host),
        clone_size: Some(api::Size {
            vcpus: 1,
            memory_mb: 256,
            cpu_millis: None,
        }),
        clone_ram_marker: None,
        clone_generation: Some("g_one".into()),
    });
}
fn with_seed(machine: &str) -> Value {
    let mut c = consumer(256);
    c["volume_gb"] = Value::Null;
    c.as_object_mut().unwrap().remove("volume_gb");
    c["sandbox_seeds"] =
        json!([{"machine_id": machine, "snapshot": "s_one", "generation": "g_one"}]);
    c
}

#[tokio::test]
async fn a_validated_seed_wins_inside_its_region_and_a_failed_check_is_cold() {
    let (f, ds) = fleet_in_regions(&["bhs", "bhs", "gra", "gra"]).await;
    // d1 is the fuller host of bhs: without the seed, d2 would be picked.
    ds[0].stub.add("t0", "big", 10_000);
    poll_static_hosts_once(&f.st).await;
    seed_on(&f, &ds[0], "m_seed");
    let (s, b) = admit(
        &f,
        "ns",
        "req_one",
        body(&["bhs", "gra"], vec![with_seed("m_seed")]),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(
        (b["mode"].as_str(), b["host"].as_str()),
        (Some("sandbox-seed"), Some("d1")),
        "{b}"
    );
    assert_eq!(b["seed"]["machine_id"], "m_seed");
    // A selector the host does not know: cold, never an error, and the usual pick.
    let (s, b) = admit(
        &f,
        "ns2",
        "req_two",
        body(&["bhs", "gra"], vec![with_seed("m_nope")]),
    )
    .await;
    assert_eq!(
        (s, b["mode"].as_str(), b["host"].as_str()),
        (StatusCode::OK, Some("cold"), Some("d2")),
        "{b}"
    );
    assert!(b.get("seed").is_none());
}

#[tokio::test]
async fn a_seed_on_another_regions_host_is_never_selected() {
    let (f, ds) = fleet_in_regions(&["bhs", "gra"]).await;
    seed_on(&f, &ds[1], "m_seed");
    // The only seed that fits is in gra, and only bhs is allowed: cold in bhs.
    let (s, b) = admit(
        &f,
        "ns",
        "req_one",
        body(&["bhs"], vec![with_seed("m_seed")]),
    )
    .await;
    assert_eq!(
        (s, b["mode"].as_str(), b["host"].as_str()),
        (StatusCode::OK, Some("cold"), Some("d1")),
        "{b}"
    );
    // Preferred bhs full: gra, where the seed is, is used.
    let (s, b) = admit(
        &f,
        "ns2",
        "req_two",
        body(&["gra"], vec![with_seed("m_seed")]),
    )
    .await;
    assert_eq!(
        (s, b["mode"].as_str()),
        (StatusCode::OK, Some("sandbox-seed")),
        "{b}"
    );
}

#[tokio::test]
async fn a_pending_admissions_pin_survives_the_heartbeat_forget_unpin_and_delete() {
    let (f, _ds) = fleet_in_regions(&["bhs", "gra"]).await;
    let (_, b) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    let host = b["host"].as_str().unwrap().to_string();
    // The host never lists the namespace, and the pin is older than ten minutes.
    let later = Utc::now() + chrono::Duration::minutes(11);
    let beat = |f: &Fleet, at| {
        let mut reg = f.st.reg.lock().unwrap();
        let mut h = reg.hosts[&host].clone();
        h.namespaces.clear();
        reg.heartbeat(h, at);
    };
    beat(&f, later);
    assert_eq!(pinned(&f.st, "ns").as_deref(), Some(host.as_str()));
    // The holds lapsed with the deadline, the fence did not.
    assert_eq!(holds(&f, &host), 0);
    // forget refuses while an admission is pending on the host.
    f.st.reg.lock().unwrap().forget(&host);
    assert!(f.st.reg.lock().unwrap().hosts.contains_key(&host));
    // Operator unpin and namespace delete refuse.
    let (s, _, _) = call(&f.st, "POST", "/v1/namespaces/ns/unpin", "api", None).await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, _, _) = call(&f.st, "DELETE", "/v1/namespaces/ns", "api", None).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(pinned(&f.st, "ns").as_deref(), Some(host.as_str()));
}

#[tokio::test]
async fn a_cancelled_admissions_pin_follows_the_heartbeat_rule() {
    let (f, _ds) = fleet_in_regions(&["bhs", "gra"]).await;
    let (_, b) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    let host = b["host"].as_str().unwrap().to_string();
    assert_eq!(cancel(&f, "ns", "req_one").await, StatusCode::NO_CONTENT);
    let beat = |at| {
        let mut reg = f.st.reg.lock().unwrap();
        let mut h = reg.hosts[&host].clone();
        h.namespaces.clear();
        reg.heartbeat(h, at);
    };
    // Younger than ten minutes: kept as any fresh pin; older and unlisted: released.
    beat(Utc::now() + chrono::Duration::minutes(5));
    assert!(pinned(&f.st, "ns").is_some());
    beat(Utc::now() + chrono::Duration::minutes(11));
    assert_eq!(pinned(&f.st, "ns"), None);
}

#[tokio::test]
async fn a_gateway_put_with_an_id_ends_cancellation_and_a_quota_put_only_that() {
    let (f, _ds) = fleet_in_regions(&["bhs", "gra"]).await;
    let (_, b) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    let host = b["host"].as_str().unwrap().to_string();
    // A quota with the id: checked and it ends cancellation, but consumes no requirement.
    let (s, _, text) = call(
        &f.st,
        "PUT",
        "/v1/namespaces/ns/quota?region=bhs&placement_request_id=req_one",
        "api",
        Some(json!({})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{text}");
    assert_eq!(cancel(&f, "ns", "req_one").await, StatusCode::CONFLICT);
    // Both requirements are still to dispatch: the fence and the holds stay.
    assert!(crate::sandbox_admissions::namespace_pending(
        &f.st.reg.lock().unwrap(),
        "ns"
    ));
    assert_eq!(holds(&f, &host), 2);
    // The gateway consumes its hold, a repeat (a retry) takes none and is not refused.
    let (s, text) = put_gateway(&f, "ns", "bhs", "req_one").await;
    assert_eq!(s, StatusCode::OK, "{text}");
    let (s, text) = put_gateway(&f, "ns", "bhs", "req_one").await;
    assert_eq!(s, StatusCode::OK, "{text}");
    // The consumer's create completes the admission: the fence goes with the last requirement.
    let (s, _, text) = create_under(&f, "ns", "bhs", "req_one", 256).await;
    assert_eq!(s, StatusCode::CREATED, "{text}");
    assert!(!crate::sandbox_admissions::namespace_pending(
        &f.st.reg.lock().unwrap(),
        "ns"
    ));
}

#[tokio::test]
async fn dispatch_that_differs_from_the_admission_is_409_and_forwards_nothing() {
    let (f, ds) = fleet_in_regions(&["bhs", "gra"]).await;
    let (_, b) = admit(&f, "ns", "req_one", both(&["bhs", "gra"])).await;
    let host = b["host"].as_str().unwrap().to_string();
    let before = snapshot(&f);
    let (s, text) = put_gateway(&f, "ns", "gra", "req_one").await;
    assert_eq!(s, StatusCode::CONFLICT, "{text}");
    let (s, text) = put_gateway(&f, "ns", "bhs", "req_unknown").await;
    assert_eq!(s, StatusCode::CONFLICT, "{text}");
    // A gateway of another size is not the admitted gateway.
    let (s, _, text) = call(
        &f.st,
        "PUT",
        "/v1/namespaces/ns/gateway?region=bhs&placement_request_id=req_one",
        "api",
        Some(json!({"image": "proxy:1", "port": 3128, "size": {"vcpus": 2, "memory_mb": 512}})),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{text}");
    // A create of another size, another region, a volume the admission did not name.
    let (s, _, text) = create_under(&f, "ns", "bhs", "req_one", 512).await;
    assert_eq!(s, StatusCode::CONFLICT, "{text}");
    let (s, _, text) = create_under(&f, "ns", "gra", "req_one", 256).await;
    assert_eq!(s, StatusCode::CONFLICT, "{text}");
    let (s, _, text) = call_with(
        &f.st,
        "127.0.0.1".parse().unwrap(),
        &[(crate::sandbox_admissions::HEADER, "req_one")],
        "POST",
        "/v1/machines",
        "api",
        Some({
            let mut b = create_body("ns", "sandbox", 256);
            b["region"] = "bhs".into();
            b
        }),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{text}");
    assert!(ds.iter().all(|d| d.stub.creates.lock().unwrap().is_empty()));
    assert!(f
        .st
        .reg
        .lock()
        .unwrap()
        .sandbox_admissions
        .values()
        .next()
        .unwrap()
        .pending());
    // Both holds are still there, and nothing else changed.
    assert_eq!(holds(&f, &host), 2);
    assert_eq!(snapshot(&f), before);
}

#[tokio::test]
async fn a_create_under_the_admission_goes_to_its_host_and_takes_over_its_hold() {
    let (f, ds) = fleet_in_regions(&["bhs", "bhs", "gra"]).await;
    // d1 is the fuller host: by memory alone the ordinary placement prefers d2.
    ds[0].stub.add("t0", "big", 10_000);
    poll_static_hosts_once(&f.st).await;
    let (_, b) = admit(&f, "ns", "req_one", body(&["bhs"], vec![consumer(256)])).await;
    assert_eq!(b["host"], "d2");
    let before = host_used(&f, "d2");
    let (s, h, text) = create_under(&f, "ns", "bhs", "req_one", 256).await;
    assert_eq!(s, StatusCode::CREATED, "{text}");
    assert_eq!(h["x-briqyard-host"], "d2");
    // The admission's hold became the create's: the host's figure counts the memory once.
    assert_eq!(host_used(&f, "d2"), before);
    assert_eq!(holds(&f, "d2"), 0);
}

#[tokio::test]
async fn a_completed_admission_is_replayed_for_a_day_from_the_last_dispatch() {
    let (f, _ds) = fleet_in_regions(&["bhs", "gra"]).await;
    let (_, first) = admit(&f, "ns", "req_one", body(&["bhs"], vec![consumer(256)])).await;
    let (s, _, text) = create_under(&f, "ns", "bhs", "req_one", 256).await;
    assert_eq!(s, StatusCode::CREATED, "{text}");
    let at = Utc::now();
    f.st.reg
        .lock()
        .unwrap()
        .prune(at + chrono::Duration::hours(23));
    let (s, again) = admit(&f, "ns", "req_one", body(&["bhs"], vec![consumer(256)])).await;
    assert_eq!((s, again), (StatusCode::OK, first));
    f.st.reg
        .lock()
        .unwrap()
        .prune(at + chrono::Duration::hours(26));
    assert!(f.st.reg.lock().unwrap().sandbox_admissions.is_empty());
}

#[tokio::test]
async fn hold_deadline_is_pruned_by_the_heartbeat() {
    let f = world();
    let (_, b) = admit(&f, "ns", "req_one", both(&["bhs"])).await;
    let host = b["host"].as_str().unwrap().to_string();
    assert_eq!(holds(&f, &host), 2);
    f.st.reg
        .lock()
        .unwrap()
        .prune(Utc::now() + chrono::Duration::minutes(3));
    assert_eq!(holds(&f, &host), 2);
    f.st.reg
        .lock()
        .unwrap()
        .prune(Utc::now() + chrono::Duration::minutes(5));
    assert_eq!((holds(&f, &host), host_used(&f, &host)), (0, 1_000));
    // Decision and pin stay.
    assert_eq!(pinned(&f.st, "ns").as_deref(), Some(host.as_str()));
}

#[tokio::test]
async fn the_status_advertises_placement_admission() {
    let f = world();
    let (s, _, b) = call(&f.st, "GET", "/v1/status", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(json(&b)["placement_admission_v1"], true);
}

#[tokio::test]
async fn invalid_bodies_are_400_and_store_nothing() {
    let f = world();
    let bad = vec![
        json!({"regions": [], "requirements": [gateway()]}),
        json!({"regions": ["bhs", "bhs"], "requirements": [gateway()]}),
        json!({"regions": ["bhs"], "requirements": []}),
        json!({"regions": ["bhs"], "requirements": [gateway(), gateway()]}),
        json!({"regions": ["bhs"], "requirements": [{"role": "consumer", "size": {"vcpus": 0, "memory_mb": 256}}]}),
        json!({"regions": ["bhs"], "requirements": [{"role": "gateway", "size": {"vcpus": 1, "memory_mb": 256}, "sandbox_seeds": [{"machine_id": "m_x", "snapshot": "s_one", "generation": "g_one"}]}]}),
        json!({"regions": ["bhs"], "requirements": [gateway()], "extra": 1}),
    ];
    let before = snapshot(&f);
    for b in bad {
        let (s, _, text) = call(&f.st, "PUT", &path("ns", "req_one"), "api", Some(b.clone())).await;
        assert!(
            s == StatusCode::BAD_REQUEST || s == StatusCode::UNPROCESSABLE_ENTITY,
            "{b}: {s} {text}"
        );
    }
    assert_eq!(snapshot(&f), before);
}
