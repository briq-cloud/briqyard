//! A seeded sandbox in a spilling walk: the placement admission checks the offered seeds on
//! their hosts, and the walk weighs the boot queue of a host that holds one. These tests drive
//! the whole route against stub daemons: the admission, then the create that follows it.

use super::placement_admission::{admit, body, consumer, outcomes, pair, seed_on};
use super::*;
use serde_json::{json, Value};

/// A consumer requirement offering `machines`, each with the snapshot `seed_on` makes.
fn offering(machines: &[&str]) -> Value {
    let mut c = consumer(256);
    c.as_object_mut().unwrap().remove("volume_gb");
    c["sandbox_seeds"] = machines
        .iter()
        .map(|m| selector(m))
        .collect::<Vec<_>>()
        .into();
    c
}
fn selector(machine: &str) -> Value {
    json!({"machine_id": machine, "snapshot": "s_one", "generation": "g_one"})
}
/// A spilling request over `regions`, offering `machines`.
fn spill_request(regions: &[&str], machines: &[&str]) -> Value {
    let mut b = body(regions, vec![offering(machines)]);
    b["spill_when_busy"] = true.into();
    b
}
/// `id` reports a gate of 4 boots and `queued` waiting, heard of just now: the admission does
/// not read it again, so the figures stand.
fn queue(f: &Fleet, id: &str, queued: u32) {
    let mut reg = f.st.reg.lock().unwrap();
    let h = reg.hosts.get_mut(id).unwrap();
    h.boots_at_once = Some(4);
    h.boot_queue = Some(queued);
    h.last_seen = Utc::now();
}
/// The create that follows an admission, carrying `seed` when given.
async fn create_with(
    f: &Fleet,
    ns: &str,
    region: &str,
    id: &str,
    seed: Option<Value>,
) -> (StatusCode, String) {
    let mut b = create_body(ns, "sandbox", 256);
    b["region"] = region.into();
    b["start"] = true.into();
    if let Some(mut seed) = seed {
        seed["request_id"] = id.into();
        b["sandbox_seed"] = seed;
    }
    let (s, _, text) = call_with(
        &f.st,
        "127.0.0.1".parse().unwrap(),
        &[(crate::sandbox_admissions::HEADER, id)],
        "POST",
        "/v1/machines",
        "api",
        Some(b),
    )
    .await;
    (s, text)
}

#[tokio::test]
async fn a_spilled_admission_answers_the_seed_of_the_other_regions_host() {
    // d1 and d2 in bhs, d3 in gra. Seeds on d1 (bhs) and d3 (gra), both offered.
    let (f, ds) = fleet_in_regions(&["bhs", "bhs", "gra"]).await;
    seed_on(&f, &ds[0], "m_bhs");
    seed_on(&f, &ds[2], "m_gra");
    // Both bhs hosts are three waves deep: bhs scores 3, gra 0 + 1 × 2.
    queue(&f, "d1", 12);
    queue(&f, "d2", 12);
    let (s, b) = admit(
        &f,
        "ns",
        "req_one",
        spill_request(&["bhs", "gra"], &["m_bhs", "m_gra"]),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(
        (b["region"].as_str(), b["host"].as_str(), b["mode"].as_str()),
        (Some("gra"), Some("d3"), Some("sandbox-seed")),
        "{b}"
    );
    assert_eq!(b["seed"]["machine_id"], "m_gra", "{b}");
    assert_eq!(
        outcomes(&b),
        vec![pair("bhs", "busy"), pair("gra", "placed")]
    );
    assert_eq!(pinned(&f.st, "ns").as_deref(), Some("d3"));

    // Only the far host holds a seed: the same answer.
    let (f, ds) = fleet_in_regions(&["bhs", "bhs", "gra"]).await;
    seed_on(&f, &ds[2], "m_gra");
    queue(&f, "d1", 12);
    queue(&f, "d2", 12);
    let (s, b) = admit(
        &f,
        "ns",
        "req_one",
        spill_request(&["bhs", "gra"], &["m_gra"]),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(
        (b["host"].as_str(), b["mode"].as_str()),
        (Some("d3"), Some("sandbox-seed")),
        "{b}"
    );
    assert_eq!(b["seed"]["machine_id"], "m_gra");
}

#[tokio::test]
async fn a_spilled_admission_to_a_host_without_a_seed_is_cold() {
    // The only seed is on a bhs host too deep to keep the burst: gra takes it, cold.
    let (f, ds) = fleet_in_regions(&["bhs", "gra"]).await;
    seed_on(&f, &ds[0], "m_bhs");
    queue(&f, "d1", 12);
    let (s, b) = admit(
        &f,
        "ns",
        "req_one",
        spill_request(&["bhs", "gra"], &["m_bhs"]),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(
        (b["host"].as_str(), b["mode"].as_str()),
        (Some("d2"), Some("cold")),
        "{b}"
    );
    assert!(b.get("seed").is_none(), "{b}");
}

#[tokio::test]
async fn without_the_flag_the_seed_of_the_other_region_is_not_taken() {
    // The same queue and seeds, no `spill_when_busy`: the first region keeps the burst, cold.
    let (f, ds) = fleet_in_regions(&["bhs", "gra"]).await;
    seed_on(&f, &ds[1], "m_gra");
    queue(&f, "d1", 12);
    let (s, b) = admit(
        &f,
        "ns",
        "req_one",
        body(&["bhs", "gra"], vec![offering(&["m_gra"])]),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(
        (b["host"].as_str(), b["mode"].as_str()),
        (Some("d1"), Some("cold")),
        "{b}"
    );
}

#[tokio::test]
async fn a_seeded_host_loses_its_preference_at_spill_waves() {
    // d1 holds the seed; d2 is an idle host of the same region. spill_waves is 2.
    let (f, ds) = fleet_in_regions(&["bhs", "bhs", "gra"]).await;
    seed_on(&f, &ds[0], "m_bhs");
    // One wave: the seed still comes first.
    queue(&f, "d1", 4);
    let (_, b) = admit(
        &f,
        "ns1",
        "req_1",
        spill_request(&["bhs", "gra"], &["m_bhs"]),
    )
    .await;
    assert_eq!(
        (b["host"].as_str(), b["mode"].as_str()),
        (Some("d1"), Some("sandbox-seed")),
        "{b}"
    );
    // Two waves, the threshold: d1 is deep and loses the preference to the idle d2 of the same
    // region.
    queue(&f, "d1", 8);
    let (_, b) = admit(
        &f,
        "ns2",
        "req_2",
        spill_request(&["bhs", "gra"], &["m_bhs"]),
    )
    .await;
    assert_eq!(
        (b["region"].as_str(), b["host"].as_str(), b["mode"].as_str()),
        (Some("bhs"), Some("d2"), Some("cold")),
        "{b}"
    );
    assert!(b.get("seed").is_none(), "{b}");
}

#[tokio::test]
async fn a_seeded_host_that_is_deep_loses_to_a_host_in_the_next_region() {
    // d1 holds the seed and is three waves deep; the next region's d2 is idle and holds none.
    let (f, ds) = fleet_in_regions(&["bhs", "gra"]).await;
    seed_on(&f, &ds[0], "m_bhs");
    queue(&f, "d1", 12);
    let (s, b) = admit(
        &f,
        "ns",
        "req_one",
        spill_request(&["bhs", "gra"], &["m_bhs"]),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(
        (b["region"].as_str(), b["host"].as_str(), b["mode"].as_str()),
        (Some("gra"), Some("d2"), Some("cold")),
        "{b}"
    );
    assert_eq!(
        outcomes(&b),
        vec![pair("bhs", "busy"), pair("gra", "placed")]
    );

    // At the threshold the region keeps the burst (a later region needs a strictly lower
    // score), and so does the seeded host: it is the region's only one.
    let (f, ds) = fleet_in_regions(&["bhs", "gra"]).await;
    seed_on(&f, &ds[0], "m_bhs");
    queue(&f, "d1", 8);
    let (_, b) = admit(
        &f,
        "ns",
        "req_one",
        spill_request(&["bhs", "gra"], &["m_bhs"]),
    )
    .await;
    assert_eq!(
        (b["region"].as_str(), b["host"].as_str()),
        (Some("bhs"), Some("d1")),
        "{b}"
    );
}

#[tokio::test]
async fn a_create_with_the_answered_seed_is_accepted_and_another_is_refused() {
    let (f, ds) = fleet_in_regions(&["bhs", "bhs", "gra"]).await;
    seed_on(&f, &ds[0], "m_bhs");
    seed_on(&f, &ds[2], "m_gra");
    queue(&f, "d1", 12);
    queue(&f, "d2", 12);
    let (s, b) = admit(
        &f,
        "ns",
        "req_one",
        spill_request(&["bhs", "gra"], &["m_bhs", "m_gra"]),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["seed"]["machine_id"], "m_gra", "{b}");

    // A seed that was offered but not answered: refused, and nothing reached a host.
    let (s, text) = create_with(&f, "ns", "gra", "req_one", Some(selector("m_bhs"))).await;
    assert_eq!(s, StatusCode::CONFLICT, "{text}");
    assert!(text.contains("selector differs"), "{text}");
    // The answered machine with another snapshot or generation.
    for (field, value) in [("snapshot", "s_other"), ("generation", "g_other")] {
        let mut other = selector("m_gra");
        other[field] = value.into();
        let (s, text) = create_with(&f, "ns", "gra", "req_one", Some(other)).await;
        assert_eq!(s, StatusCode::CONFLICT, "{field}: {text}");
    }
    // No seed at all, when one was admitted.
    let (s, text) = create_with(&f, "ns", "gra", "req_one", None).await;
    assert_eq!(s, StatusCode::CONFLICT, "{text}");
    for d in &ds {
        assert!(d.stub.creates.lock().unwrap().is_empty());
    }

    // The answered seed: accepted, on the admitted host.
    let (s, text) = create_with(&f, "ns", "gra", "req_one", Some(selector("m_gra"))).await;
    assert_eq!(s, StatusCode::CREATED, "{text}");
    let creates = ds[2].stub.creates.lock().unwrap();
    assert_eq!(creates.len(), 1);
    assert_eq!(
        creates[0].sandbox_seed.as_ref().unwrap().machine_id,
        "m_gra"
    );
    assert!(ds[0].stub.creates.lock().unwrap().is_empty());
    assert!(ds[1].stub.creates.lock().unwrap().is_empty());
}

/// The time of an admission with 0, 1 and 3 offered seeds, each on a host of its own, against
/// stub daemons on loopback: `cargo test -p briqyard-fleet --release admission_seed_check_cost
/// -- --ignored --nocapture`. Loopback has no network latency, so it shows the work the check
/// adds (two reads per seed, the seeds in parallel), not what a far host's round trip adds.
#[tokio::test]
#[ignore = "a measurement, not a check"]
async fn admission_seed_check_cost() {
    const RUNS: usize = 200;
    let (f, ds) = fleet_in_regions(&["bhs", "bhs", "gra"]).await;
    let machines = ["m_a", "m_b", "m_c"];
    for (d, m) in ds.iter().zip(machines) {
        seed_on(&f, d, m);
    }
    // The three cases run in turn within each iteration, so the growth of the registry over the
    // runs weighs on each the same.
    let cases = [0usize, 1, 3];
    let mut micros: Vec<Vec<u128>> = vec![Vec::with_capacity(RUNS); cases.len()];
    for i in 0..RUNS {
        for (case, seeds) in cases.into_iter().enumerate() {
            let ns = format!("ns{case}x{i}");
            let id = format!("req_{case}x{i}");
            let b = spill_request(&["bhs", "gra"], &machines[..seeds]);
            let start = std::time::Instant::now();
            let (s, b) = admit(&f, &ns, &id, b).await;
            micros[case].push(start.elapsed().as_micros());
            assert_eq!(s, StatusCode::OK, "{b}");
            assert_eq!(b["mode"] == "sandbox-seed", seeds > 0, "{b}");
            // Release the hold, so the hosts do not fill over the runs.
            let path = format!("/v1/namespaces/{ns}/admissions/{id}");
            let (s, _, text) = call(&f.st, "DELETE", &path, "api", None).await;
            assert!(s.is_success(), "{text}");
        }
    }
    for (case, seeds) in cases.into_iter().enumerate() {
        let m = &mut micros[case];
        m.sort_unstable();
        println!(
            "seeds {seeds}: p50 {} us, p95 {} us, max {} us ({RUNS} admissions)",
            m[RUNS / 2],
            m[RUNS * 95 / 100],
            m[RUNS - 1]
        );
    }
}
