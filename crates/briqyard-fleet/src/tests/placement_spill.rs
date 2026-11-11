//! The walk that spills a burst to a later region when the first is queueing boots (ADR 0130).

use super::placement_admission::{
    admit, both, cfg, consumer, fill, holds, outcomes, pair, put_host,
};
use super::*;
use serde_json::Value;

/// `id` reports a gate of `at_once` boots and `queue` waiting, last heard of five seconds ago:
/// a fresh read is not skipped for it.
fn queue(f: &Fleet, id: &str, at_once: u32, queued: u32) {
    let mut reg = f.st.reg.lock().unwrap();
    let h = reg.hosts.get_mut(id).unwrap();
    h.boots_at_once = Some(at_once);
    h.boot_queue = Some(queued);
    h.last_seen = Utc::now() - chrono::Duration::seconds(5);
}
fn spilling(mut b: Value) -> Value {
    b["spill_when_busy"] = true.into();
    b
}
/// `bhs` h1 and h2, `gra` h3 and h4, `rbx` h5, all idle with a gate of 4.
fn world3() -> Fleet {
    let f = fleet(cfg());
    for (id, region) in [
        ("h1", "bhs"),
        ("h2", "bhs"),
        ("h3", "gra"),
        ("h4", "gra"),
        ("h5", "rbx"),
    ] {
        put_host(&f, id, region, 10_000, 1_000);
        queue(&f, id, 4, 0);
    }
    f
}
fn busy_both(f: &Fleet, queued: u32) {
    queue(f, "h1", 4, queued);
    queue(f, "h2", 4, queued);
}
fn depth(b: &Value, region: &str) -> Option<u64> {
    b["regions"]
        .as_array()?
        .iter()
        .find(|o| o["region"] == region)?["depth"]
        .as_u64()
}

#[tokio::test]
async fn a_region_below_the_threshold_keeps_the_burst() {
    let f = world3();
    // 7 queued behind a gate of 4: one whole wave, below spill_waves = 2.
    busy_both(&f, 7);
    let (s, b) = admit(&f, "ns", "r1", spilling(both(&["bhs", "gra"]))).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["region"], "bhs");
    assert_eq!(outcomes(&b), vec![pair("bhs", "placed")]);
}

#[tokio::test]
async fn busy_at_the_threshold_stays_and_one_wave_deeper_spills() {
    // 8 queued behind a gate of 4: two waves, the threshold. The region is busy, and the idle
    // next region scores 0 + 1 × 2 = 2: a tie stays. The hosts of bhs do not answer a fresh
    // read here, so they keep the figures they had.
    let f = world3();
    busy_both(&f, 8);
    let (s, b) = admit(&f, "ns", "r1", spilling(both(&["bhs", "gra"]))).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(outcomes(&b), vec![pair("bhs", "placed")]);
    assert_eq!(
        f.st.busy_reads.lock().unwrap().len(),
        2,
        "both hosts were read"
    );

    // 12 queued: three waves against 2, the next region takes the burst.
    let f = world3();
    busy_both(&f, 12);
    let (s, b) = admit(&f, "ns", "r1", spilling(both(&["bhs", "gra"]))).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["region"], "gra");
    assert_eq!(
        outcomes(&b),
        vec![pair("bhs", "busy"), pair("gra", "placed")]
    );
    assert_eq!(depth(&b, "bhs"), Some(3));
    assert_eq!(depth(&b, "gra"), None);
    assert_eq!(
        pinned(&f.st, "ns").as_deref(),
        Some(b["host"].as_str().unwrap())
    );
}

#[tokio::test]
async fn a_later_region_wins_only_with_a_strictly_lower_score() {
    // score = depth + index × spill_waves (2): bhs 5 against gra 2 + 2 = 4.
    let f = world3();
    busy_both(&f, 20);
    queue(&f, "h3", 4, 8);
    queue(&f, "h4", 4, 8);
    let (_, b) = admit(&f, "ns", "r1", spilling(both(&["bhs", "gra"]))).await;
    assert_eq!(b["region"], "gra", "{b}");
    assert_eq!(depth(&b, "bhs"), Some(5));

    // bhs 4 against gra 4: a tie stays in the first region, which is busy and placed in.
    let f = world3();
    busy_both(&f, 16);
    queue(&f, "h3", 4, 8);
    queue(&f, "h4", 4, 8);
    let (_, b) = admit(&f, "ns", "r1", spilling(both(&["bhs", "gra"]))).await;
    assert_eq!(b["region"], "bhs", "{b}");
    assert_eq!(outcomes(&b), vec![pair("bhs", "placed")]);

    // Three regions: bhs 6, gra 3 + 2 = 5, rbx 1 + 4 = 5: gra, the first of the lowest.
    let f = world3();
    busy_both(&f, 24);
    queue(&f, "h3", 4, 12);
    queue(&f, "h4", 4, 12);
    queue(&f, "h5", 4, 4);
    let (_, b) = admit(&f, "ns", "r1", spilling(both(&["bhs", "gra", "rbx"]))).await;
    assert_eq!(b["region"], "gra", "{b}");
    assert_eq!(
        outcomes(&b),
        vec![pair("bhs", "busy"), pair("gra", "placed")]
    );

    // rbx idle: 0 + 4 = 4 beats bhs 6 and gra 3 + 2 = 5, and gra is listed as busy too.
    let f = world3();
    busy_both(&f, 24);
    queue(&f, "h3", 4, 12);
    queue(&f, "h4", 4, 12);
    let (_, b) = admit(&f, "ns", "r1", spilling(both(&["bhs", "gra", "rbx"]))).await;
    assert_eq!(b["region"], "rbx", "{b}");
    assert_eq!(
        outcomes(&b),
        vec![
            pair("bhs", "busy"),
            pair("gra", "busy"),
            pair("rbx", "placed")
        ]
    );
    assert_eq!(depth(&b, "gra"), Some(3));
}

#[tokio::test]
async fn holds_count_in_the_queue_until_the_host_reports_them() {
    let f = world3();
    // 10 queued, a gate of 4: two waves, a tie with the idle region. One admission adds its
    // two holds (gateway, consumer) to its host.
    busy_both(&f, 10);
    let (_, a) = admit(&f, "ns1", "r1", spilling(both(&["bhs", "gra"]))).await;
    assert_eq!(a["region"], "bhs");
    let host = a["host"].as_str().unwrap();
    assert_eq!(holds(&f, host), 2);
    // 12 on that host, 10 on the other: the pick takes the shallower one.
    let (_, b) = admit(&f, "ns2", "r2", spilling(both(&["bhs", "gra"]))).await;
    assert_eq!(b["region"], "bhs");
    assert_ne!(b["host"].as_str().unwrap(), host);
    // Both hold 12 now: three waves against 2.
    let (_, c) = admit(&f, "ns3", "r3", spilling(both(&["bhs", "gra"]))).await;
    assert_eq!(c["region"], "gra", "{c}");
    assert_eq!(depth(&c, "bhs"), Some(3));
}

#[tokio::test]
async fn a_fresh_read_can_clear_a_busy_region() {
    let (f, ds) = fleet_in_regions(&["bhs", "gra"]).await;
    // The heartbeat figures say deep; the host has since drained.
    queue(&f, "d1", 4, 40);
    ds[0].stub.boot_figures.lock().unwrap().replace((4, 0));
    let (s, b) = admit(&f, "ns", "r1", spilling(both(&["bhs", "gra"]))).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["region"], "bhs", "{b}");
    assert_eq!(outcomes(&b), vec![pair("bhs", "placed")]);
    assert_eq!(f.st.reg.lock().unwrap().hosts["d1"].boot_queue, Some(0));
    assert!(ds[0].stub.calls().iter().any(|c| c.contains("status")));
}

#[tokio::test]
async fn a_fresh_read_can_confirm_a_busy_region() {
    let (f, ds) = fleet_in_regions(&["bhs", "gra"]).await;
    queue(&f, "d1", 4, 12);
    ds[0].stub.boot_figures.lock().unwrap().replace((4, 12));
    let (_, b) = admit(&f, "ns", "r1", spilling(both(&["bhs", "gra"]))).await;
    assert_eq!(b["region"], "gra", "{b}");
    assert_eq!(depth(&b, "bhs"), Some(3));
}

#[tokio::test]
async fn a_host_heard_from_a_moment_ago_is_not_read_again() {
    let (f, ds) = fleet_in_regions(&["bhs", "gra"]).await;
    ds[0].stub.boot_figures.lock().unwrap().replace((4, 40));
    poll_static_hosts_once(&f.st).await;
    // The poll just heard it: its figures are fresh, the stub is not asked again.
    ds[0].stub.boot_figures.lock().unwrap().replace((4, 0));
    let (_, b) = admit(&f, "ns", "r1", spilling(both(&["bhs", "gra"]))).await;
    assert_eq!(b["region"], "gra", "{b}");
}

#[tokio::test]
async fn nothing_is_read_when_nothing_is_busy() {
    let (f, ds) = fleet_in_regions(&["bhs", "gra"]).await;
    ds[0].stub.boot_figures.lock().unwrap().replace((4, 3));
    poll_static_hosts_once(&f.st).await;
    f.st.reg
        .lock()
        .unwrap()
        .hosts
        .get_mut("d1")
        .unwrap()
        .last_seen = Utc::now() - chrono::Duration::seconds(5);
    let before = ds[0].stub.calls().len();
    let (_, b) = admit(&f, "ns", "r1", spilling(both(&["bhs", "gra"]))).await;
    assert_eq!(b["region"], "bhs");
    assert_eq!(ds[0].stub.calls().len(), before);
}

#[tokio::test]
async fn without_the_flag_nothing_changes() {
    let f = world3();
    busy_both(&f, 40);
    let before = f.st.busy_reads.lock().unwrap().len();
    for body in [both(&["bhs", "gra"]), {
        let mut b = both(&["bhs", "gra"]);
        b["spill_when_busy"] = false.into();
        b
    }] {
        let f = world3();
        busy_both(&f, 40);
        let (s, b) = admit(&f, "ns", "r1", body).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["region"], "bhs");
        assert_eq!(outcomes(&b), vec![pair("bhs", "placed")]);
        assert!(f.st.busy_reads.lock().unwrap().is_empty());
    }
    assert_eq!(before, 0);
}

#[tokio::test]
async fn one_region_or_no_spill_waves_is_the_walk_of_adr_0128() {
    let f = world3();
    busy_both(&f, 40);
    let (_, b) = admit(&f, "ns", "r1", spilling(both(&["bhs"]))).await;
    assert_eq!(outcomes(&b), vec![pair("bhs", "placed")]);
    assert!(f.st.busy_reads.lock().unwrap().is_empty());

    let f = fleet(config::Config {
        placement: config::Placement {
            spill_waves: 0,
            ..Default::default()
        },
        ..cfg()
    });
    for (id, region) in [("h1", "bhs"), ("h3", "gra")] {
        put_host(&f, id, region, 10_000, 1_000);
    }
    queue(&f, "h1", 4, 40);
    // The field is accepted, and the walk is ADR 0128.
    let (s, b) = admit(&f, "ns", "r1", spilling(both(&["bhs", "gra"]))).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(outcomes(&b), vec![pair("bhs", "placed")]);
    assert!(f.st.busy_reads.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_host_without_figures_is_never_busy() {
    let f = world3();
    for id in ["h1", "h2"] {
        let mut reg = f.st.reg.lock().unwrap();
        let h = reg.hosts.get_mut(id).unwrap();
        h.boots_at_once = None;
        h.boot_queue = Some(500);
    }
    let (_, b) = admit(&f, "ns", "r1", spilling(both(&["bhs", "gra"]))).await;
    assert_eq!(outcomes(&b), vec![pair("bhs", "placed")]);
}

#[tokio::test]
async fn a_later_region_without_a_candidate_is_skipped_never_a_refusal() {
    let f = world3();
    busy_both(&f, 20);
    fill(&f, "h3");
    fill(&f, "h4");
    set_state(&f.st, "h5", "down");
    let (s, b) = admit(&f, "ns", "r1", spilling(both(&["bhs", "gra", "rbx"]))).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["region"], "bhs");
    assert_eq!(outcomes(&b), vec![pair("bhs", "placed")]);

    // Before any region with a candidate, a full region moves on and is listed.
    let f = world3();
    fill(&f, "h1");
    fill(&f, "h2");
    busy_both_gra(&f);
    let (_, b) = admit(&f, "ns", "r1", spilling(both(&["bhs", "gra", "rbx"]))).await;
    assert_eq!(b["region"], "rbx", "{b}");
    assert_eq!(
        outcomes(&b),
        vec![
            pair("bhs", "full"),
            pair("gra", "busy"),
            pair("rbx", "placed")
        ]
    );
}
fn busy_both_gra(f: &Fleet) {
    queue(f, "h3", 4, 40);
    queue(f, "h4", 4, 40);
}

#[tokio::test]
async fn within_a_region_fewer_waves_come_before_free_memory_only_when_spilling() {
    let build = || {
        let f = fleet(cfg());
        // h1 has the most free memory but is three waves deep.
        put_host(&f, "h1", "bhs", 10_000, 1_000);
        put_host(&f, "h2", "bhs", 10_000, 3_000);
        put_host(&f, "h3", "gra", 10_000, 1_000);
        queue(&f, "h1", 4, 12);
        queue(&f, "h2", 4, 0);
        f
    };
    let f = build();
    let (_, b) = admit(&f, "ns", "r1", both(&["bhs", "gra"])).await;
    assert_eq!(
        (b["host"].as_str(), b["region"].as_str()),
        (Some("h1"), Some("bhs"))
    );
    // Spilling: h2 is the host of bhs, depth 0, and bhs is not busy.
    let f = build();
    let (_, b) = admit(&f, "ns", "r1", spilling(both(&["bhs", "gra"]))).await;
    assert_eq!(
        (b["host"].as_str(), b["region"].as_str()),
        (Some("h2"), Some("bhs")),
        "{b}"
    );
    assert_eq!(outcomes(&b), vec![pair("bhs", "placed")]);
}

#[tokio::test]
async fn a_pinned_namespace_ignores_busy() {
    let f = world3();
    let (_, a) = admit(&f, "ns", "r1", both(&["bhs", "gra"])).await;
    let host = a["host"].as_str().unwrap().to_string();
    queue(&f, &host, 4, 400);
    let (_, b) = admit(&f, "ns", "r2", spilling(both(&["gra", "bhs"]))).await;
    assert_eq!(
        (b["binding"].as_str(), b["host"].as_str()),
        (Some("existing"), Some(host.as_str()))
    );
}

#[tokio::test]
async fn the_flag_is_part_of_the_fingerprint_only_when_set() {
    let f = world3();
    let plain = both(&["bhs", "gra"]);
    let (_, a) = admit(&f, "ns", "r1", plain.clone()).await;
    // false and absent are the same body, whatever the order of the keys.
    let mut off = plain.clone();
    off["spill_when_busy"] = false.into();
    let (s, b) = admit(&f, "ns", "r1", off).await;
    assert_eq!((s, &b), (StatusCode::OK, &a));
    // The other value under the same id is a different body.
    let (s, _) = admit(&f, "ns", "r1", spilling(plain.clone())).await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (_, c) = admit(&f, "ns2", "r2", spilling(plain.clone())).await;
    let (s, _) = admit(&f, "ns2", "r2", plain).await;
    assert_eq!(s, StatusCode::CONFLICT);
    // The stored record never carries the flag, so a fleet rolled back past this ADR loads it.
    let saved = std::fs::read_to_string(&f.st.state_path).unwrap();
    // (Inside a fingerprint, a string, it is escaped.)
    assert!(!saved.contains("\"spill_when_busy\""), "{c}");
}

#[tokio::test]
async fn a_replay_returns_the_spilled_decision_whatever_the_queue_became() {
    let f = world3();
    busy_both(&f, 20);
    let (_, a) = admit(&f, "ns", "r1", spilling(both(&["bhs", "gra"]))).await;
    assert_eq!(a["region"], "gra");
    busy_both(&f, 0);
    let (s, b) = admit(&f, "ns", "r1", spilling(both(&["bhs", "gra"]))).await;
    assert_eq!((s, &b), (StatusCode::OK, &a));
}

#[tokio::test]
async fn an_older_client_reads_busy_as_full() {
    #[derive(serde::Deserialize, Debug, PartialEq)]
    #[serde(rename_all = "snake_case")]
    enum Before {
        Placed,
        Unconfirmed,
        Ineligible,
        #[serde(other)]
        Full,
    }
    #[derive(serde::Deserialize)]
    struct Outcome {
        outcome: Before,
    }
    #[derive(serde::Deserialize)]
    struct Decision {
        regions: Vec<Outcome>,
    }
    let f = world3();
    busy_both(&f, 20);
    let (_, text) = {
        let (s, _, t) = call(
            &f.st,
            "PUT",
            "/v1/namespaces/ns/admissions/r1",
            "api",
            Some(spilling(both(&["bhs", "gra"]))),
        )
        .await;
        (s, t)
    };
    let d: Decision = serde_json::from_str(&text).unwrap();
    assert_eq!(
        d.regions.iter().map(|o| &o.outcome).collect::<Vec<_>>(),
        vec![&Before::Full, &Before::Placed]
    );
}

#[tokio::test]
async fn the_status_advertises_spill_and_the_metrics_count_it() {
    let f = world3();
    let (s, _, b) = call(&f.st, "GET", "/v1/status", "api", None).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(json(&b)["placement_spill_v1"], true);
    busy_both(&f, 20);
    admit(&f, "ns", "r1", spilling(both(&["bhs", "gra"]))).await;
    admit(&f, "ns2", "r2", spilling(both(&["bhs", "gra"]))).await;
    let (_, _, m) = call(&f.st, "GET", "/metrics", "api", None).await;
    assert!(
        m.contains(r#"briqyard_fleet_placement_spills_total{from="bhs",to="gra"} 2"#),
        "{m}"
    );
    // A replay is not a second spill.
    admit(&f, "ns", "r1", spilling(both(&["bhs", "gra"]))).await;
    let (_, _, m) = call(&f.st, "GET", "/metrics", "api", None).await;
    assert!(m.contains(r#"to="gra"} 2"#), "{m}");
    let _ = consumer(1);
}
