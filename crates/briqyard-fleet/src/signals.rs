//! What an external scaler reads (ADR 0042), as the Cluster Autoscaler reads the scheduler's
//! unschedulable pods: each region's room, and every create refused for want of room, counted
//! by what ran out. On `/metrics` and in `/v1/status`.

use crate::registry::{Policy, Registry, Resource};
use briqyard_api::metrics::{family, label_value};
use briqyard_api::{RegionRoom, Room, Unschedulable};
use std::collections::BTreeMap;
use std::sync::Mutex;

/// The region a refusal is counted in when no host is in the region it asked: a caller's typo
/// never makes a new series.
pub const OTHER: &str = "other";

/// Creates refused 503 `capacity` since the fleet started, by region and what ran out.
#[derive(Default)]
pub struct Refusals(Mutex<BTreeMap<(String, Resource), u64>>);

impl Refusals {
    /// Counts one refusal in `region` (a host's, empty, or `OTHER`).
    pub fn count(&self, region: &str, resource: Resource) {
        *self
            .0
            .lock()
            .unwrap()
            .entry((region.to_string(), resource))
            .or_default() += 1;
    }
}

/// The region a refusal is counted in: the one asked when a host is in it or none was asked,
/// else `OTHER`.
pub fn counted_region<'a>(reg: &Registry, asked: &'a str) -> &'a str {
    match asked.is_empty() || reg.hosts.values().any(|h| h.region == asked) {
        true => asked,
        false => OTHER,
    }
}

/// Each region a host is in, with its room, and each a refusal was counted in, by name. A
/// region no host is in has no room: it would read as a region with none.
pub fn regions(reg: &Registry, policy: &Policy, refusals: &Refusals) -> Vec<RegionRoom> {
    let mut out: BTreeMap<String, RegionRoom> = reg
        .room(policy)
        .into_iter()
        .map(|(region, (free, largest_slot))| {
            let room = RegionRoom {
                region: region.clone(),
                free: Some(free),
                largest_slot: Some(largest_slot),
                unschedulable: Unschedulable::default(),
            };
            (region, room)
        })
        .collect();
    for ((region, resource), n) in refusals.0.lock().unwrap().iter() {
        let room = out.entry(region.clone()).or_insert_with(|| RegionRoom {
            region: region.clone(),
            ..Default::default()
        });
        let u = &mut room.unschedulable;
        match resource {
            Resource::Memory => u.memory = *n,
            Resource::Cpu => u.cpu = *n,
            Resource::Disk => u.disk = *n,
            Resource::Pressure => u.pressure = *n,
        }
    }
    out.into_values().collect()
}

/// The fleet's `/metrics`: hosts by state and each host's, then each region's room and refusals. A region a
/// host is in has every series, zeros included, so a rate is defined from the first scrape; a
/// region with refusals only has the counter alone.
pub fn render(reg: &Registry, regions: &[RegionRoom]) -> String {
    let mut out = String::new();
    let o = &mut out;
    let mut states: BTreeMap<&str, usize> = BTreeMap::from([("ready", 0)]);
    for h in reg.hosts.values() {
        *states.entry(h.state.as_str()).or_default() += 1;
    }
    let states = states
        .into_iter()
        .map(|(s, n)| (format!("state=\"{}\"", label_value(s)), n.to_string()))
        .collect();
    family(
        o,
        "briqyard_fleet_hosts",
        "gauge",
        "Hosts in the registry, by state.",
        states,
    );
    // One series per host, its state now (kube-state-metrics' node shape): a scrape target's
    // labels stay what does not change, so a drain never starts a host's series over.
    let mut each: Vec<_> = reg.hosts.values().collect();
    each.sort_by(|a, b| a.id.cmp(&b.id));
    let each = each
        .into_iter()
        .map(|h| {
            let labels = format!(
                "host=\"{}\",region=\"{}\",state=\"{}\"",
                label_value(&h.id),
                label_value(&h.region),
                label_value(&h.state)
            );
            (labels, "1".to_string())
        })
        .collect();
    family(
        o,
        "briqyard_fleet_host_state",
        "gauge",
        "1 for the state each host is in: one series per host.",
        each,
    );
    let per_resource = |pick: fn(&RegionRoom) -> Option<Room>| {
        regions
            .iter()
            .filter_map(|r| pick(r).map(|room| (label_value(&r.region), room)))
            .flat_map(|(region, room)| {
                [("memory", room.memory_mb), ("disk", room.disk_mb)].map(|(resource, v)| {
                    (
                        format!("resource=\"{resource}\",region=\"{region}\""),
                        v.to_string(),
                    )
                })
            })
            .collect()
    };
    family(
        o,
        "briqyard_fleet_free_mb",
        "gauge",
        "Free memory and disk, in MB, summed over the region's hosts that take a new namespace.",
        per_resource(|r| r.free),
    );
    family(
        o,
        "briqyard_fleet_largest_slot_mb",
        "gauge",
        "The most free memory and disk, in MB, on one of the region's hosts that take a new namespace.",
        per_resource(|r| r.largest_slot),
    );
    let refused = regions
        .iter()
        .flat_map(|r| {
            let u = r.unschedulable;
            Resource::ALL.map(|resource| {
                let n = match resource {
                    Resource::Memory => u.memory,
                    Resource::Cpu => u.cpu,
                    Resource::Disk => u.disk,
                    Resource::Pressure => u.pressure,
                };
                (
                    format!(
                        "resource=\"{}\",region=\"{}\"",
                        resource.as_str(),
                        label_value(&r.region)
                    ),
                    n.to_string(),
                )
            })
        })
        .collect();
    family(
        o,
        "briqyard_fleet_unschedulable_total",
        "counter",
        "Creates refused 503 capacity since the fleet started, by what ran out.",
        refused,
    );
    out
}
