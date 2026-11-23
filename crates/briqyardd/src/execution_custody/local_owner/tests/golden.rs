//! The target's own producer against R's merged golden: the owner state the golden's values
//! describe, run through the collector, must answer with the golden's records.

use super::super::attempt::{Attempt, Record};
use super::super::*;
use super::fixtures::*;
use briqyard_api::execution::sealed::{
    canonical::{decode, encode},
    custody::Capture,
    owner::{ArmReceipt, Collected, FragmentState, Observation, ObserveRequest, Point, UnitState},
    prim::PosInt,
    transition::{Death, Launch},
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const GOLDEN: &str =
    include_str!("../../../../../briqyard-api/testdata/owner_v1/sealed_owner_v1.golden");

fn record<T: briqyard_api::execution::sealed::canonical::Wire>(name: &str) -> T {
    let line = GOLDEN
        .lines()
        .find(|line| line.split('\t').next() == Some(name))
        .unwrap();
    let body = line.splitn(3, '\t').nth(2).unwrap();
    decode(body.as_bytes()).unwrap()
}

struct Golden {
    observation: Observation,
    arm: ArmReceipt,
    launch: Launch,
    capture: Capture,
    retired: Launch,
    death: Death,
    host: Arc<Host>,
}

fn golden() -> Golden {
    let observation: Observation = record("observation");
    let mut procs: HashMap<u64, MeasuredProc> = HashMap::new();
    for p in [&observation.original, &observation.custodian] {
        procs.insert(p.pid.get(), measured(p));
    }
    let authority_original = proc_in(&observation, 4500, 0x01);
    let authority_custodian = proc_in(&observation, 4600, 0x02);
    for p in [&authority_original, &authority_custodian] {
        procs.insert(p.pid.get(), measured(p));
    }
    let unit = |u: &briqyard_api::execution::sealed::owner::UnitObservation| UnitMeasure {
        fragment: u.fragment.clone(),
        argv: u.argv.clone(),
        sandbox: u.sandbox.clone(),
        fdstore: u.fdstore.clone(),
        job: u.job,
        state: u.state,
        reloaded: true,
    };
    let host = Arc::new(Host(Mutex::new(HostState {
        boot: observation.boot.clone(),
        procs,
        fragments: [FragmentState::Legacy; 2],
        units: [unit(&observation.unit), unit(&observation.unit)],
        guards: [
            observation.images.guard.clone(),
            observation.images.guard.clone(),
        ],
        unit_procs: [None, None],
        final_io: [false; 2],
    })));
    Golden {
        arm: record("arm"),
        launch: record("launch.captured"),
        capture: record("capture"),
        retired: record("launch.retired"),
        death: record("death"),
        observation,
        host,
    }
}

fn proc_in(
    observation: &Observation,
    pid: u64,
    exe: u8,
) -> briqyard_api::execution::sealed::objects::Proc {
    briqyard_api::execution::sealed::objects::Proc {
        pid: PosInt::new(pid).unwrap(),
        start: PosInt::new(pid + 1000).unwrap(),
        exe: digest(exe),
        ..observation.original.clone()
    }
}

fn attempt(g: &Golden) -> Attempt {
    let o = &g.observation;
    let record = |original: &briqyard_api::execution::sealed::objects::Proc,
                  custodian: &briqyard_api::execution::sealed::objects::Proc,
                  lease| {
        serde_json::from_value::<Record>(serde_json::json!({
            "lease": lease, "original": original, "custodian": custodian,
            "guard_image": o.images.guard, "fragment": "legacy", "arm": null,
            "captured": null, "exit": null, "final_io": false, "retirement": null,
            "handoff": null, "seal": null, "guard": null, "consumed": null,
        }))
        .unwrap()
    };
    Attempt {
        version: o.version,
        x: o.request.x.clone(),
        registered: o.request.registered.clone(),
        plan: g.arm.plan.clone(),
        plan_bytes: String::new(),
        target: g.arm.target.clone(),
        boot: o.boot.clone(),
        generation: o.target.generation,
        lockout: o.target.lockout.clone(),
        enrolled: None,
        seal_receipt: None,
        daemon: record(&o.original, &o.custodian, o.leases.daemon.clone()),
        authority: record(&proc_in(o, 4500, 0x01), &proc_in(o, 4600, 0x02), None),
        events: Vec::new(),
    }
}

fn collect(
    attempt: &Attempt,
    g: &Golden,
    point: Point,
    resource: Resource,
) -> Result<Collected, OwnerError> {
    let mut request: ObserveRequest = g.observation.request.clone();
    request.point = point;
    request.resource = resource;
    attempt.collect(&request, &g.host)
}

#[test]
fn the_prearm_answer_is_the_goldens_collected_record_byte_for_byte() {
    let g = golden();
    let answer = collect(&attempt(&g), &g, Point::Prearm, Resource::Daemon).unwrap();
    let want = GOLDEN
        .lines()
        .find(|line| line.starts_with("collected\t"))
        .unwrap()
        .splitn(3, '\t')
        .nth(2)
        .unwrap();
    assert_eq!(String::from_utf8(encode(&answer).unwrap()).unwrap(), want);
}

#[test]
fn the_launch_answer_carries_the_goldens_receipt_and_captured_pair() {
    let g = golden();
    let mut a = attempt(&g);
    a.enrolled = Some(g.arm.version);
    a.daemon.fragment = FragmentState::Guarded;
    a.authority.fragment = FragmentState::Guarded;
    a.authority.lease = Some(digest(0x99));
    a.daemon.arm = Some(g.arm.clone());
    let mut other = g.arm.clone();
    other.resource = Resource::Authority;
    a.authority.arm = Some(other);
    a.daemon.captured = Some(briqyard_api::execution::sealed::owner::LaunchCapture {
        launch: g.launch.clone(),
        capture: g.capture.clone(),
    });
    let answer = collect(&a, &g, Point::Launch, Resource::Daemon).unwrap();
    let golden: Collected = record("collected.arm");
    assert_eq!(answer.arm, golden.arm);
    assert_eq!(answer.launch_capture, golden.launch_capture);
    assert!(answer.daemon_retirement.is_none());
    let mut expected = golden.observation.clone();
    expected.request.point = Point::Launch;
    expected.fragments.daemon = FragmentState::Guarded;
    expected.fragments.authority = FragmentState::Guarded;
    expected.leases.authority = Some(digest(0x99));
    assert_eq!(
        answer.observation, expected,
        "only the point and the installed fragments differ"
    );
    assert_eq!(answer.observation.unit.state, UnitState::Active);
}

#[test]
fn the_seal_and_launch_a_answers_carry_the_goldens_retired_launch_and_death() {
    let g = golden();
    let golden: Collected = record("collected.retire");
    let mut a = attempt(&g);
    a.enrolled = Some(g.arm.version);
    a.daemon.arm = Some(g.arm.clone());
    let mut other = g.arm.clone();
    other.resource = Resource::Authority;
    a.authority.arm = Some(other);
    a.daemon.retirement = golden.daemon_retirement.clone();
    a.daemon.exit = Some(PosInt::new(2).unwrap());
    let seal = collect(&a, &g, Point::Seal, Resource::Daemon);
    assert!(
        seal.is_err(),
        "the original is recorded exited but still measured as running"
    );
    g.host
        .0
        .lock()
        .unwrap()
        .procs
        .remove(&g.observation.original.pid.get());
    let seal = collect(&a, &g, Point::Seal, Resource::Daemon).unwrap();
    assert_eq!(seal.daemon_retirement, golden.daemon_retirement);
    assert!(seal.arm.is_none() && seal.launch_capture.is_none());
    assert_eq!(
        (
            &golden.daemon_retirement.as_ref().unwrap().launch,
            &golden.daemon_retirement.as_ref().unwrap().death
        ),
        (&g.retired, &g.death)
    );
}
