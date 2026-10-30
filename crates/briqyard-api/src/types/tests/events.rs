use super::*;

#[test]
fn event() {
    // `type` on the wire (a keyword in Rust); a host event has no machine, namespace or data.
    let e: Event = same(json!({
        "seq": 1, "at": "2026-10-20T14:00:00Z", "type": "normal", "reason": "host_started",
        "message": "daemon started"
    }));
    assert_eq!(
        (e.kind.as_str(), e.machine_id.as_str()),
        (event::NORMAL, "")
    );
    let e: Event = same(json!({
        "seq": 812, "at": "2026-10-20T14:03:11.204Z", "type": "warning", "reason": "exited",
        "message": "exited with code 7", "machine_id": "m_1", "namespace": "t1", "host": "h1",
        "data": {"code": 7, "oom": false, "restarting": true}
    }));
    assert_eq!(e.reason, reason::EXITED);
    assert_eq!(e.data.as_ref().map(|d| d["code"].clone()), Some(json!(7)));
    // The seq is required: an event is nothing without its place in the log.
    assert!(serde_json::from_value::<Event>(json!({
        "at": "2026-10-20T14:00:00Z", "type": "normal", "reason": "created", "message": ""
    }))
    .is_err());
    let p: EventsPage = same(json!({"events": [], "next": "h1:12,h2:40"}));
    assert_eq!(p.next, "h1:12,h2:40");
}

#[test]
fn reasons_and_page_limits() {
    // A closed list, each once, each a snake_case word.
    let mut all = reason::ALL.to_vec();
    all.sort();
    all.dedup();
    assert_eq!(all.len(), reason::ALL.len());
    assert_eq!(all.len(), 40);
    assert!(all
        .iter()
        .all(|r| r.bytes().all(|c| c.is_ascii_lowercase() || c == b'_')));
    assert_eq!((event::NORMAL, event::WARNING), ("normal", "warning"));
    assert_eq!(events_limit(None), 500);
    assert_eq!(events_limit(Some(0)), 500);
    assert_eq!(events_limit(Some(20)), 20);
    assert_eq!(events_limit(Some(usize::MAX)), 5000);
}

#[test]
fn state_and_stop_constants() {
    // What the description enumerates, byte for byte.
    assert_eq!(
        [
            state::CREATED,
            state::STARTING,
            state::RUNNING,
            state::STOPPING,
            state::STOPPED,
            state::DESTROYING,
            state::ERROR
        ],
        [
            "created",
            "starting",
            "running",
            "stopping",
            "stopped",
            "destroying",
            "error"
        ]
    );
    assert_eq!(
        [stop::USER, stop::IDLE, stop::EXIT, stop::HOST],
        ["user", "idle", "exit", "host"]
    );
}
