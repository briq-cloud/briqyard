use super::*;
use briqyard_api::reason;

pub(super) fn open() -> (tempfile::TempDir, Events) {
    let dir = tempfile::tempdir().unwrap();
    let ev = Events::open(dir.path()).unwrap();
    (dir, ev)
}

pub(super) fn t(s: &str) -> DateTime<Utc> {
    s.parse().unwrap()
}

pub(super) fn all(ev: &Events, since: u64) -> Vec<u64> {
    let p = ev.read(since, &Filter::default(), 5000).unwrap();
    p.events.iter().map(|e| e.seq).collect()
}

/// An event as a past hour would have logged it, written into that hour's file.
pub(super) fn logged_at(ev: &Events, at: &str, n: usize) {
    let mut log = ev.inner.log.lock().unwrap();
    for _ in 0..n {
        log.seq += 1;
        let e = api::Event {
            seq: log.seq,
            at: t(at),
            kind: event::NORMAL.into(),
            reason: reason::CREATED.into(),
            message: String::new(),
            machine_id: String::new(),
            namespace: String::new(),
            host: String::new(),
            data: None,
            count: 1,
            first_at: None,
        };
        log.append(&e).unwrap();
    }
}
