use super::*;

/// How long after its line the repeats of an event are folded rather than logged.
pub(super) const FOLD_MINUTES: i64 = 10;
/// The reasons whose repeats fold: uses and refusals, which change nothing, and the readiness
/// flips, which a probe can make every second.
pub(super) const FOLDED: [&str; 4] = [
    reason::SESSION_OPENED,
    reason::QUOTA_EXCEEDED,
    reason::READY,
    reason::NOT_READY,
];
/// Of those, the ones that change the machine: a folded flip still takes a seq, its version,
/// with no line.
pub(super) const FLIPS: [&str; 2] = [reason::READY, reason::NOT_READY];

pub(super) type Key = (String, String, &'static str);

/// An event's line and the repeats folded since, not logged yet.
pub(super) struct Series {
    /// When the line was logged: repeats fold until `FOLD_MINUTES` after it.
    pub(super) opened: DateTime<Utc>,
    pub(super) folded: Option<Folded>,
}

/// Repeats folded: the last one, when it was, how many, and when the first was.
pub(super) struct Folded {
    pub(super) last: Ev,
    pub(super) at: DateTime<Utc>,
    pub(super) count: u64,
    pub(super) first_at: DateTime<Utc>,
}

impl Series {
    pub(super) fn due(&self, now: DateTime<Utc>) -> bool {
        now >= self.opened + Duration::minutes(FOLD_MINUTES)
    }

    pub(super) fn fold(&mut self, ev: Ev, now: DateTime<Utc>) {
        let (count, first_at) = match &self.folded {
            Some(f) => (f.count + 1, f.first_at),
            None => (1, now),
        };
        self.folded = Some(Folded {
            last: ev,
            at: now,
            count,
            first_at,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::testutil::*;
    use briqyard_api::reason;

    /// What the log holds about a machine: (seq, reason, count).
    fn lines_of(ev: &Events) -> Vec<(u64, String, u64)> {
        let p = ev.read(0, &Filter::default(), 5000).unwrap();
        p.events
            .into_iter()
            .map(|e| (e.seq, e.reason, e.count))
            .collect()
    }

    fn session(n: u32) -> Ev {
        Ev::normal(reason::SESSION_OPENED, format!("sh #{n}")).of("m_a", "t1")
    }

    #[test]
    fn repeats_of_a_use_fold_into_one_line_after_their_window() {
        let (_dir, ev) = open();
        let t0 = t("2026-10-28T10:00:00Z");
        let s = |m: i64| t0 + Duration::seconds(m);
        // The first is logged at once; the next ones within 10 minutes are folded, no seq.
        assert_eq!(ev.emit_at(session(0), s(0)), Some(1));
        for i in 1..=4 {
            assert_eq!(ev.emit_at(session(i), s(i as i64 * 60)), None);
        }
        // Another machine's, and the host's, are their own.
        let other = Ev::normal(reason::SESSION_OPENED, "").of("m_b", "t1");
        assert_eq!(ev.emit_at(other, s(300)), Some(2));
        assert_eq!(lines_of(&ev).len(), 2);
        // Nothing due before the window ends; at its end, one line for the four.
        assert!(ev.flush_due(s(599)).is_empty());
        assert_eq!(lines_of(&ev).len(), 2);
        assert!(
            ev.flush_due(s(600)).is_empty(),
            "no flips to log under a record"
        );
        let p = ev.read(2, &Filter::default(), 10).unwrap();
        let e = &p.events[0];
        assert_eq!((e.seq, e.count, e.message.as_str()), (3, 4, "sh #4"));
        assert_eq!((e.first_at, e.at), (Some(s(60)), s(240)));
        // The series ended: the next one is logged at once and opens another.
        assert_eq!(ev.emit_at(session(5), s(700)), Some(4));
        assert_eq!(ev.emit_at(session(6), s(701)), None);
        // `/metrics` counts every one, folded or not.
        assert_eq!(ev.emitted()[&("normal", "session_opened")], 8);
        // One alone keeps its shape: no count, no first time.
        let line = serde_json::to_value(&ev.read(0, &Filter::default(), 1).unwrap().events[0]);
        let line = line.unwrap();
        assert!(
            line.get("count").is_none() && line.get("first_at").is_none(),
            "{line}"
        );
    }

    #[test]
    fn a_change_logs_what_was_folded_first() {
        let (_dir, ev) = open();
        let t0 = t("2026-10-28T10:00:00Z");
        for i in 0..3 {
            ev.emit_at(session(i), t0 + Duration::seconds(i as i64));
        }
        let stopped = Ev::normal(reason::STOPPED, "stopped (user)").of("m_a", "t1");
        assert_eq!(ev.emit_at(stopped, t0 + Duration::seconds(5)), Some(3));
        assert_eq!(
            lines_of(&ev),
            [
                (1, "session_opened".into(), 1),
                (2, "session_opened".into(), 2),
                (3, "stopped".into(), 1)
            ]
        );
        // The series goes on to its window's end: a session after the stop still folds.
        assert_eq!(ev.emit_at(session(9), t0 + Duration::seconds(6)), None);
    }

    #[test]
    fn folded_flips_take_a_seq_and_the_last_line_says_what_the_machine_is() {
        let (_dir, ev) = open();
        let t0 = t("2026-10-28T10:00:00Z");
        let flip = |ready: bool, sec: i64| {
            let e = match ready {
                true => Ev::normal(reason::READY, format!("ready {sec}")),
                false => Ev::warning(reason::NOT_READY, format!("not ready {sec}")),
            };
            ev.emit_at(e.of("m_a", "t1"), t0 + Duration::seconds(sec))
        };
        assert_eq!(flip(true, 0), Some(1));
        assert_eq!(flip(false, 1), Some(2));
        // Folded: a seq (the machine's version moves), no line.
        assert_eq!(flip(true, 2), Some(3));
        assert_eq!(flip(false, 3), Some(4));
        assert_eq!(flip(true, 4), Some(5));
        assert_eq!(lines_of(&ev).len(), 2);
        // A cursor on a seq no line has reads on from it.
        assert_eq!(all(&ev, 4), Vec::<u64>::new());
        assert_eq!(ev.read(4, &Filter::default(), 10).unwrap().next, 5);
        // Due: the machine is named, its flips logged under its lock, the last seen last.
        let due = t0 + Duration::minutes(10);
        assert_eq!(ev.flush_due(due), ["m_a"]);
        assert_eq!(ev.flush_machine("m_a", due), Some(7));
        let p = ev.read(5, &Filter::default(), 10).unwrap();
        let got: Vec<_> = p
            .events
            .iter()
            .map(|e| (e.seq, e.reason.as_str(), e.count, e.message.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                (6, "not_ready", 1, "not ready 3"),
                (7, "ready", 2, "ready 4")
            ]
        );
        assert!(ev.flush_due(due).is_empty());
        // A change of the machine logs its folded flips before itself, whatever their window.
        assert_eq!(flip(false, 700), Some(8));
        assert_eq!(flip(true, 701), Some(9));
        assert_eq!(flip(false, 702), Some(10));
        let stopping = Ev::normal(reason::STOPPING, "").of("m_a", "t1");
        assert_eq!(ev.emit_at(stopping, t0 + Duration::seconds(703)), Some(12));
        let reasons: Vec<String> = lines_of(&ev).into_iter().skip(4).map(|l| l.1).collect();
        assert_eq!(reasons, ["not_ready", "ready", "not_ready", "stopping"]);
    }

    #[test]
    fn a_tenant_refusal_folds_and_the_daemon_going_down_logs_what_was_folded() {
        let (_dir, ev) = open();
        let t0 = t("2026-10-28T10:00:00Z");
        for i in 0..3 {
            let refused = Ev::warning(reason::QUOTA_EXCEEDED, format!("refused {i}")).tenant("t1");
            ev.emit_at(refused, t0 + Duration::seconds(i));
        }
        // The host's own events never fold.
        ev.emit_at(Ev::normal(reason::HOST_STARTED, ""), t0);
        ev.emit_at(Ev::normal(reason::HOST_STARTED, ""), t0);
        assert_eq!(lines_of(&ev).len(), 3);
        ev.close();
        let last = lines_of(&ev).pop().unwrap();
        assert_eq!(last, (4, "quota_exceeded".into(), 2));
    }

    #[test]
    fn retention_counts_lines_not_seqs() {
        let (dir, ev) = open();
        logged_at(&ev, "2026-10-20T10:00:00Z", 3);
        // Seqs a flip took with no line.
        ev.inner.log.lock().unwrap().seq += 1000;
        logged_at(&ev, "2026-10-20T11:00:00Z", 3);
        let now = t("2026-10-20T12:00:00Z");
        assert_eq!(ev.prune(now, 7, 6).unwrap(), 0);
        // A cursor in the gap is whole: the lines it lacks are all kept.
        assert_eq!(all(&ev, 500), [1004, 1005, 1006]);
        assert_eq!(ev.prune(now, 7, 5).unwrap(), 1);
        // Pruned up to seq 3: a cursor at or past it misses nothing, even in the gap; one
        // before it does.
        assert_eq!(all(&ev, 3), [1004, 1005, 1006]);
        assert_eq!(all(&ev, 500), [1004, 1005, 1006]);
        let err = ev.read(2, &Filter::default(), 10).unwrap_err();
        assert_eq!(err.downcast_ref::<Gone>().map(|g| g.oldest), Some(1004));
        // Counted again at a start.
        drop(ev);
        let ev = Events::open(dir.path()).unwrap();
        let files: Vec<File> = ev
            .inner
            .log
            .lock()
            .unwrap()
            .files
            .values()
            .copied()
            .collect();
        assert_eq!(
            files,
            [File {
                first: 1004,
                last: 1006,
                lines: 3
            }]
        );
    }

    #[test]
    fn a_due_flip_logs_the_machine_s_flips_not_its_uses_still_in_their_window() {
        let (_dir, ev) = open();
        let t0 = t("2026-10-28T10:00:00Z");
        let at = |s: i64| t0 + Duration::seconds(s);
        let flip = |reason: &'static str, s: i64| {
            ev.emit_at(Ev::normal(reason, reason).of("m_a", "t1"), at(s));
        };
        flip(reason::READY, 0);
        flip(reason::READY, 1);
        // Sessions opened 5 minutes later: their window ends 5 minutes after the flip's.
        ev.emit_at(session(0), at(300));
        ev.emit_at(session(1), at(301));
        let due = at(600);
        assert_eq!(ev.flush_due(due), ["m_a"]);
        ev.flush_machine("m_a", due);
        let got: Vec<(String, u64)> = lines_of(&ev).into_iter().map(|l| (l.1, l.2)).collect();
        assert_eq!(
            got,
            [
                ("ready".into(), 1),
                ("session_opened".into(), 1),
                ("ready".into(), 1)
            ]
        );
        // The sessions' fold comes at the end of their own window.
        assert!(ev.flush_due(at(899)).is_empty());
        assert_eq!(lines_of(&ev).len(), 3);
        ev.flush_due(at(900));
        assert_eq!(
            lines_of(&ev).pop().unwrap(),
            (5, "session_opened".into(), 1)
        );
    }
}
