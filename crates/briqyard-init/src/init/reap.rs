use super::*;

/// Children we spawned and wait for ourselves. The orphan reaper leaves these alone, and
/// every change wakes it.
pub(super) static TRACKED: Mutex<Tracked> = Mutex::new(Tracked {
    pids: BTreeSet::new(),
    changes: 0,
});
pub(super) static TRACKED_CHANGED: Condvar = Condvar::new();

pub(super) struct Tracked {
    pids: BTreeSet<i32>,
    /// Counts every insert and remove: a waiter tells a change it did not see by it.
    changes: u64,
}

impl Tracked {
    pub(super) fn insert(&mut self, pid: i32) {
        self.pids.insert(pid);
        self.changed();
    }

    pub(super) fn remove(&mut self, pid: i32) {
        self.pids.remove(&pid);
        self.changed();
    }

    pub(super) fn contains(&self, pid: i32) -> bool {
        self.pids.contains(&pid)
    }

    pub(super) fn changed(&mut self) {
        self.changes += 1;
        TRACKED_CHANGED.notify_all();
    }
}

/// PID 1 inherits every orphan and must reap them, but a plain wait on any child would steal
/// the statuses of the children we wait for ourselves. Peek without reaping, and reap only
/// what nobody tracks. The spawn path holds the same lock while registering a new child.
///
/// `waitid` blocks until a child has exited, so the reaper sleeps only when it cannot: with
/// no child at all (`ECHILD`: the next one is our own spawn), or with a tracked child's
/// status waiting for its owner (the kernel reports the same child until it is collected).
/// Both end with a change to `TRACKED`, which wakes it.
pub(super) fn reap_orphans() {
    loop {
        let seen = TRACKED.lock().unwrap().changes;
        match reap_one() {
            Ok(Reaped::Orphan(_)) | Err(nix::errno::Errno::EINTR) => {}
            Ok(Reaped::Ours(pid)) => wait_tracked(|t| !t.contains(pid.as_raw())),
            Ok(Reaped::Nothing) | Err(_) => wait_tracked(|t| t.changes != seen),
        }
    }
}

/// Blocks until `done` holds for the tracked children.
pub(super) fn wait_tracked(done: impl Fn(&Tracked) -> bool) {
    let mut t = TRACKED.lock().unwrap();
    while !done(&t) {
        t = TRACKED_CHANGED.wait(t).unwrap();
    }
}

/// What one look at the exited children found.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Reaped {
    /// Nobody tracked it: reaped.
    Orphan(Pid),
    /// A child we wait for ourselves: its status is left where it is.
    Ours(Pid),
    Nothing,
}

/// Waits (without reaping) for any exited child, then reaps it unless it is tracked.
pub(super) fn reap_one() -> nix::Result<Reaped> {
    let status = waitid(Id::All, WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT)?;
    let pid = match status.pid() {
        Some(p) => p,
        None => return Ok(Reaped::Nothing),
    };
    let tracked = TRACKED.lock().unwrap();
    let is_ours = tracked.contains(pid.as_raw());
    if !is_ours {
        let _ = waitpid(pid, None);
    }
    drop(tracked);
    Ok(if is_ours {
        Reaped::Ours(pid)
    } else {
        Reaped::Orphan(pid)
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::init::testutil::*;
    use nix::sys::wait::WaitStatus;
    use std::time::Instant;

    // --- the reaper ---

    #[test]
    fn the_reaper_waits_until_a_tracked_child_is_collected() {
        // No such process: the tracked set alone is what is waited on.
        let pid = -4242;
        TRACKED.lock().unwrap().insert(pid);
        let (tx, rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            wait_tracked(|t| !t.contains(pid));
            tx.send(()).unwrap();
        });
        assert!(
            rx.recv_timeout(Duration::from_millis(100)).is_err(),
            "woke before the child was collected"
        );
        untrack(pid);
        rx.recv_timeout(Duration::from_secs(5))
            .expect("woke on the removal");
        waiter.join().unwrap();
    }

    // The orphan is left unwaited on purpose: reaping it is what the test checks.
    #[allow(clippy::zombie_processes)]
    #[test]
    fn reaper_leaves_tracked_children_and_reaps_orphans() {
        // Ours: still running, held by its stdin. The orphan: exits at once, nobody waits.
        let mut ours = spawn_tracked(
            std::process::Command::new("cat")
                .stdin(Stdio::piped())
                .stdout(Stdio::null()),
        );
        let our_pid = Pid::from_raw(ours.id() as i32);
        let orphan = {
            let tracked = TRACKED.lock().unwrap();
            let child = std::process::Command::new("true").spawn().unwrap();
            drop(tracked);
            Pid::from_raw(child.id() as i32)
            // `child` is dropped without a wait: a zombie until someone reaps it.
        };
        wait_until("the orphan exits", || {
            proc_state(orphan.as_raw()) == Some('Z')
        });

        // Another test's tracked child may be reported first; only an orphan gets reaped,
        // and the only orphan is ours.
        let start = Instant::now();
        loop {
            match reap_one() {
                Ok(Reaped::Orphan(p)) => {
                    assert_eq!(p, orphan);
                    break;
                }
                Ok(Reaped::Ours(p)) => assert_ne!(p, orphan),
                Ok(Reaped::Nothing) => {}
                Err(e) => panic!("{e}"),
            }
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "the orphan was not reaped"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            waitpid(orphan, Some(WaitPidFlag::WNOHANG)),
            Err(nix::errno::Errno::ECHILD),
            "reaped: nothing left to wait for"
        );

        // Now ours exits: the reaper sees it, names it, and leaves the status for us.
        drop(ours.stdin.take());
        wait_until("our child exits", || {
            proc_state(our_pid.as_raw()) == Some('Z')
        });
        let start = Instant::now();
        loop {
            match reap_one() {
                Ok(Reaped::Ours(p)) if p == our_pid => break,
                Ok(Reaped::Orphan(p)) => panic!("reaped {p}, which nobody here spawned"),
                Ok(_) => {}
                Err(e) => panic!("{e}"),
            }
            assert!(start.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(10));
        }
        // The status is still ours to collect.
        assert_eq!(waitpid(our_pid, None), Ok(WaitStatus::Exited(our_pid, 0)));
        untrack(our_pid.as_raw());
    }
}
