//! Whole backup callers are observers; admitted jobs own their turns through completion.
use super::*;
use tokio::sync::{oneshot, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

const MAX_ADMITTED: usize = 128;
pub(super) enum Work {
    Census,
    Requested(
        Arc<Entry>,
        DateTime<Utc>,
        Option<api::CopyConsistencyRequest>,
    ),
    Scheduled(Arc<Entry>, DateTime<Utc>),
    Expire(Arc<Holder>),
    Delete {
        owner: Owner,
        backup_id: String,
        chain: bool,
    },
}
enum Reply {
    Requested(Box<Result<api::Backup, MError>>),
    Deleted(Result<(), MError>),
    Background,
}
pub(super) struct Ticket {
    receiver: oneshot::Receiver<Reply>,
}
impl Ticket {
    pub async fn result(self) -> Result<api::Backup, MError> {
        match self.receiver.await {
            Ok(Reply::Requested(result)) => *result,
            _ => Err(MError::Other(anyhow!(
                "backup owner ended without a settled result"
            ))),
        }
    }
    pub async fn deleted(self) -> Result<(), MError> {
        match self.receiver.await {
            Ok(Reply::Deleted(result)) => result,
            _ => Err(MError::Other(anyhow!(
                "backup deletion owner ended without a settled result"
            ))),
        }
    }
    pub async fn finished(self) {
        let _ = self.receiver.await;
    }
}
struct Run {
    owner: Option<(String, String)>,
    resources: Mutex<Option<(OwnedMutexGuard<()>, OwnedSemaphorePermit)>>,
    active: Mutex<Option<OwnedSemaphorePermit>>,
    task: Mutex<Option<JoinHandle<()>>>,
}
struct State {
    closed: bool,
    next: u64,
    epoch: u64,
    running: HashMap<u64, Arc<Run>>,
}
pub(super) struct Jobs {
    state: Mutex<State>,
    admission: Arc<Semaphore>,
    changed: Notify,
}
impl Jobs {
    pub fn new(at_once: usize) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                closed: false,
                next: 1,
                epoch: 0,
                running: HashMap::new(),
            }),
            admission: Arc::new(Semaphore::new(
                at_once.saturating_mul(2).clamp(1, MAX_ADMITTED),
            )),
            changed: Notify::new(),
        })
    }
    /// Bounded retained-job owner observations include jobs whose request waiter left.
    pub fn has_owner(&self, machine: &str, namespace: &str) -> bool {
        self.state.try_lock().is_ok_and(|s| {
            s.running.values().any(|run| {
                run.owner
                    .as_ref()
                    .is_some_and(|(m, n)| m == machine && n == namespace)
            })
        })
    }
    pub fn epoch(&self) -> u64 {
        self.state.lock().unwrap().epoch
    }
    pub async fn reserve(&self) -> Result<OwnedSemaphorePermit, MError> {
        self.admission
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| closed())
    }
    pub fn try_reserve(&self) -> Option<OwnedSemaphorePermit> {
        self.admission.clone().try_acquire_owned().ok()
    }
    pub fn close(&self) {
        self.state.lock().unwrap().closed = true;
        self.admission.close();
    }
    pub fn is_closed(&self) -> bool {
        self.state.lock().unwrap().closed
    }
    pub fn pending(&self) -> usize {
        self.state.lock().unwrap().running.len()
    }
    pub async fn drain(&self) {
        loop {
            let changed = self.changed.notified();
            if self.pending() == 0 {
                return;
            }
            changed.await;
        }
    }
    pub fn start(
        self: &Arc<Self>,
        manager: Manager,
        work: Work,
        turn: OwnedMutexGuard<()>,
        admission: OwnedSemaphorePermit,
    ) -> Result<Ticket, MError> {
        let owner = match &work {
            Work::Requested(e, _, _) | Work::Scheduled(e, _) => {
                Some(Owner::Machine(e.clone()).who())
            }
            Work::Expire(h) => Some(Owner::Holder(h.clone()).who()),
            Work::Delete { owner, .. } => Some(owner.who()),
            Work::Census => None,
        };
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return Err(closed());
        }
        let io_scope = manager.inner.zfs.io_scope()?;
        let id = state.next;
        state.next = state.next.checked_add(1).ok_or_else(closed)?;
        let (ready, started) = oneshot::channel();
        let (respond, receiver) = oneshot::channel();
        let jobs = self.clone();
        let run = Arc::new(Run {
            owner,
            resources: Mutex::new(Some((turn, admission))),
            active: Mutex::new(None),
            task: Mutex::new(None),
        });
        let owned = run.clone();
        let task = tokio::spawn(async move {
            if started.await.is_err() {
                return;
            }
            let reply = io_scope
                .run(async {
                    // A census must never queue behind an unbounded stream transfer.
                    let gate = manager.inner.backups.gate.clone();
                    let active = if matches!(&work, Work::Census) {
                        gate.try_acquire_owned().ok()
                    } else {
                        gate.acquire_owned().await.ok()
                    };
                    match active {
                        Some(active) => {
                            *owned.active.lock().unwrap() = Some(active);
                            let reply = match work {
                                Work::Census => {
                                    manager.run_backup_census().await;
                                    Reply::Background
                                }
                                Work::Requested(entry, now, opt) => Reply::Requested(Box::new(
                                    manager.backup_entry_requested(&entry, now, opt).await,
                                )),
                                Work::Scheduled(entry, now) => {
                                    manager.scheduled_backup(&entry, now).await;
                                    Reply::Background
                                }
                                Work::Delete {
                                    owner,
                                    backup_id,
                                    chain,
                                } => Reply::Deleted(
                                    manager.delete_backup_owned(&owner, &backup_id, chain).await,
                                ),
                                Work::Expire(holder) => {
                                    manager.expire(&holder).await;
                                    Reply::Background
                                }
                            };
                            reply
                        }
                        None => Reply::Requested(Box::new(Err(closed()))),
                    }
                })
                .await;
            // Bookkeeping and every actual admission/turn end before a positive reply.
            // A dropped response receiver never cancels this retained whole-generation job.
            drop(owned.active.lock().unwrap().take());
            drop(owned.resources.lock().unwrap().take());
            {
                let mut state = jobs.state.lock().unwrap();
                state.running.remove(&id);
                state.epoch = state.epoch.wrapping_add(1);
            }
            drop(owned);
            jobs.changed.notify_waiters();
            let _ = respond.send(reply);
        });
        *run.task.lock().unwrap() = Some(task);
        state.running.insert(id, run);
        state.epoch = state.epoch.wrapping_add(1);
        let _ = ready.send(());
        Ok(Ticket { receiver })
    }
}
fn closed() -> MError {
    MError::Conflict("backup admission is closed".into())
}
