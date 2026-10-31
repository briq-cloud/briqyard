//! Exact child ownership. An observer is never the command's lifetime owner.
use super::*;
use std::future::Future;
use std::process::{ExitStatus, Stdio};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, ChildStderr};
use tokio::sync::{oneshot, watch, Notify};

tokio::task_local! {
    static ADMITTED: Arc<Owners>;
}
/// A real owner registration, acquired before launching a backup or restore task.
/// Closing admission does not revoke already admitted work; drain includes the scope.
pub struct IoScope {
    registration: Registration,
}
impl IoScope {
    pub async fn run<T>(self, work: impl Future<Output = T>) -> T {
        let owners = self.registration.owners.clone();
        let result = ADMITTED.scope(owners, work).await;
        self.registration.settle();
        result
    }
}
const STDERR_BYTES: usize = 64 << 10;
#[derive(Default)]
pub(super) struct Owners {
    state: Mutex<OwnerState>,
    changed: Notify,
    #[cfg(test)]
    lose_wait_observation: std::sync::atomic::AtomicBool,
}
#[derive(Default)]
struct OwnerState {
    closed: bool,
    next: u64,
    active: HashMap<u64, OwnerEntry>,
}
struct OwnerEntry {
    fenced: bool,
    _marker: Option<Call>,
}
struct Registration {
    owners: Arc<Owners>,
    id: u64,
    settled: bool,
}
impl Registration {
    fn fence(&self) {
        self.owners
            .state
            .lock()
            .unwrap()
            .active
            .get_mut(&self.id)
            .unwrap()
            .fenced = true;
    }
    fn mark(&self, marker: Call) {
        self.owners
            .state
            .lock()
            .unwrap()
            .active
            .get_mut(&self.id)
            .unwrap()
            ._marker = Some(marker);
    }
    fn settle(mut self) {
        self.settled = true;
        self.owners.state.lock().unwrap().active.remove(&self.id);
        self.owners.changed.notify_waiters();
    }
}
impl Drop for Registration {
    fn drop(&mut self) {
        if !self.settled {
            // Panic/runtime teardown is not a positive child-exit observation.
            if let Some(entry) = self.owners.state.lock().unwrap().active.get_mut(&self.id) {
                entry.fenced = true;
            }
        }
    }
}
impl Owners {
    fn register(self: &Arc<Self>, io: bool) -> Result<Registration> {
        let mut state = self.state.lock().unwrap();
        let admitted = ADMITTED
            .try_with(|owner| Arc::ptr_eq(owner, self))
            .unwrap_or(false);
        if io && state.closed && !admitted {
            return Err(anyhow!("ZFS transfer admission is closed"));
        }
        let id = state.next.checked_add(1).context("ZFS owner sequence")?;
        state.next = id;
        state.active.insert(
            id,
            OwnerEntry {
                fenced: false,
                _marker: None,
            },
        );
        Ok(Registration {
            owners: self.clone(),
            id,
            settled: false,
        })
    }
    pub fn close(&self) {
        self.state.lock().unwrap().closed = true;
    }
    pub async fn drain(&self) {
        loop {
            let changed = self.changed.notified();
            if self.state.lock().unwrap().active.is_empty() {
                return;
            }
            changed.await;
        }
    }
    #[cfg(test)]
    pub fn lose_wait_observation(&self) {
        self.lose_wait_observation
            .store(true, std::sync::atomic::Ordering::Release);
    }
    #[cfg(test)]
    pub fn fenced(&self) -> bool {
        self.state
            .lock()
            .unwrap()
            .active
            .values()
            .any(|entry| entry.fenced)
    }
    #[cfg(test)]
    pub fn pending(&self) -> usize {
        self.state.lock().unwrap().active.len()
    }
}
struct Observer<T> {
    result: oneshot::Receiver<Result<T>>,
    cancel: Option<watch::Sender<bool>>,
}
impl<T> Drop for Observer<T> {
    fn drop(&mut self) {
        if let Some(cancel) = &self.cancel {
            cancel.send_replace(true);
        }
    }
}
impl<T> Observer<T> {
    async fn result(mut self) -> Result<T> {
        let result = match (&mut self.result).await {
            Ok(result) => result,
            // Loss of the supervisor is not a settled failure authorizing cleanup.
            // Its registration remains fenced unless it positively settled first.
            Err(_) => std::future::pending::<Result<T>>().await,
        };
        self.cancel = None;
        result
    }
}
/// Continue draining after the retained diagnostic prefix is full, so stderr cannot
/// block the owned child. Neither an unbounded read nor a dropped drain task is safe.
async fn drain_stderr(mut stderr: ChildStderr) -> std::io::Result<Vec<u8>> {
    let mut prefix = Vec::new();
    let mut buffer = [0; 8192];
    loop {
        let n = stderr.read(&mut buffer).await?;
        if n == 0 {
            return Ok(prefix);
        }
        let keep = n.min(STDERR_BYTES.saturating_sub(prefix.len()));
        prefix.extend_from_slice(&buffer[..keep]);
    }
}
async fn completed(
    what: &str,
    status: ExitStatus,
    stderr: tokio::task::JoinHandle<std::io::Result<Vec<u8>>>,
) -> Result<()> {
    let stderr = stderr
        .await
        .context("ZFS stderr owner")?
        .context("read ZFS stderr")?;
    if status.success() {
        return Ok(());
    }
    let message = String::from_utf8_lossy(&stderr);
    let message = message.trim();
    Err(anyhow!(
        "{what}: {}",
        if message.is_empty() {
            status.to_string()
        } else {
            message.to_string()
        }
    ))
}
impl Zfs {
    pub fn io_scope(&self) -> Result<IoScope> {
        Ok(IoScope {
            registration: self.owners.register(true)?,
        })
    }
    pub fn close_io_admission(&self) {
        self.owners.close();
    }
    pub async fn drain_io(&self) {
        self.owners.drain().await;
    }

    /// Registration precedes spawn. This retained worker owns transfer, child, pipes,
    /// diagnostic drain and running marker until positive wait, independently of its waiter.
    pub(super) async fn owned<T, F, Fut>(
        &self,
        mut command: Command,
        what: String,
        io: bool,
        prepare: F,
    ) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Child) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T>> + Send + 'static,
    {
        let registration = self.owners.register(io)?;
        registration.mark(self.begin(&what));
        let (respond, result) = oneshot::channel();
        let (cancel, mut cancelled) = watch::channel(false);
        tokio::spawn(async move {
            command.stderr(Stdio::piped()).kill_on_drop(true);
            let mut child = match command.spawn() {
                Ok(child) => child,
                Err(error) => {
                    registration.settle();
                    let _ = respond.send(Err(error).with_context(|| format!("run {what}")));
                    return;
                }
            };
            let stderr = tokio::spawn(drain_stderr(child.stderr.take().expect("piped stderr")));
            let prepared =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prepare(&mut child)));
            let value = match prepared {
                Ok(transfer) => {
                    use futures::FutureExt;
                    let transfer = std::panic::AssertUnwindSafe(transfer).catch_unwind();
                    tokio::pin!(transfer);
                    tokio::select! { biased;
                        _ = async { let _ = cancelled.wait_for(|cancel| *cancel).await; }, if io => Err(anyhow!("ZFS transfer observer cancelled")),
                        value = &mut transfer => value.unwrap_or_else(|_| Err(anyhow!("ZFS transfer panicked"))),
                    }
                }
                Err(_) => Err(anyhow!("ZFS transfer setup panicked")),
            }; // Transfer future and pipe owners drop before termination/wait.
            if value.is_err() {
                let _ = child.start_kill();
            }
            let status = tokio::select! { biased;
                _ = async { let _ = cancelled.wait_for(|cancel| *cancel).await; }, if io => {
                    let _ = child.start_kill();
                    child.wait().await
                },
                status = child.wait() => status,
            };
            // Fault tests lose the observation only after reaping their real child, so
            // exercising the conservative uncertainty path leaves no test subprocess.
            #[cfg(test)]
            let status = if status.is_ok()
                && registration
                    .owners
                    .lose_wait_observation
                    .load(std::sync::atomic::Ordering::Acquire)
            {
                Err(std::io::Error::other("injected lost wait observation"))
            } else {
                status
            };
            let status = match status {
                Ok(status) => status,
                Err(_) => {
                    // No cleanup/result/admission release after an uncertain wait. Keep
                    // exact handles and marker; drain remains incomplete.
                    registration.fence();
                    let retained = (child, stderr, registration, respond);
                    std::future::pending::<()>().await;
                    drop(retained);
                    return;
                }
            };
            let exit = completed(&what, status, stderr).await;
            let answer = value.and_then(|value| exit.map(|()| value));
            registration.settle();
            let _ = respond.send(answer);
        });
        Observer {
            result,
            cancel: io.then_some(cancel),
        }
        .result()
        .await
    }

    pub async fn send_with<T, F, Fut>(
        &self,
        name: &str,
        snap: &str,
        from: Option<&str>,
        send: F,
    ) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(tokio::process::ChildStdout) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T>> + Send + 'static,
    {
        let mut command = self.send_command(name, snap, from);
        command.stdin(Stdio::null()).stdout(Stdio::piped());
        self.owned(
            command,
            format!("zfs send {}@{snap}", self.ds(name)),
            true,
            move |child| send(child.stdout.take().expect("piped stdout")),
        )
        .await
    }
    pub async fn receive_with<T, F, Fut>(&self, name: &str, receive: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(tokio::process::ChildStdin) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T>> + Send + 'static,
    {
        let mut command = self.tools.zfs.command();
        command
            .args(["receive", "-F", "-u", &self.ds(name)])
            .stdin(Stdio::piped())
            .stdout(Stdio::null());
        self.owned(
            command,
            format!("zfs receive {}", self.ds(name)),
            true,
            move |child| receive(child.stdin.take().expect("piped stdin")),
        )
        .await
    }
}

/// Command output retains the legacy representation; the diagnostic drain is separately
/// bounded. Protocol callers validate their own small typed results before accepting them.
pub(super) async fn read_answer(mut reader: impl AsyncRead + Unpin) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).await?;
    Ok(bytes)
}

#[cfg(test)]
mod observer_tests {
    use super::*;

    #[tokio::test]
    async fn lost_supervisor_result_is_not_a_cleanup_error_receipt() {
        let (respond, result) = oneshot::channel::<Result<()>>();
        let (cancel, _cancelled) = watch::channel(false);
        drop(respond);
        let observer = Observer {
            result,
            cancel: Some(cancel),
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(20), observer.result())
                .await
                .is_err()
        );
    }
}
