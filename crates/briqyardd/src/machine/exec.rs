//! Running commands in a machine: exec, sessions, files and logs.

use super::*;

impl Manager {
    // --- exec and files ---

    pub(super) async fn running_vsock(&self, id: &str, wake: bool) -> Result<PathBuf, MError> {
        let e = self.own_entry(id)?;
        self.ordinary_operation(&e.snapshot())?;
        let (st, reason, live) = {
            let r = e.rec.lock().unwrap();
            (
                r.state.clone(),
                r.stopped_reason.clone(),
                e.live.lock().unwrap().clone(),
            )
        };
        if st == state::RUNNING {
            if let Some(l) = live {
                return Ok(l.vsock);
            }
        }
        if !wake {
            let s = if reason.is_empty() {
                st
            } else {
                format!("{st} ({reason})")
            };
            return Err(MError::NotRunning(s));
        }
        // A command that woke the machine runs once it is ready, as traffic does (ADR 0022):
        // a database woken by `psql` must be accepting by then. A machine already running
        // and not ready still takes commands at once, as a pod does.
        self.wake_detached(id).await?;
        let boot = Duration::from_secs(self.inner.cfg.boot_timeout_sec.max(10));
        self.wait(id, Until::Ready, boot).await?;
        let live = e.live.lock().unwrap().clone();
        live.map(|l| l.vsock)
            .ok_or_else(|| MError::NotRunning("no process".into()))
    }

    /// A wake on behalf of something else (an exec, an ingress connection), which may give
    /// up before the boot is done: the boot goes on without it.
    async fn wake_detached(&self, id: &str) -> Result<api::Machine, MError> {
        let m = self.clone();
        let id = id.to_string();
        detached(async move { m.wake(&id, None).await }).await
    }

    /// Runs a command to its end (the JSON exec): a session whose stdin is the request's,
    /// read to its exit (ADR 0029). The machine is in use while it runs.
    pub async fn exec(&self, id: &str, req: api::ExecRequest) -> Result<api::ExecResult, MError> {
        let timeout_ms = if req.timeout_ms == 0 {
            300_000
        } else {
            req.timeout_ms
        };
        let greq = guest::Request {
            op: "exec".into(),
            cmd: req.cmd,
            env: req.env,
            cwd: req.cwd,
            stdin: req.stdin.into_bytes(),
            timeout_ms,
            ..Default::default()
        };
        let (mut conn, _in_use) = self.start_command(id, req.wake, greq).await?;
        let out = tokio::time::timeout(
            Duration::from_millis(timeout_ms + 10_000),
            guestc::collect(&mut conn),
        )
        .await
        .map_err(|_| MError::NotRunning("the command did not finish".into()))?
        .map_err(|err| {
            if err.downcast_ref::<guestc::Closed>().is_some() {
                MError::NotRunning("the machine went down during the command".into())
            } else {
                self.init_named(id, err)
            }
        })?;
        Ok(api::ExecResult {
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            exit_code: out.code,
            timed_out: out.timed_out,
        })
    }

    /// A guest call's error with the machine's init named when it did not know the op (ADR
    /// 0027): what an exec, a put, a get, and any op added later go through. A guest that
    /// cannot be reached is exiting: not running, 409.
    fn init_named(&self, id: &str, err: anyhow::Error) -> MError {
        match not_running_if_unreachable(err) {
            MError::Other(err) => {
                let init = self
                    .entry(id)
                    .map(|e| e.snapshot().init_version)
                    .unwrap_or_default();
                MError::Other(guestc::with_init(err, &init))
            }
            not_running => not_running,
        }
    }

    /// Starts an exec session (ADR 0029): the command runs once the guest takes it, and the
    /// machine is in use until the session is dropped. Wakes the machine as an exec does.
    pub async fn open_session(
        &self,
        id: &str,
        req: api::session::ExecSession,
    ) -> Result<Session, MError> {
        if req.cmd.is_empty() {
            return Err(invalid("cmd is required"));
        }
        let program = req.cmd[0].clone();
        let greq = guest::Request {
            op: "exec".into(),
            cmd: req.cmd,
            env: req.env,
            cwd: req.cwd,
            timeout_ms: req.timeout_ms,
            interactive: true,
            tty: req.tty,
            cols: req.cols,
            rows: req.rows,
            ..Default::default()
        };
        let (conn, in_use) = self.start_command(id, req.wake, greq).await?;
        let (machine, namespace) = {
            let r = in_use.0.rec.lock().unwrap();
            (r.id.clone(), r.namespace.clone())
        };
        // A use, not a change: the machine's version does not move (ADR 0019).
        let tty = if req.tty { " on a terminal" } else { "" };
        self.inner.events.emit(
            Ev::normal(reason::SESSION_OPENED, format!("{program}{tty}"))
                .of(&machine, &namespace)
                .data(json!({ "command": program, "tty": req.tty })),
        );
        Ok(Session {
            conn,
            machine,
            in_use,
        })
    }

    /// The one way a command starts in a machine for a caller: woken when asked, the guest's
    /// connection once it took the command, and the machine in use while `InUse` lives.
    async fn start_command(
        &self,
        id: &str,
        wake: bool,
        req: guest::Request,
    ) -> Result<(Box<dyn guestc::Conn>, InUse), MError> {
        self.inner
            .stats
            .execs
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let e = self.own_entry(id)?;
        self.ordinary_operation(&e.snapshot())?;
        // In use from the call (ADR 0053): the sleeper leaves a machine it wakes for this.
        let in_use = InUse::new(e.clone());
        let sock = self.running_vsock(id, wake).await?;
        // An init older than sessions takes the request as a plain exec, its input and terminal
        // ignored (ADR 0027): refused, the init named, before the guest is asked.
        let init = e.snapshot().init_version;
        if req.interactive && api::version::before(&init, api::version::SESSIONS) {
            let old = guestc::UnknownOp {
                op: "session".into(),
                init,
            };
            return Err(MError::Conflict(old.to_string()));
        }
        let conn = tokio::time::timeout(
            Duration::from_secs(10),
            self.inner.guest.session(&sock, req),
        )
        .await
        .map_err(|_| MError::NotRunning("the guest did not take the command".into()))?
        .map_err(not_running_if_unreachable)?;
        Ok((conn, in_use))
    }

    /// Probe this running init now: a retained guest may predate its upgraded host.
    pub async fn file_capabilities(
        &self,
        id: &str,
    ) -> Result<api::files::FileCapabilities, MError> {
        let _in_use = InUse::new(self.own_entry(id)?);
        let sock = self.running_vsock(id, false).await?;
        let pong = tokio::time::timeout(Duration::from_secs(10), self.inner.guest.ping(&sock))
            .await
            .map_err(|_| MError::NotRunning("file capability handshake timeout".into()))?
            .map_err(not_running_if_unreachable)?;
        Ok(api::files::FileCapabilities::from_pong(&pong))
    }

    /// A file operation holds use for its whole transfer, including the guest handshake.
    pub async fn file_stream(
        &self,
        id: &str,
        req: guest::Request,
    ) -> Result<(Box<dyn guestc::Conn>, Option<u64>, InUse), MError> {
        let e = self.own_entry(id)?;
        self.ordinary_operation(&e.snapshot())?;
        let in_use = InUse::new(e);
        let sock = self.running_vsock(id, false).await?;
        let (conn, size) = tokio::time::timeout(
            Duration::from_secs(10),
            self.inner.guest.file_stream(&sock, req),
        )
        .await
        .map_err(|_| MError::NotRunning("file stream handshake timeout".into()))?
        .map_err(|e| {
            if e.is::<guestc::FileTransferBusy>() {
                MError::Conflict(e.to_string())
            } else {
                self.init_named(id, e)
            }
        })?;
        Ok((conn, size, in_use))
    }

    pub async fn put_file(&self, id: &str, req: api::PutFileRequest) -> Result<(), MError> {
        let sock = self.running_vsock(id, false).await?;
        let data =
            guest::base64_decode(&req.base64).map_err(|e| invalid(format!("base64: {e}")))?;
        let mode = match &req.mode {
            Some(m) if !m.is_empty() => {
                u32::from_str_radix(m, 8).map_err(|_| invalid(format!("mode {m:?}")))?
            }
            _ => 0o644,
        };
        tokio::time::timeout(
            Duration::from_secs(60),
            self.inner.guest.put(&sock, &req.path, mode, data),
        )
        .await
        .map_err(|_| MError::NotRunning("timeout".into()))?
        .map_err(|err| self.init_named(id, err))?;
        let _ = self.touch(id);
        Ok(())
    }

    pub async fn get_file(&self, id: &str, path: &str) -> Result<Vec<u8>, MError> {
        let sock = self.running_vsock(id, false).await?;
        let data = tokio::time::timeout(Duration::from_secs(60), self.inner.guest.get(&sock, path))
            .await
            .map_err(|_| MError::NotRunning("timeout".into()))?
            .map_err(|err| self.init_named(id, err))?;
        let _ = self.touch(id);
        Ok(data)
    }

    // --- logs ---

    /// Pages the console. `since` is an offset in the whole console, the rotated file
    /// included (ADR 0021); `limit` caps lines.
    pub fn logs(&self, id: &str, since: &str, limit: usize) -> Result<api::LogsResponse, MError> {
        self.entry(id)?;
        let limit = if limit == 0 || limit > 5000 {
            500
        } else {
            limit
        };
        let dir = self.inner.cfg.run_dir().join(id);
        match console_page(&dir, log_cursor(since)?, limit).map_err(|e| MError::Other(e.into()))? {
            None => Ok(api::LogsResponse::default()),
            Some((lines, next)) => Ok(api::LogsResponse {
                lines,
                next: next.to_string(),
            }),
        }
    }

    /// Follows the console from `since` (ADR 0025): the lines after it, then each new one,
    /// one JSON line each (`api::LogLine`), `{}` every `events::HEARTBEAT`, and a last error
    /// line when the machine is destroyed or the daemon goes down. Checked before any line
    /// goes out; ends when `tx` is dropped.
    pub fn follow_logs(
        &self,
        id: &str,
        since: &str,
        tx: tokio::sync::mpsc::Sender<String>,
    ) -> Result<(), MError> {
        // Subscribed before the machine is looked up: a destroy in between is seen.
        let (logged, closing) = self.inner.events.subscribe();
        self.entry(id)?;
        let cursor = log_cursor(since)?;
        let me = self.clone();
        let id = id.to_string();
        tokio::spawn(async move { me.follow(id, cursor, logged, closing, tx).await });
        Ok(())
    }

    pub(super) async fn follow(
        &self,
        id: String,
        mut cursor: u64,
        mut logged: broadcast::Receiver<api::Event>,
        mut closing: tokio::sync::watch::Receiver<bool>,
        tx: tokio::sync::mpsc::Sender<String>,
    ) {
        let dir = self.inner.cfg.run_dir().join(&id);
        let grown = console::grown(&dir);
        let start = tokio::time::Instant::now() + events::HEARTBEAT;
        let mut beat = tokio::time::interval_at(start, events::HEARTBEAT);
        loop {
            // Enabled before the read: a line written after it wakes this one.
            let woken = grown.notified();
            tokio::pin!(woken);
            woken.as_mut().enable();
            loop {
                let (lines, next) = match console_page(&dir, cursor, FOLLOW_PAGE) {
                    Ok(Some(page)) => page,
                    Ok(None) => break,
                    Err(err) => {
                        let why = format!("read the console: {err}");
                        events::send(&tx, &mut closing, events::last_line("internal", &why)).await;
                        return;
                    }
                };
                cursor = next;
                let full = lines.len() == FOLLOW_PAGE;
                for l in lines {
                    let line = serde_json::to_string(&l).unwrap_or_default() + "\n";
                    if !events::send(&tx, &mut closing, line).await {
                        return;
                    }
                }
                if !full {
                    break;
                }
            }
            let destroyed = loop {
                let beat_now = tokio::select! {
                    _ = &mut woken => break false,
                    e = logged.recv() => match e {
                        Ok(e) if e.machine_id == id && e.reason == reason::DESTROYED => break true,
                        Ok(_) => false,
                        // Behind the host's log: the records say whether it is gone.
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            if !self.inner.machines.lock().unwrap().contains_key(&id) {
                                break true;
                            }
                            false
                        }
                        Err(broadcast::error::RecvError::Closed) => return,
                    },
                    _ = beat.tick() => true,
                    _ = closing.wait_for(|c| *c) => {
                        // Only if there is room: a daemon going down waits for no reader.
                        let why = format!("the daemon is going down: follow again from since={cursor}");
                        let _ = tx.try_send(events::last_line("shutdown", &why));
                        return;
                    }
                    _ = tx.closed() => return,
                };
                if beat_now && !events::send(&tx, &mut closing, "{}\n".into()).await {
                    return;
                }
            };
            if destroyed {
                let why = format!("machine {id} was destroyed; its console went with it");
                events::send(&tx, &mut closing, events::last_line("destroyed", &why)).await;
                return;
            }
        }
    }

    /// Holds the machine in use for a connection the ingress is delivering (ADR 0053): from
    /// its arrival until it reaches the machine's port, through a wake and the program's start.
    /// The sleeper leaves it running meanwhile, and its last use is the delivery.
    pub fn in_use(&self, id: &str) -> Result<InUse, MError> {
        Ok(InUse::new(self.entry(id)?))
    }

    /// Whether the machine runs: a connection waiting for its port gives up once it does not.
    pub fn is_running(&self, id: &str) -> bool {
        self.entry(id)
            .is_ok_and(|e| e.rec.lock().unwrap().state == state::RUNNING)
    }

    /// The address a proxy connects to, waking the machine when asked.
    pub async fn machine_addr(&self, id: &str, wake: bool) -> Result<Ipv4Addr, MError> {
        let e = self.entry(id)?;
        let (st, ip) = {
            let r = e.rec.lock().unwrap();
            (r.state.clone(), r.ip.clone())
        };
        if st == state::RUNNING {
            e.touch();
            return Ok(ip.parse().unwrap());
        }
        if !wake {
            return Err(MError::NotRunning(st));
        }
        self.wake_detached(id).await?;
        Ok(ip.parse().unwrap())
    }
}

/// Lines a follow reads at a time.
const FOLLOW_PAGE: usize = 500;

/// A `/logs` cursor: an offset in the whole console; empty is its start.
fn log_cursor(since: &str) -> Result<u64, MError> {
    match since {
        "" => Ok(0),
        s => s
            .parse()
            .map_err(|_| invalid("since must be a cursor from a previous page")),
    }
}

/// Up to `limit` whole lines of the console in `dir` from `from`, and the cursor after the
/// last; `None` when the machine has no console yet.
fn console_page(
    dir: &Path,
    from: u64,
    limit: usize,
) -> std::io::Result<Option<(Vec<api::LogLine>, u64)>> {
    use std::io::BufRead;
    let Some((mut pos, mut r)) = console::read_from(dir, from)? else {
        return Ok(None);
    };
    let mut lines = Vec::new();
    while lines.len() < limit {
        let mut line = String::new();
        let n = r.read_line(&mut line)?;
        if n == 0 || !line.ends_with('\n') {
            break;
        }
        pos += n as u64;
        lines.push(parse_log_line(&line));
    }
    Ok(Some((lines, pos)))
}

pub(super) fn parse_log_line(line: &str) -> api::LogLine {
    let line = line.trim_end_matches(['\r', '\n']);
    if let Some((ts, rest)) = line.split_once(' ') {
        if let Ok(t) = DateTime::parse_from_rfc3339(ts) {
            return api::LogLine {
                ts: t.with_timezone(&Utc),
                line: rest.to_string(),
            };
        }
    }
    api::LogLine {
        ts: Utc::now(),
        line: line.to_string(),
    }
}
