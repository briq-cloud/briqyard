use super::*;

/// How long a command on a terminal has after its hangup before it is killed.
pub(super) const HANGUP_GRACE: Duration = Duration::from_secs(5);

/// The most stdin the init holds for a command that has not read it yet (ADR 0029).
pub(super) const STDIN_QUEUE_BYTES: usize = 16 << 20;

/// What the command's stdin gets, in order: bytes, then maybe its end. Bytes from the host
/// hold their room in the queue until written.
pub(super) enum Input {
    Data {
        bytes: Vec<u8>,
        /// Its room in the queue, given back when the bytes are written (dropped).
        _room: Option<tokio::sync::OwnedSemaphorePermit>,
    },
    Close,
}

/// Where the command's stdin goes: its pipe, or the terminal it runs on.
pub(super) enum Stdin {
    Pipe(tokio::process::ChildStdin),
    Pty(Arc<Pty>),
}

/// How an exec's wait ended.
pub(super) enum End {
    Exited(std::io::Result<std::process::ExitStatus>),
    TimedOut,
    /// The host closed the connection: nobody reads the answer any more.
    HostGone,
}

/// Runs a command for the host (ADR 0004, 0029): the request's stdin first, then the host's
/// `stdin` frames while `interactive`; stdout and stderr, or the terminal's output with `tty`,
/// streamed as they come; `exit` last. The command ends at its deadline (`timeout_ms`, 0 is
/// none) and when the host closes the connection: killed, or hung up on a terminal.
pub(super) async fn exec_op<R, W>(
    st: &Arc<State>,
    input: R,
    stream: Arc<tokio::sync::Mutex<W>>,
    req: Request,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    if req.cmd.is_empty() {
        send(&stream, &Response::error("empty command")).await;
        return;
    }
    let deadline = (req.timeout_ms > 0).then(|| Duration::from_millis(req.timeout_ms));
    let mut env = st.environment().clone();
    for (k, v) in &req.env {
        env.retain(|(ek, _)| ek != k);
        env.push((k.clone(), v.clone()));
    }
    if req.tty && !env.iter().any(|(k, _)| k == "TERM") {
        env.push(("TERM".into(), "xterm".into()));
    }
    let path = match look_path(&req.cmd[0], &env) {
        Ok(p) => p,
        Err(e) => {
            send(
                &stream,
                &Response::chunk("stderr", format!("{e}\n").into_bytes()),
            )
            .await;
            send(&stream, &Response::exit(127, false)).await;
            return;
        }
    };
    let mut cmd = Command::new(path);
    cmd.args(&req.cmd[1..]);
    cmd.env_clear();
    cmd.envs(env.iter().map(|(k, v)| (k, v)));
    let cwd = if !req.cwd.is_empty() {
        req.cwd.clone()
    } else if !st.config().workdir.is_empty() {
        st.config().workdir.clone()
    } else {
        "/".into()
    };
    cmd.current_dir(cwd);
    let pty = if req.tty {
        match on_terminal(&mut cmd, req.cols, req.rows) {
            Ok(p) => Some(Arc::new(p)),
            Err(e) => {
                let msg = format!("a terminal for the command: {e}\n");
                send(&stream, &Response::chunk("stderr", msg.into_bytes())).await;
                send(&stream, &Response::exit(126, false)).await;
                return;
            }
        }
    } else {
        cmd.stdin(if req.interactive || !req.stdin.is_empty() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd.process_group(0);
        None
    };
    cmd.kill_on_drop(true);
    let mut child = {
        let mut tracked = TRACKED.lock().unwrap();
        match cmd.spawn() {
            Ok(c) => {
                tracked.insert(c.id().unwrap_or(0) as i32);
                c
            }
            Err(e) => {
                drop(tracked);
                send(
                    &stream,
                    &Response::chunk("stderr", format!("{e}\n").into_bytes()),
                )
                .await;
                send(&stream, &Response::exit(126, false)).await;
                return;
            }
        }
    };
    // The command's copies of its terminal are its own now: once they are closed, the
    // terminal's output ends.
    drop(cmd);
    let pid = child.id().unwrap_or(0) as i32;
    let sink = match &pty {
        Some(p) => Some(Stdin::Pty(p.clone())),
        None => child.stdin.take().map(Stdin::Pipe),
    };
    let (to_stdin, stdin_rx) = tokio::sync::mpsc::unbounded_channel();
    if !req.stdin.is_empty() {
        let _ = to_stdin.send(Input::Data {
            bytes: req.stdin.clone(),
            _room: None,
        });
    }
    if !req.interactive {
        let _ = to_stdin.send(Input::Close);
    }
    tokio::spawn(write_stdin(sink, stdin_rx));
    let (gone_tx, mut gone) = tokio::sync::oneshot::channel();
    let budget = Arc::new(tokio::sync::Semaphore::new(STDIN_QUEUE_BYTES));
    let host = tokio::spawn(read_input(input, to_stdin, pty.clone(), gone_tx, budget));
    let mut readers = Vec::new();
    if let Some(p) = &pty {
        let (p, s) = (p.clone(), stream.clone());
        readers.push(tokio::spawn(async move {
            let mut buf = vec![0u8; 64 << 10];
            while let Ok(n) = p.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                send(&s, &Response::chunk("stdout", buf[..n].to_vec())).await;
            }
        }));
    }
    if let Some(out) = child.stdout.take() {
        readers.push(forward("stdout", out, stream.clone()));
    }
    if let Some(err) = child.stderr.take() {
        readers.push(forward("stderr", err, stream.clone()));
    }
    let end = {
        let exited = async {
            match deadline {
                Some(d) => tokio::time::timeout(d, child.wait()).await.ok(),
                None => Some(child.wait().await),
            }
        };
        tokio::select! {
            s = exited => match s {
                Some(s) => End::Exited(s),
                None => End::TimedOut,
            },
            _ = &mut gone => End::HostGone,
        }
    };
    let (status, timed_out) = match end {
        End::Exited(s) => (s, false),
        End::TimedOut => {
            let _ = kill(Pid::from_raw(-pid), Signal::SIGKILL);
            (child.wait().await, true)
        }
        End::HostGone => {
            hang_up(pid, pty.is_some(), &mut child).await;
            TRACKED.lock().unwrap().remove(pid);
            return;
        }
    };
    TRACKED.lock().unwrap().remove(pid);
    // Grandchildren may keep the pipes (or the terminal) open; give them a moment, then let go.
    let drain = async {
        for r in readers {
            let _ = r.await;
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(2), drain).await;
    let code = match status {
        Ok(s) => exit_code(s),
        Err(_) => 126,
    };
    send(&stream, &Response::exit(code, timed_out)).await;
    // The exit is the last frame: the connection closes with both its halves.
    host.abort();
}

/// Sends what a pipe gives as `kind` frames until it closes.
pub(super) fn forward<O, W>(
    kind: &'static str,
    mut out: O,
    s: Arc<tokio::sync::Mutex<W>>,
) -> tokio::task::JoinHandle<()>
where
    O: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 << 10];
        while let Ok(n) = out.read(&mut buf).await {
            if n == 0 {
                break;
            }
            send(&s, &Response::chunk(kind, buf[..n].to_vec())).await;
        }
    })
}

/// The host's frames after an exec's request, until it closes the connection: the command's
/// stdin and its end, the terminal's size. The close fires `gone`.
///
/// Stdin goes through a queue, so a command slow to read it does not keep the close from
/// being seen; the queue holds `budget` bytes at most (PID 1's memory is the machine's). Full,
/// the reader waits for room and reads no more of the connection: the host's writes stall, and
/// the client's behind them.
pub(super) async fn read_input<R: AsyncRead + Unpin>(
    mut input: R,
    stdin: tokio::sync::mpsc::UnboundedSender<Input>,
    pty: Option<Arc<Pty>>,
    gone: tokio::sync::oneshot::Sender<()>,
    budget: Arc<tokio::sync::Semaphore>,
) {
    while let Ok(f) = read_request(&mut input).await {
        match f.op.as_str() {
            "stdin" => {
                let room = f.data.len().clamp(1, STDIN_QUEUE_BYTES) as u32;
                let Ok(held) = budget.clone().acquire_many_owned(room).await else {
                    break;
                };
                let _ = stdin.send(Input::Data {
                    bytes: f.data,
                    _room: Some(held),
                });
            }
            "close_stdin" => {
                let _ = stdin.send(Input::Close);
            }
            "resize" => {
                if let Some(p) = &pty {
                    if let Err(e) = p.resize(f.cols, f.rows) {
                        log!("resize the terminal: {e}");
                    }
                }
            }
            _ => {}
        }
    }
    let _ = gone.send(());
}

/// Writes the command's stdin as it comes. A pipe closes at `Close`; a terminal has no end of
/// input (^D is a byte like any other), so it stays. A failed write drops the rest.
pub(super) async fn write_stdin(
    sink: Option<Stdin>,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<Input>,
) {
    let mut sink = sink;
    while let Some(i) = rx.recv().await {
        let written = match (i, &mut sink) {
            (Input::Data { bytes, .. }, Some(Stdin::Pipe(p))) => p.write_all(&bytes).await,
            (Input::Data { bytes, .. }, Some(Stdin::Pty(p))) => p.write_all(&bytes).await,
            (Input::Close, Some(Stdin::Pipe(_))) => {
                sink = None;
                Ok(())
            }
            _ => Ok(()),
        };
        if written.is_err() {
            sink = None;
        }
    }
}

/// Ends a command whose host is gone: a hangup on a terminal, as when its window closes, then
/// SIGKILL after [`HANGUP_GRACE`]; SIGKILL at once without one. Its process group either way.
pub(super) async fn hang_up(pid: i32, tty: bool, child: &mut tokio::process::Child) {
    if tty {
        let _ = kill(Pid::from_raw(-pid), Signal::SIGHUP);
        if tokio::time::timeout(HANGUP_GRACE, child.wait())
            .await
            .is_ok()
        {
            return;
        }
    }
    let _ = kill(Pid::from_raw(-pid), Signal::SIGKILL);
    let _ = child.wait().await;
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::init::testutil::*;
    use std::time::Instant;

    // --- exec ---

    #[tokio::test]
    async fn exec_streams_output_and_exit_code() {
        let st = state();
        let f = exec(
            &st,
            exec_req(&["sh", "-c", "echo out; echo err >&2; exit 3"]),
        )
        .await;
        assert_eq!(text(&f, "stdout"), "out\n");
        assert_eq!(text(&f, "stderr"), "err\n");
        let exit = exit_of(&f);
        assert_eq!((exit.code, exit.timed_out), (3, false));
    }

    #[tokio::test]
    async fn exec_feeds_stdin() {
        let st = state();
        let mut req = exec_req(&["cat"]);
        req.stdin = b"hello from the host".to_vec();
        let f = exec(&st, req).await;
        assert_eq!(text(&f, "stdout"), "hello from the host");
        assert_eq!(exit_of(&f).code, 0);
        // Without stdin the command reads nothing, not the init's own input.
        let f = exec(&st, exec_req(&["cat"])).await;
        assert_eq!(text(&f, "stdout"), "");
        assert_eq!(exit_of(&f).code, 0);
    }

    #[tokio::test]
    async fn exec_environment_and_directory() {
        let st = state_with(Config {
            env: BTreeMap::from([("FOO".to_string(), "image".to_string())]),
            workdir: "/tmp".into(),
            ..Default::default()
        });
        let f = exec(&st, exec_req(&["sh", "-c", "echo $FOO $HOME; pwd"])).await;
        assert_eq!(text(&f, "stdout"), "image /root\n/tmp\n");
        // The request's env replaces the image's; its cwd replaces the workdir.
        let mut req = exec_req(&["sh", "-c", "echo $FOO; pwd"]);
        req.env.insert("FOO".into(), "request".into());
        req.cwd = "/".into();
        let f = exec(&st, req).await;
        assert_eq!(text(&f, "stdout"), "request\n/\n");
        // No workdir and no cwd: the root.
        let f = exec(&state(), exec_req(&["pwd"])).await;
        assert_eq!(text(&f, "stdout"), "/\n");
    }

    #[tokio::test]
    async fn exec_refusals() {
        let st = state();
        let f = exec(&st, exec_req(&[])).await;
        assert_eq!(f.len(), 1);
        assert_eq!(
            (f[0].kind.as_str(), f[0].message.as_str()),
            ("error", "empty command")
        );
        // Not in PATH: 127, as a shell says.
        let f = exec(&st, exec_req(&["no-such-command-briqyard"])).await;
        assert_eq!(
            text(&f, "stderr"),
            "no-such-command-briqyard: not found in PATH\n"
        );
        assert_eq!(exit_of(&f).code, 127);
        // Found but cannot be run: 126.
        let f = exec(&st, exec_req(&["/etc/passwd"])).await;
        assert!(!text(&f, "stderr").is_empty());
        assert_eq!(exit_of(&f).code, 126);
        // A missing working directory is a spawn failure too.
        let mut req = exec_req(&["pwd"]);
        req.cwd = "/no/such/dir".into();
        let f = exec(&st, req).await;
        assert_eq!(exit_of(&f).code, 126);
    }

    #[tokio::test]
    async fn exec_reports_a_signal() {
        let f = exec(&state(), exec_req(&["sh", "-c", "kill -9 $$"])).await;
        let exit = exit_of(&f);
        assert_eq!((exit.code, exit.timed_out), (137, false));
    }

    #[tokio::test]
    async fn exec_timeout_kills_the_process_group() {
        let st = state();
        // The shell prints its sleep's pid so the test can watch that grandchild die too.
        let mut req = exec_req(&["sh", "-c", "sleep 60 & echo $!; wait"]);
        req.timeout_ms = 300;
        let start = Instant::now();
        let f = exec(&st, req).await;
        assert!(start.elapsed() < Duration::from_secs(10));
        let exit = exit_of(&f);
        assert_eq!((exit.code, exit.timed_out), (137, true));
        let grandchild: i32 = text(&f, "stdout").trim().parse().unwrap();
        // Killed with its group: gone, or a zombie waiting for the system's init.
        wait_until("the grandchild sleep is killed", || {
            matches!(proc_state(grandchild), None | Some('Z'))
        });
    }

    #[tokio::test]
    async fn exec_untracks_its_child() {
        let st = state();
        let f = exec(&st, exec_req(&["sh", "-c", "echo $$"])).await;
        let pid: i32 = text(&f, "stdout").trim().parse().unwrap();
        assert!(!TRACKED.lock().unwrap().contains(pid));
    }

    // --- sessions (ADR 0029) ---

    /// A session as the host holds one: the request sent, the connection kept for input
    /// frames, the output read as it comes.
    struct Live {
        rd: tokio::io::ReadHalf<tokio::io::DuplexStream>,
        wr: tokio::io::WriteHalf<tokio::io::DuplexStream>,
        task: tokio::task::JoinHandle<()>,
        out: String,
    }

    async fn open(st: &Arc<State>, req: Request) -> Live {
        let (client, server) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(handle(st.clone(), server));
        let (rd, wr) = tokio::io::split(client);
        let mut live = Live {
            rd,
            wr,
            task,
            out: String::new(),
        };
        live.send(req).await;
        live
    }

    fn input(op: &str) -> Request {
        Request {
            op: op.into(),
            ..Default::default()
        }
    }

    fn stdin(data: &str) -> Request {
        Request {
            data: data.as_bytes().to_vec(),
            ..input("stdin")
        }
    }

    impl Live {
        async fn send(&mut self, r: Request) {
            self.wr
                .write_all(&guest::encode_frame(&r).unwrap())
                .await
                .unwrap();
        }

        async fn frame(&mut self) -> Response {
            let read = async {
                let mut hdr = [0u8; 4];
                self.rd.read_exact(&mut hdr).await.unwrap();
                let mut body = vec![0u8; u32::from_be_bytes(hdr) as usize];
                self.rd.read_exact(&mut body).await.unwrap();
                guest::decode_frame::<Response>(&body).unwrap()
            };
            tokio::time::timeout(Duration::from_secs(10), read)
                .await
                .expect("a frame within 10 s")
        }

        /// Reads output until it holds `needle`.
        async fn until(&mut self, needle: &str) {
            while !self.out.contains(needle) {
                let f = self.frame().await;
                assert_ne!(f.kind, "exit", "ended before {needle:?}: {:?}", self.out);
                self.out.push_str(&String::from_utf8_lossy(&f.data));
            }
        }

        /// Reads to the exit, the output kept.
        async fn exit(&mut self) -> Response {
            loop {
                let f = self.frame().await;
                if f.kind == "exit" {
                    return f;
                }
                self.out.push_str(&String::from_utf8_lossy(&f.data));
            }
        }

        /// The host goes: its side of the connection closes.
        async fn hang_up(self) {
            drop((self.rd, self.wr));
            tokio::time::timeout(Duration::from_secs(10), self.task)
                .await
                .expect("the exec ends with its host")
                .unwrap();
        }
    }

    fn session(cmd: &[&str], tty: bool) -> Request {
        Request {
            interactive: true,
            tty,
            ..exec_req(cmd)
        }
    }

    fn gone(pid: i32) -> bool {
        matches!(proc_state(pid), None | Some('Z'))
    }

    #[tokio::test]
    async fn a_session_streams_stdin_until_it_closes() {
        let mut s = open(&state(), session(&["cat"], false)).await;
        s.send(stdin("one\n")).await;
        s.until("one\n").await;
        s.send(stdin("two\n")).await;
        s.send(input("close_stdin")).await;
        let exit = s.exit().await;
        assert_eq!((exit.code, s.out.as_str()), (0, "one\ntwo\n"));
        // Nothing follows the exit: the init closed its side.
        let mut rest = Vec::new();
        s.rd.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    }

    #[tokio::test]
    async fn a_session_on_a_terminal_has_its_size_and_follows_a_resize() {
        let mut req = session(
            &[
                "sh",
                "-c",
                "tty; stty size; echo TERM=$TERM; echo err >&2; read x; stty size; echo got $x; exit 4",
            ],
            true,
        );
        (req.cols, req.rows) = (100, 30);
        let mut s = open(&state(), req).await;
        s.until("TERM=xterm").await;
        assert!(s.out.contains("/dev/pts/"), "{}", s.out);
        assert!(s.out.contains("30 100"), "{}", s.out);
        s.until("err").await;
        // The resize is applied as it is read, before the next frame's input.
        s.send(Request {
            cols: 120,
            rows: 40,
            ..input("resize")
        })
        .await;
        s.send(stdin("hi\n")).await;
        let exit = s.exit().await;
        assert_eq!(exit.code, 4);
        assert!(s.out.contains("40 120"), "{}", s.out);
        // One output: what the terminal printed, its own echo of the input included.
        assert!(
            s.out.contains("hi\r\n") && s.out.contains("got hi"),
            "{}",
            s.out
        );
    }

    #[tokio::test]
    async fn a_terminal_is_80_by_24_unless_asked_and_takes_the_hosts_term() {
        let mut req = session(&["sh", "-c", "stty size; echo $TERM"], true);
        req.env.insert("TERM".into(), "xterm-256color".into());
        let mut s = open(&state(), req).await;
        assert_eq!(s.exit().await.code, 0);
        assert_eq!(s.out, "24 80\r\nxterm-256color\r\n");
    }

    #[tokio::test]
    async fn the_hosts_close_kills_the_command() {
        // A session, and a plain exec too: nobody reads its answer any more.
        for interactive in [true, false] {
            let mut req = exec_req(&["sh", "-c", "echo $$; exec sleep 60"]);
            req.interactive = interactive;
            let mut s = open(&state(), req).await;
            s.until("\n").await;
            let pid: i32 = s.out.trim().parse().unwrap();
            let start = Instant::now();
            s.hang_up().await;
            assert!(start.elapsed() < Duration::from_secs(3));
            wait_until("the command is killed", || gone(pid));
        }
    }

    #[tokio::test]
    async fn the_stdin_queue_is_bounded_and_holds_back_the_host() {
        // A queue's worth of stdin and one megabyte more, then the host's close.
        let mb = guest::encode_frame(&stdin(&"x".repeat(1 << 20))).unwrap();
        let full = STDIN_QUEUE_BYTES >> 20;
        let input = std::io::Cursor::new(mb.repeat(full + 1));
        let (tx, mut queued) = tokio::sync::mpsc::unbounded_channel();
        let (gone_tx, gone) = tokio::sync::oneshot::channel();
        let budget = Arc::new(tokio::sync::Semaphore::new(STDIN_QUEUE_BYTES));
        let mut reader = tokio::spawn(read_input(input, tx, None, gone_tx, budget));
        // Nothing writes the command's stdin: the reader waits with the queue full, so it
        // reads no more of the connection (the host's writes stall behind it).
        let waited = tokio::time::timeout(Duration::from_secs(5), &mut reader).await;
        assert!(waited.is_err(), "the reader went past a full queue");
        let mut held = Vec::new();
        while let Ok(i) = queued.try_recv() {
            held.push(i);
        }
        assert_eq!(held.len(), full);
        // Written (dropped) frees its room: the rest comes in, then the close.
        drop(held);
        tokio::time::timeout(Duration::from_secs(20), reader)
            .await
            .expect("the reader goes on once the queue drains")
            .unwrap();
        assert!(gone.await.is_ok());
        assert!(
            matches!(queued.try_recv(), Ok(Input::Data { bytes, _room: Some(_) }) if bytes.len() == 1 << 20)
        );
    }

    #[tokio::test]
    async fn the_hosts_close_hangs_up_a_terminal() {
        let script = "trap 'exit 9' HUP; echo $$; while :; do sleep 0.1; done";
        let mut s = open(&state(), session(&["sh", "-c", script], true)).await;
        s.until("\n").await;
        let pid: i32 = s.out.trim().parse().unwrap();
        let start = Instant::now();
        s.hang_up().await;
        assert!(start.elapsed() < HANGUP_GRACE, "ended by its hangup");
        wait_until("the shell is gone", || gone(pid));
        // One that ignores the hangup is killed after the grace.
        let mut s = open(
            &state(),
            session(&["sh", "-c", "trap '' HUP; echo $$; exec sleep 60"], true),
        )
        .await;
        s.until("\n").await;
        let pid: i32 = s.out.trim().parse().unwrap();
        let start = Instant::now();
        s.hang_up().await;
        assert!(start.elapsed() >= HANGUP_GRACE);
        wait_until("the sleep is killed", || gone(pid));
    }

    #[tokio::test]
    async fn a_session_has_no_deadline_unless_asked() {
        let mut req = session(&["sh", "-c", "sleep 1; echo done"], false);
        req.timeout_ms = 0;
        let mut s = open(&state(), req).await;
        let exit = s.exit().await;
        assert_eq!(
            (exit.code, exit.timed_out, s.out.as_str()),
            (0, false, "done\n")
        );
        let mut req = session(&["sleep", "30"], false);
        req.timeout_ms = 200;
        let mut s = open(&state(), req).await;
        let exit = s.exit().await;
        assert_eq!((exit.code, exit.timed_out), (137, true));
    }
}
