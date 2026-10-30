use super::*;

pub(super) fn saw_oom() -> bool {
    let mut buf = vec![0u8; 1 << 16];
    let n = unsafe {
        libc::klogctl(
            3,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len() as libc::c_int,
        )
    };
    if n <= 0 {
        return false;
    }
    String::from_utf8_lossy(&buf[..n as usize]).contains("Out of memory")
}

pub(super) fn halt() -> ! {
    // A write to the console returns once the tty holds the bytes; the serial port sends
    // them as the kernel gets to it. The exit line must be out before the reset.
    if let Some(c) = CONSOLE.get() {
        let _ = unsafe { libc::tcdrain(c.lock().unwrap().as_raw_fd()) };
    }
    nix::unistd::sync();
    // Firecracker exits when the guest resets.
    let _ = nix::sys::reboot::reboot(nix::sys::reboot::RebootMode::RB_AUTOBOOT);
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

// --- the host's side: vsock ---

pub(super) async fn serve(st: Arc<State>) {
    let mut listener = None;
    for _ in 0..50 {
        match VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, guest::PORT)) {
            Ok(l) => {
                listener = Some(l);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    let mut listener = match listener {
        Some(l) => l,
        None => {
            log!("vsock listen failed");
            return;
        }
    };
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle(st.clone(), stream));
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}

pub(super) async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Request> {
    let mut hdr = [0u8; 4];
    AsyncReadExt::read_exact(&mut *stream, &mut hdr).await?;
    let n = u32::from_be_bytes(hdr) as usize;
    if n > guest::MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut body = vec![0u8; n];
    AsyncReadExt::read_exact(&mut *stream, &mut body).await?;
    guest::decode_frame(&body)
}

pub(super) async fn send<S: AsyncWrite + Unpin>(
    stream: &Arc<tokio::sync::Mutex<S>>,
    resp: &Response,
) {
    if let Ok(frame) = guest::encode_frame(resp) {
        let mut s = stream.lock().await;
        let _ = AsyncWriteExt::write_all(&mut *s, &frame).await;
        let _ = AsyncWriteExt::flush(&mut *s).await;
    }
}

pub(super) async fn handle<S>(st: Arc<State>, stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Read and written at once: an exec takes input frames while its output goes out.
    let (mut input, output) = tokio::io::split(stream);
    let req = match read_request(&mut input).await {
        Ok(r) => r,
        Err(_) => return,
    };
    let stream = Arc::new(tokio::sync::Mutex::new(output));
    match req.op.as_str() {
        "ping" => {
            let uptime = fs::read_to_string("/proc/uptime")
                .ok()
                .and_then(|s| s.split_whitespace().next().and_then(|v| v.parse().ok()))
                .unwrap_or(0.0);
            let main_pid = st.main_pid.lock().unwrap().unwrap_or(0);
            send(
                &stream,
                &Response {
                    kind: "pong".into(),
                    uptime,
                    main_pid,
                    version: briqyard_api::VERSION.into(),
                    ..Default::default()
                },
            )
            .await;
        }
        "exec" => exec_op(&st, input, stream, req).await,
        "put_stream" | "get_stream" => files::serve(input, stream, req).await,
        "put" => {
            let res = (|| -> std::io::Result<()> {
                if let Some(parent) = Path::new(&req.path).parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&req.path, &req.data)?;
                fs::set_permissions(&req.path, fs::Permissions::from_mode(file_mode(req.mode)))
            })();
            match res {
                Ok(()) => send(&stream, &Response::new("ok")).await,
                Err(e) => send(&stream, &Response::error(e.to_string())).await,
            }
        }
        "get" => match fs::read(&req.path) {
            Ok(data) => send(&stream, &Response::chunk("file", data)).await,
            Err(e) => send(&stream, &Response::error(e.to_string())).await,
        },
        "shutdown" => {
            *st.requested.lock().unwrap() = true;
            send(&stream, &Response::new("ok")).await;
            let pid = *st.main_pid.lock().unwrap();
            if let Some(pid) = pid {
                let grace = Duration::from_secs(if req.grace_sec == 0 {
                    10
                } else {
                    req.grace_sec
                });
                log!("stopping pid={pid} grace={}s", grace.as_secs());
                let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
                if tokio::time::timeout(grace, st.main_done.notified())
                    .await
                    .is_err()
                    && st.main_pid.lock().unwrap().is_some()
                {
                    log!("killing pid={pid}");
                    let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
                }
            }
        }
        other => send(&stream, &Response::error(format!("unknown op {other}"))).await,
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::init::testutil::*;
    use std::time::Instant;

    // --- the handler over an in-memory stream ---

    /// Sends one request through `handle` and returns every response it wrote.
    async fn roundtrip(st: &Arc<State>, req: Request) -> Vec<Response> {
        let (mut client, server) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(handle(st.clone(), server));
        client
            .write_all(&guest::encode_frame(&req).unwrap())
            .await
            .unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        task.await.unwrap();
        frames(&out)
    }

    #[tokio::test]
    async fn handle_ping() {
        let st = state();
        *st.main_pid.lock().unwrap() = Some(42);
        let f = roundtrip(
            &st,
            Request {
                op: "ping".into(),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "pong");
        assert_eq!(f[0].main_pid, 42);
        assert!(f[0].uptime > 0.0, "read from /proc/uptime");
        assert_eq!(f[0].version, briqyard_api::VERSION);
    }

    #[tokio::test]
    async fn handle_put_and_get() {
        let st = state();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("deep/dir/file.txt");
        let f = roundtrip(
            &st,
            Request {
                op: "put".into(),
                path: path.to_string_lossy().into_owned(),
                data: b"content".to_vec(),
                mode: 0o600,
                ..Default::default()
            },
        )
        .await;
        assert_eq!(f[0].kind, "ok");
        assert_eq!(fs::read(&path).unwrap(), b"content");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
        let f = roundtrip(
            &st,
            Request {
                op: "get".into(),
                path: path.to_string_lossy().into_owned(),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(f[0].kind, "file");
        assert_eq!(f[0].data, b"content");
        // No mode means 0644.
        let plain = root.path().join("plain");
        roundtrip(
            &st,
            Request {
                op: "put".into(),
                path: plain.to_string_lossy().into_owned(),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(fs::metadata(&plain).unwrap().mode() & 0o7777, 0o644);
        // A missing file is an error response, not a dropped connection.
        let f = roundtrip(
            &st,
            Request {
                op: "get".into(),
                path: root.path().join("missing").to_string_lossy().into_owned(),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(f[0].kind, "error");
        assert!(f[0].message.contains("No such file"), "{}", f[0].message);
    }

    #[tokio::test]
    async fn handle_unknown_op_and_bad_frames() {
        let st = state();
        let f = roundtrip(
            &st,
            Request {
                op: "dance".into(),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(f[0].kind, "error");
        assert_eq!(f[0].message, "unknown op dance");
        // A frame past the limit, or not JSON: the connection is dropped with no answer.
        for bad in [
            ((guest::MAX_FRAME as u32 + 1).to_be_bytes().to_vec()),
            [&3u32.to_be_bytes()[..], b"{x}"].concat(),
            b"\0\0".to_vec(),
        ] {
            let (mut client, server) = tokio::io::duplex(1 << 16);
            let task = tokio::spawn(handle(st.clone(), server));
            client.write_all(&bad).await.unwrap();
            drop(client);
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn handle_exec() {
        let f = roundtrip(&state(), exec_req(&["echo", "through", "vsock"])).await;
        assert_eq!(text(&f, "stdout"), "through vsock\n");
        assert_eq!(exit_of(&f).code, 0);
    }

    /// Plays the main process for a shutdown: a tracked child, waited for as `run` does.
    struct Main {
        pid: i32,
        status: tokio::task::JoinHandle<std::process::ExitStatus>,
    }

    fn main_process(st: &Arc<State>, script: &str) -> Main {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", script]);
        cmd.kill_on_drop(false);
        let mut tracked = TRACKED.lock().unwrap();
        let mut child = cmd.spawn().unwrap();
        let pid = child.id().unwrap() as i32;
        tracked.insert(pid);
        drop(tracked);
        *st.main_pid.lock().unwrap() = Some(pid);
        let st = st.clone();
        let status = tokio::spawn(async move {
            let status = child.wait().await.unwrap();
            untrack(pid);
            *st.main_pid.lock().unwrap() = None;
            st.main_done.notify_waiters();
            status
        });
        Main { pid, status }
    }

    #[tokio::test]
    async fn shutdown_terminates_the_main_process() {
        let st = state();
        let main = main_process(&st, "sleep 60");
        let f = roundtrip(
            &st,
            Request {
                op: "shutdown".into(),
                grace_sec: 5,
                ..Default::default()
            },
        )
        .await;
        assert_eq!(f[0].kind, "ok");
        assert!(
            *st.requested.lock().unwrap(),
            "the exit is marked as requested"
        );
        let status = main.status.await.unwrap();
        assert_eq!(status.signal(), Some(libc::SIGTERM), "{status:?}");
        assert_eq!(*st.main_pid.lock().unwrap(), None);
        assert!(matches!(proc_state(main.pid), None | Some('Z')));
    }

    #[tokio::test]
    async fn shutdown_kills_after_the_grace() {
        let st = state();
        // Ignores SIGTERM; exec keeps it one process so SIGKILL on the pid ends it all.
        let main = main_process(&st, "trap '' TERM; exec sleep 60");
        // Not before the trap is set and sleep is running, or SIGTERM lands on a shell
        // that still honours it.
        wait_until("the main process is sleep", || {
            fs::read_to_string(format!("/proc/{}/comm", main.pid))
                .map(|c| c.trim() == "sleep")
                .unwrap_or(false)
        });
        let start = Instant::now();
        let f = roundtrip(
            &st,
            Request {
                op: "shutdown".into(),
                grace_sec: 1,
                ..Default::default()
            },
        )
        .await;
        assert_eq!(f[0].kind, "ok");
        let status = main.status.await.unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL), "{status:?}");
        assert!(
            start.elapsed() >= Duration::from_secs(1),
            "the grace was given"
        );
    }

    #[tokio::test]
    async fn shutdown_with_no_main_process() {
        let st = state();
        let f = roundtrip(
            &st,
            Request {
                op: "shutdown".into(),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(f[0].kind, "ok");
        assert!(*st.requested.lock().unwrap());
    }
}
