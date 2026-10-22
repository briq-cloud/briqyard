//! The host's side of the guest protocol: one connection per operation through Firecracker's
//! vsock Unix socket.

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use briqyard_api::guest::{self, Request, Response};
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// An exec's connection to the init, past its request: its output frames to read, its input
/// frames to write (ADR 0029). Closing it ends the command.
pub trait Conn: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Conn for T {}

/// The guest as the manager reaches it, by the machine's vsock socket: the init over vsock
/// on the host, a mock in the manager's tests.
#[async_trait]
pub trait Guest: Send + Sync {
    /// Waits for the init to answer; its version (ADR 0027), empty from an init older than
    /// the report.
    async fn wait_ready(&self, vsock: &Path, timeout: Duration) -> Result<String>;
    async fn shutdown(&self, vsock: &Path, grace: Duration) -> Result<()>;
    /// Starts a command and hands its connection over: [`collect`] reads it to the exit.
    async fn session(&self, vsock: &Path, req: Request) -> Result<Box<dyn Conn>>;
    async fn put(&self, vsock: &Path, path: &str, mode: u32, data: Vec<u8>) -> Result<()>;
    async fn get(&self, vsock: &Path, path: &str) -> Result<Vec<u8>>;
}

/// The init behind Firecracker's vsock socket.
pub struct Vsock;

#[async_trait]
impl Guest for Vsock {
    async fn wait_ready(&self, vsock: &Path, timeout: Duration) -> Result<String> {
        wait_ready(vsock, timeout).await
    }
    async fn shutdown(&self, vsock: &Path, grace: Duration) -> Result<()> {
        shutdown(vsock, grace).await
    }
    async fn session(&self, vsock: &Path, req: Request) -> Result<Box<dyn Conn>> {
        Ok(Box::new(session(vsock, req).await?))
    }
    async fn put(&self, vsock: &Path, path: &str, mode: u32, data: Vec<u8>) -> Result<()> {
        put(vsock, path, mode, data).await
    }
    async fn get(&self, vsock: &Path, path: &str) -> Result<Vec<u8>> {
        get(vsock, path).await
    }
}

/// Connects to the init: open Firecracker's socket, ask for the guest port, wait for its OK.
pub async fn dial(uds: &Path) -> Result<UnixStream> {
    let mut s = UnixStream::connect(uds)
        .await
        .with_context(|| format!("vsock {}", uds.display()))?;
    s.write_all(format!("CONNECT {}\n", guest::PORT).as_bytes())
        .await?;
    let mut r = BufReader::new(s);
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), r.read_line(&mut line))
        .await
        .context("vsock connect")??;
    if !line.starts_with("OK ") {
        return Err(anyhow!("vsock connect refused: {}", line.trim()));
    }
    Ok(r.into_inner())
}

/// Writes one frame: a request, or an exec's input after it.
pub async fn write_request<W: AsyncWrite + Unpin>(s: &mut W, req: &Request) -> Result<()> {
    s.write_all(&guest::encode_frame(req)?).await?;
    s.flush().await?;
    Ok(())
}

/// Reads one frame of the guest protocol.
pub async fn read_frame<R, T>(s: &mut R) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: serde::de::DeserializeOwned,
{
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await?;
    let n = u32::from_be_bytes(hdr) as usize;
    if n > guest::MAX_FRAME {
        return Err(anyhow!("frame too large"));
    }
    let mut body = vec![0u8; n];
    s.read_exact(&mut body).await?;
    Ok(guest::decode_frame(&body)?)
}

#[derive(Debug)]
pub struct ExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub code: i32,
    pub timed_out: bool,
}

/// How much of each stream is kept.
pub const MAX_OUTPUT: usize = 4 << 20;

#[derive(Debug, thiserror::Error)]
#[error("the guest connection closed before the command ended")]
pub struct Closed;

/// An op the machine's init does not know: it is older than this daemon's use of it (ADR
/// 0027). The init of a machine is the one its root disk was made with.
#[derive(Debug, thiserror::Error)]
#[error("the machine's init ({}) does not know `{op}`: it is older than this daemon; the machine gets this daemon's init when its root disk is made again (an image change)", if .init.is_empty() { "older than the version report" } else { .init.as_str() })]
pub struct UnknownOp {
    pub op: String,
    /// The machine's `init_version`; empty until [`with_init`] names it.
    pub init: String,
}

/// The error of an answer `error`: [`UnknownOp`] when the init does not know the op.
fn answered(op: &str, message: &str) -> anyhow::Error {
    match message == format!("unknown op {op}") {
        true => UnknownOp {
            op: op.into(),
            init: String::new(),
        }
        .into(),
        false => anyhow!("{message}"),
    }
}

/// Names the machine's init in an [`UnknownOp`]; any other error as it is.
pub fn with_init(err: anyhow::Error, init: &str) -> anyhow::Error {
    match err.downcast::<UnknownOp>() {
        Ok(u) => UnknownOp {
            op: u.op,
            init: init.into(),
        }
        .into(),
        Err(err) => err,
    }
}

/// Starts a command: the connection, its request sent, for the output to be read from and
/// the input written to.
pub async fn session(uds: &Path, mut req: Request) -> Result<UnixStream> {
    req.op = "exec".into();
    let mut s = dial(uds).await?;
    write_request(&mut s, &req).await?;
    Ok(s)
}

/// Reads an exec's output frames to its `exit`; a connection closed before it is [`Closed`].
pub async fn collect<R: AsyncRead + Unpin>(s: &mut R) -> Result<ExecOutput> {
    let mut out = ExecOutput {
        stdout: Vec::new(),
        stderr: Vec::new(),
        code: 0,
        timed_out: false,
    };
    loop {
        let r: Response = match read_frame(s).await {
            Ok(r) => r,
            Err(e) => {
                if e.downcast_ref::<std::io::Error>()
                    .map(|e| e.kind() == std::io::ErrorKind::UnexpectedEof)
                    .unwrap_or(false)
                {
                    return Err(Closed.into());
                }
                return Err(e);
            }
        };
        match r.kind.as_str() {
            "stdout" => append(&mut out.stdout, &r.data),
            "stderr" => append(&mut out.stderr, &r.data),
            "exit" => {
                out.code = r.code;
                out.timed_out = r.timed_out;
                return Ok(out);
            }
            "error" => return Err(answered("exec", &r.message)),
            _ => {}
        }
    }
}

fn append(buf: &mut Vec<u8>, data: &[u8]) {
    let room = MAX_OUTPUT.saturating_sub(buf.len());
    buf.extend_from_slice(&data[..data.len().min(room)]);
}

async fn round_trip(uds: &Path, req: Request) -> Result<Response> {
    let mut s = dial(uds).await?;
    write_request(&mut s, &req).await?;
    let r: Response = read_frame(&mut s).await?;
    if r.kind == "error" {
        return Err(answered(&req.op, &r.message));
    }
    Ok(r)
}

pub async fn put(uds: &Path, path: &str, mode: u32, data: Vec<u8>) -> Result<()> {
    let r = round_trip(
        uds,
        Request {
            op: "put".into(),
            path: path.into(),
            mode,
            data,
            ..Default::default()
        },
    )
    .await?;
    if r.kind != "ok" {
        return Err(anyhow!("guest answered {}", r.kind));
    }
    Ok(())
}

pub async fn get(uds: &Path, path: &str) -> Result<Vec<u8>> {
    let r = round_trip(
        uds,
        Request {
            op: "get".into(),
            path: path.into(),
            ..Default::default()
        },
    )
    .await?;
    if r.kind != "file" {
        return Err(anyhow!("guest answered {}", r.kind));
    }
    Ok(r.data)
}

pub async fn ping(uds: &Path) -> Result<Response> {
    let r = round_trip(
        uds,
        Request {
            op: "ping".into(),
            ..Default::default()
        },
    )
    .await?;
    if r.kind != "pong" {
        return Err(anyhow!("guest answered {}", r.kind));
    }
    Ok(r)
}

/// Asks the init to end the main process (SIGTERM, then SIGKILL after the grace) and halt.
pub async fn shutdown(uds: &Path, grace: Duration) -> Result<()> {
    let r = round_trip(
        uds,
        Request {
            op: "shutdown".into(),
            grace_sec: grace.as_secs(),
            ..Default::default()
        },
    )
    .await?;
    if r.kind != "ok" {
        return Err(anyhow!("guest answered {}", r.kind));
    }
    Ok(())
}

/// Polls `ping` until the init answers or the timeout passes; the version its `pong` says.
pub async fn wait_ready(uds: &Path, timeout: Duration) -> Result<String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let last = match tokio::time::timeout(Duration::from_secs(2), ping(uds)).await {
            Ok(Ok(pong)) => return Ok(pong.version),
            Ok(Err(e)) => e.to_string(),
            Err(_) => "timeout".to_string(),
        };
        if tokio::time::Instant::now() > deadline {
            return Err(anyhow!(
                "guest init did not answer within {timeout:?} (last: {last})"
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    /// A stand-in for Firecracker's vsock socket with the init behind it: answers the
    /// `CONNECT` line with `handshake`, reads one request frame, writes `answers` as they
    /// are, closes, and hands the request back.
    fn serve(
        uds: &Path,
        handshake: &'static str,
        answers: Vec<Vec<u8>>,
    ) -> tokio::task::JoinHandle<Request> {
        let ln = UnixListener::bind(uds).unwrap();
        tokio::spawn(async move {
            let (s, _) = ln.accept().await.unwrap();
            let mut r = BufReader::new(s);
            let mut line = String::new();
            r.read_line(&mut line).await.unwrap();
            assert_eq!(line, format!("CONNECT {}\n", guest::PORT));
            let mut s = r.into_inner();
            s.write_all(handshake.as_bytes()).await.unwrap();
            if handshake != OK {
                // Refused: the client hangs up, there is no request to read.
                return Request::default();
            }
            let mut hdr = [0u8; 4];
            s.read_exact(&mut hdr).await.unwrap();
            let mut body = vec![0u8; u32::from_be_bytes(hdr) as usize];
            s.read_exact(&mut body).await.unwrap();
            let req: Request = guest::decode_frame(&body).unwrap();
            for a in answers {
                s.write_all(&a).await.unwrap();
            }
            req
        })
    }

    fn frame(r: &Response) -> Vec<u8> {
        guest::encode_frame(r).unwrap()
    }

    fn socket() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.sock");
        (dir, path)
    }

    const OK: &str = "OK 7421\n";

    #[tokio::test]
    async fn dial_does_the_vsock_handshake() {
        let (_dir, path) = socket();
        let server = serve(&path, OK, vec![]);
        let mut s = dial(&path).await.unwrap();
        // Something must follow for the server to finish: an empty request.
        write_request(&mut s, &Request::default()).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn dial_refused_or_absent() {
        let (_dir, path) = socket();
        let _server = serve(&path, "nope\n", vec![]);
        let err = dial(&path).await.unwrap_err();
        assert_eq!(err.to_string(), "vsock connect refused: nope");

        let missing = path.with_file_name("none.sock");
        let err = dial(&missing).await.unwrap_err();
        assert!(
            format!("{err:#}").contains(&format!("vsock {}", missing.display())),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn exec_streams_both_outputs_then_exit() {
        let (_dir, path) = socket();
        let server = serve(
            &path,
            OK,
            vec![
                frame(&Response::chunk("stdout", b"hel".to_vec())),
                frame(&Response::chunk("stderr", b"warn\n".to_vec())),
                frame(&Response::chunk("stdout", b"lo\n".to_vec())),
                frame(&Response::chunk("something-new", b"ignored".to_vec())),
                frame(&Response::exit(3, true)),
            ],
        );
        let req = Request {
            cmd: vec!["sh".into(), "-c".into(), "echo hello".into()],
            cwd: "/work".into(),
            stdin: b"in".to_vec(),
            timeout_ms: 500,
            ..Default::default()
        };
        let out = collect(&mut session(&path, req).await.unwrap())
            .await
            .unwrap();
        assert_eq!(out.stdout, b"hello\n");
        assert_eq!(out.stderr, b"warn\n");
        assert_eq!(out.code, 3);
        assert!(out.timed_out);
        let seen = server.await.unwrap();
        // exec sets the op itself; the rest of the request goes through as given.
        assert_eq!(seen.op, "exec");
        assert_eq!(seen.cmd, vec!["sh", "-c", "echo hello"]);
        assert_eq!(seen.cwd, "/work");
        assert_eq!(seen.stdin, b"in");
        assert_eq!(seen.timeout_ms, 500);
    }

    #[tokio::test]
    async fn a_session_is_the_exec_connection_kept_for_input() {
        let (_dir, path) = socket();
        let ln = UnixListener::bind(&path).unwrap();
        // The init's side: the request, then input frames, answered by an echo and the exit.
        let init = tokio::spawn(async move {
            let (s, _) = ln.accept().await.unwrap();
            let mut r = BufReader::new(s);
            let mut line = String::new();
            r.read_line(&mut line).await.unwrap();
            let mut s = r.into_inner();
            s.write_all(OK.as_bytes()).await.unwrap();
            let req: Request = read_frame(&mut s).await.unwrap();
            let input: Request = read_frame(&mut s).await.unwrap();
            let close: Request = read_frame(&mut s).await.unwrap();
            for a in [
                Response::chunk("stdout", input.data.clone()),
                Response::exit(0, false),
            ] {
                s.write_all(&frame(&a)).await.unwrap();
            }
            (req, input.op, close.op)
        });
        let req = Request {
            cmd: vec!["cat".into()],
            interactive: true,
            tty: true,
            cols: 100,
            rows: 30,
            ..Default::default()
        };
        let mut s = session(&path, req).await.unwrap();
        for f in [
            Request {
                op: "stdin".into(),
                data: b"typed".to_vec(),
                ..Default::default()
            },
            Request {
                op: "close_stdin".into(),
                ..Default::default()
            },
        ] {
            write_request(&mut s, &f).await.unwrap();
        }
        let out = collect(&mut s).await.unwrap();
        assert_eq!((out.stdout.as_slice(), out.code), (&b"typed"[..], 0));
        let (seen, input, close) = init.await.unwrap();
        assert_eq!(seen.op, "exec");
        assert!(seen.interactive && seen.tty);
        assert_eq!((seen.cols, seen.rows), (100, 30));
        assert_eq!((input.as_str(), close.as_str()), ("stdin", "close_stdin"));
    }

    #[tokio::test]
    async fn exec_error_frame_is_the_init_message() {
        let (_dir, path) = socket();
        let _server = serve(
            &path,
            OK,
            vec![frame(&Response::error("no such file: /bin/nope"))],
        );
        let err = collect(&mut session(&path, Request::default()).await.unwrap())
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "no such file: /bin/nope");
    }

    #[tokio::test]
    async fn exec_closed_before_exit_is_closed() {
        let (_dir, path) = socket();
        let _server = serve(
            &path,
            OK,
            vec![frame(&Response::chunk("stdout", b"partial".to_vec()))],
        );
        let err = collect(&mut session(&path, Request::default()).await.unwrap())
            .await
            .unwrap_err();
        assert!(err.downcast_ref::<Closed>().is_some(), "{err}");
    }

    #[tokio::test]
    async fn a_frame_past_the_limit_is_refused() {
        let (_dir, path) = socket();
        let _server = serve(
            &path,
            OK,
            vec![((guest::MAX_FRAME as u32) + 1).to_be_bytes().to_vec()],
        );
        let err = collect(&mut session(&path, Request::default()).await.unwrap())
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "frame too large");
    }

    #[test]
    fn output_is_capped() {
        let mut buf = vec![0u8; MAX_OUTPUT - 3];
        append(&mut buf, b"abcdef");
        assert_eq!(buf.len(), MAX_OUTPUT);
        assert_eq!(&buf[MAX_OUTPUT - 3..], b"abc");
        // Full: nothing more is kept, and nothing panics.
        append(&mut buf, b"xyz");
        assert_eq!(buf.len(), MAX_OUTPUT);
    }

    #[tokio::test]
    async fn put_sends_the_file_and_wants_ok() {
        let (_dir, path) = socket();
        let server = serve(&path, OK, vec![frame(&Response::new("ok"))]);
        put(&path, "/etc/app.conf", 0o600, b"k=v\n".to_vec())
            .await
            .unwrap();
        let seen = server.await.unwrap();
        assert_eq!(seen.op, "put");
        assert_eq!(seen.path, "/etc/app.conf");
        assert_eq!(seen.mode, 0o600);
        assert_eq!(seen.data, b"k=v\n");

        let (_dir, path) = socket();
        let _server = serve(&path, OK, vec![frame(&Response::new("pong"))]);
        let err = put(&path, "/x", 0o644, vec![]).await.unwrap_err();
        assert_eq!(err.to_string(), "guest answered pong");
    }

    #[tokio::test]
    async fn get_reads_the_file() {
        let (_dir, path) = socket();
        let server = serve(
            &path,
            OK,
            vec![frame(&Response::chunk("file", b"content".to_vec()))],
        );
        assert_eq!(get(&path, "/etc/hostname").await.unwrap(), b"content");
        let seen = server.await.unwrap();
        assert_eq!(
            (seen.op.as_str(), seen.path.as_str()),
            ("get", "/etc/hostname")
        );

        let (_dir, path) = socket();
        let _server = serve(&path, OK, vec![frame(&Response::error("not found"))]);
        let err = get(&path, "/nope").await.unwrap_err();
        assert_eq!(err.to_string(), "not found");
    }

    #[tokio::test]
    async fn ping_and_shutdown() {
        let (_dir, path) = socket();
        let pong = Response {
            kind: "pong".into(),
            uptime: 12.5,
            main_pid: 7,
            ..Default::default()
        };
        let server = serve(&path, OK, vec![frame(&pong)]);
        let r = ping(&path).await.unwrap();
        assert_eq!((r.uptime, r.main_pid), (12.5, 7));
        assert_eq!(server.await.unwrap().op, "ping");

        let (_dir, path) = socket();
        let server = serve(&path, OK, vec![frame(&Response::new("ok"))]);
        shutdown(&path, Duration::from_secs(10)).await.unwrap();
        let seen = server.await.unwrap();
        assert_eq!((seen.op.as_str(), seen.grace_sec), ("shutdown", 10));

        let (_dir, path) = socket();
        let _server = serve(&path, OK, vec![frame(&Response::new("ok"))]);
        let err = ping(&path).await.unwrap_err();
        assert_eq!(err.to_string(), "guest answered ok");
    }

    #[tokio::test]
    async fn wait_ready_polls_until_a_pong() {
        let (_dir, path) = socket();
        let t0 = std::time::Instant::now();
        let err = wait_ready(&path, Duration::from_millis(250))
            .await
            .unwrap_err();
        assert!(t0.elapsed() >= Duration::from_millis(250));
        let msg = err.to_string();
        assert!(msg.contains("did not answer within"), "{msg}");
        assert!(msg.contains("last: vsock"), "{msg}");

        // An init older than the version report answers none: an empty version.
        let _server = serve(&path, OK, vec![frame(&Response::new("pong"))]);
        assert_eq!(wait_ready(&path, Duration::from_secs(5)).await.unwrap(), "");
    }

    #[tokio::test]
    async fn an_op_an_old_init_does_not_know_is_named_with_its_version() {
        let (_dir, path) = socket();
        // What every init answers an op it does not know.
        let _server = serve(&path, OK, vec![frame(&Response::error("unknown op get"))]);
        let err = get(&path, "/etc/hostname").await.unwrap_err();
        assert!(err.downcast_ref::<UnknownOp>().is_some());
        assert_eq!(
            with_init(err, "0.1.0+fdad892eeefa").to_string(),
            "the machine's init (0.1.0+fdad892eeefa) does not know `get`: it is older than this daemon; the machine gets this daemon's init when its root disk is made again (an image change)"
        );
        let unnamed = UnknownOp {
            op: "resize".into(),
            init: String::new(),
        };
        assert!(unnamed.to_string().starts_with(
            "the machine's init (older than the version report) does not know `resize`"
        ));
        // Any other error is the init's own message, untouched.
        let (_dir, path) = socket();
        let _server = serve(&path, OK, vec![frame(&Response::error("no such file"))]);
        let err = with_init(get(&path, "/x").await.unwrap_err(), "0.1.0+a");
        assert_eq!(err.to_string(), "no such file");
    }

    #[tokio::test]
    async fn wait_ready_answers_the_inits_version() {
        let (_dir, path) = socket();
        let pong = Response {
            kind: "pong".into(),
            version: "0.1.0+fdad892eeefa".into(),
            ..Default::default()
        };
        let _server = serve(&path, OK, vec![frame(&pong)]);
        assert_eq!(
            wait_ready(&path, Duration::from_secs(5)).await.unwrap(),
            "0.1.0+fdad892eeefa"
        );
    }
}
