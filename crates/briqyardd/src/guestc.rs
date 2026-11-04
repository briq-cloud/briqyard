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
    /// Bounded sync, including EOF proving the guest handler has closed.
    async fn fs_sync(&self, _vsock: &Path) -> Result<()> {
        Err(anyhow!("filesystem sync unavailable"))
    }
    /// No lifecycle caller until ADR 0092 slice C. Drop closes and thaws.
    async fn fs_freeze(&self, _vsock: &Path, _hold: Duration) -> Result<Frozen> {
        Err(anyhow!("filesystem freeze unavailable"))
    }
    async fn shutdown(&self, vsock: &Path, grace: Duration) -> Result<()>;
    /// Starts a command and hands its connection over: [`collect`] reads it to the exit.
    async fn session(&self, vsock: &Path, req: Request) -> Result<Box<dyn Conn>>;
    async fn exec_stream_v1(&self, _vsock: &Path, _req: Request) -> Result<Box<dyn Conn>> {
        Err(anyhow!("exec stream v1 unavailable"))
    }
    async fn put(&self, vsock: &Path, path: &str, mode: u32, data: Vec<u8>) -> Result<()>;
    async fn get(&self, vsock: &Path, path: &str) -> Result<Vec<u8>>;
    async fn ping(&self, _vsock: &Path) -> Result<Response> {
        Err(anyhow!("guest ping unavailable"))
    }
    async fn destination_control(&self, _vsock: &Path, _request: Request) -> Result<Response> {
        Err(anyhow!("sandbox destination control unavailable"))
    }
    async fn clone_control(&self, _vsock: &Path, _request: Request) -> Result<guest::CloneStatus> {
        Err(anyhow!("clone control unavailable"))
    }
    /// Open a raw file stream after its ready handshake (ADR 0061).
    async fn file_stream(
        &self,
        _vsock: &Path,
        _req: Request,
    ) -> Result<(Box<dyn Conn>, Option<u64>)> {
        Err(anyhow!("streaming files unavailable"))
    }
}

/// The init behind Firecracker's vsock socket.
pub struct Vsock;

#[async_trait]
impl Guest for Vsock {
    async fn fs_sync(&self, vsock: &Path) -> Result<()> {
        tokio::time::timeout(CONTROL_TIMEOUT, async {
            let mut conn = dial(vsock).await?;
            write_request(
                &mut conn,
                &Request {
                    op: "fs_sync".into(),
                    ..Default::default()
                },
            )
            .await?;
            sync_answer(Box::new(conn)).await
        })
        .await
        .context("guest fs_sync timeout")?
    }
    async fn fs_freeze(&self, vsock: &Path, hold: Duration) -> Result<Frozen> {
        tokio::time::timeout(CONTROL_TIMEOUT, async {
            let mut conn = dial(vsock).await?;
            write_request(
                &mut conn,
                &Request {
                    op: "fs_freeze".into(),
                    timeout_ms: hold.as_millis().min(30_000) as u64,
                    ..Default::default()
                },
            )
            .await?;
            let answer: Response = read_frame(&mut conn).await?;
            check_fs_answer("fs_freeze", &answer)?;
            Ok(Frozen {
                conn: Box::new(conn),
                filesystems: answer.frozen,
            })
        })
        .await
        .context("guest fs_freeze timeout")?
    }

    async fn destination_control(&self, vsock: &Path, request: Request) -> Result<Response> {
        let exchange = async {
            let mut connection = dial(vsock).await?;
            write_request(&mut connection, &request).await?;
            let response: Response = read_frame(&mut connection).await?;
            anyhow::ensure!(response.kind == "ok", "guest control refused");
            Ok(response)
        };
        tokio::time::timeout(Duration::from_secs(10), exchange)
            .await
            .context("guest control timeout")?
    }
    async fn clone_control(&self, vsock: &Path, request: Request) -> Result<guest::CloneStatus> {
        self.destination_control(vsock, request)
            .await?
            .clone_status
            .ok_or_else(|| anyhow!("clone control omitted its identity/status acknowledgment"))
    }
    async fn ping(&self, vsock: &Path) -> Result<Response> {
        ping(vsock).await
    }
    async fn file_stream(
        &self,
        vsock: &Path,
        req: Request,
    ) -> Result<(Box<dyn Conn>, Option<u64>)> {
        let mut conn = dial(vsock).await?;
        write_request(&mut conn, &req).await?;
        let r: Response = read_frame(&mut conn).await?;
        if r.kind == "error" {
            if r.message == "too many file transfers" {
                return Err(FileTransferBusy.into());
            }
            return Err(answered(&req.op, &r.message));
        }
        if r.kind != "ready" {
            return Err(anyhow!("guest answered {}", r.kind));
        }
        Ok((Box::new(conn), r.size))
    }
    async fn wait_ready(&self, vsock: &Path, timeout: Duration) -> Result<String> {
        wait_ready(vsock, timeout).await
    }
    async fn shutdown(&self, vsock: &Path, grace: Duration) -> Result<()> {
        shutdown(vsock, grace).await
    }
    async fn session(&self, vsock: &Path, req: Request) -> Result<Box<dyn Conn>> {
        Ok(Box::new(session(vsock, req).await?))
    }
    async fn exec_stream_v1(&self, vsock: &Path, mut req: Request) -> Result<Box<dyn Conn>> {
        req.op = "exec_stream_v1".into();
        let mut conn = dial(vsock).await?;
        write_request(&mut conn, &req).await?;
        Ok(Box::new(conn))
    }
    async fn put(&self, vsock: &Path, path: &str, mode: u32, data: Vec<u8>) -> Result<()> {
        put(vsock, path, mode, data).await
    }
    async fn get(&self, vsock: &Path, path: &str) -> Result<Vec<u8>> {
        get(vsock, path).await
    }
}

/// The guest's bounded file transfer slots are all in use.
#[derive(Debug, thiserror::Error)]
#[error("too many file transfers in the guest")]
pub struct FileTransferBusy;

/// The guest cannot be reached: Firecracker's socket refuses (its process is exiting or gone)
/// or the init's port does (the guest is exiting). The machine is not running, whatever its
/// record says until the exit is settled.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Unreachable(pub String);

/// Connects to the init: open Firecracker's socket, ask for the guest port, wait for its OK.
///
/// A reset of the socket during the handshake (Firecracker's muxer tearing down a connection
/// as the guest's vsock is reset, a restore or a restart of the init) happens before any
/// request was written: nothing reached the guest, so the handshake is tried again, a few
/// times, then reported as an unreachable guest. Only the handshake is retried: once a request
/// is sent, a command may have started and is never sent twice.
pub async fn dial(uds: &Path) -> Result<UnixStream> {
    let mut attempt = 1;
    loop {
        match handshake(uds).await {
            Err(Handshake::Reset(_)) if attempt < HANDSHAKE_ATTEMPTS => {
                attempt += 1;
                tokio::time::sleep(HANDSHAKE_PAUSE * attempt).await;
            }
            Err(Handshake::Reset(e)) => {
                return Err(Unreachable(format!(
                    "vsock {}: reset {HANDSHAKE_ATTEMPTS} times: {e}",
                    uds.display()
                ))
                .into())
            }
            Err(Handshake::Failed(e)) => return Err(e),
            Ok(s) => return Ok(s),
        }
    }
}

const HANDSHAKE_ATTEMPTS: u32 = 4;
const HANDSHAKE_PAUSE: Duration = Duration::from_millis(100);

enum Handshake {
    /// The socket was reset before the guest answered: nothing was delivered.
    Reset(std::io::Error),
    Failed(anyhow::Error),
}

fn is_reset(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(e.kind(), ConnectionReset | ConnectionAborted | BrokenPipe)
}

impl From<std::io::Error> for Handshake {
    fn from(e: std::io::Error) -> Self {
        if is_reset(&e) {
            Handshake::Reset(e)
        } else {
            Handshake::Failed(e.into())
        }
    }
}

async fn handshake(uds: &Path) -> std::result::Result<UnixStream, Handshake> {
    let mut s = UnixStream::connect(uds).await.map_err(|e| {
        Handshake::Failed(Unreachable(format!("vsock {}: {e}", uds.display())).into())
    })?;
    s.write_all(format!("CONNECT {}\n", guest::PORT).as_bytes())
        .await?;
    let mut r = BufReader::new(s);
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), r.read_line(&mut line))
        .await
        .map_err(|e| Handshake::Failed(anyhow::Error::new(e).context("vsock connect")))??;
    if !line.starts_with("OK ") {
        return Err(Handshake::Failed(
            Unreachable(format!("vsock connect refused: {}", line.trim())).into(),
        ));
    }
    Ok(r.into_inner())
}

/// Writes one frame: a request, or an exec's input after it.
pub async fn write_request<W: AsyncWrite + Unpin>(s: &mut W, req: &Request) -> Result<()> {
    s.write_all(&guest::encode_frame(req)?)
        .await
        .map_err(after_write)?;
    s.flush().await.map_err(after_write)?;
    Ok(())
}

/// Reads one frame of the guest protocol.
pub async fn read_frame<R, T>(s: &mut R) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: serde::de::DeserializeOwned,
{
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await.map_err(after_write)?;
    let n = u32::from_be_bytes(hdr) as usize;
    if n > guest::MAX_FRAME {
        return Err(anyhow!("frame too large"));
    }
    let mut body = vec![0u8; n];
    s.read_exact(&mut body).await.map_err(after_write)?;
    Ok(guest::decode_frame(&body)?)
}

/// An io error on a connection whose request was already sent: a reset or an end of stream
/// is the guest going away, [`Closed`]. The command may have started, so nothing sends
/// it again; the caller reports it (ADR 0091).
pub(crate) fn after_write(e: std::io::Error) -> anyhow::Error {
    if is_reset(&e) || e.kind() == std::io::ErrorKind::UnexpectedEof {
        Closed.into()
    } else {
        e.into()
    }
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
        let r: Response = read_frame(s).await?;
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

/// How long `wait_ready` sleeps after a refused or unanswered ping, `elapsed` into the wait.
/// The init is listening some 500 ms after the machine starts and a ping that finds nobody
/// listening costs one local connect, so the first seconds are polled every few milliseconds:
/// readiness is noticed within that, not within a hundred (ADR 0093). A guest that stays
/// silent past them is slow or wedged, and costs the VMM a connect every 100 ms.
fn poll_interval(elapsed: Duration) -> Duration {
    if elapsed < FAST_POLL_FOR {
        FAST_POLL
    } else {
        SLOW_POLL
    }
}

const FAST_POLL: Duration = Duration::from_millis(5);
const FAST_POLL_FOR: Duration = Duration::from_secs(5);
const SLOW_POLL: Duration = Duration::from_millis(100);

/// Polls `ping` until the init answers or the timeout passes; the version its `pong` says.
pub async fn wait_ready(uds: &Path, timeout: Duration) -> Result<String> {
    let start = tokio::time::Instant::now();
    let deadline = start + timeout;
    loop {
        let last = match tokio::time::timeout(Duration::from_secs(2), ping(uds)).await {
            Ok(Ok(pong)) => return Ok(pong.version),
            Ok(Err(e)) => e.to_string(),
            Err(_) => "timeout".to_string(),
        };
        let now = tokio::time::Instant::now();
        if now > deadline {
            return Err(anyhow!(
                "guest init did not answer within {timeout:?} (last: {last})"
            ));
        }
        tokio::time::sleep(poll_interval(now - start)).await;
    }
}

/// Every guest control exchange is bounded independently of other machines.
pub const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);

fn check_fs_answer(op: &str, r: &Response) -> Result<()> {
    if r.kind == "error" {
        return Err(answered(op, &r.message));
    }
    anyhow::ensure!(r.kind == "ok", "guest {op} answered {}", r.kind);
    Ok(())
}
async fn sync_answer(mut conn: Box<dyn Conn>) -> Result<()> {
    let answer: Response = read_frame(&mut conn).await?;
    check_fs_answer("fs_sync", &answer)?;
    let mut byte = [0];
    anyhow::ensure!(
        conn.read(&mut byte).await? == 0,
        "fs_sync omitted terminal EOF"
    );
    Ok(())
}
/// A connection-scoped freeze; cancellation or Drop closes the connection.
pub struct Frozen {
    conn: Box<dyn Conn>,
    pub filesystems: Vec<String>,
}
#[derive(Debug, thiserror::Error)]
#[error("freeze_expired")]
pub struct FreezeExpired;

impl Frozen {
    pub async fn thaw(mut self) -> Result<Response> {
        tokio::time::timeout(CONTROL_TIMEOUT, async {
            // The deadline terminal can already be buffered when the peer closes.
            // Even if the write sees EPIPE, read it before classifying the freeze.
            let sent = write_request(
                &mut self.conn,
                &Request {
                    op: "fs_thaw".into(),
                    ..Default::default()
                },
            )
            .await;
            let answer: Response = match read_frame(&mut self.conn).await {
                Ok(answer) => answer,
                Err(error) => {
                    sent?;
                    return Err(error);
                }
            };
            if answer.thawed_by == "deadline" {
                return Err(FreezeExpired.into());
            }
            sent?;
            check_fs_answer("fs_thaw", &answer)?;
            anyhow::ensure!(
                answer.thawed_by == "host",
                "fs_thaw omitted host acknowledgment"
            );
            Ok(answer)
        })
        .await
        .context("guest fs_thaw timeout")?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    /// A stand-in for Firecracker's vsock socket with the init behind it: answers the
    /// `CONNECT` line with `handshake`, reads one request frame, writes `answers` as they
    /// are, closes, and hands the request back. Within 10 s: a client that never sends what
    /// it waits on fails its test, the socket closed.
    fn serve(
        uds: &Path,
        handshake: &'static str,
        answers: Vec<Vec<u8>>,
    ) -> tokio::task::JoinHandle<Request> {
        let ln = UnixListener::bind(uds).unwrap();
        let serve = async move {
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
        };
        tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(10), serve)
                .await
                .expect("the stand-in waited 10 s")
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
    async fn filesystem_controls_preserve_the_op_on_the_real_wire() {
        for answer in [Response::new("ok"), Response::error("unknown op fs_sync")] {
            let (_dir, path) = socket();
            let server = serve(&path, OK, vec![frame(&answer)]);
            let result = Vsock.fs_sync(&path).await;
            assert_eq!(server.await.unwrap().op, "fs_sync");
            if answer.kind == "ok" {
                result.unwrap();
            } else {
                assert!(result.unwrap_err().is::<UnknownOp>());
            }
        }
        let (_dir, path) = socket();
        let server = serve(
            &path,
            OK,
            vec![frame(&Response {
                frozen: vec!["/".into()],
                ..Response::new("ok")
            })],
        );
        let frozen = Vsock
            .fs_freeze(&path, Duration::from_secs(21))
            .await
            .unwrap();
        let request = server.await.unwrap();
        assert_eq!(request.op, "fs_freeze");
        assert_eq!(request.timeout_ms, 21_000);
        assert_eq!(frozen.filesystems, ["/"]);
    }

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

        assert!(err.is::<Unreachable>());

        let missing = path.with_file_name("none.sock");
        let err = dial(&missing).await.unwrap_err();
        assert!(
            format!("{err:#}").contains(&format!("vsock {}", missing.display())),
            "{err:#}"
        );
        assert!(err.is::<Unreachable>());
        // A socket nobody listens on any more: a Firecracker exiting.
        let gone = path.with_file_name("gone.sock");
        drop(UnixListener::bind(&gone).unwrap());
        let err = dial(&gone).await.unwrap_err();
        assert!(err.to_string().contains("Connection refused"), "{err}");
        assert!(err.is::<Unreachable>());
    }

    #[tokio::test]
    async fn dial_retries_a_reset_handshake_and_gives_up_as_unreachable() {
        // A Firecracker that resets the first two handshakes (it closes with the CONNECT
        // line's tail unread, which a stream socket reports to the peer as a reset), then
        // answers.
        let (_dir, path) = socket();
        let ln = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut s, _) = ln.accept().await.unwrap();
                let mut one = [0u8; 1];
                s.read_exact(&mut one).await.unwrap();
                drop(s);
            }
            let (s, _) = ln.accept().await.unwrap();
            let mut r = BufReader::new(s);
            let mut line = String::new();
            r.read_line(&mut line).await.unwrap();
            r.get_mut().write_all(OK.as_bytes()).await.unwrap();
            r
        });
        let attempts = tokio::time::timeout(Duration::from_secs(10), dial(&path)).await;
        let dialed = attempts.expect("dial hung");
        if cfg!(target_os = "linux") {
            dialed.expect("the third handshake answers");
            server.await.unwrap();
        } else {
            // Other kernels report the hang-up as an end of stream instead of a reset.
            let _ = dialed;
            server.abort();
        }
    }

    #[test]
    fn only_a_reset_is_retried() {
        use std::io::{Error, ErrorKind::*};
        for k in [ConnectionReset, ConnectionAborted, BrokenPipe] {
            assert!(is_reset(&Error::from(k)));
        }
        for k in [ConnectionRefused, NotFound, UnexpectedEof, TimedOut] {
            assert!(!is_reset(&Error::from(k)));
        }
    }

    #[tokio::test]
    async fn a_reset_after_the_request_is_closed_and_the_request_is_not_sent_again() {
        // The stand-in answers the handshake, reads the request, then closes with the rest of
        // what the client wrote unread (a reset on Linux, an end of stream elsewhere): either
        // way a closed connection, and the listener sees exactly one connection.
        let (_dir, path) = socket();
        let ln = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let mut accepted = 0;
            let (s, _) = ln.accept().await.unwrap();
            accepted += 1;
            let mut r = BufReader::new(s);
            let mut line = String::new();
            r.read_line(&mut line).await.unwrap();
            r.get_mut().write_all(OK.as_bytes()).await.unwrap();
            let mut one = [0u8; 1];
            r.read_exact(&mut one).await.unwrap();
            drop(r);
            // A second connection would be a second run of the command.
            let more = tokio::time::timeout(Duration::from_millis(1500), ln.accept()).await;
            assert!(more.is_err(), "the request was sent again");
            accepted
        });
        let req = Request {
            cmd: vec!["true".into()],
            ..Default::default()
        };
        let mut s = session(&path, req).await.unwrap();
        let err = collect(&mut s).await.unwrap_err();
        assert!(err.is::<Closed>(), "{err:#}");
        assert_eq!(server.await.unwrap(), 1);
    }

    #[test]
    fn a_reset_after_the_write_is_closed() {
        assert!(
            after_write(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)).is::<Closed>()
        );
        use std::io::{Error, ErrorKind::*};
        for k in [ConnectionReset, ConnectionAborted, BrokenPipe] {
            assert!(after_write(Error::from(k)).is::<Closed>());
        }
        assert!(!after_write(Error::from(PermissionDenied)).is::<Closed>());
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

    #[test]
    fn polling_is_fast_while_a_guest_boots_and_slow_when_it_is_silent() {
        assert_eq!(poll_interval(Duration::ZERO), FAST_POLL);
        assert_eq!(poll_interval(Duration::from_millis(900)), FAST_POLL);
        assert_eq!(poll_interval(FAST_POLL_FOR), SLOW_POLL);
        assert_eq!(poll_interval(Duration::from_secs(60)), SLOW_POLL);
        assert!(FAST_POLL <= Duration::from_millis(5));
    }

    /// Answers connection after connection as scripted: `None` hangs up at once, as a
    /// guest with nobody listening does; `Some(handshake)` answers the `CONNECT` line and,
    /// when it is `OK`, the ping with a pong. Returns how many connections it served.
    fn serve_script(
        uds: &Path,
        script: Vec<Option<&'static str>>,
        version: &'static str,
    ) -> tokio::task::JoinHandle<usize> {
        let ln = UnixListener::bind(uds).unwrap();
        tokio::spawn(async move {
            let n = script.len();
            for step in script {
                let (s, _) = ln.accept().await.unwrap();
                let Some(handshake) = step else { continue };
                let mut r = BufReader::new(s);
                let mut line = String::new();
                r.read_line(&mut line).await.unwrap();
                let mut s = r.into_inner();
                s.write_all(handshake.as_bytes()).await.unwrap();
                if handshake == OK {
                    let mut hdr = [0u8; 4];
                    s.read_exact(&mut hdr).await.unwrap();
                    let mut body = vec![0u8; u32::from_be_bytes(hdr) as usize];
                    s.read_exact(&mut body).await.unwrap();
                    let pong = Response {
                        kind: "pong".into(),
                        version: version.into(),
                        ..Default::default()
                    };
                    s.write_all(&frame(&pong)).await.unwrap();
                }
            }
            n
        })
    }

    #[tokio::test]
    async fn wait_ready_notices_a_guest_that_comes_up_late_without_a_polling_delay() {
        let (_dir, path) = socket();
        let late = path.clone();
        // Nothing listens for 300 ms, as before the VMM has made its socket.
        let server = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            serve_script(&late, vec![Some(OK)], "0.1.0+late")
                .await
                .unwrap()
        });
        let t0 = std::time::Instant::now();
        let version = wait_ready(&path, Duration::from_secs(5)).await.unwrap();
        let took = t0.elapsed();
        assert_eq!(version, "0.1.0+late");
        assert!(took >= Duration::from_millis(300), "{took:?}");
        // Generous for a loaded runner; a 100 ms sleep alone could not pass this bound
        // together with the startup of the stand-in.
        assert!(took < Duration::from_millis(1500), "{took:?}");
        assert_eq!(server.await.unwrap(), 1);
    }

    #[tokio::test]
    async fn wait_ready_goes_on_through_refusals_and_a_guest_that_restarts() {
        let (_dir, path) = socket();
        // The init restarts under it: a hang-up mid-handshake, a refusal, then the pong.
        let server = serve_script(
            &path,
            vec![None, Some("REFUSED\n"), None, Some(OK)],
            "0.1.0+again",
        );
        let version = wait_ready(&path, Duration::from_secs(5)).await.unwrap();
        assert_eq!(version, "0.1.0+again");
        assert_eq!(server.await.unwrap(), 4);
    }

    #[tokio::test]
    async fn a_guest_that_never_answers_ends_at_the_timeout_with_its_last_error() {
        let (_dir, path) = socket();
        let _server = serve_script(&path, vec![Some("REFUSED vsock\n"); 1_000], "");
        let t0 = std::time::Instant::now();
        let err = wait_ready(&path, Duration::from_millis(300))
            .await
            .unwrap_err();
        assert!(t0.elapsed() >= Duration::from_millis(300));
        assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
        let msg = err.to_string();
        assert!(
            msg.starts_with("guest init did not answer within 300ms"),
            "{msg}"
        );
        assert!(
            msg.contains("vsock connect refused: REFUSED vsock"),
            "{msg}"
        );
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
    #[tokio::test]
    async fn streaming_file_handshake_keeps_raw_bytes_and_reports_old_inits() {
        let (_dir, path) = socket();
        let server = serve(
            &path,
            OK,
            vec![
                frame(&Response {
                    kind: "ready".into(),
                    size: Some(4),
                    ..Default::default()
                }),
                b"raw\0".to_vec(),
            ],
        );
        let (mut conn, size) = Vsock
            .file_stream(
                &path,
                Request {
                    op: "get_stream".into(),
                    path: "/file".into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(size, Some(4));
        let mut bytes = Vec::new();
        conn.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"raw\0");
        assert_eq!(server.await.unwrap().op, "get_stream");
        let (_dir, path) = socket();
        let server = serve(
            &path,
            OK,
            vec![frame(&Response::error("unknown op put_stream"))],
        );
        let err = Vsock
            .file_stream(
                &path,
                Request {
                    op: "put_stream".into(),
                    ..Default::default()
                },
            )
            .await
            .err()
            .unwrap();
        assert!(err.is::<UnknownOp>());
        server.await.unwrap();
    }
    #[tokio::test]
    async fn a_guests_file_transfer_limit_is_a_typed_refusal() {
        let (_dir, path) = socket();
        let server = serve(
            &path,
            OK,
            vec![frame(&Response::error("too many file transfers"))],
        );
        let err = Vsock
            .file_stream(
                &path,
                Request {
                    op: "get_stream".into(),
                    ..Default::default()
                },
            )
            .await
            .err()
            .unwrap();
        assert!(err.is::<FileTransferBusy>());
        server.await.unwrap();
    }
}

#[cfg(test)]
mod filesystem_tests {
    use super::*;
    #[tokio::test]
    async fn sync_requires_eof_and_preserves_old_init_unknown_op() {
        for kind in ["ok", "unknown", "error"] {
            let (client, mut server) = tokio::io::duplex(4096);
            let answer = match kind {
                "ok" => Response::new("ok"),
                "unknown" => Response::error("unknown op fs_sync"),
                _ => Response::error("disk failed"),
            };
            server
                .write_all(&guest::encode_frame(&answer).unwrap())
                .await
                .unwrap();
            drop(server);
            let result = sync_answer(Box::new(client)).await;
            if kind == "ok" {
                result.unwrap();
            } else if kind == "unknown" {
                assert!(result.unwrap_err().is::<UnknownOp>());
            } else {
                assert!(result.is_err());
            }
        }
        let (client, mut server) = tokio::io::duplex(4096);
        server
            .write_all(&guest::encode_frame(&Response::new("ok")).unwrap())
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), sync_answer(Box::new(client)))
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn deadline_terminal_survives_a_broken_pipe_on_thaw() {
        let (client, mut server) = tokio::io::duplex(4096);
        server
            .write_all(
                &guest::encode_frame(&Response {
                    thawed_by: "deadline".into(),
                    ..Response::error("freeze expired")
                })
                .unwrap(),
            )
            .await
            .unwrap();
        drop(server); // The next write is EPIPE, but the terminal is buffered.
        let error = Frozen {
            conn: Box::new(client),
            filesystems: vec![],
        }
        .thaw()
        .await
        .unwrap_err();
        assert!(error.is::<FreezeExpired>(), "{error:#}");
    }

    #[tokio::test]
    async fn thaw_deadline_is_an_error_and_drop_closes() {
        let (client, mut server) = tokio::io::duplex(4096);
        let host = tokio::spawn(async move {
            let request: Request = read_frame(&mut server).await.unwrap();
            assert_eq!(request.op, "fs_thaw");
            server
                .write_all(
                    &guest::encode_frame(&Response {
                        thawed_by: "deadline".into(),
                        ..Response::error("freeze expired")
                    })
                    .unwrap(),
                )
                .await
                .unwrap();
        });
        assert!(Frozen {
            conn: Box::new(client),
            filesystems: vec!["/".into()]
        }
        .thaw()
        .await
        .is_err());
        host.await.unwrap();
        let (client, mut server) = tokio::io::duplex(4096);
        drop(Frozen {
            conn: Box::new(client),
            filesystems: vec![],
        });
        assert_eq!(server.read(&mut [0]).await.unwrap(), 0);
    }
}
