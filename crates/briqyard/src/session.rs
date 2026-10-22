//! `machine exec -i` and `-t` (ADR 0029): an exec session over a WebSocket. With `-t` the
//! local terminal is in raw mode while it lasts, its size follows the window, and every key
//! (Ctrl-C included) goes to the command; the remote exit code is the CLI's.

use super::Client;
use anyhow::{anyhow, bail, Context, Result};
use briqyard_api::session::{self as wire, channel, ExecSession, Resize, SessionEnd};
use futures::{SinkExt, StreamExt};
use reqwest::header;
use std::io::{IsTerminal, Read, Write};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

/// What the local side gives a session.
#[derive(Debug)]
pub enum Local {
    Stdin(Vec<u8>),
    /// Stdin ended (a pipe ran out).
    EndOfInput,
    Resize(Resize),
    /// The CLI was asked to stop (a signal): it leaves with this code.
    Stop(i32),
}

/// Runs a session to its end and answers the command's exit code. `interactive` sends stdin.
pub async fn run(c: &Client, id: &str, mut req: ExecSession, interactive: bool) -> Result<i32> {
    if req.tty && !std::io::stdin().is_terminal() {
        bail!("-t needs a terminal on stdin; -i alone streams a pipe");
    }
    if req.tty {
        let size = window();
        (req.cols, req.rows) = (size.cols, size.rows);
        if let (false, Ok(term)) = (req.env.contains_key("TERM"), std::env::var("TERM")) {
            req.env.insert("TERM".into(), term);
        }
    }
    let ws = connect(c, id, &req).await?;
    let (tx, rx) = mpsc::channel(16);
    if interactive {
        read_stdin(tx.clone());
    }
    watch_signals(tx, req.tty)?;
    // Raw only once connected: a refusal prints as any error does. Restored on every way out
    // of here, an error included.
    let _raw = match req.tty {
        true => Some(Raw::enter()?),
        false => None,
    };
    drive(ws, rx, &mut std::io::stdout(), &mut std::io::stderr()).await
}

/// The upgrade: the session's query, the bearer token, a handshake checked as RFC 6455 says.
/// Through reqwest, so a pinned certificate and the token go as for every other call.
pub async fn connect(
    c: &Client,
    id: &str,
    req: &ExecSession,
) -> Result<WebSocketStream<reqwest::Upgraded>> {
    let key = generate_key();
    let mut r = c
        .http
        .get(format!("{}/v1/machines/{id}/exec", c.base))
        .query(&req.to_query())
        .header(header::CONNECTION, "Upgrade")
        .header(header::UPGRADE, "websocket")
        .header(header::SEC_WEBSOCKET_VERSION, "13")
        .header(header::SEC_WEBSOCKET_KEY, &key);
    if let Some(t) = &c.token {
        r = r.bearer_auth(t);
    }
    let resp = r
        .send()
        .await
        .with_context(|| format!("request {}", c.base))?;
    if resp.status() != reqwest::StatusCode::SWITCHING_PROTOCOLS {
        return Err(super::refusal(resp).await);
    }
    let accepted = resp
        .headers()
        .get(header::SEC_WEBSOCKET_ACCEPT)
        .and_then(|v| v.to_str().ok());
    if accepted != Some(derive_accept_key(key.as_bytes()).as_str()) {
        bail!("{} answered 101 without accepting the session", c.base);
    }
    let io = resp.upgrade().await.context("the session's upgrade")?;
    Ok(WebSocketStream::from_raw_socket(io, Role::Client, None).await)
}

/// Carries the session: local input out, the command's output to `out` and `err`, until its
/// exit (its code) or a stop asked locally.
pub async fn drive<S>(
    mut ws: WebSocketStream<S>,
    mut local: mpsc::Receiver<Local>,
    out: &mut impl Write,
    err: &mut impl Write,
) -> Result<i32>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            m = ws.next() => {
                let b = match m {
                    Some(Ok(Message::Binary(b))) => b,
                    // Pings are answered by the library as it reads.
                    Some(Ok(Message::Close(_))) | None => bail!("the session closed before the command ended"),
                    Some(Err(e)) => return Err(anyhow!("the session: {e}")),
                    Some(Ok(_)) => continue,
                };
                match wire::parse(&b) {
                    Some((channel::STDOUT, p)) => {
                        out.write_all(p)?;
                        out.flush()?;
                    }
                    Some((channel::STDERR, p)) => {
                        err.write_all(p)?;
                        err.flush()?;
                    }
                    Some((channel::EXIT, p)) => return ended(serde_json::from_slice(p)?, err),
                    _ => {}
                }
            }
            Some(l) = local.recv() => {
                let m = match l {
                    Local::Stdin(d) => wire::message(channel::STDIN, &d),
                    Local::EndOfInput => wire::message(channel::CLOSE, &[channel::STDIN]),
                    Local::Resize(r) => wire::message(channel::RESIZE, &serde_json::to_vec(&r)?),
                    Local::Stop(code) => {
                        // The command ends with its session.
                        let _ = ws.close(None).await;
                        return Ok(code);
                    }
                };
                // The command may have ended under this input: its end is still to be read.
                if ws.send(Message::Binary(m)).await.is_err() {
                    local.close();
                }
            }
        }
    }
}

/// The exit code of a session's end, or the error it ended with.
fn ended(end: SessionEnd, err: &mut impl Write) -> Result<i32> {
    let Some(code) = end.exit_code.filter(|_| end.code.is_empty()) else {
        bail!("{} ({})", end.error, end.code);
    };
    if end.timed_out {
        let _ = writeln!(err, "(timed out)");
    }
    Ok(code)
}

/// Stdin in chunks as it comes, then its end; on a thread, since a read of it blocks.
fn read_stdin(tx: mpsc::Sender<Local>) {
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 32 << 10];
        let mut stdin = std::io::stdin().lock();
        loop {
            let m = match stdin.read(&mut buf) {
                Ok(0) | Err(_) => Local::EndOfInput,
                Ok(n) => Local::Stdin(buf[..n].to_vec()),
            };
            let end = matches!(m, Local::EndOfInput);
            if tx.blocking_send(m).is_err() || end {
                return;
            }
        }
    });
}

/// SIGWINCH (with a terminal) sends the new size; SIGINT, SIGTERM and SIGHUP stop the
/// session with 128 plus the signal, as a shell reports it.
fn watch_signals(tx: mpsc::Sender<Local>, tty: bool) -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut winch = signal(SignalKind::window_change())?;
    let mut int = signal(SignalKind::interrupt())?;
    let mut term = signal(SignalKind::terminate())?;
    let mut hup = signal(SignalKind::hangup())?;
    tokio::spawn(async move {
        loop {
            let m = tokio::select! {
                _ = winch.recv(), if tty => Local::Resize(window()),
                _ = int.recv() => Local::Stop(128 + libc::SIGINT),
                _ = term.recv() => Local::Stop(128 + libc::SIGTERM),
                _ = hup.recv() => Local::Stop(128 + libc::SIGHUP),
            };
            if tx.send(m).await.is_err() {
                return;
            }
        }
    });
    Ok(())
}

/// The local terminal's size; 0 by 0 (the remote's default) when it has none.
fn window() -> Resize {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) } < 0 {
        return Resize::default();
    }
    Resize {
        cols: ws.ws_col,
        rows: ws.ws_row,
    }
}

/// The local terminal in raw mode until dropped: bytes as typed, no echo, no signals from
/// keys, no output translation (the remote terminal does its own).
struct Raw(libc::termios);

impl Raw {
    fn enter() -> Result<Self> {
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut t) } != 0 {
            return Err(std::io::Error::last_os_error()).context("read the terminal's mode");
        }
        let saved = t;
        unsafe { libc::cfmakeraw(&mut t) };
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &t) } != 0 {
            return Err(std::io::Error::last_os_error()).context("set the terminal raw");
        }
        Ok(Raw(saved))
    }
}

impl Drop for Raw {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.0) };
    }
}
