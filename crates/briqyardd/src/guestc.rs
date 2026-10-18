//! The host's side of the guest protocol: one connection per operation through Firecracker's
//! vsock Unix socket.

use anyhow::{anyhow, Context, Result};
use briqyard_api::guest::{self, Request, Response};
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

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

async fn write_request(s: &mut UnixStream, req: &Request) -> Result<()> {
    s.write_all(&guest::encode_frame(req)?).await?;
    s.flush().await?;
    Ok(())
}

async fn read_response(s: &mut UnixStream) -> Result<Response> {
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

pub async fn exec(uds: &Path, mut req: Request) -> Result<ExecOutput> {
    req.op = "exec".into();
    let mut s = dial(uds).await?;
    write_request(&mut s, &req).await?;
    let mut out = ExecOutput {
        stdout: Vec::new(),
        stderr: Vec::new(),
        code: 0,
        timed_out: false,
    };
    loop {
        let r = match read_response(&mut s).await {
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
            "error" => return Err(anyhow!("{}", r.message)),
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
    let r = read_response(&mut s).await?;
    if r.kind == "error" {
        return Err(anyhow!("{}", r.message));
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

/// Polls `ping` until the init answers or the timeout passes.
pub async fn wait_ready(uds: &Path, timeout: Duration) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let last = match tokio::time::timeout(Duration::from_secs(2), ping(uds)).await {
            Ok(Ok(_)) => return Ok(()),
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
