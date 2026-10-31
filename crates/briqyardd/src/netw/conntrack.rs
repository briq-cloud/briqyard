//! Address ownership transitions: remove only flows involving the address being reused.

use anyhow::{anyhow, Context, Result};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

const STDERR_LIMIT: usize = 4096;

pub async fn available() -> Result<()> {
    run(&["--version"]).await
}

pub async fn clear(ip: &str) -> Result<()> {
    let _: std::net::Ipv4Addr = ip.parse().context("conntrack address")?;
    for direction in ["--orig-src", "--orig-dst", "--reply-src", "--reply-dst"] {
        run(&["--delete", "--family", "ipv4", direction, ip]).await?;
    }
    Ok(())
}

struct Diagnostic {
    bytes: Vec<u8>,
    truncated: bool,
}

/// Drain the pipe so verbose deletion cannot stall; retain only a bounded diagnostic prefix.
async fn diagnostic(mut reader: impl AsyncRead + Unpin) -> std::io::Result<Diagnostic> {
    let mut result = Diagnostic {
        bytes: Vec::new(),
        truncated: false,
    };
    let mut chunk = [0u8; 4096];
    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            return Ok(result);
        }
        let retained = n.min(STDERR_LIMIT - result.bytes.len());
        result.bytes.extend_from_slice(&chunk[..retained]);
        result.truncated |= retained < n;
    }
}

fn deleted_nothing(status: ExitStatus, diagnostic: &Diagnostic) -> bool {
    if status.code() != Some(1) || diagnostic.truncated {
        return false;
    }
    let text = String::from_utf8_lossy(&diagnostic.bytes);
    let line = text.strip_suffix('\n').unwrap_or(&text);
    let Some((version, summary)) = line
        .strip_prefix("conntrack v")
        .and_then(|text| text.split_once(" (conntrack-tools): "))
    else {
        return false;
    };
    !version.is_empty()
        && version
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|c| c.is_ascii_digit()))
        && summary == "0 flow entries have been deleted."
}

async fn run(args: &[&str]) -> Result<()> {
    let mut cmd = Command::new("conntrack");
    cmd.args(args).env("LC_ALL", "C");
    execute(cmd, Duration::from_secs(10)).await
}

async fn execute(mut cmd: Command, deadline: Duration) -> Result<()> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("run conntrack")?;
    let stderr = child.stderr.take().expect("piped stderr");
    let outcome = tokio::time::timeout(deadline, async {
        tokio::try_join!(child.wait(), diagnostic(stderr))
    })
    .await;
    let (status, diagnostic) = match outcome {
        Ok(Ok(output)) => output,
        failed => {
            // Timeout/read errors do not leave a command running behind the network lock.
            let _ = child.start_kill();
            child.wait().await.context("reap conntrack")?;
            return match failed {
                Err(_) => Err(anyhow!("conntrack deadline exceeded")),
                Ok(Err(error)) => Err(error).context("read conntrack diagnostic"),
                Ok(Ok(_)) => unreachable!(),
            };
        }
    };
    if !status.success() && !deleted_nothing(status, &diagnostic) {
        return Err(anyhow!(
            "conntrack: {}{}",
            String::from_utf8_lossy(&diagnostic.bytes).trim(),
            if diagnostic.truncated {
                " [stderr truncated]"
            } else {
                ""
            }
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
