//! Address ownership transitions: remove only flows involving the address being reused.

use anyhow::{anyhow, Context, Result};
use std::process::{Output, Stdio};
use std::time::Duration;
use tokio::process::Command;

pub async fn available() -> Result<()> {
    run(&["--version"]).await.map(|_| ())
}

pub async fn clear(ip: &str) -> Result<()> {
    let _: std::net::Ipv4Addr = ip.parse().context("conntrack address")?;
    for direction in ["--orig-src", "--orig-dst", "--reply-src", "--reply-dst"] {
        run(&["--delete", "--family", "ipv4", direction, ip]).await?;
    }
    Ok(())
}

fn deleted_nothing(output: &Output) -> bool {
    let error = String::from_utf8_lossy(&output.stderr);
    output.status.code() == Some(1)
        && error.lines().count() == 1
        && error
            .trim_end()
            .ends_with(": 0 flow entries have been deleted.")
}

async fn run(args: &[&str]) -> Result<Output> {
    let mut cmd = Command::new("conntrack");
    cmd.args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(10), cmd.output())
        .await
        .context("conntrack deadline")?
        .context("run conntrack")?;
    if !output.status.success() && !deleted_nothing(&output) {
        return Err(anyhow!(
            "conntrack: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    #[test]
    fn an_empty_delete_does_not_hide_a_permission_or_protocol_failure() {
        let output = |code, message: &str| Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: vec![],
            stderr: message.as_bytes().to_vec(),
        };
        assert!(deleted_nothing(&output(
            1,
            "conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.\n"
        )));
        assert!(!deleted_nothing(&output(
            1,
            "Operation failed: permission denied\n"
        )));
        assert!(!deleted_nothing(&output(1, "Operation failed\nconntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.\n")));
        assert!(!deleted_nothing(&output(
            2,
            "conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.\n"
        )));
    }
}
