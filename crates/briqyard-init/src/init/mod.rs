//! The init proper: boot the guest from the config drive, run the image's command, serve the
//! host over vsock, halt when the command ends.

use anyhow::{anyhow, Context, Result};
use briqyard_api::guest::{self, Config, ExitReport, Request, Response};
use nix::mount::{mount, MsFlags};
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitid, waitpid, Id, WaitPidFlag};
use nix::unistd::Pid;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::Notify;
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY, VMADDR_CID_HOST};

const CONFIG_DEVICE: &str = "/dev/vdb";

static CONSOLE: OnceLock<Mutex<fs::File>> = OnceLock::new();

/// One console line: the daemon reads the `[briqyard] ` prefix.
fn console_line(args: std::fmt::Arguments) -> String {
    format!("[briqyard] {args}\n")
}

fn logf(args: std::fmt::Arguments) {
    let line = console_line(args);
    match CONSOLE.get() {
        Some(c) => {
            let _ = c.lock().unwrap().write_all(line.as_bytes());
        }
        None => {
            let _ = std::io::stderr().write_all(line.as_bytes());
        }
    }
}

macro_rules! log {
    ($($arg:tt)*) => { logf(format_args!($($arg)*)) };
}

struct State {
    cfg: Config,
    env: Vec<(String, String)>,
    main_pid: Mutex<Option<i32>>,
    main_done: Notify,
    requested: Mutex<bool>,
}

mod boot;
mod exec;
mod files;
mod network;
mod pty;
mod reap;
mod serve;
#[cfg(all(test, target_os = "linux"))]
mod testutil;
mod user;

use boot::*;
use exec::*;
use network::*;
use pty::*;
use reap::*;
use serve::*;
use user::*;

pub fn main() {
    if std::process::id() != 1 {
        eprintln!("briqyard-init must run as PID 1");
        std::process::exit(2);
    }
    mount_base();
    if let Ok(f) = fs::OpenOptions::new().write(true).open("/dev/console") {
        let _ = CONSOLE.set(Mutex::new(f));
    }
    std::thread::spawn(reap_orphans);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let report = ExitReport {
        version: briqyard_api::VERSION.into(),
        ..rt.block_on(run())
    };
    log!("{}", exit_line(&report));
    rt.block_on(report_exit(&report));
    halt();
}

/// The console's trace of the exit; what counts is the report sent to the host.
fn exit_line(r: &ExitReport) -> String {
    format!(
        "exit code={} oom={} requested={}",
        r.code, r.oom, r.requested
    )
}

/// Tells the host how the main process ended: one connection out on [`guest::EXIT_PORT`],
/// one frame, then the host's close, so the frame is on the host before the reset. Bounded:
/// a host that does not listen never holds the reset.
async fn report_exit(r: &ExitReport) {
    let connect = VsockStream::connect(VsockAddr::new(VMADDR_CID_HOST, guest::EXIT_PORT));
    let sent = async {
        let mut s = connect.await?;
        send_exit(&mut s, r).await
    };
    match tokio::time::timeout(Duration::from_secs(2), sent).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => log!("exit report: {e}"),
        Err(_) => log!("exit report: the host did not take it in time"),
    }
}

/// Writes the report, ends the write side, and reads until the host closes.
async fn send_exit<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    r: &ExitReport,
) -> std::io::Result<()> {
    s.write_all(&guest::encode_frame(r)?).await?;
    s.shutdown().await?;
    let mut sink = [0u8; 64];
    while s.read(&mut sink).await? > 0 {}
    Ok(())
}

/// Boots the guest and runs the main process to its end. A failure before the process
/// starts reports as a code of its own, not `started`, with why: 125 the drive or the disks,
/// 126 the command, 127 its program.
async fn run() -> ExitReport {
    let failed = |code: i32, error: String| {
        log!("{error}");
        ExitReport {
            code,
            error,
            ..Default::default()
        }
    };
    let (cfg, files) = match read_config_drive() {
        Ok(v) => v,
        Err(e) => return failed(125, format!("config drive: {e:#}")),
    };
    if let Err(e) = setup_mounts(&cfg) {
        return failed(125, format!("mounts: {e:#}"));
    }
    if let Err(e) = write_files(&files) {
        return failed(125, format!("boot files: {e:#}"));
    }
    setup_names(&cfg);
    if let Err(e) = setup_network(&cfg).await {
        log!("network: {e:#}");
    }
    let env = build_env(&cfg.env);
    let st = Arc::new(State {
        cfg,
        env,
        main_pid: Mutex::new(None),
        main_done: Notify::new(),
        requested: Mutex::new(false),
    });
    let mut cmd = match main_command(&st) {
        Ok(c) => c,
        Err(e) => return failed(126, format!("command: {e:#}")),
    };
    let mut child = {
        let mut tracked = TRACKED.lock().unwrap();
        match cmd.spawn() {
            Ok(c) => {
                tracked.insert(c.id().unwrap_or(0) as i32);
                c
            }
            Err(e) => {
                return failed(127, format!("start {:?}: {e}", cmd.as_std().get_program()));
            }
        }
    };
    let pid = child.id().unwrap_or(0) as i32;
    *st.main_pid.lock().unwrap() = Some(pid);
    // The host's first pong means the main process runs: a guest that fails before it is a
    // failed boot, whichever of the pong and the exit report the host sees first.
    tokio::spawn(serve(st.clone()));
    log!("started pid={pid} {}", argv_string(cmd.as_std()));
    let status = child.wait().await;
    TRACKED.lock().unwrap().remove(pid);
    *st.main_pid.lock().unwrap() = None;
    st.main_done.notify_waiters();
    let code = match status {
        Ok(s) => exit_code(s),
        Err(e) => {
            log!("wait: {e}");
            255
        }
    };
    let requested = *st.requested.lock().unwrap();
    ExitReport {
        code,
        oom: code == 137 && saw_oom(),
        requested,
        started: true,
        ..Default::default()
    }
}

fn argv_string(c: &std::process::Command) -> String {
    let mut s = c.get_program().to_string_lossy().into_owned();
    for a in c.get_args() {
        s.push(' ');
        s.push_str(&a.to_string_lossy());
    }
    s
}

fn exit_code(s: std::process::ExitStatus) -> i32 {
    if let Some(sig) = s.signal() {
        return 128 + sig;
    }
    s.code().unwrap_or(255)
}

// The init is Linux-only and so are its tests: run them in the dev VM
// (`cargo test -p briqyard-init` there). Nothing here needs /dev/kvm, a real mount or PID 1.

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    // --- the console ---

    fn report(code: i32, oom: bool, requested: bool) -> ExitReport {
        ExitReport {
            code,
            oom,
            requested,
            ..Default::default()
        }
    }

    #[test]
    fn exit_line_is_the_console_trace() {
        assert_eq!(
            console_line(format_args!("{}", exit_line(&report(0, false, true)))),
            "[briqyard] exit code=0 oom=false requested=true\n"
        );
        assert_eq!(
            exit_line(&report(137, true, false)),
            "exit code=137 oom=true requested=false"
        );
        assert_eq!(
            console_line(format_args!("started pid={}", 7)),
            "[briqyard] started pid=7\n"
        );
    }

    #[tokio::test]
    async fn exit_report_is_one_frame_then_the_hosts_close() {
        let (mut guest, mut host) = tokio::io::duplex(1024);
        let r = report(7, false, false);
        let mut sent = tokio::spawn(async move { send_exit(&mut guest, &r).await });
        // The host reads one frame and finds the write side ended, then closes.
        let mut hdr = [0u8; 4];
        host.read_exact(&mut hdr).await.unwrap();
        let mut body = vec![0u8; u32::from_be_bytes(hdr) as usize];
        host.read_exact(&mut body).await.unwrap();
        assert_eq!(
            guest::decode_frame::<ExitReport>(&body).unwrap(),
            report(7, false, false)
        );
        assert_eq!(host.read(&mut [0u8; 8]).await.unwrap(), 0);
        // Until then the init is still waiting on the host.
        assert!(tokio::time::timeout(Duration::from_millis(50), &mut sent)
            .await
            .is_err());
        drop(host);
        sent.await.unwrap().unwrap();
    }

    #[test]
    fn exit_codes() {
        use std::process::ExitStatus;
        assert_eq!(exit_code(ExitStatus::from_raw(0)), 0);
        assert_eq!(exit_code(ExitStatus::from_raw(3 << 8)), 3);
        // Killed by a signal: 128 plus its number, as a shell reports it.
        assert_eq!(exit_code(ExitStatus::from_raw(9)), 137);
        assert_eq!(exit_code(ExitStatus::from_raw(15)), 143);
    }

    #[test]
    fn argv_strings() {
        let mut c = std::process::Command::new("/bin/sh");
        c.args(["-c", "echo hi"]);
        assert_eq!(argv_string(&c), "/bin/sh -c echo hi");
        assert_eq!(argv_string(&std::process::Command::new("true")), "true");
    }
}
