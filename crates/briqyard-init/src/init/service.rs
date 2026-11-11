//! The `service-ready-v1` profile (ADR 0127): a running service is parked, sealed in a memory
//! template, and resumed in each clone.
//!
//! The workload runs in its own cgroup so it can be frozen as a whole. Park runs the
//! application's hook, refuses while any non-loopback TCP connection is established, freezes
//! the workload, and takes the identity out of the guest. Resume runs in a clone, after the
//! identity is configured and with the workload still frozen; the workload thaws only when
//! the hook exits 0.
use super::*;
use guest::{CloneHooks, CLONE_HOOK_FAILED};

const CGROUP: &str = "/sys/fs/cgroup/briqyard-workload";
/// The most of a hook's stderr reported back.
const TAIL: usize = 4096;
/// The freezer settles within this or the park fails.
const FREEZE_TIMEOUT: Duration = Duration::from_secs(10);
/// A killed hook's group is gone within this, or the scan decides.
const GROUP_GONE_TIMEOUT: Duration = Duration::from_secs(1);
/// Executions admitted before the park settle (spawn) within this, or the park is refused.
const ADMISSION_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) fn prepare_cgroup() -> Result<()> {
    fs::create_dir_all(CGROUP).context("workload cgroup")?;
    anyhow::ensure!(
        Path::new(CGROUP).join("cgroup.freeze").exists(),
        "the guest kernel has no cgroup freezer"
    );
    Ok(())
}

/// The workload and all it forks start inside the cgroup.
pub(super) fn join_cgroup(cmd: &mut Command) {
    let procs = std::ffi::CString::new(format!("{CGROUP}/cgroup.procs")).expect("no NUL");
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            let fd = libc::open(procs.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let n = libc::write(fd, b"0".as_ptr().cast(), 1);
            let err = std::io::Error::last_os_error();
            libc::close(fd);
            if n != 1 {
                return Err(err);
            }
            Ok(())
        });
    }
}

fn set_frozen(frozen: bool) -> Result<()> {
    fs::write(
        Path::new(CGROUP).join("cgroup.freeze"),
        if frozen { b"1" } else { b"0" },
    )
    .context("cgroup.freeze")
}

/// Waits for the freezer to report the state it was asked for.
async fn wait_frozen(frozen: bool) -> Result<()> {
    let want = format!("frozen {}", u8::from(frozen));
    let deadline = tokio::time::Instant::now() + FREEZE_TIMEOUT;
    loop {
        let events = fs::read_to_string(Path::new(CGROUP).join("cgroup.events"))?;
        if events.lines().any(|l| l == want) {
            return Ok(());
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "workload cgroup did not reach `{want}`"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// The established TCP connections of `/proc/net/tcp` or `tcp6` text with a non-loopback end.
pub(super) fn established_external(table: &str, v6: bool) -> Vec<String> {
    let addr = |hex: &str| -> Option<std::net::IpAddr> {
        let (ip, _) = hex.split_once(':')?;
        let bytes = (0..ip.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(ip.get(i..i + 2)?, 16).ok())
            .collect::<Option<Vec<u8>>>()?;
        // The kernel prints each 32-bit word in host (little-endian) order.
        let words: Vec<u8> = bytes
            .chunks(4)
            .flat_map(|w| w.iter().rev().copied().collect::<Vec<_>>())
            .collect();
        match (v6, words.len()) {
            (false, 4) => Some(std::net::Ipv4Addr::from(<[u8; 4]>::try_from(words).ok()?).into()),
            (true, 16) => {
                let v = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(words).ok()?);
                Some(v.to_ipv4_mapped().map_or(v.into(), Into::into))
            }
            _ => None,
        }
    };
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            (f.get(3) == Some(&"01")).then_some((*f.get(1)?, *f.get(2)?))
        })
        .filter(|(local, remote)| {
            // An unparsable address counts as external: refuse rather than guess.
            let external = |a: &str| addr(a).is_none_or(|ip| !ip.is_loopback());
            external(local) || external(remote)
        })
        .map(|(local, remote)| format!("{local}->{remote}"))
        .collect()
}

/// Why `/proc/<pid>` is outside the workload, or `None` when it is init, a kernel thread, a
/// zombie, or inside the workload cgroup.
pub(super) fn outside_workload(pid: i32, status: &str, cgroup: &str) -> Option<String> {
    let field = |key: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .map(str::trim)
    };
    let name = field("Name:").unwrap_or("?");
    // A status that cannot be read counts as foreign: refuse rather than guess.
    let Some(ppid) = field("PPid:").and_then(|v| v.parse::<i32>().ok()) else {
        return Some(format!("{name}[{pid}]"));
    };
    if pid == 1 || pid == 2 || ppid == 2 || ppid == 0 {
        return None;
    }
    if field("State:").is_some_and(|s| s.starts_with('Z')) {
        return None;
    }
    let inside = cgroup.lines().any(|l| {
        l.rsplit(':').next().is_some_and(|p| {
            let p = p.trim_start_matches('/');
            p == "briqyard-workload" || p.starts_with("briqyard-workload/")
        })
    });
    (!inside).then(|| format!("{name}[{pid}]"))
}

fn foreign_processes() -> Result<Vec<String>> {
    let mut found = vec![];
    for entry in fs::read_dir("/proc").context("/proc")?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<i32>().ok())
        else {
            continue;
        };
        // A process that exits during the scan is gone, not foreign.
        let (Ok(status), Ok(cgroup)) = (
            fs::read_to_string(entry.path().join("status")),
            fs::read_to_string(entry.path().join("cgroup")),
        ) else {
            continue;
        };
        found.extend(outside_workload(pid, &status, &cgroup));
    }
    Ok(found)
}

fn external_connections() -> Result<Vec<String>> {
    let mut found = vec![];
    for (path, v6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        match fs::read_to_string(path) {
            Ok(table) => found.extend(established_external(&table, v6)),
            Err(e) if v6 && e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| path.to_string()),
        }
    }
    Ok(found)
}

#[derive(Debug)]
pub(super) struct HookFailure(String);

impl std::fmt::Display for HookFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn tail_of(bytes: &[u8]) -> String {
    let start = bytes.len().saturating_sub(TAIL);
    String::from_utf8_lossy(&bytes[start..])
        .trim_end()
        .to_string()
}

/// Waits (at most `GROUP_GONE_TIMEOUT`) until no process is left in group `pgid`.
async fn wait_group_gone(pgid: i32) {
    let deadline = tokio::time::Instant::now() + GROUP_GONE_TIMEOUT;
    while kill(Pid::from_raw(-pgid), None) != Err(nix::errno::Errno::ESRCH)
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Runs one hook as the workload's user, in its environment, to its end or its timeout.
pub(super) async fn run_hook(
    st: &State,
    name: &str,
    argv: &[String],
    timeout_s: u32,
) -> Result<(), HookFailure> {
    let fail = |why: String| HookFailure(format!("{name} hook {why}"));
    let mut cmd =
        workload_command(st, argv).map_err(|e| fail(format!("could not start: {e:#}")))?;
    cmd.stderr(Stdio::piped());
    let mut child = {
        let mut tracked = TRACKED.lock().unwrap();
        let child = cmd
            .spawn()
            .map_err(|e| fail(format!("could not start: {e}")))?;
        tracked.insert(child.id().unwrap_or(0) as i32);
        child
    };
    let pid = child.id().unwrap_or(0) as i32;
    let mut stderr = child.stderr.take();
    let mut tail: Vec<u8> = vec![];
    // The hook ends when it exits, not when its stderr closes: a background child may hold
    // the pipe. Its group is killed then, which closes the pipe, and the rest is drained.
    let outcome = tokio::time::timeout(Duration::from_secs(u64::from(timeout_s)), async {
        let mut chunk = [0u8; 1024];
        let mut open = stderr.is_some();
        // The exit is observed without reaping: the group is killed while its leader still
        // holds the pid, so the pid cannot have been reused.
        let mut exited = tokio::task::spawn_blocking(move || {
            waitid(
                Id::Pid(Pid::from_raw(pid)),
                WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT,
            )
        });
        loop {
            tokio::select! {
                _ = &mut exited => break,
                n = async { stderr.as_mut().unwrap().read(&mut chunk).await }, if open => match n {
                    Ok(n) if n > 0 => {
                        tail.extend_from_slice(&chunk[..n]);
                        if tail.len() > 2 * TAIL {
                            tail.drain(..tail.len() - TAIL);
                        }
                    }
                    _ => open = false,
                },
            }
        }
        let _ = kill(Pid::from_raw(-pid), Signal::SIGKILL);
        let status = child.wait().await;
        if let Some(e) = stderr.as_mut() {
            // A descendant in its own group may still hold the pipe: read what is there.
            let _ = tokio::time::timeout(Duration::from_secs(1), async {
                while let Ok(n) = e.read(&mut chunk).await {
                    if n == 0 {
                        break;
                    }
                    tail.extend_from_slice(&chunk[..n]);
                    if tail.len() > 2 * TAIL {
                        tail.drain(..tail.len() - TAIL);
                    }
                }
            })
            .await;
        }
        status
    })
    .await;
    let result = match outcome {
        Ok(Ok(status)) if status.success() => Ok(()),
        Ok(Ok(status)) => Err(fail(format!(
            "exited {}: {}",
            exit_code(status),
            tail_of(&tail)
        ))),
        Ok(Err(e)) => Err(fail(format!("wait failed: {e}"))),
        Err(_) => {
            // The leader is not reaped yet (the wait above is cancelled), so the pid is ours.
            let _ = kill(Pid::from_raw(-pid), Signal::SIGKILL);
            let _ = child.wait().await;
            Err(fail(format!(
                "timed out after {timeout_s}s: {}",
                tail_of(&tail)
            )))
        }
    };
    // The leader is reaped. Untrack it first: the orphan reaper waits on the tracked set, and
    // until it collects the hook's killed children they stay zombies in the group.
    TRACKED.lock().unwrap().remove(pid);
    // Whatever the hook left running in its process group was killed with it: wait until the
    // group is gone, so a dying child is not taken for a foreign process by the scan.
    wait_group_gone(pid).await;
    result
}

fn hooks(st: &State) -> Result<&CloneHooks> {
    st.cfg
        .clone_hooks
        .as_ref()
        .ok_or_else(|| anyhow!("no clone hooks"))
}

fn refusal(code: &str, message: String) -> Response {
    Response {
        error_code: code.into(),
        ..Response::error(message)
    }
}

/// Refuses after the freeze: the service is thawed and keeps running as it was. If the thaw
/// is not confirmed the workload's state is unknown and the refusal is terminal. An empty
/// `code` is a plain error.
async fn refuse_thawed(code: &str, message: String) -> Response {
    let thawed = match set_frozen(false) {
        Ok(()) => wait_frozen(false).await,
        Err(e) => Err(e),
    };
    match thawed {
        Ok(()) if code.is_empty() => Response::error(message),
        Ok(()) => refusal(code, message),
        Err(e) => refusal(
            guest::PARK_UNRECOVERABLE,
            format!("{message}; the workload could not be thawed: {e:#}"),
        ),
    }
}

/// Waits for the executions the gate admitted to spawn, so the process scan sees them. The
/// gate is held by the caller: no new one is admitted meanwhile.
async fn wait_admitted(st: &State) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + ADMISSION_TIMEOUT;
    while st.admitting.load(std::sync::atomic::Ordering::SeqCst) > 0 {
        if tokio::time::Instant::now() >= deadline {
            return Err("an execution admitted before the park did not start in time".into());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Ok(())
}

/// Runs the park hook, then quiesces. A refusal up to and including the checks thaws the
/// workload: the service keeps running as it was. A failure after them is terminal
/// (`PARK_UNRECOVERABLE`) and the daemon stops the source.
pub(super) async fn park(st: &Arc<State>) -> Response {
    let mut gate = st.clone_gate.lock().await;
    if !matches!(*gate, clone::Gate::Service) {
        return Response::error("service is not running unparked");
    }
    let hooks = match hooks(st) {
        Ok(h) => h,
        Err(e) => return Response::error(format!("{e:#}")),
    };
    if let Err(e) = wait_admitted(st).await {
        return Response::error(e);
    }
    if let Err(e) = run_hook(st, "park", &hooks.park, hooks.park_timeout_s).await {
        return refusal(CLONE_HOOK_FAILED, e.to_string());
    }
    if let Err(e) = set_frozen(true) {
        return Response::error(format!("freeze: {e:#}"));
    }
    if let Err(e) = wait_frozen(true).await {
        return refuse_thawed("", format!("freeze: {e:#}")).await;
    }
    // The tables are read with the workload frozen, so no connection opens or closes
    // between the check and the seal. A refusal thaws the service as it was.
    match external_connections() {
        Ok(open) if open.is_empty() => {}
        Ok(open) => {
            return refuse_thawed(
                "established_socket",
                format!(
                    "park left {} established non-loopback TCP connection(s): {}",
                    open.len(),
                    open.join(", ")
                ),
            )
            .await;
        }
        Err(e) => return refuse_thawed("", format!("socket check: {e:#}")).await,
    }
    match foreign_processes() {
        Ok(found) if found.is_empty() => {}
        Ok(found) => {
            return refuse_thawed(
                "process_outside_workload",
                format!(
                    "park left {} process(es) outside the workload cgroup, which the freeze does not stop (an exec session, a leftover, or a child that left the hook's group): {}",
                    found.len(),
                    found.join(", ")
                ),
            )
            .await;
        }
        Err(e) => return refuse_thawed("", format!("process check: {e:#}")).await,
    }
    // Nothing can reconnect from here: the workload is frozen.
    if let Err(e) = clone_identity::prepare_builder().await {
        // Terminal: the network, names and identity files are partly gone and are not put
        // back. The workload stays frozen and the daemon stops this source.
        return refusal(
            guest::PARK_UNRECOVERABLE,
            format!("park identity removal failed after the freeze: {e:#}"),
        );
    }
    *gate = clone::Gate::Parked;
    Response {
        clone_status: gate.status(),
        ..Response::new("ok")
    }
}

/// Runs in a clone once it is activated. The identity file is written for the hook; the
/// workload thaws on exit 0, and on any failure never does.
pub(super) async fn resume(st: Arc<State>) {
    let (identity, generation) = {
        let gate = st.clone_gate.lock().await;
        match &*gate {
            clone::Gate::Configured { identity, .. } => {
                (identity.clone(), identity.generation.clone())
            }
            _ => return,
        }
    };
    let outcome: Result<(), String> = async {
        let hooks = hooks(&st).map_err(|e| format!("{e:#}"))?;
        write_clone_json(&st.paths.clone_json, &identity)
            .map_err(|e| format!("clone.json: {e:#}"))?;
        run_hook(&st, "resume", &hooks.resume, hooks.resume_timeout_s)
            .await
            .map_err(|e| e.to_string())?;
        set_frozen(false).map_err(|e| format!("thaw: {e:#}"))?;
        wait_frozen(false)
            .await
            .map_err(|e| format!("thaw unconfirmed, the workload may have run: {e:#}"))
    }
    .await;
    let mut gate = st.clone_gate.lock().await;
    match outcome {
        Ok(()) => gate.mark_active(),
        Err(failure) => {
            log!("clone {generation}: {failure}");
            *gate = clone::Gate::HookFailed { identity, failure };
        }
    }
}

fn write_clone_json(path: &Path, identity: &guest::CloneIdentity) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let body = serde_json::json!({
        "generation": identity.generation,
        "hostname": identity.hostname,
        "ip": identity.ip,
        "machine_id": identity.machine_id,
    });
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec(&body)?)?;
    fs::rename(tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue\n";

    #[test]
    fn only_established_non_loopback_connections_count() {
        // 127.0.0.1:8080 <- 127.0.0.1:5000, established: loopback.
        let loopback = "   0: 0100007F:1F90 0100007F:1388 01 0:0 0:0\n";
        // 10.64.1.2:8080 <- 10.64.1.1:5000, established.
        let external = "   1: 0201400A:1F90 0101400A:1388 01 0:0 0:0\n";
        // Listening and time-wait are not established.
        let listening = "   2: 00000000:1F90 00000000:0000 0A 0:0 0:0\n";
        let waiting = "   3: 0201400A:1F90 0101400A:1389 06 0:0 0:0\n";
        let table = format!("{HEADER}{loopback}{listening}{waiting}");
        assert!(established_external(&table, false).is_empty());
        let table = format!("{HEADER}{loopback}{external}{listening}");
        assert_eq!(
            established_external(&table, false),
            vec!["0201400A:1F90->0101400A:1388".to_string()]
        );
    }

    #[test]
    fn ipv6_loopback_and_mapped_addresses() {
        let v6 = "00000000000000000000000001000000"; // ::1
        let mapped = "0000000000000000FFFF00000100007F"; // ::ffff:127.0.0.1
        let other = "00000000000000000000000002000000"; // ::2
        let row = |a: &str, b: &str| format!("   0: {a}:1F90 {b}:1388 01 0:0 0:0\n");
        assert!(established_external(&format!("{HEADER}{}", row(v6, v6)), true).is_empty());
        assert!(established_external(&format!("{HEADER}{}", row(mapped, mapped)), true).is_empty());
        assert_eq!(
            established_external(&format!("{HEADER}{}", row(other, v6)), true).len(),
            1
        );
        // What cannot be parsed is refused.
        assert_eq!(
            established_external(&format!("{HEADER}   0: zz:1 zz:2 01 0:0 0:0\n"), false).len(),
            1
        );
    }

    use testutil::one_at_a_time;

    /// A state whose console and identity file live in a private temp directory, so the
    /// tests run without root.
    fn hooked_state(park: &[&str], resume: &[&str], seconds: u32) -> Arc<State> {
        let mut st = hooked_state_at(park, resume, seconds);
        let dir = std::env::temp_dir().join(format!(
            "init-service-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        let state = Arc::get_mut(&mut st).unwrap();
        state.paths = Paths {
            console: dir.join("console"),
            clone_json: dir.join("run/clone.json"),
        };
        fs::write(&state.paths.console, b"").unwrap();
        st
    }

    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    fn hooked_state_at(park: &[&str], resume: &[&str], seconds: u32) -> Arc<State> {
        let argv = |a: &[&str]| a.iter().map(|s| s.to_string()).collect();
        testutil::state_with(Config {
            template_profile: Some(guest::SERVICE_READY_V1.into()),
            clone_hooks: Some(CloneHooks {
                park: argv(park),
                resume: argv(resume),
                park_timeout_s: seconds,
                resume_timeout_s: seconds,
            }),
            env: BTreeMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
            ..Default::default()
        })
    }

    #[tokio::test]
    async fn hook_exit_code_and_stderr_tail_are_reported() {
        let _one = one_at_a_time().await;
        let st = hooked_state(&["true"], &["true"], 5);
        run_hook(&st, "park", &["true".into()], 5).await.unwrap();
        let failure = run_hook(
            &st,
            "park",
            &["sh".into(), "-c".into(), "echo boom >&2; exit 3".into()],
            5,
        )
        .await
        .unwrap_err()
        .to_string();
        assert_eq!(failure, "park hook exited 3: boom");
    }

    #[tokio::test]
    async fn hook_timeout_kills_the_whole_group() {
        let _one = one_at_a_time().await;
        let st = hooked_state(&["true"], &["true"], 1);
        let marker = std::env::temp_dir().join(format!("hook-orphan-{}", std::process::id()));
        let script = format!("(sleep 2; touch {}) & sleep 30", marker.display());
        let failure = run_hook(&st, "resume", &["sh".into(), "-c".into(), script], 1)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            failure.starts_with("resume hook timed out after 1s"),
            "{failure}"
        );
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert!(!marker.exists(), "a child of the hook outlived its timeout");
    }

    #[tokio::test]
    async fn park_failure_leaves_the_gate_running() {
        let _one = one_at_a_time().await;
        let st = hooked_state(&["false"], &["true"], 5);
        let response = park(&st).await;
        assert_eq!(response.kind, "error");
        assert_eq!(response.error_code, CLONE_HOOK_FAILED);
        assert!(matches!(*st.clone_gate.lock().await, clone::Gate::Service));
        // Only a running service parks.
        *st.clone_gate.lock().await = clone::Gate::Parked;
        assert_eq!(park(&st).await.kind, "error");
    }

    #[tokio::test]
    async fn park_waits_for_an_admitted_execution_to_spawn() {
        let st = hooked_state(&["true"], &["true"], 5);
        let admission = Admission::new(&st);
        let release = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            drop(admission);
        });
        let start = tokio::time::Instant::now();
        wait_admitted(&st).await.unwrap();
        assert!(start.elapsed() >= Duration::from_millis(90));
        release.await.unwrap();
        wait_admitted(&st).await.unwrap();
    }

    /// Makes this process the parent of the orphans it leaves (as PID 1 is in the guest),
    /// until dropped. Without it the host's init would reap them and hide a missing reap.
    struct Subreaper;
    impl Subreaper {
        fn new() -> Self {
            nix::sys::prctl::set_child_subreaper(true).unwrap();
            Subreaper
        }
    }
    impl Drop for Subreaper {
        fn drop(&mut self) {
            let _ = nix::sys::prctl::set_child_subreaper(false);
        }
    }

    #[tokio::test]
    async fn a_killed_hook_group_is_gone_before_the_run_returns() {
        let _one = one_at_a_time().await;
        let _sub = Subreaper::new();
        let st = hooked_state(&["true"], &["true"], 5);
        let marker = std::env::temp_dir().join(format!("hook-bg-{}", std::process::id()));
        let _ = fs::remove_file(&marker);
        let script = format!(
            "sleep 60411 & echo $$ $! > {m}.tmp; mv {m}.tmp {m}",
            m = marker.display()
        );
        // The orphan reaper of the guest, narrowed to the one orphan this test makes: it
        // follows the real rule (an orphan is reaped once its group leader is untracked)
        // and leaves every other child of the test binary alone.
        let reaper = {
            let marker = marker.clone();
            tokio::task::spawn_blocking(move || {
                let ids = loop {
                    if let Some(ids) = fs::read_to_string(&marker)
                        .ok()
                        .map(|s| {
                            s.split_whitespace()
                                .filter_map(|n| n.parse::<i32>().ok())
                                .collect::<Vec<_>>()
                        })
                        .filter(|v| v.len() == 2)
                    {
                        break ids;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                };
                wait_tracked(|t| !t.contains(ids[0]));
                let give_up = std::time::Instant::now() + Duration::from_secs(5);
                while std::time::Instant::now() < give_up {
                    // ECHILD until the shell is gone and the child is ours.
                    if let Ok(nix::sys::wait::WaitStatus::Signaled(..)) = nix::sys::wait::waitpid(
                        Pid::from_raw(ids[1]),
                        Some(nix::sys::wait::WaitPidFlag::WNOHANG),
                    ) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                (ids[0], ids[1])
            })
        };
        let t0 = std::time::Instant::now();
        run_hook(&st, "park", &["sh".into(), "-c".into(), script], 5)
            .await
            .unwrap();
        let took = t0.elapsed();
        let (pgid, bg) = reaper.await.unwrap();
        let _ = fs::remove_file(&marker);
        assert!(
            took < GROUP_GONE_TIMEOUT / 2,
            "the run waited for the group: {took:?}"
        );
        assert_eq!(
            kill(Pid::from_raw(-pgid), None),
            Err(nix::errno::Errno::ESRCH),
            "the group is not gone"
        );
        assert!(!std::path::Path::new(&format!("/proc/{bg}")).exists());
    }

    #[tokio::test]
    async fn parked_and_failed_gates_admit_no_work() {
        let st = hooked_state(&["true"], &["true"], 5);
        let gate = st.clone_gate.lock().await;
        assert!(gate.allows("exec") && gate.allows(guest::SERVICE_PARK_OP));
        assert!(!gate.allows("clone_configure_v1"));
        drop(gate);
        *st.clone_gate.lock().await = clone::Gate::Parked;
        let gate = st.clone_gate.lock().await;
        for op in ["exec", "put", "get", guest::SERVICE_PARK_OP] {
            assert!(!gate.allows(op), "{op}");
        }
        assert!(gate.allows("clone_configure_v1") && gate.allows("clone_activate_v1"));
        assert_eq!(gate.status().unwrap().stage, "parked");
    }

    #[tokio::test]
    async fn failed_resume_never_thaws_and_reports_why() {
        let _one = one_at_a_time().await;
        let st = hooked_state(&["true"], &["sh", "-c", "echo no >&2; exit 1"], 5);
        let identity = guest::CloneIdentity {
            generation: "clone-1".into(),
            hostname: "clone-1".into(),
            ip: "10.64.1.2/24".into(),
            mac: [2, 1, 2, 3, 4, 5],
            machine_id: "0123456789abcdef0123456789abcdef".into(),
        };
        *st.clone_gate.lock().await = clone::Gate::Configured {
            request: Box::new(CloneConfigureStub::request()),
            identity,
            active: false,
            activating: true,
            service: true,
        };
        resume(st.clone()).await;
        let status = st.clone_gate.lock().await.status().unwrap();
        assert_eq!(status.stage, "hook_failed");
        assert_eq!(status.profile, guest::SERVICE_READY_V1);
        assert_eq!(status.failure.unwrap(), "resume hook exited 1: no");
        assert!(!st.clone_gate.lock().await.allows("exec"));
    }

    struct CloneConfigureStub;
    impl CloneConfigureStub {
        fn request() -> guest::CloneConfigure {
            guest::CloneConfigure {
                generation: "clone-1".into(),
                hostname: "clone-1".into(),
                ip: "10.64.1.2/24".into(),
                gateway: "10.64.1.1".into(),
                dns: vec!["10.64.1.1".into()],
                mac: [2, 1, 2, 3, 4, 5],
                entropy: [42; 32],
                realtime_sec: 1_793_404_800,
            }
        }
    }

    #[test]
    fn processes_outside_the_workload_are_found() {
        let st = |name: &str, ppid: i32, state: &str| {
            format!("Name:\t{name}\nState:\t{state}\nPPid:\t{ppid}\n")
        };
        let inside = "0::/briqyard-workload\n";
        let root = "0::/\n";
        assert_eq!(
            outside_workload(40, &st("sh", 1, "S (sleeping)"), root).as_deref(),
            Some("sh[40]")
        );
        assert!(outside_workload(40, &st("app", 1, "S (sleeping)"), inside).is_none());
        assert!(outside_workload(1, &st("init", 0, "S (sleeping)"), root).is_none());
        assert!(outside_workload(9, &st("kworker", 2, "I (idle)"), root).is_none());
        assert!(outside_workload(41, &st("sh", 1, "Z (zombie)"), root).is_none());
        assert!(outside_workload(
            40,
            &st("app", 1, "S (sleeping)"),
            "0::/briqyard-workload/sub\n"
        )
        .is_none());
        assert!(outside_workload(
            40,
            &st("app", 1, "S (sleeping)"),
            "0::/briqyard-workload2\n"
        )
        .is_some());
        assert!(outside_workload(40, "Name:\tapp\nState:\tS\n", inside).is_some());
        assert!(outside_workload(40, "Name:\tapp\nPPid:\tx\n", inside).is_some());
    }
}
