use super::*;
use std::time::Instant;

pub(super) fn untrack(pid: i32) {
    TRACKED.lock().unwrap().remove(pid);
}

/// Spawns a process tracked under the TRACKED lock, as the init does: the reaper test
/// reaps any untracked exited child of this process and must not steal its status.
pub(super) fn spawn_tracked(cmd: &mut std::process::Command) -> std::process::Child {
    let mut tracked = TRACKED.lock().unwrap();
    let child = cmd.spawn().unwrap();
    tracked.insert(child.id() as i32);
    child
}

pub(super) fn state_with(cfg: Config) -> Arc<State> {
    let env = build_env(&cfg.env);
    let gate = clone::Gate::from_config(&cfg).unwrap();
    Arc::new(State {
        cfg,
        env,
        main_pid: Mutex::new(None),
        main_done: Notify::new(),
        requested: Mutex::new(false),
        clone_gate: tokio::sync::Mutex::new(gate),
        activate: Notify::new(),
    })
}

pub(super) fn state() -> Arc<State> {
    state_with(Config::default())
}

/// The frames a handler wrote, in order.
pub(super) fn frames(buf: &[u8]) -> Vec<Response> {
    let mut r = buf;
    let mut out = Vec::new();
    while !r.is_empty() {
        out.push(guest::read_frame(&mut r).unwrap());
    }
    out
}

pub(super) fn text(frames: &[Response], kind: &str) -> String {
    let mut s = Vec::new();
    for f in frames.iter().filter(|f| f.kind == kind) {
        s.extend_from_slice(&f.data);
    }
    String::from_utf8_lossy(&s).into_owned()
}

pub(super) fn exit_of(frames: &[Response]) -> &Response {
    let last = frames.last().expect("a response");
    assert_eq!(last.kind, "exit", "{last:?}");
    last
}

/// Runs an exec request against an in-memory sink and returns the frames it produced.
/// The host's side stays open throughout: its close would end the command.
pub(super) async fn exec(st: &Arc<State>, req: Request) -> Vec<Response> {
    let sink = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let (host, input) = tokio::io::duplex(64);
    exec_op(st, input, sink.clone(), req).await;
    drop(host);
    let buf = sink.lock().await;
    frames(&buf)
}

pub(super) fn exec_req(cmd: &[&str]) -> Request {
    Request {
        op: "exec".into(),
        cmd: cmd.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}

pub(super) fn proc_state(pid: i32) -> Option<char> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = stat.rsplit_once(')')?.1;
    after.split_whitespace().next()?.chars().next()
}

pub(super) fn wait_until(what: &str, mut ok: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ok() {
        assert!(start.elapsed() < Duration::from_secs(5), "{what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub(super) fn write(p: &Path, data: &[u8], mode: u32) {
    fs::write(p, data).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
}
