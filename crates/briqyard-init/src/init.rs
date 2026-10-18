//! The init proper: boot the guest from the config drive, run the image's command, serve the
//! host over vsock, halt when the command ends.

use anyhow::{anyhow, Context, Result};
use briqyard_api::guest::{self, Config, Request, Response};
use nix::mount::{mount, MsFlags};
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitid, waitpid, Id, WaitPidFlag};
use nix::unistd::Pid;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::Notify;
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};

const CONFIG_DEVICE: &str = "/dev/vdb";

static CONSOLE: OnceLock<Mutex<fs::File>> = OnceLock::new();

/// Children we spawned and wait for ourselves. The orphan reaper leaves these alone.
static TRACKED: Mutex<Option<HashSet<i32>>> = Mutex::new(None);

fn logf(args: std::fmt::Arguments) {
    let line = format!("[briqyard] {args}\n");
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

pub fn main() {
    if std::process::id() != 1 {
        eprintln!("briqyard-init must run as PID 1");
        std::process::exit(2);
    }
    mount_base();
    if let Ok(f) = fs::OpenOptions::new().write(true).open("/dev/console") {
        let _ = CONSOLE.set(Mutex::new(f));
    }
    *TRACKED.lock().unwrap() = Some(HashSet::new());
    std::thread::spawn(reap_orphans);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let (code, oom, requested) = rt.block_on(run());
    log!("exit code={code} oom={oom} requested={requested}");
    halt();
}

async fn run() -> (i32, bool, bool) {
    let (cfg, files) = match read_config_drive() {
        Ok(v) => v,
        Err(e) => {
            log!("config drive: {e:#}");
            return (125, false, false);
        }
    };
    if let Err(e) = setup_mounts(&cfg) {
        log!("mounts: {e:#}");
        return (125, false, false);
    }
    if let Err(e) = write_files(&files) {
        log!("boot files: {e:#}");
        return (125, false, false);
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
    tokio::spawn(serve(st.clone()));
    let mut cmd = match main_command(&st) {
        Ok(c) => c,
        Err(e) => {
            log!("command: {e:#}");
            return (126, false, false);
        }
    };
    let mut child = {
        let mut tracked = TRACKED.lock().unwrap();
        match cmd.spawn() {
            Ok(c) => {
                tracked.as_mut().unwrap().insert(c.id().unwrap_or(0) as i32);
                c
            }
            Err(e) => {
                log!("start {:?}: {e}", cmd.as_std().get_program());
                return (127, false, false);
            }
        }
    };
    let pid = child.id().unwrap_or(0) as i32;
    *st.main_pid.lock().unwrap() = Some(pid);
    log!("started pid={pid} {}", argv_string(cmd.as_std()));
    let status = child.wait().await;
    TRACKED.lock().unwrap().as_mut().unwrap().remove(&pid);
    *st.main_pid.lock().unwrap() = None;
    st.main_done.notify_waiters();
    let code = match status {
        Ok(s) => exit_code(s),
        Err(e) => {
            log!("wait: {e}");
            255
        }
    };
    let oom = code == 137 && saw_oom();
    let requested = *st.requested.lock().unwrap();
    (code, oom, requested)
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

/// PID 1 inherits every orphan and must reap them, but a plain wait on any child would steal
/// the statuses of the children we wait for ourselves. Peek without reaping, and reap only
/// what nobody tracks. The spawn path holds the same lock while registering a new child.
fn reap_orphans() {
    loop {
        match waitid(Id::All, WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT) {
            Ok(status) => {
                let pid = match status.pid() {
                    Some(p) => p,
                    None => {
                        std::thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                };
                let tracked = TRACKED.lock().unwrap();
                let is_ours = tracked
                    .as_ref()
                    .map(|t| t.contains(&pid.as_raw()))
                    .unwrap_or(false);
                if !is_ours {
                    let _ = waitpid(pid, None);
                }
                drop(tracked);
                if is_ours {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            Err(nix::errno::Errno::ECHILD) => std::thread::sleep(Duration::from_millis(100)),
            Err(nix::errno::Errno::EINTR) => {}
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

fn mount_base() {
    let nosuid = MsFlags::MS_NOSUID;
    let noexec = MsFlags::MS_NOEXEC;
    let nodev = MsFlags::MS_NODEV;
    let mounts: &[(&str, &str, &str, MsFlags, &str)] = &[
        ("proc", "/proc", "proc", nosuid | noexec | nodev, ""),
        ("sysfs", "/sys", "sysfs", nosuid | noexec | nodev, ""),
        ("devtmpfs", "/dev", "devtmpfs", nosuid, "mode=0755"),
        ("tmpfs", "/run", "tmpfs", nosuid | nodev, "mode=0755"),
        ("tmpfs", "/tmp", "tmpfs", nosuid | nodev, "mode=1777"),
    ];
    for (src, dst, fstype, flags, data) in mounts {
        let _ = fs::create_dir_all(dst);
        let _ = mount(Some(*src), *dst, Some(*fstype), *flags, Some(*data));
    }
    // What an init is expected to add to devtmpfs: bash's `<(...)` opens /dev/fd/N.
    for (link, target) in [
        ("/dev/fd", "/proc/self/fd"),
        ("/dev/stdin", "/proc/self/fd/0"),
        ("/dev/stdout", "/proc/self/fd/1"),
        ("/dev/stderr", "/proc/self/fd/2"),
    ] {
        let _ = std::os::unix::fs::symlink(target, link);
    }
    let _ = fs::create_dir_all("/dev/pts");
    let _ = mount(
        Some("devpts"),
        "/dev/pts",
        Some("devpts"),
        nosuid | noexec,
        Some("mode=0620,gid=5,ptmxmode=666"),
    );
    let _ = fs::create_dir_all("/dev/shm");
    let _ = mount(
        Some("tmpfs"),
        "/dev/shm",
        Some("tmpfs"),
        nosuid | nodev,
        Some("mode=1777"),
    );
    let _ = fs::create_dir_all("/sys/fs/cgroup");
    let _ = mount(
        Some("cgroup2"),
        "/sys/fs/cgroup",
        Some("cgroup2"),
        nosuid | noexec | nodev,
        Some(""),
    );
    let _ = fs::create_dir_all("/dev/mqueue");
    let _ = mount(
        Some("mqueue"),
        "/dev/mqueue",
        Some("mqueue"),
        nosuid | noexec | nodev,
        Some(""),
    );
}

struct BootFile {
    path: String,
    mode: u32,
    data: Vec<u8>,
}

/// Reads the raw tar on the config device.
fn read_config_drive() -> Result<(Config, Vec<BootFile>)> {
    let f = fs::File::open(CONFIG_DEVICE).context(CONFIG_DEVICE)?;
    let mut archive = tar::Archive::new(std::io::BufReader::with_capacity(1 << 20, f));
    let mut cfg: Option<Config> = None;
    let mut files = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let name = entry.path()?.to_string_lossy().into_owned();
        if name == guest::CONFIG_NAME {
            let mut s = String::new();
            entry.read_to_string(&mut s)?;
            cfg = Some(serde_json::from_str(&s).context("config.json")?);
        } else if let Some(rest) = name.strip_prefix(guest::FILES_PREFIX) {
            if entry.header().entry_type().is_file() {
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;
                files.push(BootFile {
                    path: format!("/{rest}"),
                    mode: entry.header().mode().unwrap_or(0o644),
                    data,
                });
            }
        }
    }
    let cfg = cfg.ok_or_else(|| anyhow!("no config.json on the config drive"))?;
    for f in &mut files {
        if let Some(m) = cfg.files.iter().find(|m| m.path == f.path) {
            if m.mode != 0 {
                f.mode = m.mode;
            }
        }
    }
    Ok((cfg, files))
}

/// Mounts the data volumes; a fresh one gets the image directory's owner and content, as
/// Docker does for a named volume.
fn setup_mounts(cfg: &Config) -> Result<()> {
    for m in &cfg.mounts {
        let path = Path::new(&m.path);
        let had = fs::metadata(path).ok();
        let mut staging: Option<PathBuf> = None;
        if had.is_some() {
            let s = PathBuf::from(format!("{}.briqyard-seed", m.path));
            let _ = fs::rename(path, &s);
            staging = Some(s);
        }
        fs::create_dir_all(path)?;
        let fstype = if m.fstype.is_empty() {
            "ext4"
        } else {
            &m.fstype
        };
        mount(
            Some(m.device.as_str()),
            path,
            Some(fstype),
            MsFlags::MS_NOATIME,
            None::<&str>,
        )
        .with_context(|| format!("mount {} on {}", m.device, m.path))?;
        if is_empty_volume(path) {
            // A fresh ext4 has lost+found; a database refuses a data directory that is "not
            // empty". Docker's named volumes are plain directories, so match that: fsck makes
            // the directory again if it ever needs it.
            let _ = fs::remove_dir(path.join("lost+found"));
            if let Some(meta) = &had {
                let _ = nix::unistd::chown(path, Some(meta.uid().into()), Some(meta.gid().into()));
                let _ = fs::set_permissions(path, fs::Permissions::from_mode(meta.mode() & 0o7777));
                if let Some(s) = &staging {
                    let _ = copy_tree(s, path);
                }
            }
        }
        if let Some(s) = staging {
            let _ = fs::remove_dir_all(s);
        }
    }
    Ok(())
}

fn is_empty_volume(path: &Path) -> bool {
    match fs::read_dir(path) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .all(|e| e.file_name() == "lost+found"),
        Err(_) => false,
    }
}

fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        let target = dst.join(entry.file_name());
        let ft = meta.file_type();
        if ft.is_dir() {
            fs::create_dir_all(&target)?;
            let _ = fs::set_permissions(&target, fs::Permissions::from_mode(meta.mode() & 0o7777));
            let _ = nix::unistd::chown(&target, Some(meta.uid().into()), Some(meta.gid().into()));
            copy_tree(&entry.path(), &target)?;
        } else if ft.is_symlink() {
            let l = fs::read_link(entry.path())?;
            let _ = std::os::unix::fs::symlink(l, &target);
            let _ = std::os::unix::fs::lchown(&target, Some(meta.uid()), Some(meta.gid()));
        } else if ft.is_file() {
            fs::copy(entry.path(), &target)?;
            let _ = nix::unistd::chown(&target, Some(meta.uid().into()), Some(meta.gid().into()));
        }
    }
    Ok(())
}

fn write_files(files: &[BootFile]) -> Result<()> {
    for f in files {
        if let Some(parent) = Path::new(&f.path).parent() {
            fs::create_dir_all(parent)?;
        }
        let mode = if f.mode & 0o777 == 0 {
            0o644
        } else {
            f.mode & 0o7777
        };
        fs::write(&f.path, &f.data).with_context(|| f.path.clone())?;
        let _ = fs::set_permissions(&f.path, fs::Permissions::from_mode(mode));
    }
    Ok(())
}

fn setup_names(cfg: &Config) {
    if !cfg.hostname.is_empty() {
        let _ = nix::unistd::sethostname(&cfg.hostname);
        let _ = fs::write("/etc/hostname", format!("{}\n", cfg.hostname));
    }
    let mut hosts =
        String::from("127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n");
    if let Some((ip, _)) = cfg.ip.split_once('/') {
        if !cfg.hostname.is_empty() {
            hosts.push_str(&format!("{ip}\t{}\n", cfg.hostname));
        }
    }
    for (name, addr) in &cfg.hosts {
        hosts.push_str(&format!("{addr}\t{name}\n"));
    }
    let _ = fs::write("/etc/hosts", hosts);
    let mut resolv = String::new();
    for d in &cfg.dns {
        resolv.push_str(&format!("nameserver {d}\n"));
    }
    resolv.push_str("search internal\noptions ndots:1\n");
    let _ = fs::write("/etc/resolv.conf", resolv);
}

async fn setup_network(cfg: &Config) -> Result<()> {
    use futures::TryStreamExt;
    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);
    if let Some(lo) = handle
        .link()
        .get()
        .match_name("lo".into())
        .execute()
        .try_next()
        .await?
    {
        let _ = handle.link().set(lo.header.index).up().execute().await;
    }
    if cfg.ip.is_empty() {
        return Ok(());
    }
    let mut eth = None;
    for _ in 0..50 {
        eth = handle
            .link()
            .get()
            .match_name("eth0".into())
            .execute()
            .try_next()
            .await
            .ok()
            .flatten();
        if eth.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let eth = eth.ok_or_else(|| anyhow!("eth0 did not appear"))?;
    let index = eth.header.index;
    let (ip, prefix) = cfg
        .ip
        .split_once('/')
        .ok_or_else(|| anyhow!("ip {:?}: want CIDR", cfg.ip))?;
    let ip: std::net::Ipv4Addr = ip.parse()?;
    let prefix: u8 = prefix.parse()?;
    if let Err(e) = handle
        .address()
        .add(index, ip.into(), prefix)
        .execute()
        .await
    {
        if !e.to_string().contains("exists") {
            return Err(anyhow!("address: {e}"));
        }
    }
    handle
        .link()
        .set(index)
        .up()
        .execute()
        .await
        .context("eth0 up")?;
    if !cfg.gateway.is_empty() {
        let gw: std::net::Ipv4Addr = cfg.gateway.parse()?;
        if let Err(e) = handle
            .route()
            .add()
            .v4()
            .gateway(gw)
            .output_interface(index)
            .execute()
            .await
        {
            if !e.to_string().contains("exists") {
                return Err(anyhow!("default route: {e}"));
            }
        }
    }
    Ok(())
}

fn build_env(env: &BTreeMap<String, String>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    if !env.contains_key("PATH") {
        out.push((
            "PATH".into(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
        ));
    }
    if !env.contains_key("HOME") {
        out.push(("HOME".into(), "/root".into()));
    }
    out
}

fn main_command(st: &State) -> Result<Command> {
    let cfg = &st.cfg;
    let mut argv: Vec<String> = cfg.entrypoint.clone();
    argv.extend(cfg.cmd.iter().cloned());
    if argv.is_empty() {
        return Err(anyhow!("the image has no entrypoint or command"));
    }
    let path = look_path(&argv[0], &st.env)?;
    let mut cmd = Command::new(path);
    cmd.args(&argv[1..]);
    cmd.env_clear();
    cmd.envs(st.env.iter().map(|(k, v)| (k, v)));
    cmd.current_dir(if cfg.workdir.is_empty() {
        "/"
    } else {
        &cfg.workdir
    });
    cmd.stdin(Stdio::null());
    let console = fs::OpenOptions::new()
        .write(true)
        .open("/dev/console")
        .context("/dev/console")?;
    cmd.stdout(Stdio::from(console.try_clone()?));
    cmd.stderr(Stdio::from(console));
    cmd.process_group(0);
    if !cfg.user.is_empty() {
        let (uid, gid, home) = lookup_user(&cfg.user)?;
        let groups = supplementary_groups(uid);
        cmd.uid(uid).gid(gid);
        if !groups.is_empty() {
            unsafe {
                cmd.pre_exec(move || {
                    nix::unistd::setgroups(&groups.iter().map(|g| (*g).into()).collect::<Vec<_>>())
                        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
                });
            }
        }
        if let Some(h) = home {
            cmd.env("HOME", h);
        }
    }
    cmd.kill_on_drop(false);
    Ok(cmd)
}

fn look_path(name: &str, env: &[(String, String)]) -> Result<String> {
    if name.contains('/') {
        return Ok(name.to_string());
    }
    let path = env
        .iter()
        .find(|(k, _)| k == "PATH")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    for dir in path.split(':') {
        let p = Path::new(dir).join(name);
        if let Ok(m) = fs::metadata(&p) {
            if !m.is_dir() {
                return Ok(p.to_string_lossy().into_owned());
            }
        }
    }
    Err(anyhow!("{name}: not found in PATH"))
}

fn read_table(path: &str) -> Vec<Vec<String>> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split(':').map(String::from).collect())
        .collect()
}

/// Resolves "name", "uid", "name:group" or "uid:gid" through /etc/passwd and /etc/group.
fn lookup_user(spec: &str) -> Result<(u32, u32, Option<String>)> {
    let (user, group) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    let passwd = read_table("/etc/passwd");
    let groups = read_table("/etc/group");
    let mut found = None;
    for row in &passwd {
        if row.len() >= 7 && (row[0] == user || row[2] == user) {
            let uid: u32 = row[2].parse().unwrap_or(0);
            let gid: u32 = row[3].parse().unwrap_or(0);
            found = Some((uid, gid, Some(row[5].clone())));
            break;
        }
    }
    let (uid, mut gid, home) = match found {
        Some(f) => f,
        None => {
            let n: u32 = user
                .parse()
                .map_err(|_| anyhow!("user {user:?} not found"))?;
            (n, n, None)
        }
    };
    if let Some(g) = group {
        gid = match groups
            .iter()
            .find(|r| r.len() >= 3 && (r[0] == g || r[2] == g))
        {
            Some(r) => r[2].parse().unwrap_or(gid),
            None => g.parse().map_err(|_| anyhow!("group {g:?} not found"))?,
        };
    }
    Ok((uid, gid, home))
}

fn supplementary_groups(uid: u32) -> Vec<u32> {
    let passwd = read_table("/etc/passwd");
    let name = match passwd
        .iter()
        .find(|r| r.len() >= 3 && r[2] == uid.to_string())
    {
        Some(r) => r[0].clone(),
        None => return vec![],
    };
    read_table("/etc/group")
        .iter()
        .filter(|r| r.len() >= 4 && r[3].split(',').any(|m| m == name))
        .filter_map(|r| r[2].parse().ok())
        .collect()
}

fn saw_oom() -> bool {
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

fn halt() -> ! {
    if let Some(c) = CONSOLE.get() {
        let _ = c.lock().unwrap().flush();
    }
    nix::unistd::sync();
    std::thread::sleep(Duration::from_millis(50));
    // Firecracker exits when the guest resets.
    let _ = nix::sys::reboot::reboot(nix::sys::reboot::RebootMode::RB_AUTOBOOT);
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

// --- the host's side: vsock ---

async fn serve(st: Arc<State>) {
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

async fn read_request(stream: &mut VsockStream) -> std::io::Result<Request> {
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

async fn send(stream: &Arc<tokio::sync::Mutex<VsockStream>>, resp: &Response) {
    if let Ok(frame) = guest::encode_frame(resp) {
        let mut s = stream.lock().await;
        let _ = AsyncWriteExt::write_all(&mut *s, &frame).await;
        let _ = AsyncWriteExt::flush(&mut *s).await;
    }
}

async fn handle(st: Arc<State>, mut stream: VsockStream) {
    let req = match read_request(&mut stream).await {
        Ok(r) => r,
        Err(_) => return,
    };
    let stream = Arc::new(tokio::sync::Mutex::new(stream));
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
                    ..Default::default()
                },
            )
            .await;
        }
        "exec" => exec_op(&st, stream, req).await,
        "put" => {
            let res = (|| -> std::io::Result<()> {
                if let Some(parent) = Path::new(&req.path).parent() {
                    fs::create_dir_all(parent)?;
                }
                let mode = if req.mode & 0o777 == 0 {
                    0o644
                } else {
                    req.mode & 0o7777
                };
                fs::write(&req.path, &req.data)?;
                fs::set_permissions(&req.path, fs::Permissions::from_mode(mode))
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

async fn exec_op(st: &Arc<State>, stream: Arc<tokio::sync::Mutex<VsockStream>>, req: Request) {
    if req.cmd.is_empty() {
        send(&stream, &Response::error("empty command")).await;
        return;
    }
    let timeout = Duration::from_millis(if req.timeout_ms == 0 {
        600_000
    } else {
        req.timeout_ms
    });
    let mut env = st.env.clone();
    for (k, v) in &req.env {
        env.retain(|(ek, _)| ek != k);
        env.push((k.clone(), v.clone()));
    }
    let path = match look_path(&req.cmd[0], &env) {
        Ok(p) => p,
        Err(e) => {
            send(
                &stream,
                &Response::chunk("stderr", format!("{e}\n").into_bytes()),
            )
            .await;
            send(&stream, &Response::exit(127, false)).await;
            return;
        }
    };
    let mut cmd = Command::new(path);
    cmd.args(&req.cmd[1..]);
    cmd.env_clear();
    cmd.envs(env.iter().map(|(k, v)| (k, v)));
    let cwd = if !req.cwd.is_empty() {
        req.cwd.clone()
    } else if !st.cfg.workdir.is_empty() {
        st.cfg.workdir.clone()
    } else {
        "/".into()
    };
    cmd.current_dir(cwd);
    cmd.stdin(if req.stdin.is_empty() {
        Stdio::null()
    } else {
        Stdio::piped()
    });
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.process_group(0);
    cmd.kill_on_drop(true);
    let mut child = {
        let mut tracked = TRACKED.lock().unwrap();
        match cmd.spawn() {
            Ok(c) => {
                tracked.as_mut().unwrap().insert(c.id().unwrap_or(0) as i32);
                c
            }
            Err(e) => {
                drop(tracked);
                send(
                    &stream,
                    &Response::chunk("stderr", format!("{e}\n").into_bytes()),
                )
                .await;
                send(&stream, &Response::exit(126, false)).await;
                return;
            }
        }
    };
    let pid = child.id().unwrap_or(0) as i32;
    if let Some(mut stdin) = child.stdin.take() {
        let data = req.stdin.clone();
        tokio::spawn(async move {
            let _ = stdin.write_all(&data).await;
            let _ = stdin.shutdown().await;
        });
    }
    let mut readers = Vec::new();
    if let Some(mut out) = child.stdout.take() {
        let s = stream.clone();
        readers.push(tokio::spawn(async move {
            let mut buf = vec![0u8; 64 << 10];
            while let Ok(n) = out.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                send(&s, &Response::chunk("stdout", buf[..n].to_vec())).await;
            }
        }));
    }
    if let Some(mut err) = child.stderr.take() {
        let s = stream.clone();
        readers.push(tokio::spawn(async move {
            let mut buf = vec![0u8; 64 << 10];
            while let Ok(n) = err.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                send(&s, &Response::chunk("stderr", buf[..n].to_vec())).await;
            }
        }));
    }
    let (status, timed_out) = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(s) => (s, false),
        Err(_) => {
            let _ = kill(Pid::from_raw(-pid), Signal::SIGKILL);
            (child.wait().await, true)
        }
    };
    TRACKED.lock().unwrap().as_mut().unwrap().remove(&pid);
    // Grandchildren may keep the pipes open; give them a moment, then let go.
    let drain = async {
        for r in readers {
            let _ = r.await;
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(2), drain).await;
    let code = match status {
        Ok(s) => exit_code(s),
        Err(_) => 126,
    };
    send(&stream, &Response::exit(code, timed_out)).await;
}
