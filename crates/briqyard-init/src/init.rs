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

/// Children we spawned and wait for ourselves. The orphan reaper leaves these alone, and
/// every change wakes it.
static TRACKED: Mutex<Tracked> = Mutex::new(Tracked {
    pids: BTreeSet::new(),
    changes: 0,
});
static TRACKED_CHANGED: Condvar = Condvar::new();

struct Tracked {
    pids: BTreeSet<i32>,
    /// Counts every insert and remove: a waiter tells a change it did not see by it.
    changes: u64,
}

impl Tracked {
    fn insert(&mut self, pid: i32) {
        self.pids.insert(pid);
        self.changed();
    }

    fn remove(&mut self, pid: i32) {
        self.pids.remove(&pid);
        self.changed();
    }

    fn contains(&self, pid: i32) -> bool {
        self.pids.contains(&pid)
    }

    fn changed(&mut self) {
        self.changes += 1;
        TRACKED_CHANGED.notify_all();
    }
}

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
/// starts reports as a code of its own, not `started`: 125 the drive or the disks, 126 the
/// command, 127 its program.
async fn run() -> ExitReport {
    let failed = |code: i32| ExitReport {
        code,
        ..Default::default()
    };
    let (cfg, files) = match read_config_drive() {
        Ok(v) => v,
        Err(e) => {
            log!("config drive: {e:#}");
            return failed(125);
        }
    };
    if let Err(e) = setup_mounts(&cfg) {
        log!("mounts: {e:#}");
        return failed(125);
    }
    if let Err(e) = write_files(&files) {
        log!("boot files: {e:#}");
        return failed(125);
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
        Err(e) => {
            log!("command: {e:#}");
            return failed(126);
        }
    };
    let mut child = {
        let mut tracked = TRACKED.lock().unwrap();
        match cmd.spawn() {
            Ok(c) => {
                tracked.insert(c.id().unwrap_or(0) as i32);
                c
            }
            Err(e) => {
                log!("start {:?}: {e}", cmd.as_std().get_program());
                return failed(127);
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

/// PID 1 inherits every orphan and must reap them, but a plain wait on any child would steal
/// the statuses of the children we wait for ourselves. Peek without reaping, and reap only
/// what nobody tracks. The spawn path holds the same lock while registering a new child.
///
/// `waitid` blocks until a child has exited, so the reaper sleeps only when it cannot: with
/// no child at all (`ECHILD`: the next one is our own spawn), or with a tracked child's
/// status waiting for its owner (the kernel reports the same child until it is collected).
/// Both end with a change to `TRACKED`, which wakes it.
fn reap_orphans() {
    loop {
        let seen = TRACKED.lock().unwrap().changes;
        match reap_one() {
            Ok(Reaped::Orphan(_)) | Err(nix::errno::Errno::EINTR) => {}
            Ok(Reaped::Ours(pid)) => wait_tracked(|t| !t.contains(pid.as_raw())),
            Ok(Reaped::Nothing) | Err(_) => wait_tracked(|t| t.changes != seen),
        }
    }
}

/// Blocks until `done` holds for the tracked children.
fn wait_tracked(done: impl Fn(&Tracked) -> bool) {
    let mut t = TRACKED.lock().unwrap();
    while !done(&t) {
        t = TRACKED_CHANGED.wait(t).unwrap();
    }
}

/// What one look at the exited children found.
#[derive(Debug, PartialEq, Eq)]
enum Reaped {
    /// Nobody tracked it: reaped.
    Orphan(Pid),
    /// A child we wait for ourselves: its status is left where it is.
    Ours(Pid),
    Nothing,
}

/// Waits (without reaping) for any exited child, then reaps it unless it is tracked.
fn reap_one() -> nix::Result<Reaped> {
    let status = waitid(Id::All, WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT)?;
    let pid = match status.pid() {
        Some(p) => p,
        None => return Ok(Reaped::Nothing),
    };
    let tracked = TRACKED.lock().unwrap();
    let is_ours = tracked.contains(pid.as_raw());
    if !is_ours {
        let _ = waitpid(pid, None);
    }
    drop(tracked);
    Ok(if is_ours {
        Reaped::Ours(pid)
    } else {
        Reaped::Orphan(pid)
    })
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

#[derive(Debug)]
struct BootFile {
    path: String,
    mode: u32,
    data: Vec<u8>,
}

/// Reads the raw tar on the config device.
fn read_config_drive() -> Result<(Config, Vec<BootFile>)> {
    let f = fs::File::open(CONFIG_DEVICE).context(CONFIG_DEVICE)?;
    read_config_archive(std::io::BufReader::with_capacity(1 << 20, f))
}

/// Reads the config drive's tar: `config.json`, then the boot files under `files/`, whose
/// mode comes from the tar header unless the config names one.
fn read_config_archive<R: Read>(r: R) -> Result<(Config, Vec<BootFile>)> {
    let mut archive = tar::Archive::new(r);
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
/// Docker does for a named volume. An ext4 volume is mounted with `discard`, so what the guest
/// deletes goes back to the host's pool (ADR 0037), and grown to its disk (ADR 0040).
fn setup_mounts(cfg: &Config) -> Result<()> {
    for m in &cfg.mounts {
        let path = Path::new(&m.path);
        let seed = stage_mount_point(path)?;
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
            (fstype == "ext4").then_some("discard"),
        )
        .with_context(|| format!("mount {} on {}", m.device, m.path))?;
        if fstype == "ext4" {
            match grow_filesystem(&m.device, path) {
                Ok(Some((was, now))) => log!("volume {}: grown from {was} to {now} MB", m.path),
                Ok(None) => {}
                // The volume serves at the size it had; the next boot tries again.
                Err(e) => log!("volume {}: not grown: {e:#}", m.path),
            }
        }
        seed_mount_point(path, seed);
    }
    Ok(())
}

nix::ioctl_write_ptr!(ext4_resize_fs, b'f', 16, u64);

/// Grows the ext4 filesystem mounted at `path` to the end of `device` (ADR 0040): the disk
/// grows on the host, the filesystem here, at the next boot. The kernel grows a mounted
/// filesystem itself (`EXT4_IOC_RESIZE_FS`, what `resize2fs` asks of one), so the image needs
/// no tool, and it returns at once when the filesystem fills the device already. The sizes
/// before and after, in MB, when it grew.
fn grow_filesystem(device: &str, path: &Path) -> Result<Option<(u64, u64)>> {
    use std::io::{Seek, SeekFrom};
    let bytes = fs::File::open(device)
        .and_then(|mut d| d.seek(SeekFrom::End(0)))
        .with_context(|| format!("size of {device}"))?;
    let statvfs = || nix::sys::statvfs::statvfs(path).context("statvfs");
    let mb = |st: &nix::sys::statvfs::Statvfs| st.blocks() * st.fragment_size() >> 20;
    let st = statvfs()?;
    let blocks: u64 = bytes / st.block_size();
    let dir = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    // SAFETY: the ioctl reads one u64 from the pointer, which outlives the call.
    unsafe { ext4_resize_fs(dir.as_raw_fd(), &blocks) }
        .with_context(|| format!("EXT4_IOC_RESIZE_FS to {blocks} blocks"))?;
    let (was, now) = (mb(&st), mb(&statvfs()?));
    Ok((now > was).then_some((was, now)))
}

/// What the image had at a mount path, kept aside while the volume is mounted over it.
struct Seed {
    /// The image directory's metadata, when there was one.
    had: Option<fs::Metadata>,
    /// Where its content was moved.
    staging: Option<PathBuf>,
}

/// Moves what the image has at `path` aside and makes an empty directory to mount on.
fn stage_mount_point(path: &Path) -> Result<Seed> {
    let had = fs::metadata(path).ok();
    let mut staging: Option<PathBuf> = None;
    if had.is_some() {
        let s = PathBuf::from(format!("{}.briqyard-seed", path.display()));
        let _ = fs::rename(path, &s);
        staging = Some(s);
    }
    fs::create_dir_all(path)?;
    Ok(Seed { had, staging })
}

/// After the mount: a fresh volume gets the image directory's owner, mode and content; the
/// staged copy goes either way.
fn seed_mount_point(path: &Path, seed: Seed) {
    if is_empty_volume(path) {
        // A fresh ext4 has lost+found; a database refuses a data directory that is "not
        // empty". Docker's named volumes are plain directories, so match that: fsck makes
        // the directory again if it ever needs it.
        let _ = fs::remove_dir(path.join("lost+found"));
        if let Some(meta) = &seed.had {
            let _ = nix::unistd::chown(path, Some(meta.uid().into()), Some(meta.gid().into()));
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(meta.mode() & 0o7777));
            if let Some(s) = &seed.staging {
                let _ = copy_tree(s, path);
            }
        }
    }
    if let Some(s) = seed.staging {
        let _ = fs::remove_dir_all(s);
    }
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
    write_files_under(Path::new("/"), files)
}

/// Writes the boot files, each at its absolute path under `root`.
fn write_files_under(root: &Path, files: &[BootFile]) -> Result<()> {
    for f in files {
        let target = root.join(f.path.trim_start_matches('/'));
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, &f.data).with_context(|| f.path.clone())?;
        let _ = fs::set_permissions(&target, fs::Permissions::from_mode(file_mode(f.mode)));
    }
    Ok(())
}

/// The mode a file is written with: 0644 when none was given, else the permission bits.
fn file_mode(mode: u32) -> u32 {
    if mode & 0o777 == 0 {
        0o644
    } else {
        mode & 0o7777
    }
}

fn setup_names(cfg: &Config) {
    if !cfg.hostname.is_empty() {
        let _ = nix::unistd::sethostname(&cfg.hostname);
        let _ = fs::write("/etc/hostname", format!("{}\n", cfg.hostname));
    }
    let _ = fs::write("/etc/hosts", hosts_text(cfg));
    let _ = fs::write("/etc/resolv.conf", resolv_text(cfg));
}

/// /etc/hosts: loopback, the machine's own name on its address, then the config's entries.
fn hosts_text(cfg: &Config) -> String {
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
    hosts
}

/// /etc/resolv.conf: the config's servers, `.internal` as the search domain.
fn resolv_text(cfg: &Config) -> String {
    let mut resolv = String::new();
    for d in &cfg.dns {
        resolv.push_str(&format!("nameserver {d}\n"));
    }
    resolv.push_str("search internal\noptions ndots:1\n");
    resolv
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
    parse_table(&fs::read_to_string(path).unwrap_or_default())
}

/// A passwd or group file: one row per line, colon-separated; comments and blank lines skipped.
fn parse_table(text: &str) -> Vec<Vec<String>> {
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split(':').map(String::from).collect())
        .collect()
}

/// Resolves "name", "uid", "name:group" or "uid:gid" through /etc/passwd and /etc/group.
fn lookup_user(spec: &str) -> Result<(u32, u32, Option<String>)> {
    lookup_user_in(spec, &read_table("/etc/passwd"), &read_table("/etc/group"))
}

/// `lookup_user` against the given passwd and group rows. Returns uid, gid and the home
/// directory when the user has a passwd entry.
fn lookup_user_in(
    spec: &str,
    passwd: &[Vec<String>],
    groups: &[Vec<String>],
) -> Result<(u32, u32, Option<String>)> {
    let (user, group) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    let mut found = None;
    for row in passwd {
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
    supplementary_groups_in(uid, &read_table("/etc/passwd"), &read_table("/etc/group"))
}

/// The groups that list the user with this uid as a member.
fn supplementary_groups_in(uid: u32, passwd: &[Vec<String>], groups: &[Vec<String>]) -> Vec<u32> {
    let name = match passwd
        .iter()
        .find(|r| r.len() >= 3 && r[2] == uid.to_string())
    {
        Some(r) => r[0].clone(),
        None => return vec![],
    };
    groups
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
    // A write to the console returns once the tty holds the bytes; the serial port sends
    // them as the kernel gets to it. The exit line must be out before the reset.
    if let Some(c) = CONSOLE.get() {
        let _ = unsafe { libc::tcdrain(c.lock().unwrap().as_raw_fd()) };
    }
    nix::unistd::sync();
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

async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Request> {
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

async fn send<S: AsyncWrite + Unpin>(stream: &Arc<tokio::sync::Mutex<S>>, resp: &Response) {
    if let Ok(frame) = guest::encode_frame(resp) {
        let mut s = stream.lock().await;
        let _ = AsyncWriteExt::write_all(&mut *s, &frame).await;
        let _ = AsyncWriteExt::flush(&mut *s).await;
    }
}

async fn handle<S>(st: Arc<State>, stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Read and written at once: an exec takes input frames while its output goes out.
    let (mut input, output) = tokio::io::split(stream);
    let req = match read_request(&mut input).await {
        Ok(r) => r,
        Err(_) => return,
    };
    let stream = Arc::new(tokio::sync::Mutex::new(output));
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
                    version: briqyard_api::VERSION.into(),
                    ..Default::default()
                },
            )
            .await;
        }
        "exec" => exec_op(&st, input, stream, req).await,
        "put" => {
            let res = (|| -> std::io::Result<()> {
                if let Some(parent) = Path::new(&req.path).parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&req.path, &req.data)?;
                fs::set_permissions(&req.path, fs::Permissions::from_mode(file_mode(req.mode)))
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

/// How long a command on a terminal has after its hangup before it is killed.
const HANGUP_GRACE: Duration = Duration::from_secs(5);

/// The most stdin the init holds for a command that has not read it yet (ADR 0029).
const STDIN_QUEUE_BYTES: usize = 16 << 20;

/// What the command's stdin gets, in order: bytes, then maybe its end. Bytes from the host
/// hold their room in the queue until written.
enum Input {
    Data {
        bytes: Vec<u8>,
        /// Its room in the queue, given back when the bytes are written (dropped).
        _room: Option<tokio::sync::OwnedSemaphorePermit>,
    },
    Close,
}

/// Where the command's stdin goes: its pipe, or the terminal it runs on.
enum Stdin {
    Pipe(tokio::process::ChildStdin),
    Pty(Arc<Pty>),
}

/// How an exec's wait ended.
enum End {
    Exited(std::io::Result<std::process::ExitStatus>),
    TimedOut,
    /// The host closed the connection: nobody reads the answer any more.
    HostGone,
}

/// Runs a command for the host (ADR 0004, 0029): the request's stdin first, then the host's
/// `stdin` frames while `interactive`; stdout and stderr, or the terminal's output with `tty`,
/// streamed as they come; `exit` last. The command ends at its deadline (`timeout_ms`, 0 is
/// none) and when the host closes the connection: killed, or hung up on a terminal.
async fn exec_op<R, W>(st: &Arc<State>, input: R, stream: Arc<tokio::sync::Mutex<W>>, req: Request)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    if req.cmd.is_empty() {
        send(&stream, &Response::error("empty command")).await;
        return;
    }
    let deadline = (req.timeout_ms > 0).then(|| Duration::from_millis(req.timeout_ms));
    let mut env = st.env.clone();
    for (k, v) in &req.env {
        env.retain(|(ek, _)| ek != k);
        env.push((k.clone(), v.clone()));
    }
    if req.tty && !env.iter().any(|(k, _)| k == "TERM") {
        env.push(("TERM".into(), "xterm".into()));
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
    let pty = if req.tty {
        match on_terminal(&mut cmd, req.cols, req.rows) {
            Ok(p) => Some(Arc::new(p)),
            Err(e) => {
                let msg = format!("a terminal for the command: {e}\n");
                send(&stream, &Response::chunk("stderr", msg.into_bytes())).await;
                send(&stream, &Response::exit(126, false)).await;
                return;
            }
        }
    } else {
        cmd.stdin(if req.interactive || !req.stdin.is_empty() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd.process_group(0);
        None
    };
    cmd.kill_on_drop(true);
    let mut child = {
        let mut tracked = TRACKED.lock().unwrap();
        match cmd.spawn() {
            Ok(c) => {
                tracked.insert(c.id().unwrap_or(0) as i32);
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
    // The command's copies of its terminal are its own now: once they are closed, the
    // terminal's output ends.
    drop(cmd);
    let pid = child.id().unwrap_or(0) as i32;
    let sink = match &pty {
        Some(p) => Some(Stdin::Pty(p.clone())),
        None => child.stdin.take().map(Stdin::Pipe),
    };
    let (to_stdin, stdin_rx) = tokio::sync::mpsc::unbounded_channel();
    if !req.stdin.is_empty() {
        let _ = to_stdin.send(Input::Data {
            bytes: req.stdin.clone(),
            _room: None,
        });
    }
    if !req.interactive {
        let _ = to_stdin.send(Input::Close);
    }
    tokio::spawn(write_stdin(sink, stdin_rx));
    let (gone_tx, mut gone) = tokio::sync::oneshot::channel();
    let budget = Arc::new(tokio::sync::Semaphore::new(STDIN_QUEUE_BYTES));
    let host = tokio::spawn(read_input(input, to_stdin, pty.clone(), gone_tx, budget));
    let mut readers = Vec::new();
    if let Some(p) = &pty {
        let (p, s) = (p.clone(), stream.clone());
        readers.push(tokio::spawn(async move {
            let mut buf = vec![0u8; 64 << 10];
            while let Ok(n) = p.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                send(&s, &Response::chunk("stdout", buf[..n].to_vec())).await;
            }
        }));
    }
    if let Some(out) = child.stdout.take() {
        readers.push(forward("stdout", out, stream.clone()));
    }
    if let Some(err) = child.stderr.take() {
        readers.push(forward("stderr", err, stream.clone()));
    }
    let end = {
        let exited = async {
            match deadline {
                Some(d) => tokio::time::timeout(d, child.wait()).await.ok(),
                None => Some(child.wait().await),
            }
        };
        tokio::select! {
            s = exited => match s {
                Some(s) => End::Exited(s),
                None => End::TimedOut,
            },
            _ = &mut gone => End::HostGone,
        }
    };
    let (status, timed_out) = match end {
        End::Exited(s) => (s, false),
        End::TimedOut => {
            let _ = kill(Pid::from_raw(-pid), Signal::SIGKILL);
            (child.wait().await, true)
        }
        End::HostGone => {
            hang_up(pid, pty.is_some(), &mut child).await;
            TRACKED.lock().unwrap().remove(pid);
            return;
        }
    };
    TRACKED.lock().unwrap().remove(pid);
    // Grandchildren may keep the pipes (or the terminal) open; give them a moment, then let go.
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
    // The exit is the last frame: the connection closes with both its halves.
    host.abort();
}

/// Sends what a pipe gives as `kind` frames until it closes.
fn forward<O, W>(
    kind: &'static str,
    mut out: O,
    s: Arc<tokio::sync::Mutex<W>>,
) -> tokio::task::JoinHandle<()>
where
    O: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 << 10];
        while let Ok(n) = out.read(&mut buf).await {
            if n == 0 {
                break;
            }
            send(&s, &Response::chunk(kind, buf[..n].to_vec())).await;
        }
    })
}

/// The host's frames after an exec's request, until it closes the connection: the command's
/// stdin and its end, the terminal's size. The close fires `gone`.
///
/// Stdin goes through a queue, so a command slow to read it does not keep the close from
/// being seen; the queue holds `budget` bytes at most (PID 1's memory is the machine's). Full,
/// the reader waits for room and reads no more of the connection: the host's writes stall, and
/// the client's behind them.
async fn read_input<R: AsyncRead + Unpin>(
    mut input: R,
    stdin: tokio::sync::mpsc::UnboundedSender<Input>,
    pty: Option<Arc<Pty>>,
    gone: tokio::sync::oneshot::Sender<()>,
    budget: Arc<tokio::sync::Semaphore>,
) {
    while let Ok(f) = read_request(&mut input).await {
        match f.op.as_str() {
            "stdin" => {
                let room = f.data.len().clamp(1, STDIN_QUEUE_BYTES) as u32;
                let Ok(held) = budget.clone().acquire_many_owned(room).await else {
                    break;
                };
                let _ = stdin.send(Input::Data {
                    bytes: f.data,
                    _room: Some(held),
                });
            }
            "close_stdin" => {
                let _ = stdin.send(Input::Close);
            }
            "resize" => {
                if let Some(p) = &pty {
                    if let Err(e) = p.resize(f.cols, f.rows) {
                        log!("resize the terminal: {e}");
                    }
                }
            }
            _ => {}
        }
    }
    let _ = gone.send(());
}

/// Writes the command's stdin as it comes. A pipe closes at `Close`; a terminal has no end of
/// input (^D is a byte like any other), so it stays. A failed write drops the rest.
async fn write_stdin(sink: Option<Stdin>, mut rx: tokio::sync::mpsc::UnboundedReceiver<Input>) {
    let mut sink = sink;
    while let Some(i) = rx.recv().await {
        let written = match (i, &mut sink) {
            (Input::Data { bytes, .. }, Some(Stdin::Pipe(p))) => p.write_all(&bytes).await,
            (Input::Data { bytes, .. }, Some(Stdin::Pty(p))) => p.write_all(&bytes).await,
            (Input::Close, Some(Stdin::Pipe(_))) => {
                sink = None;
                Ok(())
            }
            _ => Ok(()),
        };
        if written.is_err() {
            sink = None;
        }
    }
}

/// Ends a command whose host is gone: a hangup on a terminal, as when its window closes, then
/// SIGKILL after [`HANGUP_GRACE`]; SIGKILL at once without one. Its process group either way.
async fn hang_up(pid: i32, tty: bool, child: &mut tokio::process::Child) {
    if tty {
        let _ = kill(Pid::from_raw(-pid), Signal::SIGHUP);
        if tokio::time::timeout(HANGUP_GRACE, child.wait())
            .await
            .is_ok()
        {
            return;
        }
    }
    let _ = kill(Pid::from_raw(-pid), Signal::SIGKILL);
    let _ = child.wait().await;
}

/// Puts the command on a new terminal of `cols` by `rows`: its stdin, stdout and stderr, and
/// its controlling terminal in a session of its own.
fn on_terminal(cmd: &mut Command, cols: u16, rows: u16) -> std::io::Result<Pty> {
    let (pty, slave) = Pty::open(cols, rows)?;
    cmd.stdin(Stdio::from(slave.try_clone()?));
    cmd.stdout(Stdio::from(slave.try_clone()?));
    cmd.stderr(Stdio::from(slave));
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(pty)
}

/// The host side of a command's terminal, non-blocking, read and written through the runtime.
struct Pty {
    master: tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
}

/// A terminal's size; 0 is 80 columns, 24 rows.
fn winsize(cols: u16, rows: u16) -> libc::winsize {
    libc::winsize {
        ws_row: if rows == 0 { 24 } else { rows },
        ws_col: if cols == 0 { 80 } else { cols },
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

/// A libc return value as a result.
fn cvt(n: isize) -> std::io::Result<usize> {
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

impl Pty {
    /// A new terminal and the command's side of it, both closed on exec.
    fn open(cols: u16, rows: u16) -> std::io::Result<(Pty, std::os::fd::OwnedFd)> {
        let size = winsize(cols, rows);
        let p = nix::pty::openpty(Some(&size), None).map_err(std::io::Error::from)?;
        for fd in [&p.master, &p.slave] {
            if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        let flags = unsafe { libc::fcntl(p.master.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe {
                libc::fcntl(
                    p.master.as_raw_fd(),
                    libc::F_SETFL,
                    flags | libc::O_NONBLOCK,
                )
            } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the OwnedFd is a valid descriptor, owned by the AsyncFd and closed only by it.
        let master = unsafe { tokio::io::unix::AsyncFd::register(p.master)? };
        Ok((Pty { master }, p.slave))
    }

    /// What the terminal printed; 0 once every copy of the command's side is closed (the
    /// kernel answers EIO then).
    async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let mut ready = self.master.readable().await?;
            let fd = self.master.as_raw_fd();
            match ready
                .try_io(|_| cvt(unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) }))
            {
                Ok(Err(e)) if e.raw_os_error() == Some(libc::EIO) => return Ok(0),
                Ok(r) => return r,
                Err(_would_block) => continue,
            }
        }
    }

    async fn write_all(&self, mut data: &[u8]) -> std::io::Result<()> {
        while !data.is_empty() {
            let mut ready = self.master.writable().await?;
            let fd = self.master.as_raw_fd();
            match ready
                .try_io(|_| cvt(unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) }))
            {
                Ok(Ok(n)) => data = &data[n..],
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
        Ok(())
    }

    /// A new size: the kernel sends SIGWINCH to the terminal's foreground process group.
    fn resize(&self, cols: u16, rows: u16) -> std::io::Result<()> {
        let size = winsize(cols, rows);
        if unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ as _, &size) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

// The init is Linux-only and so are its tests: run them in the dev VM
// (`cargo test -p briqyard-init` there). Nothing here needs /dev/kvm, a real mount or PID 1.
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use nix::sys::wait::WaitStatus;
    use std::time::Instant;

    fn untrack(pid: i32) {
        TRACKED.lock().unwrap().remove(pid);
    }

    /// Spawns a process tracked under the TRACKED lock, as the init does: the reaper test
    /// reaps any untracked exited child of this process and must not steal its status.
    fn spawn_tracked(cmd: &mut std::process::Command) -> std::process::Child {
        let mut tracked = TRACKED.lock().unwrap();
        let child = cmd.spawn().unwrap();
        tracked.insert(child.id() as i32);
        child
    }

    fn state_with(cfg: Config) -> Arc<State> {
        let env = build_env(&cfg.env);
        Arc::new(State {
            cfg,
            env,
            main_pid: Mutex::new(None),
            main_done: Notify::new(),
            requested: Mutex::new(false),
        })
    }

    fn state() -> Arc<State> {
        state_with(Config::default())
    }

    /// The frames a handler wrote, in order.
    fn frames(buf: &[u8]) -> Vec<Response> {
        let mut r = buf;
        let mut out = Vec::new();
        while !r.is_empty() {
            out.push(guest::read_frame(&mut r).unwrap());
        }
        out
    }

    fn text(frames: &[Response], kind: &str) -> String {
        let mut s = Vec::new();
        for f in frames.iter().filter(|f| f.kind == kind) {
            s.extend_from_slice(&f.data);
        }
        String::from_utf8_lossy(&s).into_owned()
    }

    fn exit_of(frames: &[Response]) -> &Response {
        let last = frames.last().expect("a response");
        assert_eq!(last.kind, "exit", "{last:?}");
        last
    }

    /// Runs an exec request against an in-memory sink and returns the frames it produced.
    /// The host's side stays open throughout: its close would end the command.
    async fn exec(st: &Arc<State>, req: Request) -> Vec<Response> {
        let sink = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let (host, input) = tokio::io::duplex(64);
        exec_op(st, input, sink.clone(), req).await;
        drop(host);
        let buf = sink.lock().await;
        frames(&buf)
    }

    fn exec_req(cmd: &[&str]) -> Request {
        Request {
            op: "exec".into(),
            cmd: cmd.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    fn proc_state(pid: i32) -> Option<char> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let after = stat.rsplit_once(')')?.1;
        after.split_whitespace().next()?.chars().next()
    }

    fn wait_until(what: &str, mut ok: impl FnMut() -> bool) {
        let start = Instant::now();
        while !ok() {
            assert!(start.elapsed() < Duration::from_secs(5), "{what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

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

    // --- the config drive ---

    fn config_json() -> String {
        serde_json::to_string(&Config {
            hostname: "db".into(),
            ip: "10.64.1.2/24".into(),
            gateway: "10.64.1.1".into(),
            dns: vec!["10.64.1.1".into()],
            entrypoint: vec!["/bin/sh".into()],
            cmd: vec!["-c".into(), "true".into()],
            files: vec![
                guest::FileMeta {
                    path: "/etc/app.conf".into(),
                    mode: 0o600,
                },
                guest::FileMeta {
                    path: "/bin/run.sh".into(),
                    mode: 0,
                },
            ],
            ..Default::default()
        })
        .unwrap()
    }

    fn tar_with(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, data, mode) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(*mode);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_cksum();
            b.append_data(&mut h, name, &data[..]).unwrap();
        }
        b.into_inner().unwrap()
    }

    #[test]
    fn config_archive_parses_config_and_files() {
        let mut b = tar::Builder::new(Vec::new());
        let cfg = config_json();
        let mut h = tar::Header::new_gnu();
        h.set_size(cfg.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, guest::CONFIG_NAME, cfg.as_bytes())
            .unwrap();
        // A directory entry under files/ is not a file: skipped.
        let mut d = tar::Header::new_gnu();
        d.set_entry_type(tar::EntryType::Directory);
        d.set_size(0);
        d.set_mode(0o755);
        d.set_cksum();
        b.append_data(&mut d, "files/etc", &[][..]).unwrap();
        let mut f = tar::Header::new_gnu();
        f.set_size(4);
        f.set_mode(0o644);
        f.set_cksum();
        b.append_data(&mut f, "files/etc/app.conf", &b"k=v\n"[..])
            .unwrap();
        let mut f = tar::Header::new_gnu();
        f.set_size(2);
        f.set_mode(0o755);
        f.set_cksum();
        b.append_data(&mut f, "files/bin/run.sh", &b"#!"[..])
            .unwrap();
        let mut f = tar::Header::new_gnu();
        f.set_size(1);
        f.set_mode(0o600);
        f.set_cksum();
        b.append_data(&mut f, "other/ignored", &b"x"[..]).unwrap();
        let tar = b.into_inner().unwrap();

        let (cfg, files) = read_config_archive(&tar[..]).unwrap();
        assert_eq!(cfg.hostname, "db");
        assert_eq!(cfg.entrypoint, vec!["/bin/sh"]);
        assert_eq!(cfg.cmd, vec!["-c", "true"]);
        assert_eq!(
            files.len(),
            2,
            "the directory and the stray entry are not boot files"
        );
        // The config's mode wins over the tar header; a zero in the config keeps the header's.
        assert_eq!(files[0].path, "/etc/app.conf");
        assert_eq!(files[0].mode, 0o600);
        assert_eq!(files[0].data, b"k=v\n");
        assert_eq!(files[1].path, "/bin/run.sh");
        assert_eq!(files[1].mode, 0o755);
        assert_eq!(files[1].data, b"#!");
    }

    #[test]
    fn config_archive_without_config_or_with_bad_json() {
        let tar = tar_with(&[("files/etc/x", b"1", 0o644)]);
        let e = read_config_archive(&tar[..]).unwrap_err();
        assert!(e.to_string().contains("no config.json"), "{e:#}");
        let tar = tar_with(&[(guest::CONFIG_NAME, b"{not json", 0o644)]);
        let e = read_config_archive(&tar[..]).unwrap_err();
        assert!(format!("{e:#}").contains("config.json"), "{e:#}");
        // Not a tar at all.
        assert!(read_config_archive(&b"hello"[..]).is_err());
    }

    #[test]
    fn config_archive_file_mode_from_header_when_config_is_silent() {
        let cfg = serde_json::to_string(&Config::default()).unwrap();
        let tar = tar_with(&[
            (guest::CONFIG_NAME, cfg.as_bytes(), 0o644),
            ("files/opt/a", b"a", 0o640),
            ("files/opt/b", b"b", 0),
        ]);
        let (_, files) = read_config_archive(&tar[..]).unwrap();
        assert_eq!(files[0].mode, 0o640);
        assert_eq!(
            files[1].mode, 0,
            "written as 0644 later, see write_files_under"
        );
    }

    #[test]
    fn boot_files_written_with_their_modes() {
        let root = tempfile::tempdir().unwrap();
        let files = vec![
            BootFile {
                path: "/etc/app/app.conf".into(),
                mode: 0o600,
                data: b"k=v\n".to_vec(),
            },
            BootFile {
                path: "/bin/run.sh".into(),
                mode: 0,
                data: b"#!/bin/sh\n".to_vec(),
            },
            BootFile {
                path: "/setuid".into(),
                mode: 0o4755,
                data: vec![],
            },
            BootFile {
                path: "/extra-bits".into(),
                mode: 0o10644,
                data: vec![],
            },
        ];
        write_files_under(root.path(), &files).unwrap();
        let mode = |p: &str| fs::metadata(root.path().join(p)).unwrap().mode() & 0o7777;
        assert_eq!(
            fs::read(root.path().join("etc/app/app.conf")).unwrap(),
            b"k=v\n"
        );
        assert_eq!(mode("etc/app/app.conf"), 0o600);
        assert_eq!(mode("bin/run.sh"), 0o644, "no mode means 0644");
        assert_eq!(mode("setuid"), 0o4755, "setuid is kept");
        assert_eq!(
            mode("extra-bits"),
            0o644,
            "only the permission bits are kept"
        );
        // Written again at the next boot: the content is replaced.
        let again = vec![BootFile {
            path: "/bin/run.sh".into(),
            mode: 0o755,
            data: b"new".to_vec(),
        }];
        write_files_under(root.path(), &again).unwrap();
        assert_eq!(fs::read(root.path().join("bin/run.sh")).unwrap(), b"new");
        assert_eq!(mode("bin/run.sh"), 0o755);
    }

    #[test]
    fn file_modes() {
        assert_eq!(file_mode(0), 0o644);
        assert_eq!(file_mode(0o600), 0o600);
        assert_eq!(
            file_mode(0o4000),
            0o644,
            "no permission bits at all means the default"
        );
        assert_eq!(file_mode(0o100755), 0o755, "the file type bits are dropped");
    }

    // --- the volume ---

    #[test]
    fn a_filesystem_that_cannot_grow_is_an_error_not_a_failed_boot() {
        // Not ext4, or not root: the kernel refuses, and the caller logs it and boots on.
        let dir = tempfile::tempdir().unwrap();
        let dev = dir.path().join("dev");
        std::fs::write(&dev, vec![0u8; 1 << 20]).unwrap();
        let err = grow_filesystem(dev.to_str().unwrap(), dir.path()).unwrap_err();
        assert!(
            format!("{err:#}").contains("EXT4_IOC_RESIZE_FS to "),
            "{err:#}"
        );
        let err = grow_filesystem("/nonexistent", dir.path()).unwrap_err();
        assert!(
            format!("{err:#}").contains("size of /nonexistent"),
            "{err:#}"
        );
    }

    fn write(p: &Path, data: &[u8], mode: u32) {
        fs::write(p, data).unwrap();
        fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn names(p: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(p)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn fresh_volume_is_seeded_from_the_image_directory() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("var/lib/app");
        fs::create_dir_all(data.join("sub")).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o750)).unwrap();
        write(&data.join("seed.txt"), b"seed", 0o640);
        write(&data.join("sub/deep.txt"), b"deep", 0o600);
        std::os::unix::fs::symlink("seed.txt", data.join("link")).unwrap();

        let seed = stage_mount_point(&data).unwrap();
        // The image's content is aside and an empty directory waits for the mount.
        let staging = root.path().join("var/lib/app.briqyard-seed");
        assert_eq!(seed.staging.as_deref(), Some(staging.as_path()));
        assert!(seed.had.is_some());
        assert!(names(&data).is_empty());
        assert_eq!(names(&staging), ["link", "seed.txt", "sub"]);

        // What a mount of a fresh ext4 leaves there.
        fs::create_dir(data.join("lost+found")).unwrap();
        seed_mount_point(&data, seed);

        assert_eq!(
            names(&data),
            ["link", "seed.txt", "sub"],
            "lost+found is gone"
        );
        assert_eq!(fs::read(data.join("seed.txt")).unwrap(), b"seed");
        assert_eq!(fs::read(data.join("sub/deep.txt")).unwrap(), b"deep");
        assert_eq!(
            fs::read_link(data.join("link")).unwrap(),
            Path::new("seed.txt")
        );
        assert_eq!(fs::metadata(&data).unwrap().mode() & 0o7777, 0o750);
        assert_eq!(
            fs::metadata(data.join("sub/deep.txt")).unwrap().mode() & 0o7777,
            0o600
        );
        assert!(!staging.exists(), "the staged copy is removed");
    }

    #[test]
    fn used_volume_keeps_its_content() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        fs::create_dir_all(&data).unwrap();
        write(&data.join("image.txt"), b"image", 0o644);
        let seed = stage_mount_point(&data).unwrap();
        // The volume already has data: nothing is seeded over it.
        fs::create_dir(data.join("lost+found")).unwrap();
        write(&data.join("PG_VERSION"), b"17", 0o600);
        seed_mount_point(&data, seed);
        assert_eq!(names(&data), ["PG_VERSION", "lost+found"]);
        assert!(!root.path().join("data.briqyard-seed").exists());
    }

    #[test]
    fn mount_point_the_image_does_not_have() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("new/mnt");
        let seed = stage_mount_point(&data).unwrap();
        assert!(seed.had.is_none());
        assert!(seed.staging.is_none());
        assert!(data.is_dir(), "made so the mount has somewhere to go");
        fs::create_dir(data.join("lost+found")).unwrap();
        seed_mount_point(&data, seed);
        assert!(
            names(&data).is_empty(),
            "lost+found is removed on a fresh volume"
        );
    }

    #[test]
    fn empty_volume() {
        let root = tempfile::tempdir().unwrap();
        assert!(is_empty_volume(root.path()));
        fs::create_dir(root.path().join("lost+found")).unwrap();
        assert!(
            is_empty_volume(root.path()),
            "only lost+found counts as empty"
        );
        write(&root.path().join("x"), b"", 0o644);
        assert!(!is_empty_volume(root.path()));
        assert!(
            !is_empty_volume(&root.path().join("missing")),
            "unreadable is not empty"
        );
    }

    #[test]
    fn copy_tree_keeps_modes_and_links() {
        let root = tempfile::tempdir().unwrap();
        let src = root.path().join("src");
        let dst = root.path().join("dst");
        fs::create_dir_all(src.join("a/b")).unwrap();
        fs::set_permissions(src.join("a"), fs::Permissions::from_mode(0o700)).unwrap();
        write(&src.join("a/b/f"), b"f", 0o755);
        std::os::unix::fs::symlink("/nowhere", src.join("dangling")).unwrap();
        fs::create_dir(&dst).unwrap();
        copy_tree(&src, &dst).unwrap();
        assert_eq!(fs::metadata(dst.join("a")).unwrap().mode() & 0o7777, 0o700);
        assert_eq!(fs::read(dst.join("a/b/f")).unwrap(), b"f");
        assert_eq!(
            fs::metadata(dst.join("a/b/f")).unwrap().mode() & 0o7777,
            0o755
        );
        assert_eq!(
            fs::read_link(dst.join("dangling")).unwrap(),
            Path::new("/nowhere")
        );
        assert!(copy_tree(&root.path().join("missing"), &dst).is_err());
    }

    // --- names ---

    #[test]
    fn hosts_file() {
        let mut cfg = Config {
            hostname: "db".into(),
            ip: "10.64.1.2/24".into(),
            ..Default::default()
        };
        cfg.hosts
            .insert("cache.internal".into(), "10.64.1.3".into());
        cfg.hosts.insert("api.internal".into(), "10.64.1.4".into());
        assert_eq!(
            hosts_text(&cfg),
            "127.0.0.1\tlocalhost\n\
             ::1\tlocalhost ip6-localhost ip6-loopback\n\
             10.64.1.2\tdb\n\
             10.64.1.4\tapi.internal\n\
             10.64.1.3\tcache.internal\n"
        );
        // No address, or no name: the machine's own line is left out.
        let cfg = Config {
            hostname: "db".into(),
            ..Default::default()
        };
        assert_eq!(
            hosts_text(&cfg),
            "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n"
        );
        let cfg = Config {
            ip: "10.64.1.2/24".into(),
            ..Default::default()
        };
        assert!(!hosts_text(&cfg).contains("10.64.1.2"));
    }

    #[test]
    fn resolv_conf() {
        let cfg = Config {
            dns: vec!["10.64.1.1".into(), "1.1.1.1".into()],
            ..Default::default()
        };
        assert_eq!(
            resolv_text(&cfg),
            "nameserver 10.64.1.1\nnameserver 1.1.1.1\nsearch internal\noptions ndots:1\n"
        );
        assert_eq!(
            resolv_text(&Config::default()),
            "search internal\noptions ndots:1\n"
        );
    }

    // --- users and groups ---

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/sh\n\
        # a comment\n\
        \n\
        postgres:x:999:999::/var/lib/postgresql:/bin/sh\n\
        short:x:7\n\
        nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n";
    const GROUP: &str = "root:x:0:\n\
        postgres:x:999:\n\
        docker:x:120:postgres,alice\n\
        staff:x:50:alice\n";

    fn lookup(spec: &str) -> Result<(u32, u32, Option<String>)> {
        lookup_user_in(spec, &parse_table(PASSWD), &parse_table(GROUP))
    }

    #[test]
    fn tables() {
        let t = parse_table(PASSWD);
        assert_eq!(t.len(), 4, "comments and blank lines are skipped");
        assert_eq!(t[0][0], "root");
        assert_eq!(t[2], vec!["short", "x", "7"]);
        assert!(parse_table("").is_empty());
    }

    #[test]
    fn user_lookup() {
        assert_eq!(lookup("root").unwrap(), (0, 0, Some("/root".into())));
        assert_eq!(
            lookup("postgres").unwrap(),
            (999, 999, Some("/var/lib/postgresql".into()))
        );
        // A uid finds its passwd row too, home included.
        assert_eq!(lookup("999").unwrap(), lookup("postgres").unwrap());
        assert_eq!(lookup("0").unwrap(), lookup("root").unwrap());
        // A numeric user with no row: uid and gid alike, no home.
        assert_eq!(lookup("1000").unwrap(), (1000, 1000, None));
        assert_eq!(lookup("1000:1001").unwrap(), (1000, 1001, None));
        // A short passwd row is ignored rather than read out of bounds: its name is unknown
        // and its uid falls back to the numeric rule.
        assert!(lookup("short").is_err());
        assert_eq!(lookup("7").unwrap(), (7, 7, None));
    }

    #[test]
    fn user_lookup_with_group() {
        let home = Some("/var/lib/postgresql".to_string());
        assert_eq!(lookup("postgres:docker").unwrap(), (999, 120, home.clone()));
        assert_eq!(lookup("postgres:0").unwrap(), (999, 0, home.clone()));
        assert_eq!(lookup("999:root").unwrap(), (999, 0, home.clone()));
        // A numeric group with no row is taken as is.
        assert_eq!(lookup("postgres:5000").unwrap(), (999, 5000, home));
    }

    #[test]
    fn user_lookup_errors() {
        for (spec, what) in [
            ("alice", "user \"alice\" not found"),
            ("", "user \"\" not found"),
            ("alice:root", "user \"alice\" not found"),
            ("postgres:nogroup", "group \"nogroup\" not found"),
            ("postgres:", "group \"\" not found"),
        ] {
            let e = lookup(spec).unwrap_err().to_string();
            assert_eq!(e, what, "{spec}");
        }
    }

    #[test]
    fn supplementary_groups_of_a_user() {
        let passwd = parse_table(PASSWD);
        let groups = parse_table(GROUP);
        assert_eq!(supplementary_groups_in(999, &passwd, &groups), vec![120]);
        assert!(supplementary_groups_in(65534, &passwd, &groups).is_empty());
        assert!(
            supplementary_groups_in(1000, &passwd, &groups).is_empty(),
            "no passwd row"
        );
        // Membership is by name, exact: "alice" is not "alic".
        let mut p = passwd.clone();
        p.push(
            "alic:x:2000:2000::/home/alic:/bin/sh"
                .split(':')
                .map(String::from)
                .collect(),
        );
        assert!(supplementary_groups_in(2000, &p, &groups).is_empty());
    }

    // --- the environment and the command ---

    #[test]
    fn environment_defaults() {
        let env = build_env(&BTreeMap::new());
        assert_eq!(
            env,
            vec![
                (
                    "PATH".to_string(),
                    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string()
                ),
                ("HOME".to_string(), "/root".to_string()),
            ]
        );
        // The image's values win and come first.
        let mut image = BTreeMap::new();
        image.insert("PATH".to_string(), "/app/bin".to_string());
        image.insert("HOME".to_string(), "/app".to_string());
        image.insert("A".to_string(), "1".to_string());
        let env = build_env(&image);
        assert_eq!(env.len(), 3);
        assert!(env.contains(&("PATH".to_string(), "/app/bin".to_string())));
        assert!(env.contains(&("HOME".to_string(), "/app".to_string())));
        assert!(env.contains(&("A".to_string(), "1".to_string())));
    }

    #[test]
    fn path_lookup() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        let sbin = root.path().join("sbin");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&sbin).unwrap();
        write(&bin.join("tool"), b"", 0o755);
        write(&sbin.join("tool"), b"", 0o755);
        fs::create_dir(bin.join("adir")).unwrap();
        write(&sbin.join("adir"), b"", 0o755);
        let env = vec![(
            "PATH".to_string(),
            format!("{}:{}", bin.display(), sbin.display()),
        )];
        // First directory wins; a directory of that name is not a command.
        assert_eq!(
            look_path("tool", &env).unwrap(),
            bin.join("tool").to_string_lossy()
        );
        assert_eq!(
            look_path("adir", &env).unwrap(),
            sbin.join("adir").to_string_lossy()
        );
        // A path is taken as given, found or not.
        assert_eq!(look_path("/x/y", &env).unwrap(), "/x/y");
        assert_eq!(look_path("./y", &env).unwrap(), "./y");
        let e = look_path("missing", &env).unwrap_err().to_string();
        assert_eq!(e, "missing: not found in PATH");
        assert!(look_path("tool", &[]).is_err(), "no PATH, nothing found");
    }

    // --- exec ---

    #[tokio::test]
    async fn exec_streams_output_and_exit_code() {
        let st = state();
        let f = exec(
            &st,
            exec_req(&["sh", "-c", "echo out; echo err >&2; exit 3"]),
        )
        .await;
        assert_eq!(text(&f, "stdout"), "out\n");
        assert_eq!(text(&f, "stderr"), "err\n");
        let exit = exit_of(&f);
        assert_eq!((exit.code, exit.timed_out), (3, false));
    }

    #[tokio::test]
    async fn exec_feeds_stdin() {
        let st = state();
        let mut req = exec_req(&["cat"]);
        req.stdin = b"hello from the host".to_vec();
        let f = exec(&st, req).await;
        assert_eq!(text(&f, "stdout"), "hello from the host");
        assert_eq!(exit_of(&f).code, 0);
        // Without stdin the command reads nothing, not the init's own input.
        let f = exec(&st, exec_req(&["cat"])).await;
        assert_eq!(text(&f, "stdout"), "");
        assert_eq!(exit_of(&f).code, 0);
    }

    #[tokio::test]
    async fn exec_environment_and_directory() {
        let st = state_with(Config {
            env: BTreeMap::from([("FOO".to_string(), "image".to_string())]),
            workdir: "/tmp".into(),
            ..Default::default()
        });
        let f = exec(&st, exec_req(&["sh", "-c", "echo $FOO $HOME; pwd"])).await;
        assert_eq!(text(&f, "stdout"), "image /root\n/tmp\n");
        // The request's env replaces the image's; its cwd replaces the workdir.
        let mut req = exec_req(&["sh", "-c", "echo $FOO; pwd"]);
        req.env.insert("FOO".into(), "request".into());
        req.cwd = "/".into();
        let f = exec(&st, req).await;
        assert_eq!(text(&f, "stdout"), "request\n/\n");
        // No workdir and no cwd: the root.
        let f = exec(&state(), exec_req(&["pwd"])).await;
        assert_eq!(text(&f, "stdout"), "/\n");
    }

    #[tokio::test]
    async fn exec_refusals() {
        let st = state();
        let f = exec(&st, exec_req(&[])).await;
        assert_eq!(f.len(), 1);
        assert_eq!(
            (f[0].kind.as_str(), f[0].message.as_str()),
            ("error", "empty command")
        );
        // Not in PATH: 127, as a shell says.
        let f = exec(&st, exec_req(&["no-such-command-briqyard"])).await;
        assert_eq!(
            text(&f, "stderr"),
            "no-such-command-briqyard: not found in PATH\n"
        );
        assert_eq!(exit_of(&f).code, 127);
        // Found but cannot be run: 126.
        let f = exec(&st, exec_req(&["/etc/passwd"])).await;
        assert!(!text(&f, "stderr").is_empty());
        assert_eq!(exit_of(&f).code, 126);
        // A missing working directory is a spawn failure too.
        let mut req = exec_req(&["pwd"]);
        req.cwd = "/no/such/dir".into();
        let f = exec(&st, req).await;
        assert_eq!(exit_of(&f).code, 126);
    }

    #[tokio::test]
    async fn exec_reports_a_signal() {
        let f = exec(&state(), exec_req(&["sh", "-c", "kill -9 $$"])).await;
        let exit = exit_of(&f);
        assert_eq!((exit.code, exit.timed_out), (137, false));
    }

    #[tokio::test]
    async fn exec_timeout_kills_the_process_group() {
        let st = state();
        // The shell prints its sleep's pid so the test can watch that grandchild die too.
        let mut req = exec_req(&["sh", "-c", "sleep 60 & echo $!; wait"]);
        req.timeout_ms = 300;
        let start = Instant::now();
        let f = exec(&st, req).await;
        assert!(start.elapsed() < Duration::from_secs(10));
        let exit = exit_of(&f);
        assert_eq!((exit.code, exit.timed_out), (137, true));
        let grandchild: i32 = text(&f, "stdout").trim().parse().unwrap();
        // Killed with its group: gone, or a zombie waiting for the system's init.
        wait_until("the grandchild sleep is killed", || {
            matches!(proc_state(grandchild), None | Some('Z'))
        });
    }

    #[tokio::test]
    async fn exec_untracks_its_child() {
        let st = state();
        let f = exec(&st, exec_req(&["sh", "-c", "echo $$"])).await;
        let pid: i32 = text(&f, "stdout").trim().parse().unwrap();
        assert!(!TRACKED.lock().unwrap().contains(pid));
    }

    // --- the handler over an in-memory stream ---

    /// Sends one request through `handle` and returns every response it wrote.
    async fn roundtrip(st: &Arc<State>, req: Request) -> Vec<Response> {
        let (mut client, server) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(handle(st.clone(), server));
        client
            .write_all(&guest::encode_frame(&req).unwrap())
            .await
            .unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        task.await.unwrap();
        frames(&out)
    }

    #[tokio::test]
    async fn handle_ping() {
        let st = state();
        *st.main_pid.lock().unwrap() = Some(42);
        let f = roundtrip(
            &st,
            Request {
                op: "ping".into(),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "pong");
        assert_eq!(f[0].main_pid, 42);
        assert!(f[0].uptime > 0.0, "read from /proc/uptime");
        assert_eq!(f[0].version, briqyard_api::VERSION);
    }

    #[tokio::test]
    async fn handle_put_and_get() {
        let st = state();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("deep/dir/file.txt");
        let f = roundtrip(
            &st,
            Request {
                op: "put".into(),
                path: path.to_string_lossy().into_owned(),
                data: b"content".to_vec(),
                mode: 0o600,
                ..Default::default()
            },
        )
        .await;
        assert_eq!(f[0].kind, "ok");
        assert_eq!(fs::read(&path).unwrap(), b"content");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
        let f = roundtrip(
            &st,
            Request {
                op: "get".into(),
                path: path.to_string_lossy().into_owned(),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(f[0].kind, "file");
        assert_eq!(f[0].data, b"content");
        // No mode means 0644.
        let plain = root.path().join("plain");
        roundtrip(
            &st,
            Request {
                op: "put".into(),
                path: plain.to_string_lossy().into_owned(),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(fs::metadata(&plain).unwrap().mode() & 0o7777, 0o644);
        // A missing file is an error response, not a dropped connection.
        let f = roundtrip(
            &st,
            Request {
                op: "get".into(),
                path: root.path().join("missing").to_string_lossy().into_owned(),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(f[0].kind, "error");
        assert!(f[0].message.contains("No such file"), "{}", f[0].message);
    }

    #[tokio::test]
    async fn handle_unknown_op_and_bad_frames() {
        let st = state();
        let f = roundtrip(
            &st,
            Request {
                op: "dance".into(),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(f[0].kind, "error");
        assert_eq!(f[0].message, "unknown op dance");
        // A frame past the limit, or not JSON: the connection is dropped with no answer.
        for bad in [
            ((guest::MAX_FRAME as u32 + 1).to_be_bytes().to_vec()),
            [&3u32.to_be_bytes()[..], b"{x}"].concat(),
            b"\0\0".to_vec(),
        ] {
            let (mut client, server) = tokio::io::duplex(1 << 16);
            let task = tokio::spawn(handle(st.clone(), server));
            client.write_all(&bad).await.unwrap();
            drop(client);
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn handle_exec() {
        let f = roundtrip(&state(), exec_req(&["echo", "through", "vsock"])).await;
        assert_eq!(text(&f, "stdout"), "through vsock\n");
        assert_eq!(exit_of(&f).code, 0);
    }

    // --- sessions (ADR 0029) ---

    /// A session as the host holds one: the request sent, the connection kept for input
    /// frames, the output read as it comes.
    struct Live {
        rd: tokio::io::ReadHalf<tokio::io::DuplexStream>,
        wr: tokio::io::WriteHalf<tokio::io::DuplexStream>,
        task: tokio::task::JoinHandle<()>,
        out: String,
    }

    async fn open(st: &Arc<State>, req: Request) -> Live {
        let (client, server) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(handle(st.clone(), server));
        let (rd, wr) = tokio::io::split(client);
        let mut live = Live {
            rd,
            wr,
            task,
            out: String::new(),
        };
        live.send(req).await;
        live
    }

    fn input(op: &str) -> Request {
        Request {
            op: op.into(),
            ..Default::default()
        }
    }

    fn stdin(data: &str) -> Request {
        Request {
            data: data.as_bytes().to_vec(),
            ..input("stdin")
        }
    }

    impl Live {
        async fn send(&mut self, r: Request) {
            self.wr
                .write_all(&guest::encode_frame(&r).unwrap())
                .await
                .unwrap();
        }

        async fn frame(&mut self) -> Response {
            let read = async {
                let mut hdr = [0u8; 4];
                self.rd.read_exact(&mut hdr).await.unwrap();
                let mut body = vec![0u8; u32::from_be_bytes(hdr) as usize];
                self.rd.read_exact(&mut body).await.unwrap();
                guest::decode_frame::<Response>(&body).unwrap()
            };
            tokio::time::timeout(Duration::from_secs(10), read)
                .await
                .expect("a frame within 10 s")
        }

        /// Reads output until it holds `needle`.
        async fn until(&mut self, needle: &str) {
            while !self.out.contains(needle) {
                let f = self.frame().await;
                assert_ne!(f.kind, "exit", "ended before {needle:?}: {:?}", self.out);
                self.out.push_str(&String::from_utf8_lossy(&f.data));
            }
        }

        /// Reads to the exit, the output kept.
        async fn exit(&mut self) -> Response {
            loop {
                let f = self.frame().await;
                if f.kind == "exit" {
                    return f;
                }
                self.out.push_str(&String::from_utf8_lossy(&f.data));
            }
        }

        /// The host goes: its side of the connection closes.
        async fn hang_up(self) {
            drop((self.rd, self.wr));
            tokio::time::timeout(Duration::from_secs(10), self.task)
                .await
                .expect("the exec ends with its host")
                .unwrap();
        }
    }

    fn session(cmd: &[&str], tty: bool) -> Request {
        Request {
            interactive: true,
            tty,
            ..exec_req(cmd)
        }
    }

    fn gone(pid: i32) -> bool {
        matches!(proc_state(pid), None | Some('Z'))
    }

    #[tokio::test]
    async fn a_session_streams_stdin_until_it_closes() {
        let mut s = open(&state(), session(&["cat"], false)).await;
        s.send(stdin("one\n")).await;
        s.until("one\n").await;
        s.send(stdin("two\n")).await;
        s.send(input("close_stdin")).await;
        let exit = s.exit().await;
        assert_eq!((exit.code, s.out.as_str()), (0, "one\ntwo\n"));
        // Nothing follows the exit: the init closed its side.
        let mut rest = Vec::new();
        s.rd.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    }

    #[tokio::test]
    async fn a_session_on_a_terminal_has_its_size_and_follows_a_resize() {
        let mut req = session(
            &[
                "sh",
                "-c",
                "tty; stty size; echo TERM=$TERM; echo err >&2; read x; stty size; echo got $x; exit 4",
            ],
            true,
        );
        (req.cols, req.rows) = (100, 30);
        let mut s = open(&state(), req).await;
        s.until("TERM=xterm").await;
        assert!(s.out.contains("/dev/pts/"), "{}", s.out);
        assert!(s.out.contains("30 100"), "{}", s.out);
        s.until("err").await;
        // The resize is applied as it is read, before the next frame's input.
        s.send(Request {
            cols: 120,
            rows: 40,
            ..input("resize")
        })
        .await;
        s.send(stdin("hi\n")).await;
        let exit = s.exit().await;
        assert_eq!(exit.code, 4);
        assert!(s.out.contains("40 120"), "{}", s.out);
        // One output: what the terminal printed, its own echo of the input included.
        assert!(
            s.out.contains("hi\r\n") && s.out.contains("got hi"),
            "{}",
            s.out
        );
    }

    #[tokio::test]
    async fn a_terminal_is_80_by_24_unless_asked_and_takes_the_hosts_term() {
        let mut req = session(&["sh", "-c", "stty size; echo $TERM"], true);
        req.env.insert("TERM".into(), "xterm-256color".into());
        let mut s = open(&state(), req).await;
        assert_eq!(s.exit().await.code, 0);
        assert_eq!(s.out, "24 80\r\nxterm-256color\r\n");
    }

    #[tokio::test]
    async fn the_hosts_close_kills_the_command() {
        // A session, and a plain exec too: nobody reads its answer any more.
        for interactive in [true, false] {
            let mut req = exec_req(&["sh", "-c", "echo $$; exec sleep 60"]);
            req.interactive = interactive;
            let mut s = open(&state(), req).await;
            s.until("\n").await;
            let pid: i32 = s.out.trim().parse().unwrap();
            let start = Instant::now();
            s.hang_up().await;
            assert!(start.elapsed() < Duration::from_secs(3));
            wait_until("the command is killed", || gone(pid));
        }
    }

    #[tokio::test]
    async fn the_stdin_queue_is_bounded_and_holds_back_the_host() {
        // A queue's worth of stdin and one megabyte more, then the host's close.
        let mb = guest::encode_frame(&stdin(&"x".repeat(1 << 20))).unwrap();
        let full = STDIN_QUEUE_BYTES >> 20;
        let input = std::io::Cursor::new(mb.repeat(full + 1));
        let (tx, mut queued) = tokio::sync::mpsc::unbounded_channel();
        let (gone_tx, gone) = tokio::sync::oneshot::channel();
        let budget = Arc::new(tokio::sync::Semaphore::new(STDIN_QUEUE_BYTES));
        let mut reader = tokio::spawn(read_input(input, tx, None, gone_tx, budget));
        // Nothing writes the command's stdin: the reader waits with the queue full, so it
        // reads no more of the connection (the host's writes stall behind it).
        let waited = tokio::time::timeout(Duration::from_secs(5), &mut reader).await;
        assert!(waited.is_err(), "the reader went past a full queue");
        let mut held = Vec::new();
        while let Ok(i) = queued.try_recv() {
            held.push(i);
        }
        assert_eq!(held.len(), full);
        // Written (dropped) frees its room: the rest comes in, then the close.
        drop(held);
        tokio::time::timeout(Duration::from_secs(20), reader)
            .await
            .expect("the reader goes on once the queue drains")
            .unwrap();
        assert!(gone.await.is_ok());
        assert!(
            matches!(queued.try_recv(), Ok(Input::Data { bytes, _room: Some(_) }) if bytes.len() == 1 << 20)
        );
    }

    #[tokio::test]
    async fn the_hosts_close_hangs_up_a_terminal() {
        let script = "trap 'exit 9' HUP; echo $$; while :; do sleep 0.1; done";
        let mut s = open(&state(), session(&["sh", "-c", script], true)).await;
        s.until("\n").await;
        let pid: i32 = s.out.trim().parse().unwrap();
        let start = Instant::now();
        s.hang_up().await;
        assert!(start.elapsed() < HANGUP_GRACE, "ended by its hangup");
        wait_until("the shell is gone", || gone(pid));
        // One that ignores the hangup is killed after the grace.
        let mut s = open(
            &state(),
            session(&["sh", "-c", "trap '' HUP; echo $$; exec sleep 60"], true),
        )
        .await;
        s.until("\n").await;
        let pid: i32 = s.out.trim().parse().unwrap();
        let start = Instant::now();
        s.hang_up().await;
        assert!(start.elapsed() >= HANGUP_GRACE);
        wait_until("the sleep is killed", || gone(pid));
    }

    #[tokio::test]
    async fn a_session_has_no_deadline_unless_asked() {
        let mut req = session(&["sh", "-c", "sleep 1; echo done"], false);
        req.timeout_ms = 0;
        let mut s = open(&state(), req).await;
        let exit = s.exit().await;
        assert_eq!(
            (exit.code, exit.timed_out, s.out.as_str()),
            (0, false, "done\n")
        );
        let mut req = session(&["sleep", "30"], false);
        req.timeout_ms = 200;
        let mut s = open(&state(), req).await;
        let exit = s.exit().await;
        assert_eq!((exit.code, exit.timed_out), (137, true));
    }

    /// Plays the main process for a shutdown: a tracked child, waited for as `run` does.
    struct Main {
        pid: i32,
        status: tokio::task::JoinHandle<std::process::ExitStatus>,
    }

    fn main_process(st: &Arc<State>, script: &str) -> Main {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", script]);
        cmd.kill_on_drop(false);
        let mut tracked = TRACKED.lock().unwrap();
        let mut child = cmd.spawn().unwrap();
        let pid = child.id().unwrap() as i32;
        tracked.insert(pid);
        drop(tracked);
        *st.main_pid.lock().unwrap() = Some(pid);
        let st = st.clone();
        let status = tokio::spawn(async move {
            let status = child.wait().await.unwrap();
            untrack(pid);
            *st.main_pid.lock().unwrap() = None;
            st.main_done.notify_waiters();
            status
        });
        Main { pid, status }
    }

    #[tokio::test]
    async fn shutdown_terminates_the_main_process() {
        let st = state();
        let main = main_process(&st, "sleep 60");
        let f = roundtrip(
            &st,
            Request {
                op: "shutdown".into(),
                grace_sec: 5,
                ..Default::default()
            },
        )
        .await;
        assert_eq!(f[0].kind, "ok");
        assert!(
            *st.requested.lock().unwrap(),
            "the exit is marked as requested"
        );
        let status = main.status.await.unwrap();
        assert_eq!(status.signal(), Some(libc::SIGTERM), "{status:?}");
        assert_eq!(*st.main_pid.lock().unwrap(), None);
        assert!(matches!(proc_state(main.pid), None | Some('Z')));
    }

    #[tokio::test]
    async fn shutdown_kills_after_the_grace() {
        let st = state();
        // Ignores SIGTERM; exec keeps it one process so SIGKILL on the pid ends it all.
        let main = main_process(&st, "trap '' TERM; exec sleep 60");
        // Not before the trap is set and sleep is running, or SIGTERM lands on a shell
        // that still honours it.
        wait_until("the main process is sleep", || {
            fs::read_to_string(format!("/proc/{}/comm", main.pid))
                .map(|c| c.trim() == "sleep")
                .unwrap_or(false)
        });
        let start = Instant::now();
        let f = roundtrip(
            &st,
            Request {
                op: "shutdown".into(),
                grace_sec: 1,
                ..Default::default()
            },
        )
        .await;
        assert_eq!(f[0].kind, "ok");
        let status = main.status.await.unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL), "{status:?}");
        assert!(
            start.elapsed() >= Duration::from_secs(1),
            "the grace was given"
        );
    }

    #[tokio::test]
    async fn shutdown_with_no_main_process() {
        let st = state();
        let f = roundtrip(
            &st,
            Request {
                op: "shutdown".into(),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(f[0].kind, "ok");
        assert!(*st.requested.lock().unwrap());
    }

    // --- the reaper ---

    #[test]
    fn the_reaper_waits_until_a_tracked_child_is_collected() {
        // No such process: the tracked set alone is what is waited on.
        let pid = -4242;
        TRACKED.lock().unwrap().insert(pid);
        let (tx, rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            wait_tracked(|t| !t.contains(pid));
            tx.send(()).unwrap();
        });
        assert!(
            rx.recv_timeout(Duration::from_millis(100)).is_err(),
            "woke before the child was collected"
        );
        untrack(pid);
        rx.recv_timeout(Duration::from_secs(5))
            .expect("woke on the removal");
        waiter.join().unwrap();
    }

    // The orphan is left unwaited on purpose: reaping it is what the test checks.
    #[allow(clippy::zombie_processes)]
    #[test]
    fn reaper_leaves_tracked_children_and_reaps_orphans() {
        // Ours: still running, held by its stdin. The orphan: exits at once, nobody waits.
        let mut ours = spawn_tracked(
            std::process::Command::new("cat")
                .stdin(Stdio::piped())
                .stdout(Stdio::null()),
        );
        let our_pid = Pid::from_raw(ours.id() as i32);
        let orphan = {
            let tracked = TRACKED.lock().unwrap();
            let child = std::process::Command::new("true").spawn().unwrap();
            drop(tracked);
            Pid::from_raw(child.id() as i32)
            // `child` is dropped without a wait: a zombie until someone reaps it.
        };
        wait_until("the orphan exits", || {
            proc_state(orphan.as_raw()) == Some('Z')
        });

        // Another test's tracked child may be reported first; only an orphan gets reaped,
        // and the only orphan is ours.
        let start = Instant::now();
        loop {
            match reap_one() {
                Ok(Reaped::Orphan(p)) => {
                    assert_eq!(p, orphan);
                    break;
                }
                Ok(Reaped::Ours(p)) => assert_ne!(p, orphan),
                Ok(Reaped::Nothing) => {}
                Err(e) => panic!("{e}"),
            }
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "the orphan was not reaped"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            waitpid(orphan, Some(WaitPidFlag::WNOHANG)),
            Err(nix::errno::Errno::ECHILD),
            "reaped: nothing left to wait for"
        );

        // Now ours exits: the reaper sees it, names it, and leaves the status for us.
        drop(ours.stdin.take());
        wait_until("our child exits", || {
            proc_state(our_pid.as_raw()) == Some('Z')
        });
        let start = Instant::now();
        loop {
            match reap_one() {
                Ok(Reaped::Ours(p)) if p == our_pid => break,
                Ok(Reaped::Orphan(p)) => panic!("reaped {p}, which nobody here spawned"),
                Ok(_) => {}
                Err(e) => panic!("{e}"),
            }
            assert!(start.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(10));
        }
        // The status is still ours to collect.
        assert_eq!(waitpid(our_pid, None), Ok(WaitStatus::Exited(our_pid, 0)));
        untrack(our_pid.as_raw());
    }
}
