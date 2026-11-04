//! Filesystem control owns its descriptors on a dedicated, short-lived thread.
use super::*;
use std::sync::mpsc;

fn paths(cfg: &Config) -> Vec<String> {
    let mut paths = vec!["/".into()];
    paths.extend(
        cfg.mounts
            .iter()
            .filter(|m| !m.read_only)
            .map(|m| m.path.clone()),
    );
    paths.reverse();
    paths
}

struct Filesystems(Vec<(String, fs::File)>);
impl Filesystems {
    fn open(paths: Vec<String>) -> Result<Self> {
        let mut files = Vec::new();
        for path in paths {
            let file = fs::File::open(&path).with_context(|| format!("open filesystem {path}"))?;
            let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
            if unsafe { libc::fstatvfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
                return Err(std::io::Error::last_os_error()).context("filesystem flags");
            }
            if unsafe { stat.assume_init() }.f_flag & libc::ST_RDONLY == 0 {
                files.push((path, file));
            }
        }
        Ok(Self(files))
    }
    fn sync(&self) -> Result<()> {
        for (path, file) in &self.0 {
            if unsafe { libc::syncfs(file.as_raw_fd()) } != 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("sync {path}"));
            }
        }
        Ok(())
    }
    fn freeze(self) -> Result<Frozen> {
        let mut frozen = Frozen(Vec::new());
        for (path, file) in self.0 {
            // Linux asm-generic: _IOWR('X', 119, int).
            if unsafe { libc::ioctl(file.as_raw_fd(), 0xc0045877u32 as _, 0) } != 0 {
                let error = std::io::Error::last_os_error();
                let context = if error.raw_os_error() == Some(libc::EBUSY) {
                    format!("freeze {path}: already frozen or a configured mount shares an earlier filesystem; check mounted devices")
                } else {
                    format!("freeze {path}")
                };
                return Err(error).context(context);
            }
            frozen.0.push((path, file));
        }
        Ok(frozen)
    }
}
struct Frozen(Vec<(String, fs::File)>);
impl Frozen {
    fn thaw(&mut self) -> Result<()> {
        let mut error = None;
        self.0.retain(|(path, file)| {
            let rc = unsafe { libc::ioctl(file.as_raw_fd(), 0xc0045878u32 as _, 0) };
            let err = std::io::Error::last_os_error();
            if rc == 0 || err.raw_os_error() == Some(libc::EINVAL) {
                return false;
            }
            error = Some(anyhow!("thaw {path}: {err}"));
            true
        });
        error.map_or(Ok(()), Err)
    }
}
impl Drop for Frozen {
    fn drop(&mut self) {
        let _ = self.thaw();
    }
}
fn deadline(ms: u64) -> Duration {
    Duration::from_millis(if ms == 0 { 10_000 } else { ms.min(30_000) })
}
fn response(result: Result<()>) -> Response {
    match result {
        Ok(()) => Response::new("ok"),
        Err(e) => Response::error(format!("{e:#}")),
    }
}

pub(super) async fn serve<R, W>(
    cfg: &Config,
    input: R,
    output: Arc<tokio::sync::Mutex<W>>,
    req: Request,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    serve_paths(paths(cfg), input, output, req).await;
}

async fn serve_paths<R, W>(
    paths: Vec<String>,
    mut input: R,
    output: Arc<tokio::sync::Mutex<W>>,
    req: Request,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let is_sync = req.op == "fs_sync";
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let (thaw_tx, thaw_rx) = mpsc::channel::<()>();
    let worker = std::thread::spawn(move || {
        let files = Filesystems::open(paths);
        if req.op == "fs_sync" {
            let _ = ready_tx.send(response(files.and_then(|f| f.sync())));
            return;
        }
        let mut frozen = match files.and_then(Filesystems::freeze) {
            Ok(f) => f,
            Err(e) => {
                let _ = ready_tx.send(response(Err(e)));
                return;
            }
        };
        // Start after FIFREEZE has flushed and blocked writers, not before its flush.
        let until = std::time::Instant::now() + deadline(req.timeout_ms);
        let ack = Response {
            frozen: frozen.0.iter().map(|(p, _)| p.clone()).collect(),
            ..Response::new("ok")
        };
        if ready_tx.send(ack).is_err() {
            return;
        }
        let expired = matches!(
            thaw_rx.recv_timeout(until.saturating_duration_since(std::time::Instant::now())),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
        let mut result = response(frozen.thaw());
        result.thawed_by = if expired { "deadline" } else { "host" }.into();
        if expired && result.kind == "ok" {
            result = Response {
                thawed_by: "deadline".into(),
                ..Response::error("freeze expired")
            };
        }
        let _ = done_tx.send(result);
    });
    let Ok(ready) = ready_rx.await else {
        return;
    };
    // A sync or failed freeze worker has no held operation. Joining before ACK leaves
    // no idle blocking-pool worker in a sealed memory image.
    if ready.kind != "ok" || is_sync {
        drop(thaw_tx);
        let _ = worker.join();
        serve::send(&output, &ready).await;
        return;
    }
    // Bound sending the initial ACK as well: an unread connection cannot retain a freeze.
    tokio::select! {
        _ = serve::send(&output, &ready) => {},
        _ = tokio::time::sleep(Duration::from_secs(30)) => { drop(thaw_tx); return; }
    }
    let mut done_rx = done_rx;
    let result = tokio::select! {
        result = &mut done_rx => result.ok(),
        request = serve::read_request(&mut input) => {
            drop(thaw_tx);
            let result = done_rx.await.ok();
            match request { Ok(r) if r.op == "fs_thaw" => result, _ => None }
        }
    };
    let _ = worker.join();
    if let Some(result) = result {
        serve::send(&output, &result).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn barriers_admit_sync_without_activation_but_never_freeze() {
        for profile in [guest::INIT_READY_V1, guest::SANDBOX_READY_V1] {
            let gate = clone::Gate::from_config(&Config {
                template_profile: Some(profile.into()),
                ..Default::default()
            })
            .unwrap();
            assert!(gate.allows("fs_sync"));
            assert!(!gate.allows("fs_freeze"));
        }
    }
    #[test]
    fn writable_paths_skip_read_only_and_absent_volumes() {
        let mut cfg = Config::default();
        assert_eq!(paths(&cfg), ["/"]);
        cfg.mounts = vec![guest::Mount {
            device: "/dev/vdc".into(),
            path: "/absent-readonly".into(),
            fstype: "ext4".into(),
            read_only: true,
        }];
        assert_eq!(paths(&cfg), ["/"]);
        cfg.mounts.push(guest::Mount {
            path: "/work".into(),
            read_only: false,
            ..cfg.mounts[0].clone()
        });
        assert_eq!(paths(&cfg), ["/work", "/"]);
        assert_eq!(deadline(0), Duration::from_secs(10));
        assert_eq!(deadline(u64::MAX), Duration::from_secs(30));
    }

    #[tokio::test]
    async fn held_connection_protocol_deadline_close_and_sync_eof() {
        for mode in ["sync", "host", "deadline", "close", "invalid"] {
            let (mut client, server) = tokio::io::duplex(4096);
            let (input, output) = tokio::io::split(server);
            let task = tokio::spawn(serve_paths(
                vec![],
                input,
                Arc::new(tokio::sync::Mutex::new(output)),
                Request {
                    op: if mode == "sync" {
                        "fs_sync"
                    } else {
                        "fs_freeze"
                    }
                    .into(),
                    timeout_ms: if mode == "deadline" { 20 } else { 5000 },
                    ..Default::default()
                },
            ));
            assert_eq!(frame(&mut client).await.kind, "ok");
            match mode {
                "sync" => assert_eq!(client.read(&mut [0]).await.unwrap(), 0),
                "close" => drop(client),
                "invalid" => {
                    client
                        .write_all(
                            &guest::encode_frame(&Request {
                                op: "ping".into(),
                                ..Default::default()
                            })
                            .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
                }
                _ => {
                    if mode == "host" {
                        client
                            .write_all(
                                &guest::encode_frame(&Request {
                                    op: "fs_thaw".into(),
                                    ..Default::default()
                                })
                                .unwrap(),
                            )
                            .await
                            .unwrap();
                    }
                    let answer = tokio::time::timeout(Duration::from_secs(2), frame(&mut client))
                        .await
                        .unwrap();
                    assert_eq!(answer.thawed_by, mode);
                    assert_eq!(answer.kind, if mode == "host" { "ok" } else { "error" });
                }
            }
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap();
        }
    }

    struct LoopMount {
        dir: tempfile::TempDir,
    }
    impl LoopMount {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let disk = dir.path().join("disk");
            fs::File::create(&disk).unwrap().set_len(32 << 20).unwrap();
            assert!(std::process::Command::new("mkfs.ext4")
                .args(["-q", "-F"])
                .arg(&disk)
                .status()
                .unwrap()
                .success());
            fs::create_dir(dir.path().join("mnt")).unwrap();
            let mount = Self { dir };
            assert!(std::process::Command::new("mount")
                .args(["-o", "loop"])
                .arg(disk)
                .arg(mount.path())
                .status()
                .unwrap()
                .success());
            mount
        }
        fn path(&self) -> PathBuf {
            self.dir.path().join("mnt")
        }
    }
    impl Drop for LoopMount {
        fn drop(&mut self) {
            let _ = Filesystems::open(vec![self.path().to_string_lossy().into()])
                .map(|f| Frozen(f.0).thaw());
            let _ = std::process::Command::new("umount")
                .arg(self.path())
                .status();
        }
    }
    async fn frame(client: &mut tokio::io::DuplexStream) -> Response {
        let mut header = [0; 4];
        client.read_exact(&mut header).await.unwrap();
        let mut body = vec![0; u32::from_be_bytes(header) as usize];
        client.read_exact(&mut body).await.unwrap();
        guest::decode_frame(&body).unwrap()
    }
    async fn start(
        path: String,
        ms: u64,
    ) -> (tokio::io::DuplexStream, tokio::task::JoinHandle<()>) {
        let (mut client, server) = tokio::io::duplex(4096);
        let (input, output) = tokio::io::split(server);
        let task = tokio::spawn(serve_paths(
            vec![path],
            input,
            Arc::new(tokio::sync::Mutex::new(output)),
            Request {
                op: "fs_freeze".into(),
                timeout_ms: ms,
                ..Default::default()
            },
        ));
        assert_eq!(frame(&mut client).await.kind, "ok");
        (client, task)
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "root and loopback ext4; CI runs --ignored run_as"]
    async fn run_as_host_thaw_with_two_legacy_puts_blocked_on_frozen_ext4() {
        let mount = LoopMount::new();
        let (mut control, freeze) =
            start(mount.path().to_string_lossy().into_owned(), 10_000).await;
        let mut puts = Vec::new();
        let mut clients = Vec::new();
        for name in ["writer-one", "writer-two"] {
            let (mut client, server) = tokio::io::duplex(4096);
            puts.push(tokio::spawn(serve::handle(testutil::state(), server)));
            client
                .write_all(
                    &guest::encode_frame(&Request {
                        op: "put".into(),
                        path: mount.path().join(name).to_string_lossy().into_owned(),
                        data: b"written".to_vec(),
                        ..Default::default()
                    })
                    .unwrap(),
                )
                .await
                .unwrap();
            clients.push(client);
        }
        // Observe both writers in the kernel's freeze wait before sending host thaw.
        // The test's block_on thread remains independent of the two runtime workers.
        testutil::wait_until("two puts blocked by the filesystem freeze", || {
            fs::read_dir("/proc/self/task")
                .unwrap()
                .filter_map(|t| fs::read_to_string(t.ok()?.path().join("wchan")).ok())
                .filter(|w| {
                    w.contains("sb_start_write")
                        || w.contains("percpu_rwsem_wait")
                        || w.contains("rwsem_down_read_slowpath")
                })
                .count()
                >= 2
        });
        control
            .write_all(
                &guest::encode_frame(&Request {
                    op: "fs_thaw".into(),
                    ..Default::default()
                })
                .unwrap(),
            )
            .await
            .unwrap();
        let thaw = tokio::time::timeout(Duration::from_secs(3), frame(&mut control))
            .await
            .unwrap();
        assert_eq!(thaw.kind, "ok", "{}", thaw.message);
        assert_eq!(thaw.thawed_by, "host");
        freeze.await.unwrap();
        for mut client in clients {
            assert_eq!(frame(&mut client).await.kind, "ok");
        }
        for put in puts {
            put.await.unwrap();
        }
        for name in ["writer-one", "writer-two"] {
            assert_eq!(fs::read(mount.path().join(name)).unwrap(), b"written");
        }
    }

    #[tokio::test]
    #[ignore = "root and loopback ext4; CI runs --ignored run_as"]
    async fn run_as_filesystem_freeze_thaw_deadline_and_disconnect() {
        let mount = LoopMount::new();
        let path = mount.path().to_string_lossy().into_owned();
        let files = || Filesystems::open(vec![path.clone()]).unwrap();
        fs::write(mount.path().join("dirty"), b"durable").unwrap();
        files().sync().unwrap();
        // A later freeze failure must unwind the filesystem already frozen.
        let error = match Filesystems::open(vec![path.clone(), path.clone()])
            .unwrap()
            .freeze()
        {
            Ok(_) => panic!("duplicate filesystem unexpectedly froze twice"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("check mounted devices"));
        files().freeze().unwrap().thaw().unwrap();
        let mut already_thawed = files().freeze().unwrap();
        assert_eq!(
            unsafe { libc::ioctl(already_thawed.0[0].1.as_raw_fd(), 0xc0045878u32 as _, 0) },
            0
        );
        already_thawed.thaw().unwrap(); // EINVAL is success if the workload thawed it.
        for mode in ["host", "deadline", "disconnect"] {
            let (mut client, task) =
                start(path.clone(), if mode == "deadline" { 500 } else { 5000 }).await;
            assert!(
                files().freeze().is_err(),
                "held filesystem rejects another freeze"
            );
            if mode == "disconnect" {
                drop(client);
            } else {
                if mode == "host" {
                    client
                        .write_all(
                            &guest::encode_frame(&Request {
                                op: "fs_thaw".into(),
                                ..Default::default()
                            })
                            .unwrap(),
                        )
                        .await
                        .unwrap();
                }
                let answer = tokio::time::timeout(Duration::from_secs(2), frame(&mut client))
                    .await
                    .unwrap();
                assert_eq!(answer.thawed_by, mode);
                assert_eq!(answer.kind, if mode == "host" { "ok" } else { "error" });
            }
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap();
            files().freeze().unwrap().thaw().unwrap();
        }
    }
}
