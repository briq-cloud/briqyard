//! Firecracker's client, process and VMM.

use super::*;
use tokio::net::UnixListener;

#[test]
fn the_vmm_version_is_firecrackers_and_the_kernels() {
    let out = "Firecracker v1.17.0\n\nSupported snapshot data format versions: v8.0.0\n";
    assert_eq!(
        version_of(out, "6.8.0-45-generic\n"),
        Some("v1.17.0/6.8.0-45-generic".into())
    );
    assert_eq!(version_of("jailer v1.17.0\n", "6.8.0"), None);
    assert_eq!(version_of("", "6.8.0"), None);
    assert_eq!(version_of("Firecracker \n", "6.8.0"), None);
}

/// A stand-in for Firecracker's API socket: answers each connection with the next canned
/// response and hands back the requests it read, in order. Within 10 s: a client that
/// never sends what it waits on fails its test, the socket closed.
fn serve(socket: &Path, responses: Vec<&'static str>) -> tokio::task::JoinHandle<Vec<String>> {
    let ln = UnixListener::bind(socket).unwrap();
    let serve = async move {
        let mut seen = Vec::new();
        for resp in responses {
            let (mut s, _) = ln.accept().await.unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = s.read(&mut buf).await.unwrap();
                req.extend_from_slice(&buf[..n]);
                if n == 0 || complete(&req) {
                    break;
                }
            }
            seen.push(String::from_utf8(req).unwrap());
            s.write_all(resp.as_bytes()).await.unwrap();
        }
        seen
    };
    tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(10), serve)
            .await
            .expect("the stand-in waited 10 s")
    })
}

/// Whether the head and the body announced by Content-Length are all there.
fn complete(req: &[u8]) -> bool {
    let Some(end) = req.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&req[..end]).to_ascii_lowercase();
    let len: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    req.len() >= end + 4 + len
}

fn body(req: &str) -> serde_json::Value {
    let (_, b) = req.split_once("\r\n\r\n").unwrap();
    serde_json::from_str(b).unwrap()
}

fn socket() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api.sock");
    (dir, path)
}

const NO_CONTENT: &str =
    "HTTP/1.1 204 No Content\r\nServer: Firecracker API\r\nConnection: keep-alive\r\n\r\n";

#[tokio::test]
async fn put_sends_json_and_takes_204() {
    let (_dir, path) = socket();
    let server = serve(&path, vec![NO_CONTENT]);
    Client::new(&path).machine_config(2, 512).await.unwrap();
    let seen = server.await.unwrap();
    let req = &seen[0];
    assert!(req.starts_with("PUT /machine-config HTTP/1.1\r\n"), "{req}");
    assert!(
        req.contains("\r\nContent-Type: application/json\r\n"),
        "{req}"
    );
    assert!(req.contains("\r\nConnection: close\r\n"), "{req}");
    let b = body(req);
    assert_eq!(
        b,
        serde_json::json!({"vcpu_count": 2, "mem_size_mib": 512, "smt": false})
    );
    let len: usize = req
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length: "))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(len, b.to_string().len());
}

#[tokio::test]
async fn every_call_has_its_path_and_body() {
    let (_dir, path) = socket();
    let server = serve(&path, vec![NO_CONTENT; 13]);
    let c = Client::new(&path);
    c.boot_source(Path::new("/vmlinux"), "console=ttyS0")
        .await
        .unwrap();
    c.drive("rootfs", Path::new("/root"), true, false, "Writeback", None)
        .await
        .unwrap();
    c.network_interface("eth0", "tm1", "06:b1:0a:40:00:02")
        .await
        .unwrap();
    c.vsock(3, Path::new("/vsock.sock")).await.unwrap();
    c.start().await.unwrap();
    c.pause().await.unwrap();
    c.resume().await.unwrap();
    c.snapshot_create(Path::new("/snap.state"), Path::new("/snap.mem"), false)
        .await
        .unwrap();
    c.snapshot_load(
        Path::new("/snap.state"),
        Path::new("/snap.mem"),
        "eth0",
        "tm1",
    )
    .await
    .unwrap();
    let rate = DiskRate {
        bandwidth_mb: 2,
        iops: 100,
        burst_sec: 3,
    };
    c.drive(
        "data",
        Path::new("/data"),
        false,
        false,
        "Writeback",
        Some(&rate),
    )
    .await
    .unwrap();
    c.drive_rate("data", &DiskRate::default()).await.unwrap();
    c.metrics(Path::new("/metrics.fifo")).await.unwrap();
    c.drive(
        "config",
        Path::new("/config.tar"),
        false,
        true,
        "Unsafe",
        None,
    )
    .await
    .unwrap();
    let seen = server.await.unwrap();
    let first = |i: usize| seen[i].lines().next().unwrap().to_string();
    assert_eq!(first(0), "PUT /boot-source HTTP/1.1");
    assert_eq!(
        body(&seen[0]),
        serde_json::json!({"kernel_image_path": "/vmlinux", "boot_args": "console=ttyS0"})
    );
    assert_eq!(first(1), "PUT /drives/rootfs HTTP/1.1");
    assert_eq!(
        body(&seen[1]),
        serde_json::json!({"drive_id": "rootfs", "path_on_host": "/root", "is_root_device": true, "is_read_only": false, "cache_type": "Writeback", "discard": true})
    );
    assert_eq!(first(2), "PUT /network-interfaces/eth0 HTTP/1.1");
    assert_eq!(
        body(&seen[2]),
        serde_json::json!({"iface_id": "eth0", "host_dev_name": "tm1", "guest_mac": "06:b1:0a:40:00:02"})
    );
    assert_eq!(first(3), "PUT /vsock HTTP/1.1");
    assert_eq!(
        body(&seen[3]),
        serde_json::json!({"guest_cid": 3, "uds_path": "/vsock.sock"})
    );
    assert_eq!(first(4), "PUT /actions HTTP/1.1");
    assert_eq!(
        body(&seen[4]),
        serde_json::json!({"action_type": "InstanceStart"})
    );
    assert_eq!(first(5), "PATCH /vm HTTP/1.1");
    assert_eq!(body(&seen[5]), serde_json::json!({"state": "Paused"}));
    assert_eq!(first(6), "PATCH /vm HTTP/1.1");
    assert_eq!(body(&seen[6]), serde_json::json!({"state": "Resumed"}));
    assert_eq!(first(7), "PUT /snapshot/create HTTP/1.1");
    assert_eq!(body(&seen[7])["snapshot_type"], "Full");
    assert_eq!(body(&seen[7])["sync_snapshot_files"], false);
    assert_eq!(first(8), "PUT /snapshot/load HTTP/1.1");
    let load = body(&seen[8]);
    assert_eq!(load["resume_vm"], true);
    assert_eq!(load["mem_backend"]["backend_path"], "/snap.mem");
    assert_eq!(load["network_overrides"][0]["host_dev_name"], "tm1");
    // A limited drive: buckets a second deep, the burst given once.
    assert_eq!(first(9), "PUT /drives/data HTTP/1.1");
    assert_eq!(
        body(&seen[9])["rate_limiter"],
        serde_json::json!({
            "bandwidth": {"size": 2 << 20, "one_time_burst": 3 * (2 << 20), "refill_time": 1000},
            "ops": {"size": 100, "one_time_burst": 300, "refill_time": 1000},
        })
    );
    // No limit is buckets of size 0, which Firecracker reads as none: a PATCH lifts them.
    assert_eq!(first(10), "PATCH /drives/data HTTP/1.1");
    assert_eq!(
        body(&seen[10]),
        serde_json::json!({"drive_id": "data", "rate_limiter": {
            "bandwidth": {"size": 0, "one_time_burst": 0, "refill_time": 1000},
            "ops": {"size": 0, "one_time_burst": 0, "refill_time": 1000},
        }})
    );
    assert_eq!(first(11), "PUT /metrics HTTP/1.1");
    assert_eq!(
        body(&seen[11]),
        serde_json::json!({"metrics_path": "/metrics.fifo"})
    );
    // A writable drive takes discards (ADR 0037); a read-only one cannot.
    assert_eq!(body(&seen[9])["discard"], true);
    assert_eq!(
        body(&seen[12]),
        serde_json::json!({"drive_id": "config", "path_on_host": "/config.tar", "is_root_device": false, "is_read_only": true, "cache_type": "Unsafe"})
    );
}

#[test]
fn disk_io_adds_what_each_metrics_line_grew_by() {
    let io = DiskIo::default();
    let line = |r: u64, w: u64, t: u64| {
        serde_json::json!({
            "utc_timestamp_ms": 1,
            "block": {"read_bytes": r, "write_bytes": w, "rate_limiter_throttled_events": t},
            "block_rootfs": {"read_bytes": r, "write_bytes": w, "rate_limiter_throttled_events": t},
        })
        .to_string()
    };
    io.add(&line(4096, 0, 0));
    io.add(&line(0, 1 << 20, 7));
    io.add("{\"block\": {\"read_b"); // a torn line adds nothing
    io.add(&serde_json::json!({"api_server": {}}).to_string());
    let got = |c: &AtomicU64| c.load(Relaxed);
    assert_eq!(
        (
            got(&io.read_bytes),
            got(&io.write_bytes),
            got(&io.throttled)
        ),
        (4096, 1 << 20, 7)
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_metrics_pipe_is_read_until_the_process_ends() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(METRICS_FIFO);
    nix::unistd::mkfifo(&path, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
    let io = Arc::new(DiskIo::default());
    let (done_tx, done) = watch::channel(false);
    read_metrics(&path, io.clone(), done).unwrap();
    // Firecracker opens it as it does: read and write, non-blocking.
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut fc = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&path)
        .unwrap();
    for t in [2, 3] {
        let l = serde_json::json!({"block": {"rate_limiter_throttled_events": t}});
        writeln!(fc, "{l}").unwrap();
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while io.throttled.load(Relaxed) < 5 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(io.throttled.load(Relaxed), 5);
    // Once the process is gone the reader stops: later lines are not counted.
    done_tx.send(true).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    writeln!(
        fc,
        "{}",
        serde_json::json!({"block": {"rate_limiter_throttled_events": 9}})
    )
    .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(io.throttled.load(Relaxed), 5);
}

#[tokio::test]
async fn a_fault_is_an_api_error() {
    let (_dir, path) = socket();
    let fault = r#"{"fault_message":"The requested operation is not supported after starting the microVM."}"#;
    let resp = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{fault}",
            fault.len()
        );
    let server = serve(&path, vec![Box::leak(resp.into_boxed_str())]);
    let err = Client::new(&path).start().await.unwrap_err();
    let api = err.downcast_ref::<ApiError>().expect("an ApiError");
    assert_eq!(api.status, 400);
    assert_eq!(
        api.fault,
        "The requested operation is not supported after starting the microVM."
    );
    assert_eq!(err.to_string(), format!("firecracker: 400 {}", api.fault));
    server.await.unwrap();
}

#[tokio::test]
async fn a_fault_that_is_not_json_keeps_the_body() {
    let (_dir, path) = socket();
    let server = serve(
        &path,
        vec!["HTTP/1.1 500 Internal Server Error\r\nContent-Length: 6\r\n\r\nboom!\n"],
    );
    let err = Client::new(&path).start().await.unwrap_err();
    let api = err.downcast_ref::<ApiError>().unwrap();
    assert_eq!((api.status, api.fault.as_str()), (500, "boom!\n"));
    server.await.unwrap();
}

#[tokio::test]
async fn info_reads_the_json_answer() {
    let (_dir, path) = socket();
    let info = r#"{"id":"m-1","state":"Running","vmm_version":"1.10.0"}"#;
    let resp = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{info}",
        info.len()
    );
    let server = serve(&path, vec![Box::leak(resp.into_boxed_str())]);
    let v = Client::new(&path).info().await.unwrap();
    assert_eq!(v["state"], "Running");
    let seen = server.await.unwrap();
    assert!(seen[0].starts_with("GET / HTTP/1.1\r\n"), "{}", seen[0]);
    assert!(seen[0].contains("Content-Length: 0\r\n"), "{}", seen[0]);
    assert!(seen[0].ends_with("\r\n\r\n"), "{}", seen[0]);
}

#[tokio::test]
async fn a_bad_status_line_is_an_error() {
    let (_dir, path) = socket();
    let server = serve(&path, vec!["nonsense\r\n\r\n"]);
    let err = Client::new(&path).info().await.unwrap_err();
    assert!(err.to_string().contains("bad status line"), "{err}");
    server.await.unwrap();
}

#[tokio::test]
async fn wait_api_gives_up_without_a_socket() {
    let (_dir, path) = socket();
    let t0 = std::time::Instant::now();
    let err = Client::new(&path)
        .wait_api(Duration::from_millis(100))
        .await
        .unwrap_err();
    assert!(t0.elapsed() >= Duration::from_millis(100));
    let msg = err.to_string();
    assert!(msg.contains("did not answer within"), "{msg}");
    assert!(msg.contains("connect"), "{msg}");
}

#[tokio::test]
async fn wait_api_returns_once_the_api_answers() {
    let (_dir, path) = socket();
    let server = serve(
        &path,
        vec!["HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"],
    );
    Client::new(&path)
        .wait_api(Duration::from_secs(5))
        .await
        .unwrap();
    server.await.unwrap();
}

#[test]
fn adoption_checks() {
    // Only a Firecracker carrying the machine's id is ours: the binary by any path, the
    // id as the jailer spells it.
    let fc = b"/usr/local/bin/firecracker\0--id\0m-abc123\0--api-sock\0/run/api.sock\0";
    assert_eq!(firecracker_id(fc).as_deref(), Some("m_abc123"));
    assert_eq!(
        firecracker_id(b"firecracker\0--id\0m-x\0").as_deref(),
        Some("m_x")
    );
    assert_eq!(firecracker_id(b"firecracker\0--api-sock\0/x\0"), None);
    assert_eq!(firecracker_id(b"/usr/bin/jailer\0--id\0m-abc123\0"), None);
    assert_eq!(
        firecracker_id(b"/bin/sh\0-c\0firecracker --id m-abc123\0"),
        None
    );
    assert_eq!(firecracker_id(b""), None);
    // This process is not a Firecracker (and there is no /proc on a Mac): never killed.
    assert_eq!(machine_of(std::process::id()), None);
    assert!(api_running(
        &serde_json::json!({"id": "m-1", "state": "Running", "vmm_version": "1.10"})
    ));
    assert!(!api_running(&serde_json::json!({"state": "Paused"})));
    assert!(!api_running(&serde_json::json!({"state": "Not started"})));
    assert!(!api_running(&serde_json::json!({})));
}

#[test]
fn cpu_time_from_cpu_stat() {
    let stat = "usage_usec 1234567\nuser_usec 1000000\nsystem_usec 234567\nnr_periods 0\n";
    assert_eq!(cpu_usec(stat), Some(1_234_567));
    assert_eq!(cpu_usec("user_usec 5\n"), None);
    assert_eq!(cpu_usec("usage_usec x\n"), None);
}

#[test]
fn jail_paths() {
    let base = Path::new("/var/lib/briqyard/jail");
    // Firecracker takes only letters, digits and dashes in an id.
    assert_eq!(fc_id("m_abc123"), "m-abc123");
    assert_eq!(
        jail_root(base, "m_abc123"),
        PathBuf::from("/var/lib/briqyard/jail/firecracker/m-abc123/root")
    );
    // The stats are read where the jailer, told the same parent, puts the cgroup.
    assert_eq!(
        cgroup_dir("m_abc123"),
        PathBuf::from("/sys/fs/cgroup/firecracker/m-abc123")
    );
    let dir = Path::new("/var/lib/briqyard/run/m_abc123");
    // A memory snapshot is where Firecracker wrote it: the chroot when jailed.
    assert_eq!(
        snapshot_files(dir, None, "m_abc123"),
        [dir.join("snap.state"), dir.join("snap.mem")]
    );
    let root = jail_root(base, "m_abc123");
    assert_eq!(
        snapshot_files(dir, Some(base), "m_abc123"),
        [root.join("snap.state"), root.join("snap.mem")]
    );
    // Snapshots with memory beside the chroot, out of the jailer's cleaning (ADR 0031).
    assert_eq!(memory_dir(dir, None, "m_abc123"), dir.join("snapshots"));
    assert_eq!(
        memory_dir(dir, Some(base), "m_abc123"),
        root.parent().unwrap().join("snapshots")
    );
    assert_eq!(
        paths(dir),
        (
            dir.join("api.sock"),
            dir.join("vsock.sock"),
            dir.join("console.log"),
            dir.join("firecracker.log")
        )
    );
    assert_eq!(paths_for(dir, None, "m_abc123"), paths(dir));
    let jail = Jail {
        jailer: "/usr/local/bin/jailer".into(),
        base: base.to_path_buf(),
        uid: 100_002,
        gid: 100_002,
        cpus: 1,
        memory_mb: 512,
    };
    let root = jail_root(base, "m_abc123");
    assert_eq!(
        paths_for(dir, Some(&jail), "m_abc123"),
        (
            root.join("run/firecracker.socket"),
            root.join("vsock.sock"),
            dir.join("console.log"),
            dir.join("firecracker.log")
        )
    );
}

#[test]
fn the_exit_socket_is_next_to_the_vsock_socket() {
    // Firecracker's convention for a guest connection to host port P: `<uds_path>_P`.
    assert_eq!(
        exit_socket(Path::new("/run/m_1/vsock.sock")),
        PathBuf::from("/run/m_1/vsock.sock_7422")
    );
    assert_eq!(
        exit_socket(Path::new("/jail/firecracker/m-1/root/vsock.sock")),
        PathBuf::from("/jail/firecracker/m-1/root/vsock.sock_7422")
    );
}

#[tokio::test]
async fn the_exit_listener_takes_one_frame_then_closes() {
    let dir = tempfile::tempdir().unwrap();
    let vsock = dir.path().join("vsock.sock");
    let (done_tx, done) = watch::channel(false);
    let mut rx = listen_exit(&vsock, 0, 0, done).unwrap();
    assert!(rx.borrow().is_none());
    // The guest's connection, as Firecracker brings it to the host.
    let mut s = UnixStream::connect(exit_socket(&vsock)).await.unwrap();
    let report = guest::ExitReport {
        code: 7,
        requested: true,
        ..Default::default()
    };
    s.write_all(&guest::encode_frame(&report).unwrap())
        .await
        .unwrap();
    s.shutdown().await.unwrap();
    rx.wait_for(|r| r.is_some()).await.unwrap();
    assert_eq!(rx.borrow().as_ref(), Some(&report));
    // The host closed after the frame, and the listener is done: the channel closes.
    assert_eq!(s.read(&mut [0u8; 8]).await.unwrap(), 0);
    assert!(rx.changed().await.is_err());
    drop(done_tx);
}

#[tokio::test]
async fn the_exit_listener_ends_with_the_process() {
    let dir = tempfile::tempdir().unwrap();
    let vsock = dir.path().join("vsock.sock");
    let (done_tx, done) = watch::channel(false);
    let mut rx = listen_exit(&vsock, 0, 0, done).unwrap();
    // No connection ever: the process is gone, the channel closes with nothing in it.
    done_tx.send(true).unwrap();
    assert!(rx.wait_for(|r| r.is_some()).await.is_err());
    assert!(rx.borrow().is_none());
    // Bound again on the same path, as an adoption does.
    let (done_tx, done) = watch::channel(false);
    listen_exit(&vsock, 0, 0, done).unwrap();
    // A path that cannot be bound is an error, not a panic.
    assert!(listen_exit(
        Path::new("/nonexistent/dir/v.sock"),
        0,
        0,
        done_tx.subscribe()
    )
    .is_err());
}

#[test]
fn inside_and_outside() {
    let dir = Path::new("/run/m_1");
    let root = Path::new("/jail/firecracker/m-1/root");
    assert_eq!(
        inside_path(None, dir, "snap.mem"),
        PathBuf::from("/run/m_1/snap.mem")
    );
    assert_eq!(
        outside_path(None, dir, "snap.mem"),
        PathBuf::from("/run/m_1/snap.mem")
    );
    assert_eq!(
        inside_path(Some(root), dir, "snap.mem"),
        PathBuf::from("/snap.mem")
    );
    assert_eq!(
        outside_path(Some(root), dir, "snap.mem"),
        PathBuf::from("/jail/firecracker/m-1/root/snap.mem")
    );
}

#[test]
fn the_jailer_is_told_the_cgroup_parent_and_the_limits() {
    let jail = Jail {
        jailer: "/usr/local/bin/jailer".into(),
        base: "/var/lib/briqyard/jail".into(),
        uid: 100_002,
        gid: 100_002,
        cpus: 2,
        memory_mb: 768,
    };
    let args: Vec<String> = jailer_args(&jail, "m_abc123", Path::new("/usr/local/bin/firecracker"))
        .into_iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        args,
        [
            "--id",
            "m-abc123",
            "--exec-file",
            "/usr/local/bin/firecracker",
            "--uid",
            "100002",
            "--gid",
            "100002",
            "--chroot-base-dir",
            "/var/lib/briqyard/jail",
            "--cgroup-version",
            "2",
            "--parent-cgroup",
            CGROUP_PARENT,
            "--new-pid-ns",
            "--cgroup",
            "cpu.max=200000 100000",
            "--cgroup",
            "cpu.weight=200",
            "--cgroup",
            "memory.max=805306368",
        ]
    );
    // No limit, no cgroup argument.
    let free = Jail {
        cpus: 0,
        memory_mb: 0,
        ..jail
    };
    let args = jailer_args(&free, "m_abc123", Path::new("/fc"));
    assert!(!args.iter().any(|a| a == "--cgroup"), "{args:?}");
}

#[test]
fn the_pid_file_is_read_once_and_must_be_there() {
    let root = tempfile::tempdir().unwrap();
    let err = jailed_pid(root.path()).unwrap_err();
    assert!(format!("{err:#}").contains("firecracker.pid"), "{err:#}");
    std::fs::write(root.path().join("firecracker.pid"), "nope\n").unwrap();
    let err = jailed_pid(root.path()).unwrap_err();
    assert!(format!("{err:#}").contains("\"nope\\n\""), "{err:#}");
    std::fs::write(root.path().join("firecracker.pid"), "4242\n").unwrap();
    assert_eq!(jailed_pid(root.path()).unwrap(), 4242);
}

#[test]
fn placing_a_file_in_the_jail() {
    use std::os::unix::fs::PermissionsExt;
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir_all(&root).unwrap();
    let host = dir.path().join("vmlinux");
    std::fs::write(&host, b"kernel").unwrap();
    std::fs::set_permissions(&host, std::fs::Permissions::from_mode(0o644)).unwrap();
    // Not root: the chown fails and is ignored; the link is what matters.
    let inside = place_file(&root, &host, "vmlinux", 100_000, 100_000).unwrap();
    assert_eq!(inside, PathBuf::from("/vmlinux"));
    assert_eq!(std::fs::read(root.join("vmlinux")).unwrap(), b"kernel");
    // Read-only for Firecracker; a shared kernel stays readable by all.
    assert_eq!(mode(&root.join("vmlinux")), 0o444);
    // A new file of the same name replaces the earlier one.
    let host2 = dir.path().join("config.tar");
    std::fs::write(&host2, b"v2").unwrap();
    place_file(&root, &host2, "vmlinux", 100_000, 100_000).unwrap();
    assert_eq!(std::fs::read(root.join("vmlinux")).unwrap(), b"v2");
    // A config drive, written for the daemon alone, is the jail's user's alone.
    std::fs::set_permissions(&host2, std::fs::Permissions::from_mode(0o600)).unwrap();
    place_file(&root, &host2, "config.tar", 100_000, 100_000).unwrap();
    assert_eq!(mode(&root.join("config.tar")), 0o400);
    // A host file that does not exist cannot be placed.
    let err = place_file(&root, &dir.path().join("missing"), "x", 0, 0).unwrap_err();
    assert!(err.to_string().contains("into the jail"), "{err}");
}

#[tokio::test]
async fn console_lines_are_stamped() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("console.log");
    let f = crate::console::Writer::open(dir.path(), 1 << 20)
        .await
        .unwrap();
    let out = std::sync::Arc::new(tokio::sync::Mutex::new(f));
    stamp(&b"one\ntwo"[..], out).await;
    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text:?}");
    for (line, want) in lines.iter().zip(["one", "two"]) {
        let (ts, rest) = line.split_once(' ').unwrap();
        chrono::DateTime::parse_from_rfc3339(ts).unwrap();
        assert_eq!(rest, want);
    }
    // The last line gets its newline even when the source had none.
    assert!(text.ends_with("two\n"));
}
