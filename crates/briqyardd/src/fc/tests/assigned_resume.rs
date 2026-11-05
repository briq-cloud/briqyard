//! API-state evidence only. These tests do not qualify native process ownership.
use super::*;
const PAUSED: &str = "HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\n{\"state\":\"Paused\"}";
const RUNNING: &str = "HTTP/1.1 200 OK\r\nContent-Length: 19\r\n\r\n{\"state\":\"Running\"}";
const UNKNOWN: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
const FAILED: &str = "HTTP/1.1 500 Failed\r\nContent-Length: 0\r\n\r\n";
fn owned(dir: &Path, api: &Path) -> (Firecracker, Vm, watch::Sender<bool>) {
    let (gone, exited) = watch::channel(false);
    let (_, exit) = watch::channel(None);
    (
        Firecracker {
            launches: Default::default(),
            orphans: Default::default(),
            startup: Default::default(),
            binary: PathBuf::new(),
            jailer: PathBuf::new(),
            pci: false,
            console_max: 0,
            version: String::new(),
            identity: BootIdentity::ambiguous(LEGACY_PROFILE),
            classes: Default::default(),
            cpu_template: None,
        },
        Vm {
            #[cfg(target_os = "linux")]
            identity: None,
            pid: 42,
            api: api.into(),
            vsock: dir.join("vsock"),
            dir: dir.into(),
            chroot: None,
            resumed: true,
            boot_identity: None,
            incarnation: None,
            exited,
            exit,
            vmm_oom: Default::default(),
        },
        gone,
    )
}

#[tokio::test]
async fn assigned_resume_confirms_paused_and_running_without_relaxing_legacy_resume() {
    for paused in [true, false] {
        let (dir, path) = socket();
        let server = serve(
            &path,
            if paused {
                vec![PAUSED, NO_CONTENT, RUNNING]
            } else {
                vec![RUNNING, RUNNING]
            },
        );
        let (vmm, vm, _gone) = owned(dir.path(), &path);
        vmm.resume_assigned(&vm).await.unwrap();
        let seen = server.await.unwrap();
        assert!(seen[0].starts_with("GET / "));
        assert_eq!(
            seen.iter()
                .filter(|request| request.starts_with("PATCH /vm "))
                .count(),
            usize::from(paused)
        );
        if paused {
            assert_eq!(body(&seen[1])["state"], "Resumed");
        }
    }
    let (dir, path) = socket();
    let server = serve(&path, vec![RUNNING]);
    let (vmm, vm, _gone) = owned(dir.path(), &path);
    assert!(vmm.resume_paused(&vm).await.is_err());
    assert_eq!(server.await.unwrap().len(), 1);
}

#[tokio::test]
async fn assigned_resume_refuses_unknown_state_unconfirmed_running_and_exited_handles() {
    for responses in [vec![UNKNOWN], vec![PAUSED, NO_CONTENT, PAUSED]] {
        let (dir, path) = socket();
        let expected = responses.len();
        let server = serve(&path, responses);
        let (vmm, vm, _gone) = owned(dir.path(), &path);
        assert!(vmm.resume_assigned(&vm).await.is_err());
        assert_eq!(server.await.unwrap().len(), expected);
    }
    let (dir, path) = socket();
    let (vmm, vm, gone) = owned(dir.path(), &path);
    gone.send(true).unwrap();
    assert!(vmm.resume_assigned(&vm).await.is_err());
}

#[tokio::test]
async fn assigned_resume_uncertain_response_requires_explicit_actual_state_query_on_retry() {
    let (dir, path) = socket();
    let server = serve(&path, vec![PAUSED, FAILED, RUNNING, RUNNING]);
    let (vmm, vm, _gone) = owned(dir.path(), &path);
    assert!(vmm.resume_assigned(&vm).await.is_err());
    vmm.resume_assigned(&vm).await.unwrap();
    let seen = server.await.unwrap();
    assert_eq!(seen.len(), 4);
    assert!(seen[1].starts_with("PATCH /vm "));
    assert!(seen[2].starts_with("GET / "));
    assert!(seen[3].starts_with("GET / "));
}
