//! Pure typed-supervision and owned-filesystem fixtures, never a host service probe.
use super::{
    fs::{Dir, Owner},
    unit,
};
use std::{fs, os::unix::fs::symlink};

fn hooks() -> unit::Hooks {
    let mut hooks = unit::Hooks::empty();
    for name in unit::HOOKS {
        hooks
            .observe(name, r#"{"type":"a(sasbttttuii)","data":[]}"#)
            .unwrap();
    }
    hooks
}
fn properties() -> String {
    unit::PROPERTIES.split(',').map(|key| {
        let value=match key {
            "Id"=>"briqyardd.service","LoadState"=>"loaded","ActiveState"=>"active","SubState"=>"running",
            "MainPID"=>"42","ControlPID"=>"0","ControlGroup"=>unit::GROUP,"InvocationID"=>"0123456789abcdef0123456789abcdef",
            "KillMode"=>"process","Delegate"=>"no","Type"=>"simple","RemainAfterExit"=>"no","NeedDaemonReload"=>"no","Slice"=>"system.slice",
            "FragmentPath"=>"/etc/systemd/system/briqyardd.service",
            "ExecStart"=>"{ path=/usr/local/bin/briqyardd ; argv[]=/usr/local/bin/briqyardd --config /etc/briqyard/config.yaml ; ignore_errors=no ; start_time=n/a ; stop_time=n/a ; pid=42 ; code=(null) ; status=0/0 }",
            _=>"",
        };format!("{key}={value}\n")
    }).collect()
}
#[test]
fn supported_first_upgrade_uses_typed_current_supervision_not_a_fictional_old_lock() {
    // There is deliberately no legacy-lock flag or historical-attestation field.
    let id = unit::validate(&properties(), 42, &hooks()).unwrap();
    assert_eq!(id.pid, 42);
    for (old, new) in [
        ("MainPID=42", "MainPID=43"),
        ("KillMode=process", "KillMode=control-group"),
        ("Delegate=no", "Delegate=yes"),
        ("Type=simple", "Type=forking"),
        ("DropInPaths=", "DropInPaths=/unknown.conf"),
        ("NeedDaemonReload=no", "NeedDaemonReload=yes"),
        (
            "InvocationID=0123456789abcdef0123456789abcdef",
            "InvocationID=00000000000000000000000000000000",
        ),
        (
            "path=/usr/local/bin/briqyardd",
            "path=/usr/local/bin/wrapper",
        ),
    ] {
        assert!(
            unit::validate(&properties().replace(old, new), 42, &hooks()).is_err(),
            "{old}"
        );
    }
    let changed = unit::validate(
        &properties().replace(
            "0123456789abcdef0123456789abcdef",
            "1123456789abcdef0123456789abcdef",
        ),
        42,
        &hooks(),
    )
    .unwrap();
    assert_ne!(id, changed);
}
#[test]
fn missing_and_duplicate_properties_are_unresolved() {
    assert!(unit::validate(&properties().replace("ControlPID=0\n", ""), 42, &hooks()).is_err());
    assert!(unit::validate(&(properties() + "MainPID=42\n"), 42, &hooks()).is_err());
    assert!(unit::validate(&properties(), 42, &unit::Hooks::empty()).is_err());
}
#[test]
fn hook_absence_never_means_empty_and_typed_arrays_are_closed() {
    for json in [
        r#"{"type":"a(sasbttttuii)"}"#,
        r#"{"data":[]}"#,
        r#"{"type":"a(sasbttttuii)","data":[],"data":[]}"#,
        r#"{"type":"a(sasbttttuii)","data":[],"extra":0}"#,
        r#"{"type":"s","data":[]}"#,
        r#"{"type":"a(sasbttttuii)","data":[null]}"#,
    ] {
        assert!(unit::Hooks::empty().observe("ExecStartPre", json).is_err());
    }
    let mut hooks = unit::Hooks::empty();
    hooks
        .observe("ExecStartPre", r#"{"type":"a(sasbttttuii)","data":[]}"#)
        .unwrap();
    assert!(hooks
        .observe("ExecStartPre", r#"{"type":"a(sasbttttuii)","data":[]}"#)
        .is_err());
}
#[test]
fn configured_jailer_and_vmm_lineage_must_both_be_supported() {
    unit::jailer_version("Jailer v1.17.0\n", "v1.17.0/kernel").unwrap();
    for (j, v) in [
        ("Jailer v1.16.0", "v1.17.0/kernel"),
        ("Jailer v1.17.0", "v1.16.0/kernel"),
        ("wrapper v1.17.0", "v1.17.0/kernel"),
        ("Jailer v1.17.0\nextra", "v1.17.0/kernel"),
    ] {
        assert!(unit::jailer_version(j, v).is_err());
    }
}
#[test]
fn service_inventory_rejects_preexec_prejoin_helpers_children_and_ambiguous_pids() {
    for text in ["42\n43\n", "43\n", "42\n42\n", "42\n0\n", "unreadable"] {
        assert!(unit::final_service_members(text, 42, false).is_err());
    }
    unit::final_service_members("42\n", 42, false).unwrap();
    assert!(unit::final_service_members("42\n", 42, true).is_err());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let dir = Dir::absolute(&path).unwrap();
    dir.owned(
        Owner {
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        },
        true,
    )
    .unwrap();
    fs::write(path.join("cgroup.procs"), "42\n").unwrap();
    assert!(!dir.has_directories().unwrap());
    fs::create_dir(path.join("child")).unwrap();
    assert!(dir.has_directories().unwrap());
    fs::remove_dir(path.join("child")).unwrap();
    symlink(&path, path.join("child")).unwrap();
    assert!(dir.has_directories().unwrap());
    assert!(dir.child(c"child").is_err());
    assert!(dir.text(c"missing", 4096).is_err());
    fs::write(path.join("oversized"), vec![b'x'; 4097]).unwrap();
    assert!(dir.bytes(c"oversized", 4096).is_err());
}

#[test]
fn self_start_identity_distinguishes_reused_pids_without_name_inference() {
    let stat = |start: &str| {
        let mut fields = vec!["0"; 20];
        fields[0] = "S";
        fields[19] = start;
        format!("42 (daemon name) {}", fields.join(" "))
    };
    assert_eq!(unit::self_start(&stat("123")).unwrap(), 123);
    assert_ne!(
        unit::self_start(&stat("123")).unwrap(),
        unit::self_start(&stat("124")).unwrap()
    );
    assert!(unit::self_start("42 (daemon name) S").is_err());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_start_outside_the_official_unit_names_the_check_that_failed() {
    // Whatever runs this test is not briqyardd.service: the barrier refuses, and the
    // error says which check, not only the errno of the last system call.
    let Err(error) = super::native::Barrier::acquire().await else {
        panic!("a test process passed the supervision barrier");
    };
    let chain: Vec<String> = error.chain().map(|e| e.to_string()).collect();
    assert!(chain.len() >= 2, "no context on {chain:?}");
    assert!(!chain[0].contains("os error"), "bare errno: {chain:?}");
}

#[test]
fn a_host_with_thousands_of_idle_leaves_lists_and_a_runaway_directory_says_so() {
    // The barrier refused a host that held 6408 empty machine cgroups left by earlier
    // versions with a bare EINVAL: the listing cap was 4096 and said nothing.
    let temp = tempfile::tempdir().unwrap();
    for i in 0..5000 {
        fs::create_dir(temp.path().join(format!("m-{i:012x}"))).unwrap();
    }
    let dir = Dir::absolute(&temp.path().canonicalize().unwrap()).unwrap();
    let error = dir.children(4096).unwrap_err();
    assert!(
        error.to_string().contains("more than 4096 entries"),
        "no reason on {error}"
    );
    assert_eq!(dir.children(65_536 + 1024).unwrap().len(), 5000);
}

#[tokio::test(start_paused = true)]
async fn service_wait_observes_exit_and_fork_without_admitting_survivors() {
    let mut samples = vec![vec![42, 43], vec![42, 43, 44], vec![42, 44], vec![42]].into_iter();
    unit::wait_service(42, || Ok((samples.next().unwrap(), false)))
        .await
        .unwrap();
    assert!(samples.next().is_none());
    assert!(unit::wait_service(42, || Ok((vec![43], false)))
        .await
        .is_err());
    assert!(unit::wait_service(42, || Ok((vec![42], true)))
        .await
        .is_err());
    assert!(
        unit::wait_service(42, || Err(std::io::Error::other("unreadable")))
            .await
            .is_err()
    );
}

#[tokio::test(start_paused = true)]
async fn service_wait_timeout_is_closed_and_names_survivors() {
    let began = tokio::time::Instant::now();
    let err = unit::wait_service(42, || Ok((vec![42, 43], false)))
        .await
        .unwrap_err();
    assert_eq!(began.elapsed(), std::time::Duration::from_secs(10));
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert!(err.to_string().contains("43"));
    assert!(unit::final_service_pids(&[42, 43], 42, false).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn exited_unreaped_children_are_absent_from_cgroup_procs() {
    use std::process::Command;
    let mut child = Command::new("/bin/true").spawn().unwrap();
    let pid = child.id();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        if stat
            .rsplit_once(')')
            .unwrap()
            .1
            .trim_start()
            .starts_with('Z')
        {
            break;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("child did not exit");
        }
        std::thread::yield_now();
    }
    let group = std::fs::read_to_string("/proc/self/cgroup").unwrap();
    let result = std::fs::read_to_string(format!(
        "/sys/fs/cgroup{}/cgroup.procs",
        group.trim().strip_prefix("0::").unwrap()
    ));
    child.wait().unwrap();
    // Some container test runners hide their own cgroup mount. Native CI exposes it.
    if let Ok(members) = result {
        assert!(!super::fs::pids(&members).unwrap().contains(&pid));
    }
}

#[tokio::test(start_paused = true)]
async fn background_service_wait_survives_timeouts_without_clearing_or_restarting() {
    let began = tokio::time::Instant::now();
    unit::await_service_settlement(42, || {
        Ok((
            if began.elapsed() < std::time::Duration::from_secs(75) {
                vec![42, 43]
            } else {
                vec![42]
            },
            false,
        ))
    })
    .await
    .unwrap();
    assert_eq!(began.elapsed(), std::time::Duration::from_secs(75));
    assert!(unit::await_service_settlement(42, || Ok((vec![42], true)))
        .await
        .is_err());
}

#[tokio::test(start_paused = true)]
async fn repeated_timeout_then_clean_restarts_cannot_exhaust_five_starts_in_ten_seconds() {
    let began = tokio::time::Instant::now();
    for _ in 0..5 {
        assert!(unit::wait_service(42, || Ok((vec![42, 43], false)))
            .await
            .is_err());
        unit::await_service_settlement(42, || Ok((vec![42], false)))
            .await
            .unwrap();
    }
    assert_eq!(began.elapsed(), std::time::Duration::from_secs(50));
}
