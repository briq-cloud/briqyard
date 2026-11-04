//! Runtime classes (ADR 0088): what a machine of a class boots, and what it refuses.

use super::*;
use crate::config::RuntimeClass;
use crate::machine::classes as machine_classes;
use crate::machine::start::config_drive;

async fn classes_harness() -> Harness {
    let h = harness_config(|c| {
        c.network.range = "10.64.0.0/22".into();
        c.capacity.memory_mb = 4096;
        c.runtime_classes.insert(
            "nested".into(),
            RuntimeClass {
                kernel: "/classes/nested/vmlinux".into(),
                modules: Some("/classes/nested/modules.ext4".into()),
                release: "6.18.54-briqyard-nested".into(),
                versions: None,
                nested: true,
            },
        );
        c.runtime_classes.insert(
            "plain".into(),
            RuntimeClass {
                kernel: "/classes/plain/vmlinux".into(),
                ..Default::default()
            },
        );
    })
    .await;
    h.ready().await;
    h
}

fn of_class(h: &Harness, name: &str, class: &str) -> api::CreateMachineRequest {
    api::CreateMachineRequest {
        runtime_class: class.into(),
        ..h.request(name)
    }
}

fn boot_of(h: &Harness, id: &str) -> fc::Boot {
    h.host.boots_seen.lock().unwrap().get(id).unwrap().clone()
}

#[tokio::test]
async fn a_class_the_host_does_not_serve_is_refused_by_name() {
    let h = classes_harness().await;
    let err =
        h.m.create_made(of_class(&h, "a", "gvisor"))
            .await
            .unwrap_err();
    assert_eq!(
        err.to_string(),
        "invalid request: runtime class gvisor is not served by this host"
    );
    assert!(matches!(err, MError::Invalid(_)));
    // Naming the default is the same as naming nothing.
    let m = h.m.create_made(of_class(&h, "b", "default")).await.unwrap();
    assert_eq!(m.runtime_class, "default");
    assert!(h.stored(&m.id).unwrap().runtime_class.is_empty());
}

#[tokio::test]
async fn a_machine_boots_its_classs_kernel_modules_and_template() {
    let h = classes_harness().await;
    let default = h.m.create_made(h.request("d")).await.unwrap();
    let plain = h.m.create_made(of_class(&h, "p", "plain")).await.unwrap();
    let nested = h.m.create_made(of_class(&h, "n", "nested")).await.unwrap();
    assert_eq!(nested.runtime_class, "nested");
    let d = boot_of(&h, &default.id);
    assert_eq!(d.kernel, h.m.inner.cfg.kernel);
    assert!(d.modules.is_none() && !d.virtualization);
    let p = boot_of(&h, &plain.id);
    assert_eq!(p.kernel, PathBuf::from("/classes/plain/vmlinux"));
    assert!(p.modules.is_none() && !p.virtualization);
    let n = boot_of(&h, &nested.id);
    assert_eq!(n.kernel, PathBuf::from("/classes/nested/vmlinux"));
    assert_eq!(
        n.modules.as_deref(),
        Some(Path::new("/classes/nested/modules.ext4"))
    );
    assert!(
        n.virtualization,
        "a nested class boots without the template"
    );
    // The boot identity is the class's own: its kernel, and no CPU template.
    let identity = |id: &str| h.stored(id).unwrap().boot_identity.unwrap();
    assert_eq!(identity(&default.id).cpu_config, "test-template");
    assert_eq!(identity(&nested.id).cpu_config, "none");
    assert_eq!(identity(&nested.id).kernel_sha256, "nested-kernel-digest");
    assert_eq!(identity(&plain.id).cpu_config, "test-template");
    assert_eq!(identity(&plain.id).kernel_sha256, "plain-kernel-digest");
    assert_eq!(n.boot_identity, h.stored(&nested.id).unwrap().boot_identity);
}

#[test]
fn the_modules_drive_follows_the_volume_in_the_guest_config() {
    // Firecracker names disks in the order it is given them: root, config, volume, modules.
    assert_eq!(machine_classes::modules_device(false), "/dev/vdc");
    assert_eq!(machine_classes::modules_device(true), "/dev/vdd");
}

#[tokio::test]
async fn the_guest_mounts_the_modules_read_only_at_their_release() {
    let h = classes_harness().await;
    let mut rec = record();
    rec.runtime_class = "nested".into();
    let with_volume = h.m.modules_mount(&rec).unwrap();
    assert_eq!(with_volume.device, "/dev/vdd");
    assert_eq!(with_volume.path, "/lib/modules/6.18.54-briqyard-nested");
    assert!(with_volume.read_only);
    rec.volume = None;
    assert_eq!(h.m.modules_mount(&rec).unwrap().device, "/dev/vdc");
    // A class without modules, and the default, mount nothing.
    rec.runtime_class = "plain".into();
    assert!(h.m.modules_mount(&rec).is_none());
    rec.runtime_class.clear();
    assert!(h.m.modules_mount(&rec).is_none());
    // The mount is in the config drive the boot reads, after the volume's.
    let mut rec = record();
    rec.runtime_class = "nested".into();
    let drive = config_drive(&rec, Ipv4Addr::new(10, 64, 1, 1), h.m.modules_mount(&rec)).unwrap();
    let mut tar = tar::Archive::new(std::io::Cursor::new(drive));
    let mut entry = tar.entries().unwrap().next().unwrap().unwrap();
    let cfg: guest::Config = serde_json::from_reader(&mut entry).unwrap();
    let devices: Vec<_> = cfg
        .mounts
        .iter()
        .map(|m| (m.device.as_str(), m.read_only))
        .collect();
    assert_eq!(devices, [("/dev/vdc", false), ("/dev/vdd", true)]);
}

#[tokio::test]
async fn a_stop_with_suspend_is_a_plain_stop_for_a_nested_machine() {
    let h = classes_harness().await;
    let n = h.m.create_made(of_class(&h, "n", "nested")).await.unwrap();
    let d = h.m.create_made(h.request("d")).await.unwrap();
    let stopped = h.m.stop(&n.id, Duration::ZERO, true, None).await.unwrap();
    assert_eq!(stopped.state, state::STOPPED);
    assert!(!stopped.suspended);
    assert!(!h.stored(&n.id).unwrap().suspended);
    assert!(h.events_of(&n.id).iter().any(|e| e
        .message
        .contains("suspend: refused (runtime class nested)")));
    assert!(!h.reasons(&n.id).iter().any(|r| r == reason::SUSPENDED));
    // A default machine on the same host still suspends.
    assert!(
        h.m.stop(&d.id, Duration::ZERO, true, None)
            .await
            .unwrap()
            .suspended
    );
    // A wake is a cold boot.
    h.m.start(&n.id, None).await.unwrap();
    assert!(!h.m.get(&n.id).unwrap().suspended);
    assert!(!boot_of(&h, &n.id).resume);
}

#[tokio::test]
async fn a_memory_snapshot_of_a_nested_machine_is_refused_naming_the_class() {
    let h = classes_harness().await;
    let n = h.m.create_made(of_class(&h, "n", "nested")).await.unwrap();
    let req = |memory| api::SnapshotRequest {
        consistency: None,
        name: None,
        memory,
        template: false,
    };
    let err = h.m.snapshot(&n.id, req(true)).await.unwrap_err();
    assert!(matches!(err, MError::Refused(_)), "{err}");
    assert!(err.to_string().contains("runtime class nested"), "{err}");
    // Its disks snapshot as any machine's.
    h.m.snapshot(&n.id, req(false)).await.unwrap();
}

#[tokio::test]
async fn a_fork_takes_its_sources_class_and_names_no_other() {
    let h = classes_harness().await;
    let n = h.m.create_made(of_class(&h, "n", "nested")).await.unwrap();
    let fork = |name: &str, class: &str| api::CreateMachineRequest {
        fork: Some(api::ForkSpec {
            consistency: None,
            machine_id: n.id.clone(),
            copy: String::new(),
            snapshot: None,
        }),
        image: String::new(),
        runtime_class: class.into(),
        start: Some(false),
        ..h.request(name)
    };
    let child = h.m.create_made(fork("child", "")).await.unwrap();
    assert_eq!(child.runtime_class, "nested");
    let named = h.m.create_made(fork("named", "nested")).await.unwrap();
    assert_eq!(named.runtime_class, "nested");
    let err = h.m.create_made(fork("other", "plain")).await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "invalid request: a fork keeps its source's runtime class (nested), and the request says plain"
    );
    let err = h.m.create_made(fork("dflt", "default")).await.unwrap_err();
    assert!(err.to_string().contains("keeps its source's"), "{err}");
}

#[tokio::test]
async fn a_memory_fork_of_a_nested_source_and_a_warm_slot_in_a_class_are_refused() {
    let h = classes_harness().await;
    let n = h.m.create_made(of_class(&h, "n", "nested")).await.unwrap();
    let memory = api::CreateMachineRequest {
        fork: Some(api::ForkSpec {
            consistency: None,
            machine_id: n.id.clone(),
            copy: String::new(),
            snapshot: Some("s".into()),
        }),
        image: String::new(),
        ..h.request("mf")
    };
    let err = h.m.create_made(memory).await.unwrap_err();
    assert!(
        matches!(err, MError::Refused(_)) || err.to_string().contains("snapshot"),
        "{err}"
    );
    let seed = api::CreateMachineRequest {
        sandbox_seed: Some(api::SandboxSeed {
            machine_id: "m_x".into(),
            snapshot: "s".into(),
            generation: "g".into(),
            request_id: "r".into(),
        }),
        ..of_class(&h, "seed", "nested")
    };
    assert!(h.m.create_made(seed).await.is_err());
    let build = api::CreateMachineRequest {
        template_build: Some("init-ready-v1".into()),
        ..of_class(&h, "build", "plain")
    };
    let err = h.m.create_made(build).await.unwrap_err();
    assert!(err.to_string().contains("default runtime class"), "{err}");
}

/// Only `nested` takes no memory snapshot (ADR 0088): the one rule a memory snapshot, a
/// suspend and a memory fork all ask, naming the class.
#[tokio::test]
async fn only_a_nested_class_refuses_memory() {
    let h = classes_harness().await;
    let refusal = |class: &str| {
        let rec = Record {
            runtime_class: class.into(),
            ..super::record()
        };
        h.m.memory_refusal(&rec)
    };
    assert_eq!(refusal(""), None);
    assert_eq!(refusal("plain"), None);
    assert_eq!(refusal("nested").as_deref(), Some("runtime class nested"));
}

#[test]
fn a_restore_and_a_fork_inherit_unless_the_request_agrees() {
    assert_eq!(
        machine_classes::inherited("", "nested", "a fork", "its source's").unwrap(),
        "nested"
    );
    assert_eq!(
        machine_classes::inherited("nested", "nested", "a fork", "its source's").unwrap(),
        "nested"
    );
    assert_eq!(
        machine_classes::inherited("", "", "a fork", "its source's").unwrap(),
        ""
    );
    let err = machine_classes::inherited("nested", "", "a restore", "the backup's").unwrap_err();
    assert_eq!(
        err.to_string(),
        "invalid request: a restore keeps the backup's runtime class (default), and the request says nested"
    );
}

#[tokio::test]
async fn a_record_of_a_class_the_host_no_longer_serves_does_not_start() {
    let h = classes_harness().await;
    let n = h.m.create_made(of_class(&h, "n", "nested")).await.unwrap();
    h.m.stop(&n.id, Duration::ZERO, false, None).await.unwrap();
    // The configuration dropped the class while the machine slept.
    let e = h.m.entry(&n.id).unwrap();
    e.rec.lock().unwrap().runtime_class = "gone".into();
    let err = h.m.start(&n.id, None).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("runtime class gone is not served by this host"),
        "{err}"
    );
}

#[tokio::test]
async fn the_classes_a_host_serves_are_listed() {
    let h = classes_harness().await;
    let names: Vec<_> =
        h.m.runtime_classes()
            .into_iter()
            .map(|c| (c.name, c.nested, c.kernel_release))
            .collect();
    assert_eq!(
        names,
        [
            (
                "nested".to_string(),
                true,
                "6.18.54-briqyard-nested".to_string()
            ),
            ("plain".to_string(), false, String::new()),
        ]
    );
}

#[test]
fn versions_come_from_the_classs_versions_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("versions.json");
    std::fs::write(
        &path,
        r#"{"kernel_release":"6.18.54-briqyard-nested","kernel":"6.18.54","openzfs":"2.4.1","arch":"x86_64"}"#,
    )
    .unwrap();
    let mut cfg = Config::default();
    cfg.runtime_classes.insert(
        "nested".into(),
        RuntimeClass {
            kernel: "/k".into(),
            versions: Some(path.clone()),
            nested: true,
            ..Default::default()
        },
    );
    let infos = machine_classes::infos(&cfg).unwrap();
    assert_eq!(infos[0].openzfs, "2.4.1");
    assert_eq!(infos[0].kernel_release, "6.18.54-briqyard-nested");
    std::fs::write(&path, "not json").unwrap();
    assert!(machine_classes::infos(&cfg).is_err());
}
