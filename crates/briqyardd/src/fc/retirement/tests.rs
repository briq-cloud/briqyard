use super::*;
use std::{fs, os::unix::fs::symlink};

struct Fixture {
    temp: tempfile::TempDir,
    path: std::path::PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("firecracker/m-owned");
        fs::create_dir_all(&path).unwrap();
        for directory in [temp.path(), path.parent().unwrap(), path.as_path()] {
            for name in ["cgroup.procs", "cgroup.threads"] {
                fs::write(directory.join(name), "").unwrap();
            }
        }
        fs::write(path.join("cgroup.procs"), "").unwrap();
        fs::write(path.join("cgroup.events"), "populated 0\nfrozen 0\n").unwrap();
        Self { temp, path }
    }
    fn held(&self) -> Leaf {
        Leaf::open(self.temp.path(), "m_owned").unwrap().unwrap()
    }
}

#[test]
fn refuses_live_frozen_or_ambiguous_control_evidence() {
    for (control, text) in [
        ("cgroup.procs", "42\n"),
        ("cgroup.events", "populated 1\nfrozen 0\n"),
        ("cgroup.events", "populated 0\nfrozen 1\n"),
        ("cgroup.events", "populated 0\n"),
        ("cgroup.events", "populated 0\npopulated 0\nfrozen 0\n"),
    ] {
        let f = Fixture::new();
        fs::write(f.path.join(control), text).unwrap();
        assert!(f.held().remove("m_owned").is_err());
        assert!(f.path.is_dir());
    }
}

#[test]
fn child_directories_and_symlinks_are_never_removed() {
    let f = Fixture::new();
    fs::create_dir(f.path.join("child")).unwrap();
    assert!(f.held().remove("m_owned").is_err());
    fs::remove_dir(f.path.join("child")).unwrap();
    symlink(f.temp.path(), f.path.join("foreign")).unwrap();
    assert!(f.held().remove("m_owned").is_err());
    assert!(f.path.join("foreign").symlink_metadata().is_ok());
}

#[test]
fn held_inode_and_parent_cannot_be_replaced() {
    for parent in [false, true] {
        let f = Fixture::new();
        let held = f.held();
        let old = if parent {
            f.path.parent().unwrap()
        } else {
            &f.path
        };
        fs::rename(old, f.temp.path().join("old")).unwrap();
        fs::create_dir_all(&f.path).unwrap();
        assert!(held.remove("m_owned").is_err());
        assert!(f.path.is_dir());
    }
}

#[test]
fn symlinked_ancestry_and_original_id_collisions_refuse() {
    let f = Fixture::new();
    assert!(f.held().remove("m-owned").is_err());
    for id in ["m-owned", "m_owned_more", "../m_owned", "m/owned", ""] {
        assert!(Leaf::open(f.temp.path(), id).is_err());
    }
    fs::rename(f.path.parent().unwrap(), f.temp.path().join("other")).unwrap();
    symlink(
        f.temp.path().join("other"),
        f.temp.path().join("firecracker"),
    )
    .unwrap();
    assert!(Leaf::open(f.temp.path(), "m_owned").is_err());
}

#[test]
fn nonrecursive_kernel_removal_failure_retains_everything() {
    let f = Fixture::new();
    // Ordinary fixture files deliberately do not simulate virtual cgroup controls:
    // the real rmdir must fail rather than unlinking them to make the test pass.
    assert!(f.held().remove("m_owned").is_err());
    assert!(f.path.join("cgroup.events").is_file());
    assert!(f.path.join("cgroup.procs").is_file());
}

#[test]
fn empty_checked_leaf_passes_policy_before_kernel_rmdir() {
    let f = Fixture::new();
    f.held().check("m_owned").unwrap();
}

#[test]
fn final_counter_snapshot_requires_cpu_memory_and_local_oom_evidence() {
    let f = Fixture::new();
    for (name, text) in [
        ("cpu.stat", "usage_usec 730\n"),
        ("memory.current", "42\n"),
        (
            "memory.events.local",
            "oom 3\noom_kill 2\noom_group_kill 1\n",
        ),
    ] {
        fs::write(f.path.join(name), text).unwrap();
    }
    let usage = f.held().final_usage("m_owned").unwrap();
    assert_eq!(usage.cpu_usec, 730);
    assert_eq!(usage.memory_bytes, 42);
    for (name, text) in [
        ("cpu.stat", "usage_usec 730\nusage_usec 730\n"),
        ("memory.current", "unavailable"),
        ("memory.events.local", "oom 3\noom_kill 2\n"),
    ] {
        let original = fs::read(f.path.join(name)).unwrap();
        fs::write(f.path.join(name), text).unwrap();
        assert!(f.held().final_usage("m_owned").is_err());
        assert!(f.path.is_dir());
        fs::write(f.path.join(name), original).unwrap();
    }
}

#[test]
fn absent_leaf_still_requires_valid_existing_ancestor_membership() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    // Only this owned ordinary-directory fixture is removed; no kernel cgroup is used.
    fs::remove_dir_all(&f.path).unwrap();
    fs::set_permissions(
        f.temp.path().join("cgroup.procs"),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    assert!(Leaf::open(f.temp.path(), "m_owned").is_err());
    fs::set_permissions(
        f.temp.path().join("cgroup.procs"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    fs::remove_file(f.path.parent().unwrap().join("cgroup.threads")).unwrap();
    assert!(Leaf::open(f.temp.path(), "m_owned").is_err());
    fs::write(f.path.parent().unwrap().join("cgroup.threads"), "").unwrap();
    assert!(Leaf::open(f.temp.path(), "m_owned").unwrap().is_none());
}

#[test]
fn empty_leaf_refuses_ancestor_membership_drift_after_capture() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let held = f.held();
    fs::set_permissions(
        f.temp.path().join("cgroup.procs"),
        fs::Permissions::from_mode(0o662),
    )
    .unwrap();
    assert!(held.remove("m_owned").is_err());
    assert!(f.path.is_dir());
    fs::set_permissions(
        f.temp.path().join("cgroup.procs"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let held = f.held();
    let parent = f.path.parent().unwrap();
    fs::rename(parent.join("cgroup.threads"), parent.join("old_threads")).unwrap();
    symlink(parent.join("old_threads"), parent.join("cgroup.threads")).unwrap();
    assert!(held.remove("m_owned").is_err());
    assert!(f.path.is_dir());
}
