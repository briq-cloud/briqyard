use super::*;
use crate::store::Store;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Barrier, Mutex};

fn fail() -> io::Error {
    io::Error::other("injected storage failure")
}
fn target() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("identity");
    (directory, path)
}

#[test]
fn publication_faults_preserve_the_correct_visible_generation() {
    for stage in [
        Stage::ParentOpen,
        Stage::TemporaryCreate,
        Stage::Write,
        Stage::FileSync,
        Stage::Rename,
        Stage::ParentSync,
    ] {
        let (_directory, path) = target();
        std::fs::write(&path, b"old").unwrap();
        let publisher = Publisher::with_check(move |current, _| {
            if current == stage {
                Err(fail())
            } else {
                Ok(())
            }
        });
        let error = publisher.publish(&path, b"new").unwrap_err();
        let uncertain = matches!(stage, Stage::Rename | Stage::ParentSync);
        assert_eq!(
            matches!(error, PublicationError::Uncertain { .. }),
            uncertain,
            "{stage:?}: {error}"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            if stage == Stage::ParentSync {
                b"new"
            } else {
                b"old"
            }
        );
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1
        );
    }
}

#[test]
fn a_partial_write_never_replaces_the_old_target() {
    let (_directory, path) = target();
    std::fs::write(&path, b"old").unwrap();
    let publisher = Publisher::with_check(|stage, temporary| {
        if stage == Stage::Write {
            std::fs::write(temporary, b"par")?;
            return Err(fail());
        }
        Ok(())
    });
    assert!(matches!(
        publisher.publish(&path, b"new"),
        Err(PublicationError::NotPublished {
            stage: Stage::Write,
            ..
        })
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"old");
    assert_eq!(
        std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
        1
    );
}

#[test]
fn rename_that_took_effect_but_reported_failure_is_uncertain() {
    let (_directory, path) = target();
    std::fs::write(&path, b"old").unwrap();
    let destination = path.clone();
    let publisher = Publisher::with_check(move |stage, temporary| {
        if stage == Stage::Rename {
            std::fs::rename(temporary, &destination)?;
            return Err(fail());
        }
        Ok(())
    });
    assert!(matches!(
        publisher.publish(&path, b"new"),
        Err(PublicationError::Uncertain {
            stage: Stage::Rename,
            ..
        })
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"new");
    Publisher::default().confirm(&path, b"new").unwrap();
}

#[test]
fn barriers_order_content_before_replacement_before_directory() {
    let (_directory, path) = target();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let events = seen.clone();
    let publisher = Publisher::with_check(move |stage, _| {
        events.lock().unwrap().push(stage);
        Ok(())
    });
    publisher.publish(&path, b"value").unwrap();
    assert_eq!(
        *seen.lock().unwrap(),
        [
            Stage::ParentOpen,
            Stage::TemporaryCreate,
            Stage::Write,
            Stage::FileSync,
            Stage::Rename,
            Stage::ParentSync
        ]
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn exclusive_temporary_collision_never_takes_over_or_removes_a_foreign_file() {
    for symlink in [false, true] {
        let (_directory, path) = target();
        let victim = path.with_file_name("foreign");
        std::fs::write(&victim, b"untouched").unwrap();
        let victim_copy = victim.clone();
        let collision = Arc::new(Mutex::new(None));
        let collision_copy = collision.clone();
        let publisher = Publisher::with_check(move |stage, temporary| {
            if stage == Stage::TemporaryCreate {
                *collision_copy.lock().unwrap() = Some(temporary.to_path_buf());
                if symlink {
                    std::os::unix::fs::symlink(&victim_copy, temporary)?;
                } else {
                    std::fs::write(temporary, b"foreign temporary")?;
                }
            }
            Ok(())
        });
        assert!(matches!(
            publisher.publish(&path, b"new"),
            Err(PublicationError::NotPublished {
                stage: Stage::TemporaryCreate,
                ..
            })
        ));
        assert!(!path.exists());
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        assert!(std::fs::symlink_metadata(collision.lock().unwrap().as_ref().unwrap()).is_ok());
    }
}

#[test]
fn publications_use_distinct_private_temporaries_and_ignore_old_temporaries() {
    let (_directory, path) = target();
    let stale = path.with_file_name(".publish-old.tmp");
    std::fs::write(&stale, b"leftover").unwrap();
    let names = Arc::new(Mutex::new(Vec::new()));
    let copy = names.clone();
    let publisher = Publisher::with_check(move |stage, path| {
        if stage == Stage::Write {
            assert_eq!(std::fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
            copy.lock().unwrap().push(path.to_path_buf());
        }
        Ok(())
    });
    publisher.publish(&path, b"one").unwrap();
    publisher.publish(&path, b"two").unwrap();
    let names = names.lock().unwrap();
    assert_ne!(names[0], names[1]);
    assert_eq!(std::fs::read(stale).unwrap(), b"leftover");
}

#[test]
fn confirmation_cannot_replace_newer_bytes_or_accept_inode_replacement() {
    let (_directory, path) = target();
    Publisher::default().publish(&path, b"newer").unwrap();
    assert!(matches!(
        Publisher::default().confirm(&path, b"older"),
        Err(PublicationError::Conflict)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"newer");
    for stage in [Stage::ConfirmSync, Stage::ConfirmCheck] {
        let publisher = Publisher::with_check(move |current, path| {
            if current == stage {
                let other = path.with_file_name("replacement");
                std::fs::write(&other, b"newer")?;
                std::fs::rename(other, path)?;
            }
            Ok(())
        });
        assert!(matches!(
            publisher.confirm(&path, b"newer"),
            Err(PublicationError::Conflict)
        ));
    }
}

#[test]
fn confirmation_rejects_in_place_mutation_and_symlink_targets() {
    let (_directory, path) = target();
    std::fs::write(&path, b"original").unwrap();
    let publisher = Publisher::with_check(|stage, path| {
        if stage == Stage::ConfirmCheck {
            std::fs::write(path, b"changed")?;
        }
        Ok(())
    });
    assert!(matches!(
        publisher.confirm(&path, b"original"),
        Err(PublicationError::Conflict)
    ));
    let link = path.with_file_name("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(Publisher::default().confirm(&link, b"changed").is_err());
}

#[test]
fn confirmation_never_accepts_equal_bytes_when_a_barrier_fails() {
    for stage in [
        Stage::ParentOpen,
        Stage::ConfirmOpen,
        Stage::ConfirmSync,
        Stage::ParentSync,
        Stage::ConfirmCheck,
    ] {
        let (_directory, path) = target();
        std::fs::write(&path, b"same").unwrap();
        let publisher = Publisher::with_check(move |current, _| {
            if current == stage {
                Err(fail())
            } else {
                Ok(())
            }
        });
        assert!(matches!(
            publisher.confirm(&path, b"same"),
            Err(PublicationError::Uncertain { .. })
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"same");
    }
}

#[test]
fn post_rename_failure_retains_identity_and_existing_startup_repairs_it() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("state");
    let failing = Publisher::with_check(|stage, _| {
        if stage == Stage::ParentSync {
            Err(fail())
        } else {
            Ok(())
        }
    });
    let store = Store::open_using(&root, failing).unwrap();
    assert!(store.establish_host_id(|| "h_original".into()).is_err());
    assert_eq!(
        std::fs::read(root.join("meta/host_id.json")).unwrap(),
        b"h_original"
    );
    assert!(store
        .establish_host_id(|| panic!("must not generate a replacement identity"))
        .is_err());
    let checked = Arc::new(Mutex::new(Vec::new()));
    let copy = checked.clone();
    let repaired = Store::open_using(
        &root,
        Publisher::with_check(move |stage, _| {
            if matches!(stage, Stage::ConfirmSync | Stage::ParentSync) {
                copy.lock().unwrap().push(stage);
            }
            Ok(())
        }),
    )
    .unwrap();
    assert_eq!(
        repaired
            .establish_host_id(|| panic!("existing identity"))
            .unwrap(),
        "h_original"
    );
    assert_eq!(
        *checked.lock().unwrap(),
        [Stage::ConfirmSync, Stage::ParentSync]
    );
}

#[test]
fn existing_raw_identity_is_exact_and_not_a_json_string() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let raw = "h_legacy\n";
    store.put_meta("host_id", raw).unwrap();
    assert_eq!(store.establish_host_id(|| panic!("existing")).unwrap(), raw);
    assert_eq!(
        std::fs::read(directory.path().join("meta/host_id.json")).unwrap(),
        raw.as_bytes()
    );
}

#[test]
fn every_directory_barrier_failure_blocks_open_and_is_repaired_on_retry() {
    // First capture the real barriers. Then fail each distinct occurrence, not just one
    // convenient mkdir. Retrying sees whatever prefix the failed open already created.
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path().join("a/b/state");
    let observed = Arc::new(Mutex::new(Vec::new()));
    let copy = observed.clone();
    Store::open_using(
        &root,
        Publisher::with_check(move |stage, path| {
            if matches!(stage, Stage::DirectorySync | Stage::DirectoryParentSync) {
                copy.lock().unwrap().push((stage, path.to_path_buf()));
            }
            Ok(())
        }),
    )
    .unwrap();
    let barriers = observed.lock().unwrap().len();
    for fail_at in 0..barriers {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("a/b/state");
        let count = AtomicUsize::new(0);
        let fault = Publisher::with_check(move |stage, _| {
            if matches!(stage, Stage::DirectorySync | Stage::DirectoryParentSync)
                && count.fetch_add(1, Ordering::SeqCst) == fail_at
            {
                return Err(fail());
            }
            Ok(())
        });
        assert!(
            Store::open_using(&root, fault).is_err(),
            "barrier {fail_at}"
        );
        let seen = Arc::new(AtomicUsize::new(0));
        let copy = seen.clone();
        Store::open_using(
            &root,
            Publisher::with_check(move |stage, _| {
                if matches!(stage, Stage::DirectorySync | Stage::DirectoryParentSync) {
                    copy.fetch_add(1, Ordering::SeqCst);
                }
                Ok(())
            }),
        )
        .unwrap();
        assert_eq!(
            seen.load(Ordering::SeqCst),
            barriers,
            "retry barrier {fail_at}"
        );
    }
}

#[test]
fn directory_creation_and_mode_failures_also_refuse_initialization() {
    for fail_stage in [Stage::DirectoryCreate, Stage::DirectoryMode] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap().join("state");
        let expected = root.clone();
        let publisher = Publisher::with_check(move |stage, path| {
            if path == expected && stage == fail_stage {
                return Err(fail());
            }
            Ok(())
        });
        assert!(Store::open_using(&root, publisher).is_err());
        Store::open(&root).unwrap();
    }
}

#[test]
fn initialization_does_not_change_existing_ancestor_permissions() {
    let directory = tempfile::tempdir().unwrap();
    let parent = directory.path().join("parent");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o750)).unwrap();
    let root = parent.join("new/state");
    Store::open(&root).unwrap();
    assert_eq!(
        std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
        0o750
    );
    for path in [parent.join("new"), root.clone(), root.join("meta")] {
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}

#[test]
fn a_store_or_identity_lock_symlink_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let link = directory.path().join("linked");
    std::os::unix::fs::symlink(directory.path(), &link).unwrap();
    assert!(Store::open(&link).is_err());
    let root = directory.path().join("state");
    let store = Store::open(&root).unwrap();
    let victim = directory.path().join("foreign");
    std::fs::write(&victim, b"unchanged").unwrap();
    std::os::unix::fs::symlink(&victim, root.join("meta/host-id.lock")).unwrap();
    assert!(store.establish_host_id(|| panic!("lock failed")).is_err());
    assert_eq!(std::fs::read(victim).unwrap(), b"unchanged");
}

#[test]
fn concurrent_initializers_generate_only_one_identity() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let start = Arc::new(Barrier::new(8));
    let generated = Arc::new(AtomicUsize::new(0));
    let identities: Vec<_> = std::thread::scope(|scope| {
        let mut threads = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            let start = start.clone();
            let generated = generated.clone();
            threads.push(scope.spawn(move || {
                start.wait();
                store
                    .establish_host_id(|| format!("h_{}", generated.fetch_add(1, Ordering::SeqCst)))
                    .unwrap()
            }));
        }
        threads.into_iter().map(|t| t.join().unwrap()).collect()
    });
    assert!(identities.iter().all(|id| id == "h_0"));
    assert_eq!(generated.load(Ordering::SeqCst), 1);
}

#[test]
fn generic_record_writes_keep_their_existing_error_contract() {
    let directory = tempfile::tempdir().unwrap();
    let publisher = Publisher::with_check(|_, _| Err(fail()));
    // Construct directly: strict startup failure must not alter the legacy write helper.
    let store = Store {
        root: directory.path().to_path_buf(),
        publisher,
    };
    std::fs::create_dir(directory.path().join("meta")).unwrap();
    store.put_meta("ordinary", "raw").unwrap();
    assert_eq!(store.get_meta("ordinary").unwrap().as_deref(), Some("raw"));
}

#[test]
fn directory_retry_does_not_treat_existence_as_durability() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("state");
    Store::open(&root).unwrap();
    let faulted = Arc::new(AtomicBool::new(false));
    let copy = faulted.clone();
    let meta = root.join("meta");
    let publisher = Publisher::with_check(move |stage, path| {
        if stage == Stage::DirectoryParentSync && path == meta {
            copy.store(true, Ordering::SeqCst);
            return Err(fail());
        }
        Ok(())
    });
    assert!(Store::open_using(&root, publisher).is_err());
    assert!(faulted.load(Ordering::SeqCst));
}

#[test]
fn cleanup_does_not_delete_a_replaced_temporary() {
    let (_directory, path) = target();
    let replacement = Arc::new(Mutex::new(None));
    let copy = replacement.clone();
    let publisher = Publisher::with_check(move |stage, path| {
        if stage == Stage::FileSync {
            std::fs::rename(path, path.with_extension("retained"))?;
            std::fs::write(path, b"foreign replacement")?;
            *copy.lock().unwrap() = Some(path.to_path_buf());
            return Err(fail());
        }
        Ok(())
    });
    assert!(publisher.publish(&path, b"candidate").is_err());
    assert!(!path.exists());
    assert_eq!(
        std::fs::read(replacement.lock().unwrap().as_ref().unwrap()).unwrap(),
        b"foreign replacement"
    );
}

// The child is the same test binary, so the workspace's parent-death guard applies too.
// It has its own short bound and no access to any state outside its disposable fixture.
#[test]
fn initializer_child_process() {
    use std::io::Write;
    let Some(root) = std::env::var_os("BRIQYARD_TEST_IDENTITY_ROOT") else {
        return;
    };
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(6));
        std::process::exit(102);
    });
    let root = PathBuf::from(root);
    let store = Store::open(&root).unwrap();
    let probe = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root.join("meta/host-id.lock"))
        .unwrap();
    // SAFETY: the probe owns this descriptor. A nonblocking probe must fail while the
    // parent is inside its identity generator, before it can publish or release its lock.
    assert_ne!(
        unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let error = io::Error::last_os_error().raw_os_error().unwrap();
    assert!([libc::EWOULDBLOCK, libc::EAGAIN].contains(&error));
    drop(probe);
    println!("initializer-ready");
    std::io::stdout().flush().unwrap();
    let id = store
        .establish_host_id(|| {
            std::fs::write(root.join("generated-by-child"), b"unexpected").unwrap();
            "h_child".into()
        })
        .unwrap();
    std::fs::write(root.join("child-result"), id).unwrap();
}

#[test]
fn a_second_process_cannot_generate_an_identity_while_the_first_initializes() {
    use std::io::BufRead;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};
    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("state");
    let store = Store::open(&root).unwrap();
    let mut owned = None;
    let mut output_reader = None;
    let id = store
        .establish_host_id(|| {
            let mut child = OwnedChild(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "store::durable::tests::initializer_child_process",
                        "--nocapture",
                    ])
                    .env("BRIQYARD_TEST_IDENTITY_ROOT", &root)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .unwrap(),
            );
            let stdout = child.0.stdout.take().unwrap();
            let (send, receive) = std::sync::mpsc::channel();
            let reader = std::thread::spawn(move || {
                for line in std::io::BufReader::new(stdout).lines() {
                    if line.unwrap() == "initializer-ready" {
                        let _ = send.send(());
                    }
                }
            });
            // Keep ownership before any fallible assertion so a panic also reaps the child.
            owned = Some(child);
            receive
                .recv_timeout(Duration::from_secs(3))
                .expect("second initializer did not become ready");
            output_reader = Some(reader);
            "h_first".into()
        })
        .unwrap();
    let child = owned.as_mut().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "second initializer did not finish"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    output_reader.unwrap().join().unwrap();
    assert_eq!(id, "h_first");
    assert_eq!(
        std::fs::read(root.join("child-result")).unwrap(),
        b"h_first"
    );
    assert!(!root.join("generated-by-child").exists());
}

#[tokio::test]
async fn manager_initialization_refuses_uncertain_identity_before_recovery() {
    use crate::{config::Config, image::Builder, machine::Manager, netw::dns::Resolver};
    for existing in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let mut config = Config {
            data_dir: directory.path().join("data"),
            ..Default::default()
        };
        config.network.egress = "unused-fixture-interface".into();
        config.firecracker = directory.path().join("unused-vmm");
        let root = config.state_dir();
        let store = Store::open_using(
            &root,
            Publisher::with_check(|stage, _| {
                if stage == Stage::ParentSync {
                    return Err(fail());
                }
                Ok(())
            }),
        )
        .unwrap();
        if existing {
            store.put_meta("host_id", "h_existing").unwrap();
        }
        let fake = crate::zfs::fake::Fake::open("byard").await.unwrap();
        // Forget the fake pool preparation; recovery must issue no further commands.
        let _ = fake.calls();
        let init = directory.path().join("init");
        std::fs::write(&init, b"fixture").unwrap();
        let images = Builder::new(fake.zfs.clone(), config.image_dir(), init, 8, vec![]).unwrap();
        let run_dir = config.run_dir();
        let error =
            match Manager::new(config, store, fake.zfs.clone(), images, Resolver::new(&[])).await {
                Ok(_) => panic!("uncertain identity must prevent recovery"),
                Err(error) => error,
            };
        assert!(matches!(
            error.downcast_ref::<PublicationError>(),
            Some(PublicationError::Uncertain {
                stage: Stage::ParentSync,
                ..
            })
        ));
        assert!(
            !run_dir.exists(),
            "manager must stop before runtime preparation"
        );
        assert!(fake.calls().is_empty(), "no storage recovery may run");
        assert!(
            root.join("meta/host_id.json").is_file(),
            "retain the visible identity"
        );
    }
}
