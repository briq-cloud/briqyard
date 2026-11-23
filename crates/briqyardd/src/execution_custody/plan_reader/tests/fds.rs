//! A hostile reply that attaches descriptors, observed from a separate process so no other
//! test's descriptors can move the count. The parent hosts the malicious helper; a re-executed
//! copy of this test binary is the reader, in its own descriptor table.

use super::*;
use std::process::Command;

const CHILD: &str = "execution_custody::plan_reader::tests::fds::reader_child";
const COUNTS: [usize; 3] = [1, 8, 64];

#[test]
fn replies_with_attached_descriptors_leak_none_into_the_reader() {
    let world = World::new();
    let turn = AtomicUsize::new(0);
    let _helper = serve(&world.sock_dir(), move |_| {
        let count = COUNTS[turn.fetch_add(1, Ordering::SeqCst)];
        Reply::Fds(count, framed(b"reply"))
    });
    let me = own_helper();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            CHILD,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("PLAN_READER_FD_CHILD", world.sock_dir())
        .env("PLAN_READER_HELPER_PID", me.pid.to_string())
        .env("PLAN_READER_HELPER_START", me.start_ticks.to_string())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && text.contains("FD_DOMAIN_OK"),
        "{text}"
    );
}

#[test]
#[ignore = "child process of replies_with_attached_descriptors_leak_none_into_the_reader; run only by it"]
fn reader_child() {
    let var = |name| std::env::var(name).unwrap();
    let helper = EnrolledHelper::new(
        TEST_HELPER_IMAGE,
        var("PLAN_READER_HELPER_PID").parse().unwrap(),
        var("PLAN_READER_HELPER_START").parse().unwrap(),
        "test".to_string(),
    );
    let endpoint = ReaderEndpoint::rooted_at(
        &PathBuf::from(var("PLAN_READER_FD_CHILD")),
        own(),
        helper,
        test_probe,
        pidfd_open_by_pid,
    );
    let count = || std::fs::read_dir("/proc/self/fd").unwrap().count();
    let before = count();
    for attached in COUNTS {
        let error = endpoint
            .exchange(b"{}", Deadline::within(GENEROUS))
            .unwrap_err();
        assert!(
            error.to_string().contains("ancillary data"),
            "{attached}: {error}"
        );
        assert_eq!(count(), before, "{attached} attached descriptors leaked");
    }
    println!("FD_DOMAIN_OK");
}
