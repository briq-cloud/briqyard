use super::*;
use std::os::unix::process::ExitStatusExt;

#[test]
fn zero_deleted_is_an_exact_complete_summary_not_a_permission_error() {
    let zero = "conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.\n";
    let output = |code, text: &str, truncated| {
        deleted_nothing(
            ExitStatus::from_raw(code << 8),
            &Diagnostic {
                bytes: text.as_bytes().to_vec(),
                truncated,
            },
        )
    };
    assert!(output(1, zero, false));
    for text in [
        "Operation failed: permission denied\n",
        &format!("Operation failed\n{zero}"),
        &format!("permission denied: {zero}"),
        &zero.replace("v1.4.8", "vbad"),
        &zero.replace("0 flow", "10 flow"),
    ] {
        assert!(!output(1, text, false), "{text}");
    }
    assert!(!output(2, zero, false));
    assert!(!output(1, zero, true));
}

#[tokio::test]
async fn a_noisy_child_is_drained_without_retaining_flow_output_or_unbounded_stderr() {
    let mut command = Command::new("/bin/sh");
    command.args([
        "-c",
        r#"
        test -c /dev/fd/1 || exit 42
        i=0
        while [ "$i" -lt 16384 ]; do
            printf 'per-flow stdout which must never be retained\n'
            printf 'diagnostic noise which must be drained and bounded\n' >&2
            i=$((i+1))
        done
        printf 'conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.\n' >&2
        exit 1
    "#,
    ]);
    let error = execute(command, Duration::from_secs(5))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.len() <= STDERR_LIMIT + 64,
        "retained {} bytes",
        error.len()
    );
    assert!(error.contains("[stderr truncated]"), "{error}");
    assert!(!error.contains("per-flow stdout"));
    assert!(
        !error.contains("0 flow entries"),
        "the tail must not overwrite the retained prefix"
    );
}

#[tokio::test]
async fn a_timeout_kills_and_reaps_the_command_before_returning() {
    let dir = tempfile::tempdir().unwrap();
    let pid = dir.path().join("pid");
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "echo $$ > \"$1\"; exec sleep 30", "fixture"])
        .arg(&pid);
    let error = execute(command, Duration::from_millis(250))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("deadline"), "{error:#}");
    let pid: i32 = std::fs::read_to_string(pid)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let result = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None);
    assert_eq!(
        result.unwrap_err(),
        nix::errno::Errno::ESRCH,
        "the child must be reaped"
    );
}
