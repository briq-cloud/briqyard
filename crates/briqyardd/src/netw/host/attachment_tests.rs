//! Exercise the real command path in a child with private fake tools, never the host network.
use super::*;
use std::os::unix::fs::PermissionsExt;

const CHILD: &str = "netw::host::attachment_tests::retry_after_link_up_child";
const FIXTURE: &str = "BRIQYARD_TEST_ATTACHMENT_DIR";

#[tokio::test]
async fn failed_link_up_and_failed_cleanup_cannot_leave_sibling_access_after_a_patch() {
    let dir = tempfile::tempdir().unwrap();
    let scripts = [
        (
            "ip",
            r#"#!/bin/sh
set -eu
if [ "$*" = 'link set btabcdef123456 up' ] && [ ! -f "$BRIQYARD_TEST_ATTACHMENT_DIR/up-failed" ]; then
  touch "$BRIQYARD_TEST_ATTACHMENT_DIR/up-failed"
  echo 'fixture: link up refused' >&2
  exit 1
fi
"#,
        ),
        ("conntrack", "#!/bin/sh\nexit 0\n"),
        (
            "nft",
            r#"#!/bin/sh
set -eu
script=$(/bin/cat)
case "$script" in
  *'delete element bridge briqyard via_siblings'*)
    if [ -f "$BRIQYARD_TEST_ATTACHMENT_DIR/up-failed" ] && [ ! -f "$BRIQYARD_TEST_ATTACHMENT_DIR/cleanup-failed" ]; then
      touch "$BRIQYARD_TEST_ATTACHMENT_DIR/cleanup-failed"
      echo 'fixture: cleanup refused' >&2
      exit 1
    fi
    rm -f "$BRIQYARD_TEST_ATTACHMENT_DIR/siblings-admitted"
    ;;
  *'add element bridge briqyard via_siblings'*)
    touch "$BRIQYARD_TEST_ATTACHMENT_DIR/siblings-admitted"
    ;;
esac
"#,
        ),
    ];
    for (name, source) in scripts {
        let file = dir.path().join(name);
        std::fs::write(&file, source).unwrap();
        std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    // Only the child receives PATH. Parallel tests and the caller's tools are unchanged.
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CHILD, "--nocapture"])
            .env(FIXTURE, dir.path())
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    dir.path().display(),
                    std::env::var("PATH").unwrap()
                ),
            )
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn retry_after_link_up_child() {
    let Some(path) = std::env::var_os(FIXTURE) else {
        return;
    };
    let path = std::path::PathBuf::from(path);
    let net = HostNet::new().await.unwrap();
    let opted = nft::Policy::Via {
        ip: "10.64.1.3".into(),
        to: "10.64.1.2".into(),
        to_tap: "btgateway".into(),
        host: "10.64.1.1".into(),
        siblings: true,
    };
    assert!(net
        .attach(
            "m_abcdef123456",
            "by1",
            opted.ip(),
            None,
            Some(&opted),
            true
        )
        .await
        .is_err());
    assert!(
        path.join("siblings-admitted").exists(),
        "the committed admission's cleanup failed"
    );
    assert!(path.join("cleanup-failed").exists());
    // A stopped record can be PATCHed before the next start. Its current policy no longer
    // describes the uncertain admission, which must still be revoked before the retry.
    let mut strict = opted;
    if let nft::Policy::Via { siblings, .. } = &mut strict {
        *siblings = false;
    }
    net.attach(
        "m_abcdef123456",
        "by1",
        strict.ip(),
        None,
        Some(&strict),
        true,
    )
    .await
    .unwrap();
    assert!(
        !path.join("siblings-admitted").exists(),
        "strict retry retained stale sibling permission"
    );
    assert!(net.update.lock().await.is_empty());
}
