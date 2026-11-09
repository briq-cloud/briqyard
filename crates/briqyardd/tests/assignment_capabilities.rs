//! Capability probes are pure, including with missing or malformed configuration.
#[test]
fn capability_commands_preserve_legacy_stdout_without_opening_state() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("bad.yaml");
    std::fs::write(&config, b"data_dir: [invalid\n").unwrap();
    for path in [&config, &temp.path().join("missing.yaml")] {
        for (command, expected) in [
            (
                "assigned-update-capabilities",
                b"assigned-update-v3\n".as_slice(),
            ),
            (
                "assigned-run-lifecycle-capabilities",
                b"assigned-run-lifecycle-v1\n".as_slice(),
            ),
            ("assigned-run-capabilities", b"assigned-run-v1\n".as_slice()),
            ("state-capabilities", b"launch-identity-v1\n".as_slice()),
            (
                "assignment-capabilities",
                b"destination-assignment-v1\n".as_slice(),
            ),
        ] {
            let output = std::process::Command::new(env!("CARGO_BIN_EXE_briqyardd"))
                .arg("--config")
                .arg(path)
                .arg(command)
                .output()
                .unwrap();
            assert!(output.status.success());
            assert_eq!(output.stdout, expected);
        }
    }
    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
}
