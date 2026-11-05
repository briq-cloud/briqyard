//! `doctor` (ADR 0050).

use super::*;

#[test]
fn doctor_reads_needrestart_and_reboot_settings() {
    let conf = |s: &str| vec![s.to_string()];
    // The snippet the bootstrap writes, and an entry in the main file's hash.
    let snippet = include_str!("../../../../hack/bootstrap-host.sh")
        .split("conf.d/briqyard.conf <<'EOF'\n")
        .nth(1)
        .and_then(|s| s.split("\nEOF\n").next())
        .unwrap();
    assert!(needrestart_spares_daemon(&conf(snippet)));
    assert!(needrestart_spares_daemon(&conf(
        "$nrconf{override_rc} = {\n    qr(^briqyardd) => 0,\n};"
    )));
    // Ubuntu's file alone, a comment, the fleet alone, or a forced restart: not spared.
    assert!(!needrestart_spares_daemon(&conf(
        "$nrconf{override_rc} = {\n    qr(^dbus) => 0,\n};"
    )));
    assert!(!needrestart_spares_daemon(&conf(
        "# $nrconf{override_rc}{qr(^briqyardd\\.service$)} = 0;"
    )));
    assert!(!needrestart_spares_daemon(&conf(
        "$nrconf{override_rc}{qr(^briqyard-fleet\\.service$)} = 0;"
    )));
    assert!(!needrestart_spares_daemon(&conf(
        "$nrconf{override_rc}{qr(^briqyardd\\.service$)} = 1;"
    )));
    assert!(!needrestart_spares_daemon(&[]));
    // apt-config's answer, as Ubuntu 26.04 prints it.
    assert!(!reboots_on_its_own(""));
    assert!(!reboots_on_its_own("R='false'\n"));
    assert!(reboots_on_its_own("R='true'\n"));
}

#[test]
fn doctor_takes_the_last_needrestart_entry_in_name_order() {
    let rc = |p: &str, v: u8| format!("$nrconf{{override_rc}}{{qr({p})}} = {v};");
    let spared = |confs: &[String]| needrestart_spares_daemon(confs);
    let ours = rc("^briqyardd\\.service$", 0);
    // The last entry that matches wins, whichever pattern it uses.
    assert!(!spared(&[ours.clone(), rc("^briqyard", 1)]));
    assert!(spared(&[rc("^briqyard", 1), ours.clone()]));
    assert!(spared(&[ours.clone(), rc("^dbus", 1)]));
    // A hash assigned again forgets what came before it.
    assert!(!spared(&[
        ours.clone(),
        "$nrconf{override_rc} = {\n    qr(^dbus) => 0,\n};".to_string()
    ]));
    // The files: needrestart.conf, then conf.d by name, whatever order the directory lists.
    let dir = std::env::temp_dir().join(format!("briqyard-doctor-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("conf.d")).unwrap();
    std::fs::write(
        dir.join("needrestart.conf"),
        "$nrconf{override_rc} = {\n    qr(^briqyardd) => 1,\n};",
    )
    .unwrap();
    std::fs::write(dir.join("conf.d/briqyard.conf"), &ours).unwrap();
    std::fs::write(dir.join("conf.d/50-site.conf"), rc("^briqyard", 1)).unwrap();
    std::fs::write(dir.join("conf.d/README.needrestart"), rc("^briqyard", 1)).unwrap();
    assert!(spared(&needrestart_confs(&dir)));
    std::fs::write(dir.join("conf.d/zz-site.conf"), rc("^briqyard", 1)).unwrap();
    assert!(!spared(&needrestart_confs(&dir)));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn doctor_reads_needrestart_patterns_as_needrestart_matches_them() {
    let spared =
        |p: &str| needrestart_spares_daemon(&[format!("$nrconf{{override_rc}}{{qr({p})}} = 0;")]);
    // One pattern for both units, the unit by name, its dots unescaped.
    assert!(spared("^briqyard"));
    assert!(spared("^briqyardd\\.service$"));
    assert!(spared("^briqyardd.service$"));
    assert!(spared("briqyardd"));
    assert!(spared("\\.service$"));
    // Another unit, or a regex this check does not read.
    assert!(!spared("^briqyard-fleet\\.service$"));
    assert!(!spared("^briqyardd$"));
    assert!(!spared("^briqyard[dx]"));
    assert!(!spared("^dbus"));
}

#[test]
fn a_nested_class_in_the_configuration_asks_for_kvm_nested() {
    use crate::doctor::config_serves_nested;
    let class = |nested: bool| {
        format!(
            "token: t\nruntime_classes:\n  nested:\n    kernel: /k\n    modules: /m\n    nested: {nested}\n"
        )
    };
    assert!(config_serves_nested(&class(true)));
    assert!(!config_serves_nested(&class(false)));
    assert!(!config_serves_nested("token: t\n"));
    assert!(!config_serves_nested("runtime_classes: {}\n"));
    assert!(!config_serves_nested(": not yaml ["));
    assert!(!config_serves_nested(""));
}

#[test]
fn the_files_checked_are_the_configured_ones() {
    use crate::doctor::HostFiles;
    let conf = "token: t\nfirecracker: /usr/local/lib/briqyard/runtime/h/firecracker\n\
                jailer: /usr/local/lib/briqyard/runtime/h/jailer\n\
                kernel: /usr/local/lib/briqyard/runtime/h/vmlinux\n\
                init: /usr/local/lib/briqyard/runtime/h/briqyard-init\n";
    let files = HostFiles::from_config(conf);
    assert_eq!(
        files.firecracker,
        "/usr/local/lib/briqyard/runtime/h/firecracker"
    );
    assert_eq!(files.jailer, "/usr/local/lib/briqyard/runtime/h/jailer");
    assert_eq!(files.kernel, "/usr/local/lib/briqyard/runtime/h/vmlinux");
    assert_eq!(
        files.init,
        "/usr/local/lib/briqyard/runtime/h/briqyard-init"
    );
    // Without a readable configuration, or a field, the daemon's defaults.
    for conf in ["", ": not yaml [", "token: t\njailer: ''\n"] {
        let files = HostFiles::from_config(conf);
        assert_eq!(files.firecracker, "/usr/local/bin/firecracker");
        assert_eq!(files.jailer, "/usr/local/bin/jailer");
        assert_eq!(files.kernel, "/var/lib/briqyard/vmlinux");
        assert_eq!(files.init, "/usr/local/bin/briqyard-init");
    }
}
