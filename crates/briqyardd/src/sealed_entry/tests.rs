use crate::Args;
use clap::{error::ErrorKind, Parser};

fn parse(command: &str, tail: &[&str]) -> Result<Args, clap::Error> {
    Args::try_parse_from(
        [
            "/usr/local/bin/briqyardd",
            "--config",
            "/etc/briqyard/config.yaml",
            command,
        ]
        .into_iter()
        .chain(tail.iter().copied()),
    )
}

#[test]
fn sealed_command_shapes_require_exactly_one_of_each_selector() {
    for (command, resource, base) in [
        ("sealed-guard", "daemon", "/var/lib/briqyard"),
        ("sealed-custodian", "daemon", "/var/lib/briqyard"),
        (
            "sealed-custodian",
            "authority",
            "/var/lib/briq-execution-authority",
        ),
    ] {
        let path = format!("{base}/sealed-ops/{}/1/{resource}", "0".repeat(64));
        let options = ["--resource", resource, "--operation-dir", &path];
        assert!(parse(command, &options).is_ok(), "{command} {resource}");
        for incomplete in [&options[0..2], &options[2..4]] {
            assert!(matches!(
                parse(command, incomplete),
                Err(error) if error.kind() == ErrorKind::MissingRequiredArgument
            ));
        }
        for duplicate in [&options[0..2], &options[2..4]] {
            let both = [&options[..], duplicate].concat();
            assert!(matches!(
                parse(command, &both),
                Err(error) if error.kind() == ErrorKind::ArgumentConflict
            ));
        }
        assert!(parse(command, &["--resource", "DAEMON", "--operation-dir", &path]).is_err());
    }
    assert!(parse("sealed_guard", &[]).is_err());
    assert!(parse("sealed-custody", &[]).is_err());
}

#[test]
fn ordinary_command_shapes_are_unchanged() {
    assert!(Args::try_parse_from(["briqyardd"]).unwrap().cmd.is_none());
    assert!(parse("check-config", &[]).is_ok());
    assert!(parse("scoped-execution-capabilities", &[]).is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn syntactically_correct_argv_and_config_path_cannot_grant_permission() {
    use super::Mode;
    use crate::Cmd;

    let path = format!("/var/lib/briqyard/sealed-ops/{}/1/daemon", "0".repeat(64));
    let options = ["--resource", "daemon", "--operation-dir", &path];
    for command in ["sealed-guard", "sealed-custodian"] {
        let args = parse(command, &options).unwrap();
        let (opts, mode) = match args.cmd.unwrap() {
            Cmd::SealedGuard(opts) => (opts, Mode::Guard),
            Cmd::SealedCustodian(opts) => (opts, Mode::Custodian),
            _ => panic!("expected a sealed command"),
        };
        assert_eq!(opts.refusal(mode), "protected_startup_inputs_unavailable");
    }
    let Some(Cmd::SealedGuard(opts)) = parse(
        "sealed-guard",
        &["--resource", "authority", "--operation-dir", &path],
    )
    .unwrap()
    .cmd
    else {
        panic!("expected a sealed guard");
    };
    assert_eq!(opts.refusal(Mode::Guard), "resource_not_supported_by_guard");
    let Some(Cmd::SealedCustodian(opts)) = parse(
        "sealed-custodian",
        &["--resource", "authority", "--operation-dir", &path],
    )
    .unwrap()
    .cmd
    else {
        panic!("expected a sealed custodian");
    };
    assert_eq!(opts.refusal(Mode::Custodian), "invalid_operation_directory");
}
