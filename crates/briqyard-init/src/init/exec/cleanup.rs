use super::*;

pub(super) fn cleanup_failures(
    killed: Result<(), nix::errno::Errno>,
    waited: &std::io::Result<std::process::ExitStatus>,
    inspected: Result<(), String>,
) -> Option<String> {
    let mut failures = Vec::new();
    if let Err(error) = killed {
        if error != nix::errno::Errno::ESRCH {
            failures.push(format!("kill command group: {error}"));
        }
    }
    if let Err(error) = waited {
        failures.push(format!("wait for command: {error}"));
    }
    if let Err(error) = inspected {
        failures.push(error);
    }
    (!failures.is_empty()).then(|| failures.join("; "))
}

pub(super) fn terminal(
    status: std::io::Result<std::process::ExitStatus>,
    timed_out: bool,
    cancelled: bool,
    invalid_control: bool,
    cleanup_error: Option<String>,
) -> Response {
    let failure = if let Some(error) = cleanup_error {
        Some(("exec_cleanup_failed", error))
    } else if let Err(error) = &status {
        Some(("exec_wait_failed", format!("wait for command: {error}")))
    } else if invalid_control {
        Some((
            "invalid",
            "only cancel is accepted after the initial request".into(),
        ))
    } else {
        None
    };
    if let Some((code, message)) = failure {
        return Response {
            error_code: code.into(),
            ..Response::error(message)
        };
    }
    let mut response = Response::exit(exit_code(status.unwrap()), timed_out);
    response.cancelled = cancelled;
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    fn success() -> std::io::Result<std::process::ExitStatus> {
        Ok(std::process::ExitStatus::from_raw(9))
    }
    #[test]
    fn injected_cleanup_failures_never_acknowledge_completion_or_cancellation() {
        let failures = [
            cleanup_failures(Err(nix::errno::Errno::EPERM), &success(), Ok(())),
            cleanup_failures(
                Ok(()),
                &Err(std::io::Error::other("injected wait failure")),
                Ok(()),
            ),
            cleanup_failures(
                Ok(()),
                &success(),
                Err("injected inspection failure".into()),
            ),
        ];
        for failure in failures {
            assert!(failure.is_some());
            let response = terminal(success(), false, true, false, failure);
            assert_eq!(response.kind, "error");
            assert_eq!(response.error_code, "exec_cleanup_failed");
            assert!(!response.cancelled);
            assert!(!response.message.is_empty());
        }
        let response = terminal(
            Err(std::io::Error::other("injected wait failure")),
            false,
            false,
            false,
            None,
        );
        assert_eq!(response.kind, "error");
        assert_eq!(response.error_code, "exec_wait_failed");
        assert!(!response.cancelled);
    }
}
