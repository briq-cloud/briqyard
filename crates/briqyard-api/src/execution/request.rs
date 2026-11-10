//! The synchronous request commitment is independent of JSON member ordering.
use super::{token_digest, Limits, VerifyError};
use crate::ExecRequest;

/// Versioned, length-prefixed UTF-8 fields. Maps are ordered by UTF-8 bytes. Integers
/// are unsigned big-endian u64. No wake is allowed; timeout is explicit, never defaulted.
pub fn exec_request_digest(req: &ExecRequest, limits: &Limits) -> Result<String, VerifyError> {
    if req.wake
        || req.cmd.is_empty()
        || req.timeout_ms == 0
        || req.timeout_ms > limits.max_duration_seconds.saturating_mul(1000)
        || req.stdin.len() as u64 > limits.max_input_bytes
    {
        return Err(VerifyError::Claims);
    }
    let mut bytes = b"briqyard-exec-request-v1\0".to_vec();
    fn field(bytes: &mut Vec<u8>, value: &str) {
        bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    bytes.extend_from_slice(&(req.cmd.len() as u64).to_be_bytes());
    for value in &req.cmd {
        field(&mut bytes, value);
    }
    bytes.extend_from_slice(&(req.env.len() as u64).to_be_bytes());
    for (name, value) in &req.env {
        field(&mut bytes, name);
        field(&mut bytes, value);
    }
    field(&mut bytes, &req.cwd);
    field(&mut bytes, &req.stdin);
    bytes.extend_from_slice(&req.timeout_ms.to_be_bytes());
    // token_digest hashes arbitrary UTF-8, but this encoding contains arbitrary u64
    // bytes; use the same digest representation without a lossy text conversion.
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use sha2::{Digest, Sha256};
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(&bytes)))
}

/// Stable run identity from the actual VMM's kernel process identity. Fields cannot
/// alias by concatenation. This is not a PID or a caller-selected logical run name.
pub fn process_run_id(
    host_boot_id: &str,
    pid: u32,
    start_ticks: u64,
    admission_instance: &str,
) -> String {
    token_digest(&format!(
        "briqyard-process-run-v1:{host_boot_id}:{pid}:{start_ticks}:{admission_instance}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn limits() -> Limits {
        Limits {
            max_duration_seconds: 20,
            max_input_bytes: 1024,
            max_output_bytes: 4096,
            execution_mode: None,
            output_mode: None,
        }
    }
    #[test]
    fn encoding_commits_boundaries_order_input_and_timeout() {
        let mut a = ExecRequest {
            cmd: vec!["a".into(), "bc".into()],
            timeout_ms: 1000,
            wake: false,
            ..Default::default()
        };
        let digest = exec_request_digest(&a, &limits()).unwrap();
        a.cmd = vec!["ab".into(), "c".into()];
        assert_ne!(digest, exec_request_digest(&a, &limits()).unwrap());
        a.stdin = "input".into();
        let input = exec_request_digest(&a, &limits()).unwrap();
        a.timeout_ms += 1;
        assert_ne!(input, exec_request_digest(&a, &limits()).unwrap());
        a.wake = true;
        assert!(exec_request_digest(&a, &limits()).is_err());
        a.wake = false;
        a.timeout_ms = 0;
        assert!(exec_request_digest(&a, &limits()).is_err());
    }
    #[test]
    fn process_identity_includes_boot_pid_and_kernel_start() {
        let a = process_run_id("boot-1", 12, 34, "instance-1");
        assert_ne!(a, process_run_id("boot-1", 12, 34, "instance-2"));
        assert_ne!(a, process_run_id("boot-2", 12, 34, "instance-1"));
        assert_ne!(a, process_run_id("boot-1", 13, 34, "instance-1"));
        assert_ne!(a, process_run_id("boot-1", 12, 35, "instance-1"));
    }
}
