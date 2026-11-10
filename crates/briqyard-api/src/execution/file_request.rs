//! Dormant streaming-file commitment. This is not admission or dispatch authority.
use super::{verify, Operation, VerifyError, MAX_SAFE_INTEGER};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_FILE_TIMEOUT_MS: u64 = 600_000;

/// Control metadata only; payload bytes must never be collected into this object.
/// Missing mode preserves existing permissions; an explicit mode sets them.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileRequest {
    pub v: u8,
    pub operation: Operation,
    pub path: String,
    pub mode: Option<u32>,
    pub declared_size: Option<u64>,
    pub max_bytes: u64,
    /// Lowercase hexadecimal SHA-256 of the upload, when independently known.
    pub expected_sha256: Option<String>,
    pub timeout_ms: u64,
    /// Frozen absolute operation deadline, distinct from each authorization lease.
    pub deadline_ms: u64,
    pub metadata_revision: String,
    pub projection_digest: String,
}

impl FileRequest {
    /// Structural checks only. Callers must also prove current time, protection,
    /// installed projection, target and admission before polling any payload.
    pub fn validate(&self) -> Result<(), VerifyError> {
        if self.v != 1
            || !matches!(self.operation, Operation::FilesRead | Operation::FilesWrite)
            || crate::files::check_path(&self.path).is_err()
            || self.max_bytes > crate::files::MAX_SIZE
            || self.declared_size.is_some_and(|n| n > self.max_bytes)
            || self.mode.is_some_and(|n| n > 0o777)
            || self.expected_sha256.as_ref().is_some_and(|s| {
                s.len() != 64
                    || !s
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            })
            || (self.operation == Operation::FilesRead
                && (self.mode.is_some()
                    || self.declared_size.is_some()
                    || self.expected_sha256.is_some()))
            || self.timeout_ms == 0
            || self.timeout_ms > MAX_FILE_TIMEOUT_MS
            || self.deadline_ms < self.timeout_ms
            || self.deadline_ms > MAX_SAFE_INTEGER
            || !verify::id(&self.metadata_revision)
            || !verify::digest(&self.projection_digest)
        {
            return Err(VerifyError::Claims);
        }
        Ok(())
    }
}

/// Versioned binary encoding, independent of JSON order. Integers are u64 BE;
/// strings have a u64 byte-length prefix. Optional fields have a 0/1 presence byte.
/// Paths retain their exact UTF-8 bytes. No implicit timeout or mode is applied.
pub fn file_request_digest(req: &FileRequest) -> Result<String, VerifyError> {
    req.validate()?;
    fn number(out: &mut Vec<u8>, value: u64) {
        out.extend_from_slice(&value.to_be_bytes());
    }
    fn field(out: &mut Vec<u8>, value: &str) {
        number(out, value.len() as u64);
        out.extend_from_slice(value.as_bytes());
    }
    fn optional_number(out: &mut Vec<u8>, value: Option<u64>) {
        out.push(u8::from(value.is_some()));
        if let Some(value) = value {
            number(out, value);
        }
    }
    let mut out = b"briqyard-file-request-v1\0".to_vec();
    out.push(match req.operation {
        Operation::FilesRead => 1,
        Operation::FilesWrite => 2,
        _ => return Err(VerifyError::Claims),
    });
    field(&mut out, &req.path);
    optional_number(&mut out, req.mode.map(u64::from));
    optional_number(&mut out, req.declared_size);
    number(&mut out, req.max_bytes);
    out.push(u8::from(req.expected_sha256.is_some()));
    if let Some(value) = &req.expected_sha256 {
        field(&mut out, value);
    }
    number(&mut out, req.timeout_ms);
    number(&mut out, req.deadline_ms);
    field(&mut out, &req.metadata_revision);
    field(&mut out, &req.projection_digest);
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(out)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cross_language_vectors() {
        let cases: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/file-request-v1.json"))
                .unwrap();
        for case in cases.as_array().unwrap() {
            let request: FileRequest = serde_json::from_value(case["request"].clone()).unwrap();
            assert_eq!(
                file_request_digest(&request).unwrap(),
                case["digest"].as_str().unwrap(),
                "{}",
                case["name"]
            );
        }
    }
    fn request() -> FileRequest {
        FileRequest {
            v: 1,
            operation: Operation::FilesWrite,
            path: "/tmp/é data".into(),
            mode: None,
            declared_size: None,
            max_bytes: 100,
            expected_sha256: None,
            timeout_ms: 120_000,
            deadline_ms: 1_800_000_000_000,
            metadata_revision: "revision-1".into(),
            projection_digest: super::super::token_digest("projection-1"),
        }
    }
    #[test]
    fn every_semantic_field_is_committed() {
        let a = request();
        let original = file_request_digest(&a).unwrap();
        let edits: &[fn(&mut FileRequest)] = &[
            |r| r.operation = Operation::FilesRead,
            |r| r.path.push('x'),
            |r| r.mode = Some(0o644),
            |r| r.mode = Some(0),
            |r| r.declared_size = Some(0),
            |r| r.max_bytes += 1,
            |r| r.expected_sha256 = Some("a".repeat(64)),
            |r| r.timeout_ms += 1,
            |r| r.deadline_ms += 1,
            |r| r.metadata_revision.push('x'),
            |r| r.projection_digest = super::super::token_digest("other"),
        ];
        for edit in edits {
            let mut b = a.clone();
            edit(&mut b);
            assert_ne!(original, file_request_digest(&b).unwrap());
        }
    }
    #[test]
    fn structural_bounds_and_invalid_combinations_refuse() {
        let edits: &[fn(&mut FileRequest)] = &[
            |r| r.v = 2,
            |r| r.operation = Operation::Exec,
            |r| r.path = "/a/../b".into(),
            |r| r.path = "/a//b".into(),
            |r| r.max_bytes = crate::files::MAX_SIZE + 1,
            |r| r.declared_size = Some(101),
            |r| r.mode = Some(0o1000),
            |r| r.expected_sha256 = Some("A".repeat(64)),
            |r| r.timeout_ms = 0,
            |r| r.timeout_ms = MAX_FILE_TIMEOUT_MS + 1,
            |r| r.deadline_ms = r.timeout_ms - 1,
            |r| r.deadline_ms = MAX_SAFE_INTEGER + 1,
            |r| r.metadata_revision.clear(),
            |r| r.projection_digest.clear(),
        ];
        for edit in edits {
            let mut b = request();
            edit(&mut b);
            assert!(file_request_digest(&b).is_err());
        }
        for field in ["mode", "declared_size", "expected_sha256"] {
            let mut b = serde_json::to_value(request()).unwrap();
            b["operation"] = "files_read".into();
            b[field] = match field {
                "expected_sha256" => "a".repeat(64).into(),
                _ => 0.into(),
            };
            assert!(serde_json::from_value::<FileRequest>(b)
                .unwrap()
                .validate()
                .is_err());
        }
        let mut valid = request();
        valid.max_bytes = crate::files::MAX_SIZE;
        valid.declared_size = Some(valid.max_bytes);
        valid.timeout_ms = MAX_FILE_TIMEOUT_MS;
        valid.mode = Some(0o777);
        assert!(valid.validate().is_ok());
        let mut extra = serde_json::to_value(&valid).unwrap();
        extra["wake"] = true.into();
        assert!(serde_json::from_value::<FileRequest>(extra).is_err());
    }
}
