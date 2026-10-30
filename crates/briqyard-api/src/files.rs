//! Bounds and validation shared by streaming file clients and servers (ADR 0061).

pub const LEGACY_MAX_SIZE: u64 = 1 << 20;
pub const LEGACY_MAX_JSON: usize = (LEGACY_MAX_SIZE as usize).div_ceil(3) * 4 + 16_384;
pub const MAX_SIZE: u64 = 1 << 30;
pub const CHUNK_SIZE: usize = 64 << 10;
pub const IDLE_SEC: u64 = 60;
pub const TRANSFER_SEC: u64 = 900;
pub const MAX_TRANSFERS: usize = 16;

/// A single regular file at an absolute guest path. No ambiguous or parent components.
pub fn check_path(path: &str) -> Result<(), String> {
    if path.len() > 4096
        || !path.starts_with('/')
        || path.contains('\0')
        || path[1..]
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err("path must name a file by an absolute path without empty, . or .. components (at most 4096 bytes)".into());
    }
    Ok(())
}

pub fn check_size(size: u64) -> Result<(), String> {
    if size > MAX_SIZE {
        return Err(format!("file exceeds {MAX_SIZE} bytes"));
    }
    Ok(())
}

/// Count untrusted stream bytes before writing them, with or without a declared total.
pub fn streamed_size(total: u64, additional: u64, declared: Option<u64>) -> Result<u64, String> {
    let next = total.checked_add(additional).ok_or("file size overflow")?;
    check_size(next)?;
    if declared.is_some_and(|size| next > size) {
        return Err("file stream exceeds declared size".into());
    }
    Ok(next)
}

pub fn mode(asked: Option<&str>) -> Result<u32, String> {
    let mode = match asked {
        Some(s) => u32::from_str_radix(s, 8).map_err(|_| "mode must be octal permission bits")?,
        None => 0o644,
    };
    if mode > 0o777 {
        return Err("mode must contain only permission bits (0000–0777)".into());
    }
    Ok(mode)
}

/// Live file support, from a fresh guest pong rather than its release number.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FileCapabilities {
    pub file_stream_v1: bool,
    pub init_version: String,
    pub legacy_max_bytes: u64,
    pub native_max_bytes: u64,
}

impl FileCapabilities {
    pub fn from_pong(pong: &crate::guest::Response) -> Self {
        Self {
            file_stream_v1: pong.file_stream_v1,
            init_version: pong.version.clone(),
            legacy_max_bytes: LEGACY_MAX_SIZE,
            native_max_bytes: MAX_SIZE,
        }
    }
}

/// A bounded legacy JSON response is decoded only after its encoded length is checked.
pub fn legacy_bytes(base64: &str) -> Result<Vec<u8>, String> {
    if base64.len() > (LEGACY_MAX_SIZE as usize).div_ceil(3) * 4 {
        return Err("legacy file exceeds 1 MiB; an image change installs streaming support".into());
    }
    let data = crate::guest::base64_decode(base64)?;
    if data.len() as u64 > LEGACY_MAX_SIZE {
        return Err("legacy file exceeds 1 MiB; an image change installs streaming support".into());
    }
    Ok(data)
}

/// The guest's result after a complete upload has been atomically committed.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FileWriteResponse {
    pub size: u64,
    pub sha256: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paths_and_bounds() {
        for path in [
            "", "/", "relative", "/a/../b", "/a/./b", "/a//b", "/a/", "/a\0b",
        ] {
            assert!(check_path(path).is_err(), "{path:?}");
        }
        assert!(check_path("/tmp/hello & é").is_ok());
        assert!(check_path(&format!("/{}", "a".repeat(4096))).is_err());
        assert!(check_size(MAX_SIZE).is_ok());
        assert!(check_size(MAX_SIZE + 1).is_err());
        assert_eq!(streamed_size(MAX_SIZE - 1, 1, None).unwrap(), MAX_SIZE);
        assert!(streamed_size(MAX_SIZE, 1, None).is_err());
        assert!(streamed_size(u64::MAX, 1, None).is_err());
        assert!(streamed_size(3, 2, Some(4)).is_err());
        assert_eq!(streamed_size(3, 2, None).unwrap(), 5);
        assert_eq!(mode(None).unwrap(), 0o644);
        assert_eq!(mode(Some("0000")).unwrap(), 0);
        for m in ["888", "4755", "100644", ""] {
            assert!(mode(Some(m)).is_err());
        }
    }
    #[test]
    fn live_capability_does_not_follow_the_version() {
        for supported in [false, true] {
            let pong: crate::guest::Response = serde_json::from_value(
                serde_json::json!({"type":"pong", "version":"0.1.7", "file_stream_v1":supported}),
            )
            .unwrap();
            assert_eq!(FileCapabilities::from_pong(&pong).file_stream_v1, supported);
        }
        let old: crate::guest::Response =
            serde_json::from_value(serde_json::json!({"type":"pong", "version":"0.1.7"})).unwrap();
        assert!(!FileCapabilities::from_pong(&old).file_stream_v1);
        assert!(legacy_bytes(&"A".repeat(LEGACY_MAX_JSON)).is_err());
        assert_eq!(
            legacy_bytes(&crate::guest::base64_encode(&vec![
                7;
                LEGACY_MAX_SIZE as usize
            ]))
            .unwrap()
            .len(),
            LEGACY_MAX_SIZE as usize
        );
        assert!(legacy_bytes(&crate::guest::base64_encode(&vec![
            7;
            LEGACY_MAX_SIZE as usize
                + 1
        ]))
        .is_err());
    }
}
