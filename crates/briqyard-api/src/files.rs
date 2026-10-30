//! Bounds and validation shared by streaming file clients and servers (ADR 0061).

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
        assert_eq!(mode(None).unwrap(), 0o644);
        assert_eq!(mode(Some("0000")).unwrap(), 0);
        for m in ["888", "4755", "100644", ""] {
            assert!(mode(Some(m)).is_err());
        }
    }
}
