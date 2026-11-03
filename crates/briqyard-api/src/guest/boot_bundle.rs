//! Versioned assigned-boot evidence, independent of tar headers, padding and timestamps.
use super::Config;

/// Init's existing installation rule: mode zero (including only special bits) means 0644.
pub fn boot_file_mode(mode: u32) -> u32 {
    if mode & 0o777 == 0 {
        0o644
    } else {
        mode & 0o7777
    }
}
/// Metadata's first matching nonzero mode wins; zero retains the archive header mode.
pub fn effective_boot_file_mode(config: &Config, path: &str, header_mode: u32) -> u32 {
    let mode = config
        .files
        .iter()
        .find(|file| file.path == path)
        .filter(|file| file.mode != 0)
        .map_or(header_mode, |file| file.mode);
    boot_file_mode(mode)
}
fn canonical(path: &str) -> bool {
    path.starts_with('/')
        && path.len() > 1
        && !path.contains('\0')
        && path[1..]
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}
/// Parsed/default-resolved config plus ordered (absolute path, effective mode, bytes).
/// Assigned archives reject alias spellings and duplicates instead of hiding overwritten
/// entries. No expected digest is stored in Config, so this cannot hash itself.
pub fn boot_bundle_fingerprint_bytes(
    config: &Config,
    files: &[(String, u32, Vec<u8>)],
) -> Result<Vec<u8>, &'static str> {
    let mut seen = std::collections::BTreeSet::new();
    for metadata in &config.files {
        if !canonical(&metadata.path) || !seen.insert(&metadata.path) {
            return Err("ambiguous assigned boot metadata path");
        }
    }
    seen.clear();
    let mut effective = Vec::with_capacity(files.len());
    for (path, mode, data) in files {
        if !canonical(path) || !seen.insert(path) {
            return Err("ambiguous assigned boot file path");
        }
        effective.push((path, effective_boot_file_mode(config, path, *mode), data));
    }
    let mut bytes = b"briqyard:assigned-run-v1:boot-bundle-v1\0".to_vec();
    bytes.extend(
        serde_json::to_vec(&(config, effective)).map_err(|_| "serialize assigned boot bundle")?,
    );
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Config {
        Config {
            assigned_run_generation: Some("a".repeat(64)),
            ..Default::default()
        }
    }
    #[test]
    fn bundle_measures_config_generation_order_bytes_and_effective_modes() {
        let config = config();
        let files = vec![("/a".into(), 0, vec![1]), ("/b".into(), 0o755, vec![2])];
        let fingerprint = boot_bundle_fingerprint_bytes(&config, &files).unwrap();
        let mut changed = config.clone();
        changed.cmd.push("different".into());
        assert_ne!(
            fingerprint,
            boot_bundle_fingerprint_bytes(&changed, &files).unwrap()
        );
        changed = config.clone();
        changed.assigned_run_generation = Some("b".repeat(64));
        assert_ne!(
            fingerprint,
            boot_bundle_fingerprint_bytes(&changed, &files).unwrap()
        );
        let mut reversed = files.clone();
        reversed.reverse();
        assert_ne!(
            fingerprint,
            boot_bundle_fingerprint_bytes(&config, &reversed).unwrap()
        );
        let mut changed_files = files.clone();
        changed_files[0].2.push(3);
        assert_ne!(
            fingerprint,
            boot_bundle_fingerprint_bytes(&config, &changed_files).unwrap()
        );
        changed_files = files.clone();
        changed_files[0].1 = 0o644;
        assert_eq!(
            fingerprint,
            boot_bundle_fingerprint_bytes(&config, &changed_files).unwrap()
        );
        let mut metadata = config.clone();
        metadata.files.push(super::super::FileMeta {
            path: "/a".into(),
            mode: 0o600,
        });
        assert_eq!(effective_boot_file_mode(&metadata, "/a", 0o755), 0o600);
        assert_eq!(effective_boot_file_mode(&metadata, "/b", 0o4000), 0o644);
        let mut same_effect = files.clone();
        same_effect[0].1 = 0o777;
        assert_eq!(
            boot_bundle_fingerprint_bytes(&metadata, &files).unwrap(),
            boot_bundle_fingerprint_bytes(&metadata, &same_effect).unwrap()
        );
    }
    #[test]
    fn assigned_bundles_refuse_duplicate_and_noncanonical_paths() {
        let config = config();
        for path in ["relative", "/", "//a", "/a/", "/a/../b", "/./a", "/a\0b"] {
            assert!(
                boot_bundle_fingerprint_bytes(&config, &[(path.into(), 0, vec![])]).is_err(),
                "{path:?}"
            );
        }
        assert!(boot_bundle_fingerprint_bytes(
            &config,
            &[("/a".into(), 0, vec![1]), ("/a".into(), 0, vec![2])]
        )
        .is_err());
        let mut duplicate = config;
        duplicate.files = vec![
            super::super::FileMeta {
                path: "/a".into(),
                mode: 0,
            },
            super::super::FileMeta {
                path: "/a".into(),
                mode: 0o600,
            },
        ];
        assert!(boot_bundle_fingerprint_bytes(&duplicate, &[]).is_err());
    }
}
