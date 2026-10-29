use super::*;

/// Writes the YAML to a temp file and loads it the way the daemon does.
pub(super) fn load(yaml: &str) -> Result<Config> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    std::fs::write(&path, yaml).unwrap();
    Config::load(Some(&path))
}
