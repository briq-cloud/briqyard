//! Capture identity from the same input that is parsed and validated.
use super::*;
use briqyard_api as api;
use sha2::{Digest, Sha256};

pub(super) fn load(path: Option<&Path>) -> Result<Config> {
    let mut cfg: Config = match path {
        None => Config {
            loaded_identity: api::LoadedConfigIdentity::Defaults,
            ..Config::default()
        },
        Some(p) => {
            let text = std::fs::read_to_string(p)
                .with_context(|| format!("read config {}", p.display()))?;
            let parse = || format!("parse config {}", p.display());
            let mut doc: serde_yaml::Value = serde_yaml::from_str(&text).with_context(parse)?;
            let mut cfg: Config = match old_provisioner(&mut doc).with_context(parse)? {
                // From the text, so that an error says where.
                None => serde_yaml::from_str(&text).with_context(parse)?,
                Some(warning) => {
                    tracing::warn!(config = %p.display(), "{warning}");
                    serde_yaml::from_value(doc).with_context(parse)?
                }
            };
            cfg.loaded_identity = api::LoadedConfigIdentity::File {
                sha256: format!("{:x}", Sha256::digest(text.as_bytes())),
            };
            cfg
        }
    };
    if let Ok(v) = std::env::var("BRIQYARD_RELEASE_TOKEN") {
        cfg.bootstrap.release_token = v;
    }
    cfg.validate()?;
    Ok(cfg)
}
