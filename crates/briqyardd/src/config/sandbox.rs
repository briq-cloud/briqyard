//! Operator allowlist; an empty list keeps the sandbox seed profile unavailable.
use super::*;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxRecipe {
    pub image: String,
    pub image_config_digest: String,
    pub init_sha256: String,
    pub size: api::Size,
    pub volume_gb: u32,
}
impl SandboxRecipe {
    pub fn device(&self) -> api::guest::SandboxDevice {
        api::guest::SandboxDevice {
            bytes: (self.volume_gb as u64) << 30,
            logical_sector_bytes: 512,
            drive_id: "data".into(),
        }
    }
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn registry_key(value: &str) -> String {
    match value.to_ascii_lowercase().as_str() {
        "index.docker.io" | "registry-1.docker.io" => "docker.io".into(),
        _ => value.to_ascii_lowercase(),
    }
}
impl Config {
    pub(super) fn check_sandbox_recipes(&self) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        for recipe in &self.templates.sandbox_recipes {
            let (image, manifest) = recipe
                .image
                .split_once("@sha256:")
                .context("sandbox recipe requires a pinned manifest")?;
            let registry = image.split('/').next().unwrap_or("");
            if self.token.is_empty()
                || !registry.contains('.')
                || image.contains('@')
                || !digest(manifest)
                || !digest(recipe.init_sha256.as_str())
                || !recipe
                    .image_config_digest
                    .strip_prefix("sha256:")
                    .is_some_and(digest)
                || recipe.volume_gb == 0
                || recipe.size.check().is_err()
                || self
                    .registries
                    .iter()
                    .any(|r| registry_key(&r.host) == registry_key(registry))
                || !seen.insert((
                    recipe.image.clone(),
                    recipe.size.vcpus,
                    recipe.size.memory_mb,
                    recipe.size.cpu_millis(),
                ))
            {
                bail!("sandbox recipes require configured API authentication and unique pinned public image/config/init/size/device inputs without registry credentials");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::config::testutil::load;
    fn yaml(token: &str) -> String {
        format!("token: '{token}'\ntemplates:\n  sandbox_recipes:\n    - image: registry.example/public@sha256:{}\n      image_config_digest: sha256:{}\n      init_sha256: '{}'\n      size: {{vcpus: 1, memory_mb: 256}}\n      volume_gb: 2\n", "a".repeat(64), "b".repeat(64), "c".repeat(64))
    }
    #[test]
    fn operator_recipes_require_authentication_and_pins_without_registry_credentials() {
        assert!(load("").unwrap().templates.sandbox_recipes.is_empty());
        assert!(load(&yaml("")).is_err());
        assert_eq!(
            load(&yaml("admin")).unwrap().templates.sandbox_recipes[0]
                .device()
                .bytes,
            2 << 30
        );
        assert!(
            load(&yaml("admin").replace(&format!("@sha256:{}", "a".repeat(64)), ":latest"))
                .is_err()
        );
        assert!(load(&format!(
            "{}registries:\n  - host: registry.example\n    username: user\n    password: test\n",
            yaml("admin")
        ))
        .is_err());
    }
}
