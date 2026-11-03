//! Operator allowlist; an empty list keeps the sandbox seed profile unavailable.
use super::*;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxRecipe {
    pub image: String,
    pub image_config_digest: String,
    pub init_sha256: String,
    pub size: api::Size,
    /// Capacity of the `/work` data volume; `0` is a recipe without one (two-drive topology).
    pub volume_gb: u32,
}
impl SandboxRecipe {
    pub fn volume(&self) -> Option<u32> {
        (self.volume_gb > 0).then_some(self.volume_gb)
    }
    /// The sealed data-device identity; none for a volume-free recipe.
    pub fn device(&self) -> Option<api::guest::SandboxDevice> {
        self.volume().map(api::guest::SandboxDevice::of_gb)
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
                    recipe.volume_gb,
                ))
            {
                bail!("sandbox recipes require configured API authentication and unique pinned public image/config/init/size/volume inputs without registry credentials");
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
                .unwrap()
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
    #[test]
    fn volume_gb_zero_declares_a_volume_free_recipe_and_the_field_stays_required() {
        let free = yaml("admin").replace("volume_gb: 2", "volume_gb: 0");
        let recipe = &load(&free).unwrap().templates.sandbox_recipes[0];
        assert_eq!(recipe.volume(), None);
        assert!(recipe.device().is_none());
        let recipe = &load(&yaml("admin")).unwrap().templates.sandbox_recipes[0];
        assert_eq!(recipe.volume(), Some(2));
        assert_eq!(recipe.device().unwrap().gb(), 2);
        // A recipe that forgets the field is refused, never read as volume-free.
        assert!(load(&yaml("admin").replace("      volume_gb: 2\n", "")).is_err());
        // Both shapes of one image and size may coexist; the same shape twice may not.
        let entry = yaml("admin")
            .split_once("    - image")
            .map(|(_, rest)| format!("    - image{rest}"))
            .unwrap();
        let both = format!(
            "{}{}",
            yaml("admin"),
            entry.replace("volume_gb: 2", "volume_gb: 0")
        );
        assert_eq!(load(&both).unwrap().templates.sandbox_recipes.len(), 2);
        assert!(load(&format!("{}{entry}", yaml("admin"))).is_err());
    }
}
