//! Create continuity once per ordinary boot; checkpoint restore retains this RAM value.
use super::*;

pub(super) fn boot_proof(cfg: &Config) -> Result<Option<guest::AssignedRunProof>> {
    let Some(generation) = &cfg.assigned_run_generation else {
        return Ok(None);
    };
    anyhow::ensure!(
        cfg.template_profile.is_none(),
        "assigned boot proof requires ordinary init"
    );
    let proof = guest::AssignedRunProof {
        protocol: 1,
        generation: generation.clone(),
        init_sha256: clone_identity::executable_sha256(),
        boot_marker: hex::encode(clone_identity::random_id()?),
    };
    proof.validate().map_err(|error| anyhow!(error))?;
    Ok(Some(proof))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordinary_boot_marker_is_not_configured_and_is_fresh_per_boot() {
        let cfg = Config {
            assigned_run_generation: Some("a".repeat(64)),
            ..Default::default()
        };
        let first = boot_proof(&cfg).unwrap().unwrap();
        let second = boot_proof(&cfg).unwrap().unwrap();
        assert_eq!(first.generation, second.generation);
        assert_eq!(first.init_sha256, clone_identity::executable_sha256());
        assert_ne!(first.boot_marker, second.boot_marker);
        assert!(boot_proof(&Config::default()).unwrap().is_none());
    }
}
