//! Guest continuity for an ordinary assigned boot, independent of host process generations.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignedRunProof {
    pub protocol: u8,
    pub generation: String,
    /// Measured by the running init, never copied from host configuration.
    pub init_sha256: String,
    /// Random boot-local RAM state: stable across checkpoint/resume, fresh on reboot.
    pub boot_marker: String,
}
impl AssignedRunProof {
    pub fn validate(&self) -> Result<(), &'static str> {
        let hex = |value: &str, len| {
            value.len() == len
                && value
                    .bytes()
                    .all(|v| v.is_ascii_hexdigit() && !v.is_ascii_uppercase())
        };
        if self.protocol != 1
            || !hex(&self.generation, 64)
            || !hex(&self.init_sha256, 64)
            || !hex(&self.boot_marker, 32)
        {
            return Err("invalid assigned run guest proof");
        }
        Ok(())
    }
    pub fn verify(
        &self,
        generation: &str,
        init_sha256: &str,
        boot_marker: &str,
    ) -> Result<(), &'static str> {
        self.validate()?;
        if self.generation != generation
            || self.init_sha256 != init_sha256
            || self.boot_marker != boot_marker
        {
            return Err("assigned run guest continuity differs");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn assigned_run_proof_checks_protocol_and_exact_guest_tuple() {
        let proof = AssignedRunProof {
            protocol: 1,
            generation: "a".repeat(64),
            init_sha256: "b".repeat(64),
            boot_marker: "c".repeat(32),
        };
        assert!(proof
            .verify(&proof.generation, &proof.init_sha256, &proof.boot_marker)
            .is_ok());
        assert!(proof
            .verify(&"d".repeat(64), &proof.init_sha256, &proof.boot_marker)
            .is_err());
        assert!(proof
            .verify(&proof.generation, &"e".repeat(64), &proof.boot_marker)
            .is_err());
        assert!(proof
            .verify(&proof.generation, &proof.init_sha256, &"f".repeat(32))
            .is_err());
        let mut unknown = proof;
        unknown.protocol = 2;
        assert!(unknown.validate().is_err());
    }
    #[test]
    fn absent_assigned_run_fields_preserve_legacy_wire() {
        let config = serde_json::to_value(super::super::Config::default()).unwrap();
        let response = serde_json::to_value(super::super::Response::new("pong")).unwrap();
        assert!(config.get("assigned_run_generation").is_none());
        assert!(response.get("assigned_run").is_none());
        let pong: super::super::Response = serde_json::from_value(response).unwrap();
        assert!(pong.assigned_run.is_none());
    }
}
