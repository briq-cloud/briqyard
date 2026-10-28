//! A pool key's id (ADR 0035): what a backup's record says of the key its streams are
//! encrypted under, so the restoring host can ask for that key. A hash of the key, never the
//! key: 32 random bytes hashed tell nothing of them.

use sha2::{Digest, Sha256};

/// The id of a pool key given as ZFS's `hex` format (64 hex digits, either case): the first 16
/// bytes of SHA-256 over a fixed label and the key's bytes, as 32 hex digits. `None` for what
/// is not a key.
pub fn id(key: &str) -> Option<String> {
    let bytes = hex::decode(key.trim()).ok().filter(|b| b.len() == 32)?;
    let mut h = Sha256::new();
    h.update(b"briqyard pool key id\0");
    h.update(&bytes);
    Some(hex::encode(&h.finalize()[..16]))
}

#[cfg(test)]
mod tests {
    #[test]
    fn an_id_is_the_keys_whatever_its_case_and_never_the_key() {
        let key = "0123456789abcdef".repeat(4);
        let id = super::id(&key).unwrap();
        assert_eq!(id.len(), 32);
        assert_eq!(super::id(&key.to_uppercase()).unwrap(), id);
        assert_eq!(super::id(&format!("{key}\n")).unwrap(), id);
        assert!(!key.contains(&id) && !id.contains(&key[..8]));
        assert_ne!(super::id(&"fedcba9876543210".repeat(4)).unwrap(), id);
        assert_eq!(super::id("abcd"), None);
        assert_eq!(super::id(&"zz".repeat(32)), None);
    }
}
