//! Exact approved release members; version strings never confer this capability.
use super::fs::invalid;
use std::{fs::File, io};

pub(super) fn hash(file: &File) -> io::Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::FileExt;
    let length = file.metadata()?.len();
    if length == 0 || length > 64 << 20 {
        return Err(invalid());
    }
    let mut hasher = Sha256::new();
    let mut offset = 0;
    let mut buffer = [0u8; 8192];
    loop {
        let count = file.read_at(&mut buffer, offset)?;
        if count == 0 {
            break;
        }
        offset = offset.checked_add(count as u64).ok_or_else(invalid)?;
        if offset > length {
            return Err(invalid());
        }
        hasher.update(&buffer[..count]);
    }
    if offset != length {
        return Err(invalid());
    }
    Ok(hasher.finalize().into())
}

pub(super) fn approved(digest: &[u8; 32], architecture: &str) -> io::Result<()> {
    // Only exact, source-audited release members grant the attach-before-fork contract.
    // Unsupported architectures and builds fail closed; a version string is not approval.
    const BUILDS: &[(&str, &str)] = &[
        (
            "x86_64",
            "65ef226e96f0ceda55ba643f445801ef2cc0ea667ef67cad8ac4f406c9c8434f",
        ),
        (
            "aarch64",
            "4d8d2dd4dfc1d47932b2bd261479181dd0c54f0a2f32714421a7e7f9f07ddec8",
        ),
    ];
    let actual = hex::encode(digest);
    if !BUILDS
        .iter()
        .any(|(arch, sha)| *arch == architecture && *sha == actual)
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn approved_builds_bind_architecture_and_every_elf_byte() {
        let x86: [u8; 32] =
            hex::decode("65ef226e96f0ceda55ba643f445801ef2cc0ea667ef67cad8ac4f406c9c8434f")
                .unwrap()
                .try_into()
                .unwrap();
        let arm: [u8; 32] =
            hex::decode("4d8d2dd4dfc1d47932b2bd261479181dd0c54f0a2f32714421a7e7f9f07ddec8")
                .unwrap()
                .try_into()
                .unwrap();
        approved(&x86, "x86_64").unwrap();
        approved(&arm, "aarch64").unwrap();
        assert!(approved(&x86, "aarch64").is_err());
        assert!(approved(&arm, "x86_64").is_err());
        assert!(approved(&x86, "unknown").is_err());
        let mut custom = x86;
        custom[0] ^= 1;
        assert!(approved(&custom, "x86_64").is_err());
    }
    #[test]
    fn held_file_digest_detects_in_place_customization_and_requires_positive_eof() {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = tempfile::tempfile().unwrap();
        assert!(hash(&file).is_err());
        file.write_all(&vec![7; 16385]).unwrap();
        let first = hash(&file).unwrap();
        file.seek(SeekFrom::Start(8192)).unwrap();
        file.write_all(&[8]).unwrap();
        assert_ne!(first, hash(&file).unwrap());
        file.set_len(0).unwrap();
        assert!(hash(&file).is_err());
    }
}
