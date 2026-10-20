//! The bearer check the daemon and the fleet share.

/// Equal, without stopping at the first byte that differs: how long the comparison took says
/// nothing about how much of a token was right.
pub fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::constant_eq;

    #[test]
    fn equal_bytes_only() {
        assert!(constant_eq(b"t0k", b"t0k"));
        assert!(constant_eq(b"", b""));
        assert!(!constant_eq(b"t0k", b"t0K"));
        assert!(!constant_eq(b"t0k", b"t0"));
        assert!(!constant_eq(b"", b"t"));
    }
}
