//! CSPRNG token generation (PLAN.md decisions log #1): 32 random bytes,
//! hex-encoded, after the `jtk_`/`brt_` prefix.

/// Generates a new opaque token: `prefix` followed by 64 lowercase hex
/// characters (32 bytes of CSPRNG output).
pub fn generate(prefix: &str) -> String {
    let bytes: [u8; 32] = rand::random();
    let mut out = String::with_capacity(prefix.len() + 64);
    out.push_str(prefix);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_expected_shape() {
        let t = generate("jtk_");
        assert!(t.starts_with("jtk_"));
        assert_eq!(t.len(), 4 + 64);
        assert!(t[4..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generates_distinct_values() {
        let a = generate("brt_");
        let b = generate("brt_");
        assert_ne!(a, b);
    }
}
