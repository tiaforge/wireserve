//! Token formatting and hashing shared between the coordinator (issues and
//! verifies both join and bearer tokens) and any code that needs to display
//! or parse a token consistently.

use sha2::{Digest, Sha256};

pub const JOIN_TOKEN_PREFIX: &str = "jtk_";
pub const BEARER_TOKEN_PREFIX: &str = "brt_";

/// SHA256 hex digest of a token's raw string form (including its `jtk_`/
/// `brt_` prefix). Deliberately unsalted, plain SHA256 — see spec §3 for the
/// rationale (tokens are CSPRNG-generated with ~256 bits of entropy, so
/// salting/slow-KDF add nothing here; this mirrors GitHub/GitLab-style API
/// token storage). The coordinator is the only thing that ever computes this
/// against a value someone claims is a valid token, and it does so
/// identically on issue (to store) and on every request (to verify).
#[must_use]
pub fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex_encode(&digest)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_token_is_deterministic() {
        let a = hash_token("jtk_abc123");
        let b = hash_token("jtk_abc123");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_token_matches_known_sha256_vector() {
        // echo -n "hello" | sha256sum
        assert_eq!(
            hash_token("hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn different_inputs_do_not_collide_in_practice() {
        let a = hash_token("jtk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let b = hash_token("jtk_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        assert_ne!(a, b);
    }

    #[test]
    fn output_is_hex_of_expected_length() {
        let h = hash_token("brt_whatever");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
