//! The sign-in's session tokens (PLAN.md M48).
//!
//! The coordinator signs one with a key only it holds; every terminator
//! checks it with the public key that comes with the poll, so a request is
//! checked on its own node without asking anyone. A token names one
//! service (`aud`): the cookie holding it is that service's alone, and a
//! terminator refuses one made out to any other — a service's owner, who
//! sees its cookies, can replay them nowhere else.
//!
//! The format is `wst1.<payload>.<signature>`, both base64url without
//! padding; the payload is JSON, and the signature covers `wst1.<payload>`.

use base64::Engine as _;
use ed25519_dalek::{Signer as _, Verifier as _};
use serde::{Deserialize, Serialize};

pub use ed25519_dalek::{SigningKey, VerifyingKey};

/// Every token starts with this, the format's version.
pub const TOKEN_PREFIX: &str = "wst1.";

/// The cookie a terminator keeps a service's session in. `__Host-`: set by
/// that service's own name only, over https, for every path — never by a
/// sibling under the same domain.
pub const COOKIE: &str = "__Host-wireserve-session";

/// Ties a sign-in to the browser that started it: the terminator sets it
/// before sending the browser to sign in, and only a ticket issued for its
/// value is redeemed there. Without it, someone could sign in, stop at the
/// redirect, and hand the ticket to someone else — whose browser would
/// then be signed in as them.
pub const BIND_COOKIE: &str = "__Host-wireserve-bind";

/// What the coordinator is told of a browser's [`BIND_COOKIE`]: its SHA-256,
/// in hex — the value itself stays in the browser.
#[must_use]
pub fn bind_hash(value: &str) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(value.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether `value` has the shape of a token the coordinator or a terminator
/// makes: `prefix` and 64 lowercase hex digits. Anything else is refused
/// before it costs anyone a call.
#[must_use]
pub fn is_token_of(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|h| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// The prefix of a ticket.
pub const TICKET_PREFIX: &str = "tkt_";

/// Where the coordinator sends a browser back to, on the service's own name,
/// with a ticket to redeem.
pub const CALLBACK_PATH: &str = "/.wireserve/callback";

/// Where a person signs out, on any service's name.
pub const SIGN_OUT_PATH: &str = "/.wireserve/sign-out";

/// The longest token anything accepts. A browser keeps a cookie of at most
/// 4096 bytes, name included; the coordinator keeps under this when it
/// signs (it leaves out groups no grant names when it must).
pub const MAX_TOKEN_LEN: usize = 3800;

/// The longest ticket a terminator passes on.
pub const MAX_TICKET_LEN: usize = 128;

/// What a token says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// The session, as the coordinator knows it.
    pub sid: String,
    /// The person's subject at the identity provider.
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    /// The one service it is good for: `<service>.<domain>`.
    pub aud: String,
    /// Unix seconds after which it must be renewed.
    pub exp: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    #[error("not a session token")]
    Malformed,
    #[error("the signature does not check out")]
    BadSignature,
}

/// A signing key from its 32-byte seed.
#[must_use]
pub fn signing_key(seed: &[u8; 32]) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(seed)
}

/// The public half of `key`, as nodes are given it: base64url, unpadded.
#[must_use]
pub fn public_key(key: &ed25519_dalek::SigningKey) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes())
}

/// Parses a public key as [`public_key`] writes it.
#[must_use]
pub fn parse_public_key(text: &str) -> Option<ed25519_dalek::VerifyingKey> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(text).ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&raw.try_into().ok()?).ok()
}

/// Signs `session`.
#[must_use]
pub fn sign(key: &ed25519_dalek::SigningKey, session: &Session) -> String {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload = serde_json::to_vec(session).expect("a session serializes");
    let signed = format!("{TOKEN_PREFIX}{}", b64.encode(payload));
    let signature = key.sign(signed.as_bytes());
    format!("{signed}.{}", b64.encode(signature.to_bytes()))
}

/// What `token` says, if `key` signed it. Says nothing about whether it is
/// for this service or still fresh: [`Session::aud`] and [`Session::exp`]
/// are the caller's to check.
pub fn verify(key: &ed25519_dalek::VerifyingKey, token: &str) -> Result<Session, TokenError> {
    if token.len() > MAX_TOKEN_LEN || !token.starts_with(TOKEN_PREFIX) {
        return Err(TokenError::Malformed);
    }
    let (signed, signature) = token.rsplit_once('.').ok_or(TokenError::Malformed)?;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let signature: [u8; 64] = b64.decode(signature).ok().and_then(|s| s.try_into().ok()).ok_or(TokenError::Malformed)?;
    key.verify(signed.as_bytes(), &ed25519_dalek::Signature::from_bytes(&signature))
        .map_err(|_| TokenError::BadSignature)?;
    let payload = b64.decode(&signed[TOKEN_PREFIX.len()..]).map_err(|_| TokenError::Malformed)?;
    serde_json::from_slice(&payload).map_err(|_| TokenError::Malformed)
}

/// `value` made safe to put in a URL's query: everything but the
/// characters that need no escaping is percent-encoded.
#[must_use]
pub fn encode_query_value(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Whether `to` may be where a browser is sent after signing in: a path on
/// the same service, and nothing that could name another host (`//host`,
/// `/\host`, a scheme).
#[must_use]
pub fn is_local_path(to: &str) -> bool {
    to.starts_with('/')
        && !to.starts_with("//")
        && !to.starts_with("/\\")
        && to.len() <= 2048
        && !to.bytes().any(|b| b.is_ascii_control() || b == b' ')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Session {
        Session {
            sid: "s1".into(),
            sub: "anna".into(),
            email: Some("anna@example.com".into()),
            groups: vec!["family".into()],
            aud: "grafana.int.test".into(),
            exp: 1_900_000_000,
        }
    }

    #[test]
    fn a_token_reads_back_with_the_key_that_signed_it_only() {
        let key = signing_key(&[7; 32]);
        let token = sign(&key, &session());
        assert!(token.starts_with(TOKEN_PREFIX));
        let public = parse_public_key(&public_key(&key)).unwrap();
        assert_eq!(verify(&public, &token).unwrap(), session());

        let other = signing_key(&[8; 32]).verifying_key();
        assert_eq!(verify(&other, &token), Err(TokenError::BadSignature));
    }

    #[test]
    fn a_changed_token_does_not_check_out() {
        let key = signing_key(&[7; 32]);
        let public = key.verifying_key();
        let token = sign(&key, &session());
        let (signed, signature) = token.rsplit_once('.').unwrap();
        let mut forged = session();
        forged.aud = "vault.int.test".into();
        let forged_payload = sign(&signing_key(&[9; 32]), &forged);
        let forged_signed = forged_payload.rsplit_once('.').unwrap().0;
        assert_eq!(verify(&public, &format!("{forged_signed}.{signature}")), Err(TokenError::BadSignature));
        assert_eq!(verify(&public, signed), Err(TokenError::Malformed), "no signature");
        assert_eq!(verify(&public, "wst2.a.b"), Err(TokenError::Malformed));
        assert_eq!(verify(&public, &"x".repeat(MAX_TOKEN_LEN + 1)), Err(TokenError::Malformed));
    }

    #[test]
    fn only_tokens_of_the_right_shape_pass() {
        let t = format!("tkt_{}", "a1".repeat(32));
        assert!(is_token_of(&t, TICKET_PREFIX));
        assert!(!is_token_of(&t.to_uppercase(), TICKET_PREFIX));
        assert!(!is_token_of(&format!("{t}0"), TICKET_PREFIX));
        assert!(!is_token_of("tkt_", TICKET_PREFIX));
        assert_eq!(bind_hash("x").len(), 64);
        assert!(is_token_of(&bind_hash("x"), ""));
    }

    #[test]
    fn a_query_value_is_escaped_whole() {
        assert_eq!(encode_query_value("/a b?x=1&y=/"), "%2Fa%20b%3Fx%3D1%26y%3D%2F");
        assert_eq!(encode_query_value("plain-1.2_~"), "plain-1.2_~");
    }

    #[test]
    fn only_a_path_on_the_same_service_is_somewhere_to_go_back_to() {
        for ok in ["/", "/dashboard?x=1", "/a/b#c"] {
            assert!(is_local_path(ok), "{ok}");
        }
        for bad in ["", "dashboard", "//evil.example/", "/\\evil.example", "https://evil.example/", "/a b", "/a\nb"] {
            assert!(!is_local_path(bad), "{bad:?}");
        }
    }
}
