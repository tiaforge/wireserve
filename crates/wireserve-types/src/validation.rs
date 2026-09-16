//! DNS-label-safe name validation, shared by every place spec §3 requires it:
//! the coordinator (`/admin/nodes`, `services[].name` in `/poll`),
//! `wireserve-admin`'s own argument parsing (fail fast, no round trip), and
//! implicitly relied on by the agent's `/etc/hosts` writer, which assumes
//! every name it's given from the coordinator is already valid.

const MAX_LABEL_LEN: usize = 63;

/// Lowercase alphanumeric and hyphens only, must start/end with an
/// alphanumeric character, at most 63 characters, non-empty.
#[must_use]
pub fn is_valid_dns_label(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_LABEL_LEN {
        return false;
    }
    let bytes = s.as_bytes();
    let is_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !is_alnum(bytes[0]) || !is_alnum(bytes[bytes.len() - 1]) {
        return false;
    }
    bytes.iter().all(|&b| is_alnum(b) || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_labels() {
        for s in ["a", "homeserver", "plex", "a-b-c", "node0", "0node", "a".repeat(63).as_str()] {
            assert!(is_valid_dns_label(s), "expected {s:?} to be valid");
        }
    }

    #[test]
    fn rejects_empty() {
        assert!(!is_valid_dns_label(""));
    }

    #[test]
    fn rejects_too_long() {
        let s = "a".repeat(64);
        assert!(!is_valid_dns_label(&s));
    }

    #[test]
    fn boundary_length_63_is_valid_64_is_not() {
        assert!(is_valid_dns_label(&"a".repeat(63)));
        assert!(!is_valid_dns_label(&"a".repeat(64)));
    }

    #[test]
    fn rejects_leading_hyphen() {
        assert!(!is_valid_dns_label("-plex"));
    }

    #[test]
    fn rejects_trailing_hyphen() {
        assert!(!is_valid_dns_label("plex-"));
    }

    #[test]
    fn rejects_uppercase() {
        assert!(!is_valid_dns_label("Plex"));
    }

    #[test]
    fn rejects_underscore() {
        assert!(!is_valid_dns_label("home_server"));
    }

    #[test]
    fn rejects_unicode() {
        assert!(!is_valid_dns_label("plëx"));
        assert!(!is_valid_dns_label("plex\u{1F600}"));
    }

    #[test]
    fn single_char_is_valid() {
        assert!(is_valid_dns_label("a"));
        assert!(is_valid_dns_label("9"));
    }

    #[test]
    fn digit_only_is_valid() {
        assert!(is_valid_dns_label("42"));
    }

    #[test]
    fn rejects_internal_whitespace_and_dots() {
        assert!(!is_valid_dns_label("home server"));
        assert!(!is_valid_dns_label("home.server"));
    }

    #[test]
    fn hyphen_in_middle_is_valid() {
        assert!(is_valid_dns_label("home-assistant"));
    }
}
