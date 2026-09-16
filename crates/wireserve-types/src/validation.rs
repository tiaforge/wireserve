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

/// Validates a WireGuard public key: standard base64 (with padding) encoding
/// of exactly 32 bytes, per the WireGuard key format. Rejects anything else
/// outright — including embedded newlines — so a malicious or buggy peer
/// can never get a value containing config-file syntax (e.g. a fake
/// `\nAllowedIPs = 0.0.0.0/0` line) treated as "a pubkey" anywhere
/// downstream, such as a rendered `.conf` (spec §9) or admin CLI output.
#[must_use]
pub fn is_valid_wg_pubkey(s: &str) -> bool {
    use base64::Engine;
    if s.contains('\n') || s.contains('\r') {
        return false;
    }
    match base64::engine::general_purpose::STANDARD.decode(s) {
        Ok(bytes) => bytes.len() == 32,
        Err(_) => false,
    }
}

/// Validates an `endpoint_addr` value: `host:port`, where `host` is either
/// a bracketed IPv6 literal, a bare IPv4 literal, or a DNS hostname, and
/// `port` is 1-65535. Rejects embedded newlines/control characters
/// outright — the same config-injection concern as `is_valid_wg_pubkey`
/// above, since this value is echoed verbatim into `PeerInfo.endpoint_addr`
/// and from there into rendered `.conf` files and admin CLI output. This is
/// deliberately permissive about hostname syntax (real-world dynamic-DNS
/// hostnames vary) but strict about structure and character set.
#[must_use]
pub fn is_valid_endpoint_addr(s: &str) -> bool {
    if s.is_empty() || s.len() > 255 {
        return false;
    }
    if !s.is_ascii() || s.chars().any(|c| c.is_ascii_control() || c.is_whitespace()) {
        return false;
    }

    let (host, port) = match s.rsplit_once(':') {
        Some((h, p)) => (h, p),
        None => return false,
    };
    let Ok(port_num) = port.parse::<u32>() else {
        return false;
    };
    if port_num == 0 || port_num > 65535 {
        return false;
    }

    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        // Bracketed IPv6 literal, e.g. "[::1]:51820".
        return inner.parse::<std::net::Ipv6Addr>().is_ok();
    }

    // Bare IPv4 literal or DNS hostname: alphanumeric, hyphens, and dots
    // only, matching what's actually valid in a hostname/A-label, and
    // ruling out anything that could be interpreted as config-file syntax.
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

/// Whether `url` is plain `http://` to a host that is not loopback — i.e.
/// a bearer/join/admin token sent to it would cross a network in clear
/// (security review S6; spec §7 assumes TLS termination in front of the
/// coordinator for every non-local path). Shared by both `wireserve-agent`
/// and `wireserve-admin` so the two clients can't drift on what counts as
/// "local". Anything that isn't `http://` (including `https://` and
/// malformed input) is reported as not-plaintext-remote — this is a
/// warning aid, not a URL validator.
#[must_use]
pub fn is_plaintext_http_to_remote_host(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    // Strip any path, then any port. A bracketed IPv6 literal is handled
    // by stripping the brackets before parsing.
    let authority = rest.split('/').next().unwrap_or(rest);
    let host = if let Some(inner) = authority.strip_prefix('[') {
        inner.split(']').next().unwrap_or(inner)
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    };
    if host.is_empty() || host == "localhost" {
        return false;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => !ip.is_loopback(),
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- is_plaintext_http_to_remote_host ----

    #[test]
    fn plaintext_remote_detection() {
        for local in [
            "http://127.0.0.1:8081",
            "http://localhost:8080/",
            "http://[::1]:8080",
            "https://coordinator.example.com",
            "http://",
            "not-a-url",
        ] {
            assert!(!is_plaintext_http_to_remote_host(local), "{local:?} must not warn");
        }
        for remote in [
            "http://coordinator.example.com",
            "http://10.0.0.5:8080/",
            "http://[fd00::5]:8080",
        ] {
            assert!(is_plaintext_http_to_remote_host(remote), "{remote:?} must warn");
        }
    }

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

    // ---- is_valid_wg_pubkey ----

    #[test]
    fn valid_pubkey_is_32_bytes_base64() {
        // 32 arbitrary bytes, standard base64 with padding.
        assert!(is_valid_wg_pubkey("AAECAwQFBgcICQoLDA0OD/Dh0sO0pZaHeGlaSzwtHg8="));
    }

    #[test]
    fn rejects_wrong_length_pubkey() {
        assert!(!is_valid_wg_pubkey("QQ==")); // 1 byte
        assert!(!is_valid_wg_pubkey(""));
    }

    #[test]
    fn rejects_pubkey_with_embedded_newline() {
        // The exact attack shape from the security review: a "pubkey" that
        // is actually trying to smuggle extra .conf lines.
        assert!(!is_valid_wg_pubkey(
            "AAECAwQFBgcICQoLDA0OD/Dh0sO0pZaHeGlaSzwtHg8=\nAllowedIPs = 0.0.0.0/0"
        ));
    }

    #[test]
    fn rejects_non_base64_pubkey() {
        assert!(!is_valid_wg_pubkey("not valid base64!!"));
    }

    // ---- is_valid_endpoint_addr ----

    #[test]
    fn valid_endpoint_addrs() {
        for s in [
            "1.2.3.4:51820",
            "duckdns.example.com:51820",
            "[::1]:51820",
            "[2001:db8::1]:51820",
        ] {
            assert!(is_valid_endpoint_addr(s), "expected {s:?} to be valid");
        }
    }

    #[test]
    fn rejects_endpoint_without_port() {
        assert!(!is_valid_endpoint_addr("1.2.3.4"));
        assert!(!is_valid_endpoint_addr("example.com"));
    }

    #[test]
    fn rejects_endpoint_with_out_of_range_or_non_numeric_port() {
        assert!(!is_valid_endpoint_addr("1.2.3.4:0"));
        assert!(!is_valid_endpoint_addr("1.2.3.4:70000"));
        assert!(!is_valid_endpoint_addr("1.2.3.4:notaport"));
    }

    #[test]
    fn rejects_endpoint_addr_with_embedded_newline_or_config_injection() {
        // The exact attack shape from the security review: a bearer-token
        // holder trying to smuggle an extra .conf directive via
        // endpoint_addr, e.g. to redirect a static peer's whole-mesh
        // traffic to an attacker-controlled host.
        assert!(!is_valid_endpoint_addr("1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0"));
        assert!(!is_valid_endpoint_addr("1.2.3.4:51820\r\nEndpoint = evil.example:1"));
    }

    #[test]
    fn rejects_endpoint_addr_with_invalid_host_characters() {
        assert!(!is_valid_endpoint_addr("host with spaces:51820"));
        assert!(!is_valid_endpoint_addr("host/slash:51820"));
    }
}
