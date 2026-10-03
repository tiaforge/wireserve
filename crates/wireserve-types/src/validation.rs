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

    // Bare IPv4 literal or DNS hostname. Checked per label, not merely
    // per character: a charset-only check accepted `-x-.example.com` and
    // `...`, which are not hostnames in any sense and passed only because
    // every byte in them happened to be in the allowed set.
    //
    // One trailing dot is tolerated (the fully-qualified form,
    // `example.com.`), since real dynamic-DNS configuration does get
    // written that way. It is stripped before the per-label checks rather
    // than being left to produce an empty final label.
    let host = host.strip_suffix('.').unwrap_or(host);
    !host.is_empty() && host.split('.').all(is_valid_hostname_label)
}

/// One label of a DNS hostname, for [`is_valid_endpoint_addr`]: ASCII
/// alphanumerics and hyphens, 1-63 bytes, not starting or ending with a
/// hyphen.
///
/// Deliberately **not** [`is_valid_dns_label`], despite the nearly
/// identical rule. That one additionally requires lowercase, because it
/// governs names *this project* assigns and then writes into
/// `/etc/hosts` (node and service names, spec §3). A hostname somebody
/// else operates may legitimately be written in mixed case — DNS
/// comparison is case-insensitive — so rejecting
/// `Duckdns.Example.com:51820` would be this validator inventing a rule
/// the protocol does not have, on a value it does not own.
fn is_valid_hostname_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
        return false;
    }
    bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Validates a `lan_addr` value: a bare IPv4 literal — no port, unlike
/// `endpoint_addr` (it always borrows a port from whichever WAN candidate
/// a peer has, see `wireserve-agent`'s `wg::choose_peer_endpoint`) — that
/// is actually inside RFC1918 private space. Server-side defense in
/// depth: `wireserve-agent`'s own `wg::pick_lan_address` never emits
/// anything else, but a malicious or buggy agent must not get a public
/// address redistributed to every peer as a "same-LAN" candidate on
/// client-side trust alone.
#[must_use]
pub fn is_valid_lan_addr(s: &str) -> bool {
    s.parse::<std::net::Ipv4Addr>().is_ok_and(|ip| ip.is_private())
}

/// Validates a `reflexive_addr` value: bare `ip:port`, `ip` a literal
/// IPv4 address (never a hostname, never a bracketed IPv6 literal — this
/// value is only ever produced from a raw socket address the
/// coordinator's UDP reflexive responder itself observed, never
/// resolved), port 1-65535.
///
/// Unlike [`is_valid_lan_addr`], privacy is deliberately NOT required
/// here: in a fully internal deployment with no real NAT between a node
/// and the coordinator, the reflexive address legitimately IS a private
/// one (same reasoning `wireserve-coordinator`'s `client_ip` module
/// gives for why `endpoint_addr`'s own fallback doesn't reject private
/// addresses outright). This only enforces literal-IPv4:port structure,
/// as defense in depth against a malicious or buggy agent smuggling
/// something else into a value that gets redistributed to every peer
/// and configured as a live WireGuard endpoint
/// (`wireserve-agent`'s `wg::choose_peer_endpoint`).
#[must_use]
pub fn is_valid_reflexive_addr(s: &str) -> bool {
    let Some((host, port)) = s.rsplit_once(':') else {
        return false;
    };
    host.parse::<std::net::Ipv4Addr>().is_ok() && matches!(port.parse::<u16>(), Ok(p) if p != 0)
}

/// Whether `s` is a usable DNS domain to name services under (PLAN.md M25),
/// e.g. `int.example.com`.
///
/// Operator-supplied rather than coordinator-allocated, so this is a footgun
/// guard more than a trust boundary — but it is also the one component of a
/// generated reverse-proxy config that does not come from the validated
/// directory, and a newline or a `{$ENV}` reaching a Caddyfile through it
/// would be a config-injection all of its own. At least two labels, so a bare
/// TLD cannot be set by accident, and short enough that `<service>.<domain>`
/// still fits a 253-byte name.
#[must_use]
pub fn is_valid_hostname(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 || s.contains('\n') || s.contains('\r') {
        return false;
    }
    // One trailing dot is tolerated, as it is for an endpoint's hostname.
    let s = s.strip_suffix('.').unwrap_or(s);
    let labels: Vec<&str> = s.split('.').collect();
    labels.len() >= 2 && labels.iter().all(|l| is_valid_hostname_label(l))
}

/// Whether an `endpoint_addr`-shaped value (`host:port`, or
/// `[v6]:port`) names a host reachable from outside the local network.
///
/// This is deliberately stricter than [`is_valid_endpoint_addr`], which
/// permits private addresses on purpose — an endpoint is self-reported, and a
/// node on a home LAN legitimately advertises `192.168.1.50:51820` to its
/// neighbours there. That is fine for peers on the same LAN and useless to a
/// phone on cellular, so anything deciding whether a device can dial a node
/// *from anywhere* has to ask this question instead (PLAN.md M24).
///
/// A hostname is taken at its word: an operator who configured
/// `--endpoint home.example.com:51820` meant it to resolve publicly, and
/// resolving it here would only produce an answer valid from this machine.
#[must_use]
pub fn is_globally_routable_endpoint(s: &str) -> bool {
    let Some(host) = endpoint_host(s) else {
        return false;
    };
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        let o = v4.octets();
        // `Ipv4Addr::is_shared` is still unstable, so 100.64.0.0/10 — the
        // carrier-grade NAT range, where a node is behind someone else's NAT
        // and cannot be dialled at all — is spelled out here.
        let is_cgnat = o[0] == 100 && (64..128).contains(&o[1]);
        return !v4.is_private()
            && !v4.is_loopback()
            && !v4.is_link_local()
            && !v4.is_unspecified()
            && !v4.is_broadcast()
            && !v4.is_multicast()
            && !is_cgnat;
        // Documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24) are
        // deliberately NOT rejected. Unlike the ranges above they say nothing
        // about reachability — nobody configures one as a real endpoint by
        // accident — and they are what this project's tests use throughout to
        // mean "a public address".
    }
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        let seg = v6.segments();
        let is_unique_local = seg[0] & 0xfe00 == 0xfc00;
        let is_link_local = seg[0] & 0xffc0 == 0xfe80;
        return !v6.is_loopback()
            && !v6.is_unspecified()
            && !v6.is_multicast()
            && !is_unique_local
            && !is_link_local;
    }
    // A hostname, already shape-checked by `is_valid_endpoint_addr`.
    true
}

/// The host part of an `endpoint_addr`, minus the port and any brackets.
fn endpoint_host(s: &str) -> Option<&str> {
    if s.contains('\n') || s.contains('\r') {
        return None;
    }
    if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        return after.starts_with(':').then_some(host);
    }
    let (host, port) = s.rsplit_once(':')?;
    (!host.is_empty() && !port.is_empty()).then_some(host)
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
    fn rejects_structurally_invalid_hostname_labels() {
        // All of these passed the old charset-only check.
        for s in [
            "-x-.example.com:51820",
            "..:51820",
            "a..b:51820",
            "example-.com:51820",
            "-example.com:51820",
            ".example.com:51820",
        ] {
            assert!(!is_valid_endpoint_addr(s), "expected {s:?} to be rejected");
        }
        let too_long = format!("{}.com:51820", "a".repeat(64));
        assert!(!is_valid_endpoint_addr(&too_long));
    }

    #[test]
    fn accepts_hostname_forms_that_really_occur() {
        for s in [
            // Mixed case: DNS is case-insensitive and this value names
            // somebody else's host, so case is not ours to police.
            "Duckdns.Example.com:51820",
            // Fully-qualified trailing dot.
            "duckdns.example.com.:51820",
            "a.b.c.d.example.com:51820",
            "host-with-hyphens.example.com:51820",
            "1.2.3.4:51820",
        ] {
            assert!(is_valid_endpoint_addr(s), "expected {s:?} to be accepted");
        }
        let max_label = format!("{}.com:51820", "a".repeat(63));
        assert!(is_valid_endpoint_addr(&max_label));
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

    // ---- is_valid_reflexive_addr ----

    #[test]
    fn accepts_a_bare_ipv4_port() {
        assert!(is_valid_reflexive_addr("203.0.113.5:51820"));
        // Deliberately not RFC1918-only, unlike is_valid_lan_addr — a
        // private reflexive address is legitimate on an internal mesh.
        assert!(is_valid_reflexive_addr("192.168.1.5:51820"));
    }

    #[test]
    fn rejects_non_ipv4_port_forms() {
        for s in [
            "duckdns.example.com:51820", // hostname
            "[2001:db8::1]:51820",       // bracketed IPv6
            "203.0.113.5",               // no port
            "203.0.113.5:0",
            "203.0.113.5:70000",
            "203.0.113.5:notaport",
            "",
            "203.0.113.5:51820\nAllowedIPs = 0.0.0.0/0",
        ] {
            assert!(!is_valid_reflexive_addr(s), "expected {s:?} to be rejected");
        }
    }

    // ---- is_valid_lan_addr ----

    #[test]
    fn accepts_private_range_lan_addrs() {
        for s in ["10.0.0.5", "172.16.4.9", "192.168.1.50"] {
            assert!(is_valid_lan_addr(s), "expected {s:?} to be valid");
        }
    }

    #[test]
    fn rejects_non_private_or_malformed_lan_addrs() {
        for s in [
            "203.0.113.5",       // public
            "127.0.0.1",         // loopback
            "::1",                // IPv6
            "192.168.1.50:51820", // host:port form, not a bare address
            "",
            "192.168.1.50\nAllowedIPs = 0.0.0.0/0",
        ] {
            assert!(!is_valid_lan_addr(s), "expected {s:?} to be rejected");
        }
    }
}

#[cfg(test)]
mod routable_endpoint_tests {
    use super::is_globally_routable_endpoint;

    #[test]
    fn accepts_public_literals_and_hostnames() {
        for s in [
            "203.0.113.5:51820",
            "[2001:db8::1]:51820",
            "duckdns.example.com:51820",
            "home.example.com.:51820",
        ] {
            assert!(is_globally_routable_endpoint(s), "expected {s:?} routable");
        }
    }

    #[test]
    fn rejects_every_address_a_phone_off_the_lan_could_not_dial() {
        for s in [
            "192.168.1.50:51820",  // RFC1918 — the case this exists for
            "10.0.0.4:51820",
            "172.16.5.9:51820",
            "127.0.0.1:51820",     // loopback
            "169.254.3.4:51820",   // link-local
            "0.0.0.0:51820",
            "100.90.0.3:51820",    // CGNAT: behind someone else's NAT
            "[fd12:3456::1]:51820", // unique-local
            "[fe80::1]:51820",     // link-local
            "[::1]:51820",
        ] {
            assert!(!is_globally_routable_endpoint(s), "expected {s:?} rejected");
        }
    }

    #[test]
    fn rejects_malformed_values_rather_than_guessing() {
        for s in ["", "no-port", "203.0.113.5", "[2001:db8::1]", ":51820", "host:"] {
            assert!(!is_globally_routable_endpoint(s), "expected {s:?} rejected");
        }
    }

    #[test]
    fn rejects_anything_carrying_a_newline() {
        assert!(!is_globally_routable_endpoint("203.0.113.5:51820\nAllowedIPs = 0.0.0.0/0"));
    }
}

#[cfg(test)]
mod hostname_tests {
    use super::is_valid_hostname;

    #[test]
    fn accepts_ordinary_domains() {
        for s in ["int.example.com", "example.com", "a.b.c.example.com", "example.com."] {
            assert!(is_valid_hostname(s), "expected {s:?} accepted");
        }
    }

    #[test]
    fn rejects_a_bare_label_so_a_tld_cannot_be_set_by_accident() {
        assert!(!is_valid_hostname("example"));
        assert!(!is_valid_hostname("localhost"));
    }

    #[test]
    fn rejects_anything_that_could_reach_a_config_file_as_syntax() {
        for s in [
            "int.example.com\nEndpoint = evil",
            "int.example.com\r",
            "int.{$HOME}.com",
            "int example.com",
            "int.example.com { }",
            "",
            ".",
            "..",
            "-bad.example.com",
            "bad-.example.com",
        ] {
            assert!(!is_valid_hostname(s), "expected {s:?} rejected");
        }
    }

    #[test]
    fn rejects_an_over_long_name() {
        let long = format!("{}.example.com", "a".repeat(250));
        assert!(!is_valid_hostname(&long));
    }
}
