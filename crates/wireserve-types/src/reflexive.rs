//! The wire format for the coordinator's self-hosted, STUN-like UDP
//! reflexive-address responder (PLAN.md M22, NAT-traversal step 2).
//!
//! Deliberately not real RFC 5389 STUN — nothing outside this project
//! ever needs to talk to this responder, so a minimal, fixed-size
//! custom protocol is enough and is far simpler to implement and audit
//! than STUN's full attribute/TLV framing.
//!
//! **Fixed sizes are the whole security story.** This is a public,
//! unauthenticated UDP endpoint (same trust model as the existing
//! unauthenticated `GET /probe` over TCP), which makes it a classic
//! reflection/amplification target: an attacker spoofs a victim's source
//! address and the responder blindly replies to that address instead.
//! The mitigation is structural rather than behavioral: [`RESPONSE_LEN`]
//! is smaller than [`REQUEST_LEN`], so the reflection factor is always
//! well under 1x — there is no request shape that produces a larger
//! reply, so this can never be used to amplify traffic toward a spoofed
//! victim, independent of any rate limiting layered on top.

use std::net::{Ipv4Addr, SocketAddrV4};

/// Identifies this exact protocol/version — never RFC 5389's magic
/// cookie, so a real STUN client or server can never mistake this for
/// standard STUN traffic (which would otherwise be misleading, since the
/// framing is entirely different despite the superficial resemblance).
const MAGIC: [u8; 4] = *b"WSR1";

/// The request is fixed-size and checked by exact equality — no
/// variable-length parsing at all, and the fixed size is what bounds the
/// reflection factor (see module doc). Comfortably larger than the
/// magic+version+nonce it actually carries; the remainder is zero
/// padding.
pub const REQUEST_LEN: usize = 64;

/// magic(4) + version(1) + nonce(8) + ipv4(4) + port(2) = 19 bytes —
/// well under [`REQUEST_LEN`], so the reflection factor is under 1x by
/// construction.
pub const RESPONSE_LEN: usize = 19;

const VERSION: u8 = 1;

// The whole anti-amplification mitigation, as a compile-time fact (see
// module doc) rather than merely a test that happens to run.
const _: () = assert!(RESPONSE_LEN < REQUEST_LEN);

pub type Nonce = [u8; 8];

/// Builds a fixed-[`REQUEST_LEN`]-byte request carrying `nonce`,
/// zero-padded. The nonce is round-tripped verbatim in the response so a
/// caller can reject a stray or spoofed reply arriving on the same
/// socket that doesn't answer the request it actually sent.
#[must_use]
pub fn build_request(nonce: Nonce) -> [u8; REQUEST_LEN] {
    let mut buf = [0u8; REQUEST_LEN];
    buf[0..4].copy_from_slice(&MAGIC);
    buf[4] = VERSION;
    buf[5..13].copy_from_slice(&nonce);
    buf
}

/// `None` for anything that isn't exactly [`REQUEST_LEN`] bytes with the
/// right magic and version — the responder drops those with no reply at
/// all (an error reply is still a reflected packet; see
/// `wireserve-coordinator::reflexive`).
#[must_use]
pub fn parse_request(buf: &[u8]) -> Option<Nonce> {
    if buf.len() != REQUEST_LEN || buf[0..4] != MAGIC || buf[4] != VERSION {
        return None;
    }
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&buf[5..13]);
    Some(nonce)
}

/// Builds the fixed-[`RESPONSE_LEN`]-byte response: `nonce` echoed back,
/// then the observed address as raw bytes (never text — keeps the size
/// exact and the parsing trivial).
#[must_use]
pub fn build_response(nonce: Nonce, addr: SocketAddrV4) -> [u8; RESPONSE_LEN] {
    let mut buf = [0u8; RESPONSE_LEN];
    buf[0..4].copy_from_slice(&MAGIC);
    buf[4] = VERSION;
    buf[5..13].copy_from_slice(&nonce);
    buf[13..17].copy_from_slice(&addr.ip().octets());
    buf[17..19].copy_from_slice(&addr.port().to_be_bytes());
    buf
}

/// `None` for anything that isn't exactly [`RESPONSE_LEN`] bytes with
/// the right magic and version.
#[must_use]
pub fn parse_response(buf: &[u8]) -> Option<(Nonce, SocketAddrV4)> {
    if buf.len() != RESPONSE_LEN || buf[0..4] != MAGIC || buf[4] != VERSION {
        return None;
    }
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&buf[5..13]);
    let ip = Ipv4Addr::new(buf[13], buf[14], buf[15], buf[16]);
    let port = u16::from_be_bytes([buf[17], buf[18]]);
    Some((nonce, SocketAddrV4::new(ip, port)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let buf = build_request(nonce);
        assert_eq!(buf.len(), REQUEST_LEN);
        assert_eq!(parse_request(&buf), Some(nonce));
    }

    #[test]
    fn response_round_trips() {
        let nonce = [9, 8, 7, 6, 5, 4, 3, 2];
        let addr = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 5), 51820);
        let buf = build_response(nonce, addr);
        assert_eq!(buf.len(), RESPONSE_LEN);
        assert_eq!(parse_response(&buf), Some((nonce, addr)));
    }

    #[test]
    fn parse_request_rejects_wrong_length() {
        assert!(parse_request(&[0u8; REQUEST_LEN - 1]).is_none());
        assert!(parse_request(&[0u8; REQUEST_LEN + 1]).is_none());
    }

    #[test]
    fn parse_request_rejects_wrong_magic_or_version() {
        let mut buf = build_request([0; 8]);
        buf[0] = b'X';
        assert!(parse_request(&buf).is_none());

        let mut buf = build_request([0; 8]);
        buf[4] = VERSION + 1;
        assert!(parse_request(&buf).is_none());
    }

    #[test]
    fn parse_response_rejects_wrong_length_magic_or_version() {
        let addr = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 1234);
        assert!(parse_response(&[0u8; RESPONSE_LEN - 1]).is_none());
        assert!(parse_response(&[0u8; RESPONSE_LEN + 1]).is_none());

        let mut buf = build_response([0; 8], addr);
        buf[0] = b'X';
        assert!(parse_response(&buf).is_none());

        let mut buf = build_response([0; 8], addr);
        buf[4] = VERSION + 1;
        assert!(parse_response(&buf).is_none());
    }
}
