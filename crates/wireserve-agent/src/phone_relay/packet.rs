//! What a carrier reads of a WireGuard packet without any key (PLAN.md
//! #337): its type, its session indexes, and the `mac1` of a handshake,
//! which names the public key it is meant for.
//!
//! Layouts from the WireGuard paper, all little-endian:
//!
//! | type | size | sender | receiver | `mac1` over |
//! | --- | --- | --- | --- | --- |
//! | 1 initiation | 148 | 4 | — | `[..116]` |
//! | 2 response | 92 | 4 | 8 | `[..60]` |
//! | 3 cookie reply | 64 | — | 4 | — |
//! | 4 data | ≥ 32 | — | 4 | — |

use blake2::digest::{FixedOutput, KeyInit, Update};
use blake2::{Blake2s256, Blake2sMac, Digest};

/// The label `mac1`'s key is hashed with.
const LABEL_MAC1: &[u8; 8] = b"mac1----";

pub const INITIATION_LEN: usize = 148;
pub const RESPONSE_LEN: usize = 92;
pub const COOKIE_REPLY_LEN: usize = 64;
/// A data packet's header and authentication tag: a keepalive is exactly
/// this long.
pub const DATA_MIN_LEN: usize = 32;

/// Where `mac1` starts in an initiation and a response: it covers every
/// byte before it.
const INITIATION_MAC1: usize = 116;
const RESPONSE_MAC1: usize = 60;

/// The four message types, as the first four bytes read in network order
/// (the type byte, then three zero bytes): what the firewall matches on.
pub const TYPE_WORD_INITIATION: u32 = 0x0100_0000;
pub const TYPE_WORD_RESPONSE: u32 = 0x0200_0000;
pub const TYPE_WORD_COOKIE_REPLY: u32 = 0x0300_0000;
pub const TYPE_WORD_DATA: u32 = 0x0400_0000;

/// A WireGuard message, by what the carrier reads of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Message {
    Initiation { sender: u32 },
    Response { sender: u32, receiver: u32 },
    CookieReply { receiver: u32 },
    Data { receiver: u32 },
}

impl Message {
    /// Reads `packet` as a WireGuard message: `None` for anything else —
    /// a wrong type, the reserved bytes set, or the wrong size.
    #[must_use]
    pub fn parse(packet: &[u8]) -> Option<Self> {
        let head: [u8; 4] = packet.get(..4)?.try_into().ok()?;
        if head[1..] != [0, 0, 0] {
            return None;
        }
        let index = |at: usize| packet.get(at..at + 4).map(|b| u32::from_le_bytes(b.try_into().expect("four bytes")));
        match (head[0], packet.len()) {
            (1, INITIATION_LEN) => Some(Self::Initiation { sender: index(4)? }),
            (2, RESPONSE_LEN) => Some(Self::Response { sender: index(4)?, receiver: index(8)? }),
            (3, COOKIE_REPLY_LEN) => Some(Self::CookieReply { receiver: index(4)? }),
            (4, n) if n >= DATA_MIN_LEN => Some(Self::Data { receiver: index(4)? }),
            _ => None,
        }
    }
}

/// The key a handshake meant for `pubkey` carries its `mac1` under:
/// `HASH(LABEL_MAC1 ‖ pubkey)`. Worked out once per key, not per packet.
#[must_use]
pub fn mac1_key(pubkey: &[u8; 32]) -> [u8; 32] {
    let mut hash = Blake2s256::new();
    Digest::update(&mut hash, LABEL_MAC1);
    Digest::update(&mut hash, pubkey);
    hash.finalize().into()
}

/// Whether `packet`, an initiation or a response, carries a `mac1` made
/// with `key` ([`mac1_key`]) — that is, whether it is meant for that key's
/// owner. Anything else is never.
#[must_use]
pub fn mac1_matches(packet: &[u8], key: &[u8; 32]) -> bool {
    let covered = match packet.len() {
        INITIATION_LEN if packet[0] == 1 => INITIATION_MAC1,
        RESPONSE_LEN if packet[0] == 2 => RESPONSE_MAC1,
        _ => return false,
    };
    let mut mac: Blake2sMac<blake2::digest::consts::U16> =
        Blake2sMac::new_from_slice(key).expect("a 32-byte key is a valid BLAKE2s key");
    Update::update(&mut mac, &packet[..covered]);
    let want: [u8; 16] = mac.finalize_fixed().into();
    // Not secret: anyone who knows the public key computes the same. A
    // plain comparison is fine.
    packet[covered..covered + 16] == want
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use defguard_boringtun::noise::{Tunn, TunnResult};
    use defguard_boringtun::x25519::{PublicKey, StaticSecret};

    /// A WireGuard end in userspace, for real handshakes.
    pub(crate) struct End {
        pub secret: [u8; 32],
        pub public: [u8; 32],
    }

    impl End {
        pub(crate) fn new(seed: u8) -> Self {
            let secret = StaticSecret::from([seed; 32]);
            let public = PublicKey::from(&secret).to_bytes();
            Self { secret: secret.to_bytes(), public }
        }

        pub(crate) fn tunnel_to(&self, peer: &End, index: u32) -> Tunn {
            Tunn::new(StaticSecret::from(self.secret), PublicKey::from(peer.public), None, None, index, None)
        }
    }

    pub(crate) fn initiation(tunn: &mut Tunn) -> Vec<u8> {
        let mut buf = vec![0u8; 2048];
        match tunn.format_handshake_initiation(&mut buf, false) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("no initiation: {other:?}"),
        }
    }

    /// What `tunn` sends back for `datagram` (a response, a keepalive).
    pub(crate) fn answer(tunn: &mut Tunn, datagram: &[u8]) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 2048];
        match tunn.decapsulate(None, datagram, &mut buf) {
            TunnResult::WriteToNetwork(p) => Some(p.to_vec()),
            TunnResult::Done | TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => None,
            TunnResult::Err(e) => panic!("rejected: {e:?}"),
        }
    }

    /// A small IPv4 packet carried through a session, as data.
    pub(crate) fn data(tunn: &mut Tunn) -> Vec<u8> {
        let mut inner = vec![0u8; 28];
        inner[0] = 0x45;
        inner[2..4].copy_from_slice(&28u16.to_be_bytes());
        inner[9] = 17;
        inner[12..16].copy_from_slice(&[10, 0, 0, 1]);
        inner[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let mut buf = vec![0u8; 2048];
        match tunn.encapsulate(&inner, &mut buf) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("no data packet: {other:?}"),
        }
    }

    #[test]
    fn a_real_handshake_and_its_data_parse() {
        let (phone, node) = (End::new(1), End::new(2));
        let (mut p, mut n) = (phone.tunnel_to(&node, 7), node.tunnel_to(&phone, 9));
        let init = initiation(&mut p);
        let Some(Message::Initiation { sender: phone_index }) = Message::parse(&init) else { panic!("{init:?}") };
        let resp = answer(&mut n, &init).unwrap();
        let Some(Message::Response { sender: node_index, receiver }) = Message::parse(&resp) else { panic!() };
        assert_eq!(receiver, phone_index, "the response names the initiation it answers");
        // The phone's keepalive completing the handshake is data for the node.
        let keepalive = answer(&mut p, &resp).unwrap();
        assert_eq!(Message::parse(&keepalive), Some(Message::Data { receiver: node_index }));
        // The responder's session starts with the initiator's first packet.
        assert!(answer(&mut n, &keepalive).is_none());
        assert_eq!(Message::parse(&data(&mut n)), Some(Message::Data { receiver: phone_index }));
        assert_eq!(Message::parse(&data(&mut p)), Some(Message::Data { receiver: node_index }));
    }

    #[test]
    fn mac1_names_the_responder_of_an_initiation_and_the_initiator_of_a_response() {
        let (phone, node, other) = (End::new(1), End::new(2), End::new(3));
        let (mut p, mut n) = (phone.tunnel_to(&node, 7), node.tunnel_to(&phone, 9));
        let init = initiation(&mut p);
        assert!(mac1_matches(&init, &mac1_key(&node.public)));
        assert!(!mac1_matches(&init, &mac1_key(&phone.public)));
        assert!(!mac1_matches(&init, &mac1_key(&other.public)));
        let resp = answer(&mut n, &init).unwrap();
        assert!(mac1_matches(&resp, &mac1_key(&phone.public)));
        assert!(!mac1_matches(&resp, &mac1_key(&node.public)));
    }

    #[test]
    fn a_changed_byte_breaks_mac1_and_other_messages_never_match() {
        let (phone, node) = (End::new(1), End::new(2));
        let mut p = phone.tunnel_to(&node, 7);
        let key = mac1_key(&node.public);
        let mut init = initiation(&mut p);
        init[40] ^= 1;
        assert!(!mac1_matches(&init, &key));
        assert!(!mac1_matches(&[1u8; INITIATION_LEN - 1], &key));
        assert!(!mac1_matches(&[2u8; INITIATION_LEN], &key), "a response's length, not its type");
    }

    #[test]
    fn anything_but_a_well_formed_message_is_none() {
        let mut init = [0u8; INITIATION_LEN];
        init[0] = 1;
        assert!(Message::parse(&init).is_some());
        init[1] = 1;
        assert_eq!(Message::parse(&init), None, "reserved bytes set");
        assert_eq!(Message::parse(&[1, 0, 0, 0, 5]), None, "short");
        assert_eq!(Message::parse(&[2u8, 0, 0, 0].repeat(INITIATION_LEN / 4)), None, "a response of an initiation's size");
        let mut data = vec![0u8; DATA_MIN_LEN];
        data[0] = 4;
        assert_eq!(Message::parse(&data), Some(Message::Data { receiver: 0 }), "a keepalive");
        assert_eq!(Message::parse(&data[..DATA_MIN_LEN - 1]), None);
        assert_eq!(Message::parse(&[5, 0, 0, 0, 0, 0, 0, 0]), None);
        assert_eq!(Message::parse(&[]), None);
    }

    #[test]
    fn the_type_words_are_what_the_firewall_reads() {
        for (word, kind) in [(TYPE_WORD_INITIATION, 1u8), (TYPE_WORD_RESPONSE, 2), (TYPE_WORD_COOKIE_REPLY, 3), (TYPE_WORD_DATA, 4)] {
            assert_eq!(word.to_be_bytes(), [kind, 0, 0, 0]);
        }
    }
}
