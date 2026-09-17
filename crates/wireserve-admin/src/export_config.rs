//! `wireserve-admin export-config <name>` (spec §9): generates a WireGuard
//! keypair locally, creates and immediately redeems a `kind: "static"` node
//! in one CLI call, and renders a `.conf` for import into an official
//! WireGuard client.

use defguard_wireguard_rs::key::Key;
use wireserve_types::{NodeKind, PeerInfo, RegisterRequest};

use crate::client::{self, AdminClient, ClientError};

#[derive(Debug, thiserror::Error)]
pub enum ExportConfigError {
    #[error(transparent)]
    Client(#[from] ClientError),
}

/// This node's own interface parameters for rendering: the private key
/// generated in step 1, its allocated addresses, and its own public key
/// (used only to skip a self-entry in the peer list — never sent anywhere).
pub struct InterfaceParams {
    pub private_key: String,
    pub ip4: String,
    pub ip6: String,
    pub own_pubkey: String,
}

/// Renders a full WireGuard `.conf`: this node's own `[Interface]` block,
/// then one `[Peer]` block per entry in `peers`, skipping any peer whose
/// pubkey matches this node's own (defensive — whether `/admin/peers`
/// already includes the just-registered node depends on timing, and either
/// way it must never get a `[Peer]` block pointing at itself).
///
/// Every peer's `AllowedIPs` is that peer's own `/32` (v4) + `/128` (v6),
/// never a shared mesh CIDR block — spec §9 is explicit about why: a wider
/// block would make this device act as a router for other peers' traffic,
/// and WireGuard requires non-overlapping `AllowedIPs` across peers on one
/// interface regardless.
///
/// Defense in depth (security review S2): the coordinator now validates
/// `pubkey`/`endpoint_addr` strictly at `/register` and `/poll` (rejecting
/// anything containing control characters, among other checks), so a
/// value reaching this function *should* already be safe — but this
/// renderer refuses to emit any peer whose `pubkey` or `endpoint_addr`
/// contains a newline regardless, rather than trusting the coordinator's
/// validation as the only line of defense against a value that would
/// otherwise let one field smuggle an entire extra `.conf` directive
/// (e.g. an `endpoint_addr` of `"1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0"`
/// hijacking this exported device's routing).
#[must_use]
pub fn render_conf(iface: &InterfaceParams, peers: &[PeerInfo]) -> String {
    let mut out = String::new();
    out.push_str("[Interface]\n");
    out.push_str(&format!("PrivateKey = {}\n", iface.private_key));
    out.push_str(&format!("Address = {}/32, {}/128\n", iface.ip4, iface.ip6));

    for peer in peers {
        if peer.pubkey == iface.own_pubkey {
            continue;
        }
        if contains_newline(&peer.pubkey)
            || peer
                .endpoint_addr
                .as_deref()
                .is_some_and(contains_newline)
        {
            eprintln!(
                "warning: skipping peer '{}' — its pubkey or endpoint_addr contains a newline, \
                 which could otherwise inject extra .conf directives; this indicates either a \
                 coordinator bug or a compromised/malicious node and should be investigated",
                peer.name
            );
            continue;
        }
        out.push('\n');
        out.push_str("[Peer]\n");
        out.push_str(&format!("PublicKey = {}\n", peer.pubkey));
        out.push_str(&format!("AllowedIPs = {}/32, {}/128\n", peer.ip4, peer.ip6));
        if let Some(endpoint) = &peer.endpoint_addr {
            out.push_str(&format!("Endpoint = {endpoint}\n"));
        }
        // This device likely roams networks (wifi/cellular switching, laptop
        // suspend) — keep the NAT mapping alive so return traffic works.
        out.push_str("PersistentKeepalive = 25\n");
    }

    out
}

fn contains_newline(s: &str) -> bool {
    s.contains('\n') || s.contains('\r')
}

/// Runs the full `export-config` flow end to end against a live
/// coordinator: keygen (local only), create+redeem a `kind: "static"` node,
/// fetch the peer directory, render the `.conf`.
///
/// Takes two base URLs, not one: `admin_client` talks to the coordinator's
/// admin listener (`create_node`, `list_peers`), while `node_facing_url`
/// is where `/register` actually lives — a separate listener by spec
/// §4.0's design, not just a separate path on the same one.
pub fn run(
    admin_client: &AdminClient,
    node_facing_url: &str,
    name: &str,
) -> Result<String, ExportConfigError> {
    let private_key = Key::generate();
    let public_key = private_key.public_key();

    // A short-lived token is right here for the same reason it is
    // elsewhere, and cheaper still: this token is minted and redeemed
    // within the same function, microseconds apart, and never leaves the
    // process. `None` takes the coordinator's configured default rather
    // than asking for special treatment.
    let created = admin_client.create_node(name, NodeKind::Static, None)?;

    let reg = client::register(
        node_facing_url,
        &RegisterRequest {
            join_token: created.join_token,
            pubkey: public_key.to_string(),
            kind: NodeKind::Static,
            listen_port: None,
            endpoint_addr: None,
        },
    )?;

    let directory = admin_client.list_peers()?;

    let iface = InterfaceParams {
        private_key: private_key.to_string(),
        ip4: reg.ip4,
        ip6: reg.ip6,
        own_pubkey: public_key.to_string(),
    };

    Ok(render_conf(&iface, &directory.peers))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(pubkey: &str, ip4: &str, ip6: &str, endpoint: Option<&str>) -> PeerInfo {
        PeerInfo {
            name: "n".into(),
            pubkey: pubkey.into(),
            ip4: ip4.into(),
            ip6: ip6.into(),
            endpoint_addr: endpoint.map(String::from),
            last_handshake: None,
        }
    }

    fn iface() -> InterfaceParams {
        InterfaceParams {
            private_key: "privkeybase64==".into(),
            ip4: "100.90.0.7".into(),
            ip6: "fd00:90::7".into(),
            own_pubkey: "ownpubkeybase64==".into(),
        }
    }

    #[test]
    fn renders_interface_block() {
        let conf = render_conf(&iface(), &[]);
        assert!(conf.contains("[Interface]"));
        assert!(conf.contains("PrivateKey = privkeybase64=="));
        assert!(conf.contains("Address = 100.90.0.7/32, fd00:90::7/128"));
    }

    #[test]
    fn omits_endpoint_line_when_absent() {
        let peers = vec![peer("otherpubkey", "100.90.0.3", "fd00:90::3", None)];
        let conf = render_conf(&iface(), &peers);
        assert!(!conf.contains("Endpoint ="));
    }

    #[test]
    fn includes_endpoint_line_when_present() {
        let peers = vec![peer(
            "otherpubkey",
            "100.90.0.3",
            "fd00:90::3",
            Some("duckdns.example.com:51820"),
        )];
        let conf = render_conf(&iface(), &peers);
        assert!(conf.contains("Endpoint = duckdns.example.com:51820"));
    }

    #[test]
    fn every_peer_gets_own_32_and_128_never_a_wider_block() {
        let peers = vec![
            peer("p1", "100.90.0.3", "fd00:90::3", None),
            peer("p2", "100.90.0.4", "fd00:90::4", None),
        ];
        let conf = render_conf(&iface(), &peers);
        assert!(conf.contains("AllowedIPs = 100.90.0.3/32, fd00:90::3/128"));
        assert!(conf.contains("AllowedIPs = 100.90.0.4/32, fd00:90::4/128"));
        assert!(!conf.contains("/24"));
        assert!(!conf.contains("/64"));
        assert!(!conf.contains("/0"));
    }

    #[test]
    fn multiple_peers_each_get_their_own_peer_block() {
        let peers = vec![
            peer("p1", "100.90.0.3", "fd00:90::3", None),
            peer("p2", "100.90.0.4", "fd00:90::4", None),
        ];
        let conf = render_conf(&iface(), &peers);
        assert_eq!(conf.matches("[Peer]").count(), 2);
    }

    #[test]
    fn self_is_excluded_from_peer_list() {
        let i = iface();
        let peers = vec![
            peer(&i.own_pubkey, "100.90.0.7", "fd00:90::7", None),
            peer("someone-else", "100.90.0.3", "fd00:90::3", None),
        ];
        let conf = render_conf(&i, &peers);
        assert_eq!(conf.matches("[Peer]").count(), 1);
        assert!(conf.contains("someone-else"));
    }

    // ---- S2 defense-in-depth: renderer refuses newline-smuggling peers ----

    #[test]
    fn skips_peer_with_newline_in_endpoint_addr_instead_of_rendering_it() {
        let peers = vec![peer(
            "otherpubkey",
            "100.90.0.3",
            "fd00:90::3",
            Some("1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0"),
        )];
        let conf = render_conf(&iface(), &peers);
        assert!(
            !conf.contains("[Peer]"),
            "a peer carrying a config-injection payload must be skipped entirely, not rendered"
        );
        assert!(!conf.contains("0.0.0.0/0"));
    }

    #[test]
    fn skips_peer_with_newline_in_pubkey_instead_of_rendering_it() {
        let peers = vec![peer(
            "legit-looking-key\nEndpoint = evil.example:1",
            "100.90.0.3",
            "fd00:90::3",
            None,
        )];
        let conf = render_conf(&iface(), &peers);
        assert!(!conf.contains("[Peer]"));
        assert!(!conf.contains("evil.example"));
    }

    #[test]
    fn other_valid_peers_are_unaffected_by_a_skipped_one() {
        let peers = vec![
            peer("good1", "100.90.0.3", "fd00:90::3", None),
            peer(
                "bad\nEndpoint = evil.example:1",
                "100.90.0.4",
                "fd00:90::4",
                None,
            ),
            peer("good2", "100.90.0.5", "fd00:90::5", None),
        ];
        let conf = render_conf(&iface(), &peers);
        assert_eq!(conf.matches("[Peer]").count(), 2);
        assert!(conf.contains("good1"));
        assert!(conf.contains("good2"));
        assert!(!conf.contains("evil.example"));
    }

    #[test]
    fn generated_private_key_never_appears_in_register_request() {
        let private_key = Key::generate();
        let public_key = private_key.public_key();
        let req = RegisterRequest {
            join_token: "jtk_x".into(),
            pubkey: public_key.to_string(),
            kind: NodeKind::Static,
            listen_port: None,
            endpoint_addr: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains(&private_key.to_string()));
        assert!(json.contains(&public_key.to_string()));
    }
}
